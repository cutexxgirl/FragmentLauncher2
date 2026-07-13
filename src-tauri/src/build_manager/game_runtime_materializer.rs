use super::{
    artifact_plan::PlannedGameGenerationBindingV2,
    cas::VerifiedCasObject,
    contracts::{
        domain_digest, EmbeddedInstallerEntry, GameRuntimeLock, GameRuntimeRole, GameRuntimeSource,
        NormalizedProcessorArgument, OfflineProcessorVerification, ProcessorInput,
        ProcessorMaterializationAccess, ProcessorMaterializationId,
    },
    game_generation::GameGenerationProcessorBuild,
    managed_fs::{
        atomic_write_small, ensure_directory_chain, ExclusiveManagedFile, FileIdentity,
        GuardedDirectoryChain, ImmutableManagedFile, RelativeManagedPath,
    },
    storage::{inspect_existing_ancestors, is_windows_reparse_point, OwnedCasRoot},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs,
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
};
use unicode_normalization::UnicodeNormalization;
use zip::{CompressionMethod, ZipArchive};

const INPUT_STATE_DOMAIN: &str = "ru.fragmc.spark2.neoforge.materialized-input-state.v2";
const CLIENT_PATCH_ARCHIVE_PATH: &str = "data/client.lzma";
const CLIENT_PATCH_MATERIALIZED_PATH: &str = "processor-inputs/data/client.lzma";
const PINNED_OFFICIAL_INPUT_COUNT: usize = 26;
const PINNED_OFFICIAL_INPUT_BYTES: u64 = 52_308_641;
const MAX_PROCESSOR_INPUT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_INPUT_TREE_ENTRIES: usize = 256;
const MAX_INSTALLER_ZIP_ENTRIES: usize = 4_096;
const MAX_INSTALLER_DECLARED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_STATE_MARKER_BYTES: usize = 256 * 1024;
pub(super) const MAX_SCRATCH_ENTRIES: usize = 512;
pub(super) const MAX_SCRATCH_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
pub(super) const STATE_MARKER_PATH: &str = "materialized-input-state-v2.json";
const USER_HOME_PATH: &str = "state/user-home";
const WORKSPACE_LAYOUT: [&str; 4] = ["inputs", "outputs", "temp", "state"];

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessorInputStateEntry {
    path: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedInput {
    path: String,
    size: u64,
    sha1: Option<String>,
    sha256: String,
    official: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProcessorInputStateMarker<'a> {
    schema_version: u8,
    domain: &'static str,
    input_state_sha256: &'a str,
    official_input_count: usize,
    official_input_bytes: u64,
    files: &'a [ProcessorInputStateEntry],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProcessorInputAudit {
    pub(super) file_count: usize,
    pub(super) total_bytes: u64,
    pub(super) input_state_sha256: String,
}

struct HeldInput {
    key: String,
    expected: ExpectedInput,
    file: ImmutableManagedFile,
}

/// Holds immutable handles for every processor input and guarded handles for their directory
/// tree. The complete inventory is still re-enumerated on every `revalidate` call because a
/// same-user process can create a new child in an already-open Windows directory.
struct ProcessorInputLease {
    root: PathBuf,
    expected: BTreeMap<String, ExpectedInput>,
    expected_directories: BTreeMap<String, String>,
    held_inputs: Vec<HeldInput>,
    audit: ProcessorInputAudit,
    _root_guard: GuardedDirectoryChain,
    _directory_guards: Vec<GuardedDirectoryChain>,
}

impl ProcessorInputLease {
    fn revalidate(&mut self) -> Result<ProcessorInputAudit, String> {
        let mut observed = BTreeSet::new();
        for held in &mut self.held_inputs {
            let actual = held.file.sha1_sha256(held.expected.size).map_err(|error| {
                format!(
                    "Processor input changed while leased ({}): {error}",
                    held.expected.path
                )
            })?;
            require_expected_digests(&held.expected, actual.size, &actual.sha1, &actual.sha256)?;
            if !observed.insert(held.key.clone()) {
                return Err("Processor input lease contains a duplicate path".into());
            }
        }
        if observed != self.expected.keys().cloned().collect() {
            return Err("Processor input lease inventory is incomplete".into());
        }
        validate_input_tree_inventory(&self.root, &self.expected, &self.expected_directories)?;
        Ok(self.audit.clone())
    }
}

/// A freshly-created, self-contained workspace for the pinned NeoForge offline processors.
///
/// The workspace is intentionally not made writable through public fields. Callers receive exact
/// path accessors and must call `revalidate_inputs` immediately before and after every processor
/// step. No method in this module recursively removes a workspace; failed workspaces are left for
/// the coordinator's validated quarantine flow.
pub(super) struct ProcessorWorkspace {
    root: PathBuf,
    inputs: PathBuf,
    outputs: PathBuf,
    temp: PathBuf,
    state: PathBuf,
    input_state_sha256: String,
    generation_binding: PlannedGameGenerationBindingV2,
    game_runtime_lock_sha256: String,
    java_runtime_lock_sha256: String,
    processor_receipt_sha256: String,
    state_marker_bytes: Vec<u8>,
    state_marker: ImmutableManagedFile,
    input_lease: ProcessorInputLease,
    home_guard: Option<GuardedDirectoryChain>,
    _workspace_guard: GuardedDirectoryChain,
    _layout_guards: Vec<GuardedDirectoryChain>,
}

impl ProcessorWorkspace {
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn inputs(&self) -> &Path {
        &self.inputs
    }

    pub(super) fn outputs(&self) -> &Path {
        &self.outputs
    }

    pub(super) fn temp(&self) -> &Path {
        &self.temp
    }

    pub(super) fn state(&self) -> &Path {
        &self.state
    }

    pub(super) fn input_state_sha256(&self) -> &str {
        &self.input_state_sha256
    }

    pub(super) fn generation_binding(&self) -> &PlannedGameGenerationBindingV2 {
        &self.generation_binding
    }

    pub(super) fn game_runtime_lock_sha256(&self) -> &str {
        &self.game_runtime_lock_sha256
    }

    pub(super) fn java_runtime_lock_sha256(&self) -> &str {
        &self.java_runtime_lock_sha256
    }

    pub(super) fn processor_receipt_sha256(&self) -> &str {
        &self.processor_receipt_sha256
    }

    pub(super) fn directory_identity(&self) -> FileIdentity {
        self._workspace_guard.leaf().info().identity.clone()
    }

    /// Rebinds every filesystem and signed-lock fact immediately before processor execution or
    /// publication. A workspace cannot be transplanted between roots, operations or releases.
    pub(super) fn validate_binding_for_build(
        &self,
        build: &GameGenerationProcessorBuild<'_, '_>,
    ) -> Result<(), String> {
        let authority = build.authority();
        validate_generation_root_binding(build, &self.generation_binding)?;
        if self.root != build.workspaces_root().join(build.workspace_name())
            || self.game_runtime_lock_sha256 != authority.game_runtime_lock_sha256()
            || self.java_runtime_lock_sha256 != authority.runtime_lock_sha256()
            || self.processor_receipt_sha256
                != verified_receipt_sha256(authority.game_runtime_lock())?
        {
            return Err("Processor workspace belongs to another sealed generation build".into());
        }
        Ok(())
    }

    /// Full content audit used before processor spawns and commit boundaries. Publication of each
    /// already-leased output uses the lightweight binding check above plus the exact-six output
    /// lease, avoiding repeated hashing of the 52 MiB immutable input closure.
    pub(super) fn validate_for_build(
        &mut self,
        build: &GameGenerationProcessorBuild<'_, '_>,
    ) -> Result<(), String> {
        self.validate_binding_for_build(build)?;
        self.revalidate_inputs()?;
        Ok(())
    }

    pub(super) fn revalidate_inputs(&mut self) -> Result<ProcessorInputAudit, String> {
        let audit = self.input_lease.revalidate()?;
        if audit.input_state_sha256 != self.input_state_sha256 {
            return Err(
                "Processor input-state digest changed while the workspace was leased".into(),
            );
        }
        Ok(audit)
    }

    /// Creates and leases the only writable home directory accepted by the invocation builder.
    /// This must run while the workspace is still fresh, before any processor is spawned.
    pub(super) fn prepare_execution_scratch(&mut self) -> Result<(), String> {
        self.revalidate_inputs()?;
        validate_empty_workspace_directory(&self.root, "outputs")?;
        validate_empty_workspace_directory(&self.root, "temp")?;
        let home = RelativeManagedPath::new(USER_HOME_PATH)
            .expect("static processor user-home path is valid");
        if self.home_guard.is_none() {
            self.home_guard = Some(
                ensure_directory_chain(&self.root, &home)
                    .map_err(|error| format!("Cannot create processor user-home: {error}"))?,
            );
        }
        validate_empty_workspace_directory(&self.state, "user-home")?;
        self.revalidate_execution_scratch()?;
        self.revalidate_inputs()?;
        Ok(())
    }

    /// Revalidates the writable workspace namespace without making any mutation. Outputs are
    /// audited separately against the per-step signed write-set.
    pub(super) fn revalidate_execution_scratch(&mut self) -> Result<(), String> {
        if self.home_guard.is_none() {
            return Err("Processor user-home has not been prepared".into());
        }
        let marker = self
            .state_marker
            .read_bounded(MAX_STATE_MARKER_BYTES as u64)
            .map_err(|error| format!("Cannot revalidate processor state marker: {error}"))?;
        if marker != self.state_marker_bytes {
            return Err("Processor input-state marker changed during execution".into());
        }
        validate_workspace_top_level(&self.root)?;
        validate_safe_scratch_tree(&self.temp, "processor temp")?;
        validate_execution_state_directory(&self.root, &self.state_marker_bytes)
    }
}

/// Creates the only production processor workspace authorized by a sealed immutable-generation
/// build. The workspace parent and unique operation-bound name are fixed by that type-state;
/// callers cannot choose an arbitrary root or reuse a workspace from another operation.
pub(super) fn materialize_processor_workspace(
    build: &GameGenerationProcessorBuild<'_, '_>,
) -> Result<ProcessorWorkspace, String> {
    let authority = build.authority();
    let binding = authority.binding();
    validate_generation_root_binding(build, &binding)?;
    let workspace_binding = ProcessorWorkspaceBinding {
        generation: binding,
        game_runtime_lock_sha256: authority.game_runtime_lock_sha256(),
        java_runtime_lock_sha256: authority.runtime_lock_sha256(),
    };
    materialize_processor_workspace_at(
        build.workspaces_root(),
        build.workspace_name(),
        build.root(),
        authority.game_runtime_lock(),
        |sha256| authority.official_object(sha256),
        workspace_binding,
    )
}

struct ProcessorWorkspaceBinding<'a> {
    generation: PlannedGameGenerationBindingV2,
    game_runtime_lock_sha256: &'a str,
    java_runtime_lock_sha256: &'a str,
}

/// Lightweight live-root check for processor steps. The 4,006 official CAS objects were sealed by
/// `PlannedGameGenerationV2`; each of the 26 processor inputs is independently reopened and hashed
/// while materializing it. Rehashing the entire ~1 GiB official set before every processor spawn
/// would add no binding strength and would make status/repair paths unusably expensive.
fn validate_generation_root_binding(
    build: &GameGenerationProcessorBuild<'_, '_>,
    binding: &PlannedGameGenerationBindingV2,
) -> Result<(), String> {
    build.root().revalidate()?;
    build.authority().validate_binding(binding)?;
    let (root_nonce, install_id, _, _) = build.root().binding();
    if root_nonce != binding.root_binding_nonce() || install_id != binding.install_id() {
        return Err("Processor generation binding belongs to another owned install root".into());
    }
    Ok(())
}

/// Raw path/materialization helper. It remains private so production callers cannot manufacture
/// filesystem authority outside `GameGenerationProcessorBuild`.
fn materialize_processor_workspace_at<'objects>(
    workspaces_root: &Path,
    workspace_name: &str,
    cas_root: &OwnedCasRoot,
    lock: &GameRuntimeLock,
    cas_object: impl Fn(&str) -> Result<&'objects VerifiedCasObject, String>,
    binding: ProcessorWorkspaceBinding<'_>,
) -> Result<ProcessorWorkspace, String> {
    lock.validate()?;
    let workspace_relative = RelativeManagedPath::new(workspace_name)
        .map_err(|error| format!("Processor workspace name is unsafe: {error}"))?;
    if workspace_relative.parent().is_some() {
        return Err("Processor workspace name must be exactly one path component".into());
    }

    inspect_existing_ancestors(workspaces_root)?;
    let parent_guard = GuardedDirectoryChain::root_only(workspaces_root)
        .map_err(|error| format!("Processor workspace parent is unsafe: {error}"))?;
    let requested_root = workspace_relative.join_to(parent_guard.root_path());
    fs::create_dir(&requested_root).map_err(|error| {
        format!(
            "Cannot create fresh processor workspace {}: {error}",
            requested_root.display()
        )
    })?;
    let workspace_guard = GuardedDirectoryChain::open(workspaces_root, &workspace_relative)
        .map_err(|error| format!("Fresh processor workspace is unsafe: {error}"))?;
    drop(parent_guard);
    let root = workspace_guard.leaf().path().to_path_buf();

    let mut initial_layout_guards = Vec::with_capacity(WORKSPACE_LAYOUT.len());
    for component in WORKSPACE_LAYOUT {
        let relative = RelativeManagedPath::new(component)
            .expect("static processor workspace component is valid");
        let path = relative.join_to(&root);
        fs::create_dir(&path)
            .map_err(|error| format!("Cannot create processor workspace {component}: {error}"))?;
        initial_layout_guards.push(
            GuardedDirectoryChain::open(&root, &relative)
                .map_err(|error| format!("Processor workspace {component} is unsafe: {error}"))?,
        );
    }

    let inputs = root.join("inputs");
    let outputs = root.join("outputs");
    let temp = root.join("temp");
    let state = root.join("state");
    let official = expected_official_processor_inputs(lock)?;
    for input in &official {
        let object = cas_object(&input.sha256).map_err(|error| {
            format!(
                "Verified CAS object is missing for processor input {} ({}): {error}",
                input.path, input.sha256
            )
        })?;
        copy_official_input(&inputs, cas_root, input, object)?;
    }

    let installer = official
        .iter()
        .find(|input| official_input_matches_artifact(input, &lock.provenance.neo_forge_installer))
        .ok_or_else(|| "Pinned NeoForge installer is absent from processor inputs".to_string())?;
    extract_client_patch(&inputs, installer, &lock.provenance.client_patch)?;

    let expected = expected_materialized_inputs(lock, &official)?;
    let mut input_lease = audit_materialized_inputs(&inputs, expected)?;
    let input_state_sha256 = input_lease.audit.input_state_sha256.clone();
    let state_entries = input_state_entries(input_lease.expected.values());
    let marker_bytes = write_state_marker(
        &state,
        &input_state_sha256,
        &state_entries,
        PINNED_OFFICIAL_INPUT_COUNT,
        PINNED_OFFICIAL_INPUT_BYTES,
    )?;
    validate_workspace_layout(&root, &marker_bytes)?;
    input_lease.revalidate()?;
    let marker_relative = RelativeManagedPath::new(STATE_MARKER_PATH)
        .expect("static processor state marker path is valid");
    let mut state_marker = ImmutableManagedFile::open(&state, &marker_relative)
        .map_err(|error| format!("Processor input-state marker is unsafe: {error}"))?;
    if state_marker
        .read_bounded(MAX_STATE_MARKER_BYTES as u64)
        .map_err(|error| format!("Cannot lease processor input-state marker: {error}"))?
        != marker_bytes
    {
        return Err("Processor input-state marker changed before it was leased".into());
    }

    // The input lease now owns stronger read-only snapshot guards for `inputs`. Retain ordinary
    // guarded handles for the three directories which the executor is allowed to write.
    initial_layout_guards.retain(|guard| guard.leaf().path() != inputs);
    Ok(ProcessorWorkspace {
        root,
        inputs,
        outputs,
        temp,
        state,
        input_state_sha256,
        generation_binding: binding.generation,
        game_runtime_lock_sha256: binding.game_runtime_lock_sha256.to_owned(),
        java_runtime_lock_sha256: binding.java_runtime_lock_sha256.to_owned(),
        processor_receipt_sha256: verified_receipt_sha256(lock)?.to_owned(),
        state_marker_bytes: marker_bytes,
        state_marker,
        input_lease,
        home_guard: None,
        _workspace_guard: workspace_guard,
        _layout_guards: initial_layout_guards,
    })
}

fn expected_official_processor_inputs(
    lock: &GameRuntimeLock,
) -> Result<Vec<ExpectedInput>, String> {
    let minecraft_client = unique_official_path_for_role(lock, GameRuntimeRole::MinecraftClient)?;
    let minecraft_mappings =
        unique_official_path_for_role(lock, GameRuntimeRole::MinecraftClientMappings)?;
    let installer = unique_official_path_for_role(lock, GameRuntimeRole::NeoforgeInstaller)?;
    let upstream = lock
        .provenance
        .processor_plans
        .upstream
        .steps
        .iter()
        .map(|step| (step.upstream_index, step))
        .collect::<HashMap<_, _>>();
    let mut required = BTreeSet::from([installer]);

    for reference in &lock.provenance.processor_plans.executable.steps {
        let step = upstream.get(&reference.upstream_index).ok_or_else(|| {
            format!(
                "Executable processor step {} is absent from the upstream plan",
                reference.upstream_index
            )
        })?;
        required.insert(step.jar_path.clone());
        required.extend(step.classpath.iter().cloned());
        for argument in &step.arguments {
            match argument {
                NormalizedProcessorArgument::Path { path } => {
                    required.insert(path.clone());
                }
                NormalizedProcessorArgument::Input {
                    input: ProcessorInput::MinecraftClient,
                } => {
                    required.insert(minecraft_client.clone());
                }
                NormalizedProcessorArgument::Input {
                    input: ProcessorInput::MinecraftClientMappings,
                }
                | NormalizedProcessorArgument::Materialization {
                    materialization: ProcessorMaterializationId::MinecraftClientMappings,
                    access: ProcessorMaterializationAccess::Read,
                } => {
                    required.insert(minecraft_mappings.clone());
                }
                NormalizedProcessorArgument::Materialization {
                    access: ProcessorMaterializationAccess::Write,
                    ..
                } => {
                    return Err(
                        "Executable processor plan contains a forbidden writable input materialization"
                            .into(),
                    );
                }
                NormalizedProcessorArgument::Literal { .. }
                | NormalizedProcessorArgument::Input {
                    input: ProcessorInput::ClientPatch,
                }
                | NormalizedProcessorArgument::Output { .. } => {}
            }
        }
    }

    let by_path = lock
        .files
        .iter()
        .map(|file| (file.path.to_lowercase(), file))
        .collect::<HashMap<_, _>>();
    let mut collision_keys = HashSet::with_capacity(required.len());
    let mut inputs = Vec::with_capacity(required.len());
    for path in required {
        let managed = RelativeManagedPath::new(&path)
            .map_err(|error| format!("Signed processor input path is unsafe ({path}): {error}"))?;
        if !collision_keys.insert(managed.collision_key().to_owned()) {
            return Err("Processor input paths collide on Windows".into());
        }
        let file = by_path.get(managed.collision_key()).ok_or_else(|| {
            format!("Processor input is not declared by the game runtime lock: {path}")
        })?;
        if file.path != path {
            return Err(format!(
                "Processor input casing differs from the signed runtime path: {path}"
            ));
        }
        let GameRuntimeSource::Official {
            size, sha1, sha256, ..
        } = &file.source
        else {
            return Err(format!("Processor input is not an official object: {path}"));
        };
        if *size == 0 || *size > MAX_PROCESSOR_INPUT_FILE_BYTES {
            return Err(format!("Processor input has an unsafe size: {path}"));
        }
        inputs.push(ExpectedInput {
            path,
            size: *size,
            sha1: Some(sha1.clone()),
            sha256: sha256.clone(),
            official: true,
        });
    }
    inputs.sort_by(|left, right| left.path.cmp(&right.path));
    let total = inputs.iter().try_fold(0_u64, |sum, input| {
        sum.checked_add(input.size)
            .ok_or_else(|| "Processor input byte total overflowed".to_string())
    })?;
    if inputs.len() != PINNED_OFFICIAL_INPUT_COUNT || total != PINNED_OFFICIAL_INPUT_BYTES {
        return Err(format!(
            "Processor input closure is not the pinned 26-file/52308641-byte set: {}/{}",
            inputs.len(),
            total
        ));
    }
    Ok(inputs)
}

fn verified_receipt_sha256(lock: &GameRuntimeLock) -> Result<&str, String> {
    match &lock.verification.offline_processors {
        OfflineProcessorVerification::Verified { receipt_sha256, .. } => Ok(receipt_sha256),
        OfflineProcessorVerification::Pending { .. } => {
            Err("Pending processor verification has no signed receipt".into())
        }
    }
}

fn unique_official_path_for_role(
    lock: &GameRuntimeLock,
    role: GameRuntimeRole,
) -> Result<String, String> {
    let mut matching = lock.files.iter().filter(|file| {
        file.role == role && matches!(&file.source, GameRuntimeSource::Official { .. })
    });
    let path = matching
        .next()
        .map(|file| file.path.clone())
        .ok_or_else(|| format!("Official processor role is missing: {role:?}"))?;
    if matching.next().is_some() {
        return Err(format!("Official processor role is ambiguous: {role:?}"));
    }
    Ok(path)
}

fn official_input_matches_artifact(
    input: &ExpectedInput,
    artifact: &super::contracts::GameOfficialArtifact,
) -> bool {
    input.official
        && input.size == artifact.size
        && input.sha1.as_deref() == Some(artifact.sha1.as_str())
        && input.sha256 == artifact.sha256
}

fn expected_materialized_inputs(
    lock: &GameRuntimeLock,
    official: &[ExpectedInput],
) -> Result<BTreeMap<String, ExpectedInput>, String> {
    let mut expected = BTreeMap::new();
    for input in official {
        insert_expected_input(&mut expected, input.clone())?;
    }
    insert_expected_input(
        &mut expected,
        ExpectedInput {
            path: CLIENT_PATCH_MATERIALIZED_PATH.to_owned(),
            size: lock.provenance.client_patch.size,
            sha1: None,
            sha256: lock.provenance.client_patch.sha256.clone(),
            official: false,
        },
    )?;
    let computed = compute_input_state_sha256(expected.values())?;
    let signed = signed_input_state_sha256(lock)?;
    if computed != signed {
        return Err(format!(
            "Materialized processor input-state differs from the verified receipt: {computed}"
        ));
    }
    Ok(expected)
}

fn insert_expected_input(
    expected: &mut BTreeMap<String, ExpectedInput>,
    input: ExpectedInput,
) -> Result<(), String> {
    let path = RelativeManagedPath::new(&input.path)
        .map_err(|error| format!("Processor input path is unsafe: {error}"))?;
    if expected
        .insert(path.collision_key().to_owned(), input)
        .is_some()
    {
        return Err("Materialized processor input paths collide on Windows".into());
    }
    Ok(())
}

fn signed_input_state_sha256(lock: &GameRuntimeLock) -> Result<String, String> {
    let OfflineProcessorVerification::Verified { runs, .. } = &lock.verification.offline_processors
    else {
        return Err("Pending NeoForge processor verification cannot be materialized".into());
    };
    let first = &runs[0].inputs_before_sha256;
    if first != &runs[0].inputs_after_sha256
        || first != &runs[1].inputs_before_sha256
        || first != &runs[1].inputs_after_sha256
    {
        return Err("Verified processor runs disagree on their immutable input state".into());
    }
    Ok(first.clone())
}

fn input_state_entries<'a>(
    inputs: impl IntoIterator<Item = &'a ExpectedInput>,
) -> Vec<ProcessorInputStateEntry> {
    let mut entries = inputs
        .into_iter()
        .map(|input| ProcessorInputStateEntry {
            path: input.path.clone(),
            size: input.size,
            sha256: input.sha256.clone(),
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    entries
}

fn compute_input_state_sha256<'a>(
    inputs: impl IntoIterator<Item = &'a ExpectedInput>,
) -> Result<String, String> {
    domain_digest(INPUT_STATE_DOMAIN, &input_state_entries(inputs))
}

fn write_state_marker(
    state_root: &Path,
    input_state_sha256: &str,
    entries: &[ProcessorInputStateEntry],
    official_input_count: usize,
    official_input_bytes: u64,
) -> Result<Vec<u8>, String> {
    let marker = ProcessorInputStateMarker {
        schema_version: 2,
        domain: INPUT_STATE_DOMAIN,
        input_state_sha256,
        official_input_count,
        official_input_bytes,
        files: entries,
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| format!("Cannot serialize processor input-state marker: {error}"))?;
    atomic_write_small(
        state_root,
        RelativeManagedPath::new(STATE_MARKER_PATH)
            .expect("static processor state marker path is valid"),
        &bytes,
        MAX_STATE_MARKER_BYTES,
    )
    .map_err(|error| format!("Cannot persist processor input-state marker: {error}"))?;
    Ok(bytes)
}

fn copy_official_input(
    inputs_root: &Path,
    cas_root: &OwnedCasRoot,
    expected: &ExpectedInput,
    object: &VerifiedCasObject,
) -> Result<(), String> {
    if !expected.official || expected.sha1.is_none() {
        return Err("Only an official dual-hash object can be copied from CAS".into());
    }
    if object.sha256() != expected.sha256 || object.size() != expected.size {
        return Err(format!(
            "Verified CAS metadata differs from signed processor input: {}",
            expected.path
        ));
    }
    let destination_relative = RelativeManagedPath::new(&expected.path)
        .map_err(|error| format!("Processor input destination is unsafe: {error}"))?;
    ensure_parent(inputs_root, &destination_relative)?;

    let mut source = object
        .open(cas_root)
        .map_err(|error| format!("CAS object is unsafe ({}): {error}", expected.sha256))?;
    let source_digest = source
        .sha1_sha256(expected.size)
        .map_err(|error| format!("Cannot verify CAS object {}: {error}", expected.sha256))?;
    require_expected_digests(
        expected,
        source_digest.size,
        &source_digest.sha1,
        &source_digest.sha256,
    )?;

    let mut destination = ExclusiveManagedFile::create(inputs_root, destination_relative.clone())
        .map_err(|error| {
        format!(
            "Cannot create independent processor input {}: {error}",
            expected.path
        )
    })?;
    let copied = source
        .copy_to_exclusive(&mut destination, expected.size)
        .map_err(|error| format!("Cannot copy processor input {}: {error}", expected.path))?;
    require_expected_digests(expected, copied.size, &copied.sha1, &copied.sha256)?;
    drop(
        destination
            .sync()
            .map_err(|error| format!("Cannot flush processor input {}: {error}", expected.path))?,
    );

    let mut materialized = ImmutableManagedFile::open(inputs_root, &destination_relative)
        .map_err(|error| format!("Materialized processor input is unsafe: {error}"))?;
    let actual = materialized
        .sha1_sha256(expected.size)
        .map_err(|error| format!("Cannot reverify processor input {}: {error}", expected.path))?;
    require_expected_digests(expected, actual.size, &actual.sha1, &actual.sha256)
}

fn require_expected_digests(
    expected: &ExpectedInput,
    size: u64,
    sha1: &str,
    sha256: &str,
) -> Result<(), String> {
    if size != expected.size
        || sha256 != expected.sha256
        || expected
            .sha1
            .as_ref()
            .is_some_and(|expected_sha1| sha1 != expected_sha1)
    {
        return Err(format!(
            "Processor input size/digest mismatch: {}",
            expected.path
        ));
    }
    Ok(())
}

fn ensure_parent(root: &Path, relative: &RelativeManagedPath) -> Result<(), String> {
    if let Some(parent) = relative.parent() {
        drop(
            ensure_directory_chain(root, &parent)
                .map_err(|error| format!("Cannot create processor input directory: {error}"))?,
        );
    }
    Ok(())
}

fn extract_client_patch(
    inputs_root: &Path,
    installer: &ExpectedInput,
    patch: &EmbeddedInstallerEntry,
) -> Result<(), String> {
    if patch.entry != CLIENT_PATCH_ARCHIVE_PATH
        || patch.size == 0
        || patch.size > MAX_PROCESSOR_INPUT_FILE_BYTES
    {
        return Err("Signed NeoForge client patch declaration is unsafe".into());
    }
    let installer_relative = RelativeManagedPath::new(&installer.path)
        .map_err(|error| format!("NeoForge installer path is unsafe: {error}"))?;
    let mut installer_file = ImmutableManagedFile::open(inputs_root, &installer_relative)
        .map_err(|error| format!("Materialized NeoForge installer is unsafe: {error}"))?;
    let installer_digest = installer_file
        .sha1_sha256(installer.size)
        .map_err(|error| format!("Cannot verify materialized NeoForge installer: {error}"))?;
    require_expected_digests(
        installer,
        installer_digest.size,
        &installer_digest.sha1,
        &installer_digest.sha256,
    )?;
    let bytes = installer_file
        .read_bounded(installer.size)
        .map_err(|error| format!("Cannot read verified NeoForge installer: {error}"))?;
    extract_client_patch_bytes(inputs_root, &bytes, patch)
}

fn extract_client_patch_bytes(
    inputs_root: &Path,
    installer_bytes: &[u8],
    patch: &EmbeddedInstallerEntry,
) -> Result<(), String> {
    let mut archive = ZipArchive::new(Cursor::new(installer_bytes))
        .map_err(|error| format!("Verified NeoForge installer ZIP is invalid: {error}"))?;
    let target_index = inspect_installer_zip(&mut archive, patch)?;
    let destination_relative = RelativeManagedPath::new(CLIENT_PATCH_MATERIALIZED_PATH)
        .expect("static client patch materialization path is valid");
    ensure_parent(inputs_root, &destination_relative)?;

    let mut entry = archive
        .by_index(target_index)
        .map_err(|error| format!("Cannot reopen NeoForge client patch: {error}"))?;
    if entry.name_raw() != CLIENT_PATCH_ARCHIVE_PATH.as_bytes()
        || entry.name() != CLIENT_PATCH_ARCHIVE_PATH
    {
        return Err("NeoForge client patch ZIP entry changed during inspection".into());
    }
    let mut destination = ExclusiveManagedFile::create(inputs_root, destination_relative.clone())
        .map_err(|error| {
        format!("Cannot create materialized NeoForge client patch: {error}")
    })?;
    let mut written = 0_u64;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = entry
            .read(&mut buffer)
            .map_err(|error| format!("Cannot decompress NeoForge client patch: {error}"))?;
        if read == 0 {
            break;
        }
        written = written
            .checked_add(read as u64)
            .ok_or_else(|| "NeoForge client patch byte counter overflowed".to_string())?;
        if written > patch.size {
            return Err("NeoForge client patch exceeded its signed size".into());
        }
        destination
            .file_mut()
            .write_all(&buffer[..read])
            .map_err(|error| format!("Cannot write NeoForge client patch: {error}"))?;
        digest.update(&buffer[..read]);
    }
    if written != patch.size || format!("{:x}", digest.finalize()) != patch.sha256 {
        return Err("NeoForge client patch size/SHA-256 mismatch".into());
    }
    drop(
        destination
            .sync()
            .map_err(|error| format!("Cannot flush materialized NeoForge client patch: {error}"))?,
    );

    let mut materialized = ImmutableManagedFile::open(inputs_root, &destination_relative)
        .map_err(|error| format!("Materialized NeoForge client patch is unsafe: {error}"))?;
    let actual = materialized
        .sha256(patch.size)
        .map_err(|error| format!("Cannot reverify NeoForge client patch: {error}"))?;
    if actual.size != patch.size || actual.sha256 != patch.sha256 {
        return Err("Materialized NeoForge client patch failed final verification".into());
    }
    Ok(())
}

fn inspect_installer_zip<R: Read + std::io::Seek>(
    archive: &mut ZipArchive<R>,
    patch: &EmbeddedInstallerEntry,
) -> Result<usize, String> {
    if archive.offset() != 0
        || archive.is_empty()
        || archive.len() > MAX_INSTALLER_ZIP_ENTRIES
        || archive
            .has_overlapping_files()
            .map_err(|error| format!("Cannot inspect overlapping NeoForge ZIP entries: {error}"))?
    {
        return Err("NeoForge installer ZIP has an unsafe physical layout".into());
    }
    let mut seen = HashSet::with_capacity(archive.len());
    let mut target = None;
    let mut declared_bytes = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("Cannot inspect NeoForge ZIP entry {index}: {error}"))?;
        let normalized = validate_installer_entry(&entry)?;
        let collision_key = normalized.to_lowercase();
        if !seen.insert(collision_key) {
            return Err(format!(
                "NeoForge installer ZIP contains a duplicate/case-colliding entry: {normalized}"
            ));
        }
        if !entry.is_dir() {
            declared_bytes = declared_bytes
                .checked_add(entry.size())
                .ok_or_else(|| "NeoForge ZIP declared-size total overflowed".to_string())?;
            if declared_bytes > MAX_INSTALLER_DECLARED_BYTES {
                return Err("NeoForge installer ZIP declared output exceeds its limit".into());
            }
        }
        if normalized.eq_ignore_ascii_case(CLIENT_PATCH_ARCHIVE_PATH) {
            if normalized != CLIENT_PATCH_ARCHIVE_PATH
                || entry.is_dir()
                || entry.size() != patch.size
                || entry.compressed_size() > installer_zip_compressed_limit(patch.size)
            {
                return Err("NeoForge client patch ZIP metadata/casing is invalid".into());
            }
            if target.replace(index).is_some() {
                return Err(
                    "NeoForge installer ZIP contains the client patch more than once".into(),
                );
            }
        }
    }
    target.ok_or_else(|| "NeoForge installer ZIP is missing data/client.lzma".into())
}

fn installer_zip_compressed_limit(uncompressed_size: u64) -> u64 {
    // Deflate can expand incompressible data slightly; this is deliberately generous while still
    // bounding absurd central-directory metadata before extraction.
    uncompressed_size.saturating_add(1024 * 1024)
}

fn validate_installer_entry<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Result<String, String> {
    let name = entry.name();
    if entry.name_raw() != name.as_bytes()
        || !name.is_ascii()
        || name.is_empty()
        || name.starts_with('/')
        || name.contains('\0')
        || name.contains('\\')
        || name.nfc().collect::<String>() != name
        || entry.encrypted()
    {
        return Err(format!(
            "NeoForge installer ZIP entry name is unsafe: {name:?}"
        ));
    }
    let is_directory = entry.is_dir();
    if is_directory != name.ends_with('/') {
        return Err(format!(
            "NeoForge installer ZIP directory marker is inconsistent: {name}"
        ));
    }
    let normalized = name.trim_end_matches('/');
    if normalized.is_empty()
        || normalized.contains("//")
        || normalized
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(format!(
            "NeoForge installer ZIP entry traverses its root: {name}"
        ));
    }
    RelativeManagedPath::new(normalized)
        .map_err(|error| format!("NeoForge installer ZIP entry is Windows-unsafe: {error}"))?;
    validate_installer_entry_mode(entry)?;
    if !is_directory
        && (!entry.is_file()
            || entry.is_symlink()
            || entry.size() > MAX_INSTALLER_DECLARED_BYTES
            || !matches!(
                entry.compression(),
                CompressionMethod::Stored | CompressionMethod::Deflated
            ))
    {
        return Err(format!(
            "NeoForge installer ZIP entry type/compression/size is forbidden: {name}"
        ));
    }
    Ok(normalized.to_owned())
}

fn validate_installer_entry_mode<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Result<(), String> {
    if let Some(mode) = entry.unix_mode() {
        let file_type = mode & 0o170_000;
        let valid = if entry.is_dir() {
            file_type == 0 || file_type == 0o040_000
        } else {
            file_type == 0 || file_type == 0o100_000
        };
        if !valid {
            return Err(format!(
                "Special/link NeoForge ZIP entry is forbidden: {}",
                entry.name()
            ));
        }
    }
    Ok(())
}

fn audit_materialized_inputs(
    inputs_root: &Path,
    expected: BTreeMap<String, ExpectedInput>,
) -> Result<ProcessorInputLease, String> {
    let expected_directories = expected_input_directories(&expected)?;
    let root_guard = GuardedDirectoryChain::root_snapshot(inputs_root)
        .map_err(|error| format!("Processor input root is unsafe: {error}"))?;
    let mut observed = BTreeSet::new();
    let mut observed_directories = BTreeSet::new();
    let mut held_inputs = Vec::with_capacity(expected.len());
    let mut directory_guards = Vec::with_capacity(expected_directories.len());
    let mut entries = 0_usize;
    {
        let mut scan = InputTreeScan {
            root: root_guard.root_path(),
            expected: &expected,
            expected_directories: &expected_directories,
            observed: &mut observed,
            observed_directories: &mut observed_directories,
            held_inputs: &mut held_inputs,
            directory_guards: &mut directory_guards,
            entries: &mut entries,
        };
        scan.scan(root_guard.root_path())?;
    }
    validate_input_inventory(
        &expected,
        &expected_directories,
        &observed,
        &observed_directories,
    )?;
    let input_state_sha256 = compute_input_state_sha256(expected.values())?;
    let total_bytes = expected.values().try_fold(0_u64, |sum, input| {
        sum.checked_add(input.size)
            .ok_or_else(|| "Materialized input byte total overflowed".to_string())
    })?;
    let audit = ProcessorInputAudit {
        file_count: expected.len(),
        total_bytes,
        input_state_sha256,
    };
    let mut lease = ProcessorInputLease {
        root: root_guard.root_path().to_path_buf(),
        expected,
        expected_directories,
        held_inputs,
        audit,
        _root_guard: root_guard,
        _directory_guards: directory_guards,
    };
    lease.revalidate()?;
    Ok(lease)
}

fn expected_input_directories(
    expected: &BTreeMap<String, ExpectedInput>,
) -> Result<BTreeMap<String, String>, String> {
    let mut directories = BTreeMap::new();
    for input in expected.values() {
        let mut parent = RelativeManagedPath::new(&input.path)
            .map_err(|error| format!("Processor input path is unsafe: {error}"))?
            .parent();
        while let Some(path) = parent {
            if let Some(previous) =
                directories.insert(path.collision_key().to_owned(), path.as_str().to_owned())
            {
                if previous != path.as_str() {
                    return Err("Processor input directories collide on Windows".into());
                }
            }
            parent = path.parent();
        }
    }
    Ok(directories)
}

struct InputTreeScan<'a> {
    root: &'a Path,
    expected: &'a BTreeMap<String, ExpectedInput>,
    expected_directories: &'a BTreeMap<String, String>,
    observed: &'a mut BTreeSet<String>,
    observed_directories: &'a mut BTreeSet<String>,
    held_inputs: &'a mut Vec<HeldInput>,
    directory_guards: &'a mut Vec<GuardedDirectoryChain>,
    entries: &'a mut usize,
}

impl InputTreeScan<'_> {
    fn scan(&mut self, directory: &Path) -> Result<(), String> {
        for entry in fs::read_dir(directory)
            .map_err(|error| format!("Cannot enumerate processor inputs: {error}"))?
        {
            *self.entries = self
                .entries
                .checked_add(1)
                .ok_or_else(|| "Processor input entry count overflowed".to_string())?;
            if *self.entries > MAX_INPUT_TREE_ENTRIES {
                return Err("Processor input tree exceeds its entry limit".into());
            }
            let entry =
                entry.map_err(|error| format!("Cannot inspect processor input: {error}"))?;
            let absolute = entry.path();
            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|error| format!("Cannot inspect processor input metadata: {error}"))?;
            if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
                return Err(format!(
                    "Link/reparse point is forbidden in processor inputs: {}",
                    absolute.display()
                ));
            }
            if metadata.is_file() && metadata.permissions().readonly() {
                return Err(format!(
                    "Read-only file is forbidden in processor inputs: {}",
                    absolute.display()
                ));
            }
            let relative = relative_manifest_path(self.root, &absolute)?;
            let managed = RelativeManagedPath::new(&relative)
                .map_err(|error| format!("Processor input path is unsafe: {error}"))?;
            let key = managed.collision_key().to_owned();
            if metadata.is_dir() {
                let canonical = self.expected_directories.get(&key).ok_or_else(|| {
                    format!("Unexpected directory in processor inputs: {relative}")
                })?;
                if managed.as_str() != canonical || !self.observed_directories.insert(key) {
                    return Err(format!(
                        "Processor input directory casing/collision mismatch: {relative}"
                    ));
                }
                let guard = GuardedDirectoryChain::open_snapshot(self.root, &managed)
                    .map_err(|error| format!("Processor input directory is unsafe: {error}"))?;
                let stable_path = guard.leaf().path().to_path_buf();
                self.directory_guards.push(guard);
                self.scan(&stable_path)?;
            } else if metadata.is_file() {
                let expected = self
                    .expected
                    .get(&key)
                    .ok_or_else(|| format!("Unexpected file in processor inputs: {relative}"))?;
                if managed.as_str() != expected.path || !self.observed.insert(key.clone()) {
                    return Err(format!(
                        "Processor input file casing/collision mismatch: {relative}"
                    ));
                }
                let mut file = ImmutableManagedFile::open(self.root, &managed)
                    .map_err(|error| format!("Processor input file is unsafe: {error}"))?;
                let digest = file.sha1_sha256(expected.size).map_err(|error| {
                    format!("Cannot hash processor input {}: {error}", expected.path)
                })?;
                require_expected_digests(expected, digest.size, &digest.sha1, &digest.sha256)?;
                self.held_inputs.push(HeldInput {
                    key,
                    expected: expected.clone(),
                    file,
                });
            } else {
                return Err(format!(
                    "Special file is forbidden in processor inputs: {}",
                    absolute.display()
                ));
            }
        }
        Ok(())
    }
}

fn validate_input_tree_inventory(
    root: &Path,
    expected: &BTreeMap<String, ExpectedInput>,
    expected_directories: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut observed = BTreeSet::new();
    let mut observed_directories = BTreeSet::new();
    let mut entries = 0_usize;
    scan_input_inventory(
        root,
        root,
        expected,
        expected_directories,
        &mut observed,
        &mut observed_directories,
        &mut entries,
    )?;
    validate_input_inventory(
        expected,
        expected_directories,
        &observed,
        &observed_directories,
    )
}

fn scan_input_inventory(
    root: &Path,
    directory: &Path,
    expected: &BTreeMap<String, ExpectedInput>,
    expected_directories: &BTreeMap<String, String>,
    observed: &mut BTreeSet<String>,
    observed_directories: &mut BTreeSet<String>,
    entries: &mut usize,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("Cannot re-enumerate processor inputs: {error}"))?
    {
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "Processor input entry count overflowed".to_string())?;
        if *entries > MAX_INPUT_TREE_ENTRIES {
            return Err("Processor input tree exceeds its entry limit".into());
        }
        let entry = entry.map_err(|error| format!("Cannot inspect processor input: {error}"))?;
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect processor input metadata: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err(format!(
                "Link/reparse point is forbidden in processor inputs: {}",
                absolute.display()
            ));
        }
        if metadata.is_file() && metadata.permissions().readonly() {
            return Err(format!(
                "Read-only file is forbidden in processor inputs: {}",
                absolute.display()
            ));
        }
        let relative = relative_manifest_path(root, &absolute)?;
        let managed = RelativeManagedPath::new(&relative)
            .map_err(|error| format!("Processor input path is unsafe: {error}"))?;
        let key = managed.collision_key().to_owned();
        if metadata.is_dir() {
            let canonical = expected_directories
                .get(&key)
                .ok_or_else(|| format!("Unexpected processor input directory: {relative}"))?;
            if managed.as_str() != canonical || !observed_directories.insert(key) {
                return Err(format!(
                    "Processor input directory casing/collision mismatch: {relative}"
                ));
            }
            let guard = GuardedDirectoryChain::open(root, &managed)
                .map_err(|error| format!("Processor input directory is unsafe: {error}"))?;
            let stable_path = guard.leaf().path().to_path_buf();
            scan_input_inventory(
                root,
                &stable_path,
                expected,
                expected_directories,
                observed,
                observed_directories,
                entries,
            )?;
        } else if metadata.is_file() {
            let expected_file = expected
                .get(&key)
                .ok_or_else(|| format!("Unexpected processor input file: {relative}"))?;
            if managed.as_str() != expected_file.path || !observed.insert(key) {
                return Err(format!(
                    "Processor input file casing/collision mismatch: {relative}"
                ));
            }
        } else {
            return Err(format!(
                "Special file is forbidden in processor inputs: {}",
                absolute.display()
            ));
        }
    }
    Ok(())
}

fn validate_input_inventory(
    expected: &BTreeMap<String, ExpectedInput>,
    expected_directories: &BTreeMap<String, String>,
    observed: &BTreeSet<String>,
    observed_directories: &BTreeSet<String>,
) -> Result<(), String> {
    if expected.keys().cloned().collect::<BTreeSet<_>>() != *observed {
        return Err("Processor input file inventory is incomplete or contains extras".into());
    }
    if expected_directories
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != *observed_directories
    {
        return Err("Processor input directory inventory is incomplete or contains extras".into());
    }
    Ok(())
}

fn relative_manifest_path(root: &Path, absolute: &Path) -> Result<String, String> {
    absolute
        .strip_prefix(root)
        .map_err(|_| "Processor input escaped its workspace root".to_string())?
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| "Processor input path is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

fn validate_workspace_layout(root: &Path, expected_marker_bytes: &[u8]) -> Result<(), String> {
    validate_workspace_top_level(root)?;
    validate_empty_workspace_directory(root, "outputs")?;
    validate_empty_workspace_directory(root, "temp")?;
    validate_state_workspace_directory(root, expected_marker_bytes)
}

fn validate_workspace_top_level(root: &Path) -> Result<(), String> {
    let expected = WORKSPACE_LAYOUT.into_iter().collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(root)
        .map_err(|error| format!("Cannot enumerate processor workspace: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("Cannot inspect processor workspace: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Processor workspace entry name is not UTF-8".to_string())?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Cannot inspect processor workspace entry: {error}"))?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || is_windows_reparse_point(&metadata)
            || !expected.contains(name.as_str())
            || !observed.insert(name)
        {
            return Err("Processor workspace top-level layout is unsafe or contains extras".into());
        }
    }
    if observed.iter().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("Processor workspace top-level layout is incomplete".into());
    }
    Ok(())
}

fn validate_empty_workspace_directory(root: &Path, component: &str) -> Result<(), String> {
    let relative = RelativeManagedPath::new(component)
        .map_err(|error| format!("Processor workspace component is unsafe: {error}"))?;
    let guard = GuardedDirectoryChain::open_snapshot(root, &relative)
        .map_err(|error| format!("Processor workspace {component} is unsafe: {error}"))?;
    if fs::read_dir(guard.leaf().path())
        .map_err(|error| format!("Cannot enumerate processor workspace {component}: {error}"))?
        .next()
        .transpose()
        .map_err(|error| format!("Cannot inspect processor workspace {component}: {error}"))?
        .is_some()
    {
        return Err(format!(
            "Fresh processor workspace {component} directory is not empty"
        ));
    }
    Ok(())
}

fn validate_safe_scratch_tree(root: &Path, label: &str) -> Result<(), String> {
    let root_guard = GuardedDirectoryChain::root_snapshot(root)
        .map_err(|error| format!("{label} root is unsafe: {error}"))?;
    let mut entries = 0_usize;
    let mut total_bytes = 0_u64;
    let mut collision_keys = BTreeSet::new();
    scan_safe_scratch_directory(
        root_guard.root_path(),
        root_guard.root_path(),
        label,
        &mut entries,
        &mut total_bytes,
        &mut collision_keys,
    )
}

fn scan_safe_scratch_directory(
    root: &Path,
    directory: &Path,
    label: &str,
    entries: &mut usize,
    total_bytes: &mut u64,
    collision_keys: &mut BTreeSet<String>,
) -> Result<(), String> {
    for entry in
        fs::read_dir(directory).map_err(|error| format!("Cannot enumerate {label}: {error}"))?
    {
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| format!("{label} entry counter overflowed"))?;
        if *entries > MAX_SCRATCH_ENTRIES {
            return Err(format!("{label} exceeds its entry limit"));
        }
        let entry = entry.map_err(|error| format!("Cannot inspect {label}: {error}"))?;
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect {label} metadata: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err(format!("Link/reparse point is forbidden in {label}"));
        }
        if metadata.is_file() && metadata.permissions().readonly() {
            return Err(format!("Read-only file is forbidden in {label}"));
        }
        let relative = relative_manifest_path(root, &absolute)?;
        let managed = RelativeManagedPath::new(&relative)
            .map_err(|error| format!("{label} path is unsafe: {error}"))?;
        if !collision_keys.insert(managed.collision_key().to_owned()) {
            return Err(format!("{label} contains a Windows path collision"));
        }
        if metadata.is_dir() {
            let guard = GuardedDirectoryChain::open_snapshot(root, &managed)
                .map_err(|error| format!("{label} directory is unsafe: {error}"))?;
            let stable = guard.leaf().path().to_path_buf();
            scan_safe_scratch_directory(
                root,
                &stable,
                label,
                entries,
                total_bytes,
                collision_keys,
            )?;
        } else if metadata.is_file() {
            let mut file = ImmutableManagedFile::open(root, &managed)
                .map_err(|error| format!("{label} file is unsafe: {error}"))?;
            let size = file.info().size;
            *total_bytes = total_bytes
                .checked_add(size)
                .ok_or_else(|| format!("{label} byte total overflowed"))?;
            if *total_bytes > MAX_SCRATCH_TOTAL_BYTES {
                return Err(format!("{label} exceeds its byte limit"));
            }
            file.sha256(size)
                .map_err(|error| format!("Cannot stabilize {label} file: {error}"))?;
        } else {
            return Err(format!("Special file is forbidden in {label}"));
        }
    }
    Ok(())
}

fn validate_state_workspace_directory(
    root: &Path,
    expected_marker_bytes: &[u8],
) -> Result<(), String> {
    let state_relative =
        RelativeManagedPath::new("state").expect("static processor state path is valid");
    let state_guard = GuardedDirectoryChain::open_snapshot(root, &state_relative)
        .map_err(|error| format!("Processor workspace state is unsafe: {error}"))?;
    let mut entries = fs::read_dir(state_guard.leaf().path())
        .map_err(|error| format!("Cannot enumerate processor workspace state: {error}"))?;
    let entry = entries
        .next()
        .transpose()
        .map_err(|error| format!("Cannot inspect processor workspace state: {error}"))?
        .ok_or_else(|| "Processor input-state marker is missing".to_string())?;
    if entries
        .next()
        .transpose()
        .map_err(|error| format!("Cannot inspect processor workspace state: {error}"))?
        .is_some()
        || entry.file_name().to_str() != Some(STATE_MARKER_PATH)
    {
        return Err("Processor workspace state contains unexpected entries".into());
    }
    let marker_relative = RelativeManagedPath::new(STATE_MARKER_PATH)
        .expect("static processor state marker path is valid");
    let mut marker = ImmutableManagedFile::open(state_guard.leaf().path(), &marker_relative)
        .map_err(|error| format!("Processor input-state marker is unsafe: {error}"))?;
    let bytes = marker
        .read_bounded(MAX_STATE_MARKER_BYTES as u64)
        .map_err(|error| format!("Cannot verify processor input-state marker: {error}"))?;
    if bytes != expected_marker_bytes {
        return Err("Processor input-state marker bytes changed after commit".into());
    }
    Ok(())
}

fn validate_execution_state_directory(
    root: &Path,
    expected_marker_bytes: &[u8],
) -> Result<(), String> {
    let state_relative =
        RelativeManagedPath::new("state").expect("static processor state path is valid");
    let state_guard = GuardedDirectoryChain::open_snapshot(root, &state_relative)
        .map_err(|error| format!("Processor workspace state is unsafe: {error}"))?;
    let state_root = state_guard.leaf().path();
    let mut names = fs::read_dir(state_root)
        .map_err(|error| format!("Cannot enumerate processor execution state: {error}"))?
        .map(|entry| {
            entry
                .map_err(|error| format!("Cannot inspect processor execution state: {error}"))?
                .file_name()
                .into_string()
                .map_err(|_| "Processor execution state name is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    if names != [STATE_MARKER_PATH.to_owned(), "user-home".to_owned()] {
        return Err("Processor execution state contains unexpected entries".into());
    }

    let marker_relative = RelativeManagedPath::new(STATE_MARKER_PATH)
        .expect("static processor state marker path is valid");
    let mut marker = ImmutableManagedFile::open(state_root, &marker_relative)
        .map_err(|error| format!("Processor input-state marker is unsafe: {error}"))?;
    let bytes = marker
        .read_bounded(MAX_STATE_MARKER_BYTES as u64)
        .map_err(|error| format!("Cannot verify processor input-state marker: {error}"))?;
    if bytes != expected_marker_bytes {
        return Err("Processor input-state marker changed during execution".into());
    }

    let home_relative = RelativeManagedPath::new("user-home")
        .expect("static processor user-home component is valid");
    let home_guard = GuardedDirectoryChain::open_snapshot(state_root, &home_relative)
        .map_err(|error| format!("Processor user-home is unsafe: {error}"))?;
    validate_safe_scratch_tree(home_guard.leaf().path(), "processor user-home")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::{
        cas::{cas_object_relative_path, verify_existing_object, ExpectedObject},
        storage::select_install_directory,
    };
    use sha1::Sha1;
    use std::{
        fs::OpenOptions,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zip::{write::SimpleFileOptions, ZipWriter};

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-processor-materializer-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn patch_declaration(bytes: &[u8]) -> EmbeddedInstallerEntry {
        EmbeddedInstallerEntry {
            entry: CLIENT_PATCH_ARCHIVE_PATH.to_owned(),
            size: bytes.len() as u64,
            sha256: format!("{:x}", Sha256::digest(bytes)),
        }
    }

    fn zip_bytes(entries: &[(&str, &[u8], Option<u32>)]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        for (name, bytes, mode) in entries {
            let mut options =
                SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
            if let Some(mode) = mode {
                options = options.unix_permissions(*mode);
            }
            writer.start_file(*name, options).expect("start zip file");
            writer.write_all(bytes).expect("write zip file");
        }
        writer.finish().expect("finish zip").into_inner()
    }

    fn symlink_patch_zip_bytes(target: &str) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .add_symlink(
                CLIENT_PATCH_ARCHIVE_PATH,
                target,
                SimpleFileOptions::default(),
            )
            .expect("add zip symlink");
        writer.finish().expect("finish zip").into_inner()
    }

    fn make_inputs_root(label: &str) -> (PathBuf, PathBuf) {
        let root = temp_root(label);
        let inputs = root.join("inputs");
        fs::create_dir_all(&inputs).expect("create inputs");
        (root, inputs)
    }

    #[test]
    fn pinned_fixture_selects_exact_official_processor_closure() {
        let lock = GameRuntimeLock::parse_and_validate(include_bytes!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        ))
        .expect("pinned fixture");
        let official = expected_official_processor_inputs(&lock).expect("processor inputs");
        assert_eq!(official.len(), PINNED_OFFICIAL_INPUT_COUNT);
        assert_eq!(
            official.iter().map(|input| input.size).sum::<u64>(),
            PINNED_OFFICIAL_INPUT_BYTES
        );
        let expected = expected_materialized_inputs(&lock, &official).expect("materialized state");
        assert_eq!(expected.len(), PINNED_OFFICIAL_INPUT_COUNT + 1);
        assert_eq!(
            compute_input_state_sha256(expected.values()).unwrap(),
            signed_input_state_sha256(&lock).unwrap()
        );
    }

    #[test]
    fn extracts_only_exact_verified_client_patch() {
        let patch_bytes = b"verified-client-patch";
        let archive = zip_bytes(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", None),
            (CLIENT_PATCH_ARCHIVE_PATH, patch_bytes, None),
            ("ignored/metadata.json", b"{}", None),
        ]);
        let declaration = patch_declaration(patch_bytes);
        let (root, inputs) = make_inputs_root("extract");
        extract_client_patch_bytes(&inputs, &archive, &declaration).expect("extract patch");
        assert_eq!(
            fs::read(inputs.join("processor-inputs/data/client.lzma")).unwrap(),
            patch_bytes
        );
        assert!(!inputs.join("META-INF/MANIFEST.MF").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn rejects_traversal_backslash_duplicate_special_and_oversize_patch_entries() {
        let patch = b"patch";
        let declaration = patch_declaration(patch);
        for (label, archive) in [
            (
                "traversal",
                zip_bytes(&[
                    ("../evil", b"x", None),
                    (CLIENT_PATCH_ARCHIVE_PATH, patch, None),
                ]),
            ),
            (
                "backslash",
                zip_bytes(&[("data\\client.lzma", patch, None)]),
            ),
            (
                "duplicate",
                zip_bytes(&[
                    (CLIENT_PATCH_ARCHIVE_PATH, patch, None),
                    ("DATA/CLIENT.LZMA", patch, None),
                ]),
            ),
            ("special", symlink_patch_zip_bytes("patch")),
            (
                "oversize",
                zip_bytes(&[(CLIENT_PATCH_ARCHIVE_PATH, b"patch-extra", None)]),
            ),
        ] {
            let (root, inputs) = make_inputs_root(label);
            assert!(extract_client_patch_bytes(&inputs, &archive, &declaration).is_err());
            assert!(!inputs.join(CLIENT_PATCH_MATERIALIZED_PATH).exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn cas_copy_is_independent_and_reverified_with_both_hashes() {
        let bytes = b"verified-cas-processor-input";
        let sha1 = format!("{:x}", Sha1::digest(bytes));
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        let root = temp_root("cas-copy");
        let cas_root = select_install_directory(&root)
            .expect("claim install")
            .into_owned_cas_root();
        let inputs = root.join("test-inputs");
        let source_relative = cas_object_relative_path(&sha256).unwrap();
        let source = source_relative.join_to(cas_root.managed_root());
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(&inputs).unwrap();
        fs::write(&source, bytes).unwrap();
        let expected = ExpectedInput {
            path: "libraries/example/input.jar".into(),
            size: bytes.len() as u64,
            sha1: Some(sha1),
            sha256: sha256.clone(),
            official: true,
        };
        let object = verify_existing_object(
            &cas_root,
            &ExpectedObject {
                sha256,
                size: bytes.len() as u64,
            },
            0,
        )
        .expect("verify CAS fixture");
        copy_official_input(&inputs, &cas_root, &expected, &object).expect("copy input");
        let destination = inputs.join("libraries/example/input.jar");
        OpenOptions::new()
            .write(true)
            .open(&destination)
            .unwrap()
            .write_all(b"changed")
            .unwrap();
        assert_eq!(fs::read(&source).unwrap(), bytes);
        drop(cas_root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cas_copy_rejects_another_owned_root_and_hardlinked_source() {
        let bytes = b"cas-object";
        let sha1 = format!("{:x}", Sha1::digest(bytes));
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        let root = temp_root("cas-path");
        let cas_root = select_install_directory(&root)
            .expect("claim install")
            .into_owned_cas_root();
        let other_install = temp_root("cas-other-root");
        let other_cas_root = select_install_directory(&other_install)
            .expect("claim other install")
            .into_owned_cas_root();
        let inputs = root.join("test-inputs");
        let source = cas_object_relative_path(&sha256)
            .unwrap()
            .join_to(cas_root.managed_root());
        fs::create_dir_all(source.parent().unwrap()).unwrap();
        fs::create_dir_all(&inputs).unwrap();
        fs::write(&source, bytes).unwrap();
        let expected = ExpectedInput {
            path: "libraries/example/input.jar".into(),
            size: bytes.len() as u64,
            sha1: Some(sha1),
            sha256: sha256.clone(),
            official: true,
        };
        let object = verify_existing_object(
            &cas_root,
            &ExpectedObject {
                sha256: sha256.clone(),
                size: bytes.len() as u64,
            },
            0,
        )
        .expect("verify CAS fixture");
        assert!(copy_official_input(&inputs, &other_cas_root, &expected, &object).is_err());
        let alias = root.join("hardlink-alias");
        if fs::hard_link(&source, &alias).is_ok() {
            assert!(copy_official_input(&inputs, &cas_root, &expected, &object).is_err());
        }
        drop(other_cas_root);
        drop(cas_root);
        fs::remove_dir_all(other_install).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn input_state_is_sorted_and_changes_on_any_signed_field() {
        let a = ExpectedInput {
            path: "z/input.jar".into(),
            size: 1,
            sha1: Some("1".repeat(40)),
            sha256: "a".repeat(64),
            official: true,
        };
        let b = ExpectedInput {
            path: "a/input.jar".into(),
            size: 2,
            sha1: Some("2".repeat(40)),
            sha256: "b".repeat(64),
            official: true,
        };
        let forward = compute_input_state_sha256([&a, &b]).unwrap();
        let reverse = compute_input_state_sha256([&b, &a]).unwrap();
        assert_eq!(forward, reverse);
        let mut changed = b.clone();
        changed.size += 1;
        assert_ne!(forward, compute_input_state_sha256([&a, &changed]).unwrap());
    }

    #[test]
    fn fresh_workspace_layout_rejects_output_temp_and_state_extras() {
        let root = temp_root("layout");
        for component in WORKSPACE_LAYOUT {
            fs::create_dir_all(root.join(component)).unwrap();
        }
        fs::write(root.join("state").join(STATE_MARKER_PATH), b"{}").unwrap();
        validate_workspace_layout(&root, b"{}").expect("fresh layout");

        fs::write(root.join("outputs/unexpected.bin"), b"x").unwrap();
        assert!(validate_workspace_layout(&root, b"{}").is_err());
        fs::remove_file(root.join("outputs/unexpected.bin")).unwrap();

        fs::write(root.join("temp/unexpected.bin"), b"x").unwrap();
        assert!(validate_workspace_layout(&root, b"{}").is_err());
        fs::remove_file(root.join("temp/unexpected.bin")).unwrap();

        fs::write(root.join("state/unexpected.json"), b"{}").unwrap();
        assert!(validate_workspace_layout(&root, b"{}").is_err());
        fs::remove_file(root.join("state/unexpected.json")).unwrap();
        fs::write(root.join("state").join(STATE_MARKER_PATH), b"{ }").unwrap();
        assert!(validate_workspace_layout(&root, b"{}").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn execution_scratch_allows_bounded_files_but_rejects_links_and_state_drift() {
        let root = temp_root("execution-scratch");
        for component in WORKSPACE_LAYOUT {
            fs::create_dir_all(root.join(component)).unwrap();
        }
        fs::write(root.join("state").join(STATE_MARKER_PATH), b"marker").unwrap();
        ensure_directory_chain(&root, &RelativeManagedPath::new(USER_HOME_PATH).unwrap()).unwrap();
        validate_workspace_top_level(&root).unwrap();
        validate_execution_state_directory(&root, b"marker").unwrap();

        fs::write(root.join("state/user-home/unexpected"), b"x").unwrap();
        validate_execution_state_directory(&root, b"marker").unwrap();
        fs::hard_link(
            root.join("state/user-home/unexpected"),
            root.join("state/user-home/alias"),
        )
        .unwrap();
        assert!(validate_execution_state_directory(&root, b"marker").is_err());
        fs::remove_file(root.join("state/user-home/alias")).unwrap();
        fs::remove_file(root.join("state/user-home/unexpected")).unwrap();

        let read_only = root.join("state/user-home/read-only");
        fs::write(&read_only, b"x").unwrap();
        let mut permissions = fs::metadata(&read_only).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&read_only, permissions).unwrap();
        assert!(validate_execution_state_directory(&root, b"marker").is_err());
        let mut permissions = fs::metadata(&read_only).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&read_only, permissions).unwrap();
        fs::remove_file(read_only).unwrap();

        fs::write(root.join("state/unexpected"), b"x").unwrap();
        assert!(validate_execution_state_directory(&root, b"marker").is_err());
        fs::remove_file(root.join("state/unexpected")).unwrap();

        fs::write(root.join("state").join(STATE_MARKER_PATH), b"changed").unwrap();
        assert!(validate_execution_state_directory(&root, b"marker").is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn zip_inspection_leaves_archive_position_reopenable() {
        let patch = b"patch";
        let bytes = zip_bytes(&[(CLIENT_PATCH_ARCHIVE_PATH, patch, None)]);
        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        let index = inspect_installer_zip(&mut archive, &patch_declaration(patch)).unwrap();
        let mut entry = archive.by_index(index).unwrap();
        let mut extracted = Vec::new();
        entry.read_to_end(&mut extracted).unwrap();
        assert_eq!(extracted, patch);
    }
}
