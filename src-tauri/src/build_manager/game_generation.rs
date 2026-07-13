use super::{
    artifact_plan::{ArtifactInventoryV2, PlannedGameGenerationBindingV2, PlannedGameGenerationV2},
    contracts::{
        domain_digest, is_sha256, GameRuntimeFile, GameRuntimeLock, GameRuntimeRole,
        GameRuntimeSource, OfflineProcessorVerification,
    },
    game_runtime_executor::ProcessorExecutionResult,
    managed_fs::{
        atomic_write_small, ensure_directory_chain, move_managed_directory_no_replace_if,
        open_or_create_lock_file, quarantine_node_if_identity,
        remove_bounded_managed_directory_tree, ConditionalManagedDirectoryMoveOutcome,
        ExclusiveManagedFile, FileIdentity, GuardedDirectoryChain, ImmutableManagedFile,
        ManagedDirectoryRemovalLimits, ManagedFsError, ManagedLockFile, ManagedNodeKind,
        RecursiveChangeSentinel, RelativeManagedPath,
    },
    storage::{is_windows_reparse_point, OwnedCasRoot},
};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt, fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};
use uuid::Uuid;

const GENERATION_SCHEMA_VERSION: u8 = 1;
const GENERATION_DOMAIN: &str = "ru.fragmc.launcher.game-runtime-generation.v1";
const TREE_DIGEST_DOMAIN: &str = "ru.fragmc.launcher.game-runtime-tree.v1";
const OUTPUTS_DIGEST_DOMAIN: &str = "ru.fragmc.launcher.game-runtime.outputs.v1";
const GENERATION_MARKER: &str = "generation.json";
const MAX_MARKER_BYTES: u64 = 64 * 1024;
const MAX_TREE_ENTRIES: usize = 8_192;
const MAX_STALE_PROCESSOR_WORKSPACES: usize = 128;
const PROCESSOR_WORKSPACE_GC_MAX_ENTRIES: usize = 2_048;
const PROCESSOR_WORKSPACE_GC_MAX_DEPTH: usize = PROCESSOR_WORKSPACE_GC_MAX_ENTRIES;
// Product-wide, release-independent cleanup ceiling. Valid runtime locks are capped at 16 GiB;
// this additionally covers signed transient processor artifacts, both scratch trees and worst-
// case allocation-unit overhead for the bounded 2,048-node workspace. Using the current release's
// calculated budget here would make a smaller future release unable to collect a larger old one.
const PROCESSOR_WORKSPACE_GC_MAX_ALLOCATED_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const PROCESSOR_WORKSPACE_LOCK: &str = "runtime/minecraft/locks/processor-workspaces.lock";
const MAX_GAME_QUARANTINE_BUCKETS: usize = 8;
const GAME_QUARANTINE_GC_LIMITS: ManagedDirectoryRemovalLimits = ManagedDirectoryRemovalLimits {
    max_entries: 20_000,
    max_allocated_bytes: 64 * 1024 * 1024 * 1024,
    max_depth: 256,
};
const PINNED_FILE_COUNT: usize = 4_012;
const PINNED_OFFICIAL_COUNT: usize = 4_006;
const PINNED_DERIVED_COUNT: usize = 6;

#[derive(Debug)]
pub(super) enum GameGenerationError {
    Cancelled,
    Failed(String),
    AppliedButDurabilityUnconfirmed { destination: String, detail: String },
}

impl fmt::Display for GameGenerationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("Game generation was cancelled"),
            Self::Failed(message) => formatter.write_str(message),
            Self::AppliedButDurabilityUnconfirmed {
                destination,
                detail,
            } => write!(
                formatter,
                "game_generation_durability_unconfirmed: publication reached {destination}, but durability is unconfirmed: {detail}"
            ),
        }
    }
}

impl std::error::Error for GameGenerationError {}

impl From<String> for GameGenerationError {
    fn from(value: String) -> Self {
        Self::Failed(value)
    }
}

impl From<&str> for GameGenerationError {
    fn from(value: &str) -> Self {
        Self::Failed(value.to_owned())
    }
}

fn managed_error(context: &str, error: ManagedFsError) -> GameGenerationError {
    match error {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination,
            detail,
        } => GameGenerationError::AppliedButDurabilityUnconfirmed {
            destination: destination.display().to_string(),
            detail: format!("{context}: {detail}"),
        },
        other => GameGenerationError::Failed(format!("{context}: {other}")),
    }
}

type GenerationResult<T> = Result<T, GameGenerationError>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedGameFile {
    path: String,
    role: GameRuntimeRole,
    source_kind: &'static str,
    size: u64,
    sha1: String,
    sha256: String,
}

impl ExpectedGameFile {
    fn from_signed(file: &GameRuntimeFile) -> Self {
        let (source_kind, size, sha1, sha256) = match &file.source {
            GameRuntimeSource::Official {
                size, sha1, sha256, ..
            } => ("official", *size, sha1.clone(), sha256.clone()),
            GameRuntimeSource::Derived {
                size, sha1, sha256, ..
            } => ("derived", *size, sha1.clone(), sha256.clone()),
        };
        Self {
            path: file.path.clone(),
            role: file.role,
            source_kind,
            size,
            sha1,
            sha256,
        }
    }

    fn is_official(&self) -> bool {
        self.source_kind == "official"
    }

    fn is_derived(&self) -> bool {
        self.source_kind == "derived"
    }
}

#[derive(Clone, Debug)]
struct ExpectedGameTree {
    files: BTreeMap<String, ExpectedGameFile>,
    directories: BTreeMap<String, String>,
    tree_sha256: String,
    total_bytes: u64,
    processor_receipt_sha256: String,
    processor_outputs_sha256: String,
}

impl ExpectedGameTree {
    fn from_lock(lock: &GameRuntimeLock) -> Result<Self, String> {
        lock.validate()?;
        let mut files = BTreeMap::new();
        let mut canonical = Vec::with_capacity(lock.files.len());
        let mut directories = BTreeMap::new();
        let mut official_count = 0_usize;
        let mut derived_count = 0_usize;
        let mut total_bytes = 0_u64;
        for file in &lock.files {
            let expected = ExpectedGameFile::from_signed(file);
            let managed = RelativeManagedPath::new(&expected.path)
                .map_err(|error| format!("Signed game path is unsafe: {error}"))?;
            if managed.as_str() != expected.path {
                return Err("Signed game path is not canonical".into());
            }
            register_expected_directories(&managed, &mut directories)?;
            if files
                .insert(managed.collision_key().to_owned(), expected.clone())
                .is_some()
            {
                return Err("Signed game tree contains a Windows path collision".into());
            }
            if expected.is_official() {
                official_count += 1;
            } else if expected.is_derived() {
                derived_count += 1;
            }
            total_bytes = total_bytes
                .checked_add(expected.size)
                .ok_or_else(|| "Signed game tree byte total overflowed".to_string())?;
            canonical.push(expected);
        }
        canonical.sort_by(|left, right| left.path.cmp(&right.path));
        if canonical.len() != PINNED_FILE_COUNT
            || official_count != PINNED_OFFICIAL_COUNT
            || derived_count != PINNED_DERIVED_COUNT
        {
            return Err("Game generation is not the pinned 4,006+6 file set".into());
        }
        let tree_sha256 = domain_digest(TREE_DIGEST_DOMAIN, &canonical)?;
        let OfflineProcessorVerification::Verified {
            receipt_sha256,
            consensus_outputs,
            ..
        } = &lock.verification.offline_processors
        else {
            return Err("Game generation requires a verified processor receipt".into());
        };
        let processor_outputs_sha256 = domain_digest(OUTPUTS_DIGEST_DOMAIN, consensus_outputs)?;
        Ok(Self {
            files,
            directories,
            tree_sha256,
            total_bytes,
            processor_receipt_sha256: receipt_sha256.clone(),
            processor_outputs_sha256,
        })
    }

    fn expected(&self, path: &str) -> Result<&ExpectedGameFile, String> {
        let managed = RelativeManagedPath::new(path)
            .map_err(|error| format!("Game generation path is unsafe: {error}"))?;
        self.files
            .get(managed.collision_key())
            .filter(|expected| expected.path == managed.as_str())
            .ok_or_else(|| format!("Game generation path is not signed: {path}"))
    }
}

fn register_expected_directories(
    file: &RelativeManagedPath,
    directories: &mut BTreeMap<String, String>,
) -> Result<(), String> {
    let mut parent = file.parent();
    while let Some(directory) = parent {
        let key = directory.collision_key().to_owned();
        if let Some(existing) = directories.insert(key, directory.as_str().to_owned()) {
            if existing != directory.as_str() {
                return Err("Signed game directory contains a Windows path collision".into());
            }
        }
        parent = directory.parent();
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GameGenerationMarker {
    schema_version: u8,
    domain: String,
    game_runtime_lock_sha256: String,
    game_runtime_id: String,
    java_runtime_lock_sha256: String,
    processor_receipt_sha256: String,
    processor_outputs_sha256: String,
    file_count: usize,
    official_file_count: usize,
    derived_file_count: usize,
    total_bytes: u64,
    tree_sha256: String,
}

impl GameGenerationMarker {
    fn expected(
        tree: &ExpectedGameTree,
        game_lock: &GameRuntimeLock,
        game_lock_sha256: &str,
        runtime_lock_sha256: &str,
    ) -> Self {
        Self {
            schema_version: GENERATION_SCHEMA_VERSION,
            domain: GENERATION_DOMAIN.to_owned(),
            game_runtime_lock_sha256: game_lock_sha256.to_owned(),
            game_runtime_id: game_lock.id.clone(),
            java_runtime_lock_sha256: runtime_lock_sha256.to_owned(),
            processor_receipt_sha256: tree.processor_receipt_sha256.clone(),
            processor_outputs_sha256: tree.processor_outputs_sha256.clone(),
            file_count: PINNED_FILE_COUNT,
            official_file_count: PINNED_OFFICIAL_COUNT,
            derived_file_count: PINNED_DERIVED_COUNT,
            total_bytes: tree.total_bytes,
            tree_sha256: tree.tree_sha256.clone(),
        }
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut bytes = serde_json::to_vec(self)
            .map_err(|error| format!("Cannot serialize game generation marker: {error}"))?;
        bytes.push(b'\n');
        if bytes.len() as u64 > MAX_MARKER_BYTES {
            return Err("Game generation marker exceeds the launcher limit".into());
        }
        Ok(bytes)
    }
}

struct GenerationAuditLease {
    generation: PathBuf,
    image: PathBuf,
    expected: ExpectedGameTree,
    marker: ImmutableManagedFile,
    files: BTreeMap<String, ImmutableManagedFile>,
    _generation_guard: GuardedDirectoryChain,
    _image_guard: GuardedDirectoryChain,
    namespace_guards: Vec<GuardedDirectoryChain>,
    change_sentinel: RecursiveChangeSentinel,
}

impl GenerationAuditLease {
    fn revalidate(&self, expected_marker: &[u8]) -> Result<(), String> {
        self.revalidate_sentinel()?;
        self._generation_guard
            .revalidate()
            .map_err(|error| format!("Game generation root changed: {error}"))?;
        self._image_guard
            .revalidate()
            .map_err(|error| format!("Game generation image changed: {error}"))?;
        for guard in &self.namespace_guards {
            guard
                .revalidate()
                .map_err(|error| format!("Game generation namespace guard changed: {error}"))?;
        }
        if !audit_generation_root_namespace(&self.generation)? {
            return Err("Game generation marker disappeared".into());
        }
        let namespace = scan_image(&self.image, &self.expected, false)?;
        let expected_files = self.expected.files.keys().cloned().collect::<BTreeSet<_>>();
        let expected_directories = self
            .expected
            .directories
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if namespace.seen_files != expected_files
            || namespace.seen_directories != expected_directories
        {
            return Err("Game generation namespace changed while leased".into());
        }
        self.marker
            .revalidate()
            .map_err(|error| format!("Game generation marker changed: {error}"))?;
        let marker_relative = RelativeManagedPath::new(GENERATION_MARKER)
            .expect("static generation marker path is valid");
        let reopened_marker = ImmutableManagedFile::open(&self.generation, &marker_relative)
            .map_err(|error| format!("Cannot reopen game generation marker: {error}"))?;
        if reopened_marker.info().identity != self.marker.info().identity
            || reopened_marker.info().size != self.marker.info().size
            || self.marker.info().size != expected_marker.len() as u64
        {
            return Err("Game generation marker identity/size changed".into());
        }
        if self.files.len() != self.expected.files.len() {
            return Err("Game generation file lease coverage changed".into());
        }
        for (key, expected) in &self.expected.files {
            let file = self
                .files
                .get(key)
                .ok_or_else(|| format!("Game generation lease is missing: {}", expected.path))?;
            file.revalidate()
                .map_err(|error| format!("Game generation lease changed: {error}"))?;
            let relative = RelativeManagedPath::new(&expected.path)
                .map_err(|error| format!("Signed game path is unsafe: {error}"))?;
            let reopened = ImmutableManagedFile::open(&self.image, &relative)
                .map_err(|error| format!("Cannot reopen game file {}: {error}", expected.path))?;
            if file.info().size != expected.size
                || reopened.info().size != expected.size
                || reopened.info().identity != file.info().identity
            {
                return Err(format!(
                    "Game generation file identity/size changed: {}",
                    expected.path
                ));
            }
        }
        self.revalidate_sentinel()?;
        Ok(())
    }

    fn revalidate_sentinel(&self) -> Result<(), String> {
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| format!("Game generation changed after full audit: {error}"))
    }
}

/// Live authority for one completely audited immutable Minecraft/NeoForge generation.
/// It is deliberately non-Clone and retains handle-bound leases for the exact namespace.
pub(super) struct GameRuntimeInstallation {
    generation: PathBuf,
    image: PathBuf,
    install_id: Uuid,
    root_binding_nonce: Uuid,
    inventory_fingerprint: String,
    game_runtime_lock_sha256: String,
    marker_bytes: Vec<u8>,
    lease: GenerationAuditLease,
}

impl fmt::Debug for GameRuntimeInstallation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("GameRuntimeInstallation")
            .field("generation", &self.generation)
            .field("image", &self.image)
            .field("install_id", &self.install_id)
            .field("game_runtime_lock_sha256", &self.game_runtime_lock_sha256)
            .finish_non_exhaustive()
    }
}

impl GameRuntimeInstallation {
    pub(super) fn generation(&self) -> &Path {
        &self.generation
    }

    pub(super) fn image(&self) -> &Path {
        &self.image
    }

    pub(super) fn game_runtime_lock_sha256(&self) -> &str {
        &self.game_runtime_lock_sha256
    }

    pub(super) fn install_id(&self) -> Uuid {
        self.install_id
    }

    pub(super) fn root_binding_nonce(&self) -> Uuid {
        self.root_binding_nonce
    }

    pub(super) fn inventory_fingerprint(&self) -> &str {
        &self.inventory_fingerprint
    }

    /// Revalidates the handle-bound generation and proves that `lock` describes the same exact
    /// game tree. This deliberately accepts no filesystem root: callers cannot transplant the
    /// live installation authority onto another directory.
    pub(super) fn revalidate_against_lock(&self, lock: &GameRuntimeLock) -> Result<(), String> {
        let expected = ExpectedGameTree::from_lock(lock)?;
        if expected.tree_sha256 != self.lease.expected.tree_sha256
            || expected.total_bytes != self.lease.expected.total_bytes
            || expected.processor_receipt_sha256 != self.lease.expected.processor_receipt_sha256
            || expected.processor_outputs_sha256 != self.lease.expected.processor_outputs_sha256
            || expected.files.len() != self.lease.expected.files.len()
            || expected.directories.len() != self.lease.expected.directories.len()
        {
            return Err("Game runtime lock does not describe this installed generation".into());
        }
        self.lease.revalidate(&self.marker_bytes)
    }

    /// Returns the launcher-owned install root only after proving the canonical generation
    /// layout. The root is derived from the sealed installation, never supplied by a caller.
    pub(super) fn install_root(&self) -> Result<&Path, String> {
        use std::ffi::OsStr;

        if self.image != self.generation.join("image")
            || self.generation.file_name() != Some(OsStr::new(&self.game_runtime_lock_sha256))
        {
            return Err("Game runtime installation path binding is invalid".into());
        }
        let generations = self
            .generation
            .parent()
            .filter(|path| path.file_name() == Some(OsStr::new("generations")))
            .ok_or_else(|| "Game runtime generation is outside its canonical layout".to_string())?;
        let minecraft = generations
            .parent()
            .filter(|path| path.file_name() == Some(OsStr::new("minecraft")))
            .ok_or_else(|| "Game runtime generation is outside its canonical layout".to_string())?;
        let runtime = minecraft
            .parent()
            .filter(|path| path.file_name() == Some(OsStr::new("runtime")))
            .ok_or_else(|| "Game runtime generation is outside its canonical layout".to_string())?;
        let root = runtime
            .parent()
            .ok_or_else(|| "Game runtime install root is missing".to_string())?;
        if !root.is_absolute() {
            return Err("Game runtime install root is not absolute".into());
        }
        Ok(root)
    }
}

pub(super) struct GameGenerationBuild<'root, 'plan> {
    root: &'root OwnedCasRoot,
    planned: PlannedGameGenerationV2<'plan>,
    staging_relative: RelativeManagedPath,
    workspaces_root: PathBuf,
    processor_workspace_gc_limits: ManagedDirectoryRemovalLimits,
    quarantine_bucket: Option<GameQuarantineBucket>,
    _operation_lock: ManagedLockFile,
    _processor_workspace_lock: ManagedLockFile,
}

struct GameQuarantineBucket {
    relative: RelativeManagedPath,
    identity: FileIdentity,
}

pub(super) struct GameGenerationProcessorBuild<'root, 'plan> {
    build: GameGenerationBuild<'root, 'plan>,
    workspace_name: String,
}

pub(super) struct GameGenerationReady<'root, 'plan> {
    build: GameGenerationBuild<'root, 'plan>,
}

pub(super) enum BeginGameGeneration<'root, 'plan> {
    Installed(GameRuntimeInstallation),
    Build(GameGenerationBuild<'root, 'plan>),
}

pub(super) enum StagedGameGeneration<'root, 'plan> {
    Ready(GameGenerationReady<'root, 'plan>),
    NeedsProcessors(GameGenerationProcessorBuild<'root, 'plan>),
}

impl GameGenerationProcessorBuild<'_, '_> {
    pub(super) fn authority(&self) -> &PlannedGameGenerationV2<'_> {
        &self.build.planned
    }

    pub(super) fn root(&self) -> &OwnedCasRoot {
        self.build.root
    }

    pub(super) fn workspaces_root(&self) -> &Path {
        &self.build.workspaces_root
    }

    pub(super) fn workspace_name(&self) -> &str {
        &self.workspace_name
    }

    pub(super) fn generation_binding(&self) -> PlannedGameGenerationBindingV2 {
        self.build.planned.binding()
    }

    pub(super) fn generation_binding_sha256(&self) -> &str {
        self.build.planned.binding_digest()
    }

    pub(super) fn game_runtime_lock(&self) -> &GameRuntimeLock {
        self.build.planned.game_runtime_lock()
    }

    pub(super) fn game_runtime_lock_sha256(&self) -> &str {
        self.build.planned.game_runtime_lock_sha256()
    }

    pub(super) fn remove_processor_workspace(
        &self,
        expected_identity: &FileIdentity,
    ) -> Result<(), String> {
        let workspace = RelativeManagedPath::new(&format!(
            "runtime/minecraft/workspaces/{}",
            self.workspace_name()
        ))
        .map_err(|error| format!("Processor workspace cleanup path is unsafe: {error}"))?;
        remove_bounded_managed_directory_tree(
            self.root().install_root(),
            &workspace,
            expected_identity,
            self.build.processor_workspace_gc_limits,
        )
        .map_err(|error| format!("Cannot remove completed processor workspace: {error}"))?;
        self.build._operation_lock.revalidate().map_err(|error| {
            format!("Game generation lock changed after workspace cleanup: {error}")
        })?;
        self.build
            ._processor_workspace_lock
            .revalidate()
            .map_err(|error| format!("Processor workspace lock changed after cleanup: {error}"))?;
        Ok(())
    }
}

#[derive(Debug)]
struct PartialGenerationAudit {
    present_files: BTreeSet<String>,
    marker_complete: bool,
}

fn generation_relative(kind: &str, game_lock_sha256: &str) -> Result<RelativeManagedPath, String> {
    RelativeManagedPath::new(&format!("runtime/minecraft/{kind}/{game_lock_sha256}"))
        .map_err(|error| format!("Cannot construct game generation path: {error}"))
}

fn image_relative(
    generation: &RelativeManagedPath,
    path: &str,
) -> Result<RelativeManagedPath, String> {
    let file = RelativeManagedPath::new(path)
        .map_err(|error| format!("Cannot construct signed game image path: {error}"))?;
    RelativeManagedPath::new(&format!("{}/image/{}", generation.as_str(), file.as_str()))
        .map_err(|error| format!("Cannot construct game staging destination: {error}"))
}

fn marker_relative(generation: &RelativeManagedPath) -> Result<RelativeManagedPath, String> {
    RelativeManagedPath::new(&format!("{}/{GENERATION_MARKER}", generation.as_str()))
        .map_err(|error| format!("Cannot construct game marker path: {error}"))
}

fn path_exists_nofollow(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!(
            "Cannot inspect managed game path {}: {error}",
            path.display()
        )),
    }
}

fn verify_real_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect {label} {}: {error}", path.display()))?;
    if !metadata.is_dir()
        || metadata.file_type().is_symlink()
        || is_windows_reparse_point(&metadata)
    {
        return Err(format!(
            "{label} is not a real directory: {}",
            path.display()
        ));
    }
    Ok(())
}

fn relative_image_path(image: &Path, absolute: &Path) -> Result<String, String> {
    absolute
        .strip_prefix(image)
        .map_err(|_| "Game image entry escaped its root".to_string())?
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| "Game image path is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

struct ImageScan<'a> {
    image: &'a Path,
    expected: &'a ExpectedGameTree,
    seen_files: BTreeSet<String>,
    seen_directories: BTreeSet<String>,
    leases: BTreeMap<String, ImmutableManagedFile>,
    entries: usize,
    hash_files: bool,
}

impl ImageScan<'_> {
    fn scan(&mut self, directory: &Path) -> Result<(), String> {
        for entry in fs::read_dir(directory)
            .map_err(|error| format!("Cannot enumerate game image: {error}"))?
        {
            self.entries = self
                .entries
                .checked_add(1)
                .ok_or_else(|| "Game image entry count overflowed".to_string())?;
            if self.entries > MAX_TREE_ENTRIES {
                return Err("Game image exceeds the launcher entry limit".into());
            }
            let entry =
                entry.map_err(|error| format!("Cannot inspect game image entry: {error}"))?;
            let absolute = entry.path();
            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|error| format!("Cannot inspect game image metadata: {error}"))?;
            if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
                return Err(format!(
                    "Link/reparse point is forbidden in game image: {}",
                    absolute.display()
                ));
            }
            let relative = relative_image_path(self.image, &absolute)?;
            let managed = RelativeManagedPath::new(&relative)
                .map_err(|error| format!("Game image path is unsafe: {error}"))?;
            let key = managed.collision_key().to_owned();
            if metadata.is_dir() {
                let canonical = self
                    .expected
                    .directories
                    .get(&key)
                    .ok_or_else(|| format!("Unexpected directory in game image: {relative}"))?;
                if canonical != managed.as_str() || !self.seen_directories.insert(key) {
                    return Err(format!(
                        "Game image directory casing/collision mismatch: {relative}"
                    ));
                }
                let guard = GuardedDirectoryChain::open(self.image, &managed)
                    .map_err(|error| format!("Game image directory is unsafe: {error}"))?;
                guard
                    .revalidate()
                    .map_err(|error| format!("Game image directory changed: {error}"))?;
                self.scan(&absolute)?;
            } else if metadata.is_file() {
                let expected = self
                    .expected
                    .files
                    .get(&key)
                    .ok_or_else(|| format!("Unexpected file in game image: {relative}"))?;
                if expected.path != managed.as_str() || !self.seen_files.insert(key.clone()) {
                    return Err(format!(
                        "Game image file casing/collision mismatch: {relative}"
                    ));
                }
                if self.hash_files {
                    let mut file = ImmutableManagedFile::open(self.image, &managed)
                        .map_err(|error| format!("Game image file is unsafe: {error}"))?;
                    let digest = file
                        .sha1_sha256(expected.size)
                        .map_err(|error| format!("Cannot hash game image file: {error}"))?;
                    if digest.size != expected.size
                        || digest.sha1 != expected.sha1
                        || digest.sha256 != expected.sha256
                    {
                        return Err(format!("Game image file identity mismatch: {relative}"));
                    }
                    if self.leases.insert(key, file).is_some() {
                        return Err("Game image file lease map is duplicated".into());
                    }
                }
            } else {
                return Err(format!(
                    "Special file is forbidden in game image: {}",
                    absolute.display()
                ));
            }
        }
        Ok(())
    }
}

fn scan_image<'a>(
    image: &'a Path,
    expected: &'a ExpectedGameTree,
    hash_files: bool,
) -> Result<ImageScan<'a>, String> {
    verify_real_directory(image, "Game image")?;
    let mut scan = ImageScan {
        image,
        expected,
        seen_files: BTreeSet::new(),
        seen_directories: BTreeSet::new(),
        leases: BTreeMap::new(),
        entries: 0,
        hash_files,
    };
    scan.scan(image)?;
    Ok(scan)
}

fn audit_generation_root_namespace(root: &Path) -> Result<bool, String> {
    let mut image = false;
    let mut marker = false;
    let mut entries = 0_usize;
    for entry in fs::read_dir(root)
        .map_err(|error| format!("Cannot enumerate game generation root: {error}"))?
    {
        entries += 1;
        if entries > 2 {
            return Err("Game generation root contains unexpected entries".into());
        }
        let entry =
            entry.map_err(|error| format!("Cannot inspect game generation root: {error}"))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "Game generation root entry is not UTF-8".to_string())?
            .to_owned();
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Cannot inspect game generation root entry: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err("Link/reparse point is forbidden in game generation root".into());
        }
        match name.as_str() {
            "image" if metadata.is_dir() && !image => image = true,
            GENERATION_MARKER if metadata.is_file() && !marker => marker = true,
            _ => return Err(format!("Unexpected game generation root entry: {name}")),
        }
    }
    if !image {
        return Err("Game generation image directory is missing".into());
    }
    Ok(marker)
}

fn read_exact_marker(
    generation_root: &Path,
    expected_marker: &GameGenerationMarker,
) -> Result<(ImmutableManagedFile, Vec<u8>), String> {
    let relative = RelativeManagedPath::new(GENERATION_MARKER)
        .expect("static generation marker path is valid");
    let mut marker = ImmutableManagedFile::open(generation_root, &relative)
        .map_err(|error| format!("Game generation marker is unsafe: {error}"))?;
    let bytes = marker
        .read_bounded(MAX_MARKER_BYTES)
        .map_err(|error| format!("Cannot read game generation marker: {error}"))?;
    let parsed: GameGenerationMarker = serde_json::from_slice(&bytes)
        .map_err(|error| format!("Game generation marker is invalid: {error}"))?;
    if &parsed != expected_marker || bytes != expected_marker.canonical_bytes()? {
        return Err("Game generation marker does not match the signed runtime".into());
    }
    Ok((marker, bytes))
}

fn acquire_generation_namespace_guards(
    generation: &Path,
    image: &Path,
    expected: &ExpectedGameTree,
) -> Result<Vec<GuardedDirectoryChain>, String> {
    let mut guards = Vec::with_capacity(expected.directories.len() + 2);
    guards.push(
        GuardedDirectoryChain::root_snapshot(generation)
            .map_err(|error| format!("Game generation namespace is unsafe: {error}"))?,
    );
    guards.push(
        GuardedDirectoryChain::root_snapshot(image)
            .map_err(|error| format!("Game image namespace is unsafe: {error}"))?,
    );
    for directory in expected.directories.values() {
        let relative = RelativeManagedPath::new(directory)
            .map_err(|error| format!("Signed game directory path is unsafe: {error}"))?;
        let absolute = relative.join_to(image);
        guards.push(
            GuardedDirectoryChain::root_snapshot(&absolute)
                .map_err(|error| format!("Signed game directory is unsafe: {error}"))?,
        );
    }
    Ok(guards)
}

fn audit_complete_generation(
    install_root: &Path,
    relative: &RelativeManagedPath,
    expected: &ExpectedGameTree,
    expected_marker: &GameGenerationMarker,
) -> Result<Option<(GenerationAuditLease, Vec<u8>)>, String> {
    let absolute = relative.join_to(install_root);
    if !path_exists_nofollow(&absolute)? {
        return Ok(None);
    }
    verify_real_directory(&absolute, "Game generation")?;
    if !audit_generation_root_namespace(&absolute)? {
        return Err("Complete game generation marker is missing".into());
    }
    let generation_guard = GuardedDirectoryChain::open(install_root, relative)
        .map_err(|error| format!("Game generation root is unsafe: {error}"))?;
    let image_relative = RelativeManagedPath::new(&format!("{}/image", relative.as_str()))
        .map_err(|error| format!("Cannot construct game image path: {error}"))?;
    let image_guard = GuardedDirectoryChain::open(install_root, &image_relative)
        .map_err(|error| format!("Game generation image is unsafe: {error}"))?;
    let image = image_guard.leaf().path().to_path_buf();
    let change_sentinel = RecursiveChangeSentinel::arm(&absolute)
        .map_err(|error| format!("Cannot arm game generation change sentinel: {error}"))?;
    let first = scan_image(&image, expected, true)?;
    let expected_files = expected.files.keys().cloned().collect::<BTreeSet<_>>();
    let expected_directories = expected
        .directories
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    if first.seen_files != expected_files || first.seen_directories != expected_directories {
        return Err("Game generation file/directory inventory is incomplete".into());
    }
    // Freeze every directory namespace before the confirming scan. The first scan may race while
    // these handles are acquired; the second scan runs only after all 537 snapshot guards are
    // live, so no accepted directory can gain/remove/rename a child afterwards.
    let namespace_guards = acquire_generation_namespace_guards(&absolute, &image, expected)?;
    let second = scan_image(&image, expected, false)?;
    if second.seen_files != first.seen_files || second.seen_directories != first.seen_directories {
        return Err("Game generation namespace changed during audit".into());
    }
    if !audit_generation_root_namespace(&absolute)? {
        return Err("Game generation marker disappeared during audit".into());
    }
    let (marker, marker_bytes) = read_exact_marker(&absolute, expected_marker)?;
    let lease = GenerationAuditLease {
        generation: absolute,
        image: image.clone(),
        expected: expected.clone(),
        marker,
        files: first.leases,
        _generation_guard: generation_guard,
        _image_guard: image_guard,
        namespace_guards,
        change_sentinel,
    };
    lease.revalidate(&marker_bytes)?;
    Ok(Some((lease, marker_bytes)))
}

fn audit_partial_generation(
    install_root: &Path,
    relative: &RelativeManagedPath,
    expected: &ExpectedGameTree,
    expected_marker: &GameGenerationMarker,
) -> Result<PartialGenerationAudit, String> {
    let absolute = relative.join_to(install_root);
    verify_real_directory(&absolute, "Game generation staging")?;
    let marker_present = audit_generation_root_namespace(&absolute)?;
    let image = absolute.join("image");
    let first = scan_image(&image, expected, true)?;
    let second = scan_image(&image, expected, false)?;
    if second.seen_files != first.seen_files || second.seen_directories != first.seen_directories {
        return Err("Game staging namespace changed during audit".into());
    }
    if marker_present {
        let _ = read_exact_marker(&absolute, expected_marker)?;
        let expected_files = expected.files.keys().cloned().collect::<BTreeSet<_>>();
        let expected_directories = expected
            .directories
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        if first.seen_files != expected_files || first.seen_directories != expected_directories {
            return Err("Marked game staging tree is not exact and complete".into());
        }
    }
    Ok(PartialGenerationAudit {
        present_files: first.seen_files,
        marker_complete: marker_present,
    })
}

fn generation_contract_from_plan(
    planned: &PlannedGameGenerationV2<'_>,
) -> Result<(ExpectedGameTree, GameGenerationMarker), String> {
    let tree = ExpectedGameTree::from_lock(planned.game_runtime_lock())?;
    let marker = GameGenerationMarker::expected(
        &tree,
        planned.game_runtime_lock(),
        planned.game_runtime_lock_sha256(),
        planned.runtime_lock_sha256(),
    );
    Ok((tree, marker))
}

fn generation_contract_from_inventory(
    inventory: &ArtifactInventoryV2,
) -> Result<(ExpectedGameTree, GameGenerationMarker), String> {
    let tree = ExpectedGameTree::from_lock(inventory.game_runtime_lock())?;
    let marker = GameGenerationMarker::expected(
        &tree,
        inventory.game_runtime_lock(),
        inventory.game_runtime_lock_sha256(),
        inventory.java_runtime_lock_sha256(),
    );
    Ok((tree, marker))
}

fn installation_from_plan(
    root: &OwnedCasRoot,
    planned: &PlannedGameGenerationV2<'_>,
    relative: &RelativeManagedPath,
    lease: GenerationAuditLease,
    marker_bytes: Vec<u8>,
) -> GameRuntimeInstallation {
    let generation = relative.join_to(root.install_root());
    GameRuntimeInstallation {
        image: generation.join("image"),
        generation,
        install_id: planned.install_id(),
        root_binding_nonce: planned.root_binding_nonce(),
        inventory_fingerprint: planned.inventory_fingerprint().to_owned(),
        game_runtime_lock_sha256: planned.game_runtime_lock_sha256().to_owned(),
        marker_bytes,
        lease,
    }
}

fn installation_from_inventory(
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
    relative: &RelativeManagedPath,
    lease: GenerationAuditLease,
    marker_bytes: Vec<u8>,
) -> GameRuntimeInstallation {
    let generation = relative.join_to(root.install_root());
    GameRuntimeInstallation {
        image: generation.join("image"),
        generation,
        install_id: inventory.install_id(),
        root_binding_nonce: inventory.root_binding_nonce(),
        inventory_fingerprint: inventory.fingerprint().to_owned(),
        game_runtime_lock_sha256: inventory.game_runtime_lock_sha256().to_owned(),
        marker_bytes,
        lease,
    }
}

fn ensure_generation_layout(root: &OwnedCasRoot) -> GenerationResult<()> {
    for path in [
        "runtime/minecraft/generations",
        "runtime/minecraft/staging",
        "runtime/minecraft/incoming",
        "runtime/minecraft/workspaces",
        "runtime/minecraft/locks",
        "runtime/minecraft/quarantine",
    ] {
        let relative = RelativeManagedPath::new(path)
            .map_err(|error| GameGenerationError::Failed(error.to_string()))?;
        ensure_directory_chain(root.install_root(), &relative)
            .map_err(|error| managed_error("Cannot create game generation layout", error))?;
    }
    root.revalidate().map_err(GameGenerationError::Failed)
}

fn ensure_expected_staging_tree(
    install_root: &Path,
    staging: &RelativeManagedPath,
    expected: &ExpectedGameTree,
) -> GenerationResult<()> {
    let image = RelativeManagedPath::new(&format!("{}/image", staging.as_str()))
        .map_err(|error| GameGenerationError::Failed(error.to_string()))?;
    ensure_directory_chain(install_root, &image)
        .map_err(|error| managed_error("Cannot create game staging image", error))?;
    for directory in expected.directories.values() {
        let relative = RelativeManagedPath::new(&format!("{}/image/{directory}", staging.as_str()))
            .map_err(|error| GameGenerationError::Failed(error.to_string()))?;
        ensure_directory_chain(install_root, &relative)
            .map_err(|error| managed_error("Cannot create signed game directory", error))?;
    }
    Ok(())
}

fn quarantine_managed_generation(
    root: &OwnedCasRoot,
    relative: &RelativeManagedPath,
    game_lock_sha256: &str,
    bucket: &mut Option<GameQuarantineBucket>,
) -> GenerationResult<()> {
    let existing = GuardedDirectoryChain::open(root.install_root(), relative)
        .map_err(|error| managed_error("Cannot lease unsafe game generation", error))?;
    existing.revalidate().map_err(|error| {
        managed_error("Unsafe game generation changed before quarantine", error)
    })?;
    let identity = existing.leaf().info().identity.clone();
    drop(existing);
    let bucket = ensure_game_quarantine_bucket(root, game_lock_sha256, bucket)?;
    quarantine_node_if_identity(
        root.install_root(),
        relative.clone(),
        &bucket.relative,
        &identity,
        ManagedNodeKind::Directory,
    )
    .map_err(|error| managed_error("Cannot quarantine unsafe game generation", error))?;
    Ok(())
}

fn game_quarantine_root() -> RelativeManagedPath {
    RelativeManagedPath::new("runtime/minecraft/quarantine")
        .expect("static game quarantine path is valid")
}

fn ensure_game_quarantine_bucket<'a>(
    root: &OwnedCasRoot,
    game_lock_sha256: &str,
    bucket: &'a mut Option<GameQuarantineBucket>,
) -> GenerationResult<&'a GameQuarantineBucket> {
    if bucket.is_none() {
        if !is_sha256(game_lock_sha256) {
            return Err(GameGenerationError::Failed(
                "Game quarantine bucket digest is invalid".into(),
            ));
        }
        let relative = game_quarantine_root()
            .join_component(game_lock_sha256)
            .map_err(|error| managed_error("Cannot construct game quarantine bucket", error))?;
        let guard = GuardedDirectoryChain::create_exclusive(root.install_root(), &relative)
            .map_err(|error| managed_error("Cannot create game quarantine bucket", error))?;
        guard
            .revalidate()
            .map_err(|error| managed_error("Game quarantine bucket changed", error))?;
        *bucket = Some(GameQuarantineBucket {
            relative,
            identity: guard.leaf().info().identity.clone(),
        });
    }
    Ok(bucket
        .as_ref()
        .expect("a game quarantine bucket was initialized"))
}

fn reclaim_game_quarantine(root: &OwnedCasRoot) -> GenerationResult<()> {
    let quarantine = game_quarantine_root();
    let guard = GuardedDirectoryChain::open(root.install_root(), &quarantine)
        .map_err(|error| managed_error("Cannot lease game quarantine", error))?;
    let mut buckets = Vec::new();
    for entry in fs::read_dir(guard.leaf().path()).map_err(|error| {
        GameGenerationError::Failed(format!("Cannot enumerate game quarantine: {error}"))
    })? {
        let entry = entry.map_err(|error| {
            GameGenerationError::Failed(format!("Cannot inspect game quarantine entry: {error}"))
        })?;
        if buckets.len() >= MAX_GAME_QUARANTINE_BUCKETS {
            return Err(GameGenerationError::Failed(
                "Game quarantine retention bound was exceeded".into(),
            ));
        }
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| {
                GameGenerationError::Failed(
                    "Game quarantine contains a non-Unicode bucket name".into(),
                )
            })?
            .to_owned();
        if !is_sha256(&name) {
            return Err(GameGenerationError::Failed(
                "Game quarantine contains a non-canonical bucket name".into(),
            ));
        }
        let relative = quarantine
            .join_component(&name)
            .map_err(|error| managed_error("Game quarantine bucket name is unsafe", error))?;
        let bucket =
            GuardedDirectoryChain::open(root.install_root(), &relative).map_err(|error| {
                managed_error("Cannot lease retained game quarantine bucket", error)
            })?;
        bucket.revalidate().map_err(|error| {
            managed_error(
                "Retained game quarantine bucket changed during audit",
                error,
            )
        })?;
        buckets.push((relative, bucket.leaf().info().identity.clone()));
    }
    guard
        .revalidate()
        .map_err(|error| managed_error("Game quarantine changed during maintenance", error))?;
    drop(guard);

    for (relative, identity) in buckets {
        remove_bounded_managed_directory_tree(
            root.install_root(),
            &relative,
            &identity,
            GAME_QUARANTINE_GC_LIMITS,
        )
        .map_err(|error| managed_error("Cannot reclaim retained game quarantine", error))?;
    }
    root.revalidate().map_err(GameGenerationError::Failed)
}

fn cleanup_game_quarantine_bucket(
    root: &OwnedCasRoot,
    bucket: Option<GameQuarantineBucket>,
) -> GenerationResult<()> {
    let Some(bucket) = bucket else {
        return Ok(());
    };
    remove_bounded_managed_directory_tree(
        root.install_root(),
        &bucket.relative,
        &bucket.identity,
        GAME_QUARANTINE_GC_LIMITS,
    )
    .map_err(|error| managed_error("Cannot clean published game quarantine", error))?;
    root.revalidate().map_err(GameGenerationError::Failed)
}

fn require_active_build(build: &GameGenerationBuild<'_, '_>) -> GenerationResult<()> {
    build
        .root
        .revalidate()
        .map_err(GameGenerationError::Failed)?;
    let (nonce, install_id, _, _) = build.root.binding();
    if nonce != build.planned.root_binding_nonce() || install_id != build.planned.install_id() {
        return Err(GameGenerationError::Failed(
            "Game generation root no longer matches the sealed authority".into(),
        ));
    }
    let binding = build.planned.binding();
    build
        .planned
        .validate_binding(&binding)
        .map_err(GameGenerationError::Failed)?;
    build
        ._operation_lock
        .revalidate()
        .map_err(|error| managed_error("Game generation lock changed", error))?;
    build
        ._processor_workspace_lock
        .revalidate()
        .map_err(|error| managed_error("Processor workspace lock changed", error))?;
    Ok(())
}

fn cancelled() -> GameGenerationError {
    GameGenerationError::Cancelled
}

fn quarantine_stale_incoming(
    root: &OwnedCasRoot,
    game_lock_sha256: &str,
    bucket: &mut Option<GameQuarantineBucket>,
) -> GenerationResult<()> {
    let incoming_root = root.install_root().join("runtime/minecraft/incoming");
    let prefix = format!("{game_lock_sha256}-");
    let mut matching = 0_usize;
    for entry in fs::read_dir(&incoming_root).map_err(|error| {
        GameGenerationError::Failed(format!("Cannot inspect game incoming files: {error}"))
    })? {
        let entry = entry.map_err(|error| {
            GameGenerationError::Failed(format!("Cannot inspect game incoming entry: {error}"))
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        matching += 1;
        if matching > 128 {
            return Err(GameGenerationError::Failed(
                "Too many stale incoming files for one game lock".into(),
            ));
        }
        let relative = RelativeManagedPath::new(&format!("runtime/minecraft/incoming/{name}"))
            .map_err(|error| {
                GameGenerationError::Failed(format!("Stale incoming path is unsafe: {error}"))
            })?;
        let file = ImmutableManagedFile::open(root.install_root(), &relative)
            .map_err(|error| managed_error("Cannot lease stale incoming file", error))?;
        let identity = file.info().identity.clone();
        drop(file);
        let bucket = ensure_game_quarantine_bucket(root, game_lock_sha256, bucket)?;
        quarantine_node_if_identity(
            root.install_root(),
            relative,
            &bucket.relative,
            &identity,
            ManagedNodeKind::File,
        )
        .map_err(|error| managed_error("Cannot quarantine stale incoming file", error))?;
    }
    Ok(())
}

fn validate_processor_workspace_name(name: &str) -> Result<(), String> {
    if !name.is_ascii()
        || name.len() != 138
        || name.as_bytes().get(64) != Some(&b'-')
        || name.as_bytes().get(101) != Some(&b'-')
        || !is_sha256(&name[..64])
    {
        return Err("Processor workspace name is not canonical".into());
    }
    for uuid in [&name[65..101], &name[102..]] {
        let parsed = Uuid::parse_str(uuid)
            .map_err(|_| "Processor workspace name contains an invalid UUID".to_string())?;
        if parsed.to_string() != uuid {
            return Err("Processor workspace UUID is not canonical".into());
        }
    }
    Ok(())
}

fn remove_stale_processor_workspaces(
    root: &OwnedCasRoot,
    limits: ManagedDirectoryRemovalLimits,
) -> GenerationResult<()> {
    let workspaces_root = root.install_root().join("runtime/minecraft/workspaces");
    let mut matching = Vec::new();
    for entry in fs::read_dir(&workspaces_root).map_err(|error| {
        GameGenerationError::Failed(format!("Cannot inspect processor workspaces: {error}"))
    })? {
        let entry = entry.map_err(|error| {
            GameGenerationError::Failed(format!(
                "Cannot inspect processor workspace entry: {error}"
            ))
        })?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| {
                GameGenerationError::Failed("Processor workspace name is not UTF-8".into())
            })?
            .to_owned();
        validate_processor_workspace_name(&name).map_err(GameGenerationError::Failed)?;
        matching.push(name);
        if matching.len() > MAX_STALE_PROCESSOR_WORKSPACES {
            return Err(GameGenerationError::Failed(
                "Too many abandoned processor workspaces".into(),
            ));
        }
    }
    for name in matching {
        let relative = RelativeManagedPath::new(&format!("runtime/minecraft/workspaces/{name}"))
            .map_err(|error| {
                GameGenerationError::Failed(format!(
                    "Stale processor workspace path is unsafe: {error}"
                ))
            })?;
        let guard = GuardedDirectoryChain::open(root.install_root(), &relative)
            .map_err(|error| managed_error("Cannot lease stale processor workspace", error))?;
        let identity = guard.leaf().info().identity.clone();
        drop(guard);
        remove_bounded_managed_directory_tree(root.install_root(), &relative, &identity, limits)
            .map_err(|error| managed_error("Cannot remove stale processor workspace", error))?;
    }
    Ok(())
}

pub(super) fn begin_game_generation<'root, 'plan>(
    root: &'root OwnedCasRoot,
    planned: PlannedGameGenerationV2<'plan>,
) -> GenerationResult<BeginGameGeneration<'root, 'plan>> {
    ensure_generation_layout(root)?;
    root.revalidate().map_err(GameGenerationError::Failed)?;
    let (initial_nonce, initial_install_id, _, _) = root.binding();
    if initial_nonce != planned.root_binding_nonce() || initial_install_id != planned.install_id() {
        return Err(GameGenerationError::Failed(
            "Game generation authority belongs to another install root".into(),
        ));
    }
    let binding = planned.binding();
    planned
        .validate_binding(&binding)
        .map_err(GameGenerationError::Failed)?;
    let lock_relative = RelativeManagedPath::new(&format!(
        "runtime/minecraft/locks/{}.lock",
        planned.game_runtime_lock_sha256()
    ))
    .map_err(|error| GameGenerationError::Failed(error.to_string()))?;
    let operation_lock = open_or_create_lock_file(root.install_root(), &lock_relative)
        .map_err(|error| managed_error("Cannot open game generation lock", error))?;
    operation_lock.file().lock_exclusive().map_err(|error| {
        GameGenerationError::Failed(format!("Cannot lock game generation: {error}"))
    })?;
    root.revalidate().map_err(GameGenerationError::Failed)?;
    let (nonce, install_id, _, _) = root.binding();
    if nonce != planned.root_binding_nonce() || install_id != planned.install_id() {
        return Err(GameGenerationError::Failed(
            "Game generation root changed while acquiring its lock".into(),
        ));
    }
    let workspace_lock_relative = RelativeManagedPath::new(PROCESSOR_WORKSPACE_LOCK)
        .expect("static processor workspace lock path is valid");
    let processor_workspace_lock =
        open_or_create_lock_file(root.install_root(), &workspace_lock_relative)
            .map_err(|error| managed_error("Cannot open processor workspace lock", error))?;
    processor_workspace_lock
        .file()
        .lock_exclusive()
        .map_err(|error| {
            GameGenerationError::Failed(format!("Cannot lock processor workspaces: {error}"))
        })?;
    operation_lock
        .revalidate()
        .map_err(|error| managed_error("Game generation lock changed", error))?;
    processor_workspace_lock
        .revalidate()
        .map_err(|error| managed_error("Processor workspace lock changed", error))?;
    root.revalidate().map_err(GameGenerationError::Failed)?;
    planned
        .validate_binding(&binding)
        .map_err(GameGenerationError::Failed)?;
    let processor_workspace_gc_limits = ManagedDirectoryRemovalLimits {
        max_entries: PROCESSOR_WORKSPACE_GC_MAX_ENTRIES,
        max_allocated_bytes: PROCESSOR_WORKSPACE_GC_MAX_ALLOCATED_BYTES,
        max_depth: PROCESSOR_WORKSPACE_GC_MAX_DEPTH,
    };
    // The global processor-workspace lock is also the game quarantine lifecycle owner. Therefore
    // no active game build can still need a retained bucket while startup maintenance runs.
    reclaim_game_quarantine(root)?;
    let mut current_quarantine_bucket = None;
    quarantine_stale_incoming(
        root,
        planned.game_runtime_lock_sha256(),
        &mut current_quarantine_bucket,
    )?;
    remove_stale_processor_workspaces(root, processor_workspace_gc_limits)?;

    let (expected, marker) = generation_contract_from_plan(&planned)?;
    let canonical = generation_relative("generations", planned.game_runtime_lock_sha256())?;
    match audit_complete_generation(root.install_root(), &canonical, &expected, &marker) {
        Ok(Some((lease, marker_bytes))) => {
            let installed = installation_from_plan(root, &planned, &canonical, lease, marker_bytes);
            cleanup_game_quarantine_bucket(root, current_quarantine_bucket)?;
            return Ok(BeginGameGeneration::Installed(installed));
        }
        Ok(None) => {}
        Err(_) => {
            if path_exists_nofollow(&canonical.join_to(root.install_root()))? {
                quarantine_managed_generation(
                    root,
                    &canonical,
                    planned.game_runtime_lock_sha256(),
                    &mut current_quarantine_bucket,
                )?;
            }
        }
    }

    let staging = generation_relative("staging", planned.game_runtime_lock_sha256())?;
    if path_exists_nofollow(&staging.join_to(root.install_root()))?
        && audit_partial_generation(root.install_root(), &staging, &expected, &marker).is_err()
    {
        quarantine_managed_generation(
            root,
            &staging,
            planned.game_runtime_lock_sha256(),
            &mut current_quarantine_bucket,
        )?;
    }
    ensure_expected_staging_tree(root.install_root(), &staging, &expected)?;
    let workspaces_root = root.install_root().join("runtime/minecraft/workspaces");
    let build = GameGenerationBuild {
        root,
        planned,
        staging_relative: staging,
        workspaces_root,
        processor_workspace_gc_limits,
        quarantine_bucket: current_quarantine_bucket,
        _operation_lock: operation_lock,
        _processor_workspace_lock: processor_workspace_lock,
    };
    require_active_build(&build)?;
    Ok(BeginGameGeneration::Build(build))
}

fn copy_official_to_staging(
    build: &GameGenerationBuild<'_, '_>,
    expected: &ExpectedGameFile,
    cancelled_flag: &AtomicBool,
) -> GenerationResult<()> {
    if cancelled_flag.load(Ordering::Acquire) {
        return Err(cancelled());
    }
    let object = build
        .planned
        .official_object(&expected.sha256)
        .map_err(GameGenerationError::Failed)?;
    let mut source = object.open(build.root).map_err(|error| {
        GameGenerationError::Failed(format!("Cannot lease official game object: {error}"))
    })?;
    let incoming = RelativeManagedPath::new(&format!(
        "runtime/minecraft/incoming/{}-{}-{}.part",
        build.planned.game_runtime_lock_sha256(),
        build.planned.operation_id(),
        Uuid::new_v4()
    ))
    .map_err(|error| GameGenerationError::Failed(error.to_string()))?;
    let mut destination = ExclusiveManagedFile::create(build.root.install_root(), incoming)
        .map_err(|error| managed_error("Cannot create game incoming file", error))?;
    let copied = source
        .copy_to_exclusive(&mut destination, expected.size)
        .map_err(|error| managed_error("Cannot copy official game object", error))?;
    if copied.size != expected.size
        || copied.sha1 != expected.sha1
        || copied.sha256 != expected.sha256
    {
        return Err(GameGenerationError::Failed(
            "Official game CAS bytes differ from the signed runtime".into(),
        ));
    }
    let synced = destination
        .sync()
        .map_err(|error| managed_error("Cannot flush game incoming file", error))?;
    if cancelled_flag.load(Ordering::Acquire) {
        drop(synced);
        return Err(cancelled());
    }
    let final_relative = image_relative(&build.staging_relative, &expected.path)?;
    synced
        .rename_no_replace(final_relative)
        .map_err(|error| managed_error("Cannot activate official game file", error))?;
    Ok(())
}

pub(super) fn stage_official_game_files<'root, 'plan>(
    build: GameGenerationBuild<'root, 'plan>,
    cancelled_flag: &AtomicBool,
) -> GenerationResult<StagedGameGeneration<'root, 'plan>> {
    require_active_build(&build)?;
    if cancelled_flag.load(Ordering::Acquire) {
        return Err(cancelled());
    }
    let (expected, marker) = generation_contract_from_plan(&build.planned)?;
    let mut audit = audit_partial_generation(
        build.root.install_root(),
        &build.staging_relative,
        &expected,
        &marker,
    )?;
    if audit.marker_complete {
        return Ok(StagedGameGeneration::Ready(GameGenerationReady { build }));
    }
    for signed in &build.planned.game_runtime_lock().files {
        let expected_file = expected.expected(&signed.path)?;
        if !expected_file.is_official() {
            continue;
        }
        let key = RelativeManagedPath::new(&expected_file.path)
            .map_err(|error| GameGenerationError::Failed(error.to_string()))?
            .collision_key()
            .to_owned();
        if !audit.present_files.contains(&key) {
            copy_official_to_staging(&build, expected_file, cancelled_flag)?;
            audit.present_files.insert(key);
        }
    }
    require_active_build(&build)?;
    audit = audit_partial_generation(
        build.root.install_root(),
        &build.staging_relative,
        &expected,
        &marker,
    )?;
    let derived_complete = expected
        .files
        .iter()
        .all(|(key, file)| !file.is_derived() || audit.present_files.contains(key));
    if derived_complete {
        Ok(StagedGameGeneration::Ready(GameGenerationReady { build }))
    } else {
        let workspace_name = format!(
            "{}-{}-{}",
            build.planned.game_runtime_lock_sha256(),
            build.planned.operation_id(),
            Uuid::new_v4()
        );
        Ok(StagedGameGeneration::NeedsProcessors(
            GameGenerationProcessorBuild {
                build,
                workspace_name,
            },
        ))
    }
}

fn copy_derived_to_staging(
    build: &GameGenerationProcessorBuild<'_, '_>,
    result: &mut ProcessorExecutionResult,
    signed: &GameRuntimeFile,
    expected: &ExpectedGameFile,
    cancelled_flag: &AtomicBool,
) -> GenerationResult<()> {
    if cancelled_flag.load(Ordering::Acquire) {
        return Err(cancelled());
    }
    let incoming = RelativeManagedPath::new(&format!(
        "runtime/minecraft/incoming/{}-{}-{}.part",
        build.game_runtime_lock_sha256(),
        build.authority().operation_id(),
        Uuid::new_v4()
    ))
    .map_err(|error| GameGenerationError::Failed(error.to_string()))?;
    let mut destination = ExclusiveManagedFile::create(build.root().install_root(), incoming)
        .map_err(|error| managed_error("Cannot create derived incoming file", error))?;
    let copied = result
        .copy_derived_output(build, signed, &mut destination)
        .map_err(GameGenerationError::Failed)?;
    if copied.size != expected.size
        || copied.sha1 != expected.sha1
        || copied.sha256 != expected.sha256
    {
        return Err(GameGenerationError::Failed(
            "Processor output bytes differ from the signed runtime".into(),
        ));
    }
    let synced = destination
        .sync()
        .map_err(|error| managed_error("Cannot flush derived incoming file", error))?;
    if cancelled_flag.load(Ordering::Acquire) {
        drop(synced);
        return Err(cancelled());
    }
    let final_relative = image_relative(&build.build.staging_relative, &expected.path)?;
    synced
        .rename_no_replace(final_relative)
        .map_err(|error| managed_error("Cannot activate derived game file", error))?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GenerationCommitResult {
    Moved,
    ConcurrentWinner,
}

fn commit_generation_directory_with<F>(
    cancelled_flag: &AtomicBool,
    move_operation: F,
) -> GenerationResult<GenerationCommitResult>
where
    F: FnOnce() -> Result<ConditionalManagedDirectoryMoveOutcome, ManagedFsError>,
{
    if cancelled_flag.load(Ordering::Acquire) {
        return Err(cancelled());
    }
    match move_operation() {
        Ok(ConditionalManagedDirectoryMoveOutcome::Cancelled) => Err(cancelled()),
        Ok(ConditionalManagedDirectoryMoveOutcome::Moved(_)) => Ok(GenerationCommitResult::Moved),
        Err(ManagedFsError::Conflict(_)) => Ok(GenerationCommitResult::ConcurrentWinner),
        Err(error) => Err(managed_error("Cannot publish game generation", error)),
    }
}

pub(super) fn merge_processor_outputs<'root, 'plan>(
    build: GameGenerationProcessorBuild<'root, 'plan>,
    mut result: ProcessorExecutionResult,
    cancelled_flag: &AtomicBool,
) -> GenerationResult<GameGenerationReady<'root, 'plan>> {
    require_active_build(&build.build)?;
    result
        .validate_for_publish(&build)
        .map_err(GameGenerationError::Failed)?;
    let (expected, marker) = generation_contract_from_plan(&build.build.planned)?;
    let audit = audit_partial_generation(
        build.root().install_root(),
        &build.build.staging_relative,
        &expected,
        &marker,
    )?;
    for signed in &build.game_runtime_lock().files {
        let expected_file = expected.expected(&signed.path)?;
        if !expected_file.is_derived() {
            continue;
        }
        let key = RelativeManagedPath::new(&expected_file.path)
            .map_err(|error| GameGenerationError::Failed(error.to_string()))?
            .collision_key()
            .to_owned();
        if !audit.present_files.contains(&key) {
            copy_derived_to_staging(&build, &mut result, signed, expected_file, cancelled_flag)?;
        }
    }
    result
        .validate_for_publish(&build)
        .map_err(GameGenerationError::Failed)?;
    let final_audit = audit_partial_generation(
        build.root().install_root(),
        &build.build.staging_relative,
        &expected,
        &marker,
    )?;
    if final_audit.present_files.len() != PINNED_FILE_COUNT {
        return Err(GameGenerationError::Failed(
            "Processor merge did not produce the exact game file set".into(),
        ));
    }
    let proof = result
        .remove_workspace_after_publish(&build)
        .map_err(GameGenerationError::Failed)?;
    if proof.game_runtime_lock_sha256 != build.game_runtime_lock_sha256()
        || proof.generation_binding_sha256 != build.generation_binding_sha256()
        || proof.processor_receipt_sha256 != expected.processor_receipt_sha256
        || proof.outputs_sha256 != expected.processor_outputs_sha256
    {
        return Err(GameGenerationError::Failed(
            "Processor proof changed while retiring its workspace".into(),
        ));
    }
    require_active_build(&build.build)?;
    Ok(GameGenerationReady { build: build.build })
}

pub(super) fn publish_game_generation(
    ready: GameGenerationReady<'_, '_>,
    cancelled_flag: &AtomicBool,
) -> GenerationResult<GameRuntimeInstallation> {
    let mut build = ready.build;
    require_active_build(&build)?;
    if cancelled_flag.load(Ordering::Acquire) {
        return Err(cancelled());
    }
    let (expected, marker) = generation_contract_from_plan(&build.planned)?;
    let marker_bytes = marker.canonical_bytes()?;
    let partial = audit_partial_generation(
        build.root.install_root(),
        &build.staging_relative,
        &expected,
        &marker,
    )?;
    if partial.present_files.len() != PINNED_FILE_COUNT {
        return Err(GameGenerationError::Failed(
            "Cannot publish an incomplete game generation".into(),
        ));
    }
    if !partial.marker_complete {
        atomic_write_small(
            build.root.install_root(),
            marker_relative(&build.staging_relative)?,
            &marker_bytes,
            MAX_MARKER_BYTES as usize,
        )
        .map_err(|error| managed_error("Cannot write game generation marker", error))?;
    }
    // The complete lease must be dropped before the ancestor directory can be renamed on Windows.
    let staged = audit_complete_generation(
        build.root.install_root(),
        &build.staging_relative,
        &expected,
        &marker,
    )?
    .ok_or_else(|| GameGenerationError::Failed("Audited game staging disappeared".into()))?;
    drop(staged);
    require_active_build(&build)?;
    if cancelled_flag.load(Ordering::Acquire) {
        return Err(cancelled());
    }
    let canonical = generation_relative("generations", build.planned.game_runtime_lock_sha256())?;
    let commit = commit_generation_directory_with(cancelled_flag, || {
        move_managed_directory_no_replace_if(
            build.root.install_root(),
            build.staging_relative.clone(),
            canonical.clone(),
            || !cancelled_flag.load(Ordering::Acquire),
        )
    })?;
    require_active_build(&build)?;
    let (lease, audited_marker) =
        audit_complete_generation(build.root.install_root(), &canonical, &expected, &marker)?
            .ok_or_else(|| {
                GameGenerationError::Failed("Published game generation is missing".into())
            })?;
    if commit == GenerationCommitResult::ConcurrentWinner
        && path_exists_nofollow(&build.staging_relative.join_to(build.root.install_root()))?
    {
        let staging = build.staging_relative.clone();
        let game_lock_sha256 = build.planned.game_runtime_lock_sha256().to_owned();
        quarantine_managed_generation(
            build.root,
            &staging,
            &game_lock_sha256,
            &mut build.quarantine_bucket,
        )?;
    }
    if let Err(error) = cleanup_game_quarantine_bucket(build.root, build.quarantine_bucket.take()) {
        return Err(GameGenerationError::AppliedButDurabilityUnconfirmed {
            destination: canonical
                .join_to(build.root.install_root())
                .display()
                .to_string(),
            detail: format!("published generation quarantine cleanup failed: {error}"),
        });
    }
    Ok(installation_from_plan(
        build.root,
        &build.planned,
        &canonical,
        lease,
        audited_marker,
    ))
}

pub(super) fn audit_installed_game_generation(
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
) -> Result<Option<GameRuntimeInstallation>, String> {
    inventory.validate_root(root)?;
    let (expected, marker) = generation_contract_from_inventory(inventory)?;
    let relative = generation_relative("generations", inventory.game_runtime_lock_sha256())?;
    let Some((lease, marker_bytes)) =
        audit_complete_generation(root.install_root(), &relative, &expected, &marker)?
    else {
        return Ok(None);
    };
    inventory.validate_root(root)?;
    Ok(Some(installation_from_inventory(
        root,
        inventory,
        &relative,
        lease,
        marker_bytes,
    )))
}

pub(super) fn revalidate_game_runtime_installation(
    installed: &GameRuntimeInstallation,
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
) -> Result<GameRuntimeInstallation, String> {
    inventory.validate_root(root)?;
    if installed.install_id != inventory.install_id()
        || installed.root_binding_nonce != inventory.root_binding_nonce()
        || installed.inventory_fingerprint != inventory.fingerprint()
        || installed.game_runtime_lock_sha256 != inventory.game_runtime_lock_sha256()
    {
        return Err("Game runtime installation belongs to another inventory/root".into());
    }
    installed.lease.revalidate(&installed.marker_bytes)?;
    audit_installed_game_generation(root, inventory)?
        .ok_or_else(|| "Game runtime installation disappeared during revalidation".into())
}

/// O(1) final launch-window validation of a generation fully hashed before admission. The sticky
/// recursive sentinel spans that audit and the API await; retained exact handles deny writes and
/// replacement, so no file iteration, reopen, namespace scan, or content read occurs here.
pub(super) fn revalidate_game_runtime_installation_fast(
    installed: &GameRuntimeInstallation,
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
) -> Result<(), String> {
    inventory.validate_root(root)?;
    if installed.install_id != inventory.install_id()
        || installed.root_binding_nonce != inventory.root_binding_nonce()
        || installed.inventory_fingerprint != inventory.fingerprint()
        || installed.game_runtime_lock_sha256 != inventory.game_runtime_lock_sha256()
    {
        return Err("Game runtime installation belongs to another inventory/root".into());
    }
    installed.lease.revalidate_sentinel()?;
    inventory.validate_root(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::storage::select_install_directory;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};

    fn digest(bytes: &[u8]) -> (String, String) {
        (
            format!("{:x}", Sha1::digest(bytes)),
            format!("{:x}", Sha256::digest(bytes)),
        )
    }

    fn synthetic_contract() -> (
        ExpectedGameTree,
        GameGenerationMarker,
        Vec<(&'static str, &'static [u8])>,
    ) {
        let files = vec![
            (
                "versions/test/client.jar",
                b"client".as_slice(),
                GameRuntimeRole::MinecraftClient,
            ),
            (
                "libraries/test/library.jar",
                b"library".as_slice(),
                GameRuntimeRole::Library,
            ),
        ];
        let mut expected_files = BTreeMap::new();
        let mut directories = BTreeMap::new();
        let mut canonical = Vec::new();
        let mut total_bytes = 0_u64;
        for (path, bytes, role) in &files {
            let (sha1, sha256) = digest(bytes);
            let expected = ExpectedGameFile {
                path: (*path).to_owned(),
                role: *role,
                source_kind: "official",
                size: bytes.len() as u64,
                sha1,
                sha256,
            };
            let managed = RelativeManagedPath::new(path).unwrap();
            register_expected_directories(&managed, &mut directories).unwrap();
            expected_files.insert(managed.collision_key().to_owned(), expected.clone());
            total_bytes += bytes.len() as u64;
            canonical.push(expected);
        }
        canonical.sort_by(|left, right| left.path.cmp(&right.path));
        let tree = ExpectedGameTree {
            files: expected_files,
            directories,
            tree_sha256: domain_digest(TREE_DIGEST_DOMAIN, &canonical).unwrap(),
            total_bytes,
            processor_receipt_sha256: "1".repeat(64),
            processor_outputs_sha256: "2".repeat(64),
        };
        let marker = GameGenerationMarker {
            schema_version: GENERATION_SCHEMA_VERSION,
            domain: GENERATION_DOMAIN.to_owned(),
            game_runtime_lock_sha256: "3".repeat(64),
            game_runtime_id: "synthetic".into(),
            java_runtime_lock_sha256: "4".repeat(64),
            processor_receipt_sha256: tree.processor_receipt_sha256.clone(),
            processor_outputs_sha256: tree.processor_outputs_sha256.clone(),
            file_count: files.len(),
            official_file_count: files.len(),
            derived_file_count: 0,
            total_bytes,
            tree_sha256: tree.tree_sha256.clone(),
        };
        (
            tree,
            marker,
            files
                .into_iter()
                .map(|(path, bytes, _)| (path, bytes))
                .collect(),
        )
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-game-generation-{label}-{}",
            Uuid::new_v4()
        ))
    }

    fn write_generation(
        root: &Path,
        relative: &RelativeManagedPath,
        marker: &GameGenerationMarker,
        files: &[(&str, &[u8])],
    ) {
        let generation = relative.join_to(root);
        fs::create_dir_all(generation.join("image")).unwrap();
        for (path, bytes) in files {
            let destination = generation
                .join("image")
                .join(RelativeManagedPath::new(path).unwrap().to_path_buf());
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(destination, bytes).unwrap();
        }
        fs::write(
            generation.join(GENERATION_MARKER),
            marker.canonical_bytes().unwrap(),
        )
        .unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn game_quarantine_crash_recovery_and_tamper_loops_are_bounded() {
        let install = temp_root("quarantine-lifecycle");
        let root = select_install_directory(&install)
            .unwrap()
            .into_owned_cas_root();
        ensure_generation_layout(&root).unwrap();
        let game_hash = "a".repeat(64);

        for attempt in 0..8 {
            let mut bucket = None;
            let current = ensure_game_quarantine_bucket(&root, &game_hash, &mut bucket).unwrap();
            fs::create_dir(
                current
                    .relative
                    .join_to(root.install_root())
                    .join("generation"),
            )
            .unwrap();
            fs::write(
                current
                    .relative
                    .join_to(root.install_root())
                    .join("generation/tampered.bin"),
                format!("tamper-{attempt}"),
            )
            .unwrap();
            cleanup_game_quarantine_bucket(&root, bucket).unwrap();
            assert_eq!(
                fs::read_dir(game_quarantine_root().join_to(root.install_root()))
                    .unwrap()
                    .count(),
                0
            );
        }

        // A process death after quarantine but before or after canonical replacement leaves the
        // same deterministic bucket. The next lock owner reclaims it before creating new state.
        let mut crash_bucket = None;
        let current = ensure_game_quarantine_bucket(&root, &game_hash, &mut crash_bucket).unwrap();
        fs::write(
            current
                .relative
                .join_to(root.install_root())
                .join("crash.bin"),
            b"crash-leftover",
        )
        .unwrap();
        drop(crash_bucket);
        reclaim_game_quarantine(&root).unwrap();
        assert_eq!(
            fs::read_dir(game_quarantine_root().join_to(root.install_root()))
                .unwrap()
                .count(),
            0
        );

        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn game_quarantine_unsafe_or_excess_retention_fails_closed() {
        let install = temp_root("quarantine-fail-closed");
        let root = select_install_directory(&install)
            .unwrap()
            .into_owned_cas_root();
        ensure_generation_layout(&root).unwrap();
        let quarantine = game_quarantine_root();
        for index in 0..=MAX_GAME_QUARANTINE_BUCKETS {
            let bucket = quarantine.join_component(&format!("{index:064x}")).unwrap();
            GuardedDirectoryChain::create_exclusive(root.install_root(), &bucket).unwrap();
        }
        assert!(reclaim_game_quarantine(&root).is_err());
        assert_eq!(
            fs::read_dir(quarantine.join_to(root.install_root()))
                .unwrap()
                .count(),
            MAX_GAME_QUARANTINE_BUCKETS + 1
        );
        drop(root);
        fs::remove_dir_all(&install).unwrap();

        let root = select_install_directory(&install)
            .unwrap()
            .into_owned_cas_root();
        ensure_generation_layout(&root).unwrap();
        let mut bucket = None;
        let current = ensure_game_quarantine_bucket(&root, &"b".repeat(64), &mut bucket).unwrap();
        let original = current
            .relative
            .join_to(root.install_root())
            .join("original.bin");
        fs::write(&original, b"unsafe").unwrap();
        fs::hard_link(
            &original,
            current
                .relative
                .join_to(root.install_root())
                .join("alias.bin"),
        )
        .unwrap();
        assert!(reclaim_game_quarantine(&root).is_err());
        assert_eq!(fs::read(&original).unwrap(), b"unsafe");
        drop(bucket);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[test]
    fn exact_generation_audit_holds_and_revalidates_the_signed_tree() {
        let root = temp_root("exact");
        fs::create_dir_all(&root).unwrap();
        let relative = RelativeManagedPath::new("runtime/minecraft/generations/lock").unwrap();
        let (expected, marker, files) = synthetic_contract();
        write_generation(&root, &relative, &marker, &files);

        let (lease, marker_bytes) = audit_complete_generation(&root, &relative, &expected, &marker)
            .unwrap()
            .unwrap();
        lease.revalidate(&marker_bytes).unwrap();
        let extra = relative
            .join_to(&root)
            .join("image/foreign-after-audit.jar");
        if fs::write(&extra, b"foreign").is_ok() {
            assert!(lease.revalidate(&marker_bytes).is_err());
        } else {
            // Windows snapshot handles deny the namespace write outright.
            lease.revalidate(&marker_bytes).unwrap();
        }
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_generation_audit_rejects_extra_wrong_case_and_corrupt_files() {
        for mode in ["extra", "case", "corrupt"] {
            let root = temp_root(mode);
            fs::create_dir_all(&root).unwrap();
            let relative = RelativeManagedPath::new("runtime/minecraft/generations/lock").unwrap();
            let (expected, marker, files) = synthetic_contract();
            write_generation(&root, &relative, &marker, &files);
            let image = relative.join_to(&root).join("image");
            match mode {
                "extra" => fs::write(image.join("foreign.jar"), b"foreign").unwrap(),
                "case" => {
                    let temporary = image.join("libraries/test/case.tmp");
                    fs::rename(image.join("libraries/test/library.jar"), &temporary).unwrap();
                    fs::rename(temporary, image.join("libraries/test/Library.jar")).unwrap();
                }
                "corrupt" => fs::write(image.join("versions/test/client.jar"), b"changed").unwrap(),
                _ => unreachable!(),
            }
            assert!(audit_complete_generation(&root, &relative, &expected, &marker).is_err());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn partial_generation_accepts_only_a_verified_signed_subset() {
        let root = temp_root("partial");
        let relative = RelativeManagedPath::new("runtime/minecraft/staging/lock").unwrap();
        let (expected, marker, files) = synthetic_contract();
        let generation = relative.join_to(&root);
        fs::create_dir_all(generation.join("image/versions/test")).unwrap();
        fs::create_dir_all(generation.join("image/libraries/test")).unwrap();
        fs::write(generation.join("image").join(files[0].0), files[0].1).unwrap();
        let audit = audit_partial_generation(&root, &relative, &expected, &marker).unwrap();
        assert_eq!(audit.present_files.len(), 1);
        assert!(!audit.marker_complete);

        fs::write(generation.join("image/foreign.jar"), b"foreign").unwrap();
        assert!(audit_partial_generation(&root, &relative, &expected, &marker).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn generation_marker_rejects_unknown_fields_and_lock_transplants() {
        let (_expected, marker, _files) = synthetic_contract();
        let mut value = serde_json::to_value(&marker).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("unexpected".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<GameGenerationMarker>(value).is_err());

        let mut transplanted = marker.clone();
        transplanted.game_runtime_lock_sha256 = "9".repeat(64);
        assert_ne!(
            transplanted.canonical_bytes().unwrap(),
            marker.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn exact_generation_audit_rejects_hardlinked_files() {
        let root = temp_root("hardlink");
        fs::create_dir_all(&root).unwrap();
        let relative = RelativeManagedPath::new("runtime/minecraft/generations/lock").unwrap();
        let (expected, marker, files) = synthetic_contract();
        write_generation(&root, &relative, &marker, &files);
        let client = relative
            .join_to(&root)
            .join("image/versions/test/client.jar");
        let alias = root.join("alias.jar");
        fs::hard_link(&client, &alias).unwrap();
        assert!(audit_complete_generation(&root, &relative, &expected, &marker).is_err());
        fs::remove_file(alias).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn canonical_lock_produces_the_exact_pinned_generation_contract() {
        let lock = GameRuntimeLock::parse_and_validate(include_bytes!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        ))
        .unwrap();
        let expected = ExpectedGameTree::from_lock(&lock).unwrap();
        assert_eq!(expected.files.len(), PINNED_FILE_COUNT);
        assert_eq!(
            expected
                .files
                .values()
                .filter(|file| file.is_official())
                .count(),
            PINNED_OFFICIAL_COUNT
        );
        assert_eq!(
            expected
                .files
                .values()
                .filter(|file| file.is_derived())
                .count(),
            PINNED_DERIVED_COUNT
        );
        assert_eq!(expected.directories.len(), 535);
        assert_eq!(expected.total_bytes, 1_009_196_756);
        assert_eq!(expected.tree_sha256.len(), 64);
        assert_eq!(expected.processor_receipt_sha256.len(), 64);
        assert_eq!(expected.processor_outputs_sha256.len(), 64);
    }

    #[test]
    fn retry_removes_only_stale_workspaces_for_each_game_lock_without_accumulation() {
        let root_path = temp_root("stale-workspace");
        let selected = select_install_directory(&root_path).unwrap();
        let root = selected.into_owned_cas_root();
        ensure_generation_layout(&root).unwrap();
        let game_lock = "a".repeat(64);
        let other_lock = "b".repeat(64);
        let matching_name = format!("{game_lock}-{}-{}", Uuid::new_v4(), Uuid::new_v4());
        let other_name = format!("{other_lock}-{}-{}", Uuid::new_v4(), Uuid::new_v4());
        fs::create_dir(
            root_path
                .join("runtime/minecraft/workspaces")
                .join(&matching_name),
        )
        .unwrap();
        fs::create_dir(
            root_path
                .join("runtime/minecraft/workspaces")
                .join(&other_name),
        )
        .unwrap();
        fs::write(
            root_path
                .join("runtime/minecraft/workspaces")
                .join(&matching_name)
                .join("partial.bin"),
            b"partial",
        )
        .unwrap();

        let limits = ManagedDirectoryRemovalLimits {
            max_entries: 32,
            max_allocated_bytes: 1024 * 1024,
            max_depth: 8,
        };
        remove_stale_processor_workspaces(&root, limits).unwrap();
        assert!(!root_path
            .join("runtime/minecraft/workspaces")
            .join(matching_name)
            .exists());
        assert!(!root_path
            .join("runtime/minecraft/workspaces")
            .join(other_name)
            .exists());
        let second_matching = format!("{game_lock}-{}-{}", Uuid::new_v4(), Uuid::new_v4());
        fs::create_dir(
            root_path
                .join("runtime/minecraft/workspaces")
                .join(&second_matching),
        )
        .unwrap();
        remove_stale_processor_workspaces(&root, limits).unwrap();
        assert!(!root_path
            .join("runtime/minecraft/workspaces")
            .join(second_matching)
            .exists());
        drop(root);
        fs::remove_dir_all(root_path).unwrap();
    }

    #[test]
    fn deterministic_resume_keeps_verified_file_identity_and_adds_only_missing_file() {
        let root = temp_root("resume");
        let relative = RelativeManagedPath::new("runtime/minecraft/staging/lock").unwrap();
        let (expected, marker, files) = synthetic_contract();
        let generation = relative.join_to(&root);
        fs::create_dir_all(generation.join("image/versions/test")).unwrap();
        fs::create_dir_all(generation.join("image/libraries/test")).unwrap();
        fs::create_dir_all(root.join("incoming")).unwrap();
        fs::create_dir_all(root.join("source/libraries/test")).unwrap();
        fs::write(generation.join("image").join(files[0].0), files[0].1).unwrap();
        fs::write(root.join("source").join(files[1].0), files[1].1).unwrap();
        let first_relative = RelativeManagedPath::new(files[0].0).unwrap();
        let first_before = ImmutableManagedFile::open(&generation.join("image"), &first_relative)
            .unwrap()
            .info()
            .identity
            .clone();
        assert_eq!(
            audit_partial_generation(&root, &relative, &expected, &marker)
                .unwrap()
                .present_files
                .len(),
            1
        );

        let mut source = ImmutableManagedFile::open(
            &root.join("source"),
            &RelativeManagedPath::new(files[1].0).unwrap(),
        )
        .unwrap();
        let incoming = RelativeManagedPath::new("incoming/library.part").unwrap();
        let mut destination = ExclusiveManagedFile::create(&root, incoming).unwrap();
        let copied = source
            .copy_to_exclusive(&mut destination, files[1].1.len() as u64)
            .unwrap();
        assert_eq!(copied.sha256, expected.expected(files[1].0).unwrap().sha256);
        destination
            .sync()
            .unwrap()
            .rename_no_replace(image_relative(&relative, files[1].0).unwrap())
            .unwrap();
        let first_after = ImmutableManagedFile::open(&generation.join("image"), &first_relative)
            .unwrap()
            .info()
            .identity
            .clone();
        assert_eq!(first_after, first_before);
        assert_eq!(
            audit_partial_generation(&root, &relative, &expected, &marker)
                .unwrap()
                .present_files
                .len(),
            2
        );
        drop(source);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn crash_after_marker_resumes_through_the_real_commit_boundary() {
        let root = temp_root("marker-resume");
        fs::create_dir_all(root.join("runtime/minecraft/generations")).unwrap();
        let staging = RelativeManagedPath::new("runtime/minecraft/staging/lock").unwrap();
        let canonical = RelativeManagedPath::new("runtime/minecraft/generations/lock").unwrap();
        let (expected, marker, files) = synthetic_contract();
        write_generation(&root, &staging, &marker, &files);
        drop(
            audit_complete_generation(&root, &staging, &expected, &marker)
                .unwrap()
                .unwrap(),
        );
        let cancelled_flag = AtomicBool::new(false);
        commit_generation_directory_with(&cancelled_flag, || {
            move_managed_directory_no_replace_if(&root, staging.clone(), canonical.clone(), || {
                !cancelled_flag.load(Ordering::Acquire)
            })
        })
        .unwrap();
        assert!(!staging.join_to(&root).exists());
        drop(
            audit_complete_generation(&root, &canonical, &expected, &marker)
                .unwrap()
                .unwrap(),
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_at_final_predicate_never_publishes() {
        let root = temp_root("commit-cancel");
        fs::create_dir_all(root.join("runtime/minecraft/generations")).unwrap();
        let staging = RelativeManagedPath::new("runtime/minecraft/staging/lock").unwrap();
        let canonical = RelativeManagedPath::new("runtime/minecraft/generations/lock").unwrap();
        let (_expected, marker, files) = synthetic_contract();
        write_generation(&root, &staging, &marker, &files);
        let cancelled_flag = AtomicBool::new(false);
        let error = commit_generation_directory_with(&cancelled_flag, || {
            cancelled_flag.store(true, Ordering::Release);
            move_managed_directory_no_replace_if(&root, staging.clone(), canonical.clone(), || {
                !cancelled_flag.load(Ordering::Acquire)
            })
        })
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"));
        assert!(staging.join_to(&root).is_dir());
        assert!(!canonical.join_to(&root).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn concurrent_exact_winner_is_accepted_only_by_the_followup_audit() {
        let root = temp_root("concurrent-winner");
        let staging = RelativeManagedPath::new("runtime/minecraft/staging/lock").unwrap();
        let canonical = RelativeManagedPath::new("runtime/minecraft/generations/lock").unwrap();
        let (expected, marker, files) = synthetic_contract();
        write_generation(&root, &staging, &marker, &files);
        write_generation(&root, &canonical, &marker, &files);
        let cancelled_flag = AtomicBool::new(false);
        commit_generation_directory_with(&cancelled_flag, || {
            move_managed_directory_no_replace_if(&root, staging.clone(), canonical.clone(), || true)
        })
        .unwrap();
        drop(
            audit_complete_generation(&root, &canonical, &expected, &marker)
                .unwrap()
                .unwrap(),
        );
        assert!(staging.join_to(&root).is_dir());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn post_commit_durability_failure_never_returns_a_capability() {
        let cancelled_flag = AtomicBool::new(false);
        let error = commit_generation_directory_with(&cancelled_flag, || {
            Err(ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: PathBuf::from("runtime/minecraft/generations/lock"),
                detail: "injected parent flush failure".into(),
            })
        })
        .unwrap_err();
        assert!(matches!(
            error,
            GameGenerationError::AppliedButDurabilityUnconfirmed { .. }
        ));
    }
}
