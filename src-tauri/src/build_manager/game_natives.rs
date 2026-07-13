use super::{
    contracts::{domain_digest, GameRuntimeLock, GameRuntimeRole, GameRuntimeSource},
    game_generation::GameRuntimeInstallation,
    managed_fs::{
        ensure_directory_chain, remove_bounded_managed_directory_tree,
        remove_bounded_managed_garbage_tree, validate_no_named_data_streams, ExclusiveManagedFile,
        FileIdentity, GuardedDirectoryChain, ImmutableManagedFile, ManagedDirectoryRemovalLimits,
        RecursiveChangeSentinel, RelativeManagedPath,
    },
    storage::is_windows_reparse_point,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fmt, fs,
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zip::{CompressionMethod, ZipArchive};

const NATIVE_WORKSPACES_ROOT: &str = "state/launch/native-workspaces";
const SCRATCH_WORKSPACES_ROOT: &str = "state/launch/scratch-workspaces";
const RECEIPT_FILE: &str = ".fragment-native-receipt.json";
const SCRATCH_TEMP: &str = "temp";
const SCRATCH_HOME: &str = "user-home";
const SCRATCH_APPDATA: &str = "user-home/AppData/Roaming";
const SCRATCH_LOCAL_APPDATA: &str = "user-home/AppData/Local";
const RECEIPT_DOMAIN: &str = "ru.fragmc.launcher.native-workspace.v1";
const OUTPUTS_DOMAIN: &str = "ru.fragmc.launcher.native-workspace.outputs.v1";
const EXPECTED_WINDOWS_X64_ARCHIVES: usize = 8;
const MAX_NATIVE_ARCHIVES: usize = 32;
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ARCHIVE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 512;
const MAX_TOTAL_ARCHIVE_ENTRIES: usize = 4_096;
const MAX_ARCHIVE_DECLARED_BYTES: u64 = 256 * 1024 * 1024;
const MAX_TOTAL_DECLARED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_NATIVE_FILES: usize = 512;
const MAX_NATIVE_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_NATIVE_TOTAL_BYTES: u64 = 256 * 1024 * 1024;
const MAX_COMPRESSION_RATIO: u64 = 200;
const MAX_RECEIPT_BYTES: u64 = 256 * 1024;
const MAX_WORKSPACE_ENTRIES: usize = 2_048;
const MAX_INITIAL_SCRATCH_ENTRIES: usize = 16;
const WORKSPACE_CLEANUP_LIMITS: ManagedDirectoryRemovalLimits = ManagedDirectoryRemovalLimits {
    max_entries: 4_096,
    max_allocated_bytes: 1024 * 1024 * 1024,
    max_depth: 64,
};
const SCRATCH_CLEANUP_LIMITS: ManagedDirectoryRemovalLimits = ManagedDirectoryRemovalLimits {
    max_entries: 16_384,
    max_allocated_bytes: 4 * 1024 * 1024 * 1024,
    max_depth: 128,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeSourceReceipt {
    path: String,
    size: u64,
    sha1: String,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeOutputReceipt {
    path: String,
    archive_path: String,
    source_archive: String,
    size: u64,
    sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeWorkspaceReceipt {
    schema_version: u8,
    domain: String,
    launch_id: String,
    install_id: String,
    root_binding_nonce: String,
    inventory_fingerprint: String,
    game_runtime_lock_sha256: String,
    source_archives: Vec<NativeSourceReceipt>,
    files: Vec<NativeOutputReceipt>,
    file_count: usize,
    total_bytes: u64,
    outputs_sha256: String,
}

#[derive(Clone)]
struct SignedNativeArchive {
    relative: RelativeManagedPath,
    receipt: NativeSourceReceipt,
}

#[derive(Clone, Debug)]
struct PlannedNativeEntry {
    index: usize,
    archive_path: RelativeManagedPath,
    output_path: RelativeManagedPath,
    size: u64,
    compressed_size: u64,
    compression: CompressionMethod,
}

struct OpenNativeArchive {
    signed: SignedNativeArchive,
    file: ImmutableManagedFile,
    entries: Vec<PlannedNativeEntry>,
}

#[derive(Default)]
struct InspectionBudget {
    entries: usize,
    declared_bytes: u64,
}

#[derive(Default)]
struct OutputRegistry {
    files: BTreeMap<String, String>,
}

impl OutputRegistry {
    fn register(&mut self, path: &RelativeManagedPath) -> Result<(), String> {
        let key = path.collision_key().to_owned();
        match self.files.insert(key, path.as_str().to_owned()) {
            Some(existing) if existing == path.as_str() => {
                Err(format!("Native output is duplicated: {}", path.as_str()))
            }
            Some(existing) => Err(format!(
                "Native output has a Windows case collision: {existing} / {}",
                path.as_str()
            )),
            None => Ok(()),
        }
    }
}

struct ExpectedWorkspaceFile {
    path: String,
    size: u64,
    sha256: String,
    exact_bytes: Option<Vec<u8>>,
}

struct HeldWorkspaceFile {
    expected: ExpectedWorkspaceFile,
    file: ImmutableManagedFile,
}

struct NativeWorkspaceLease {
    root: PathBuf,
    expected: BTreeMap<String, ExpectedWorkspaceFile>,
    files: Vec<HeldWorkspaceFile>,
    root_guard: GuardedDirectoryChain,
    change_sentinel: RecursiveChangeSentinel,
}

impl NativeWorkspaceLease {
    fn revalidate(&mut self) -> Result<(), String> {
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| format!("Native workspace changed: {error}"))?;
        self.root_guard
            .revalidate()
            .map_err(|error| format!("Native workspace root changed: {error}"))?;
        if self.root_guard.leaf().info().named_streams != 0 {
            return Err("Native workspace root acquired an alternate data stream".into());
        }
        for held in &mut self.files {
            held.file
                .revalidate()
                .map_err(|error| format!("Native workspace file changed: {error}"))?;
            verify_no_named_streams(&self.root, &held.expected.path, &held.file)?;
            verify_workspace_file(&mut held.file, &held.expected)?;
        }
        validate_workspace_inventory(&self.root, &self.expected)?;
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| format!("Native workspace changed during full audit: {error}"))
    }

    fn revalidate_fast(&self) -> Result<(), String> {
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| format!("Native workspace changed after full audit: {error}"))
    }
}

struct ScratchWorkspaceLease {
    root: PathBuf,
    directory_guards: Vec<GuardedDirectoryChain>,
    expected_directories: BTreeMap<String, String>,
    receipt: ImmutableManagedFile,
    receipt_bytes: Vec<u8>,
    change_sentinel: RecursiveChangeSentinel,
}

impl ScratchWorkspaceLease {
    fn revalidate(&self) -> Result<(), String> {
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| format!("Launch scratch changed: {error}"))?;
        for guard in &self.directory_guards {
            guard
                .revalidate()
                .map_err(|error| format!("Launch scratch directory changed: {error}"))?;
            if guard.leaf().info().named_streams != 0 {
                return Err("Launch scratch directory acquired an alternate data stream".into());
            }
        }
        self.receipt
            .revalidate()
            .map_err(|error| format!("Native workspace receipt changed: {error}"))?;
        verify_no_named_streams(&self.root, RECEIPT_FILE, &self.receipt)?;
        let actual = self
            .receipt
            .read_bounded_shared(MAX_RECEIPT_BYTES)
            .map_err(|error| format!("Cannot re-read native workspace receipt: {error}"))?;
        if actual != self.receipt_bytes {
            return Err("Native workspace receipt bytes changed".into());
        }
        validate_scratch_inventory(&self.root, &self.expected_directories)?;
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| format!("Launch scratch changed during full audit: {error}"))
    }

    fn revalidate_fast(&self) -> Result<(), String> {
        self.change_sentinel
            .revalidate_clean()
            .map_err(|error| format!("Launch scratch changed after full audit: {error}"))
    }
}

/// Handle-bound, per-launch native directory. It is intentionally non-Clone and cannot be
/// rebound to a caller-supplied root after construction.
pub(super) struct NativeWorkspace {
    install_root: PathBuf,
    native_relative: RelativeManagedPath,
    native_path: PathBuf,
    native_identity: FileIdentity,
    scratch_relative: RelativeManagedPath,
    scratch_path: PathBuf,
    scratch_identity: FileIdentity,
    temp_path: PathBuf,
    home_path: PathBuf,
    appdata_path: PathBuf,
    local_appdata_path: PathBuf,
    native_lease: Option<NativeWorkspaceLease>,
    scratch_lease: Option<ScratchWorkspaceLease>,
    native_cleaned: bool,
    scratch_cleaned: bool,
}

impl fmt::Debug for NativeWorkspace {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeWorkspace")
            .field("native_path", &self.native_path)
            .field("scratch_path", &self.scratch_path)
            .field("native_cleaned", &self.native_cleaned)
            .field("scratch_cleaned", &self.scratch_cleaned)
            .finish_non_exhaustive()
    }
}

impl NativeWorkspace {
    pub(super) fn path(&self) -> &Path {
        &self.native_path
    }

    pub(super) fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    pub(super) fn home_path(&self) -> &Path {
        &self.home_path
    }

    pub(super) fn appdata_path(&self) -> &Path {
        &self.appdata_path
    }

    pub(super) fn local_appdata_path(&self) -> &Path {
        &self.local_appdata_path
    }

    pub(super) fn revalidate(&mut self) -> Result<(), String> {
        if self.native_cleaned || self.scratch_cleaned {
            return Err("Native workspace was already cleaned".into());
        }
        self.native_lease
            .as_mut()
            .ok_or_else(|| "Native workspace lease is missing".to_string())?
            .revalidate()?;
        self.scratch_lease
            .as_ref()
            .ok_or_else(|| "Launch scratch lease is missing".to_string())?
            .revalidate()?;
        self.native_lease
            .as_mut()
            .ok_or_else(|| "Native workspace lease is missing".to_string())?
            .revalidate()
    }

    /// Admission-window audit. The expected DLLs and receipt were fully hashed immediately before
    /// admission; this pass only polls the sticky native/scratch sentinels, so its runtime is
    /// independent of both file contents and namespace size.
    pub(super) fn revalidate_fast(&self) -> Result<(), String> {
        if self.native_cleaned || self.scratch_cleaned {
            return Err("Native workspace was already cleaned".into());
        }
        self.native_lease
            .as_ref()
            .ok_or_else(|| "Native workspace lease is missing".to_string())?
            .revalidate_fast()?;
        self.scratch_lease
            .as_ref()
            .ok_or_else(|| "Launch scratch lease is missing".to_string())?
            .revalidate_fast()?;
        self.native_lease
            .as_ref()
            .ok_or_else(|| "Native workspace lease is missing".to_string())?
            .revalidate_fast()
    }

    pub(super) fn cleanup(mut self) -> Result<(), String> {
        self.cleanup_inner()
    }

    fn cleanup_inner(&mut self) -> Result<(), String> {
        self.native_lease.take();
        self.scratch_lease.take();

        let native_result = if self.native_cleaned {
            Ok(())
        } else {
            remove_native_namespace(
                &self.install_root,
                &self.native_relative,
                &self.native_path,
                &self.native_identity,
            )
            .inspect(|_| self.native_cleaned = true)
        };
        // This is intentionally attempted even when native cleanup failed.
        let scratch_result = if self.scratch_cleaned {
            Ok(())
        } else {
            remove_scratch_namespace(
                &self.install_root,
                &self.scratch_relative,
                &self.scratch_path,
                &self.scratch_identity,
            )
            .inspect(|_| self.scratch_cleaned = true)
        };
        combine_cleanup_results(native_result, scratch_result)
    }
}

impl Drop for NativeWorkspace {
    fn drop(&mut self) {
        let _ = self.cleanup_inner();
    }
}

struct WorkspaceBuilder {
    install_root: PathBuf,
    launch_id: Uuid,
    native_relative: RelativeManagedPath,
    native_path: PathBuf,
    native_identity: FileIdentity,
    native_guard: Option<GuardedDirectoryChain>,
    scratch_relative: RelativeManagedPath,
    scratch_path: PathBuf,
    scratch_identity: FileIdentity,
    scratch_guards: Vec<GuardedDirectoryChain>,
    temp_path: PathBuf,
    home_path: PathBuf,
    appdata_path: PathBuf,
    local_appdata_path: PathBuf,
    armed: bool,
}

impl WorkspaceBuilder {
    fn release_native_guard(&mut self) {
        self.native_guard.take();
    }

    fn finish(
        mut self,
        native_lease: NativeWorkspaceLease,
        receipt: ImmutableManagedFile,
        receipt_bytes: Vec<u8>,
        scratch_sentinel: RecursiveChangeSentinel,
    ) -> NativeWorkspace {
        let scratch_lease = ScratchWorkspaceLease {
            root: self.scratch_path.clone(),
            directory_guards: std::mem::take(&mut self.scratch_guards),
            expected_directories: expected_scratch_directories(),
            receipt,
            receipt_bytes,
            change_sentinel: scratch_sentinel,
        };
        self.armed = false;
        NativeWorkspace {
            install_root: self.install_root.clone(),
            native_relative: self.native_relative.clone(),
            native_path: self.native_path.clone(),
            native_identity: self.native_identity.clone(),
            scratch_relative: self.scratch_relative.clone(),
            scratch_path: self.scratch_path.clone(),
            scratch_identity: self.scratch_identity.clone(),
            temp_path: self.temp_path.clone(),
            home_path: self.home_path.clone(),
            appdata_path: self.appdata_path.clone(),
            local_appdata_path: self.local_appdata_path.clone(),
            native_lease: Some(native_lease),
            scratch_lease: Some(scratch_lease),
            native_cleaned: false,
            scratch_cleaned: false,
        }
    }
}

impl Drop for WorkspaceBuilder {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        self.native_guard.take();
        self.scratch_guards.clear();
        let _ = remove_native_namespace(
            &self.install_root,
            &self.native_relative,
            &self.native_path,
            &self.native_identity,
        );
        let _ = remove_scratch_namespace(
            &self.install_root,
            &self.scratch_relative,
            &self.scratch_path,
            &self.scratch_identity,
        );
    }
}

fn remove_native_namespace(
    install_root: &Path,
    relative: &RelativeManagedPath,
    path: &Path,
    identity: &FileIdentity,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Cannot inspect native workspace for cleanup: {error}"
            ))
        }
        Ok(_) => {}
    }
    remove_bounded_managed_directory_tree(
        install_root,
        relative,
        identity,
        WORKSPACE_CLEANUP_LIMITS,
    )
    .map(|_| ())
    .map_err(|error| format!("Cannot clean native workspace safely: {error}"))
}

fn remove_scratch_namespace(
    install_root: &Path,
    relative: &RelativeManagedPath,
    path: &Path,
    identity: &FileIdentity,
) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "Cannot inspect launch scratch for cleanup: {error}"
            ))
        }
        Ok(_) => {}
    }
    remove_bounded_managed_garbage_tree(install_root, relative, identity, SCRATCH_CLEANUP_LIMITS)
        .map(|_| ())
        .map_err(|error| format!("Cannot clean launch scratch safely: {error}"))
}

fn combine_cleanup_results(
    native: Result<(), String>,
    scratch: Result<(), String>,
) -> Result<(), String> {
    match (native, scratch) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(native), Ok(())) => Err(native),
        (Ok(()), Err(scratch)) => Err(scratch),
        (Err(native), Err(scratch)) => Err(format!(
            "Native cleanup failed: {native}; scratch cleanup also failed: {scratch}"
        )),
    }
}

/// Extracts the signed Windows x64 LWJGL DLLs into one unique launcher-owned workspace.
/// Source JARs remain bound to the audited game image for the whole inspection/extraction pass.
pub(super) fn prepare_native_workspace(
    installed: &GameRuntimeInstallation,
    lock: &GameRuntimeLock,
) -> Result<NativeWorkspace, String> {
    installed.revalidate_against_lock(lock)?;
    let install_root = installed.install_root()?.to_path_buf();
    let signed = select_native_archives(lock)?;
    let (mut archives, output_registry) = open_and_inspect_archives(installed, lock, &signed)?;
    installed.revalidate_against_lock(lock)?;

    let mut builder = create_workspace(&install_root)?;
    let mut write_leases = Vec::with_capacity(output_registry.files.len());
    let mut outputs = Vec::with_capacity(output_registry.files.len());
    let mut total_bytes = 0_u64;
    for archive in &mut archives {
        extract_archive(
            archive,
            &install_root,
            &builder.native_relative,
            &mut write_leases,
            &mut outputs,
            &mut total_bytes,
        )?;
        archive
            .file
            .revalidate()
            .map_err(|error| format!("Native source JAR changed after extraction: {error}"))?;
    }
    if outputs.len() != output_registry.files.len()
        || outputs.len() > MAX_NATIVE_FILES
        || total_bytes > MAX_NATIVE_TOTAL_BYTES
    {
        return Err("Native extraction did not produce its exact inspected output set".into());
    }
    outputs.sort_by(|left, right| left.path.cmp(&right.path));

    let mut source_archives = signed
        .iter()
        .map(|source| source.receipt.clone())
        .collect::<Vec<_>>();
    source_archives.sort_by(|left, right| left.path.cmp(&right.path));
    let receipt = NativeWorkspaceReceipt {
        schema_version: 1,
        domain: RECEIPT_DOMAIN.to_owned(),
        launch_id: builder.launch_id.to_string(),
        install_id: installed.install_id().to_string(),
        root_binding_nonce: installed.root_binding_nonce().to_string(),
        inventory_fingerprint: installed.inventory_fingerprint().to_owned(),
        game_runtime_lock_sha256: installed.game_runtime_lock_sha256().to_owned(),
        source_archives,
        file_count: outputs.len(),
        total_bytes,
        outputs_sha256: domain_digest(OUTPUTS_DOMAIN, &outputs)?,
        files: outputs,
    };
    let receipt_bytes = canonical_receipt_bytes(&receipt)?;
    let receipt_relative = append_relative(&builder.scratch_relative, RECEIPT_FILE)?;
    let mut receipt_file = ExclusiveManagedFile::create(&install_root, receipt_relative)
        .map_err(|error| format!("Cannot create native workspace receipt: {error}"))?;
    receipt_file
        .file_mut()
        .write_all(&receipt_bytes)
        .map_err(|error| format!("Cannot write native workspace receipt: {error}"))?;
    let receipt_write_lease = receipt_file
        .seal_in_place()
        .map_err(|error| format!("Cannot seal native workspace receipt: {error}"))?;

    installed.revalidate_against_lock(lock)?;
    for file in &write_leases {
        file.revalidate()
            .map_err(|error| format!("New native workspace file changed: {error}"))?;
    }
    receipt_write_lease
        .revalidate()
        .map_err(|error| format!("New native workspace receipt changed: {error}"))?;
    drop(write_leases);
    drop(receipt_write_lease);
    drop(archives);
    let receipt_local =
        RelativeManagedPath::new(RECEIPT_FILE).expect("static native receipt path is valid");
    let receipt_lease = ImmutableManagedFile::open(&builder.scratch_path, &receipt_local)
        .map_err(|error| format!("Cannot reopen native workspace receipt: {error}"))?;
    let expected = expected_native_files(&receipt)?;
    // A Windows directory handle cannot seal child creation (verified empirically). Expected DLL
    // handles do deny replacement; the exact namespace is audited again immediately before
    // CreateProcessW. Point 5's in-game guard is the final same-user enforcement boundary after
    // spawn, so do not weaken this into a false directory-share "seal".
    builder.release_native_guard();

    let scratch_sentinel = RecursiveChangeSentinel::arm(&builder.scratch_path)
        .map_err(|error| format!("Cannot arm launch scratch change sentinel: {error}"))?;
    let mut lease = audit_workspace(&builder.native_path, expected)?;
    lease.revalidate()?;
    for guard in &builder.scratch_guards {
        guard
            .revalidate()
            .map_err(|error| format!("Launch scratch directory changed: {error}"))?;
    }
    verify_no_named_streams(&builder.scratch_path, RECEIPT_FILE, &receipt_lease)?;
    if receipt_lease
        .read_bounded_shared(MAX_RECEIPT_BYTES)
        .map_err(|error| format!("Cannot re-read native workspace receipt: {error}"))?
        != receipt_bytes
    {
        return Err("Native workspace receipt bytes changed".into());
    }
    validate_scratch_inventory(&builder.scratch_path, &expected_scratch_directories())?;
    installed.revalidate_against_lock(lock)?;
    scratch_sentinel
        .revalidate_clean()
        .map_err(|error| format!("Launch scratch changed during full audit: {error}"))?;
    Ok(builder.finish(lease, receipt_lease, receipt_bytes, scratch_sentinel))
}

fn select_native_archives(lock: &GameRuntimeLock) -> Result<Vec<SignedNativeArchive>, String> {
    lock.validate()?;
    let mut selected = Vec::new();
    let mut seen = HashMap::new();
    let mut total = 0_u64;
    for file in &lock.files {
        if file.role != GameRuntimeRole::NativeLibrary
            || !file.path.ends_with("-natives-windows.jar")
        {
            continue;
        }
        let relative = RelativeManagedPath::new(&file.path)
            .map_err(|error| format!("Signed native JAR path is unsafe: {error}"))?;
        if relative.as_str() != file.path {
            return Err("Signed native JAR path is not canonical".into());
        }
        if seen
            .insert(relative.collision_key().to_owned(), file.path.clone())
            .is_some()
        {
            return Err("Signed native JAR list contains a Windows path collision".into());
        }
        let GameRuntimeSource::Official {
            size, sha1, sha256, ..
        } = &file.source
        else {
            return Err("Native JAR must be an official signed artifact".into());
        };
        if *size > MAX_ARCHIVE_BYTES {
            return Err(format!("Native JAR exceeds its bound: {}", file.path));
        }
        total = total
            .checked_add(*size)
            .ok_or_else(|| "Native JAR byte total overflowed".to_string())?;
        if total > MAX_ARCHIVE_TOTAL_BYTES {
            return Err("Native JAR set exceeds its byte bound".into());
        }
        selected.push(SignedNativeArchive {
            relative,
            receipt: NativeSourceReceipt {
                path: file.path.clone(),
                size: *size,
                sha1: sha1.clone(),
                sha256: sha256.clone(),
            },
        });
    }
    if selected.len() != EXPECTED_WINDOWS_X64_ARCHIVES || selected.len() > MAX_NATIVE_ARCHIVES {
        return Err(format!(
            "Signed runtime must contain exactly {EXPECTED_WINDOWS_X64_ARCHIVES} Windows x64 native JARs"
        ));
    }
    selected.sort_by(|left, right| left.receipt.path.cmp(&right.receipt.path));
    Ok(selected)
}

fn open_and_inspect_archives(
    installed: &GameRuntimeInstallation,
    lock: &GameRuntimeLock,
    signed: &[SignedNativeArchive],
) -> Result<(Vec<OpenNativeArchive>, OutputRegistry), String> {
    let mut registry = OutputRegistry::default();
    let mut budget = InspectionBudget::default();
    let mut archives = Vec::with_capacity(signed.len());
    for source in signed {
        installed.revalidate_against_lock(lock)?;
        let mut file = ImmutableManagedFile::open(installed.image(), &source.relative)
            .map_err(|error| format!("Native source JAR is unsafe: {error}"))?;
        let actual = file
            .sha1_sha256(MAX_ARCHIVE_BYTES)
            .map_err(|error| format!("Cannot hash native source JAR: {error}"))?;
        if actual.size != source.receipt.size
            || actual.sha1 != source.receipt.sha1
            || actual.sha256 != source.receipt.sha256
        {
            return Err(format!(
                "Native source JAR does not match the signed lock: {}",
                source.receipt.path
            ));
        }
        let entries = inspect_archive(&mut file, source, &mut registry, &mut budget)?;
        if entries.is_empty() {
            return Err(format!(
                "Native source JAR contains no Windows x64 DLL: {}",
                source.receipt.path
            ));
        }
        file.revalidate()
            .map_err(|error| format!("Native source JAR changed during inspection: {error}"))?;
        archives.push(OpenNativeArchive {
            signed: source.clone(),
            file,
            entries,
        });
        installed.revalidate_against_lock(lock)?;
    }
    if registry.files.is_empty() || registry.files.len() > MAX_NATIVE_FILES {
        return Err("Native DLL output count is outside the launcher bound".into());
    }
    Ok((archives, registry))
}

fn inspect_archive<R: Read + Seek>(
    reader: &mut R,
    source: &SignedNativeArchive,
    registry: &mut OutputRegistry,
    budget: &mut InspectionBudget,
) -> Result<Vec<PlannedNativeEntry>, String> {
    reader
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| format!("Cannot rewind native JAR: {error}"))?;
    let mut archive = ZipArchive::new(&mut *reader)
        .map_err(|error| format!("Native JAR is not a valid ZIP: {error}"))?;
    if archive.offset() != 0
        || archive.is_empty()
        || archive.len() > MAX_ARCHIVE_ENTRIES
        || archive
            .has_overlapping_files()
            .map_err(|error| format!("Cannot inspect native JAR overlap: {error}"))?
    {
        return Err(format!(
            "Native JAR has an unsafe ZIP layout: {}",
            source.receipt.path
        ));
    }
    budget.entries = budget
        .entries
        .checked_add(archive.len())
        .ok_or_else(|| "Native JAR entry count overflowed".to_string())?;
    if budget.entries > MAX_TOTAL_ARCHIVE_ENTRIES {
        return Err("Native JAR set exceeds its entry bound".into());
    }

    let mut planned = Vec::new();
    let mut seen_entries = HashMap::new();
    let mut archive_declared = 0_u64;
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|error| format!("Cannot inspect native JAR entry {index}: {error}"))?;
        let (managed, is_directory) = validate_archive_entry(&entry)?;
        if seen_entries
            .insert(
                managed.collision_key().to_owned(),
                managed.as_str().to_owned(),
            )
            .is_some()
        {
            return Err(format!(
                "Native JAR contains a duplicate/case-colliding entry: {}",
                managed.as_str()
            ));
        }
        if is_directory {
            continue;
        }

        archive_declared = archive_declared
            .checked_add(entry.size())
            .ok_or_else(|| "Native JAR declared byte count overflowed".to_string())?;
        budget.declared_bytes = budget
            .declared_bytes
            .checked_add(entry.size())
            .ok_or_else(|| "Native JAR set declared byte count overflowed".to_string())?;
        if archive_declared > MAX_ARCHIVE_DECLARED_BYTES
            || budget.declared_bytes > MAX_TOTAL_DECLARED_BYTES
        {
            return Err("Native JAR declared output exceeds its byte bound".into());
        }
        validate_compression_ratio(&entry)?;

        if is_meta_inf(&managed) {
            continue;
        }
        let lower_name = managed.file_name().to_ascii_lowercase();
        if lower_name.ends_with(".so")
            || lower_name.ends_with(".dylib")
            || lower_name.ends_with(".jnilib")
        {
            return Err(format!(
                "Non-Windows native library is forbidden in x64 native JAR: {}",
                managed.as_str()
            ));
        }
        if !lower_name.ends_with(".dll") {
            continue;
        }
        if !managed.as_str().starts_with("windows/x64/") {
            return Err(format!(
                "DLL is outside the signed Windows x64 namespace: {}",
                managed.as_str()
            ));
        }
        if entry.size() == 0 || entry.size() > MAX_NATIVE_FILE_BYTES {
            return Err(format!(
                "Native DLL size is outside the launcher bound: {}",
                managed.as_str()
            ));
        }

        // `java.library.path` points at the workspace root. The signed LWJGL jars namespace their
        // DLLs below windows/x64, so flatten only the already-validated basename and reject every
        // cross-JAR Windows collision before a file is created.
        let output_path = RelativeManagedPath::new(managed.file_name())
            .map_err(|error| format!("Native DLL basename is unsafe: {error}"))?;
        registry.register(&output_path)?;
        planned.push(PlannedNativeEntry {
            index,
            archive_path: managed,
            output_path,
            size: entry.size(),
            compressed_size: entry.compressed_size(),
            compression: entry.compression(),
        });
    }
    Ok(planned)
}

fn validate_archive_entry<R: Read>(
    entry: &zip::read::ZipFile<'_, R>,
) -> Result<(RelativeManagedPath, bool), String> {
    let name = entry.name();
    if entry.name_raw() != name.as_bytes()
        || name.is_empty()
        || name.starts_with('/')
        || name.contains('\0')
        || name.contains('\\')
        || entry.encrypted()
    {
        return Err(format!("Native JAR entry name is unsafe: {name:?}"));
    }
    let is_directory = entry.is_dir();
    if is_directory != name.ends_with('/') {
        return Err(format!(
            "Native JAR directory marker is inconsistent: {name}"
        ));
    }
    let normalized = name.trim_end_matches('/');
    if normalized.is_empty()
        || normalized.contains("//")
        || normalized
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(format!("Native JAR entry traverses its root: {name}"));
    }
    let managed = RelativeManagedPath::new(normalized)
        .map_err(|error| format!("Native JAR entry is Windows-unsafe: {error}"))?;
    if entry.is_symlink() || (!is_directory && !entry.is_file()) {
        return Err(format!(
            "Link/special native JAR entry is forbidden: {name}"
        ));
    }
    if let Some(mode) = entry.unix_mode() {
        let file_type = mode & 0o170_000;
        let valid = if is_directory {
            file_type == 0 || file_type == 0o040_000
        } else {
            file_type == 0 || file_type == 0o100_000
        };
        if !valid {
            return Err(format!(
                "Special native JAR entry mode is forbidden: {name}"
            ));
        }
    }
    if !matches!(
        entry.compression(),
        CompressionMethod::Stored | CompressionMethod::Deflated
    ) {
        return Err(format!(
            "Unsupported native JAR compression is forbidden: {name}"
        ));
    }
    if is_directory && (entry.size() != 0 || entry.compressed_size() != 0) {
        return Err(format!("Native JAR directory contains data: {name}"));
    }
    Ok((managed, is_directory))
}

fn validate_compression_ratio<R: Read>(entry: &zip::read::ZipFile<'_, R>) -> Result<(), String> {
    if entry.size() > MAX_NATIVE_FILE_BYTES {
        return Err(format!(
            "Native JAR entry exceeds the per-file bound: {}",
            entry.name()
        ));
    }
    if entry.size() == 0 {
        return Ok(());
    }
    if entry.compressed_size() == 0
        || entry.size()
            > entry
                .compressed_size()
                .saturating_mul(MAX_COMPRESSION_RATIO)
    {
        return Err(format!(
            "Native JAR entry exceeds the compression-ratio bound: {}",
            entry.name()
        ));
    }
    Ok(())
}

fn is_meta_inf(path: &RelativeManagedPath) -> bool {
    path.as_str()
        .split('/')
        .next()
        .is_some_and(|component| component.eq_ignore_ascii_case("META-INF"))
}

fn extract_archive(
    source: &mut OpenNativeArchive,
    install_root: &Path,
    workspace: &RelativeManagedPath,
    write_leases: &mut Vec<ImmutableManagedFile>,
    outputs: &mut Vec<NativeOutputReceipt>,
    total_bytes: &mut u64,
) -> Result<(), String> {
    source
        .file
        .seek(std::io::SeekFrom::Start(0))
        .map_err(|error| format!("Cannot rewind native source JAR: {error}"))?;
    let source_path = source.signed.receipt.path.clone();
    let mut archive = ZipArchive::new(&mut source.file)
        .map_err(|error| format!("Cannot reopen inspected native JAR: {error}"))?;
    if archive.offset() != 0
        || archive
            .has_overlapping_files()
            .map_err(|error| format!("Cannot recheck native JAR overlap: {error}"))?
    {
        return Err("Native JAR layout changed before extraction".into());
    }
    for planned in &source.entries {
        let mut entry = archive.by_index(planned.index).map_err(|error| {
            format!(
                "Cannot reopen native JAR entry {}: {error}",
                planned.archive_path.as_str()
            )
        })?;
        let (actual_path, is_directory) = validate_archive_entry(&entry)?;
        if is_directory
            || actual_path != planned.archive_path
            || entry.size() != planned.size
            || entry.compressed_size() != planned.compressed_size
            || entry.compression() != planned.compression
        {
            return Err(format!(
                "Native JAR entry changed between inspection and extraction: {}",
                planned.archive_path.as_str()
            ));
        }
        let destination = append_managed(workspace, &planned.output_path)?;
        let mut output = ExclusiveManagedFile::create(install_root, destination)
            .map_err(|error| format!("Cannot create native DLL: {error}"))?;
        let mut digest = Sha256::new();
        let mut written = 0_u64;
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let read = entry.read(&mut buffer).map_err(|error| {
                format!(
                    "Cannot decompress native DLL {}: {error}",
                    planned.archive_path.as_str()
                )
            })?;
            if read == 0 {
                break;
            }
            written = written
                .checked_add(read as u64)
                .ok_or_else(|| "Native DLL byte count overflowed".to_string())?;
            if written > planned.size {
                return Err(format!(
                    "Native DLL exceeded its inspected size: {}",
                    planned.archive_path.as_str()
                ));
            }
            output
                .file_mut()
                .write_all(&buffer[..read])
                .map_err(|error| format!("Cannot write native DLL: {error}"))?;
            digest.update(&buffer[..read]);
        }
        if written != planned.size {
            return Err(format!(
                "Native DLL did not reach its inspected size: {}",
                planned.archive_path.as_str()
            ));
        }
        *total_bytes = total_bytes
            .checked_add(written)
            .ok_or_else(|| "Native DLL total size overflowed".to_string())?;
        if *total_bytes > MAX_NATIVE_TOTAL_BYTES {
            return Err("Native DLL output exceeds its total byte bound".into());
        }
        outputs.push(NativeOutputReceipt {
            path: planned.output_path.as_str().to_owned(),
            archive_path: planned.archive_path.as_str().to_owned(),
            source_archive: source_path.clone(),
            size: written,
            sha256: format!("{:x}", digest.finalize()),
        });
        write_leases.push(
            output
                .seal_in_place()
                .map_err(|error| format!("Cannot seal native DLL: {error}"))?,
        );
    }
    Ok(())
}

fn create_workspace(install_root: &Path) -> Result<WorkspaceBuilder, String> {
    let native_base = RelativeManagedPath::new(NATIVE_WORKSPACES_ROOT)
        .expect("static native workspace root is valid");
    let scratch_base = RelativeManagedPath::new(SCRATCH_WORKSPACES_ROOT)
        .expect("static scratch workspace root is valid");
    let native_base_guard = ensure_directory_chain(install_root, &native_base)
        .map_err(|error| format!("Cannot create native workspace layout: {error}"))?;
    native_base_guard
        .revalidate()
        .map_err(|error| format!("Native workspace layout changed: {error}"))?;
    let scratch_base_guard = ensure_directory_chain(install_root, &scratch_base)
        .map_err(|error| format!("Cannot create launch scratch layout: {error}"))?;
    scratch_base_guard
        .revalidate()
        .map_err(|error| format!("Launch scratch layout changed: {error}"))?;

    let launch_id = Uuid::new_v4();
    let launch_name = launch_id.to_string();
    let native_relative = native_base
        .join_component(&launch_name)
        .map_err(|error| format!("Cannot derive native workspace path: {error}"))?;
    let scratch_relative = scratch_base
        .join_component(&launch_name)
        .map_err(|error| format!("Cannot derive scratch workspace path: {error}"))?;
    let native_guard = GuardedDirectoryChain::create_exclusive(install_root, &native_relative)
        .map_err(|error| format!("Cannot create exclusive native workspace: {error}"))?;
    let stable_install_root = native_guard.root_path().to_path_buf();
    let native_identity = native_guard.leaf().info().identity.clone();
    let native_path = native_relative.join_to(install_root);
    if native_guard.leaf().info().named_streams != 0 {
        return Err("Native workspace path/stream binding is invalid".into());
    }
    let scratch_guard = match GuardedDirectoryChain::create_exclusive(
        &stable_install_root,
        &scratch_relative,
    ) {
        Ok(guard) => guard,
        Err(error) => {
            drop(native_guard);
            let cleanup = remove_native_namespace(
                &stable_install_root,
                &native_relative,
                &native_path,
                &native_identity,
            );
            return Err(match cleanup {
                Ok(()) => format!("Cannot create exclusive launch scratch: {error}"),
                Err(cleanup) => format!(
                    "Cannot create exclusive launch scratch: {error}; native rollback failed: {cleanup}"
                ),
            });
        }
    };
    let scratch_identity = scratch_guard.leaf().info().identity.clone();
    if scratch_guard.leaf().info().named_streams != 0 {
        drop(scratch_guard);
        drop(native_guard);
        let native = remove_native_namespace(
            &stable_install_root,
            &native_relative,
            &native_path,
            &native_identity,
        );
        let scratch = remove_scratch_namespace(
            &stable_install_root,
            &scratch_relative,
            &scratch_relative.join_to(install_root),
            &scratch_identity,
        );
        return combine_cleanup_results(native, scratch)
            .and(Err("Launch scratch path/stream binding is invalid".into()));
    }
    // Keep the ordinary absolute DOS path for Java. The guard has already proved it resolves to
    // the exact handle-bound `\\?\` path retained through `stable_install_root` for cleanup.
    let scratch_path = scratch_relative.join_to(install_root);
    let mut builder = WorkspaceBuilder {
        install_root: stable_install_root,
        launch_id,
        native_relative,
        native_path,
        native_identity,
        native_guard: Some(native_guard),
        scratch_relative,
        scratch_path: scratch_path.clone(),
        scratch_identity,
        scratch_guards: vec![scratch_guard],
        temp_path: scratch_path.join(SCRATCH_TEMP),
        home_path: scratch_path.join(SCRATCH_HOME),
        appdata_path: scratch_path
            .join(SCRATCH_HOME)
            .join("AppData")
            .join("Roaming"),
        local_appdata_path: scratch_path
            .join(SCRATCH_HOME)
            .join("AppData")
            .join("Local"),
        armed: true,
    };
    for suffix in [
        SCRATCH_TEMP,
        SCRATCH_HOME,
        SCRATCH_APPDATA,
        SCRATCH_LOCAL_APPDATA,
    ] {
        let relative = append_relative(&builder.scratch_relative, suffix)?;
        let guard = ensure_directory_chain(&builder.install_root, &relative)
            .map_err(|error| format!("Cannot create launch scratch directory: {error}"))?;
        if guard.leaf().info().named_streams != 0 {
            return Err("Launch scratch directory has an alternate data stream".into());
        }
        builder.scratch_guards.push(guard);
    }
    Ok(builder)
}

fn append_relative(
    base: &RelativeManagedPath,
    suffix: &str,
) -> Result<RelativeManagedPath, String> {
    RelativeManagedPath::new(&format!("{}/{suffix}", base.as_str()))
        .map_err(|error| format!("Cannot derive managed native path: {error}"))
}

fn append_managed(
    base: &RelativeManagedPath,
    suffix: &RelativeManagedPath,
) -> Result<RelativeManagedPath, String> {
    append_relative(base, suffix.as_str())
}

fn canonical_receipt_bytes(receipt: &NativeWorkspaceReceipt) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec(receipt)
        .map_err(|error| format!("Cannot serialize native workspace receipt: {error}"))?;
    bytes.push(b'\n');
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err("Native workspace receipt exceeds its byte bound".into());
    }
    Ok(bytes)
}

fn expected_native_files(
    receipt: &NativeWorkspaceReceipt,
) -> Result<BTreeMap<String, ExpectedWorkspaceFile>, String> {
    let mut expected = BTreeMap::new();
    for output in &receipt.files {
        let relative = RelativeManagedPath::new(&output.path)
            .map_err(|error| format!("Native receipt output path is unsafe: {error}"))?;
        if relative.parent().is_some() {
            return Err("Native DLL output is not flattened into workspace root".into());
        }
        let value = ExpectedWorkspaceFile {
            path: output.path.clone(),
            size: output.size,
            sha256: output.sha256.clone(),
            exact_bytes: None,
        };
        if expected
            .insert(relative.collision_key().to_owned(), value)
            .is_some()
        {
            return Err("Native receipt output contains a Windows collision".into());
        }
    }
    Ok(expected)
}

fn expected_scratch_directories() -> BTreeMap<String, String> {
    let mut expected = BTreeMap::new();
    for path in [
        SCRATCH_TEMP,
        SCRATCH_HOME,
        "user-home/AppData",
        SCRATCH_APPDATA,
        SCRATCH_LOCAL_APPDATA,
    ] {
        let managed = RelativeManagedPath::new(path).expect("static scratch path is valid");
        expected.insert(
            managed.collision_key().to_owned(),
            managed.as_str().to_owned(),
        );
    }
    expected
}

fn validate_scratch_inventory(
    root: &Path,
    expected_directories: &BTreeMap<String, String>,
) -> Result<(), String> {
    let root_guard = GuardedDirectoryChain::root_snapshot(root)
        .map_err(|error| format!("Launch scratch root is unsafe: {error}"))?;
    if root_guard.leaf().info().named_streams != 0 {
        return Err("Launch scratch root has an alternate data stream".into());
    }
    let mut seen_directories = BTreeSet::new();
    let mut receipt_seen = false;
    let mut entries = 0_usize;
    scan_scratch_inventory(
        root_guard.root_path(),
        root_guard.root_path(),
        expected_directories,
        &mut seen_directories,
        &mut receipt_seen,
        &mut entries,
    )?;
    if seen_directories != expected_directories.keys().cloned().collect() || !receipt_seen {
        return Err("Launch scratch initial inventory is incomplete".into());
    }
    Ok(())
}

fn scan_scratch_inventory(
    root: &Path,
    directory: &Path,
    expected_directories: &BTreeMap<String, String>,
    seen_directories: &mut BTreeSet<String>,
    receipt_seen: &mut bool,
    entries: &mut usize,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("Cannot enumerate launch scratch: {error}"))?
    {
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "Launch scratch entry count overflowed".to_string())?;
        if *entries > MAX_INITIAL_SCRATCH_ENTRIES {
            return Err("Launch scratch initial inventory exceeds its entry bound".into());
        }
        let entry = entry.map_err(|error| format!("Cannot inspect launch scratch: {error}"))?;
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect launch scratch metadata: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err("Link/reparse point is forbidden in launch scratch before spawn".into());
        }
        let relative = relative_workspace_path(root, &absolute)?;
        let key = relative.collision_key().to_owned();
        if metadata.is_dir() {
            let canonical = expected_directories.get(&key).ok_or_else(|| {
                format!(
                    "Unexpected launch scratch directory before spawn: {}",
                    relative.as_str()
                )
            })?;
            if canonical != relative.as_str() || !seen_directories.insert(key) {
                return Err("Launch scratch directory casing/collision changed".into());
            }
            let guard = GuardedDirectoryChain::open_snapshot(root, &relative)
                .map_err(|error| format!("Launch scratch directory is unsafe: {error}"))?;
            if guard.leaf().info().named_streams != 0 {
                return Err("Launch scratch directory has an alternate data stream".into());
            }
            scan_scratch_inventory(
                root,
                guard.leaf().path(),
                expected_directories,
                seen_directories,
                receipt_seen,
                entries,
            )?;
        } else if metadata.is_file() {
            if relative.as_str() != RECEIPT_FILE || *receipt_seen {
                return Err(format!(
                    "Unexpected launch scratch file before spawn: {}",
                    relative.as_str()
                ));
            }
            let file = ImmutableManagedFile::open(root, &relative)
                .map_err(|error| format!("Launch scratch file is unsafe: {error}"))?;
            verify_no_named_streams(root, RECEIPT_FILE, &file)?;
            *receipt_seen = true;
        } else {
            return Err("Special file is forbidden in launch scratch before spawn".into());
        }
    }
    Ok(())
}

fn audit_workspace(
    root: &Path,
    expected: BTreeMap<String, ExpectedWorkspaceFile>,
) -> Result<NativeWorkspaceLease, String> {
    let change_sentinel = RecursiveChangeSentinel::arm(root)
        .map_err(|error| format!("Cannot arm native workspace change sentinel: {error}"))?;
    let root_guard = GuardedDirectoryChain::root_snapshot(root)
        .map_err(|error| format!("Native workspace root is unsafe: {error}"))?;
    if root_guard.leaf().info().named_streams != 0 {
        return Err("Native workspace root has an alternate data stream".into());
    }
    let mut seen = BTreeSet::new();
    let mut files = Vec::with_capacity(expected.len());
    let mut entries = 0_usize;
    scan_workspace_files(
        root_guard.root_path(),
        root_guard.root_path(),
        &expected,
        &mut seen,
        &mut files,
        &mut entries,
    )?;
    if seen != expected.keys().cloned().collect() {
        return Err("Native workspace file inventory is incomplete".into());
    }
    Ok(NativeWorkspaceLease {
        root: root_guard.root_path().to_path_buf(),
        expected,
        files,
        root_guard,
        change_sentinel,
    })
}

fn scan_workspace_files(
    root: &Path,
    directory: &Path,
    expected: &BTreeMap<String, ExpectedWorkspaceFile>,
    seen: &mut BTreeSet<String>,
    files: &mut Vec<HeldWorkspaceFile>,
    entries: &mut usize,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("Cannot enumerate native workspace: {error}"))?
    {
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "Native workspace entry count overflowed".to_string())?;
        if *entries > MAX_WORKSPACE_ENTRIES {
            return Err("Native workspace exceeds its entry bound".into());
        }
        let entry = entry.map_err(|error| format!("Cannot inspect native workspace: {error}"))?;
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect native workspace metadata: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err("Link/reparse point is forbidden in native workspace".into());
        }
        let relative = relative_workspace_path(root, &absolute)?;
        if metadata.is_dir() {
            return Err(format!(
                "Unexpected directory in flattened native workspace: {}",
                relative.as_str()
            ));
        }
        if !metadata.is_file() {
            return Err("Special file is forbidden in native workspace".into());
        }
        let key = relative.collision_key().to_owned();
        let expected_file = expected
            .get(&key)
            .ok_or_else(|| format!("Unexpected native workspace file: {}", relative.as_str()))?;
        if expected_file.path != relative.as_str() || !seen.insert(key) {
            return Err("Native workspace contains a duplicate/case-colliding file".into());
        }
        let mut file = ImmutableManagedFile::open(root, &relative)
            .map_err(|error| format!("Native workspace file is unsafe: {error}"))?;
        verify_no_named_streams(root, &expected_file.path, &file)?;
        verify_workspace_file(&mut file, expected_file)?;
        files.push(HeldWorkspaceFile {
            expected: ExpectedWorkspaceFile {
                path: expected_file.path.clone(),
                size: expected_file.size,
                sha256: expected_file.sha256.clone(),
                exact_bytes: expected_file.exact_bytes.clone(),
            },
            file,
        });
    }
    Ok(())
}

fn validate_workspace_inventory(
    root: &Path,
    expected: &BTreeMap<String, ExpectedWorkspaceFile>,
) -> Result<(), String> {
    let fresh_root = GuardedDirectoryChain::root_snapshot(root)
        .map_err(|error| format!("Cannot reopen native workspace root: {error}"))?;
    if fresh_root.leaf().info().named_streams != 0 {
        return Err("Native workspace root acquired an alternate data stream".into());
    }
    let mut seen = BTreeSet::new();
    let mut count = 0_usize;
    for entry in fs::read_dir(fresh_root.leaf().path())
        .map_err(|error| format!("Cannot re-enumerate native workspace: {error}"))?
    {
        count = count
            .checked_add(1)
            .ok_or_else(|| "Native workspace entry count overflowed".to_string())?;
        if count > MAX_WORKSPACE_ENTRIES {
            return Err("Native workspace exceeds its entry bound".into());
        }
        let entry = entry.map_err(|error| format!("Cannot inspect native workspace: {error}"))?;
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect native workspace metadata: {error}"))?;
        if metadata.file_type().is_symlink()
            || is_windows_reparse_point(&metadata)
            || !metadata.is_file()
        {
            return Err("Native workspace acquired a non-regular file".into());
        }
        let relative = relative_workspace_path(root, &absolute)?;
        let key = relative.collision_key().to_owned();
        let expected_file = expected
            .get(&key)
            .filter(|value| value.path == relative.as_str())
            .ok_or_else(|| format!("Native workspace inventory changed: {}", relative.as_str()))?;
        if !seen.insert(key) {
            return Err("Native workspace acquired a duplicate/case collision".into());
        }
        let file = ImmutableManagedFile::open(root, &relative)
            .map_err(|error| format!("Native workspace file is unsafe: {error}"))?;
        if file.info().size != expected_file.size {
            return Err(format!(
                "Native workspace file size changed: {}",
                relative.as_str()
            ));
        }
        verify_no_named_streams(root, &expected_file.path, &file)?;
    }
    if seen != expected.keys().cloned().collect() {
        return Err("Native workspace inventory is no longer exact".into());
    }
    Ok(())
}

fn verify_workspace_file(
    file: &mut ImmutableManagedFile,
    expected: &ExpectedWorkspaceFile,
) -> Result<(), String> {
    if let Some(exact) = &expected.exact_bytes {
        let actual = file
            .read_bounded(MAX_RECEIPT_BYTES)
            .map_err(|error| format!("Cannot read native workspace receipt: {error}"))?;
        if &actual != exact || actual.len() as u64 != expected.size {
            return Err("Native workspace receipt bytes changed".into());
        }
        return Ok(());
    }
    let actual = file
        .sha256(expected.size)
        .map_err(|error| format!("Cannot hash native workspace file: {error}"))?;
    if actual.size != expected.size || actual.sha256 != expected.sha256 {
        return Err(format!(
            "Native workspace file digest changed: {}",
            expected.path
        ));
    }
    Ok(())
}

fn verify_no_named_streams(
    root: &Path,
    relative: &str,
    leased: &ImmutableManagedFile,
) -> Result<(), String> {
    if leased.info().named_streams != 0 {
        return Err(format!(
            "Alternate data stream is forbidden in native workspace: {relative}"
        ));
    }
    // The immutable no-follow lease prevents base-file replacement while this fresh handle
    // re-enumerates NTFS streams. On non-Windows the shared primitive is a no-op.
    let path = root.join(relative);
    let stream_handle = fs::File::open(&path)
        .map_err(|error| format!("Cannot open native workspace stream audit handle: {error}"))?;
    validate_no_named_data_streams(&stream_handle, &path)
        .map_err(|error| format!("Native workspace stream audit failed: {error}"))
}

fn relative_workspace_path(root: &Path, absolute: &Path) -> Result<RelativeManagedPath, String> {
    let relative = absolute
        .strip_prefix(root)
        .map_err(|_| "Native workspace entry escaped its root".to_string())?
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| "Native workspace path is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?
        .join("/");
    RelativeManagedPath::new(&relative)
        .map_err(|error| format!("Native workspace path is unsafe: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Cursor,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zip::{write::SimpleFileOptions, ZipWriter};

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, bytes) in entries {
            writer.start_file(*name, options).expect("start ZIP entry");
            writer.write_all(bytes).expect("write ZIP entry");
        }
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn symlink_zip(name: &str) -> Vec<u8> {
        let cursor = Cursor::new(Vec::new());
        let mut writer = ZipWriter::new(cursor);
        writer
            .add_symlink(name, "target", SimpleFileOptions::default())
            .expect("add ZIP symlink");
        writer.finish().expect("finish ZIP").into_inner()
    }

    fn mutate_zip_u16(bytes: &mut [u8], signature: &[u8; 4], field_offset: usize, value: u16) {
        let offset = bytes
            .windows(signature.len())
            .position(|window| window == signature)
            .expect("ZIP signature");
        bytes[offset + field_offset..offset + field_offset + 2]
            .copy_from_slice(&value.to_le_bytes());
    }

    fn signed_source(bytes: &[u8], suffix: &str) -> SignedNativeArchive {
        let path = format!("libraries/test-{suffix}-natives-windows.jar");
        SignedNativeArchive {
            relative: RelativeManagedPath::new(&path).unwrap(),
            receipt: NativeSourceReceipt {
                path,
                size: bytes.len() as u64,
                sha1: "0".repeat(40),
                sha256: format!("{:x}", Sha256::digest(bytes)),
            },
        }
    }

    fn inspect_bytes(
        bytes: &[u8],
        suffix: &str,
        registry: &mut OutputRegistry,
        budget: &mut InspectionBudget,
    ) -> Result<Vec<PlannedNativeEntry>, String> {
        let source = signed_source(bytes, suffix);
        inspect_archive(&mut Cursor::new(bytes), &source, registry, budget)
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-native-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    #[test]
    fn pinned_lock_selects_only_the_eight_windows_x64_archives() {
        let lock = GameRuntimeLock::parse_and_validate(include_bytes!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        ))
        .expect("pinned lock");
        let selected = select_native_archives(&lock).expect("select native archives");
        assert_eq!(selected.len(), EXPECTED_WINDOWS_X64_ARCHIVES);
        assert!(selected
            .iter()
            .all(|source| source.receipt.path.ends_with("-natives-windows.jar")));
        assert!(selected.iter().all(|source| {
            !source.receipt.path.contains("arm64") && !source.receipt.path.contains("x86")
        }));
    }

    #[test]
    fn valid_archive_ignores_metadata_and_flattens_exact_dll_basename() {
        let bytes = zip_bytes(&[
            ("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n"),
            ("windows/x64/org/lwjgl/OpenAL.dll", b"native-bytes"),
            ("META-INF/windows/x64/org/lwjgl/OpenAL.dll.sha1", b"digest"),
            ("windows/x64/org/lwjgl/OpenAL.dll.git", b"revision"),
        ]);
        let mut registry = OutputRegistry::default();
        let mut budget = InspectionBudget::default();
        let planned = inspect_bytes(&bytes, "openal", &mut registry, &mut budget).unwrap();
        assert_eq!(planned.len(), 1);
        assert_eq!(
            planned[0].archive_path.as_str(),
            "windows/x64/org/lwjgl/OpenAL.dll"
        );
        assert_eq!(planned[0].output_path.as_str(), "OpenAL.dll");
        assert_eq!(
            registry.files.values().collect::<Vec<_>>(),
            vec!["OpenAL.dll"]
        );
    }

    #[test]
    fn rejects_traversal_backslash_ads_and_non_x64_dll_paths() {
        for (label, path) in [
            ("traversal", "windows/x64/../escape.dll"),
            ("backslash", "windows\\x64\\escape.dll"),
            ("ads", "windows/x64/escape.dll:stream"),
            ("absolute", "C:/windows/x64/escape.dll"),
            ("wrong-arch", "windows/x86/escape.dll"),
        ] {
            let bytes = zip_bytes(&[(path, b"native")]);
            let result = inspect_bytes(
                &bytes,
                label,
                &mut OutputRegistry::default(),
                &mut InspectionBudget::default(),
            );
            assert!(result.is_err(), "{label} was accepted");
        }
    }

    #[test]
    fn rejects_symlink_unix_native_and_case_colliding_flattened_outputs() {
        let symlink = symlink_zip("windows/x64/org/lwjgl/link.dll");
        assert!(inspect_bytes(
            &symlink,
            "symlink",
            &mut OutputRegistry::default(),
            &mut InspectionBudget::default(),
        )
        .is_err());

        let unix = zip_bytes(&[("windows/x64/org/lwjgl/libbad.so", b"native")]);
        assert!(inspect_bytes(
            &unix,
            "unix",
            &mut OutputRegistry::default(),
            &mut InspectionBudget::default(),
        )
        .is_err());

        let first = zip_bytes(&[("windows/x64/org/lwjgl/a/OpenAL.dll", b"one")]);
        let second = zip_bytes(&[("windows/x64/org/lwjgl/b/openal.DLL", b"two")]);
        let mut registry = OutputRegistry::default();
        let mut budget = InspectionBudget::default();
        inspect_bytes(&first, "first", &mut registry, &mut budget).unwrap();
        assert!(inspect_bytes(&second, "second", &mut registry, &mut budget).is_err());
    }

    #[test]
    fn rejects_high_ratio_zip_bomb_before_extraction() {
        let zeros = vec![0_u8; 1024 * 1024];
        let bytes = zip_bytes(&[("windows/x64/org/lwjgl/bomb.dll", &zeros)]);
        assert!(inspect_bytes(
            &bytes,
            "bomb",
            &mut OutputRegistry::default(),
            &mut InspectionBudget::default(),
        )
        .is_err());
    }

    #[test]
    fn rejects_encrypted_and_unsupported_compression_metadata() {
        let original = zip_bytes(&[("windows/x64/org/lwjgl/lwjgl.dll", b"native")]);

        let mut encrypted = original.clone();
        mutate_zip_u16(&mut encrypted, b"PK\x03\x04", 6, 1);
        mutate_zip_u16(&mut encrypted, b"PK\x01\x02", 8, 1);
        assert!(inspect_bytes(
            &encrypted,
            "encrypted",
            &mut OutputRegistry::default(),
            &mut InspectionBudget::default(),
        )
        .is_err());

        let mut unsupported = original;
        mutate_zip_u16(&mut unsupported, b"PK\x03\x04", 8, 99);
        mutate_zip_u16(&mut unsupported, b"PK\x01\x02", 10, 99);
        assert!(inspect_bytes(
            &unsupported,
            "unsupported",
            &mut OutputRegistry::default(),
            &mut InspectionBudget::default(),
        )
        .is_err());
    }

    #[test]
    fn workspace_audit_is_exact_and_detects_new_files() {
        // Production workspaces are children of the install-locked native-workspaces namespace.
        // Keep the sentinel parent private here too: its required parent STREAM_* watch must not
        // observe unrelated siblings created directly under the process-wide %TEMP% directory.
        let container = temp_root("audit");
        let root = container.join("native-workspaces/launch");
        fs::create_dir_all(&root).unwrap();
        let dll = b"signed-native";
        fs::write(root.join("lwjgl.dll"), dll).unwrap();
        let mut expected = BTreeMap::new();
        let path = "lwjgl.dll";
        let bytes = dll.as_slice();
        let managed = RelativeManagedPath::new(path).unwrap();
        expected.insert(
            managed.collision_key().to_owned(),
            ExpectedWorkspaceFile {
                path: path.to_owned(),
                size: bytes.len() as u64,
                sha256: format!("{:x}", Sha256::digest(bytes)),
                exact_bytes: None,
            },
        );
        let mut lease = audit_workspace(&root, expected).expect("audit native workspace");
        lease.revalidate().expect("revalidate native workspace");
        fs::write(root.join("extra.dll"), b"unsigned").unwrap();
        assert!(lease.revalidate().is_err());
        drop(lease);
        fs::remove_dir_all(container).unwrap();
    }

    #[test]
    fn abandoned_exclusive_workspace_is_removed_by_bounded_cleanup() {
        let root = temp_root("builder-drop");
        fs::create_dir_all(&root).unwrap();
        let builder = create_workspace(&root).expect("create native workspace");
        let native = builder.native_path.clone();
        let scratch = builder.scratch_path.clone();
        assert!(native.is_dir());
        assert!(scratch.is_dir());
        drop(builder);
        assert!(!native.exists());
        assert!(!scratch.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn scratch_inventory_rejects_preseeded_temp_or_home_files() {
        let root = temp_root("scratch-inventory");
        fs::create_dir_all(&root).unwrap();
        let builder = create_workspace(&root).expect("create split workspaces");
        fs::write(builder.scratch_path.join(RECEIPT_FILE), b"receipt\n").unwrap();
        let expected = expected_scratch_directories();
        validate_scratch_inventory(&builder.scratch_path, &expected)
            .expect("exact initial scratch");
        fs::write(builder.temp_path.join("preseed.txt"), b"untrusted").unwrap();
        assert!(validate_scratch_inventory(&builder.scratch_path, &expected).is_err());
        drop(builder);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn held_native_rejects_replacement_detects_injection_and_keeps_scratch_writable() {
        let root = temp_root("split-authority");
        fs::create_dir_all(&root).unwrap();
        let mut builder = create_workspace(&root).expect("create split workspaces");
        let dll = b"signed-native";
        fs::write(builder.native_path.join("lwjgl.dll"), dll).unwrap();
        let managed = RelativeManagedPath::new("lwjgl.dll").unwrap();
        let expected = BTreeMap::from([(
            managed.collision_key().to_owned(),
            ExpectedWorkspaceFile {
                path: "lwjgl.dll".into(),
                size: dll.len() as u64,
                sha256: format!("{:x}", Sha256::digest(dll)),
                exact_bytes: None,
            },
        )]);
        builder.release_native_guard();
        let mut lease = audit_workspace(&builder.native_path, expected).expect("audit DLL root");

        assert!(fs::write(builder.native_path.join("lwjgl.dll"), b"replacement").is_err());
        fs::write(builder.temp_path.join("writable.tmp"), b"scratch").unwrap();
        // Win32 directory sharing cannot prevent a new child. The exact final audit must detect
        // it; point-5's in-game guard is the enforcement boundary after CreateProcessW.
        fs::write(builder.native_path.join("injected.dll"), b"foreign").unwrap();
        assert!(lease.revalidate().is_err());

        let native = builder.native_path.clone();
        let scratch = builder.scratch_path.clone();
        drop(lease);
        drop(builder);
        assert!(!native.exists());
        assert!(!scratch.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn cleanup_attempts_scratch_even_when_native_identity_is_rejected() {
        let root = temp_root("independent-cleanup");
        fs::create_dir_all(&root).unwrap();
        let mut builder = create_workspace(&root).expect("create split workspaces");
        fs::write(builder.temp_path.join("scratch.tmp"), b"temporary").unwrap();

        let correct_native_identity = builder.native_identity.clone();
        let mut wrong_native_identity = correct_native_identity.clone();
        wrong_native_identity.file_id[0] ^= 0xff;
        builder.native_guard.take();
        builder.scratch_guards.clear();
        builder.armed = false;
        let workspace = NativeWorkspace {
            install_root: builder.install_root.clone(),
            native_relative: builder.native_relative.clone(),
            native_path: builder.native_path.clone(),
            native_identity: wrong_native_identity,
            scratch_relative: builder.scratch_relative.clone(),
            scratch_path: builder.scratch_path.clone(),
            scratch_identity: builder.scratch_identity.clone(),
            temp_path: builder.temp_path.clone(),
            home_path: builder.home_path.clone(),
            appdata_path: builder.appdata_path.clone(),
            local_appdata_path: builder.local_appdata_path.clone(),
            native_lease: None,
            scratch_lease: None,
            native_cleaned: false,
            scratch_cleaned: false,
        };
        let native_path = builder.native_path.clone();
        let scratch_path = builder.scratch_path.clone();
        let install_root = builder.install_root.clone();
        let native_relative = builder.native_relative.clone();
        drop(builder);

        assert!(workspace.cleanup().is_err());
        assert!(native_path.exists());
        assert!(!scratch_path.exists(), "scratch cleanup was skipped");
        remove_native_namespace(
            &install_root,
            &native_relative,
            &native_path,
            &correct_native_identity,
        )
        .unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
