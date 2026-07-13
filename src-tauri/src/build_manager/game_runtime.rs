use super::{
    contracts::{
        domain_digest, GameRuntimeLock, GameRuntimeSource, NormalizedProcessorArgument,
        RuntimeLock, UpstreamProcessorStep,
    },
    game_runtime_invocation::PreparedProcessorInvocation,
    game_runtime_materializer::{MAX_SCRATCH_ENTRIES, MAX_SCRATCH_TOTAL_BYTES, STATE_MARKER_PATH},
    managed_fs::{
        validate_no_named_data_streams, ExclusiveManagedFile, FileDigests, GuardedDirectoryChain,
        ImmutableManagedFile, ManagedFsError, RelativeManagedPath,
    },
    process_supervisor::{spawn as spawn_process, ProcessSpec},
    runtime::{revalidate_runtime_installation_for_root, RuntimeInstallation},
    storage::{is_windows_reparse_point, open_regular_single_link, OwnedCasRoot},
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::OsString,
    fmt, fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    },
    thread,
    time::{Duration, Instant},
};

const EXECUTABLE_UPSTREAM_INDICES: [u8; 5] = [3, 5, 6, 8, 9];
const MAX_OUTPUT_TREE_ENTRIES: usize = 128;
const MAX_STREAM_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_DIAGNOSTIC_BYTES: usize = 1024 * 1024;
const MAX_PROCESS_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const PROCESS_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const STREAM_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
// This is a fail-closed detector rather than an OS disk quota: a child can write between scans.
// The physically-verified reserve below remains handle-protected during that window and releases
// at least 64 MiB of filesystem allocation after the Job Object has terminated the process tree.
const WORKSPACE_MONITOR_INTERVAL: Duration = Duration::from_millis(25);
const PROCESSOR_RECOVERY_RESERVE_BYTES: u64 = 64 * 1024 * 1024;
const RECOVERY_RESERVE_PATH: &str = "state/processor-recovery-reserve.bin";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecutableProcessorStep {
    pub(super) execution_index: u8,
    pub(super) upstream_index: u8,
    pub(super) id: String,
    pub(super) jar_path: String,
    pub(super) main_class: String,
    pub(super) classpath: Vec<String>,
    pub(super) arguments: Vec<NormalizedProcessorArgument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct OutputIdentity {
    path: String,
    size: u64,
    sha1: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GameRuntimeOutputAudit {
    pub(super) file_count: usize,
    pub(super) total_bytes: u64,
    pub(super) outputs_sha256: String,
}

struct HeldOutput {
    key: String,
    expected: OutputIdentity,
    file: ImmutableManagedFile,
}

/// A successful output audit plus live filesystem handles which keep the exact six files and
/// their directory chain leased until the caller commits or discards the processor workspace.
/// Call `revalidate` immediately before that commit; the lease must remain alive through it.
pub(super) struct GameRuntimeOutputLease {
    audit: GameRuntimeOutputAudit,
    root: PathBuf,
    expected: BTreeMap<String, OutputIdentity>,
    expected_directories: BTreeMap<String, String>,
    held_outputs: Vec<HeldOutput>,
    _root_guard: GuardedDirectoryChain,
    _directory_guards: Vec<GuardedDirectoryChain>,
}

impl GameRuntimeOutputLease {
    pub(super) fn audit(&self) -> &GameRuntimeOutputAudit {
        &self.audit
    }

    pub(super) fn revalidate(&mut self) -> Result<(), String> {
        let mut observed = BTreeMap::new();
        for held in &mut self.held_outputs {
            let actual = hash_held_output(&mut held.file, &held.expected)?;
            if observed.insert(held.key.clone(), actual).is_some() {
                return Err("Game runtime output lease contains a duplicate path".into());
            }
        }
        validate_output_inventory(&self.expected, &observed)?;
        validate_output_tree_inventory(&self.root, &self.expected, &self.expected_directories)
    }

    fn revalidate_namespace(&self) -> Result<(), String> {
        let mut observed = BTreeSet::new();
        for held in &self.held_outputs {
            held.file.revalidate().map_err(|error| {
                format!("Game runtime output handle changed before publication: {error}")
            })?;
            if !observed.insert(held.key.clone()) {
                return Err("Game runtime output lease contains a duplicate path".into());
            }
        }
        if observed != self.expected.keys().cloned().collect() {
            return Err("Game runtime output lease inventory is incomplete".into());
        }
        validate_output_tree_inventory(&self.root, &self.expected, &self.expected_directories)
    }

    /// Streams one exact signed derived output into a fresh exclusive destination while the
    /// complete exact-six output namespace remains leased. The caller supplies the identity from
    /// its sealed game-generation authority; a path-only lookup is deliberately insufficient.
    ///
    /// This never exposes a workspace path and never hard-links processor output into the final
    /// generation. Both signed digests are computed over the bytes actually written.
    pub(super) fn copy_expected_to(
        &mut self,
        path: &str,
        size: u64,
        sha1: &str,
        sha256: &str,
        destination: &mut ExclusiveManagedFile,
    ) -> Result<FileDigests, String> {
        self.revalidate_namespace()?;
        let managed = RelativeManagedPath::new(path)
            .map_err(|error| format!("Derived output publication path is unsafe: {error}"))?;
        let key = managed.collision_key();
        let expected = self.expected.get(key).ok_or_else(|| {
            "Requested publication file is not a signed derived output".to_string()
        })?;
        if expected.path != managed.as_str()
            || expected.size != size
            || expected.sha1 != sha1
            || expected.sha256 != sha256
        {
            return Err(
                "Requested publication identity differs from the signed derived output".into(),
            );
        }
        let held = self
            .held_outputs
            .iter_mut()
            .find(|held| held.key == key)
            .ok_or_else(|| {
                "Signed derived output is absent from the live output lease".to_string()
            })?;
        let written = held
            .file
            .copy_to_exclusive(destination, size)
            .map_err(|error| format!("Cannot copy leased processor output: {error}"))?;
        if written.size != size || written.sha1 != sha1 || written.sha256 != sha256 {
            return Err("Published processor output bytes differ from the signed identity".into());
        }
        self.revalidate_namespace()?;
        Ok(written)
    }
}

#[derive(Debug, Clone)]
pub(super) struct JavaProcessLimits {
    pub(super) timeout: Duration,
    pub(super) max_stream_bytes: u64,
    pub(super) max_diagnostic_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProcessorWorkspaceMonitorLimits {
    pub(super) output_max_entries: usize,
    pub(super) output_max_bytes: u64,
    /// Exact canonical files which may exist during this processor step. A file may be absent or
    /// shorter while it is being produced, but no other output name is accepted.
    pub(super) allowed_output_files: BTreeMap<String, u64>,
    /// Exact pre-created directory topology for the complete signed processor output closure.
    pub(super) allowed_output_directories: BTreeSet<String>,
}

#[derive(Debug, Clone, Copy)]
struct WorkspaceTreeLimit {
    max_entries: usize,
    max_bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkspaceTreeUsage {
    entries: usize,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkspaceNodeKind {
    File,
    Directory,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceTreeInventory {
    usage: WorkspaceTreeUsage,
    nodes: BTreeMap<String, WorkspaceNodeIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceNodeIdentity {
    path: String,
    kind: WorkspaceNodeKind,
    size: u64,
    file_identity: Option<WorkspaceFileIdentity>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct WorkspaceFileIdentity {
    volume: u64,
    id: [u8; 16],
}

struct ProcessorWorkspaceMonitor {
    root: PathBuf,
    inputs: PathBuf,
    temp: PathBuf,
    home: PathBuf,
    outputs: PathBuf,
    input_inventory: WorkspaceTreeInventory,
    scratch_limit: WorkspaceTreeLimit,
    output_limit: WorkspaceTreeLimit,
    allowed_output_files: BTreeMap<String, (String, u64)>,
    allowed_output_directories: BTreeMap<String, String>,
}

struct ProcessorRecoveryReserve {
    // The handle is opened with DELETE access and no sharing on Windows. Named streams are still
    // independently writable on NTFS, so every poll re-enumerates streams through this base
    // handle and cleanup deletes the complete file (all streams) by this exact handle.
    file: Option<fs::File>,
    path: PathBuf,
    identity: WorkspaceFileIdentity,
    expected_bytes: u64,
    state_guard: GuardedDirectoryChain,
    #[cfg(test)]
    injected_release_failure: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct StreamCapture {
    pub(super) bytes: u64,
    pub(super) sha256: String,
    pub(super) diagnostic: Vec<u8>,
    pub(super) truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct JavaProcessOutput {
    pub(super) exit_code: i32,
    pub(super) stdout: StreamCapture,
    pub(super) stderr: StreamCapture,
    pub(super) transcript_sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum JavaProcessError {
    Cancelled,
    Failed(String),
}

impl fmt::Display for JavaProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("NeoForge processor execution was cancelled"),
            Self::Failed(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for JavaProcessError {}

impl From<String> for JavaProcessError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

impl From<&str> for JavaProcessError {
    fn from(message: &str) -> Self {
        Self::Failed(message.to_owned())
    }
}

type JavaProcessResult<T> = Result<T, JavaProcessError>;

struct JavaProcessRequest<'a> {
    executable: &'a Path,
    arguments: &'a [OsString],
    cwd: &'a Path,
    environment: &'a [(OsString, OsString)],
    limits: JavaProcessLimits,
    workspace_monitor: Option<ProcessorWorkspaceMonitor>,
    recovery_reserve: Option<ProcessorRecoveryReserve>,
    cancelled: Arc<AtomicBool>,
}

impl ProcessorWorkspaceMonitor {
    fn for_invocation(
        invocation: &PreparedProcessorInvocation,
        limits: ProcessorWorkspaceMonitorLimits,
    ) -> Result<Self, String> {
        if limits.output_max_entries == 0 || limits.output_max_bytes == 0 {
            return Err("Processor live output monitor limits are empty".into());
        }
        let root = invocation.cwd();
        if !root.is_absolute() {
            return Err("Processor workspace monitor root is not absolute".into());
        }
        let allowed_output_files = canonical_output_files(&limits.allowed_output_files)?;
        let allowed_output_directories =
            canonical_output_directories(&limits.allowed_output_directories)?;
        validate_canonical_output_topology(&allowed_output_files, &allowed_output_directories)?;
        let expected_entries = allowed_output_files
            .len()
            .checked_add(allowed_output_directories.len())
            .ok_or_else(|| "Processor monitored output entry count overflowed".to_string())?;
        let expected_bytes =
            allowed_output_files
                .values()
                .try_fold(0_u64, |total, (_, maximum_size)| {
                    total.checked_add(*maximum_size).ok_or_else(|| {
                        "Processor monitored output byte bound overflowed".to_string()
                    })
                })?;
        if allowed_output_files.is_empty()
            || expected_entries > limits.output_max_entries
            || expected_bytes != limits.output_max_bytes
        {
            return Err("Processor live output monitor authority is inconsistent".into());
        }
        let inputs = root.join("inputs");
        let input_inventory = audit_live_workspace_inventory(
            &inputs,
            "processor inputs",
            WorkspaceTreeLimit {
                max_entries: 4_096,
                max_bytes: 1024 * 1024 * 1024,
            },
        )?;
        Ok(Self {
            root: root.to_path_buf(),
            inputs,
            temp: root.join("temp"),
            home: root.join("state/user-home"),
            outputs: root.join("outputs"),
            input_inventory,
            scratch_limit: WorkspaceTreeLimit {
                max_entries: MAX_SCRATCH_ENTRIES,
                max_bytes: MAX_SCRATCH_TOTAL_BYTES,
            },
            output_limit: WorkspaceTreeLimit {
                max_entries: limits.output_max_entries,
                max_bytes: limits.output_max_bytes,
            },
            allowed_output_files,
            allowed_output_directories,
        })
    }

    fn audit(&self) -> Result<(), String> {
        audit_live_workspace_root(&self.root)?;
        audit_live_workspace_state(&self.root.join("state"))?;
        let input_inventory = audit_live_workspace_inventory(
            &self.inputs,
            "processor inputs",
            WorkspaceTreeLimit {
                max_entries: self.input_inventory.usage.entries,
                max_bytes: self.input_inventory.usage.bytes,
            },
        )?;
        if input_inventory != self.input_inventory {
            return Err("Live processor input topology, casing or size changed".into());
        }
        let _ = audit_live_workspace_tree(&self.temp, "processor temp", self.scratch_limit)?;
        let _ = audit_live_workspace_tree(&self.home, "processor user-home", self.scratch_limit)?;
        audit_live_processor_outputs(
            &self.outputs,
            self.output_limit,
            &self.allowed_output_files,
            &self.allowed_output_directories,
        )?;
        Ok(())
    }
}

fn canonical_output_files(
    files: &BTreeMap<String, u64>,
) -> Result<BTreeMap<String, (String, u64)>, String> {
    let mut canonical = BTreeMap::new();
    for (path, max_bytes) in files {
        if *max_bytes == 0 {
            return Err(format!("Processor output has an empty live bound: {path}"));
        }
        let managed = RelativeManagedPath::new(path)
            .map_err(|error| format!("Processor monitored output path is unsafe: {error}"))?;
        let key = managed.collision_key().to_owned();
        let value = (managed.as_str().to_owned(), *max_bytes);
        if canonical
            .insert(key, value.clone())
            .is_some_and(|old| old != value)
        {
            return Err("Processor monitored output files collide on Windows".into());
        }
    }
    Ok(canonical)
}

fn canonical_output_directories(
    directories: &BTreeSet<String>,
) -> Result<BTreeMap<String, String>, String> {
    let mut canonical = BTreeMap::new();
    for path in directories {
        let managed = RelativeManagedPath::new(path)
            .map_err(|error| format!("Processor monitored output directory is unsafe: {error}"))?;
        let key = managed.collision_key().to_owned();
        let value = managed.as_str().to_owned();
        if canonical
            .insert(key, value.clone())
            .is_some_and(|old| old != value)
        {
            return Err("Processor monitored output directories collide on Windows".into());
        }
    }
    Ok(canonical)
}

fn validate_canonical_output_topology(
    files: &BTreeMap<String, (String, u64)>,
    directories: &BTreeMap<String, String>,
) -> Result<(), String> {
    for (key, (path, _)) in files {
        if directories.contains_key(key) {
            return Err("Processor monitored output has a file/directory collision".into());
        }
        let managed = RelativeManagedPath::new(path)
            .map_err(|error| format!("Processor monitored output path is unsafe: {error}"))?;
        let mut parent = managed.parent();
        while let Some(directory) = parent {
            if directories
                .get(directory.collision_key())
                .map(String::as_str)
                != Some(directory.as_str())
            {
                return Err(format!(
                    "Processor monitored output parent is absent from the exact topology: {}",
                    directory.as_str()
                ));
            }
            parent = directory.parent();
        }
    }
    Ok(())
}

impl ProcessorRecoveryReserve {
    fn allocate(workspace_root: &Path, reserve_bytes: u64) -> Result<Self, String> {
        if reserve_bytes == 0 {
            return Err("Processor recovery reserve cannot be empty".into());
        }
        let state_relative =
            RelativeManagedPath::new("state").expect("static processor state path is valid");
        let state_guard = GuardedDirectoryChain::open(workspace_root, &state_relative)
            .map_err(|error| format!("Cannot lease processor reserve state directory: {error}"))?;
        let path =
            workspace_root.join(RECOVERY_RESERVE_PATH.replace('/', std::path::MAIN_SEPARATOR_STR));
        let mut file = create_processor_reserve_file(&path)?;

        let mut chunk = vec![0_u8; 1024 * 1024];
        fill_incompressible_reserve_chunk(&mut chunk);
        let allocation = (|| -> Result<(), String> {
            let mut written = 0_u64;
            while written < reserve_bytes {
                let remaining = reserve_bytes - written;
                let write_len = usize::try_from(remaining.min(chunk.len() as u64))
                    .expect("bounded reserve chunk length fits usize");
                file.write_all(&chunk[..write_len])
                    .map_err(|error| format!("Cannot allocate processor reserve: {error}"))?;
                written += write_len as u64;
            }
            file.sync_all()
                .map_err(|error| format!("Cannot flush processor recovery reserve: {error}"))?;
            validate_no_named_data_streams(&file, &path)
                .map_err(|error| format!("Processor reserve has a named stream: {error}"))?;
            let (logical, allocated, links) = processor_reserve_metrics(&file, &path)?;
            if logical != reserve_bytes || allocated < reserve_bytes || links != 1 {
                return Err(format!(
                    "Processor recovery reserve is not exclusive and fully allocated (logical {logical}, allocated {allocated}, links {links}, required {reserve_bytes})"
                ));
            }
            Ok(())
        })();
        if let Err(error) = allocation {
            let cleanup = delete_and_sync_processor_reserve(file, &path, &state_guard).err();
            return Err(append_cleanup_error(error, cleanup));
        }
        let identity = match workspace_file_identity(&file, &path) {
            Ok(identity) => identity,
            Err(error) => {
                let cleanup = delete_and_sync_processor_reserve(file, &path, &state_guard).err();
                return Err(append_cleanup_error(error, cleanup));
            }
        };
        if let Err(error) = state_guard.sync_leaf() {
            let cleanup = delete_and_sync_processor_reserve(file, &path, &state_guard).err();
            return Err(append_cleanup_error(
                format!("Cannot flush processor reserve parent: {error}"),
                cleanup,
            ));
        }
        Ok(Self {
            file: Some(file),
            path,
            identity,
            expected_bytes: reserve_bytes,
            state_guard,
            #[cfg(test)]
            injected_release_failure: None,
        })
    }

    fn revalidate(&self) -> Result<(), String> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| "Processor recovery reserve was already released".to_string())?;
        self.state_guard
            .revalidate()
            .map_err(|error| format!("Cannot revalidate processor reserve parent: {error}"))?;
        validate_no_named_data_streams(file, &self.path)
            .map_err(|error| format!("Processor reserve has a named stream: {error}"))?;
        let identity = workspace_file_identity(file, &self.path)?;
        let (logical, allocated, links) = processor_reserve_metrics(file, &self.path)?;
        if identity != self.identity
            || logical != self.expected_bytes
            || allocated < self.expected_bytes
            || links != 1
        {
            return Err(format!(
                "Processor recovery reserve changed (logical {logical}, allocated {allocated}, links {links}, required {})",
                self.expected_bytes
            ));
        }
        Ok(())
    }

    fn release(mut self) -> Result<(), String> {
        let result = self.release_file();
        #[cfg(test)]
        if let Some(injected) = self.injected_release_failure.take() {
            return match result {
                Ok(()) => Err(injected),
                Err(error) => Err(append_cleanup_error(error, Some(injected))),
            };
        }
        result
    }

    #[cfg(test)]
    fn inject_release_failure(&mut self, message: impl Into<String>) {
        self.injected_release_failure = Some(message.into());
    }

    fn release_file(&mut self) -> Result<(), String> {
        let final_validation = self.revalidate();
        if let Err(validation_error) = final_validation {
            let cleanup_safe = self.release_cleanup_is_single_link_exact_identity();
            match cleanup_safe {
                Ok(false) => return Err(validation_error),
                Err(safety_error) => {
                    return Err(append_cleanup_error(validation_error, Some(safety_error)));
                }
                Ok(true) => {
                    // A named stream is independently writable on NTFS even while the unnamed
                    // stream is exclusive. Once the Job is reaped, deleting the exact single-link
                    // base handle safely removes all of those closed streams and recovers the
                    // reserve. The validation error is still returned so this path never claims a
                    // clean processor run.
                    let file = self.file.take().expect("validated reserve owns its file");
                    let cleanup =
                        delete_and_sync_processor_reserve(file, &self.path, &self.state_guard);
                    return Err(append_cleanup_error(validation_error, cleanup.err()));
                }
            }
        }
        let file = self
            .file
            .take()
            .ok_or_else(|| "Processor recovery reserve was already released".to_string())?;
        delete_and_sync_processor_reserve(file, &self.path, &self.state_guard)
    }

    fn release_cleanup_is_single_link_exact_identity(&self) -> Result<bool, String> {
        let file = self
            .file
            .as_ref()
            .ok_or_else(|| "Processor recovery reserve was already released".to_string())?;
        let identity = workspace_file_identity(file, &self.path)?;
        let (logical, allocated, links) = processor_reserve_metrics(file, &self.path)?;
        Ok(identity == self.identity
            && logical == self.expected_bytes
            && allocated >= self.expected_bytes
            && links == 1)
    }
}

impl Drop for ProcessorRecoveryReserve {
    fn drop(&mut self) {
        let _ = self.release_file();
    }
}

#[cfg(windows)]
fn create_processor_reserve_file(path: &Path) -> Result<fs::File, String> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::{
        Foundation::{GENERIC_READ, GENERIC_WRITE},
        Storage::FileSystem::{DELETE, FILE_FLAG_OPEN_REPARSE_POINT, SYNCHRONIZE},
    };
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | DELETE.0 | SYNCHRONIZE.0)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|error| format!("Cannot create exclusive processor reserve: {error}"))
}

#[cfg(not(windows))]
fn create_processor_reserve_file(path: &Path) -> Result<fs::File, String> {
    fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("Cannot create exclusive processor reserve: {error}"))
}

#[cfg(windows)]
fn processor_reserve_metrics(file: &fs::File, path: &Path) -> Result<(u64, u64, u32), String> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FileStandardInfo, GetFileInformationByHandleEx, FILE_STANDARD_INFO},
    };
    let mut info = FILE_STANDARD_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            HANDLE(file.as_raw_handle().cast()),
            FileStandardInfo,
            (&mut info as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    }
    .map_err(|error| {
        format!(
            "Cannot inspect processor reserve {}: {error}",
            path.display()
        )
    })?;
    let logical = u64::try_from(info.EndOfFile)
        .map_err(|_| "Processor reserve has a negative logical size".to_string())?;
    let allocated = u64::try_from(info.AllocationSize)
        .map_err(|_| "Processor reserve has a negative allocation size".to_string())?;
    Ok((logical, allocated, info.NumberOfLinks))
}

#[cfg(unix)]
fn processor_reserve_metrics(file: &fs::File, path: &Path) -> Result<(u64, u64, u32), String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "Cannot inspect processor reserve {}: {error}",
            path.display()
        )
    })?;
    let links = u32::try_from(metadata.nlink())
        .map_err(|_| "Processor reserve link count overflowed".to_string())?;
    Ok((metadata.len(), metadata.blocks().saturating_mul(512), links))
}

#[cfg(all(not(windows), not(unix)))]
fn processor_reserve_metrics(file: &fs::File, path: &Path) -> Result<(u64, u64, u32), String> {
    let size = file
        .metadata()
        .map_err(|error| {
            format!(
                "Cannot inspect processor reserve {}: {error}",
                path.display()
            )
        })?
        .len();
    Ok((size, size, 1))
}

#[cfg(windows)]
fn delete_processor_reserve_file(file: fs::File, path: &Path) -> Result<(), String> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{
            FileDispositionInfo, SetFileInformationByHandle, FILE_DISPOSITION_INFO,
        },
    };
    let disposition = FILE_DISPOSITION_INFO { DeleteFile: true };
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle().cast()),
            FileDispositionInfo,
            (&disposition as *const FILE_DISPOSITION_INFO).cast(),
            size_of::<FILE_DISPOSITION_INFO>() as u32,
        )
    }
    .map_err(|error| format!("Cannot mark processor reserve for deletion: {error}"))?;
    drop(file);
    confirm_processor_reserve_absent(path)
}

#[cfg(not(windows))]
fn delete_processor_reserve_file(file: fs::File, path: &Path) -> Result<(), String> {
    drop(file);
    fs::remove_file(path).map_err(|error| {
        format!(
            "Cannot delete processor reserve {}: {error}",
            path.display()
        )
    })?;
    confirm_processor_reserve_absent(path)
}

fn confirm_processor_reserve_absent(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err("Processor recovery reserve path remained after release".into()),
        Err(error) => Err(format!(
            "Cannot confirm processor reserve removal {}: {error}",
            path.display()
        )),
    }
}

fn delete_and_sync_processor_reserve(
    file: fs::File,
    path: &Path,
    state_guard: &GuardedDirectoryChain,
) -> Result<(), String> {
    let delete = delete_processor_reserve_file(file, path);
    let sync = state_guard
        .sync_leaf()
        .map_err(|error| format!("Cannot flush released processor reserve parent: {error}"));
    match (delete, sync) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(delete), Ok(())) => Err(delete),
        (Ok(()), Err(sync)) => Err(sync),
        (Err(delete), Err(sync)) => Err(append_cleanup_error(delete, Some(sync))),
    }
}

fn fill_incompressible_reserve_chunk(chunk: &mut [u8]) {
    let mut state = 0x6a09_e667_f3bc_c909_u64;
    for byte in chunk {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
}

fn audit_live_workspace_root(root: &Path) -> Result<(), String> {
    let guard = GuardedDirectoryChain::root_snapshot(root)
        .map_err(|error| format!("Live processor workspace root is unsafe: {error}"))?;
    validate_live_directory_streams(guard.leaf().path(), "processor workspace root")?;
    let expected = ["inputs", "outputs", "state", "temp"]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(guard.leaf().path())
        .map_err(|error| format!("Cannot enumerate live processor workspace root: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("Cannot inspect live processor workspace root: {error}"))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "Live processor workspace root entry is not UTF-8".to_string())?
            .to_owned();
        let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
            format!("Cannot inspect live processor workspace root entry: {error}")
        })?;
        if !metadata.is_dir()
            || metadata.file_type().is_symlink()
            || is_windows_reparse_point(&metadata)
            || !expected.contains(name.as_str())
            || !observed.insert(name.clone())
        {
            return Err(format!(
                "Live processor workspace root contains an unexpected entry: {name}"
            ));
        }
        let relative = RelativeManagedPath::new(&name)
            .map_err(|error| format!("Live processor workspace root path is unsafe: {error}"))?;
        let child = GuardedDirectoryChain::open_snapshot(root, &relative)
            .map_err(|error| format!("Live processor workspace directory is unsafe: {error}"))?;
        validate_live_directory_streams(child.leaf().path(), "processor workspace directory")?;
    }
    if observed != expected {
        return Err("Live processor workspace root topology changed".into());
    }
    Ok(())
}

fn audit_live_workspace_state(state: &Path) -> Result<(), String> {
    let guard = GuardedDirectoryChain::root_snapshot(state)
        .map_err(|error| format!("Live processor state root is unsafe: {error}"))?;
    validate_live_directory_streams(guard.leaf().path(), "processor state root")?;
    let expected = [
        STATE_MARKER_PATH,
        "processor-recovery-reserve.bin",
        "user-home",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect::<BTreeSet<_>>();
    let mut observed = BTreeSet::new();
    for entry in fs::read_dir(guard.leaf().path())
        .map_err(|error| format!("Cannot enumerate live processor state root: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("Cannot inspect live processor state root: {error}"))?;
        let name = entry
            .file_name()
            .to_str()
            .ok_or_else(|| "Live processor state entry is not UTF-8".to_string())?
            .to_owned();
        if !expected.contains(name.as_str()) || !observed.insert(name.clone()) {
            return Err(format!("Unexpected live processor state entry: {name}"));
        }
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect live processor state entry: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err(format!(
                "Link/reparse point is forbidden in live processor state: {name}"
            ));
        }
        match name.as_str() {
            "user-home" if metadata.is_dir() => {
                let home = GuardedDirectoryChain::root_snapshot(&absolute).map_err(|error| {
                    format!("Live processor user-home directory is unsafe: {error}")
                })?;
                validate_live_directory_streams(home.leaf().path(), "processor user-home")?;
            }
            STATE_MARKER_PATH if metadata.is_file() => {
                let file = open_regular_single_link(&absolute, false)
                    .map_err(|error| format!("Live processor state marker is unsafe: {error}"))?;
                validate_no_named_data_streams(&file, &absolute).map_err(|error| {
                    format!("Live processor state marker stream is unsafe: {error}")
                })?;
            }
            // The reserve is held with share_mode(0); its own live handle was already validated,
            // synced and allocation-size checked before spawn, so reopening it here must fail.
            "processor-recovery-reserve.bin" if metadata.is_file() => {}
            _ => return Err(format!("Live processor state entry changed type: {name}")),
        }
    }
    if observed != expected {
        return Err("Live processor state topology changed".into());
    }
    Ok(())
}

fn audit_live_workspace_tree(
    root: &Path,
    label: &str,
    limit: WorkspaceTreeLimit,
) -> Result<WorkspaceTreeUsage, String> {
    Ok(audit_live_workspace_inventory(root, label, limit)?.usage)
}

fn audit_live_workspace_inventory(
    root: &Path,
    label: &str,
    limit: WorkspaceTreeLimit,
) -> Result<WorkspaceTreeInventory, String> {
    let root_guard = GuardedDirectoryChain::root_snapshot(root)
        .map_err(|error| format!("Live {label} root is unsafe: {error}"))?;
    validate_live_directory_streams(root_guard.leaf().path(), label)?;
    let mut scan = WorkspaceTreeScan::default();
    scan_live_workspace_directory(
        root_guard.root_path(),
        root_guard.leaf().path(),
        label,
        limit,
        &mut scan,
    )?;
    Ok(WorkspaceTreeInventory {
        usage: WorkspaceTreeUsage {
            entries: scan.entries,
            bytes: scan.bytes,
        },
        nodes: scan.nodes,
    })
}

#[derive(Default)]
struct WorkspaceTreeScan {
    entries: usize,
    bytes: u64,
    collision_keys: BTreeSet<String>,
    nodes: BTreeMap<String, WorkspaceNodeIdentity>,
}

fn scan_live_workspace_directory(
    root: &Path,
    directory: &Path,
    label: &str,
    limit: WorkspaceTreeLimit,
    scan: &mut WorkspaceTreeScan,
) -> Result<(), String> {
    let directory_entries = fs::read_dir(directory)
        .map_err(|error| format!("Cannot enumerate live {label}: {error}"))?;
    for entry in directory_entries {
        let entry = entry.map_err(|error| format!("Cannot inspect live {label}: {error}"))?;
        let absolute = entry.path();
        let metadata = match fs::symlink_metadata(&absolute) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("Cannot inspect live {label} metadata: {error}")),
        };
        scan.entries = scan
            .entries
            .checked_add(1)
            .ok_or_else(|| format!("Live {label} entry counter overflowed"))?;
        if scan.entries > limit.max_entries {
            return Err(format!("Live {label} exceeds its entry limit"));
        }
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err(format!("Link/reparse point is forbidden in live {label}"));
        }
        if metadata.is_file() && metadata.permissions().readonly() {
            return Err(format!("Read-only file is forbidden in live {label}"));
        }
        let relative = absolute
            .strip_prefix(root)
            .map_err(|_| format!("Live {label} entry escaped its root"))?
            .components()
            .map(|component| {
                component
                    .as_os_str()
                    .to_str()
                    .ok_or_else(|| format!("Live {label} path is not UTF-8"))
            })
            .collect::<Result<Vec<_>, _>>()?
            .join("/");
        let managed = RelativeManagedPath::new(&relative)
            .map_err(|error| format!("Live {label} path is unsafe: {error}"))?;
        if !scan
            .collision_keys
            .insert(managed.collision_key().to_owned())
        {
            return Err(format!("Live {label} contains a Windows path collision"));
        }
        if metadata.is_dir() {
            let child_guard = match GuardedDirectoryChain::open_snapshot(root, &managed) {
                Ok(guard) => guard,
                Err(ManagedFsError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::NotFound =>
                {
                    continue
                }
                Err(error) => return Err(format!("Live {label} directory is unsafe: {error}")),
            };
            let stable = child_guard.leaf().path().to_path_buf();
            validate_live_directory_streams(&stable, label)?;
            scan.nodes.insert(
                managed.collision_key().to_owned(),
                WorkspaceNodeIdentity {
                    path: managed.as_str().to_owned(),
                    kind: WorkspaceNodeKind::Directory,
                    size: 0,
                    file_identity: None,
                },
            );
            scan_live_workspace_directory(root, &stable, label, limit, scan)?;
        } else if metadata.is_file() {
            let file = match open_regular_single_link(&absolute, false) {
                Ok(file) => file,
                Err(error) => match fs::symlink_metadata(&absolute) {
                    Err(missing) if missing.kind() == std::io::ErrorKind::NotFound => continue,
                    _ => return Err(format!("Live {label} file is unsafe: {error}")),
                },
            };
            validate_no_named_data_streams(&file, &absolute)
                .map_err(|error| format!("Live {label} file stream is unsafe: {error}"))?;
            let size = file
                .metadata()
                .map_err(|error| format!("Cannot inspect live {label} file handle: {error}"))?
                .len();
            let file_identity = workspace_file_identity(&file, &absolute)?;
            scan.bytes = scan
                .bytes
                .checked_add(size)
                .ok_or_else(|| format!("Live {label} byte total overflowed"))?;
            if scan.bytes > limit.max_bytes {
                return Err(format!("Live {label} exceeds its byte limit"));
            }
            scan.nodes.insert(
                managed.collision_key().to_owned(),
                WorkspaceNodeIdentity {
                    path: managed.as_str().to_owned(),
                    kind: WorkspaceNodeKind::File,
                    size,
                    file_identity: Some(file_identity),
                },
            );
        } else {
            return Err(format!("Special file is forbidden in live {label}"));
        }
    }
    Ok(())
}

fn audit_live_processor_outputs(
    root: &Path,
    limit: WorkspaceTreeLimit,
    allowed_files: &BTreeMap<String, (String, u64)>,
    allowed_directories: &BTreeMap<String, String>,
) -> Result<(), String> {
    let inventory = audit_live_workspace_inventory(root, "processor outputs", limit)?;
    let mut observed_directories = BTreeSet::new();
    for (key, node) in &inventory.nodes {
        match node.kind {
            WorkspaceNodeKind::Directory => {
                if allowed_directories.get(key) != Some(&node.path) {
                    return Err(format!(
                        "Live processor output directory is outside the signed topology: {}",
                        node.path
                    ));
                }
                observed_directories.insert(key.clone());
            }
            WorkspaceNodeKind::File => {
                let Some((expected_path, maximum_size)) = allowed_files.get(key) else {
                    return Err(format!(
                        "Live processor wrote an unexpected output file: {}",
                        node.path
                    ));
                };
                if &node.path != expected_path || node.size > *maximum_size {
                    return Err(format!(
                        "Live processor output path, casing or size is outside its signed bound: {}",
                        node.path
                    ));
                }
            }
        }
    }
    if observed_directories != allowed_directories.keys().cloned().collect() {
        return Err("Live processor output directory topology changed".into());
    }
    Ok(())
}

#[cfg(windows)]
fn workspace_file_identity(file: &fs::File, path: &Path) -> Result<WorkspaceFileIdentity, String> {
    use std::{mem::size_of, os::windows::io::AsRawHandle};
    use windows::Win32::{
        Foundation::HANDLE,
        Storage::FileSystem::{FileIdInfo, GetFileInformationByHandleEx, FILE_ID_INFO},
    };

    let handle = HANDLE(file.as_raw_handle().cast());
    let mut identity = FILE_ID_INFO::default();
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&mut identity as *mut FILE_ID_INFO).cast(),
            size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .map_err(|error| {
        format!(
            "Cannot query live file identity {}: {error}",
            path.display()
        )
    })?;
    Ok(WorkspaceFileIdentity {
        volume: identity.VolumeSerialNumber,
        id: identity.FileId.Identifier,
    })
}

#[cfg(unix)]
fn workspace_file_identity(file: &fs::File, path: &Path) -> Result<WorkspaceFileIdentity, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata().map_err(|error| {
        format!(
            "Cannot query live file identity {}: {error}",
            path.display()
        )
    })?;
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&metadata.ino().to_le_bytes());
    Ok(WorkspaceFileIdentity {
        volume: metadata.dev(),
        id,
    })
}

#[cfg(all(not(windows), not(unix)))]
fn workspace_file_identity(file: &fs::File, path: &Path) -> Result<WorkspaceFileIdentity, String> {
    let metadata = file.metadata().map_err(|error| {
        format!(
            "Cannot query live file identity {}: {error}",
            path.display()
        )
    })?;
    let mut id = [0_u8; 16];
    id[..8].copy_from_slice(&metadata.len().to_le_bytes());
    Ok(WorkspaceFileIdentity { volume: 0, id })
}

#[cfg(windows)]
fn validate_live_directory_streams(path: &Path, label: &str) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
        FILE_READ_ATTRIBUTES, FILE_SHARE_READ, SYNCHRONIZE,
    };

    let directory = fs::OpenOptions::new()
        .access_mode(FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | SYNCHRONIZE.0)
        .share_mode(FILE_SHARE_READ.0)
        .custom_flags((FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT).0)
        .open(path)
        .map_err(|error| format!("Cannot open live {label} for stream audit: {error}"))?;
    validate_no_named_data_streams(&directory, path)
        .map_err(|error| format!("Live {label} directory stream is unsafe: {error}"))
}

#[cfg(not(windows))]
fn validate_live_directory_streams(_path: &Path, _label: &str) -> Result<(), String> {
    Ok(())
}

pub(super) fn reconstruct_executable_processor_steps(
    lock: &GameRuntimeLock,
) -> Result<Vec<ExecutableProcessorStep>, String> {
    lock.validate()?;
    let upstream: HashMap<_, _> = lock
        .provenance
        .processor_plans
        .upstream
        .steps
        .iter()
        .map(|step| (step.upstream_index, step))
        .collect();
    let mut result = Vec::with_capacity(EXECUTABLE_UPSTREAM_INDICES.len());
    for (index, reference) in lock
        .provenance
        .processor_plans
        .executable
        .steps
        .iter()
        .enumerate()
    {
        let expected = EXECUTABLE_UPSTREAM_INDICES
            .get(index)
            .ok_or_else(|| "Executable NeoForge plan has too many steps".to_string())?;
        if reference.execution_index as usize != index || reference.upstream_index != *expected {
            return Err("Executable NeoForge plan is not exactly 3,5,6,8,9".into());
        }
        let step = upstream
            .get(expected)
            .ok_or_else(|| format!("Executable upstream step is missing: {expected}"))?;
        reject_networked_step(step)?;
        result.push(ExecutableProcessorStep {
            execution_index: reference.execution_index,
            upstream_index: reference.upstream_index,
            id: step.id.clone(),
            jar_path: step.jar_path.clone(),
            main_class: step.main_class.clone(),
            classpath: step.classpath.clone(),
            arguments: step.arguments.clone(),
        });
    }
    if result.len() != EXECUTABLE_UPSTREAM_INDICES.len() {
        return Err("Executable NeoForge plan does not contain exactly five steps".into());
    }
    Ok(result)
}

fn reject_networked_step(step: &UpstreamProcessorStep) -> Result<(), String> {
    if step.upstream_index == 4 || step.id == "DOWNLOAD_MOJMAPS" {
        return Err("Networked DOWNLOAD_MOJMAPS cannot be executed by the launcher".into());
    }
    Ok(())
}

pub(super) fn audit_existing_game_runtime_outputs(
    lock: &GameRuntimeLock,
    generation_root: &Path,
) -> Result<GameRuntimeOutputLease, String> {
    lock.validate()?;
    let expected = expected_outputs(lock)?;
    audit_output_tree(generation_root, expected)
}

fn audit_output_tree(
    generation_root: &Path,
    expected: BTreeMap<String, OutputIdentity>,
) -> Result<GameRuntimeOutputLease, String> {
    let expected_directories = expected_directories(&expected)?;
    let root_guard = GuardedDirectoryChain::root_snapshot(generation_root)
        .map_err(|error| format!("Game runtime output root is unsafe: {error}"))?;
    let mut observed = BTreeMap::new();
    let mut held_outputs = Vec::with_capacity(expected.len());
    let mut directory_guards = Vec::with_capacity(expected_directories.len());
    let mut seen_directories = BTreeSet::new();
    let mut entries = 0_usize;
    {
        let mut scan = OutputTreeScan {
            root: root_guard.root_path(),
            expected: &expected,
            expected_directories: &expected_directories,
            observed: &mut observed,
            held_outputs: &mut held_outputs,
            directory_guards: &mut directory_guards,
            seen_directories: &mut seen_directories,
            entries: &mut entries,
        };
        scan.scan(root_guard.root_path())?;
    }
    validate_output_inventory(&expected, &observed)?;
    validate_directory_inventory(&expected_directories, &seen_directories)?;
    let total_bytes = observed.values().try_fold(0_u64, |total, output| {
        total
            .checked_add(output.size)
            .ok_or_else(|| "Game runtime output byte total overflow".to_string())
    })?;
    let audit = GameRuntimeOutputAudit {
        file_count: observed.len(),
        total_bytes,
        outputs_sha256: domain_digest(
            "ru.fragmc.launcher.game-runtime.outputs.v1",
            &observed.values().collect::<Vec<_>>(),
        )?,
    };
    let mut lease = GameRuntimeOutputLease {
        audit,
        root: root_guard.root_path().to_path_buf(),
        expected,
        expected_directories,
        held_outputs,
        _root_guard: root_guard,
        _directory_guards: directory_guards,
    };
    // Repeat both hashes and the complete exact-casing inventory only after all file/directory
    // handles are held. This closes the earlier-file and concurrent-addition audit windows.
    lease.revalidate()?;
    Ok(lease)
}

fn expected_outputs(lock: &GameRuntimeLock) -> Result<BTreeMap<String, OutputIdentity>, String> {
    let mut expected = BTreeMap::new();
    for file in &lock.files {
        let GameRuntimeSource::Derived {
            size, sha1, sha256, ..
        } = &file.source
        else {
            continue;
        };
        let path = RelativeManagedPath::new(&file.path)
            .map_err(|error| format!("Derived output path is unsafe: {error}"))?;
        let identity = OutputIdentity {
            path: path.as_str().to_owned(),
            size: *size,
            sha1: sha1.clone(),
            sha256: sha256.clone(),
        };
        if expected
            .insert(path.collision_key().to_owned(), identity)
            .is_some()
        {
            return Err("Derived output paths collide on Windows".into());
        }
    }
    if expected.len() != 6 {
        return Err("Game runtime lock must contain exactly six derived outputs".into());
    }
    Ok(expected)
}

fn expected_directories(
    expected: &BTreeMap<String, OutputIdentity>,
) -> Result<BTreeMap<String, String>, String> {
    let mut directories = BTreeMap::new();
    for output in expected.values() {
        let mut path = RelativeManagedPath::new(&output.path)
            .map_err(|error| format!("Derived output path is unsafe: {error}"))?
            .parent();
        while let Some(parent) = path {
            let key = parent.collision_key().to_owned();
            let canonical = parent.as_str().to_owned();
            if let Some(existing) = directories.insert(key, canonical.clone()) {
                if existing != canonical {
                    return Err("Derived output directories collide on Windows".into());
                }
            }
            path = parent.parent();
        }
    }
    Ok(directories)
}

struct OutputTreeScan<'a> {
    root: &'a Path,
    expected: &'a BTreeMap<String, OutputIdentity>,
    expected_directories: &'a BTreeMap<String, String>,
    observed: &'a mut BTreeMap<String, OutputIdentity>,
    held_outputs: &'a mut Vec<HeldOutput>,
    directory_guards: &'a mut Vec<GuardedDirectoryChain>,
    seen_directories: &'a mut BTreeSet<String>,
    entries: &'a mut usize,
}

impl OutputTreeScan<'_> {
    fn scan(&mut self, directory: &Path) -> Result<(), String> {
        for entry in fs::read_dir(directory)
            .map_err(|error| format!("Cannot enumerate game runtime outputs: {error}"))?
        {
            *self.entries = self
                .entries
                .checked_add(1)
                .ok_or_else(|| "Game runtime output entry count overflow".to_string())?;
            if *self.entries > MAX_OUTPUT_TREE_ENTRIES {
                return Err("Game runtime output tree exceeds the entry limit".into());
            }
            let entry = entry.map_err(|error| format!("Cannot inspect output entry: {error}"))?;
            let absolute = entry.path();
            let metadata = fs::symlink_metadata(&absolute)
                .map_err(|error| format!("Cannot inspect output metadata: {error}"))?;
            if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
                return Err(format!(
                    "Link/reparse point is forbidden in outputs: {}",
                    absolute.display()
                ));
            }
            if metadata.is_file() && metadata.permissions().readonly() {
                return Err(format!(
                    "Read-only file is forbidden in outputs: {}",
                    absolute.display()
                ));
            }
            let relative = relative_output_path(self.root, &absolute)?;
            let managed = RelativeManagedPath::new(&relative)
                .map_err(|error| format!("Game runtime output path is unsafe: {error}"))?;
            let key = managed.collision_key().to_owned();
            if metadata.is_dir() {
                let canonical = self.expected_directories.get(&key).ok_or_else(|| {
                    format!("Unexpected directory in game runtime outputs: {relative}")
                })?;
                if managed.as_str() != canonical {
                    return Err(format!(
                        "Game runtime output directory casing mismatch: expected {canonical}, got {relative}"
                    ));
                }
                if !self.seen_directories.insert(key) {
                    return Err("Game runtime output directory was observed more than once".into());
                }
                let guard = GuardedDirectoryChain::open_snapshot(self.root, &managed)
                    .map_err(|error| format!("Game runtime output directory is unsafe: {error}"))?;
                let stable_directory = guard.leaf().path().to_path_buf();
                self.directory_guards.push(guard);
                self.scan(&stable_directory)?;
            } else if metadata.is_file() {
                let identity = self.expected.get(&key).ok_or_else(|| {
                    format!("Unexpected file in game runtime outputs: {relative}")
                })?;
                if managed.as_str() != identity.path {
                    return Err(format!(
                        "Game runtime output file casing mismatch: expected {}, got {relative}",
                        identity.path
                    ));
                }
                let (actual, file) = open_and_hash_managed_output(self.root, &managed, identity)?;
                if self.observed.insert(key.clone(), actual).is_some() {
                    return Err("Game runtime output path was observed more than once".into());
                }
                self.held_outputs.push(HeldOutput {
                    key,
                    expected: identity.clone(),
                    file,
                });
            } else {
                return Err(format!(
                    "Special file is forbidden in outputs: {}",
                    absolute.display()
                ));
            }
        }
        Ok(())
    }
}

fn validate_output_tree_inventory(
    root: &Path,
    expected: &BTreeMap<String, OutputIdentity>,
    expected_directories: &BTreeMap<String, String>,
) -> Result<(), String> {
    let mut files = BTreeSet::new();
    let mut directories = BTreeSet::new();
    let mut entries = 0_usize;
    scan_output_inventory(
        root,
        root,
        expected,
        expected_directories,
        &mut files,
        &mut directories,
        &mut entries,
    )?;
    let expected_files = expected.keys().cloned().collect::<BTreeSet<_>>();
    if files != expected_files {
        return Err("Game runtime output file inventory changed during audit".into());
    }
    validate_directory_inventory(expected_directories, &directories)
}

fn scan_output_inventory(
    root: &Path,
    directory: &Path,
    expected: &BTreeMap<String, OutputIdentity>,
    expected_directories: &BTreeMap<String, String>,
    files: &mut BTreeSet<String>,
    directories: &mut BTreeSet<String>,
    entries: &mut usize,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("Cannot re-enumerate game runtime outputs: {error}"))?
    {
        *entries = entries
            .checked_add(1)
            .ok_or_else(|| "Game runtime output entry count overflow".to_string())?;
        if *entries > MAX_OUTPUT_TREE_ENTRIES {
            return Err("Game runtime output tree exceeds the entry limit".into());
        }
        let entry = entry.map_err(|error| format!("Cannot inspect output entry: {error}"))?;
        let absolute = entry.path();
        let metadata = fs::symlink_metadata(&absolute)
            .map_err(|error| format!("Cannot inspect output metadata: {error}"))?;
        if metadata.file_type().is_symlink() || is_windows_reparse_point(&metadata) {
            return Err(format!(
                "Link/reparse point is forbidden in outputs: {}",
                absolute.display()
            ));
        }
        if metadata.is_file() && metadata.permissions().readonly() {
            return Err(format!(
                "Read-only file is forbidden in outputs: {}",
                absolute.display()
            ));
        }
        let relative = relative_output_path(root, &absolute)?;
        let managed = RelativeManagedPath::new(&relative)
            .map_err(|error| format!("Game runtime output path is unsafe: {error}"))?;
        let key = managed.collision_key().to_owned();
        if metadata.is_dir() {
            let canonical = expected_directories.get(&key).ok_or_else(|| {
                format!("Unexpected directory in game runtime outputs: {relative}")
            })?;
            if managed.as_str() != canonical || !directories.insert(key) {
                return Err(format!(
                    "Game runtime output directory casing/collision mismatch: {relative}"
                ));
            }
            let guard = GuardedDirectoryChain::open(root, &managed)
                .map_err(|error| format!("Game runtime output directory is unsafe: {error}"))?;
            let stable_directory = guard.leaf().path().to_path_buf();
            scan_output_inventory(
                root,
                &stable_directory,
                expected,
                expected_directories,
                files,
                directories,
                entries,
            )?;
        } else if metadata.is_file() {
            let identity = expected
                .get(&key)
                .ok_or_else(|| format!("Unexpected file in game runtime outputs: {relative}"))?;
            if managed.as_str() != identity.path || !files.insert(key) {
                return Err(format!(
                    "Game runtime output file casing/collision mismatch: {relative}"
                ));
            }
        } else {
            return Err(format!(
                "Special file is forbidden in outputs: {}",
                absolute.display()
            ));
        }
    }
    Ok(())
}

fn relative_output_path(root: &Path, absolute: &Path) -> Result<String, String> {
    absolute
        .strip_prefix(root)
        .map_err(|_| "Game runtime output escaped its root".to_string())?
        .components()
        .map(|component| {
            component
                .as_os_str()
                .to_str()
                .ok_or_else(|| "Game runtime output path is not UTF-8".to_string())
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|components| components.join("/"))
}

fn validate_directory_inventory(
    expected: &BTreeMap<String, String>,
    observed: &BTreeSet<String>,
) -> Result<(), String> {
    if expected.keys().cloned().collect::<BTreeSet<_>>() != *observed {
        return Err("Game runtime output directory inventory mismatch".into());
    }
    Ok(())
}

fn open_and_hash_managed_output(
    root: &Path,
    path: &RelativeManagedPath,
    expected: &OutputIdentity,
) -> Result<(OutputIdentity, ImmutableManagedFile), String> {
    let mut guarded = ImmutableManagedFile::open(root, path)
        .map_err(|error| format!("Game runtime output is unsafe: {error}"))?;
    let actual = hash_held_output(&mut guarded, expected)?;
    Ok((actual, guarded))
}

fn hash_held_output(
    guarded: &mut ImmutableManagedFile,
    expected: &OutputIdentity,
) -> Result<OutputIdentity, String> {
    let digest = guarded
        .sha1_sha256(expected.size)
        .map_err(|error| format!("Cannot hash game runtime output: {error}"))?;
    let actual = OutputIdentity {
        path: expected.path.clone(),
        size: digest.size,
        sha1: digest.sha1,
        sha256: digest.sha256,
    };
    if &actual != expected {
        return Err(format!(
            "Game runtime output identity mismatch: {}",
            expected.path
        ));
    }
    Ok(actual)
}

fn validate_output_inventory(
    expected: &BTreeMap<String, OutputIdentity>,
    observed: &BTreeMap<String, OutputIdentity>,
) -> Result<(), String> {
    if expected != observed {
        let missing = expected
            .keys()
            .filter(|path| !observed.contains_key(*path))
            .cloned()
            .collect::<Vec<_>>();
        let unexpected = observed
            .keys()
            .filter(|path| !expected.contains_key(*path))
            .cloned()
            .collect::<Vec<_>>();
        return Err(format!(
            "Game runtime output inventory mismatch (missing: {}; unexpected: {})",
            missing.join(", "),
            unexpected.join(", ")
        ));
    }
    Ok(())
}

/// The only production entrypoint into the raw process supervisor. The invocation is
/// unforgeable outside its module and lifetime-bound to a live materialized workspace. The Java
/// tree is completely revalidated as the final filesystem operation before `CreateProcessW`.
pub(super) fn run_prepared_java_process(
    invocation: &PreparedProcessorInvocation,
    runtime_lock: &RuntimeLock,
    runtime: &RuntimeInstallation,
    owned_root: &OwnedCasRoot,
    limits: JavaProcessLimits,
    monitor_limits: ProcessorWorkspaceMonitorLimits,
    cancelled: Arc<AtomicBool>,
) -> JavaProcessResult<JavaProcessOutput> {
    let monitor = ProcessorWorkspaceMonitor::for_invocation(invocation, monitor_limits)?;
    let reserve =
        ProcessorRecoveryReserve::allocate(invocation.cwd(), PROCESSOR_RECOVERY_RESERVE_BYTES)?;
    let mut request = JavaProcessRequest {
        executable: invocation.executable(),
        arguments: invocation.arguments(),
        cwd: invocation.cwd(),
        environment: invocation.environment(),
        limits,
        workspace_monitor: Some(monitor),
        recovery_reserve: Some(reserve),
        cancelled,
    };
    let preflight = (|| {
        validate_process_request_before_spawn(&request)?;
        // Keep the exact root-bound Java audit as the final filesystem trust operation before the
        // native process supervisor receives the already-validated request.
        let verified = revalidate_runtime_installation_for_root(runtime, runtime_lock, owned_root)?;
        if invocation.executable() != verified.java_console() {
            return Err("Prepared processor executable is not the revalidated Java console".into());
        }
        Ok(())
    })();
    if let Err(error) = preflight {
        let cleanup = release_request_recovery_reserve(&mut request);
        return Err(append_process_cleanup_error(error, cleanup));
    }
    run_java_process_validated(request)
}

fn run_java_process(mut request: JavaProcessRequest<'_>) -> Result<JavaProcessOutput, String> {
    if let Err(error) = validate_process_request_before_spawn(&request) {
        let cleanup = release_request_recovery_reserve(&mut request);
        return Err(append_process_cleanup_error(error, cleanup).to_string());
    }
    run_java_process_validated(request).map_err(|error| error.to_string())
}

fn release_request_recovery_reserve(request: &mut JavaProcessRequest<'_>) -> Option<String> {
    request
        .recovery_reserve
        .take()
        .and_then(|reserve| reserve.release().err())
}

fn validate_process_request_before_spawn(
    request: &JavaProcessRequest<'_>,
) -> JavaProcessResult<()> {
    validate_process_request(request)?;
    if request.cancelled.load(Ordering::Acquire) {
        return Err(JavaProcessError::Cancelled);
    }
    audit_process_live_state(request).map_err(|error| {
        JavaProcessError::Failed(format!(
            "NeoForge processor workspace monitor rejected pre-spawn state: {error}"
        ))
    })?;
    Ok(())
}

fn audit_process_live_state(request: &JavaProcessRequest<'_>) -> Result<(), String> {
    if let Some(monitor) = &request.workspace_monitor {
        monitor.audit()?;
    }
    if let Some(reserve) = &request.recovery_reserve {
        reserve.revalidate()?;
    }
    Ok(())
}

fn run_java_process_validated(
    mut request: JavaProcessRequest<'_>,
) -> JavaProcessResult<JavaProcessOutput> {
    let spawned = spawn_process(ProcessSpec {
        executable: request.executable,
        arguments: request.arguments,
        cwd: request.cwd,
        environment: request.environment,
    });
    let (mut child, pipes) = match spawned {
        Ok(spawned) => spawned,
        Err(error) => {
            let reserve = release_request_recovery_reserve(&mut request);
            return Err(append_process_cleanup_error(
                JavaProcessError::Failed(error),
                reserve,
            ));
        }
    };
    let (failure_tx, failure_rx) = mpsc::channel::<String>();
    let stdout_result = capture_stream(
        pipes.stdout,
        "stdout",
        request.limits.max_stream_bytes,
        request.limits.max_diagnostic_bytes,
        failure_tx.clone(),
    );
    let stderr_result = capture_stream(
        pipes.stderr,
        "stderr",
        request.limits.max_stream_bytes,
        request.limits.max_diagnostic_bytes,
        failure_tx,
    );

    let started = Instant::now();
    let mut next_workspace_audit = started + WORKSPACE_MONITOR_INTERVAL;
    let mut terminal_error = None;
    let mut status = None;
    loop {
        if request.cancelled.load(Ordering::Acquire) {
            terminal_error = Some(JavaProcessError::Cancelled);
        } else if started.elapsed() > request.limits.timeout {
            terminal_error = Some(JavaProcessError::Failed(
                "NeoForge processor execution timed out".into(),
            ));
        } else if let Ok(error) = failure_rx.try_recv() {
            terminal_error = Some(JavaProcessError::Failed(error));
        } else if Instant::now() >= next_workspace_audit {
            if let Err(error) = audit_process_live_state(&request) {
                terminal_error = Some(JavaProcessError::Failed(format!(
                    "NeoForge processor workspace limit was exceeded during execution: {error}"
                )));
            }
            next_workspace_audit = Instant::now() + WORKSPACE_MONITOR_INTERVAL;
        }
        if terminal_error.is_some() {
            break;
        }
        match child.try_wait() {
            Ok(Some(exit)) => {
                if let Err(error) = audit_process_live_state(&request) {
                    terminal_error = Some(JavaProcessError::Failed(format!(
                        "NeoForge processor workspace limit was exceeded before exit acceptance: {error}"
                    )));
                } else {
                    status = Some(exit);
                }
                break;
            }
            Ok(None) => {}
            Err(error) => {
                terminal_error = Some(JavaProcessError::Failed(format!(
                    "Cannot poll NeoForge processor: {error}"
                )));
                break;
            }
        }
        thread::sleep(Duration::from_millis(10));
    }

    // Even on a normal parent exit, terminate the job before draining pipes: a processor must not
    // leave descendants alive while they retain inherited stdout/stderr handles.
    let cleanup = child.terminate_and_reap(PROCESS_CLEANUP_TIMEOUT);
    drop(child);

    let drain_deadline = Instant::now() + STREAM_DRAIN_TIMEOUT;
    let stdout = receive_stream_capture(stdout_result, "stdout", drain_deadline);
    let stderr = receive_stream_capture(stderr_result, "stderr", drain_deadline);
    let mut result: JavaProcessResult<JavaProcessOutput> = if let Some(error) = terminal_error {
        let error = append_process_cleanup_error(error, cleanup.err());
        let error = append_process_cleanup_error(error, stdout.as_ref().err().cloned());
        Err(append_process_cleanup_error(
            error,
            stderr.as_ref().err().cloned(),
        ))
    } else {
        (|| {
            cleanup?;
            let stdout = stdout?;
            let stderr = stderr?;
            let exit_code =
                status.ok_or_else(|| "NeoForge processor status is missing".to_string())?;
            let transcript_sha256 = transcript_digest(&stdout, &stderr)?;
            Ok(JavaProcessOutput {
                exit_code,
                stdout,
                stderr,
                transcript_sha256,
            })
        })()
        .map_err(JavaProcessError::Failed)
    };
    if let Some(reserve) = request.recovery_reserve.take() {
        if let Err(error) = reserve.release() {
            result = match result {
                Ok(_) => Err(JavaProcessError::Failed(error)),
                Err(existing) => Err(append_process_cleanup_error(existing, Some(error))),
            };
        }
    }
    result
}

fn append_process_cleanup_error(
    error: JavaProcessError,
    cleanup: Option<String>,
) -> JavaProcessError {
    match cleanup {
        Some(cleanup) => {
            JavaProcessError::Failed(format!("{error}; process cleanup failed: {cleanup}"))
        }
        None => error,
    }
}

fn append_cleanup_error(error: String, cleanup: Option<String>) -> String {
    match cleanup {
        Some(cleanup) => format!("{error}; process cleanup failed: {cleanup}"),
        None => error,
    }
}

fn validate_process_request(request: &JavaProcessRequest<'_>) -> Result<(), String> {
    if !request.executable.is_absolute() || !request.cwd.is_absolute() {
        return Err("NeoForge processor executable and cwd must be absolute".into());
    }
    if request.limits.timeout.is_zero() || request.limits.timeout > MAX_PROCESS_TIMEOUT {
        return Err("NeoForge processor timeout is outside the supported bound".into());
    }
    if request.limits.max_stream_bytes == 0
        || request.limits.max_stream_bytes > MAX_STREAM_BYTES
        || request.limits.max_diagnostic_bytes > MAX_DIAGNOSTIC_BYTES
        || request.limits.max_diagnostic_bytes as u64 > request.limits.max_stream_bytes
    {
        return Err("NeoForge processor stream limits are invalid".into());
    }
    if request.arguments.len() > 512 || request.environment.len() > 128 {
        return Err("NeoForge processor invocation exceeds the launcher bound".into());
    }
    let mut environment_keys = HashSet::new();
    for (key, value) in request.environment {
        let key = key
            .to_str()
            .ok_or_else(|| "NeoForge processor environment key is not Unicode".to_string())?;
        let value = value
            .to_str()
            .ok_or_else(|| "NeoForge processor environment value is not Unicode".to_string())?;
        let mut characters = key.chars();
        if key.len() > 128
            || value.len() > 32_767
            || !characters
                .next()
                .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
            || !characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
            || !environment_keys.insert(key.to_ascii_uppercase())
        {
            return Err("NeoForge processor environment is invalid or ambiguous".into());
        }
    }
    Ok(())
}

fn capture_stream<R: Read + Send + 'static>(
    mut reader: R,
    label: &'static str,
    maximum_bytes: u64,
    diagnostic_bytes: usize,
    failure: mpsc::Sender<String>,
) -> mpsc::Receiver<Result<StreamCapture, String>> {
    let (result_tx, result_rx) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let result = (|| {
            let mut sha256 = Sha256::new();
            let mut total = 0_u64;
            let mut diagnostic = Vec::with_capacity(diagnostic_bytes);
            let mut buffer = vec![0_u8; 64 * 1024];
            loop {
                let read = match reader.read(&mut buffer) {
                    Ok(read) => read,
                    Err(error) => {
                        let message = format!("Cannot read NeoForge processor {label}: {error}");
                        let _ = failure.send(message.clone());
                        return Err(message);
                    }
                };
                if read == 0 {
                    break;
                }
                total = match total.checked_add(read as u64) {
                    Some(total) => total,
                    None => {
                        let message = format!("NeoForge processor {label} size overflow");
                        let _ = failure.send(message.clone());
                        return Err(message);
                    }
                };
                if total > maximum_bytes {
                    let message = format!("NeoForge processor {label} exceeded the byte limit");
                    let _ = failure.send(message.clone());
                    return Err(message);
                }
                sha256.update(&buffer[..read]);
                let remaining = diagnostic_bytes.saturating_sub(diagnostic.len());
                diagnostic.extend_from_slice(&buffer[..read.min(remaining)]);
            }
            Ok(StreamCapture {
                bytes: total,
                sha256: format!("{:x}", sha256.finalize()),
                truncated: total > diagnostic.len() as u64,
                diagnostic,
            })
        })();
        let _ = result_tx.send(result);
    });
    result_rx
}

fn receive_stream_capture(
    receiver: mpsc::Receiver<Result<StreamCapture, String>>,
    label: &'static str,
    deadline: Instant,
) -> Result<StreamCapture, String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(format!(
            "NeoForge processor {label} did not drain before the deadline"
        ));
    }
    match receiver.recv_timeout(remaining) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(format!(
            "NeoForge processor {label} did not drain before the deadline"
        )),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            Err(format!("NeoForge processor {label} reader terminated"))
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Transcript<'a> {
    stdout_bytes: u64,
    stdout_sha256: &'a str,
    stderr_bytes: u64,
    stderr_sha256: &'a str,
}

fn transcript_digest(stdout: &StreamCapture, stderr: &StreamCapture) -> Result<String, String> {
    domain_digest(
        "ru.fragmc.spark2.neoforge.transcript.v1",
        &Transcript {
            stdout_bytes: stdout.bytes,
            stdout_sha256: &stdout.sha256,
            stderr_bytes: stderr.bytes,
            stderr_sha256: &stderr.sha256,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    const CHILD_MODE_ENV: &str = "FRAGMENT_GAME_RUNTIME_CHILD_MODE";
    const CHILD_SCRATCH_ENV: &str = "FRAGMENT_GAME_RUNTIME_SCRATCH_PATH";

    fn child_arguments() -> Vec<OsString> {
        vec![
            OsString::from("--exact"),
            OsString::from("build_manager::game_runtime::tests::child_process_fixture"),
            OsString::from("--nocapture"),
        ]
    }

    #[cfg(windows)]
    #[allow(clippy::zombie_processes)]
    fn spawn_descendant_that_must_be_reaped_by_the_job() {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        // Deliberately do not wait here: the integration test proves the enclosing Job Object
        // terminates this inherited-pipe descendant when its direct parent exits.
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(child_arguments())
            .env(CHILD_MODE_ENV, "descendant-sleep")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .creation_flags(CREATE_NO_WINDOW);
        drop(crate::build_manager::spawn_command_with_inheritance_lock(&mut command).unwrap());
    }

    fn small_output_specs() -> Vec<(&'static str, &'static [u8])> {
        vec![
            ("libraries/neoform/mappings.txt", b"neoform"),
            ("libraries/neoform/mappings-merged.txt", b"merged"),
            ("libraries/minecraft/client-slim.jar", b"slim"),
            ("libraries/minecraft/client-extra.jar", b"extra"),
            ("libraries/minecraft/client-srg.jar", b"srg"),
            ("libraries/neoforge/client.jar", b"patched"),
        ]
    }

    fn small_expected_outputs() -> BTreeMap<String, OutputIdentity> {
        small_output_specs()
            .into_iter()
            .map(|(path, bytes)| {
                let managed = RelativeManagedPath::new(path).unwrap();
                let identity = OutputIdentity {
                    path: path.to_owned(),
                    size: bytes.len() as u64,
                    sha1: format!("{:x}", Sha1::digest(bytes)),
                    sha256: format!("{:x}", Sha256::digest(bytes)),
                };
                (managed.collision_key().to_owned(), identity)
            })
            .collect()
    }

    fn temp_output_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-game-runtime-{label}-{}",
            uuid::Uuid::new_v4()
        ))
    }

    fn write_small_output_tree(root: &Path) {
        fs::create_dir(root).unwrap();
        for (path, bytes) in small_output_specs() {
            let destination = root.join(path.replace('/', std::path::MAIN_SEPARATOR_STR));
            fs::create_dir_all(destination.parent().unwrap()).unwrap();
            fs::write(destination, bytes).unwrap();
        }
    }

    fn live_monitor_root(label: &str) -> PathBuf {
        let root = temp_output_root(label);
        fs::create_dir(&root).unwrap();
        fs::create_dir(root.join("inputs")).unwrap();
        fs::create_dir(root.join("temp")).unwrap();
        fs::create_dir(root.join("state")).unwrap();
        fs::create_dir(root.join("state/user-home")).unwrap();
        fs::create_dir(root.join("outputs")).unwrap();
        fs::write(root.join("state").join(STATE_MARKER_PATH), b"test marker").unwrap();
        root
    }

    fn empty_live_monitor(root: &Path, scratch_max_bytes: u64) -> ProcessorWorkspaceMonitor {
        ProcessorWorkspaceMonitor {
            root: root.to_path_buf(),
            inputs: root.join("inputs"),
            temp: root.join("temp"),
            home: root.join("state/user-home"),
            outputs: root.join("outputs"),
            input_inventory: audit_live_workspace_inventory(
                &root.join("inputs"),
                "processor inputs",
                WorkspaceTreeLimit {
                    max_entries: 16,
                    max_bytes: 1024,
                },
            )
            .unwrap(),
            scratch_limit: WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: scratch_max_bytes,
            },
            output_limit: WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024,
            },
            allowed_output_files: BTreeMap::new(),
            allowed_output_directories: BTreeMap::new(),
        }
    }

    fn fixture_lock() -> GameRuntimeLock {
        GameRuntimeLock::parse_and_validate(include_bytes!(
            "../../tests/fixtures/game-runtime-lock-v2-release-canonical-verified.json"
        ))
        .expect("canonical Spark2 game-runtime fixture must remain valid")
    }

    #[test]
    fn reconstructs_only_the_five_signed_offline_steps() {
        let steps = reconstruct_executable_processor_steps(&fixture_lock()).unwrap();
        assert_eq!(
            steps
                .iter()
                .map(|step| step.upstream_index)
                .collect::<Vec<_>>(),
            EXECUTABLE_UPSTREAM_INDICES
        );
        assert!(steps.iter().all(|step| step.id != "DOWNLOAD_MOJMAPS"));
    }

    #[test]
    fn validates_an_exact_six_output_inventory_and_rejects_drift() {
        let expected = expected_outputs(&fixture_lock()).unwrap();
        assert_eq!(expected.len(), 6);
        validate_output_inventory(&expected, &expected).unwrap();

        let mut missing = expected.clone();
        missing.pop_first();
        assert!(validate_output_inventory(&expected, &missing)
            .unwrap_err()
            .contains("inventory mismatch"));

        let mut altered = expected.clone();
        altered.values_mut().next().unwrap().sha256 = "f".repeat(64);
        assert!(validate_output_inventory(&expected, &altered)
            .unwrap_err()
            .contains("inventory mismatch"));
    }

    #[test]
    fn filesystem_audit_holds_and_revalidates_an_exact_six_output_lease() {
        let root = temp_output_root("lease-positive");
        write_small_output_tree(&root);
        let mut lease = audit_output_tree(&root, small_expected_outputs()).unwrap();
        assert_eq!(lease.audit().file_count, 6);
        assert_eq!(lease.audit().total_bytes, 32);
        lease.revalidate().unwrap();
        drop(lease);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn output_lease_streams_only_the_exact_signed_identity_to_an_exclusive_file() {
        let root = temp_output_root("lease-copy-source");
        let destination_root = temp_output_root("lease-copy-destination");
        write_small_output_tree(&root);
        fs::create_dir(&destination_root).unwrap();
        let expected = small_expected_outputs();
        let identity = expected
            .get(
                RelativeManagedPath::new("libraries/neoforge/client.jar")
                    .unwrap()
                    .collision_key(),
            )
            .unwrap()
            .clone();
        let mut lease = audit_output_tree(&root, expected).unwrap();
        let destination_relative = RelativeManagedPath::new("copied-client.jar").unwrap();
        let mut destination =
            ExclusiveManagedFile::create(&destination_root, destination_relative).unwrap();

        assert!(lease
            .copy_expected_to(
                &identity.path,
                identity.size,
                &identity.sha1,
                &"0".repeat(64),
                &mut destination,
            )
            .is_err());
        let written = lease
            .copy_expected_to(
                &identity.path,
                identity.size,
                &identity.sha1,
                &identity.sha256,
                &mut destination,
            )
            .unwrap();
        assert_eq!(written.size, identity.size);
        assert_eq!(written.sha1, identity.sha1);
        assert_eq!(written.sha256, identity.sha256);
        drop(destination.seal_in_place().unwrap());
        drop(lease);
        assert_eq!(
            fs::read(destination_root.join("copied-client.jar")).unwrap(),
            b"patched"
        );
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(destination_root).unwrap();
    }

    #[test]
    fn filesystem_audit_rejects_wrong_casing_missing_and_extra_entries() {
        let wrong_case = temp_output_root("wrong-case");
        write_small_output_tree(&wrong_case);
        let original = wrong_case.join("libraries");
        let intermediate = wrong_case.join("case-transition");
        let altered = wrong_case.join("Libraries");
        fs::rename(&original, &intermediate).unwrap();
        fs::rename(&intermediate, &altered).unwrap();
        let error = audit_output_tree(&wrong_case, small_expected_outputs())
            .err()
            .unwrap();
        assert!(error.contains("casing mismatch"));
        fs::remove_dir_all(wrong_case).unwrap();

        let missing = temp_output_root("missing");
        write_small_output_tree(&missing);
        fs::remove_file(missing.join("libraries/neoforge/client.jar")).unwrap();
        assert!(audit_output_tree(&missing, small_expected_outputs()).is_err());
        fs::remove_dir_all(missing).unwrap();

        let extra = temp_output_root("extra");
        write_small_output_tree(&extra);
        fs::write(extra.join("libraries/unexpected.bin"), b"unexpected").unwrap();
        assert!(audit_output_tree(&extra, small_expected_outputs()).is_err());
        fs::remove_dir_all(extra).unwrap();
    }

    #[test]
    fn filesystem_audit_rejects_corruption_and_hardlinks() {
        let corrupt = temp_output_root("corrupt");
        write_small_output_tree(&corrupt);
        fs::write(corrupt.join("libraries/minecraft/client-srg.jar"), b"bad").unwrap();
        assert!(audit_output_tree(&corrupt, small_expected_outputs()).is_err());
        fs::remove_dir_all(corrupt).unwrap();

        let hardlink = temp_output_root("hardlink");
        write_small_output_tree(&hardlink);
        let external = hardlink.with_extension("external-link");
        fs::hard_link(hardlink.join("libraries/neoforge/client.jar"), &external).unwrap();
        assert!(audit_output_tree(&hardlink, small_expected_outputs()).is_err());
        fs::remove_file(external).unwrap();
        fs::remove_dir_all(hardlink).unwrap();
    }

    #[test]
    fn filesystem_output_lease_detects_post_audit_additions_and_replacements() {
        let addition = temp_output_root("concurrent-addition");
        write_small_output_tree(&addition);
        let mut lease = audit_output_tree(&addition, small_expected_outputs()).unwrap();
        match fs::write(addition.join("libraries/late.bin"), b"late") {
            Ok(()) => assert!(lease.revalidate().is_err()),
            Err(_) => lease.revalidate().unwrap(),
        }
        drop(lease);
        fs::remove_dir_all(addition).unwrap();

        let replacement = temp_output_root("concurrent-replacement");
        write_small_output_tree(&replacement);
        let mut lease = audit_output_tree(&replacement, small_expected_outputs()).unwrap();
        let path = replacement.join("libraries/neoforge/client.jar");
        match fs::write(&path, b"changed") {
            Ok(()) => assert!(lease.revalidate().is_err()),
            Err(_) => lease.revalidate().unwrap(),
        }
        drop(lease);
        fs::remove_dir_all(replacement).unwrap();
    }

    #[test]
    fn process_runner_captures_bounded_streams_and_transcript() {
        let executable = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let arguments = vec![OsString::from("--list")];
        let output = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &cwd,
            environment: &[],
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(10),
                max_stream_bytes: 16 * 1024 * 1024,
                max_diagnostic_bytes: 64 * 1024,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
        .unwrap();
        assert_eq!(output.exit_code, 0);
        assert!(output.stdout.bytes > 0);
        assert_eq!(
            output.transcript_sha256,
            transcript_digest(&output.stdout, &output.stderr).unwrap()
        );
    }

    #[test]
    fn stream_capture_hashes_exact_bytes_and_truncates_only_diagnostics() {
        let (failure, _errors) = mpsc::channel();
        let result = capture_stream(
            std::io::Cursor::new(b"abcdef".to_vec()),
            "stdout",
            1024,
            3,
            failure,
        );
        let output =
            receive_stream_capture(result, "stdout", Instant::now() + Duration::from_secs(1))
                .unwrap();
        assert_eq!(output.bytes, 6);
        assert_eq!(output.sha256, format!("{:x}", Sha256::digest(b"abcdef")));
        assert_eq!(output.diagnostic, b"abc");
        assert!(output.truncated);
    }

    #[test]
    fn process_runner_clears_inherited_environment_and_returns_nonzero_exit() {
        let executable = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let arguments = child_arguments();
        let clear_environment = vec![(
            OsString::from(CHILD_MODE_ENV),
            OsString::from("environment-cleared"),
        )];
        let cleared = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &cwd,
            environment: &clear_environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(10),
                max_stream_bytes: 1024 * 1024,
                max_diagnostic_bytes: 1024,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
        .unwrap();
        assert_eq!(cleared.exit_code, 0);

        let nonzero_environment = vec![(OsString::from(CHILD_MODE_ENV), OsString::from("nonzero"))];
        let nonzero = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &cwd,
            environment: &nonzero_environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(10),
                max_stream_bytes: 1024 * 1024,
                max_diagnostic_bytes: 1024,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
        .unwrap();
        assert_ne!(nonzero.exit_code, 0);
    }

    #[test]
    fn process_runner_rejects_case_colliding_environment_keys() {
        let executable = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let environment = vec![
            (OsString::from("PATH"), OsString::from("one")),
            (OsString::from("path"), OsString::from("two")),
        ];
        let result = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &[],
            cwd: &cwd,
            environment: &environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(1),
                max_stream_bytes: 1024,
                max_diagnostic_bytes: 128,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        assert!(result.unwrap_err().contains("ambiguous"));
    }

    #[test]
    fn process_runner_fails_closed_before_start_when_cancelled() {
        let executable = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let result = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &[],
            cwd: &cwd,
            environment: &[],
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(1),
                max_stream_bytes: 1024,
                max_diagnostic_bytes: 128,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled: Arc::new(AtomicBool::new(true)),
        });
        assert!(result.unwrap_err().contains("cancelled"));
    }

    #[test]
    fn typed_process_cancellation_is_not_inferred_from_failure_text() {
        assert_eq!(
            append_process_cleanup_error(JavaProcessError::Cancelled, None),
            JavaProcessError::Cancelled
        );
        assert!(matches!(
            append_process_cleanup_error(
                JavaProcessError::Cancelled,
                Some("reserve release failed".into())
            ),
            JavaProcessError::Failed(message)
                if message.contains("cancelled") && message.contains("reserve release failed")
        ));
        assert!(matches!(
            JavaProcessError::Failed("NeoForge processor execution was cancelled".into()),
            JavaProcessError::Failed(_)
        ));
    }

    #[test]
    fn pre_spawn_failure_reports_reserve_release_failure() {
        let root = live_monitor_root("reserve-release-failure");
        let executable = std::env::current_exe().unwrap();
        let mut reserve = ProcessorRecoveryReserve::allocate(&root, 1024 * 1024).unwrap();
        reserve.inject_release_failure("injected reserve release failure");
        let result = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &[],
            cwd: &root,
            environment: &[],
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(1),
                max_stream_bytes: 1024,
                max_diagnostic_bytes: 128,
            },
            workspace_monitor: None,
            recovery_reserve: Some(reserve),
            cancelled: Arc::new(AtomicBool::new(true)),
        });
        let error = result.unwrap_err();
        assert!(error.contains("cancelled"), "unexpected error: {error}");
        assert!(
            error.contains("injected reserve release failure"),
            "unexpected error: {error}"
        );
        assert!(!root.join(RECOVERY_RESERVE_PATH).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_monitor_kills_children_that_write_root_state_or_inputs() {
        for (label, relative) in [
            ("root-write", "rogue.bin"),
            ("state-write", "state/rogue.bin"),
            ("input-write", "inputs/rogue.bin"),
            (
                "reserve-ads-write",
                "state/processor-recovery-reserve.bin:rogue",
            ),
        ] {
            let root = live_monitor_root(label);
            let monitor = empty_live_monitor(&root, 1024 * 1024);
            let reserve = ProcessorRecoveryReserve::allocate(&root, 1024 * 1024).unwrap();
            let attack = root.join(relative.replace('/', std::path::MAIN_SEPARATOR_STR));
            let environment = vec![
                (
                    OsString::from(CHILD_MODE_ENV),
                    OsString::from("workspace-write"),
                ),
                (
                    OsString::from(CHILD_SCRATCH_ENV),
                    attack.as_os_str().to_owned(),
                ),
            ];
            let result = run_java_process(JavaProcessRequest {
                executable: &std::env::current_exe().unwrap(),
                arguments: &child_arguments(),
                cwd: &root,
                environment: &environment,
                limits: JavaProcessLimits {
                    timeout: Duration::from_secs(10),
                    max_stream_bytes: 1024 * 1024,
                    max_diagnostic_bytes: 1024,
                },
                workspace_monitor: Some(monitor),
                recovery_reserve: Some(reserve),
                cancelled: Arc::new(AtomicBool::new(false)),
            });
            let error = result.unwrap_err();
            assert!(
                error.contains("workspace limit"),
                "unexpected error: {error}"
            );
            assert!(!root.join(RECOVERY_RESERVE_PATH).exists());
            fs::remove_dir_all(root).unwrap();
        }
    }

    #[test]
    fn live_workspace_monitor_terminates_a_child_before_exit_and_releases_reserve() {
        let root = live_monitor_root("live-monitor-termination");
        let executable = std::env::current_exe().unwrap();
        let arguments = child_arguments();
        let scratch = root.join("temp/flood.bin");
        let environment = vec![
            (
                OsString::from(CHILD_MODE_ENV),
                OsString::from("scratch-flood"),
            ),
            (
                OsString::from(CHILD_SCRATCH_ENV),
                scratch.as_os_str().to_owned(),
            ),
        ];
        let input_inventory = audit_live_workspace_inventory(
            &root.join("inputs"),
            "processor inputs",
            WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let monitor = ProcessorWorkspaceMonitor {
            root: root.clone(),
            inputs: root.join("inputs"),
            temp: root.join("temp"),
            home: root.join("state/user-home"),
            outputs: root.join("outputs"),
            input_inventory,
            scratch_limit: WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 64 * 1024,
            },
            output_limit: WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024 * 1024,
            },
            allowed_output_files: BTreeMap::new(),
            allowed_output_directories: BTreeMap::new(),
        };
        let reserve = ProcessorRecoveryReserve::allocate(&root, 1024 * 1024).unwrap();
        assert!(root.join(RECOVERY_RESERVE_PATH).is_file());
        let started = Instant::now();
        let result = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &root,
            environment: &environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(10),
                max_stream_bytes: 1024 * 1024,
                max_diagnostic_bytes: 1024,
            },
            workspace_monitor: Some(monitor),
            recovery_reserve: Some(reserve),
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        let error = result.unwrap_err();
        assert!(
            error.contains("workspace limit"),
            "unexpected error: {error}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!root.join(RECOVERY_RESERVE_PATH).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    #[allow(clippy::permissions_set_readonly_false)]
    fn live_workspace_monitor_rejects_root_input_and_state_bypasses() {
        let root = live_monitor_root("live-monitor-topology");
        fs::write(root.join("inputs/pinned.bin"), b"pinned").unwrap();
        let input_inventory = audit_live_workspace_inventory(
            &root.join("inputs"),
            "processor inputs",
            WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let monitor = ProcessorWorkspaceMonitor {
            root: root.clone(),
            inputs: root.join("inputs"),
            temp: root.join("temp"),
            home: root.join("state/user-home"),
            outputs: root.join("outputs"),
            input_inventory,
            scratch_limit: WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024,
            },
            output_limit: WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024,
            },
            allowed_output_files: BTreeMap::new(),
            allowed_output_directories: BTreeMap::new(),
        };
        let reserve = ProcessorRecoveryReserve::allocate(&root, 1024 * 1024).unwrap();
        monitor.audit().unwrap();

        fs::write(root.join("rogue.bin"), b"rogue").unwrap();
        assert!(monitor.audit().is_err());
        fs::remove_file(root.join("rogue.bin")).unwrap();

        fs::write(root.join("state/rogue.bin"), b"rogue").unwrap();
        assert!(monitor.audit().is_err());
        fs::remove_file(root.join("state/rogue.bin")).unwrap();

        fs::write(root.join("inputs/extra.bin"), b"extra").unwrap();
        assert!(monitor.audit().is_err());
        fs::remove_file(root.join("inputs/extra.bin")).unwrap();

        let read_only = root.join("temp/read-only.bin");
        fs::write(&read_only, b"read-only").unwrap();
        let mut permissions = fs::metadata(&read_only).unwrap().permissions();
        permissions.set_readonly(true);
        fs::set_permissions(&read_only, permissions).unwrap();
        assert!(monitor.audit().is_err());
        let mut permissions = fs::metadata(&read_only).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&read_only, permissions).unwrap();
        fs::remove_file(read_only).unwrap();
        monitor.audit().unwrap();

        fs::remove_file(root.join("inputs/pinned.bin")).unwrap();
        fs::write(root.join("inputs/pinned.bin"), b"forged").unwrap();
        assert!(monitor.audit().is_err());
        reserve.release().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn live_workspace_monitor_enforces_exact_output_paths_casing_and_per_file_size() {
        let root = live_monitor_root("live-monitor-exact-outputs");
        fs::create_dir(root.join("outputs/libraries")).unwrap();
        let input_inventory = audit_live_workspace_inventory(
            &root.join("inputs"),
            "processor inputs",
            WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024,
            },
        )
        .unwrap();
        let monitor = ProcessorWorkspaceMonitor {
            root: root.clone(),
            inputs: root.join("inputs"),
            temp: root.join("temp"),
            home: root.join("state/user-home"),
            outputs: root.join("outputs"),
            input_inventory,
            scratch_limit: WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024,
            },
            output_limit: WorkspaceTreeLimit {
                max_entries: 16,
                max_bytes: 1024,
            },
            allowed_output_files: canonical_output_files(&BTreeMap::from([(
                "libraries/client.jar".to_owned(),
                4,
            )]))
            .unwrap(),
            allowed_output_directories: canonical_output_directories(&BTreeSet::from([
                "libraries".to_owned(),
            ]))
            .unwrap(),
        };
        let reserve = ProcessorRecoveryReserve::allocate(&root, 1024 * 1024).unwrap();
        let expected = root.join("outputs/libraries/client.jar");
        fs::write(&expected, b"1234").unwrap();
        monitor.audit().unwrap();

        fs::write(&expected, b"12345").unwrap();
        assert!(monitor.audit().is_err());
        fs::write(&expected, b"1234").unwrap();
        fs::write(root.join("outputs/libraries/rogue.jar"), b"x").unwrap();
        assert!(monitor.audit().is_err());
        fs::remove_file(root.join("outputs/libraries/rogue.jar")).unwrap();

        fs::remove_file(&expected).unwrap();
        fs::write(root.join("outputs/libraries/Client.jar"), b"1234").unwrap();
        assert!(monitor.audit().is_err());
        reserve.release().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn live_workspace_monitor_rejects_named_streams_on_files_and_directories() {
        let root = live_monitor_root("live-monitor-ads");
        let monitor = empty_live_monitor(&root, 1024);
        let reserve = ProcessorRecoveryReserve::allocate(&root, 1024 * 1024).unwrap();

        let base = root.join("temp/payload.bin");
        fs::write(&base, b"base").unwrap();
        let file_stream = PathBuf::from(format!("{}:quota-bypass", base.display()));
        fs::write(&file_stream, vec![b'x'; 4096]).unwrap();
        assert!(monitor.audit().is_err());
        fs::remove_file(&file_stream).unwrap();
        fs::remove_file(&base).unwrap();

        let directory_stream =
            PathBuf::from(format!("{}:quota-bypass", root.join("temp").display()));
        fs::write(&directory_stream, vec![b'x'; 4096]).unwrap();
        assert!(monitor.audit().is_err());
        fs::remove_file(directory_stream).unwrap();
        monitor.audit().unwrap();

        let marker_stream = PathBuf::from(format!(
            "{}:quota-bypass",
            root.join("state").join(STATE_MARKER_PATH).display()
        ));
        fs::write(&marker_stream, vec![b'x'; 4096]).unwrap();
        assert!(monitor.audit().is_err());
        fs::remove_file(marker_stream).unwrap();

        let root_stream = PathBuf::from(format!("{}:quota-bypass", root.display()));
        fs::write(&root_stream, vec![b'x'; 4096]).unwrap();
        assert!(monitor.audit().is_err());
        fs::remove_file(root_stream).unwrap();

        let reserve_stream = PathBuf::from(format!(
            "{}:quota-bypass",
            root.join(RECOVERY_RESERVE_PATH).display()
        ));
        fs::write(&reserve_stream, vec![b'x'; 4096]).unwrap();
        assert!(reserve.revalidate().is_err());
        fs::remove_file(reserve_stream).unwrap();
        reserve.revalidate().unwrap();
        monitor.audit().unwrap();

        reserve.release().unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn reserve_release_fails_closed_when_a_late_hardlink_preserves_allocation() {
        let root = live_monitor_root("reserve-hardlink-release");
        let reserve = ProcessorRecoveryReserve::allocate(&root, 1024 * 1024).unwrap();
        let reserve_path = root.join(RECOVERY_RESERVE_PATH);
        let alias = root.join("temp/reserve-alias.bin");
        fs::hard_link(&reserve_path, &alias).unwrap();

        let error = reserve.release().unwrap_err();
        assert!(error.contains("changed"), "unexpected error: {error}");
        assert!(reserve_path.exists());
        assert!(alias.exists());

        fs::remove_file(alias).unwrap();
        fs::remove_file(reserve_path).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn process_runner_terminates_a_timed_out_child() {
        let executable = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let arguments = child_arguments();
        let environment = vec![(OsString::from(CHILD_MODE_ENV), OsString::from("sleep"))];
        let result = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &cwd,
            environment: &environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_millis(100),
                max_stream_bytes: 1024 * 1024,
                max_diagnostic_bytes: 1024,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        assert!(result.unwrap_err().contains("timed out"));
    }

    #[test]
    fn process_runner_terminates_a_child_that_exceeds_the_stream_bound() {
        let executable = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let arguments = child_arguments();
        let environment = vec![(OsString::from(CHILD_MODE_ENV), OsString::from("flood"))];
        let result = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &cwd,
            environment: &environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(10),
                max_stream_bytes: 1024,
                max_diagnostic_bytes: 128,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        });
        assert!(result.unwrap_err().contains("exceeded the byte limit"));
    }

    #[test]
    fn process_runner_terminates_a_running_child_when_cancelled() {
        let executable = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let arguments = child_arguments();
        let environment = vec![(OsString::from(CHILD_MODE_ENV), OsString::from("sleep"))];
        let cancelled = Arc::new(AtomicBool::new(false));
        let cancellation = Arc::clone(&cancelled);
        let trigger = thread::spawn(move || {
            thread::sleep(Duration::from_millis(100));
            cancellation.store(true, Ordering::Release);
        });
        let request = JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &cwd,
            environment: &environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(10),
                max_stream_bytes: 1024 * 1024,
                max_diagnostic_bytes: 1024,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled,
        };
        validate_process_request_before_spawn(&request).unwrap();
        let result = run_java_process_validated(request);
        trigger.join().unwrap();
        assert!(matches!(result, Err(JavaProcessError::Cancelled)));
    }

    #[cfg(windows)]
    #[test]
    fn process_runner_terminates_descendants_that_inherit_its_pipes() {
        let executable = std::env::current_exe().unwrap();
        let cwd = std::env::current_dir().unwrap();
        let arguments = child_arguments();
        let environment = vec![(
            OsString::from(CHILD_MODE_ENV),
            OsString::from("descendant-parent"),
        )];
        let started = Instant::now();
        let output = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &cwd,
            environment: &environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(10),
                max_stream_bytes: 1024 * 1024,
                max_diagnostic_bytes: 1024,
            },
            workspace_monitor: None,
            recovery_reserve: None,
            cancelled: Arc::new(AtomicBool::new(false)),
        })
        .unwrap();
        assert_eq!(output.exit_code, 0);
        assert!(started.elapsed() < Duration::from_secs(8));
    }

    #[test]
    fn child_process_fixture() {
        match std::env::var(CHILD_MODE_ENV).ok().as_deref() {
            Some("sleep") => thread::sleep(Duration::from_secs(30)),
            Some("environment-cleared") => {
                #[cfg(windows)]
                assert!(std::env::var_os("SystemRoot").is_none());
                #[cfg(not(windows))]
                assert!(std::env::var_os("PATH").is_none());
            }
            Some("nonzero") => panic!("intentional child failure"),
            #[cfg(windows)]
            Some("descendant-parent") => {
                spawn_descendant_that_must_be_reaped_by_the_job();
            }
            Some("descendant-sleep") => thread::sleep(Duration::from_secs(30)),
            Some("flood") => {
                let mut stdout = std::io::stdout().lock();
                let chunk = vec![b'x'; 64 * 1024];
                for _ in 0..4 {
                    stdout.write_all(&chunk).unwrap();
                    stdout.flush().unwrap();
                }
            }
            Some("scratch-flood") => {
                let path = PathBuf::from(std::env::var_os(CHILD_SCRATCH_ENV).unwrap());
                let mut file = fs::File::create(path).unwrap();
                let chunk = vec![b'x'; 64 * 1024];
                loop {
                    file.write_all(&chunk).unwrap();
                    file.flush().unwrap();
                    thread::sleep(Duration::from_millis(1));
                }
            }
            Some("workspace-write") => {
                let path = PathBuf::from(std::env::var_os(CHILD_SCRATCH_ENV).unwrap());
                fs::write(path, b"rogue").unwrap();
                thread::sleep(Duration::from_secs(30));
            }
            _ => {}
        }
    }
}
