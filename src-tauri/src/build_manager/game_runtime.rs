use super::{
    contracts::{
        domain_digest, GameRuntimeLock, GameRuntimeSource, NormalizedProcessorArgument,
        RuntimeLock, UpstreamProcessorStep,
    },
    game_runtime_invocation::PreparedProcessorInvocation,
    managed_fs::{GuardedDirectoryChain, ImmutableManagedFile, RelativeManagedPath},
    process_supervisor::{spawn as spawn_process, ProcessSpec},
    runtime::{revalidate_runtime_installation, RuntimeInstallation},
    storage::is_windows_reparse_point,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    ffi::OsString,
    fs,
    io::Read,
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
}

#[derive(Debug, Clone)]
pub(super) struct JavaProcessLimits {
    pub(super) timeout: Duration,
    pub(super) max_stream_bytes: u64,
    pub(super) max_diagnostic_bytes: usize,
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

struct JavaProcessRequest<'a> {
    executable: &'a Path,
    arguments: &'a [OsString],
    cwd: &'a Path,
    environment: &'a [(OsString, OsString)],
    limits: JavaProcessLimits,
    cancelled: Arc<AtomicBool>,
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
    limits: JavaProcessLimits,
    cancelled: Arc<AtomicBool>,
) -> Result<JavaProcessOutput, String> {
    let verified = revalidate_runtime_installation(runtime, runtime_lock)?;
    if invocation.executable() != verified.java_console() {
        return Err("Prepared processor executable is not the revalidated Java console".into());
    }
    run_java_process(JavaProcessRequest {
        executable: invocation.executable(),
        arguments: invocation.arguments(),
        cwd: invocation.cwd(),
        environment: invocation.environment(),
        limits,
        cancelled,
    })
}

fn run_java_process(request: JavaProcessRequest<'_>) -> Result<JavaProcessOutput, String> {
    validate_process_request(&request)?;
    if request.cancelled.load(Ordering::Acquire) {
        return Err("NeoForge processor execution was cancelled".into());
    }
    let (mut child, pipes) = spawn_process(ProcessSpec {
        executable: request.executable,
        arguments: request.arguments,
        cwd: request.cwd,
        environment: request.environment,
    })?;
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
    let mut terminal_error = None;
    let mut status = None;
    loop {
        if request.cancelled.load(Ordering::Acquire) {
            terminal_error = Some("NeoForge processor execution was cancelled".to_string());
        } else if started.elapsed() > request.limits.timeout {
            terminal_error = Some("NeoForge processor execution timed out".to_string());
        } else if let Ok(error) = failure_rx.try_recv() {
            terminal_error = Some(error);
        }
        if terminal_error.is_some() {
            break;
        }
        match child.try_wait() {
            Ok(Some(exit)) => {
                status = Some(exit);
                break;
            }
            Ok(None) => {}
            Err(error) => {
                terminal_error = Some(format!("Cannot poll NeoForge processor: {error}"));
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
    if let Some(error) = terminal_error {
        let error = append_cleanup_error(error, cleanup.err());
        let error = append_cleanup_error(error, stdout.as_ref().err().cloned());
        return Err(append_cleanup_error(error, stderr.as_ref().err().cloned()));
    }
    cleanup?;
    let stdout = stdout?;
    let stderr = stderr?;
    let exit_code = status.ok_or_else(|| "NeoForge processor status is missing".to_string())?;
    let transcript_sha256 = transcript_digest(&stdout, &stderr)?;
    Ok(JavaProcessOutput {
        exit_code,
        stdout,
        stderr,
        transcript_sha256,
    })
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
        drop(
            Command::new(std::env::current_exe().unwrap())
                .args(child_arguments())
                .env(CHILD_MODE_ENV, "descendant-sleep")
                .stdin(Stdio::null())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .creation_flags(CREATE_NO_WINDOW)
                .spawn()
                .unwrap(),
        );
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
            cancelled: Arc::new(AtomicBool::new(true)),
        });
        assert!(result.unwrap_err().contains("cancelled"));
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
        let result = run_java_process(JavaProcessRequest {
            executable: &executable,
            arguments: &arguments,
            cwd: &cwd,
            environment: &environment,
            limits: JavaProcessLimits {
                timeout: Duration::from_secs(10),
                max_stream_bytes: 1024 * 1024,
                max_diagnostic_bytes: 1024,
            },
            cancelled,
        });
        trigger.join().unwrap();
        assert!(result.unwrap_err().contains("cancelled"));
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
            _ => {}
        }
    }
}
