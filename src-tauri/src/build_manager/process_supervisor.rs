use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    ffi::OsString,
    fmt,
    io::Read,
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};

#[cfg(windows)]
use std::{
    ffi::c_void,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    sync::{mpsc, Barrier, Mutex},
};
#[cfg(windows)]
use windows::Win32::{
    Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE},
    System::{Threading::GetCurrentProcess, IO::CancelSynchronousIo},
};

const CLEANUP_POLL: Duration = Duration::from_millis(10);
const PROCESS_STREAM_BUFFER_BYTES: usize = 16 * 1024;
const MAX_PROCESS_TAIL_BYTES: usize = 1024 * 1024;
const DEFAULT_PROCESS_DRAIN_FINISH_TIMEOUT: Duration = Duration::from_secs(5);

#[cfg(windows)]
static PROCESS_HANDLE_INHERITANCE_LOCK: Mutex<()> = Mutex::new(());

#[cfg(windows)]
fn process_handle_inheritance_guard() -> Result<std::sync::MutexGuard<'static, ()>, ()> {
    PROCESS_HANDLE_INHERITANCE_LOCK.lock().map_err(|_| ())
}

/// Creates a `std::process::Command` child under the launcher's Windows inheritance lock.
///
/// Every production `Command` path that can request inherited stdio must use this function for the
/// single `spawn` call. Waiting or draining the child happens after this function returns and must
/// never hold the lock.
#[cfg(windows)]
pub(crate) fn spawn_command_with_inheritance_lock(
    command: &mut std::process::Command,
) -> std::io::Result<std::process::Child> {
    let _guard = process_handle_inheritance_guard()
        .map_err(|_| std::io::Error::other("process handle inheritance lock is unavailable"))?;
    command.spawn()
}

#[cfg(not(windows))]
pub(crate) fn spawn_command_with_inheritance_lock(
    command: &mut std::process::Command,
) -> std::io::Result<std::process::Child> {
    command.spawn()
}

pub(super) struct ProcessSpec<'a> {
    pub(super) executable: &'a Path,
    pub(super) arguments: &'a [OsString],
    pub(super) cwd: &'a Path,
    pub(super) environment: &'a [(OsString, OsString)],
}

pub(super) struct ProcessPipes {
    // Production instances come from `spawn`; on Windows these are cancellable anonymous-pipe
    // Files, which the continuous drain lifecycle relies on. The fields remain visible to the
    // bounded NeoForge processor runner, which has its own capture lifecycle.
    pub(super) stdout: Box<dyn Read + Send>,
    pub(super) stderr: Box<dyn Read + Send>,
}

/// Bounded diagnostic evidence for one completely drained process stream.
///
/// The tail is deliberately omitted from `Debug`: Java output may contain a launch ticket or
/// another credential. Callers must opt in to reading the raw bytes and apply their own redaction
/// before showing them to a user or writing them to a log.
#[allow(dead_code)] // Consumed by the upcoming long-running Minecraft process owner.
#[derive(PartialEq, Eq)]
pub(super) struct BoundedStreamCapture {
    total_bytes: u64,
    sha256: String,
    tail: Vec<u8>,
}

#[allow(dead_code)] // Consumed by the upcoming long-running Minecraft process owner.
impl BoundedStreamCapture {
    pub(super) fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    pub(super) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(super) fn tail(&self) -> &[u8] {
        &self.tail
    }
}

impl fmt::Debug for BoundedStreamCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedStreamCapture")
            .field("total_bytes", &self.total_bytes)
            .field("sha256", &self.sha256)
            .field("tail_bytes", &self.tail.len())
            .finish()
    }
}

#[allow(dead_code)] // Consumed by the upcoming long-running Minecraft process owner.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct BoundedProcessCapture {
    stdout: BoundedStreamCapture,
    stderr: BoundedStreamCapture,
}

#[allow(dead_code)] // Consumed by the upcoming long-running Minecraft process owner.
impl BoundedProcessCapture {
    pub(super) fn stdout(&self) -> &BoundedStreamCapture {
        &self.stdout
    }

    pub(super) fn stderr(&self) -> &BoundedStreamCapture {
        &self.stderr
    }
}

/// Owns two concurrent readers so a verbose long-running child cannot block on either pipe.
/// `finish` must be called after the contained process job is empty to collect the final bounded
/// evidence. A deadline cancels pending Windows pipe reads, so an accidentally inherited writer
/// cannot hold the launcher forever. Dropping the owner cancels and joins both readers and never
/// prints captured bytes.
#[allow(dead_code)] // Consumed by the upcoming long-running Minecraft process owner.
#[must_use = "the process pipes must remain drained until the contained process exits"]
#[cfg(windows)]
pub(super) struct ContinuousPipeDrain {
    worker: Option<JoinHandle<Result<BoundedProcessCapture, String>>>,
    cancelled: Arc<AtomicBool>,
    #[cfg(windows)]
    inner_thread: Arc<Mutex<Option<OwnedHandle>>>,
}

#[allow(dead_code)] // Consumed by the upcoming long-running Minecraft process owner.
#[cfg(windows)]
impl ContinuousPipeDrain {
    pub(super) fn finish(self) -> Result<BoundedProcessCapture, String> {
        self.finish_with_timeout(DEFAULT_PROCESS_DRAIN_FINISH_TIMEOUT)
    }

    pub(super) fn finish_with_timeout(
        mut self,
        timeout: Duration,
    ) -> Result<BoundedProcessCapture, String> {
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            self.cancel_until_stopped();
            let _ = self.join_worker();
            return Err("Contained process drain deadline overflowed".into());
        };
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
            && Instant::now() < deadline
        {
            std::thread::sleep(
                CLEANUP_POLL.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        let timed_out = self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished());
        if timed_out {
            self.cancel_until_stopped();
        }
        let result = self.join_worker();
        if timed_out {
            Err("Contained process output did not reach EOF before the drain deadline".into())
        } else {
            result
        }
    }

    fn request_cancel_once(&self) {
        self.cancelled.store(true, Ordering::Release);
        if let Some(worker) = self.worker.as_ref() {
            cancel_synchronous_thread_io(worker.as_raw_handle() as usize);
        }
        let inner = self
            .inner_thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(thread) = inner.as_ref() {
            cancel_synchronous_thread_io(thread.as_raw_handle() as usize);
        }
    }

    fn cancel_until_stopped(&self) {
        self.cancelled.store(true, Ordering::Release);
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            // A reader can observe `false` immediately before cancellation and enter ReadFile
            // immediately after an ERROR_NOT_FOUND result. Reissue cancellation until the worker
            // acknowledges it by terminating; this closes that lost-cancel window.
            self.request_cancel_once();
            std::thread::sleep(CLEANUP_POLL);
        }
    }

    fn join_worker(&mut self) -> Result<BoundedProcessCapture, String> {
        let Some(worker) = self.worker.take() else {
            return Err("Contained process output drain was already consumed".into());
        };
        worker
            .join()
            .map_err(|_| "Contained process output drain terminated unexpectedly".to_string())?
    }
}

#[cfg(windows)]
impl Drop for ContinuousPipeDrain {
    fn drop(&mut self) {
        if self.worker.is_none() {
            return;
        }
        self.cancel_until_stopped();
        // Production instances exist only for Windows anonymous-pipe Files. Repeated
        // CancelSynchronousIo closes the between-check-and-read race before this bounded join.
        // Joining deliberately avoids silently detaching credential-bearing reader threads.
        let _ = self.join_worker();
    }
}

#[allow(dead_code)]
#[cfg(not(windows))]
pub(super) struct ContinuousPipeDrain;

#[allow(dead_code)]
#[cfg(not(windows))]
impl ContinuousPipeDrain {
    pub(super) fn finish(self) -> Result<BoundedProcessCapture, String> {
        Err("Continuous process output drain is unsupported on this platform".into())
    }

    pub(super) fn finish_with_timeout(
        self,
        _timeout: Duration,
    ) -> Result<BoundedProcessCapture, String> {
        self.finish()
    }
}

#[allow(dead_code)] // Consumed by the upcoming long-running Minecraft process owner.
impl ProcessPipes {
    pub(super) fn drain_bounded(self, tail_capacity: usize) -> Result<ContinuousPipeDrain, String> {
        if tail_capacity > MAX_PROCESS_TAIL_BYTES {
            return Err("Contained process tail capacity exceeds the launcher limit".into());
        }
        #[cfg(not(windows))]
        {
            // std::io::Read offers no portable way to interrupt a blocked anonymous-pipe read.
            // Fail before starting threads instead of exposing a Drop/timeout path that can hang.
            drop(self);
            return Err("Continuous process output drain is unsupported on this platform".into());
        }
        #[cfg(windows)]
        {
            self.start_windows_drain(tail_capacity)
        }
    }

    #[cfg(windows)]
    fn start_windows_drain(self, tail_capacity: usize) -> Result<ContinuousPipeDrain, String> {
        self.start_windows_drain_with_fault(tail_capacity, DrainStartupFault::None)
    }

    #[cfg(windows)]
    fn start_windows_drain_with_fault(
        self,
        tail_capacity: usize,
        fault: DrainStartupFault,
    ) -> Result<ContinuousPipeDrain, String> {
        #[cfg(not(test))]
        let _ = fault;
        let Self { stdout, stderr } = self;
        #[cfg(test)]
        if fault == DrainStartupFault::OuterSpawn {
            return Err("Synthetic outer drain startup failure".into());
        }

        let cancelled = Arc::new(AtomicBool::new(false));
        let inner_thread = Arc::new(Mutex::new(None));
        let worker_cancelled = Arc::clone(&cancelled);
        let worker_inner_thread = Arc::clone(&inner_thread);
        let (startup_tx, startup_rx) = mpsc::channel::<Result<(), String>>();
        let worker = std::thread::Builder::new()
            .name("fragment-process-drain".into())
            .spawn(move || {
                let stderr_cancelled = Arc::clone(&worker_cancelled);
                let stderr_start = Arc::new(Barrier::new(2));
                let stderr_worker_start = Arc::clone(&stderr_start);
                #[cfg(test)]
                if fault == DrainStartupFault::StderrSpawn {
                    let error = "Synthetic stderr drain startup failure".to_string();
                    let _ = startup_tx.send(Err(error.clone()));
                    return Err(error);
                }
                let stderr_worker = std::thread::Builder::new()
                    .name("fragment-process-stderr".into())
                    .spawn(move || {
                        stderr_worker_start.wait();
                        drain_stream(stderr, tail_capacity, &stderr_cancelled)
                    });
                let stderr_worker = match stderr_worker {
                    Ok(worker) => worker,
                    Err(_) => {
                        let error = "Cannot start contained process stderr drain".to_string();
                        let _ = startup_tx.send(Err(error.clone()));
                        return Err(error);
                    }
                };
                let mut stderr_worker = PendingStreamDrain::new(
                    stderr_worker,
                    stderr_start,
                    Arc::clone(&worker_cancelled),
                    Arc::clone(&worker_inner_thread),
                );
                #[cfg(test)]
                if fault == DrainStartupFault::DisconnectAfterStderrSpawn {
                    drop(startup_tx);
                    return Err("Synthetic drain startup acknowledgement disconnect".into());
                }

                #[cfg(test)]
                let duplicate = if fault == DrainStartupFault::DuplicateCancelHandle {
                    Err("Synthetic drain thread handle duplication failure".into())
                } else {
                    duplicate_thread_handle(stderr_worker.worker())
                };
                #[cfg(not(test))]
                let duplicate = duplicate_thread_handle(stderr_worker.worker());
                let duplicate = match duplicate {
                    Ok(handle) => handle,
                    Err(error) => {
                        drop(stderr_worker);
                        let _ = startup_tx.send(Err(error.clone()));
                        return Err(error);
                    }
                };
                stderr_worker.publish_cancel_handle(duplicate);
                // The stderr worker cannot enter ReadFile until its duplicated cancellation handle
                // has been published. This removes the registration race from timeout and Drop.
                stderr_worker.release_start();
                if startup_tx.send(Ok(())).is_err() {
                    return Err(
                        "Contained process drain startup acknowledgement was abandoned".into(),
                    );
                }
                let stdout = drain_stream(stdout, tail_capacity, &worker_cancelled)
                    .map_err(|error| format!("Contained process stdout drain failed: {error}"));
                let stderr = stderr_worker.join("stderr");
                combine_stream_captures(stdout, stderr)
            })
            .map_err(|_| "Cannot start contained process output drain".to_string())?;

        match startup_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                let _ = worker.join();
                return Err(error);
            }
            Err(_) => {
                return match worker.join() {
                    Ok(Err(error)) => Err(error),
                    Ok(Ok(_)) => Err(
                        "Contained process output drain ended before startup acknowledgement"
                            .into(),
                    ),
                    Err(_) => {
                        Err("Contained process output drain terminated during startup".into())
                    }
                };
            }
        }
        Ok(ContinuousPipeDrain {
            worker: Some(worker),
            cancelled,
            inner_thread,
        })
    }
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DrainStartupFault {
    None,
    #[cfg(test)]
    OuterSpawn,
    #[cfg(test)]
    StderrSpawn,
    #[cfg(test)]
    DuplicateCancelHandle,
    #[cfg(test)]
    DisconnectAfterStderrSpawn,
}

/// Unwind-safe owner for the nested stderr reader while the outer drain is being initialized.
///
/// In particular, dropping the final `Barrier` peer does not release a waiting thread. This guard
/// therefore opens the gate itself before repeatedly cancelling and joining the reader. The
/// duplicated handle stays published until a normal join completes so `ContinuousPipeDrain` can
/// cancel both reads after a deadline.
#[cfg(windows)]
struct PendingStreamDrain {
    worker: Option<JoinHandle<Result<BoundedStreamCapture, String>>>,
    start: Arc<Barrier>,
    start_released: bool,
    cancelled: Arc<AtomicBool>,
    published_handle: Arc<Mutex<Option<OwnedHandle>>>,
}

#[cfg(windows)]
impl PendingStreamDrain {
    fn new(
        worker: JoinHandle<Result<BoundedStreamCapture, String>>,
        start: Arc<Barrier>,
        cancelled: Arc<AtomicBool>,
        published_handle: Arc<Mutex<Option<OwnedHandle>>>,
    ) -> Self {
        Self {
            worker: Some(worker),
            start,
            start_released: false,
            cancelled,
            published_handle,
        }
    }

    fn worker(&self) -> &JoinHandle<Result<BoundedStreamCapture, String>> {
        self.worker
            .as_ref()
            .expect("a pending stream drain owns its worker")
    }

    fn publish_cancel_handle(&self, handle: OwnedHandle) {
        *self
            .published_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle);
    }

    fn release_start(&mut self) {
        if self.start_released {
            return;
        }
        self.start_released = true;
        self.start.wait();
    }

    fn clear_published_handle(&self) {
        *self
            .published_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
    }

    fn join(mut self, stream: &str) -> Result<BoundedStreamCapture, String> {
        let worker = self
            .worker
            .take()
            .expect("a pending stream drain owns its worker");
        let result = join_stream_drain(worker, stream);
        self.clear_published_handle();
        result
    }

    fn cancel_and_join(&mut self) {
        if self.worker.is_none() {
            self.clear_published_handle();
            return;
        }
        self.cancelled.store(true, Ordering::Release);
        self.release_start();
        while self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            let raw_thread = self
                .worker
                .as_ref()
                .expect("a pending stream drain owns its worker")
                .as_raw_handle() as usize;
            cancel_synchronous_thread_io(raw_thread);
            std::thread::sleep(CLEANUP_POLL);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.clear_published_handle();
    }
}

#[cfg(windows)]
impl Drop for PendingStreamDrain {
    fn drop(&mut self) {
        self.cancel_and_join();
    }
}

#[cfg(windows)]
fn combine_stream_captures(
    stdout: Result<BoundedStreamCapture, String>,
    stderr: Result<BoundedStreamCapture, String>,
) -> Result<BoundedProcessCapture, String> {
    match (stdout, stderr) {
        (Ok(stdout), Ok(stderr)) => Ok(BoundedProcessCapture { stdout, stderr }),
        (Err(stdout), Ok(_)) => Err(stdout),
        (Ok(_), Err(stderr)) => Err(stderr),
        (Err(stdout), Err(stderr)) => Err(format!("{stdout}; {stderr}")),
    }
}

#[cfg(windows)]
fn cancel_synchronous_thread_io(raw_thread: usize) {
    if raw_thread == 0 {
        return;
    }
    // ERROR_NOT_FOUND only means the thread was between synchronous reads. The cancellation flag
    // is checked before the next read, so no error needs to escape or disclose stream contents.
    let _ = unsafe { CancelSynchronousIo(HANDLE(raw_thread as *mut c_void)) };
}

#[cfg(windows)]
fn duplicate_thread_handle<T>(thread: &JoinHandle<T>) -> Result<OwnedHandle, String> {
    let process = unsafe { GetCurrentProcess() };
    let mut duplicate = HANDLE::default();
    unsafe {
        DuplicateHandle(
            process,
            HANDLE(thread.as_raw_handle()),
            process,
            &mut duplicate,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    }
    .map_err(|_| "Cannot duplicate contained process drain thread handle".to_string())?;
    if duplicate.is_invalid() {
        return Err("Windows returned an invalid process drain thread handle".into());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(duplicate.0) })
}

#[cfg(windows)]
fn join_stream_drain(
    drain: JoinHandle<Result<BoundedStreamCapture, String>>,
    stream: &str,
) -> Result<BoundedStreamCapture, String> {
    drain
        .join()
        .map_err(|_| format!("Contained process {stream} drain terminated unexpectedly"))?
        .map_err(|error| format!("Contained process {stream} drain failed: {error}"))
}

#[cfg(windows)]
fn drain_stream(
    mut reader: Box<dyn Read + Send>,
    tail_capacity: usize,
    cancelled: &AtomicBool,
) -> Result<BoundedStreamCapture, String> {
    let mut buffer = [0_u8; PROCESS_STREAM_BUFFER_BYTES];
    let mut tail = VecDeque::with_capacity(tail_capacity);
    let mut hasher = Sha256::new();
    let mut total_bytes = 0_u64;
    let mut count_overflowed = false;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Err("Contained process output drain was cancelled".into());
        }
        let read = reader
            .read(&mut buffer)
            .map_err(|_| "Cannot drain contained process output".to_string())?;
        if cancelled.load(Ordering::Acquire) {
            return Err("Contained process output drain was cancelled".into());
        }
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        match total_bytes.checked_add(read as u64) {
            Some(total) => total_bytes = total,
            None => {
                // Continue draining to EOF so a theoretical counter overflow cannot deadlock the
                // child. The result fails closed after the pipe has been emptied.
                total_bytes = u64::MAX;
                count_overflowed = true;
            }
        }
        if tail_capacity != 0 {
            for byte in &buffer[..read] {
                if tail.len() == tail_capacity {
                    tail.pop_front();
                }
                tail.push_back(*byte);
            }
        }
    }
    if count_overflowed {
        return Err("Contained process output byte count overflowed".into());
    }
    Ok(BoundedStreamCapture {
        total_bytes,
        sha256: format!("{:x}", hasher.finalize()),
        tail: tail.into_iter().collect(),
    })
}

#[cfg(all(test, windows))]
mod capture_tests {
    use super::*;
    use std::io::Cursor;

    fn sha256(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    #[test]
    fn continuous_drain_counts_hashes_and_retains_only_the_bounded_tail() {
        let stdout = b"0123456789abcdef";
        let stderr = b"launch-ticket-secret";
        let capture = ProcessPipes {
            stdout: Box::new(Cursor::new(stdout.to_vec())),
            stderr: Box::new(Cursor::new(stderr.to_vec())),
        }
        .drain_bounded(8)
        .unwrap()
        .finish()
        .unwrap();

        assert_eq!(capture.stdout().total_bytes(), stdout.len() as u64);
        assert_eq!(capture.stdout().sha256(), sha256(stdout));
        assert_eq!(capture.stdout().tail(), b"89abcdef");
        assert_eq!(capture.stderr().total_bytes(), stderr.len() as u64);
        assert_eq!(capture.stderr().sha256(), sha256(stderr));
        assert_eq!(capture.stderr().tail(), b"t-secret");

        let diagnostic = format!("{capture:?}");
        assert!(!diagnostic.contains("launch-ticket"));
        assert!(!diagnostic.contains("t-secret"));
        assert!(diagnostic.contains("tail_bytes: 8"));
    }

    #[test]
    fn continuous_drain_allows_no_tail_and_rejects_unbounded_capture() {
        let capture = ProcessPipes {
            stdout: Box::new(Cursor::new(b"stdout".to_vec())),
            stderr: Box::new(Cursor::new(b"stderr".to_vec())),
        }
        .drain_bounded(0)
        .unwrap()
        .finish()
        .unwrap();
        assert!(capture.stdout().tail().is_empty());
        assert!(capture.stderr().tail().is_empty());

        let error = ProcessPipes {
            stdout: Box::new(Cursor::new(Vec::<u8>::new())),
            stderr: Box::new(Cursor::new(Vec::<u8>::new())),
        }
        .drain_bounded(MAX_PROCESS_TAIL_BYTES + 1)
        .err()
        .expect("oversized capture must fail");
        assert_eq!(
            error,
            "Contained process tail capacity exceeds the launcher limit"
        );
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::{
        ffi::{c_void, OsStr},
        fs::File,
        mem::{size_of, size_of_val},
        os::windows::{
            ffi::OsStrExt,
            io::{AsRawHandle, FromRawHandle, OwnedHandle},
        },
    };
    use windows::{
        core::{BOOL, PCWSTR, PWSTR},
        Win32::{
            Foundation::{
                SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
                WAIT_TIMEOUT,
            },
            Security::SECURITY_ATTRIBUTES,
            System::{
                JobObjects::{
                    CreateJobObjectW, IsProcessInJob, JobObjectBasicAccountingInformation,
                    JobObjectExtendedLimitInformation, QueryInformationJobObject,
                    SetInformationJobObject, TerminateJobObject,
                    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
                },
                Pipes::CreatePipe,
                Threading::{
                    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
                    GetProcessId, InitializeProcThreadAttributeList, ResumeThread,
                    TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
                    CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
                    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST,
                    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                    PROC_THREAD_ATTRIBUTE_JOB_LIST, STARTF_USESTDHANDLES, STARTUPINFOEXW,
                    STARTUPINFOW,
                },
            },
        },
    };

    struct Job {
        handle: OwnedHandle,
    }

    impl Job {
        fn new() -> Result<Self, String> {
            let raw = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
                .map_err(|error| format!("Cannot create contained process job: {error}"))?;
            let job = Self {
                handle: owned_handle(raw)?,
            };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            unsafe {
                SetInformationJobObject(
                    job.raw(),
                    JobObjectExtendedLimitInformation,
                    (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast::<c_void>(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            }
            .map_err(|error| format!("Cannot configure contained process job: {error}"))?;
            Ok(job)
        }

        fn raw(&self) -> HANDLE {
            raw_handle(&self.handle)
        }

        fn terminate(&self) -> Result<(), String> {
            unsafe { TerminateJobObject(self.raw(), 1) }
                .map_err(|error| format!("Cannot terminate contained process job: {error}"))
        }

        fn active_processes(&self) -> Result<u32, String> {
            let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
            unsafe {
                QueryInformationJobObject(
                    Some(self.raw()),
                    JobObjectBasicAccountingInformation,
                    (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)
                        .cast::<c_void>(),
                    size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                    None,
                )
            }
            .map_err(|error| format!("Cannot query contained process job state: {error}"))?;
            Ok(accounting.ActiveProcesses)
        }
    }

    struct AttributeList {
        _storage: Vec<usize>,
        raw: LPPROC_THREAD_ATTRIBUTE_LIST,
    }

    impl AttributeList {
        fn new(count: u32) -> Result<Self, String> {
            let mut bytes = 0_usize;
            let _ = unsafe { InitializeProcThreadAttributeList(None, count, None, &mut bytes) };
            if bytes == 0 {
                return Err("Windows did not report a process attribute-list size".into());
            }
            let words = bytes
                .checked_add(size_of::<usize>() - 1)
                .ok_or_else(|| "Process attribute-list size overflow".to_string())?
                / size_of::<usize>();
            let mut storage = vec![0_usize; words];
            let raw = LPPROC_THREAD_ATTRIBUTE_LIST(storage.as_mut_ptr().cast::<c_void>());
            unsafe { InitializeProcThreadAttributeList(Some(raw), count, None, &mut bytes) }
                .map_err(|error| format!("Cannot initialize process attributes: {error}"))?;
            Ok(Self {
                _storage: storage,
                raw,
            })
        }

        fn add_handles(&mut self, attribute: u32, handles: &[HANDLE]) -> Result<(), String> {
            unsafe {
                UpdateProcThreadAttribute(
                    self.raw,
                    0,
                    attribute as usize,
                    Some(handles.as_ptr().cast::<c_void>()),
                    size_of_val(handles),
                    None,
                    None,
                )
            }
            .map_err(|error| format!("Cannot set process creation attribute: {error}"))
        }
    }

    impl Drop for AttributeList {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.raw) };
        }
    }

    pub(crate) struct ContainedProcess {
        job: Job,
        process: OwnedHandle,
        pid: u32,
        exit_code: Option<i32>,
    }

    /// Non-cloneable proof of the exact suspended Java root and its mandatory Job. Both handles
    /// are duplicated without inheritance before the primary thread is resumed, so a later local
    /// IPC peer check cannot be defeated by PID reuse or by an unrelated process in the same user
    /// session.
    pub(crate) struct SuspendedProcessBinding {
        process: OwnedHandle,
        job: OwnedHandle,
        pid: u32,
    }

    impl fmt::Debug for SuspendedProcessBinding {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("SuspendedProcessBinding")
                .field("pid", &self.pid)
                .finish_non_exhaustive()
        }
    }

    impl SuspendedProcessBinding {
        pub(crate) const fn pid(&self) -> u32 {
            self.pid
        }

        /// Revalidates the exact retained process identity immediately before accepting or
        /// delivering a launch ticket. `Ok(false)` is an ordinary foreign/dead peer rejection;
        /// OS query failures remain fail-closed errors.
        pub(crate) fn validate_exact_client_pid(&self, client_pid: u32) -> Result<bool, String> {
            if client_pid != self.pid {
                return Ok(false);
            }
            let retained_pid = unsafe { GetProcessId(raw_handle(&self.process)) };
            if retained_pid == 0 {
                return Err("Cannot revalidate the retained Java process identity".into());
            }
            if retained_pid != self.pid {
                return Err("Retained Java process identity changed unexpectedly".into());
            }
            match unsafe { WaitForSingleObject(raw_handle(&self.process), 0) } {
                WAIT_TIMEOUT => {}
                WAIT_OBJECT_0 => return Ok(false),
                other => {
                    return Err(format!(
                        "Cannot poll the retained Java process identity: wait result {}",
                        other.0
                    ));
                }
            }
            let mut in_job = BOOL::from(false);
            unsafe {
                IsProcessInJob(
                    raw_handle(&self.process),
                    Some(raw_handle(&self.job)),
                    &mut in_job,
                )
            }
            .map_err(|_| "Cannot revalidate the retained Java Job identity".to_string())?;
            Ok(in_job.as_bool())
        }
    }

    struct SpawnGuard {
        job: Option<Job>,
        process: Option<OwnedHandle>,
        primary_thread: Option<OwnedHandle>,
        pid: u32,
        contained: bool,
    }

    impl SpawnGuard {
        fn process_raw(&self) -> HANDLE {
            raw_handle(
                self.process
                    .as_ref()
                    .expect("a live spawn guard always owns its process"),
            )
        }

        fn thread_raw(&self) -> HANDLE {
            raw_handle(
                self.primary_thread
                    .as_ref()
                    .expect("a live spawn guard always owns its primary thread"),
            )
        }

        fn into_child(mut self) -> ContainedProcess {
            drop(self.primary_thread.take());
            ContainedProcess {
                job: self
                    .job
                    .take()
                    .expect("a verified spawn guard owns its job"),
                process: self
                    .process
                    .take()
                    .expect("a verified spawn guard owns its process"),
                pid: self.pid,
                exit_code: None,
            }
        }
    }

    impl Drop for SpawnGuard {
        fn drop(&mut self) {
            let Some(process) = self.process.as_ref() else {
                return;
            };
            if self.contained {
                if let Some(job) = self.job.as_ref() {
                    let _ = job.terminate();
                }
            } else {
                let _ = unsafe { TerminateProcess(raw_handle(process), 1) };
            }
            let _ = unsafe { WaitForSingleObject(raw_handle(process), 5000) };
        }
    }

    impl ContainedProcess {
        pub(crate) fn pid(&self) -> u32 {
            self.pid
        }

        pub(crate) fn try_wait(&mut self) -> Result<Option<i32>, String> {
            if let Some(code) = self.exit_code {
                return Ok(Some(code));
            }
            match unsafe { WaitForSingleObject(raw_handle(&self.process), 0) } {
                WAIT_TIMEOUT => Ok(None),
                WAIT_OBJECT_0 => {
                    let mut code = 0_u32;
                    unsafe { GetExitCodeProcess(raw_handle(&self.process), &mut code) }.map_err(
                        |error| format!("Cannot read contained process exit code: {error}"),
                    )?;
                    let code = code as i32;
                    self.exit_code = Some(code);
                    Ok(Some(code))
                }
                other => Err(format!(
                    "Cannot poll contained process handle: wait result {}",
                    other.0
                )),
            }
        }

        pub(crate) fn terminate_and_reap(&mut self, timeout: Duration) -> Result<(), String> {
            let mut errors = Vec::new();
            if let Err(error) = self.job.terminate() {
                errors.push(error);
            }
            let deadline = Instant::now() + timeout;
            let mut root_reaped = false;
            let mut job_empty = false;
            loop {
                if !root_reaped {
                    match self.try_wait() {
                        Ok(Some(_)) => root_reaped = true,
                        Ok(None) => {}
                        Err(error) => {
                            errors.push(error);
                            root_reaped = true;
                        }
                    }
                }
                if !job_empty {
                    match self.job.active_processes() {
                        Ok(0) => job_empty = true,
                        Ok(_) => {}
                        Err(error) => {
                            // A query failure is not equivalent to ACTIVE_PROCESS_ZERO. Record it
                            // and stop polling this signal so cleanup cannot claim containment was
                            // drained successfully.
                            errors.push(error);
                            job_empty = true;
                        }
                    }
                }
                if root_reaped && job_empty {
                    break;
                }
                if Instant::now() >= deadline {
                    if !root_reaped {
                        errors.push(
                            "contained process root was not reaped before the cleanup deadline"
                                .into(),
                        );
                    }
                    if !job_empty {
                        errors.push(
                            "contained process job still had active processes at the cleanup deadline"
                                .into(),
                        );
                    }
                    break;
                }
                std::thread::sleep(CLEANUP_POLL);
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    impl Drop for ContainedProcess {
        fn drop(&mut self) {
            let _ = self.job.terminate();
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                match self.job.active_processes() {
                    Ok(0) => break,
                    Ok(_) if Instant::now() < deadline => std::thread::sleep(CLEANUP_POLL),
                    Ok(_) | Err(_) => break,
                }
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let wait_millis = remaining.as_millis().min(u32::MAX as u128) as u32;
            if wait_millis > 0 {
                let _ = unsafe { WaitForSingleObject(raw_handle(&self.process), wait_millis) };
            }
        }
    }

    pub(crate) fn spawn(spec: ProcessSpec<'_>) -> Result<(ContainedProcess, ProcessPipes), String> {
        spawn_with_before_resume(spec, || Ok(()))
    }

    /// Creates the process suspended, proves Job containment, then runs the caller's final
    /// synchronous authority check while the primary thread is still unable to execute.
    ///
    /// Any gate failure is handled by `SpawnGuard`: the suspended process (and, once proven, its
    /// complete Job) is terminated before this function returns the error. The gate must remain
    /// O(1), perform no network I/O, and return promptly because the process-wide inheritance
    /// lock is still held at this boundary.
    pub(crate) fn spawn_with_before_resume(
        spec: ProcessSpec<'_>,
        before_resume: impl FnOnce() -> Result<(), String>,
    ) -> Result<(ContainedProcess, ProcessPipes), String> {
        spawn_with_before_resume_identity(spec, |_| before_resume())
    }

    /// Variant used by the launch-ticket broker. The callback receives an owned, non-inheritable
    /// process/Job proof while Java is still suspended and may only move it into an already-created
    /// local broker. It must remain O(1), synchronous and network-free.
    pub(crate) fn spawn_with_before_resume_identity(
        spec: ProcessSpec<'_>,
        before_resume: impl FnOnce(SuspendedProcessBinding) -> Result<(), String>,
    ) -> Result<(ContainedProcess, ProcessPipes), String> {
        let inheritance_guard = process_handle_inheritance_guard()
            .map_err(|_| "Process handle inheritance lock is unavailable".to_string())?;
        spawn_while_inheritance_locked(spec, &inheritance_guard, before_resume)
    }

    fn spawn_while_inheritance_locked(
        spec: ProcessSpec<'_>,
        _inheritance_guard: &std::sync::MutexGuard<'static, ()>,
        before_resume: impl FnOnce(SuspendedProcessBinding) -> Result<(), String>,
    ) -> Result<(ContainedProcess, ProcessPipes), String> {
        let application = nul_terminated(spec.executable.as_os_str(), "process executable")?;
        let cwd = nul_terminated(spec.cwd.as_os_str(), "process cwd")?;
        let mut command_line = command_line(spec.executable.as_os_str(), spec.arguments)?;
        let environment = environment_block(spec.environment)?;

        let job = Job::new()?;
        let (stdout_read, stdout_write) = process_pipe(PipeEnd::Read)?;
        let (stderr_read, stderr_write) = process_pipe(PipeEnd::Read)?;
        let (stdin_write, stdin_read) = process_pipe(PipeEnd::Write)?;
        drop(stdin_write);

        let child_handles = [
            raw_handle(&stdin_read),
            raw_handle(&stdout_write),
            raw_handle(&stderr_write),
        ];
        let job_handles = [job.raw()];
        let mut info = PROCESS_INFORMATION::default();
        let flags = CREATE_SUSPENDED
            | CREATE_NO_WINDOW
            | CREATE_UNICODE_ENVIRONMENT
            | EXTENDED_STARTUPINFO_PRESENT;
        let result = (|| {
            // HANDLE_LIST validation requires every listed child handle to be inheritable at the
            // moment the attribute is installed. Both arming and attribute construction therefore
            // happen under the same process-wide spawn critical section.
            let _inheritance = InheritableHandleScope::new(&child_handles)?;
            let mut attributes = AttributeList::new(2)?;
            attributes.add_handles(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, &child_handles)?;
            attributes.add_handles(PROC_THREAD_ATTRIBUTE_JOB_LIST, &job_handles)?;

            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.StartupInfo.hStdInput = raw_handle(&stdin_read);
            startup.StartupInfo.hStdOutput = raw_handle(&stdout_write);
            startup.StartupInfo.hStdError = raw_handle(&stderr_write);
            startup.lpAttributeList = attributes.raw;
            unsafe {
                CreateProcessW(
                    PCWSTR(application.as_ptr()),
                    Some(PWSTR(command_line.as_mut_ptr())),
                    None,
                    None,
                    true,
                    flags,
                    Some(environment.as_ptr().cast::<c_void>()),
                    PCWSTR(cwd.as_ptr()),
                    (&startup as *const STARTUPINFOEXW).cast::<STARTUPINFOW>(),
                    &mut info,
                )
            }
            .map_err(|error| format!("Cannot create contained process: {error}"))
        })();
        // The inheritance scope above has reset the flags. Close every child end before unlocking;
        // closing also makes a rare reset failure non-observable to a later broad-inherit spawn.
        drop(stdin_read);
        drop(stdout_write);
        drop(stderr_write);
        result?;

        // A successful CreateProcessW contractually returns both handles. Arm cleanup immediately:
        // before containment is proven, only TerminateProcess can guarantee the suspended root is
        // stopped; after containment, the whole Job is authoritative.
        let mut guard = SpawnGuard {
            job: Some(job),
            process: Some(unsafe { OwnedHandle::from_raw_handle(info.hProcess.0) }),
            primary_thread: Some(unsafe { OwnedHandle::from_raw_handle(info.hThread.0) }),
            pid: info.dwProcessId,
            contained: false,
        };
        if guard.pid == 0 {
            return Err("Windows returned an invalid contained process ID".into());
        }
        let mut in_job = BOOL::from(false);
        unsafe {
            IsProcessInJob(
                guard.process_raw(),
                Some(guard.job.as_ref().expect("spawn guard owns its job").raw()),
                &mut in_job,
            )
        }
        .map_err(|error| format!("Cannot verify contained process job containment: {error}"))?;
        if !in_job.as_bool() {
            return Err("Contained process was created outside its mandatory job".into());
        }
        guard.contained = true;
        let binding = SuspendedProcessBinding {
            process: duplicate_owned_handle(guard.process_raw(), "Java process")?,
            job: duplicate_owned_handle(
                guard.job.as_ref().expect("spawn guard owns its job").raw(),
                "Java Job",
            )?,
            pid: guard.pid,
        };
        before_resume(binding)?;
        let previous = unsafe { ResumeThread(guard.thread_raw()) };
        if previous != 1 {
            return Err(format!(
                "Contained process primary thread resume count is invalid: {previous}"
            ));
        }
        let child = guard.into_child();

        Ok((
            child,
            ProcessPipes {
                stdout: Box::new(File::from(stdout_read)),
                stderr: Box::new(File::from(stderr_read)),
            },
        ))
    }

    fn duplicate_owned_handle(source: HANDLE, label: &str) -> Result<OwnedHandle, String> {
        let current = unsafe { GetCurrentProcess() };
        let mut duplicate = HANDLE::default();
        unsafe {
            DuplicateHandle(
                current,
                source,
                current,
                &mut duplicate,
                0,
                false,
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|_| format!("Cannot duplicate the contained {label} identity handle"))?;
        if duplicate.is_invalid() {
            return Err(format!(
                "Windows returned an invalid contained {label} identity handle"
            ));
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(duplicate.0) })
    }

    #[derive(Clone, Copy)]
    enum PipeEnd {
        Read,
        Write,
    }

    struct InheritableHandleScope<'a> {
        handles: &'a [HANDLE],
        armed: usize,
    }

    impl<'a> InheritableHandleScope<'a> {
        fn new(handles: &'a [HANDLE]) -> Result<Self, String> {
            let mut scope = Self { handles, armed: 0 };
            for handle in handles {
                unsafe {
                    SetHandleInformation(*handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                }
                .map_err(|error| {
                    format!("Cannot arm contained process child pipe inheritance: {error}")
                })?;
                scope.armed += 1;
            }
            Ok(scope)
        }
    }

    impl Drop for InheritableHandleScope<'_> {
        fn drop(&mut self) {
            for handle in &self.handles[..self.armed] {
                let _ = unsafe {
                    SetHandleInformation(*handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))
                };
            }
        }
    }

    fn process_pipe(parent_end: PipeEnd) -> Result<(OwnedHandle, OwnedHandle), String> {
        let security = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: false.into(),
            ..SECURITY_ATTRIBUTES::default()
        };
        let mut read = HANDLE::default();
        let mut write = HANDLE::default();
        unsafe { CreatePipe(&mut read, &mut write, Some(&security), 0) }
            .map_err(|error| format!("Cannot create contained process pipe: {error}"))?;
        let read = owned_handle(read)?;
        let write = owned_handle(write)?;
        Ok(match parent_end {
            PipeEnd::Read => (read, write),
            PipeEnd::Write => (write, read),
        })
    }

    fn raw_handle(handle: &OwnedHandle) -> HANDLE {
        HANDLE(handle.as_raw_handle())
    }

    fn owned_handle(handle: HANDLE) -> Result<OwnedHandle, String> {
        if handle.is_invalid() {
            return Err("Windows returned an invalid contained process handle".into());
        }
        Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
    }

    fn nul_terminated(value: &OsStr, label: &str) -> Result<Vec<u16>, String> {
        let mut encoded = value.encode_wide().collect::<Vec<_>>();
        if encoded.is_empty() || encoded.contains(&0) || encoded.len() >= 32_767 {
            return Err(format!("{label} is not a valid Windows process string"));
        }
        encoded.push(0);
        Ok(encoded)
    }

    fn command_line(executable: &OsStr, arguments: &[OsString]) -> Result<Vec<u16>, String> {
        let mut command = Vec::new();
        append_quoted_argument(&mut command, executable)?;
        for argument in arguments {
            command.push(b' ' as u16);
            append_quoted_argument(&mut command, argument)?;
        }
        if command.len() >= 32_767 {
            return Err("Contained process command line exceeds the Windows limit".into());
        }
        command.push(0);
        Ok(command)
    }

    fn append_quoted_argument(command: &mut Vec<u16>, argument: &OsStr) -> Result<(), String> {
        let encoded = argument.encode_wide().collect::<Vec<_>>();
        if encoded.contains(&0) {
            return Err("Contained process argument contains NUL".into());
        }
        command.push(b'"' as u16);
        let mut backslashes = 0_usize;
        for value in encoded {
            if value == b'\\' as u16 {
                backslashes += 1;
                continue;
            }
            if value == b'"' as u16 {
                command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
                command.push(value);
            } else {
                command.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
                command.push(value);
            }
            backslashes = 0;
        }
        command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
        command.push(b'"' as u16);
        Ok(())
    }

    fn environment_block(environment: &[(OsString, OsString)]) -> Result<Vec<u16>, String> {
        let mut entries = environment.iter().collect::<Vec<_>>();
        entries.sort_by(|(left, _), (right, _)| {
            left.to_string_lossy()
                .to_ascii_uppercase()
                .cmp(&right.to_string_lossy().to_ascii_uppercase())
        });
        let mut block = Vec::new();
        for (key, value) in entries {
            let key = key.encode_wide().collect::<Vec<_>>();
            let value = value.encode_wide().collect::<Vec<_>>();
            if key.is_empty()
                || key.contains(&0)
                || key.contains(&(b'=' as u16))
                || value.contains(&0)
            {
                return Err("Contained process environment contains an invalid entry".into());
            }
            block.extend(key);
            block.push(b'=' as u16);
            block.extend(value);
            block.push(0);
        }
        block.push(0);
        if block.len() > 32_767 {
            return Err("Contained process environment exceeds the Windows limit".into());
        }
        if block.len() == 1 {
            block.push(0);
        }
        Ok(block)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{
            fs,
            io::{Read, Write},
            process::Command,
            time::{SystemTime, UNIX_EPOCH},
        };
        use windows::Win32::Foundation::GetHandleInformation;

        struct TempDirectory(std::path::PathBuf);

        impl Drop for TempDirectory {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn encoded_argument(argument: &OsStr) -> String {
            let units = argument.encode_wide().collect::<Vec<_>>();
            let hex = units
                .iter()
                .map(|unit| format!("{unit:04x}"))
                .collect::<String>();
            format!("{}:{hex}", units.len())
        }

        #[test]
        fn windows_quoting_escapes_quotes_and_trailing_backslashes() {
            let command = command_line(
                OsStr::new(r"C:\Program Files\Java\java.exe"),
                &[
                    OsString::from(r#"plain"#),
                    OsString::from(r#"a b"#),
                    OsString::from(r#"quote\"inside"#),
                    OsString::from(r"trailing\"),
                ],
            )
            .unwrap();
            assert_eq!(*command.last().unwrap(), 0);
            assert!(command.len() < 32_767);
        }

        #[test]
        fn environment_block_is_double_nul_terminated() {
            let block = environment_block(&[(OsString::from("B"), OsString::from("2"))]).unwrap();
            assert_eq!(&block[block.len() - 2..], &[0, 0]);
        }

        #[test]
        fn process_pipe_is_inheritable_only_inside_the_explicit_scope() {
            fn is_inheritable(handle: &OwnedHandle) -> bool {
                let mut flags = 0_u32;
                unsafe { GetHandleInformation(raw_handle(handle), &mut flags) }.unwrap();
                flags & HANDLE_FLAG_INHERIT.0 != 0
            }

            let inheritance_lock = process_handle_inheritance_guard().unwrap();
            let (parent, child) = process_pipe(PipeEnd::Read).unwrap();
            assert!(!is_inheritable(&parent));
            assert!(!is_inheritable(&child));
            {
                let child_handles = [raw_handle(&child)];
                let _scope = InheritableHandleScope::new(&child_handles).unwrap();
                assert!(!is_inheritable(&parent));
                assert!(is_inheritable(&child));
            }
            assert!(!is_inheritable(&parent));
            assert!(!is_inheritable(&child));

            let invalid = HANDLE::default();
            let handles = [raw_handle(&child), invalid];
            let error = InheritableHandleScope::new(&handles)
                .err()
                .expect("invalid second handle must fail after arming the first");
            assert!(error.starts_with("Cannot arm contained process child pipe inheritance:"));
            assert!(
                !is_inheritable(&child),
                "partial-scope failure must restore the already armed prefix"
            );
            drop(child);
            drop(parent);
            drop(inheritance_lock);
        }

        #[test]
        fn handle_list_excludes_an_unrelated_inheritable_sentinel() {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "fragment supervisor handle-list probe {} {nonce}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let directory = TempDirectory(directory);
            let source = directory.0.join("handle list probe.rs");
            let executable = directory.0.join("handle list probe.exe");
            fs::write(
                &source,
                r#"
use std::ffi::c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn WriteFile(
        file: *mut c_void,
        buffer: *const c_void,
        bytes_to_write: u32,
        bytes_written: *mut u32,
        overlapped: *mut c_void,
    ) -> i32;
}

fn main() {
    let handle = std::env::args().nth(1).unwrap().parse::<usize>().unwrap();
    let payload = b"sentinel-leaked";
    let mut written = 0_u32;
    let wrote = unsafe {
        WriteFile(
            handle as *mut c_void,
            payload.as_ptr().cast(),
            payload.len() as u32,
            &mut written,
            std::ptr::null_mut(),
        )
    };
    println!("sentinel-write:{wrote}");
    println!("exact-stdout");
    eprintln!("exact-stderr");
    if wrote != 0 {
        std::process::exit(7);
    }
}
"#,
            )
            .unwrap();
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
            let mut compilation_command = Command::new(rustc);
            compilation_command
                .arg("--edition=2021")
                .args(["--crate-name", "fragment_handle_list_probe"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let compilation = spawn_command_with_inheritance_lock(&mut compilation_command)
                .unwrap()
                .wait_with_output()
                .unwrap();
            assert!(
                compilation.status.success(),
                "handle-list probe compilation failed: {}",
                String::from_utf8_lossy(&compilation.stderr)
            );

            let inheritance_guard = process_handle_inheritance_guard().unwrap();
            let (sentinel_read, sentinel_write) = process_pipe(PipeEnd::Read).unwrap();
            let sentinel_handles = [raw_handle(&sentinel_write)];
            let sentinel_scope = InheritableHandleScope::new(&sentinel_handles).unwrap();
            let arguments = [OsString::from(format!(
                "{}",
                raw_handle(&sentinel_write).0 as usize
            ))];
            let spawned = spawn_while_inheritance_locked(
                ProcessSpec {
                    executable: &executable,
                    arguments: &arguments,
                    cwd: &directory.0,
                    environment: &[],
                },
                &inheritance_guard,
                |_| Ok(()),
            );
            drop(sentinel_scope);
            drop(sentinel_write);
            drop(inheritance_guard);

            let (mut child, mut pipes) = spawned.unwrap();
            let mut stdout = String::new();
            pipes.stdout.read_to_string(&mut stdout).unwrap();
            let mut stderr = String::new();
            pipes.stderr.read_to_string(&mut stderr).unwrap();
            let exit_deadline = Instant::now() + Duration::from_secs(5);
            let exit_code = loop {
                if let Some(exit_code) = child.try_wait().unwrap() {
                    break exit_code;
                }
                assert!(
                    Instant::now() < exit_deadline,
                    "handle-list probe did not exit before the watchdog deadline"
                );
                std::thread::sleep(CLEANUP_POLL);
            };
            child.terminate_and_reap(Duration::from_secs(5)).unwrap();
            let mut sentinel = Vec::new();
            File::from(sentinel_read)
                .read_to_end(&mut sentinel)
                .unwrap();

            assert_eq!(exit_code, 0);
            assert_eq!(stdout, "sentinel-write:0\nexact-stdout\n");
            assert_eq!(stderr, "exact-stderr\n");
            assert!(sentinel.is_empty(), "unlisted sentinel handle leaked");
        }

        #[test]
        fn command_wrapper_releases_the_inheritance_lock_after_spawn() {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "fragment supervisor command-lock probe {} {nonce}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let directory = TempDirectory(directory);
            let source = directory.0.join("command lock probe.rs");
            let executable = directory.0.join("command lock probe.exe");
            fs::write(
                &source,
                r#"
use std::io::Read;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("wait") {
        let mut byte = [0_u8; 1];
        std::io::stdin().read_exact(&mut byte).unwrap();
    }
}
"#,
            )
            .unwrap();
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
            let mut compilation_command = Command::new(rustc);
            compilation_command
                .arg("--edition=2021")
                .args(["--crate-name", "fragment_command_lock_probe"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let compilation = spawn_command_with_inheritance_lock(&mut compilation_command)
                .unwrap()
                .wait_with_output()
                .unwrap();
            assert!(
                compilation.status.success(),
                "command-lock probe compilation failed: {}",
                String::from_utf8_lossy(&compilation.stderr)
            );

            let mut waiting_command = Command::new(&executable);
            waiting_command
                .arg("wait")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            let mut waiting = spawn_command_with_inheritance_lock(&mut waiting_command).unwrap();
            let mut waiting_stdin = waiting.stdin.take().unwrap();
            assert!(waiting.try_wait().unwrap().is_none());

            let contender_executable = executable.clone();
            let (spawned_tx, spawned_rx) = std::sync::mpsc::sync_channel(0);
            let contender = std::thread::spawn(move || {
                let mut command = Command::new(contender_executable);
                command
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                let result = spawn_command_with_inheritance_lock(&mut command)
                    .and_then(|mut child| child.wait());
                let _ = spawned_tx.send(result);
            });

            let contender_status = spawned_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("an unrelated spawn must not wait for the first child to exit")
                .unwrap();
            assert!(contender_status.success());
            assert!(waiting.try_wait().unwrap().is_none());
            waiting_stdin.write_all(&[1]).unwrap();
            drop(waiting_stdin);
            assert!(waiting.wait().unwrap().success());
            contender.join().unwrap();
        }

        #[test]
        fn rejecting_before_resume_gate_never_runs_suspended_payload() {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "fragment supervisor suspended-gate probe {} {nonce}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let directory = TempDirectory(directory);
            let source = directory.0.join("suspended gate probe.rs");
            let executable = directory.0.join("suspended gate probe.exe");
            let marker = directory.0.join("payload-ran");
            fs::write(
                &source,
                r#"
fn main() {
    std::fs::write(std::env::args_os().nth(1).unwrap(), b"payload-ran").unwrap();
}
"#,
            )
            .unwrap();
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
            let mut compilation_command = Command::new(rustc);
            compilation_command
                .arg("--edition=2021")
                .args(["--crate-name", "fragment_suspended_gate_probe"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let compilation = spawn_command_with_inheritance_lock(&mut compilation_command)
                .unwrap()
                .wait_with_output()
                .unwrap();
            assert!(
                compilation.status.success(),
                "suspended-gate probe compilation failed: {}",
                String::from_utf8_lossy(&compilation.stderr)
            );

            let gate_entered = std::sync::atomic::AtomicBool::new(false);
            let arguments = [marker.clone().into_os_string()];
            let error = spawn_with_before_resume_identity(
                ProcessSpec {
                    executable: &executable,
                    arguments: &arguments,
                    cwd: &directory.0,
                    environment: &[],
                },
                |binding| {
                    gate_entered.store(true, Ordering::Release);
                    assert_ne!(binding.pid(), 0);
                    assert!(binding
                        .validate_exact_client_pid(binding.pid())
                        .expect("the retained suspended identity must be queryable"));
                    assert!(!binding
                        .validate_exact_client_pid(std::process::id())
                        .expect("a foreign PID must be an ordinary rejection"));
                    Err("synthetic final authority rejection".into())
                },
            )
            .err()
            .expect("the final authority gate must reject the suspended child");

            assert!(gate_entered.load(Ordering::Acquire));
            assert_eq!(error, "synthetic final authority rejection");
            assert!(
                !marker.exists(),
                "a payload rejected before ResumeThread must never execute"
            );
        }

        #[test]
        fn bounded_drain_deadline_cancels_live_windows_pipe_reads() {
            let (stdout_read, stdout_write) = process_pipe(PipeEnd::Read).unwrap();
            let (stderr_read, stderr_write) = process_pipe(PipeEnd::Read).unwrap();
            let drain = ProcessPipes {
                stdout: Box::new(File::from(stdout_read)),
                stderr: Box::new(File::from(stderr_read)),
            }
            .drain_bounded(64)
            .unwrap();

            let started = Instant::now();
            let error = drain
                .finish_with_timeout(Duration::from_millis(50))
                .unwrap_err();
            assert_eq!(
                error,
                "Contained process output did not reach EOF before the drain deadline"
            );
            assert!(started.elapsed() < Duration::from_secs(2));
            drop(stdout_write);
            drop(stderr_write);
        }

        #[test]
        fn bounded_drain_startup_failures_are_synchronous_and_drop_every_reader() {
            use std::sync::mpsc;

            struct NeverRead {
                stream: &'static str,
                dropped: mpsc::Sender<&'static str>,
            }

            impl Read for NeverRead {
                fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                    panic!("a reader must not run after an injected drain startup failure");
                }
            }

            impl Drop for NeverRead {
                fn drop(&mut self) {
                    let _ = self.dropped.send(self.stream);
                }
            }

            let cases = [
                (
                    DrainStartupFault::OuterSpawn,
                    "Synthetic outer drain startup failure",
                ),
                (
                    DrainStartupFault::StderrSpawn,
                    "Synthetic stderr drain startup failure",
                ),
                (
                    DrainStartupFault::DuplicateCancelHandle,
                    "Synthetic drain thread handle duplication failure",
                ),
                (
                    DrainStartupFault::DisconnectAfterStderrSpawn,
                    "Synthetic drain startup acknowledgement disconnect",
                ),
            ];

            for (fault, expected) in cases {
                let (dropped_tx, dropped_rx) = mpsc::channel();
                let pipes = ProcessPipes {
                    stdout: Box::new(NeverRead {
                        stream: "stdout",
                        dropped: dropped_tx.clone(),
                    }),
                    stderr: Box::new(NeverRead {
                        stream: "stderr",
                        dropped: dropped_tx.clone(),
                    }),
                };
                drop(dropped_tx);

                let error = pipes
                    .start_windows_drain_with_fault(64, fault)
                    .err()
                    .expect("the injected startup fault must fail synchronously");
                assert_eq!(error, expected);

                let mut dropped = vec![
                    dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                    dropped_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
                ];
                dropped.sort_unstable();
                assert_eq!(dropped, ["stderr", "stdout"]);
                assert!(matches!(
                    dropped_rx.try_recv(),
                    Err(mpsc::TryRecvError::Disconnected)
                ));
            }
        }

        #[test]
        fn bounded_drain_outer_panic_cancels_and_joins_the_inner_reader() {
            use std::sync::mpsc;

            struct PanicRead;

            impl Read for PanicRead {
                fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
                    panic!("synthetic post-ack stdout drain panic");
                }
            }

            struct DropObservedPipeRead {
                file: File,
                dropped: mpsc::SyncSender<()>,
            }

            impl Read for DropObservedPipeRead {
                fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                    self.file.read(buffer)
                }
            }

            impl Drop for DropObservedPipeRead {
                fn drop(&mut self) {
                    let _ = self.dropped.send(());
                }
            }

            let (stderr_read, stderr_write) = process_pipe(PipeEnd::Read).unwrap();
            let (dropped_tx, dropped_rx) = mpsc::sync_channel(1);
            let drain = ProcessPipes {
                stdout: Box::new(PanicRead),
                stderr: Box::new(DropObservedPipeRead {
                    file: File::from(stderr_read),
                    dropped: dropped_tx,
                }),
            }
            .drain_bounded(64)
            .unwrap();

            let error = drain.finish().unwrap_err();
            assert_eq!(
                error,
                "Contained process output drain terminated unexpectedly"
            );
            assert!(
                dropped_rx.try_recv().is_ok(),
                "finish returned before the unwind guard cancelled and joined stderr"
            );
            assert!(matches!(
                dropped_rx.try_recv(),
                Err(mpsc::TryRecvError::Disconnected)
            ));
            drop(stderr_write);
        }

        #[test]
        fn bounded_drain_reissues_cancellation_after_the_check_to_read_race() {
            use std::sync::mpsc;

            struct DelayedPipeRead {
                file: File,
                entered: mpsc::SyncSender<()>,
                release: mpsc::Receiver<()>,
            }

            impl Read for DelayedPipeRead {
                fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                    let _ = self.entered.send(());
                    let _ = self.release.recv();
                    self.file.read(buffer)
                }
            }

            let (stdout_read, stdout_write) = process_pipe(PipeEnd::Read).unwrap();
            let (entered_tx, entered_rx) = mpsc::sync_channel(0);
            let (release_tx, release_rx) = mpsc::sync_channel(0);
            let drain = ProcessPipes {
                stdout: Box::new(DelayedPipeRead {
                    file: File::from(stdout_read),
                    entered: entered_tx,
                    release: release_rx,
                }),
                stderr: Box::new(std::io::Cursor::new(Vec::<u8>::new())),
            }
            .drain_bounded(64)
            .unwrap();
            let cancelled = Arc::clone(&drain.cancelled);

            // Establish the intended check-to-read race deterministically: the drain worker has
            // already observed `cancelled == false`, but DelayedPipeRead is still outside ReadFile.
            // Starting the finisher before this rendezvous lets its short timeout win the race and
            // makes the worker exit before entering DelayedPipeRead, which tests a different safe
            // path and disconnects `entered_rx`.
            entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
            let started = Instant::now();
            let finisher =
                std::thread::spawn(move || drain.finish_with_timeout(Duration::from_millis(10)));

            let cancellation_deadline = Instant::now() + Duration::from_secs(2);
            while !cancelled.load(Ordering::Acquire) {
                assert!(Instant::now() < cancellation_deadline);
                std::thread::yield_now();
            }
            // The first CancelSynchronousIo happened while DelayedPipeRead was outside ReadFile.
            // The writer stays open, so only a repeated cancellation can release the next read.
            release_tx.send(()).unwrap();
            let error = finisher.join().unwrap().unwrap_err();
            assert_eq!(
                error,
                "Contained process output did not reach EOF before the drain deadline"
            );
            assert!(started.elapsed() < Duration::from_secs(2));
            drop(stdout_write);
        }

        #[test]
        fn dropping_bounded_drain_cancels_and_joins_live_windows_pipe_reads() {
            let (stdout_read, stdout_write) = process_pipe(PipeEnd::Read).unwrap();
            let (stderr_read, stderr_write) = process_pipe(PipeEnd::Read).unwrap();
            let drain = ProcessPipes {
                stdout: Box::new(File::from(stdout_read)),
                stderr: Box::new(File::from(stderr_read)),
            }
            .drain_bounded(64)
            .unwrap();

            let started = Instant::now();
            drop(drain);
            assert!(started.elapsed() < Duration::from_secs(2));
            drop(stdout_write);
            drop(stderr_write);
        }

        #[test]
        fn bounded_drain_concurrently_empties_real_child_pipes_beyond_pipe_capacity() {
            const CHUNK_BYTES: usize = 16 * 1024;
            const CHUNKS: usize = 64;
            const STREAM_BYTES: usize = CHUNK_BYTES * CHUNKS;
            const TAIL_BYTES: usize = 128;

            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "fragment supervisor flood probe {} {nonce}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let directory = TempDirectory(directory);
            let source = directory.0.join("flood probe.rs");
            let executable = directory.0.join("flood probe.exe");
            fs::write(
                &source,
                r#"
use std::io::{self, Write};

fn main() {
    let stderr_chunk = [b'E'; 16 * 1024];
    let mut stderr = io::stderr().lock();
    for _ in 0..64 {
        stderr.write_all(&stderr_chunk).unwrap();
    }
    drop(stderr);

    let stdout_chunk = [b'O'; 16 * 1024];
    let mut stdout = io::stdout().lock();
    for _ in 0..64 {
        stdout.write_all(&stdout_chunk).unwrap();
    }
}
"#,
            )
            .unwrap();
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
            let mut compilation_command = Command::new(rustc);
            compilation_command
                .arg("--edition=2021")
                .args(["--crate-name", "fragment_flood_probe"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let compilation = spawn_command_with_inheritance_lock(&mut compilation_command)
                .unwrap()
                .wait_with_output()
                .unwrap();
            assert!(
                compilation.status.success(),
                "flood probe compilation failed: {}",
                String::from_utf8_lossy(&compilation.stderr)
            );

            let (mut child, pipes) = spawn(ProcessSpec {
                executable: &executable,
                arguments: &[],
                cwd: &directory.0,
                environment: &[],
            })
            .unwrap();
            let drain = pipes.drain_bounded(TAIL_BYTES).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let exit_code = loop {
                if let Some(exit_code) = child.try_wait().unwrap() {
                    break exit_code;
                }
                assert!(
                    Instant::now() < deadline,
                    "flood probe deadlocked while filling its output pipes"
                );
                std::thread::sleep(CLEANUP_POLL);
            };
            assert_eq!(exit_code, 0);
            child.terminate_and_reap(Duration::from_secs(5)).unwrap();
            let capture = drain.finish().unwrap();

            let stdout = vec![b'O'; STREAM_BYTES];
            let stderr = vec![b'E'; STREAM_BYTES];
            assert_eq!(capture.stdout().total_bytes(), STREAM_BYTES as u64);
            assert_eq!(
                capture.stdout().sha256(),
                format!("{:x}", Sha256::digest(&stdout))
            );
            assert_eq!(capture.stdout().tail(), &[b'O'; TAIL_BYTES]);
            assert_eq!(capture.stderr().total_bytes(), STREAM_BYTES as u64);
            assert_eq!(
                capture.stderr().sha256(),
                format!("{:x}", Sha256::digest(&stderr))
            );
            assert_eq!(capture.stderr().tail(), &[b'E'; TAIL_BYTES]);
        }

        #[test]
        fn create_process_round_trips_exact_windows_arguments() {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let directory = std::env::temp_dir().join(format!(
                "fragment supervisor argv probe {} {nonce}",
                std::process::id()
            ));
            fs::create_dir(&directory).unwrap();
            let directory = TempDirectory(directory);
            let source = directory.0.join("argv probe.rs");
            let executable = directory.0.join("argv probe.exe");
            fs::write(
                &source,
                r#"
use std::os::windows::ffi::OsStrExt;

fn main() {
    println!("pid:{}", std::process::id());
    for argument in std::env::args_os().skip(1) {
        let units = argument.encode_wide().collect::<Vec<_>>();
        let hex = units
            .iter()
            .map(|unit| format!("{unit:04x}"))
            .collect::<String>();
        println!("{}:{hex}", units.len());
    }
}
"#,
            )
            .unwrap();
            let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| OsString::from("rustc"));
            let mut compilation_command = Command::new(rustc);
            compilation_command
                .arg("--edition=2021")
                .args(["--crate-name", "fragment_argv_probe"])
                .arg(&source)
                .arg("-o")
                .arg(&executable)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            let compilation = spawn_command_with_inheritance_lock(&mut compilation_command)
                .unwrap()
                .wait_with_output()
                .unwrap();
            assert!(
                compilation.status.success(),
                "argv probe compilation failed: {}",
                String::from_utf8_lossy(&compilation.stderr)
            );

            let arguments = vec![
                OsString::from(""),
                OsString::from("plain"),
                OsString::from("with spaces"),
                OsString::from("quote\"inside"),
                OsString::from(r#"slashes\\before\"quote"#),
                OsString::from("single trailing\\"),
                OsString::from(r"trailing\\"),
                OsString::from("Фрагмент ✨"),
            ];
            let expected = arguments
                .iter()
                .map(|argument| encoded_argument(argument))
                .collect::<Vec<_>>()
                .join("\n")
                + "\n";
            let (mut child, mut pipes) = spawn(ProcessSpec {
                executable: &executable,
                arguments: &arguments,
                cwd: &directory.0,
                environment: &[],
            })
            .unwrap();
            let mut stdout = String::new();
            pipes.stdout.read_to_string(&mut stdout).unwrap();
            let mut stderr = String::new();
            pipes.stderr.read_to_string(&mut stderr).unwrap();
            child.terminate_and_reap(Duration::from_secs(5)).unwrap();
            assert!(stderr.is_empty(), "argv probe stderr: {stderr}");
            let (pid, arguments) = stdout
                .split_once('\n')
                .expect("argv probe must print its PID first");
            assert_eq!(pid, format!("pid:{}", child.pid()));
            assert_eq!(arguments, expected);
        }
    }
}

#[cfg(not(windows))]
mod platform {
    use super::*;
    use std::process::{Child, Command, Stdio};

    /// Compile-time placeholder only. Fragment's trusted launch-ticket IPC requires the Windows
    /// suspended-process and Job boundary and therefore never fabricates this proof elsewhere.
    pub(crate) struct SuspendedProcessBinding;

    impl SuspendedProcessBinding {
        pub(crate) const fn pid(&self) -> u32 {
            0
        }

        pub(crate) fn validate_exact_client_pid(&self, _client_pid: u32) -> Result<bool, String> {
            Ok(false)
        }
    }

    pub(crate) struct ContainedProcess {
        child: Child,
        exit_code: Option<i32>,
    }

    impl ContainedProcess {
        pub(crate) fn pid(&self) -> u32 {
            self.child.id()
        }

        pub(crate) fn try_wait(&mut self) -> Result<Option<i32>, String> {
            if let Some(code) = self.exit_code {
                return Ok(Some(code));
            }
            match self
                .child
                .try_wait()
                .map_err(|error| format!("Cannot poll contained process: {error}"))?
            {
                Some(status) => {
                    let code = status.code().ok_or_else(|| {
                        "Contained process exited without a numeric code".to_string()
                    })?;
                    self.exit_code = Some(code);
                    Ok(Some(code))
                }
                None => Ok(None),
            }
        }

        pub(crate) fn terminate_and_reap(&mut self, timeout: Duration) -> Result<(), String> {
            let mut errors = Vec::new();
            if self.try_wait()?.is_none() {
                if let Err(error) = self.child.kill() {
                    errors.push(format!("Cannot kill contained process: {error}"));
                }
            }
            let deadline = Instant::now() + timeout;
            loop {
                match self.try_wait() {
                    Ok(Some(_)) => break,
                    Ok(None) if Instant::now() < deadline => std::thread::sleep(CLEANUP_POLL),
                    Ok(None) => {
                        errors.push(
                            "contained process was not reaped before the cleanup deadline".into(),
                        );
                        break;
                    }
                    Err(error) => {
                        errors.push(error);
                        break;
                    }
                }
            }
            if errors.is_empty() {
                Ok(())
            } else {
                Err(errors.join("; "))
            }
        }
    }

    pub(crate) fn spawn(spec: ProcessSpec<'_>) -> Result<(ContainedProcess, ProcessPipes), String> {
        spawn_with_before_resume(spec, || Ok(()))
    }

    pub(crate) fn spawn_with_before_resume(
        spec: ProcessSpec<'_>,
        before_resume: impl FnOnce() -> Result<(), String>,
    ) -> Result<(ContainedProcess, ProcessPipes), String> {
        // Non-Windows builds do not provide the suspended-process containment boundary. They are
        // retained for compile/test portability only, so fail before process creation if the same
        // final authority gate rejects the launch.
        before_resume()?;
        let mut command = Command::new(spec.executable);
        command
            .args(spec.arguments)
            .current_dir(spec.cwd)
            .env_clear()
            .envs(spec.environment.iter().cloned())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = spawn_command_with_inheritance_lock(&mut command)
            .map_err(|error| format!("Cannot start contained process: {error}"))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| "Contained process stdout pipe is missing".to_string())?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| "Contained process stderr pipe is missing".to_string())?;
        Ok((
            ContainedProcess {
                child,
                exit_code: None,
            },
            ProcessPipes {
                stdout: Box::new(stdout),
                stderr: Box::new(stderr),
            },
        ))
    }

    pub(crate) fn spawn_with_before_resume_identity(
        _spec: ProcessSpec<'_>,
        _before_resume: impl FnOnce(SuspendedProcessBinding) -> Result<(), String>,
    ) -> Result<(ContainedProcess, ProcessPipes), String> {
        Err("Secure launch-ticket process binding requires Windows Job containment".into())
    }
}

pub(super) use platform::{spawn, spawn_with_before_resume_identity, SuspendedProcessBinding};
