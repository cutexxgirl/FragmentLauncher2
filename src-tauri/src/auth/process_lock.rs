use std::time::Duration;

#[cfg(windows)]
use std::path::PathBuf;

use async_trait::async_trait;

// One holder can spend up to the native HTTP client's 20-second request
// timeout rotating/revoking a credential. Keep the wait bounded while allowing
// that operation to finish before a second process fails closed.
const REFRESH_LOCK_WAIT: Duration = Duration::from_secs(25);

#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ProcessLockError {
    #[error("another Fragment Launcher process is updating the login session")]
    Timeout,
    #[cfg(test)]
    #[error("a previous Fragment Launcher process abandoned the login-session lock")]
    Abandoned,
    #[error("the cross-process login-session lock is unavailable")]
    Unavailable,
}

trait ProcessLeaseGuard: Send {}
impl<T: Send> ProcessLeaseGuard for T {}

pub(crate) struct RefreshProcessLease {
    _guard: Box<dyn ProcessLeaseGuard>,
}

impl RefreshProcessLease {
    fn new(guard: impl ProcessLeaseGuard + 'static) -> Self {
        Self {
            _guard: Box::new(guard),
        }
    }
}

#[async_trait]
pub(crate) trait RefreshProcessLock: Send + Sync {
    async fn acquire(&self) -> Result<RefreshProcessLease, ProcessLockError>;
}

#[cfg(windows)]
pub(crate) struct WindowsRefreshProcessLock {
    path: PathBuf,
    wait: Duration,
}

#[cfg(windows)]
impl WindowsRefreshProcessLock {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self {
            path,
            wait: REFRESH_LOCK_WAIT,
        }
    }

    #[cfg(test)]
    fn with_wait(path: PathBuf, wait: Duration) -> Self {
        Self { path, wait }
    }
}

#[cfg(windows)]
#[async_trait]
impl RefreshProcessLock for WindowsRefreshProcessLock {
    async fn acquire(&self) -> Result<RefreshProcessLease, ProcessLockError> {
        let path = self.path.clone();
        let wait = self.wait;
        tokio::task::spawn_blocking(move || acquire_windows_file_lock(path, wait))
            .await
            .map_err(|_| ProcessLockError::Unavailable)?
    }
}

#[cfg(windows)]
struct WindowsFileLease(std::fs::File);

#[cfg(windows)]
impl Drop for WindowsFileLease {
    fn drop(&mut self) {
        // File locks are process-wide and thread-neutral. An explicit unlock is
        // best effort; closing the persistent file handle releases it even if
        // this call fails.
        let _ = fs2::FileExt::unlock(&self.0);
    }
}

#[cfg(windows)]
fn acquire_windows_file_lock(
    path: PathBuf,
    wait: Duration,
) -> Result<RefreshProcessLease, ProcessLockError> {
    let file = open_windows_lock_file(&path)?;
    let deadline = std::time::Instant::now() + wait;
    loop {
        match fs2::FileExt::try_lock_exclusive(&file) {
            Ok(()) => return Ok(RefreshProcessLease::new(WindowsFileLease(file))),
            Err(error) if error.raw_os_error() == fs2::lock_contended_error().raw_os_error() => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(ProcessLockError::Timeout);
                }
                std::thread::sleep((deadline - now).min(Duration::from_millis(50)));
            }
            Err(_) => return Err(ProcessLockError::Unavailable),
        }
    }
}

#[cfg(windows)]
fn open_windows_lock_file(path: &std::path::Path) -> Result<std::fs::File, ProcessLockError> {
    use std::fs::OpenOptions;
    use std::mem::size_of;
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, HANDLE};
    use windows::Win32::Storage::FileSystem::{
        FileAttributeTagInfo, FileStandardInfo, GetFileInformationByHandleEx,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_OPEN_REPARSE_POINT,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STANDARD_INFO, SYNCHRONIZE,
    };

    let parent = path.parent().ok_or(ProcessLockError::Unavailable)?;
    std::fs::create_dir_all(parent).map_err(|_| ProcessLockError::Unavailable)?;

    // The path is fixed by native code under Tauri's per-user LocalAppData
    // directory. OPEN_REPARSE_POINT prevents the final component from following
    // a symlink/junction, and omitting FILE_SHARE_DELETE keeps its identity
    // stable for the lifetime of the handle. The file is deliberately never
    // deleted: all logon sessions for this Windows user rendezvous on it.
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .access_mode(GENERIC_READ.0 | GENERIC_WRITE.0 | SYNCHRONIZE.0)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0)
        .open(path)
        .map_err(|_| ProcessLockError::Unavailable)?;

    let handle = HANDLE(file.as_raw_handle().cast());
    if handle.0.is_null() {
        return Err(ProcessLockError::Unavailable);
    }

    let mut attributes = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `handle` is owned by `file`; the output buffer is correctly sized
    // and remains valid for the duration of the call.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            (&mut attributes as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
            size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .map_err(|_| ProcessLockError::Unavailable)?;

    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: same valid handle and correctly sized live output buffer.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&mut standard as *mut FILE_STANDARD_INFO).cast(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    }
    .map_err(|_| ProcessLockError::Unavailable)?;

    let is_reparse = attributes.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0;
    if is_reparse || attributes.ReparseTag != 0 || standard.Directory || standard.NumberOfLinks != 1
    {
        return Err(ProcessLockError::Unavailable);
    }

    Ok(file)
}

#[cfg(test)]
pub(crate) struct MemoryRefreshProcessLock {
    gate: std::sync::Arc<tokio::sync::Mutex<()>>,
    wait: Duration,
    failure: std::sync::Mutex<Option<ProcessLockError>>,
}

#[cfg(test)]
impl MemoryRefreshProcessLock {
    pub(crate) fn new(wait: Duration) -> Self {
        Self {
            gate: std::sync::Arc::new(tokio::sync::Mutex::new(())),
            wait,
            failure: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn fail_next(&self, failure: ProcessLockError) {
        *self.failure.lock().expect("memory process-lock poison") = Some(failure);
    }

    pub(crate) async fn hold(&self) -> tokio::sync::OwnedMutexGuard<()> {
        self.gate.clone().lock_owned().await
    }
}

#[cfg(test)]
#[async_trait]
impl RefreshProcessLock for MemoryRefreshProcessLock {
    async fn acquire(&self) -> Result<RefreshProcessLease, ProcessLockError> {
        if let Some(error) = self
            .failure
            .lock()
            .expect("memory process-lock poison")
            .take()
        {
            return Err(error);
        }
        let guard = tokio::time::timeout(self.wait, self.gate.clone().lock_owned())
            .await
            .map_err(|_| ProcessLockError::Timeout)?;
        Ok(RefreshProcessLease::new(guard))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dropping_memory_lease_releases_next_waiter() {
        let lock = MemoryRefreshProcessLock::new(Duration::from_millis(50));
        let first = lock.acquire().await.unwrap();
        drop(first);
        assert!(lock.acquire().await.is_ok());
    }

    #[tokio::test]
    async fn memory_lock_injects_abandoned_failure_once() {
        let lock = MemoryRefreshProcessLock::new(Duration::from_millis(50));
        lock.fail_next(ProcessLockError::Abandoned);
        assert!(matches!(
            lock.acquire().await,
            Err(ProcessLockError::Abandoned)
        ));
        assert!(lock.acquire().await.is_ok());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_file_lock_is_bounded_and_shared_by_independent_instances() {
        let directory =
            std::env::temp_dir().join(format!("fragment-auth-lock-test-{}", uuid::Uuid::new_v4()));
        let path = directory.join("refresh.lock");
        let first = WindowsRefreshProcessLock::with_wait(path.clone(), Duration::from_millis(100));
        let second = WindowsRefreshProcessLock::with_wait(path.clone(), Duration::from_millis(40));

        let first_lease = first.acquire().await.unwrap();
        assert!(matches!(
            second.acquire().await,
            Err(ProcessLockError::Timeout)
        ));
        drop(first_lease);
        assert!(second.acquire().await.is_ok());

        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_file_lock_rejects_hard_linked_nodes() {
        let directory = std::env::temp_dir().join(format!(
            "fragment-auth-lock-link-test-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let path = directory.join("refresh.lock");
        let alias = directory.join("alias.lock");
        std::fs::write(&path, []).unwrap();
        std::fs::hard_link(&path, &alias).unwrap();

        assert!(matches!(
            open_windows_lock_file(&path),
            Err(ProcessLockError::Unavailable)
        ));

        std::fs::remove_file(&alias).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_dir(&directory).unwrap();
    }
}
