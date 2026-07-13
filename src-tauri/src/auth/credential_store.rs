use async_trait::async_trait;

use super::types::Secret;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CredentialMutation {
    Applied,
    Changed,
    Missing,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum CredentialStoreError {
    #[error("secure credential storage is unavailable during {0}")]
    Unavailable(&'static str),
    #[error("stored Fragment credential is invalid")]
    InvalidStoredCredential,
}

#[async_trait]
pub(crate) trait CredentialStore: Send + Sync {
    async fn load(&self) -> Result<Option<Secret>, CredentialStoreError>;
    async fn replace_if_current(
        &self,
        expected: Option<&Secret>,
        next: &Secret,
    ) -> Result<CredentialMutation, CredentialStoreError>;
    async fn clear_if_current(
        &self,
        expected: &Secret,
    ) -> Result<CredentialMutation, CredentialStoreError>;
}

#[cfg(windows)]
pub(crate) struct WindowsCredentialStore;

#[cfg(windows)]
impl WindowsCredentialStore {
    pub(crate) fn new() -> Self {
        Self
    }

    fn write(&self, value: &Secret) -> Result<(), CredentialStoreError> {
        use windows::core::PWSTR;
        use windows::Win32::Security::Credentials::{
            CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
        };

        let mut target = wide_null(CREDENTIAL_TARGET);
        let mut username = wide_null(CREDENTIAL_USERNAME);
        let bytes = value.expose().as_bytes();
        let credential = CREDENTIALW {
            Type: CRED_TYPE_GENERIC,
            TargetName: PWSTR(target.as_mut_ptr()),
            CredentialBlobSize: bytes.len() as u32,
            CredentialBlob: bytes.as_ptr().cast_mut(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            UserName: PWSTR(username.as_mut_ptr()),
            ..Default::default()
        };
        // SAFETY: all pointers in `credential` remain valid for this call.
        unsafe { CredWriteW(&credential, 0) }
            .map_err(|_| CredentialStoreError::Unavailable("write"))
    }

    fn delete(&self) -> Result<(), CredentialStoreError> {
        use windows::core::PCWSTR;
        use windows::Win32::Security::Credentials::{CredDeleteW, CRED_TYPE_GENERIC};

        let target = wide_null(CREDENTIAL_TARGET);
        // SAFETY: `target` is NUL-terminated and valid for this call.
        match unsafe { CredDeleteW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None) } {
            Ok(()) => Ok(()),
            Err(error) if is_not_found(&error) => Ok(()),
            Err(_) => Err(CredentialStoreError::Unavailable("delete")),
        }
    }
}

#[cfg(windows)]
#[async_trait]
impl CredentialStore for WindowsCredentialStore {
    async fn load(&self) -> Result<Option<Secret>, CredentialStoreError> {
        use std::ptr;

        use windows::core::PCWSTR;
        use windows::Win32::Security::Credentials::{
            CredFree, CredReadW, CREDENTIALW, CRED_TYPE_GENERIC,
        };

        let target = wide_null(CREDENTIAL_TARGET);
        let mut raw: *mut CREDENTIALW = ptr::null_mut();
        // SAFETY: `target` is NUL-terminated and `raw` is a valid out-pointer.
        let result =
            unsafe { CredReadW(PCWSTR(target.as_ptr()), CRED_TYPE_GENERIC, None, &mut raw) };
        if let Err(error) = result {
            if is_not_found(&error) {
                return Ok(None);
            }
            return Err(CredentialStoreError::Unavailable("read"));
        }
        if raw.is_null() {
            return Err(CredentialStoreError::InvalidStoredCredential);
        }

        struct CredentialGuard(*mut CREDENTIALW);
        impl Drop for CredentialGuard {
            fn drop(&mut self) {
                // SAFETY: the pointer and blob were allocated by CredReadW and
                // remain exclusively owned until CredFree below.
                unsafe {
                    let credential = &mut *self.0;
                    let length = (credential.CredentialBlobSize as usize)
                        .min(super::types::MAX_SECRET_BYTES);
                    if !credential.CredentialBlob.is_null() {
                        for byte in
                            std::slice::from_raw_parts_mut(credential.CredentialBlob, length)
                        {
                            std::ptr::write_volatile(byte, 0);
                        }
                        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
                    }
                    CredFree(self.0.cast());
                }
            }
        }
        let _guard = CredentialGuard(raw);
        // SAFETY: `raw` remains owned by the guard for this block.
        let credential = unsafe { &*raw };
        let length = credential.CredentialBlobSize as usize;
        if length == 0
            || length > super::types::MAX_SECRET_BYTES
            || credential.CredentialBlob.is_null()
        {
            return Err(CredentialStoreError::InvalidStoredCredential);
        }
        // SAFETY: Credential Manager guarantees a blob of CredentialBlobSize bytes.
        let bytes = unsafe { std::slice::from_raw_parts(credential.CredentialBlob, length) };
        let value = std::str::from_utf8(bytes)
            .map_err(|_| CredentialStoreError::InvalidStoredCredential)?;
        Secret::new(value.to_owned())
            .map(Some)
            .map_err(|_| CredentialStoreError::InvalidStoredCredential)
    }

    async fn replace_if_current(
        &self,
        expected: Option<&Secret>,
        next: &Secret,
    ) -> Result<CredentialMutation, CredentialStoreError> {
        let current = self.load().await?;
        match (current.as_ref(), expected) {
            (None, None) => {
                self.write(next)?;
                Ok(CredentialMutation::Applied)
            }
            (None, Some(_)) => Ok(CredentialMutation::Missing),
            (Some(_), None) => Ok(CredentialMutation::Changed),
            (Some(current), Some(expected)) if current.expose() == expected.expose() => {
                self.write(next)?;
                Ok(CredentialMutation::Applied)
            }
            (Some(_), Some(_)) => Ok(CredentialMutation::Changed),
        }
    }

    async fn clear_if_current(
        &self,
        expected: &Secret,
    ) -> Result<CredentialMutation, CredentialStoreError> {
        let current = self.load().await?;
        match current.as_ref() {
            None => Ok(CredentialMutation::Missing),
            Some(current) if current.expose() == expected.expose() => {
                self.delete()?;
                Ok(CredentialMutation::Applied)
            }
            Some(_) => Ok(CredentialMutation::Changed),
        }
    }
}

// v2 deliberately does not import the old WebView/v1 credential. This prevents
// an older mutex-unaware launcher from mutating the new rotation chain.
#[cfg(windows)]
const CREDENTIAL_TARGET: &str = "FragmentLauncher2/auth/refresh-token/v2";
#[cfg(windows)]
const CREDENTIAL_USERNAME: &str = "Fragment Launcher";

#[cfg(windows)]
fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn is_not_found(error: &windows::core::Error) -> bool {
    // HRESULT_FROM_WIN32(ERROR_NOT_FOUND / 1168).
    error.code().0 == 0x8007_0490u32 as i32
}

#[cfg(test)]
pub(crate) struct MemoryCredentialStore {
    value: tokio::sync::Mutex<Option<Secret>>,
    writes: std::sync::atomic::AtomicUsize,
    clears: std::sync::atomic::AtomicUsize,
    fail_writes: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
impl MemoryCredentialStore {
    pub(crate) fn empty() -> Self {
        Self {
            value: tokio::sync::Mutex::new(None),
            writes: std::sync::atomic::AtomicUsize::new(0),
            clears: std::sync::atomic::AtomicUsize::new(0),
            fail_writes: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn with(value: Secret) -> Self {
        Self {
            value: tokio::sync::Mutex::new(Some(value)),
            writes: std::sync::atomic::AtomicUsize::new(0),
            clears: std::sync::atomic::AtomicUsize::new(0),
            fail_writes: std::sync::atomic::AtomicBool::new(false),
        }
    }

    pub(crate) fn writes(&self) -> usize {
        self.writes.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn clears(&self) -> usize {
        self.clears.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub(crate) fn set_fail_writes(&self, value: bool) {
        self.fail_writes
            .store(value, std::sync::atomic::Ordering::SeqCst);
    }

    pub(crate) async fn is_empty(&self) -> bool {
        self.value.lock().await.is_none()
    }

    pub(crate) async fn peek(&self) -> Option<String> {
        self.value
            .lock()
            .await
            .as_ref()
            .map(|value| value.expose().to_owned())
    }

    pub(crate) async fn replace_for_test(&self, value: Secret) {
        *self.value.lock().await = Some(value);
    }
}

#[cfg(test)]
#[async_trait]
impl CredentialStore for MemoryCredentialStore {
    async fn load(&self) -> Result<Option<Secret>, CredentialStoreError> {
        self.value
            .lock()
            .await
            .as_ref()
            .map(|value| Secret::new(value.expose().to_owned()))
            .transpose()
            .map_err(|_| CredentialStoreError::InvalidStoredCredential)
    }

    async fn replace_if_current(
        &self,
        expected: Option<&Secret>,
        next: &Secret,
    ) -> Result<CredentialMutation, CredentialStoreError> {
        let mut current = self.value.lock().await;
        let outcome = match (current.as_ref(), expected) {
            (None, None) => CredentialMutation::Applied,
            (None, Some(_)) => CredentialMutation::Missing,
            (Some(_), None) => CredentialMutation::Changed,
            (Some(current), Some(expected)) if current.expose() == expected.expose() => {
                CredentialMutation::Applied
            }
            (Some(_), Some(_)) => CredentialMutation::Changed,
        };
        if outcome != CredentialMutation::Applied {
            return Ok(outcome);
        }
        if self.fail_writes.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(CredentialStoreError::Unavailable("test write"));
        }
        *current = Some(
            Secret::new(next.expose().to_owned())
                .map_err(|_| CredentialStoreError::InvalidStoredCredential)?,
        );
        self.writes
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(CredentialMutation::Applied)
    }

    async fn clear_if_current(
        &self,
        expected: &Secret,
    ) -> Result<CredentialMutation, CredentialStoreError> {
        let mut current = self.value.lock().await;
        match current.as_ref() {
            None => Ok(CredentialMutation::Missing),
            Some(value) if value.expose() != expected.expose() => Ok(CredentialMutation::Changed),
            Some(_) => {
                *current = None;
                self.clears
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Ok(CredentialMutation::Applied)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_store_conditional_round_trip_keeps_secret_redacted() {
        let store = MemoryCredentialStore::empty();
        let first = Secret::new("r".repeat(64)).unwrap();
        let second = Secret::new("s".repeat(64)).unwrap();
        assert_eq!(
            store.replace_if_current(None, &first).await.unwrap(),
            CredentialMutation::Applied
        );
        let loaded = store.load().await.unwrap().unwrap();
        assert_eq!(loaded.expose(), first.expose());
        assert!(!format!("{loaded:?}").contains(first.expose()));
        assert_eq!(
            store
                .replace_if_current(Some(&first), &second)
                .await
                .unwrap(),
            CredentialMutation::Applied
        );
        assert_eq!(
            store.clear_if_current(&second).await.unwrap(),
            CredentialMutation::Applied
        );
        assert!(store.load().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn conditional_clear_never_deletes_a_winner_token() {
        let old = Secret::new("o".repeat(64)).unwrap();
        let winner = Secret::new("w".repeat(64)).unwrap();
        let store = MemoryCredentialStore::with(Secret::new(old.expose().to_owned()).unwrap());
        store.replace_for_test(winner).await;

        assert_eq!(
            store.clear_if_current(&old).await.unwrap(),
            CredentialMutation::Changed
        );
        assert_eq!(store.peek().await, Some("w".repeat(64)));
        assert_eq!(store.clears(), 0);
    }
}
