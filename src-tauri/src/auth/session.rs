use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::path::PathBuf;

use tokio::sync::Mutex;

use super::client::{ApiError, AuthApi, FragmentApiClient};
#[cfg(windows)]
use super::credential_store::WindowsCredentialStore;
use super::credential_store::{CredentialMutation, CredentialStore, CredentialStoreError};
#[cfg(windows)]
use super::process_lock::WindowsRefreshProcessLock;
use super::process_lock::{ProcessLockError, RefreshProcessLease, RefreshProcessLock};
use super::types::{
    normalize_device_name, normalize_nickname, validate_refresh_token, AdmissionChannel,
    AuthSnapshot, ContractError, LauncherAdmissionSnapshot, LauncherProfile, Secret,
    SessionResponse, TelegramLoginSnapshot, TelegramPollOutcome, TelegramPollSnapshot,
};

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("{0}")]
    Api(String),
    #[error("{0}")]
    Credentials(String),
    #[error("{0}")]
    Contract(String),
    #[error("no Telegram login challenge is active")]
    NoActiveChallenge,
    #[error("the launcher is signed out")]
    SignedOut,
    #[error("the Telegram login page could not be opened")]
    OpenTelegramLogin,
    #[error("{0}")]
    ProcessLock(String),
    #[error("the persisted Fragment login session changed in another process")]
    CredentialChanged,
    #[error("the Fragment login session changed while the request was running")]
    SessionChanged,
}

pub struct AuthSessionManager {
    api: Arc<dyn AuthApi>,
    credentials: Arc<dyn CredentialStore>,
    link_opener: Arc<dyn TelegramLinkOpener>,
    process_lock: Arc<dyn RefreshProcessLock>,
    state: Mutex<SessionState>,
    refresh_gate: Mutex<()>,
    poll_gate: Mutex<()>,
}

struct SessionState {
    access: Option<AccessSession>,
    profile: Option<LauncherProfile>,
    challenge: Option<ChallengeState>,
}

struct AccessSession {
    token: Arc<Secret>,
    refresh_at: Instant,
}

struct ChallengeState {
    id: String,
    poll_token: Arc<Secret>,
}

trait TelegramLinkOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<(), ()>;
}

#[cfg(windows)]
struct SystemTelegramLinkOpener;

#[cfg(windows)]
impl TelegramLinkOpener for SystemTelegramLinkOpener {
    fn open(&self, url: &str) -> Result<(), ()> {
        use windows::core::PCWSTR;
        use windows::Win32::UI::Shell::ShellExecuteW;
        use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

        struct WideSecret(Vec<u16>);
        impl Drop for WideSecret {
            fn drop(&mut self) {
                for unit in &mut self.0 {
                    unsafe { std::ptr::write_volatile(unit, 0) };
                }
                std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            }
        }

        let operation: Vec<u16> = "open".encode_utf16().chain(std::iter::once(0)).collect();
        let target = WideSecret(url.encode_utf16().chain(std::iter::once(0)).collect());
        // SAFETY: the UTF-16 inputs are NUL-terminated and live for the call.
        let result = unsafe {
            ShellExecuteW(
                None,
                PCWSTR(operation.as_ptr()),
                PCWSTR(target.0.as_ptr()),
                PCWSTR::null(),
                PCWSTR::null(),
                SW_SHOWNORMAL,
            )
        };
        if result.0 as isize > 32 {
            Ok(())
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
struct TestTelegramLinkOpener;

#[cfg(test)]
impl TelegramLinkOpener for TestTelegramLinkOpener {
    fn open(&self, _url: &str) -> Result<(), ()> {
        Ok(())
    }
}

impl From<ApiError> for AuthError {
    fn from(error: ApiError) -> Self {
        Self::Api(error.to_string())
    }
}

impl From<CredentialStoreError> for AuthError {
    fn from(error: CredentialStoreError) -> Self {
        Self::Credentials(error.to_string())
    }
}

impl From<ContractError> for AuthError {
    fn from(error: ContractError) -> Self {
        Self::Contract(error.to_string())
    }
}

impl From<ProcessLockError> for AuthError {
    fn from(error: ProcessLockError) -> Self {
        Self::ProcessLock(error.to_string())
    }
}

impl AuthSessionManager {
    #[cfg(windows)]
    pub fn production(refresh_lock_path: PathBuf) -> Result<Self, AuthError> {
        Ok(Self::with_components(
            Arc::new(FragmentApiClient::new()?),
            Arc::new(WindowsCredentialStore::new()),
            Arc::new(SystemTelegramLinkOpener),
            Arc::new(WindowsRefreshProcessLock::new(refresh_lock_path)),
        ))
    }

    #[cfg(test)]
    pub(crate) fn new(api: Arc<dyn AuthApi>, credentials: Arc<dyn CredentialStore>) -> Self {
        Self::with_components(
            api,
            credentials,
            Arc::new(TestTelegramLinkOpener),
            Arc::new(super::process_lock::MemoryRefreshProcessLock::new(
                Duration::from_secs(1),
            )),
        )
    }

    #[cfg(test)]
    pub(crate) fn new_with_process_lock(
        api: Arc<dyn AuthApi>,
        credentials: Arc<dyn CredentialStore>,
        process_lock: Arc<dyn RefreshProcessLock>,
    ) -> Self {
        Self::with_components(
            api,
            credentials,
            Arc::new(TestTelegramLinkOpener),
            process_lock,
        )
    }

    fn with_components(
        api: Arc<dyn AuthApi>,
        credentials: Arc<dyn CredentialStore>,
        link_opener: Arc<dyn TelegramLinkOpener>,
        process_lock: Arc<dyn RefreshProcessLock>,
    ) -> Self {
        Self {
            api,
            credentials,
            link_opener,
            process_lock,
            state: Mutex::new(SessionState {
                access: None,
                profile: None,
                challenge: None,
            }),
            refresh_gate: Mutex::new(()),
            poll_gate: Mutex::new(()),
        }
    }

    pub async fn snapshot(&self) -> AuthSnapshot {
        let state = self.state.lock().await;
        state
            .profile
            .clone()
            .map(AuthSnapshot::authenticated)
            .unwrap_or_else(AuthSnapshot::signed_out)
    }

    /// Restores a session by rotating the persisted refresh token. An invalid
    /// or revoked token produces a signed-out snapshot and is removed locally.
    pub async fn restore(&self) -> Result<AuthSnapshot, AuthError> {
        match self.refresh_access(None, false).await {
            Ok(_) => Ok(self.snapshot().await),
            Err(AuthError::SignedOut) => Ok(AuthSnapshot::signed_out()),
            Err(error) => Err(error),
        }
    }

    pub async fn begin_login(
        &self,
        device_name: Option<&str>,
    ) -> Result<TelegramLoginSnapshot, AuthError> {
        let _poll = self.poll_gate.lock().await;
        let _lifecycle = self.refresh_gate.lock().await;
        let device_name = normalize_device_name(device_name.unwrap_or("Fragment Launcher"))?;
        let response = self.api.begin_challenge(&device_name).await?;
        let snapshot = TelegramLoginSnapshot {
            expires_at: response.expires_at.clone(),
        };
        let challenge_id = response.challenge_id;
        self.state.lock().await.challenge = Some(ChallengeState {
            id: challenge_id.clone(),
            poll_token: Arc::new(response.poll_token),
        });
        if self
            .link_opener
            .open(response.telegram_link.expose())
            .is_err()
        {
            self.clear_challenge_if(&challenge_id).await;
            return Err(AuthError::OpenTelegramLogin);
        }
        Ok(snapshot)
    }

    /// Polls the native-held challenge. Neither the challenge ID nor poll token
    /// is accepted from (or returned to) the webview.
    pub async fn poll_login(&self) -> Result<TelegramPollSnapshot, AuthError> {
        let _single_poll = self.poll_gate.lock().await;
        let (id, poll_token) = {
            let state = self.state.lock().await;
            let challenge = state
                .challenge
                .as_ref()
                .ok_or(AuthError::NoActiveChallenge)?;
            (challenge.id.clone(), Arc::clone(&challenge.poll_token))
        };

        match self.api.poll_challenge(&id, &poll_token).await? {
            TelegramPollOutcome::Pending { expires_at } => {
                Ok(TelegramPollSnapshot::Pending { expires_at })
            }
            TelegramPollOutcome::Expired { expires_at } => {
                self.clear_challenge_if(&id).await;
                Ok(TelegramPollSnapshot::Expired { expires_at })
            }
            TelegramPollOutcome::Consumed { expires_at } => {
                self.clear_challenge_if(&id).await;
                Ok(TelegramPollSnapshot::Consumed { expires_at })
            }
            TelegramPollOutcome::Confirmed {
                expires_at,
                session,
            } => {
                let session = *session;
                let _lifecycle = self.refresh_gate.lock().await;
                let process_lease = match self.process_lock.acquire().await {
                    Ok(lease) => lease,
                    Err(error) => {
                        self.clear_challenge_if(&id).await;
                        let _ = self.api.logout(&session.refresh_token).await;
                        return Err(error.into());
                    }
                };
                let expected_refresh = match self.credentials.load().await {
                    Ok(refresh) => refresh,
                    Err(error) => {
                        self.clear_challenge_if(&id).await;
                        let _ = self.api.logout(&session.refresh_token).await;
                        return Err(error.into());
                    }
                };
                let is_current = self
                    .state
                    .lock()
                    .await
                    .challenge
                    .as_ref()
                    .is_some_and(|challenge| challenge.id == id);
                if !is_current {
                    let _ = self.api.logout(&session.refresh_token).await;
                    return Err(AuthError::NoActiveChallenge);
                }
                self.clear_challenge_if(&id).await;
                let profile = session.profile.clone();
                self.accept_rotated_session(session, expected_refresh.as_ref(), process_lease)
                    .await?;
                // A confirmed Telegram login creates a new DeviceSession rather
                // than rotating the prior one. Persist the winner first, then
                // best-effort revoke the replaced session so access tokens in
                // another launcher process stop passing server admission.
                if let Some(previous_refresh) = expected_refresh.as_ref() {
                    let _ = self.api.logout(previous_refresh).await;
                }
                Ok(TelegramPollSnapshot::Confirmed {
                    expires_at,
                    auth: Box::new(AuthSnapshot::authenticated(profile)),
                })
            }
        }
    }

    /// Refreshes `/auth/me`, retrying exactly once after a 401 with a
    /// single-flight refresh-token rotation.
    pub async fn refresh_profile(&self) -> Result<AuthSnapshot, AuthError> {
        let first = self.access_for_request().await?;
        let (profile, used_token) = match self.api.get_profile(&first).await {
            Ok(profile) => (profile, first),
            Err(error) if error.is_unauthorized() => {
                let second = self.refresh_access(Some(&first), true).await?;
                (self.api.get_profile(&second).await?, second)
            }
            Err(error) => return Err(error.into()),
        };
        self.snapshot_after_profile_response(&used_token, profile)
            .await
    }

    /// Updates the launcher nickname through a native authenticated PATCH,
    /// retrying exactly once after a 401.
    pub async fn update_nickname(&self, nickname: Option<&str>) -> Result<AuthSnapshot, AuthError> {
        let nickname = normalize_nickname(nickname)?;
        let first = self.access_for_request().await?;
        let (profile, used_token) =
            match self.api.update_nickname(&first, nickname.as_deref()).await {
                Ok(profile) => (profile, first),
                Err(error) if error.is_unauthorized() => {
                    let second = self.refresh_access(Some(&first), true).await?;
                    (
                        self.api
                            .update_nickname(&second, nickname.as_deref())
                            .await?,
                        second,
                    )
                }
                Err(error) => return Err(error.into()),
            };
        self.snapshot_after_profile_response(&used_token, profile)
            .await
    }

    /// Performs the authoritative FragmentApi admission check for a future
    /// launch. The access token never leaves native memory. A real spawn command
    /// must call this again immediately before creating the Java process.
    pub async fn admission(
        &self,
        channel: AdmissionChannel,
    ) -> Result<LauncherAdmissionSnapshot, AuthError> {
        let first = self.access_for_request().await?;
        let (response, used_token) = match self.api.launcher_admission(&first, channel).await {
            Ok(response) => (response, first),
            Err(error) if error.is_unauthorized() => {
                let second = match self.refresh_access(Some(&first), true).await {
                    Ok(token) => token,
                    Err(AuthError::SignedOut) => {
                        return Ok(LauncherAdmissionSnapshot::denied(
                            channel,
                            super::types::LauncherAdmissionReason::InvalidSession,
                        ));
                    }
                    Err(error) => return Err(error),
                };
                match self.api.launcher_admission(&second, channel).await {
                    Ok(response) => (response, second),
                    Err(error) => return admission_failure(channel, error),
                }
            }
            Err(error) => return admission_failure(channel, error),
        };

        let mut state = self.state.lock().await;
        if !state
            .access
            .as_ref()
            .is_some_and(|access| Arc::ptr_eq(&used_token, &access.token))
        {
            return Err(AuthError::SessionChanged);
        }
        let profile = state.profile.as_mut().ok_or(AuthError::SessionChanged)?;
        if profile.user_id != response.user_id {
            return Err(ContractError::InvalidField("userId").into());
        }
        profile.launcher_nick = Some(response.launcher_nick);
        profile.launcher_role = response.launcher_role;
        profile.launcher_permissions = response.launcher_permissions;
        profile.subscription_level = response.entitlement.level;
        profile.entitlement = response.entitlement;
        Ok(LauncherAdmissionSnapshot::allowed(channel, profile.clone()))
    }

    /// Revokes the server session when possible, then removes local credentials
    /// and RAM-only state. If the bounded cross-process lock cannot be acquired,
    /// nothing is changed and the caller must continue showing the signed-in UI.
    pub async fn logout(&self) -> Result<AuthSnapshot, AuthError> {
        let _single_flight = self.refresh_gate.lock().await;
        let _process_lease = self.process_lock.acquire().await?;
        let loaded = self.credentials.load().await?;
        if let Some(refresh) = loaded.as_ref() {
            // Remote revocation is best effort. Once the native credential is
            // safely removed, this device is signed out even while offline.
            let _ = self.api.logout(refresh).await;
            match self.credentials.clear_if_current(refresh).await? {
                CredentialMutation::Applied | CredentialMutation::Missing => {}
                CredentialMutation::Changed => {
                    self.clear_auth_state().await;
                    return Err(AuthError::CredentialChanged);
                }
            }
        }
        self.clear_auth_state().await;
        Ok(AuthSnapshot::signed_out())
    }

    async fn access_for_request(&self) -> Result<Arc<Secret>, AuthError> {
        {
            let state = self.state.lock().await;
            if let Some(access) = state.access.as_ref() {
                if access.refresh_at > Instant::now() {
                    return Ok(Arc::clone(&access.token));
                }
            }
        }
        self.refresh_access(None, false).await
    }

    async fn refresh_access(
        &self,
        rejected: Option<&Arc<Secret>>,
        force: bool,
    ) -> Result<Arc<Secret>, AuthError> {
        let _single_flight = self.refresh_gate.lock().await;

        {
            let state = self.state.lock().await;
            if let Some(access) = state.access.as_ref() {
                let was_replaced =
                    rejected.is_some_and(|rejected| !Arc::ptr_eq(rejected, &access.token));
                if was_replaced || (!force && access.refresh_at > Instant::now()) {
                    return Ok(Arc::clone(&access.token));
                }
            }
        }

        let process_lease = self.process_lock.acquire().await?;
        let Some(refresh) = self.credentials.load().await? else {
            self.clear_auth_state().await;
            return Err(AuthError::SignedOut);
        };
        if validate_refresh_token(&refresh).is_err() {
            let _ = self.credentials.clear_if_current(&refresh).await?;
            self.clear_auth_state().await;
            return Err(AuthError::SignedOut);
        }
        let response = match self.api.refresh(&refresh).await {
            Ok(response) => response,
            Err(ApiError::Unauthorized) => {
                let clear_result = self.credentials.clear_if_current(&refresh).await;
                self.clear_auth_state().await;
                clear_result?;
                return Err(AuthError::SignedOut);
            }
            Err(error) => return Err(error.into()),
        };
        self.accept_rotated_session(response, Some(&refresh), process_lease)
            .await
    }

    /// Credential persistence happens before the new access token/profile can
    /// become visible to any request or UI snapshot.
    async fn accept_rotated_session(
        &self,
        response: SessionResponse,
        expected_refresh: Option<&Secret>,
        _process_lease: RefreshProcessLease,
    ) -> Result<Arc<Secret>, AuthError> {
        match self
            .credentials
            .replace_if_current(expected_refresh, &response.refresh_token)
            .await
        {
            Ok(CredentialMutation::Applied) => {}
            Ok(CredentialMutation::Changed | CredentialMutation::Missing) => {
                let _ = self.api.logout(&response.refresh_token).await;
                self.clear_auth_state().await;
                return Err(AuthError::CredentialChanged);
            }
            Err(error) => {
                // The write result may be ambiguous. Never perform an
                // unconditional delete: a different process may own a newer
                // credential. Revoke this response token best-effort and fail closed.
                let _ = self.api.logout(&response.refresh_token).await;
                let _ = self
                    .credentials
                    .clear_if_current(&response.refresh_token)
                    .await;
                self.clear_auth_state().await;
                return Err(error.into());
            }
        }

        let refresh_early_by = (response.expires_in / 10).clamp(1, 30);
        let refresh_after = response.expires_in.saturating_sub(refresh_early_by);
        let token = Arc::new(response.access_token);
        let mut state = self.state.lock().await;
        state.profile = Some(response.profile);
        state.access = Some(AccessSession {
            token: Arc::clone(&token),
            refresh_at: Instant::now() + Duration::from_secs(refresh_after),
        });
        Ok(token)
    }

    async fn snapshot_after_profile_response(
        &self,
        token: &Arc<Secret>,
        profile: LauncherProfile,
    ) -> Result<AuthSnapshot, AuthError> {
        let mut state = self.state.lock().await;
        if !state
            .access
            .as_ref()
            .is_some_and(|access| Arc::ptr_eq(token, &access.token))
        {
            return Err(AuthError::SessionChanged);
        }
        state.profile = Some(profile);
        Ok(state
            .profile
            .clone()
            .map(AuthSnapshot::authenticated)
            .unwrap_or_else(AuthSnapshot::signed_out))
    }

    async fn clear_challenge_if(&self, id: &str) {
        let mut state = self.state.lock().await;
        if state
            .challenge
            .as_ref()
            .is_some_and(|challenge| challenge.id == id)
        {
            state.challenge = None;
        }
    }

    async fn clear_auth_state(&self) {
        let mut state = self.state.lock().await;
        state.access = None;
        state.profile = None;
        state.challenge = None;
    }
}

fn admission_failure(
    channel: AdmissionChannel,
    error: ApiError,
) -> Result<LauncherAdmissionSnapshot, AuthError> {
    if let Some(reason) = error.admission_reason() {
        Ok(LauncherAdmissionSnapshot::denied(channel, reason))
    } else {
        Err(error.into())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use async_trait::async_trait;

    use super::*;
    use crate::auth::credential_store::MemoryCredentialStore;
    use crate::auth::process_lock::{MemoryRefreshProcessLock, ProcessLockError};
    use crate::auth::types::{
        EntitlementSnapshot, LauncherAdmissionReason, LauncherAdmissionResponse, LauncherRole,
        PollStatus, SubscriptionLevel, TelegramChallengeResponse, TokenType,
    };

    struct FakeApi {
        refreshes: AtomicUsize,
        active_refreshes: AtomicUsize,
        max_active_refreshes: AtomicUsize,
        profile_gets: AtomicUsize,
        admission_calls: AtomicUsize,
        logouts: AtomicUsize,
        confirm_next_poll: AtomicBool,
        reject_next_get: AtomicBool,
        reject_next_refresh: AtomicBool,
        reject_next_admission: AtomicBool,
        fail_logout: AtomicBool,
        admission_error: std::sync::Mutex<Option<&'static str>>,
    }

    impl FakeApi {
        fn new() -> Self {
            Self {
                refreshes: AtomicUsize::new(0),
                active_refreshes: AtomicUsize::new(0),
                max_active_refreshes: AtomicUsize::new(0),
                profile_gets: AtomicUsize::new(0),
                admission_calls: AtomicUsize::new(0),
                logouts: AtomicUsize::new(0),
                confirm_next_poll: AtomicBool::new(false),
                reject_next_get: AtomicBool::new(false),
                reject_next_refresh: AtomicBool::new(false),
                reject_next_admission: AtomicBool::new(false),
                fail_logout: AtomicBool::new(false),
                admission_error: std::sync::Mutex::new(None),
            }
        }

        fn session(&self) -> SessionResponse {
            let generation = self.refreshes.load(Ordering::SeqCst);
            SessionResponse {
                token_type: TokenType::Bearer,
                access_token: Secret::new(format!("access-{generation}-{}", "a".repeat(32)))
                    .unwrap(),
                refresh_token: Secret::new(format!("refresh-{generation}-{}", "r".repeat(32)))
                    .unwrap(),
                expires_in: 900,
                profile: profile(),
            }
        }
    }

    #[async_trait]
    impl AuthApi for FakeApi {
        async fn begin_challenge(
            &self,
            _device_name: &str,
        ) -> Result<TelegramChallengeResponse, ApiError> {
            Ok(TelegramChallengeResponse {
                challenge_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                status: PollStatus::Pending,
                expires_at: "2026-07-11T12:00:00Z".into(),
                poll_token: Secret::new("p".repeat(24)).unwrap(),
                telegram_link: Secret::new("https://t.me/fragment_bot?start=login_test".into())
                    .unwrap(),
            })
        }

        async fn poll_challenge(
            &self,
            _challenge_id: &str,
            _poll_token: &Secret,
        ) -> Result<TelegramPollOutcome, ApiError> {
            if self.confirm_next_poll.swap(false, Ordering::SeqCst) {
                return Ok(TelegramPollOutcome::Confirmed {
                    expires_at: "2026-07-11T12:00:00Z".into(),
                    session: Box::new(self.session()),
                });
            }
            Ok(TelegramPollOutcome::Pending {
                expires_at: "2026-07-11T12:00:00Z".into(),
            })
        }

        async fn refresh(&self, _refresh_token: &Secret) -> Result<SessionResponse, ApiError> {
            if self.reject_next_refresh.swap(false, Ordering::SeqCst) {
                return Err(ApiError::Unauthorized);
            }
            let active = self.active_refreshes.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active_refreshes
                .fetch_max(active, Ordering::SeqCst);
            self.refreshes.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(5)).await;
            let session = self.session();
            self.active_refreshes.fetch_sub(1, Ordering::SeqCst);
            Ok(session)
        }

        async fn logout(&self, _refresh_token: &Secret) -> Result<(), ApiError> {
            self.logouts.fetch_add(1, Ordering::SeqCst);
            if self.fail_logout.load(Ordering::SeqCst) {
                Err(ApiError::Transport("test network"))
            } else {
                Ok(())
            }
        }

        async fn get_profile(&self, _access_token: &Secret) -> Result<LauncherProfile, ApiError> {
            self.profile_gets.fetch_add(1, Ordering::SeqCst);
            if self.reject_next_get.swap(false, Ordering::SeqCst) {
                Err(ApiError::Unauthorized)
            } else {
                Ok(profile())
            }
        }

        async fn update_nickname(
            &self,
            _access_token: &Secret,
            _nickname: Option<&str>,
        ) -> Result<LauncherProfile, ApiError> {
            Ok(profile())
        }

        async fn launcher_admission(
            &self,
            _access_token: &Secret,
            channel: AdmissionChannel,
        ) -> Result<LauncherAdmissionResponse, ApiError> {
            self.admission_calls.fetch_add(1, Ordering::SeqCst);
            if self.reject_next_admission.swap(false, Ordering::SeqCst) {
                return Err(ApiError::Unauthorized);
            }
            if let Some(code) = *self.admission_error.lock().unwrap() {
                return Err(ApiError::Http {
                    status: 403,
                    code: Some(code.into()),
                    message: String::new(),
                });
            }
            let profile = profile();
            Ok(LauncherAdmissionResponse {
                allowed: true,
                channel,
                admitted_at: "2026-07-11T12:00:00Z".into(),
                session_id: "660e8400-e29b-41d4-a716-446655440000".into(),
                user_id: profile.user_id,
                launcher_nick: profile.launcher_nick.unwrap(),
                launcher_role: profile.launcher_role,
                launcher_permissions: profile.launcher_permissions,
                entitlement: profile.entitlement,
            })
        }
    }

    fn profile() -> LauncherProfile {
        LauncherProfile {
            user_id: "550e8400-e29b-41d4-a716-446655440000".into(),
            launcher_nick: Some("Player_1".into()),
            launcher_nick_updated_at: None,
            launcher_nick_next_change_at: None,
            telegram_id: Some("123456789".into()),
            username: Some("player".into()),
            first_name: Some("Player".into()),
            last_name: None,
            avatar_url: None,
            telegram_avatar_url: None,
            photo_url: None,
            fid: Some("fragment-id".into()),
            launcher_role: LauncherRole::Player,
            launcher_permissions: vec![],
            subscription_level: SubscriptionLevel::Novice,
            entitlement: EntitlementSnapshot {
                active: true,
                level: SubscriptionLevel::Novice,
                expires_at: None,
                recalculated_at: Some("2026-07-11T12:00:00Z".into()),
            },
        }
    }

    #[tokio::test]
    async fn concurrent_restore_is_single_flight() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store.clone()));

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let manager = Arc::clone(&manager);
            tasks.push(tokio::spawn(async move { manager.restore().await }));
        }
        for task in tasks {
            assert!(task.await.unwrap().unwrap().authenticated);
        }
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 1);
        assert_eq!(store.writes(), 1);
    }

    #[tokio::test]
    async fn failed_refresh_persistence_never_publishes_access_session() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        store.set_fail_writes(true);
        let manager = AuthSessionManager::new(api, store);

        assert!(matches!(
            manager.restore().await,
            Err(AuthError::Credentials(_))
        ));
        assert!(!manager.snapshot().await.authenticated);
    }

    #[tokio::test]
    async fn authenticated_get_retries_only_once_after_401() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = AuthSessionManager::new(api.clone(), store);
        manager.restore().await.unwrap();
        api.reject_next_get.store(true, Ordering::SeqCst);

        assert!(manager.refresh_profile().await.unwrap().authenticated);
        assert_eq!(api.profile_gets.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn ui_snapshots_never_contain_auth_or_challenge_secrets() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = AuthSessionManager::new(api, store);

        let auth = manager.restore().await.unwrap();
        let auth_json = serde_json::to_string(&auth).unwrap();
        assert!(!auth_json.contains("access-"));
        assert!(!auth_json.contains("refresh-"));

        let login = manager.begin_login(None).await.unwrap();
        let login_json = serde_json::to_string(&login).unwrap();
        assert!(!login_json.contains("challengeId"));
        assert!(!login_json.contains("pollToken"));
        assert!(!login_json.contains("telegramLink"));
        assert!(!login_json.contains("login_test"));
    }

    #[tokio::test]
    async fn refresh_401_removes_persisted_credential() {
        let api = Arc::new(FakeApi::new());
        api.reject_next_refresh.store(true, Ordering::SeqCst);
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = AuthSessionManager::new(api, store.clone());

        assert!(!manager.restore().await.unwrap().authenticated);
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn logout_succeeds_locally_when_network_revocation_fails() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = AuthSessionManager::new(api.clone(), store.clone());
        manager.restore().await.unwrap();
        api.fail_logout.store(true, Ordering::SeqCst);

        assert!(!manager.logout().await.unwrap().authenticated);
        assert!(!manager.snapshot().await.authenticated);
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn logout_lock_timeout_keeps_native_session_and_credential() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_millis(5)));
        let manager =
            AuthSessionManager::new_with_process_lock(api, store.clone(), process_lock.clone());
        manager.restore().await.unwrap();
        let held = process_lock.hold().await;

        assert!(matches!(
            manager.logout().await,
            Err(AuthError::ProcessLock(_))
        ));
        assert!(manager.snapshot().await.authenticated);
        assert!(!store.is_empty().await);
        assert_eq!(store.clears(), 0);

        drop(held);
    }

    #[tokio::test]
    async fn confirmed_login_lock_failure_revokes_orphan_and_consumes_local_challenge() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::empty());
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_secs(1)));
        process_lock.fail_next(ProcessLockError::Timeout);
        let manager =
            AuthSessionManager::new_with_process_lock(api.clone(), store.clone(), process_lock);
        manager.begin_login(None).await.unwrap();
        api.confirm_next_poll.store(true, Ordering::SeqCst);

        assert!(matches!(
            manager.poll_login().await,
            Err(AuthError::ProcessLock(_))
        ));
        assert_eq!(api.logouts.load(Ordering::SeqCst), 1);
        assert!(store.is_empty().await);
        assert!(matches!(
            manager.poll_login().await,
            Err(AuthError::NoActiveChallenge)
        ));
    }

    #[tokio::test]
    async fn confirmed_login_persists_winner_before_revoking_replaced_session() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = AuthSessionManager::new(api.clone(), store.clone());
        manager.begin_login(None).await.unwrap();
        api.confirm_next_poll.store(true, Ordering::SeqCst);

        let result = manager.poll_login().await.unwrap();
        assert!(matches!(result, TelegramPollSnapshot::Confirmed { .. }));
        assert_eq!(store.writes(), 1);
        assert!(store.peek().await.unwrap().starts_with("refresh-0-"));
        assert_eq!(api.logouts.load(Ordering::SeqCst), 1);
        assert!(manager.snapshot().await.authenticated);
    }

    #[tokio::test]
    async fn separate_managers_reload_rotated_credential_under_shared_process_lock() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_secs(1)));
        let first = AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock.clone(),
        );
        let second =
            AuthSessionManager::new_with_process_lock(api.clone(), store.clone(), process_lock);

        let (first_result, second_result) = tokio::join!(first.restore(), second.restore());
        assert!(first_result.unwrap().authenticated);
        assert!(second_result.unwrap().authenticated);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(api.max_active_refreshes.load(Ordering::SeqCst), 1);
        assert_eq!(store.writes(), 2);
        assert!(store.peek().await.unwrap().starts_with("refresh-2-"));
    }

    #[tokio::test]
    async fn process_lock_timeout_performs_no_api_or_credential_mutation() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_millis(5)));
        let held = process_lock.hold().await;
        let manager =
            AuthSessionManager::new_with_process_lock(api.clone(), store.clone(), process_lock);

        assert!(matches!(
            manager.restore().await,
            Err(AuthError::ProcessLock(_))
        ));
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 0);
        assert_eq!(store.writes(), 0);
        assert!(store
            .peek()
            .await
            .unwrap()
            .starts_with("old-refresh-token-"));
        drop(held);
    }

    #[tokio::test]
    async fn abandoned_process_lock_fails_once_without_mutation() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_secs(1)));
        process_lock.fail_next(ProcessLockError::Abandoned);
        let manager =
            AuthSessionManager::new_with_process_lock(api.clone(), store.clone(), process_lock);

        assert!(matches!(
            manager.restore().await,
            Err(AuthError::ProcessLock(_))
        ));
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 0);
        assert_eq!(store.writes(), 0);
    }

    #[tokio::test]
    async fn admission_retries_one_401_and_returns_only_safe_profile_data() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = AuthSessionManager::new(api.clone(), store);
        manager.restore().await.unwrap();
        api.reject_next_admission.store(true, Ordering::SeqCst);

        let admission = manager.admission(AdmissionChannel::Stable).await.unwrap();
        assert!(admission.allowed);
        assert_eq!(admission.role, Some(LauncherRole::Player));
        assert_eq!(api.admission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
        let json = serde_json::to_string(&admission).unwrap();
        assert!(!json.contains("sessionId"));
        assert!(!json.contains("accessToken"));
        assert!(!json.contains("refreshToken"));
    }

    #[tokio::test]
    async fn admission_denial_is_structured_and_fail_closed() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = AuthSessionManager::new(api.clone(), store);
        manager.restore().await.unwrap();
        *api.admission_error.lock().unwrap() = Some("subscription_required");

        let admission = manager.admission(AdmissionChannel::Stable).await.unwrap();
        assert!(!admission.allowed);
        assert_eq!(
            admission.reason,
            Some(LauncherAdmissionReason::SubscriptionRequired)
        );
        assert!(admission.profile.is_none());
        assert!(admission.role.is_none());
    }
}
