use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::path::PathBuf;

use jiff::Timestamp;
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, OwnedMutexGuard};
use uuid::Uuid;

use super::client::{ApiError, AuthApi, FragmentApiClient};
#[cfg(windows)]
use super::credential_store::WindowsCredentialStore;
use super::credential_store::{CredentialMutation, CredentialStore, CredentialStoreError};
#[cfg(windows)]
use super::process_lock::WindowsRefreshProcessLock;
use super::process_lock::{ProcessLockError, RefreshProcessLease, RefreshProcessLock};
use super::types::{
    normalize_device_name, normalize_nickname, validate_refresh_token, AdmissionChannel,
    AuthSnapshot, ContractError, LauncherAdmissionReason, LauncherAdmissionResponse,
    LauncherAdmissionSnapshot, LauncherProfile, Secret, SessionResponse, TelegramLoginSnapshot,
    TelegramPollOutcome, TelegramPollSnapshot, VerifiedLaunchAdmission,
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

#[derive(Debug, thiserror::Error)]
pub(crate) enum LaunchAdmissionError {
    #[error("Fragment launch admission was denied ({0:?})")]
    Denied(LauncherAdmissionReason),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NativeAccessFailure {
    Authentication,
    Failed(String),
}

enum AdmissionRequestError {
    Auth(AuthError),
    Api(ApiError),
}

enum SessionBoundRequestError {
    Auth(AuthError),
    Api(ApiError),
}

impl AuthError {
    pub(crate) fn into_native_access_failure(self) -> NativeAccessFailure {
        match self {
            Self::SignedOut => NativeAccessFailure::Authentication,
            other => NativeAccessFailure::Failed(other.to_string()),
        }
    }
}

pub struct AuthSessionManager {
    api: Arc<dyn AuthApi>,
    credentials: Arc<dyn CredentialStore>,
    link_opener: Arc<dyn TelegramLinkOpener>,
    process_lock: Arc<dyn RefreshProcessLock>,
    state: Mutex<SessionState>,
    refresh_gate: Arc<Mutex<()>>,
    poll_gate: Mutex<()>,
}

/// Non-serializable native bearer capability for launcher-owned service calls.
/// JavaScript and Tauri command responses can never obtain the underlying token.
#[derive(Clone)]
pub(crate) struct NativeAccessToken(Arc<Secret>);

impl NativeAccessToken {
    pub(crate) fn expose(&self) -> &str {
        self.0.expose()
    }

    #[cfg(test)]
    pub(crate) fn for_test(value: &str) -> Self {
        Self(Arc::new(
            Secret::new(value.to_owned()).expect("test access token must be a valid secret"),
        ))
    }
}

impl std::fmt::Debug for NativeAccessToken {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NativeAccessToken([REDACTED])")
    }
}

/// Native-only linearization lease for the final FragmentApi decision and one exact process
/// creation. It deliberately owns both session lifecycle locks and is neither cloneable nor
/// serializable, so logout, refresh, account replacement and nickname mutation cannot cross the
/// admission-to-CreateProcess boundary.
#[must_use = "the admission lease must remain alive until CreateProcess returns"]
pub(crate) struct LaunchAdmissionLease {
    admission: VerifiedLaunchAdmission,
    _local_lifecycle: OwnedMutexGuard<()>,
    _process_lifecycle: RefreshProcessLease,
}

impl LaunchAdmissionLease {
    pub(crate) const fn channel(&self) -> AdmissionChannel {
        self.admission.channel()
    }

    pub(crate) fn minecraft_uuid(&self) -> String {
        self.admission.minecraft_uuid()
    }

    pub(crate) fn launcher_nick(&self) -> &str {
        self.admission.launcher_nick()
    }

    pub(crate) fn revalidate_fresh(&self, now: Timestamp) -> Result<(), AuthError> {
        self.admission.revalidate_fresh(now)
    }
}

struct SessionState {
    access: Option<AccessSession>,
    profile: Option<LauncherProfile>,
    challenge: Option<ChallengeState>,
}

struct AccessSession {
    token: Arc<Secret>,
    refresh_at: Instant,
    refresh_fingerprint: [u8; 32],
}

struct LockedSessionIdentity {
    user_id: Uuid,
    launcher_nick: Option<String>,
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
            refresh_gate: Arc::new(Mutex::new(())),
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

    /// Runs access refresh in an owned task. Dropping the caller's wait detaches the task instead
    /// of cancelling a server-side one-time refresh-token rotation before local persistence.
    pub(crate) async fn native_access_token_completion_safe(
        self: &Arc<Self>,
    ) -> Result<NativeAccessToken, AuthError> {
        self.access_for_request().await.map(NativeAccessToken)
    }

    /// Forces the single-flight refresh path after Spark explicitly rejected this exact access
    /// capability. The rejected token is owned by the detached task so its identity remains valid
    /// even if the coordinator stops waiting.
    pub(crate) async fn native_access_token_after_rejection_completion_safe(
        self: &Arc<Self>,
        rejected: NativeAccessToken,
    ) -> Result<NativeAccessToken, AuthError> {
        self.refresh_access(Some(&rejected.0), true)
            .await
            .map(NativeAccessToken)
    }

    /// Restores a session by rotating the persisted refresh token. An invalid
    /// or revoked token produces a signed-out snapshot and is removed locally.
    pub async fn restore(self: &Arc<Self>) -> Result<AuthSnapshot, AuthError> {
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
    pub async fn poll_login(self: &Arc<Self>) -> Result<TelegramPollSnapshot, AuthError> {
        let manager = Arc::clone(self);
        tokio::spawn(async move { manager.poll_login_core().await })
            .await
            .map_err(|_| AuthError::Api("Telegram login worker failed".into()))?
    }

    async fn poll_login_core(&self) -> Result<TelegramPollSnapshot, AuthError> {
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
    pub async fn refresh_profile(self: &Arc<Self>) -> Result<AuthSnapshot, AuthError> {
        let mut token = self.access_for_request().await?;
        let mut retried = false;
        loop {
            match self.refresh_profile_under_lifecycle(&token).await {
                Ok(snapshot) => return Ok(snapshot),
                Err(SessionBoundRequestError::Api(error))
                    if error.is_unauthorized() && !retried =>
                {
                    retried = true;
                    token = self.refresh_access(Some(&token), true).await?;
                }
                Err(SessionBoundRequestError::Auth(
                    AuthError::SessionChanged | AuthError::CredentialChanged,
                )) if !retried => {
                    retried = true;
                    token = self.refresh_access(Some(&token), true).await?;
                }
                Err(SessionBoundRequestError::Api(error)) => return Err(error.into()),
                Err(SessionBoundRequestError::Auth(error)) => return Err(error),
            }
        }
    }

    async fn refresh_profile_under_lifecycle(
        self: &Arc<Self>,
        token: &Arc<Secret>,
    ) -> Result<AuthSnapshot, SessionBoundRequestError> {
        let _local_lifecycle = Arc::clone(&self.refresh_gate).lock_owned().await;
        let _process_lifecycle = self
            .process_lock
            .acquire()
            .await
            .map_err(AuthError::from)
            .map_err(SessionBoundRequestError::Auth)?;
        let identity = self
            .recheck_locked_session(token)
            .await
            .map_err(SessionBoundRequestError::Auth)?;
        let profile = self
            .api
            .get_profile(token)
            .await
            .map_err(SessionBoundRequestError::Api)?;
        self.commit_profile_response(token, identity.user_id, profile)
            .await
            .map_err(SessionBoundRequestError::Auth)
    }

    /// Updates the launcher nickname through a native authenticated PATCH,
    /// retrying exactly once after a 401.
    pub async fn update_nickname(
        self: &Arc<Self>,
        nickname: Option<&str>,
    ) -> Result<AuthSnapshot, AuthError> {
        let nickname = normalize_nickname(nickname)?;
        let mut token = self.access_for_request().await?;
        let mut retried = false;
        loop {
            match self
                .update_nickname_under_lifecycle(&token, nickname.as_deref())
                .await
            {
                Ok(snapshot) => return Ok(snapshot),
                Err(SessionBoundRequestError::Api(error))
                    if error.is_unauthorized() && !retried =>
                {
                    retried = true;
                    token = self.refresh_access(Some(&token), true).await?;
                }
                Err(SessionBoundRequestError::Auth(
                    AuthError::SessionChanged | AuthError::CredentialChanged,
                )) if !retried => {
                    retried = true;
                    token = self.refresh_access(Some(&token), true).await?;
                }
                Err(SessionBoundRequestError::Api(error)) => return Err(error.into()),
                Err(SessionBoundRequestError::Auth(error)) => return Err(error),
            }
        }
    }

    async fn update_nickname_under_lifecycle(
        self: &Arc<Self>,
        token: &Arc<Secret>,
        nickname: Option<&str>,
    ) -> Result<AuthSnapshot, SessionBoundRequestError> {
        let _local_lifecycle = Arc::clone(&self.refresh_gate).lock_owned().await;
        let _process_lifecycle = self
            .process_lock
            .acquire()
            .await
            .map_err(AuthError::from)
            .map_err(SessionBoundRequestError::Auth)?;
        let identity = self
            .recheck_locked_session(token)
            .await
            .map_err(SessionBoundRequestError::Auth)?;
        let profile = self
            .api
            .update_nickname(token, nickname)
            .await
            .map_err(SessionBoundRequestError::Api)?;

        let mut state = self.state.lock().await;
        if !state
            .access
            .as_ref()
            .is_some_and(|access| Arc::ptr_eq(token, &access.token))
        {
            return Err(SessionBoundRequestError::Auth(AuthError::SessionChanged));
        }
        profile
            .validate()
            .map_err(AuthError::from)
            .map_err(SessionBoundRequestError::Auth)?;
        let response_user_id = Uuid::parse_str(&profile.user_id)
            .map_err(|_| AuthError::from(ContractError::InvalidField("userId")))
            .map_err(SessionBoundRequestError::Auth)?;
        if response_user_id != identity.user_id {
            return Err(SessionBoundRequestError::Auth(AuthError::from(
                ContractError::InvalidField("userId"),
            )));
        }
        if profile.launcher_nick.as_deref() != nickname {
            return Err(SessionBoundRequestError::Auth(AuthError::from(
                ContractError::InvalidField("launcherNick"),
            )));
        }
        state.profile = Some(profile);
        Ok(state
            .profile
            .clone()
            .map(AuthSnapshot::authenticated)
            .unwrap_or_else(AuthSnapshot::signed_out))
    }

    /// Performs a UI-facing admission preview. The final Java spawn path must use
    /// `launch_admission`, which requests a non-cacheable live decision.
    pub async fn admission(
        self: &Arc<Self>,
        channel: AdmissionChannel,
    ) -> Result<LauncherAdmissionSnapshot, AuthError> {
        let (response, used_token) = match self.request_launcher_admission(channel).await {
            Ok(result) => result,
            Err(AdmissionRequestError::Auth(AuthError::SignedOut)) => {
                return Ok(LauncherAdmissionSnapshot::denied(
                    channel,
                    super::types::LauncherAdmissionReason::InvalidSession,
                ));
            }
            Err(AdmissionRequestError::Auth(error)) => return Err(error),
            Err(AdmissionRequestError::Api(error)) => return admission_failure(channel, error),
        };

        let profile = self
            .derive_admission_profile(&used_token, &response)
            .await?;
        Ok(LauncherAdmissionSnapshot::allowed(channel, profile))
    }

    /// Returns a non-cloneable admission lease for exactly one immediate process creation. The
    /// final versioned FragmentApi request runs while both lifecycle locks are held, and the locks
    /// remain owned by the returned value through CreateProcess.
    pub(crate) async fn launch_admission(
        self: &Arc<Self>,
        channel: AdmissionChannel,
    ) -> Result<LaunchAdmissionLease, LaunchAdmissionError> {
        let mut token = self
            .access_for_request()
            .await
            .map_err(launch_auth_failure)?;
        let mut retried = false;
        loop {
            match self.launch_admission_under_lifecycle(&token, channel).await {
                Ok(lease) => return Ok(lease),
                Err(SessionBoundRequestError::Api(error))
                    if error.is_unauthorized() && !retried =>
                {
                    retried = true;
                    token = self
                        .refresh_access(Some(&token), true)
                        .await
                        .map_err(launch_auth_failure)?;
                }
                Err(SessionBoundRequestError::Auth(
                    AuthError::SessionChanged | AuthError::CredentialChanged,
                )) if !retried => {
                    retried = true;
                    token = self
                        .refresh_access(Some(&token), true)
                        .await
                        .map_err(launch_auth_failure)?;
                }
                Err(SessionBoundRequestError::Api(error)) => {
                    return Err(launch_admission_failure(error));
                }
                Err(SessionBoundRequestError::Auth(error)) => {
                    return Err(launch_auth_failure(error));
                }
            }
        }
    }

    async fn launch_admission_under_lifecycle(
        self: &Arc<Self>,
        token: &Arc<Secret>,
        channel: AdmissionChannel,
    ) -> Result<LaunchAdmissionLease, SessionBoundRequestError> {
        let local_lifecycle = Arc::clone(&self.refresh_gate).lock_owned().await;
        let process_lifecycle = self
            .process_lock
            .acquire()
            .await
            .map_err(AuthError::from)
            .map_err(SessionBoundRequestError::Auth)?;
        let identity = self
            .recheck_locked_session(token)
            .await
            .map_err(SessionBoundRequestError::Auth)?;

        let response = self
            .api
            .launcher_spawn_admission_v1(token, channel)
            .await
            .map_err(SessionBoundRequestError::Api)?;

        // From the successful response to returning the lease there is deliberately no await:
        // the checked token/user/nickname generation and both lifecycle guards remain exact.
        let admission = VerifiedLaunchAdmission::from_response(response, channel, Timestamp::now())
            .map_err(AuthError::from)
            .map_err(SessionBoundRequestError::Auth)?;
        if admission.user_id() != identity.user_id
            || identity.launcher_nick.as_deref() != Some(admission.launcher_nick())
        {
            return Err(SessionBoundRequestError::Auth(AuthError::SessionChanged));
        }
        Ok(LaunchAdmissionLease {
            admission,
            _local_lifecycle: local_lifecycle,
            _process_lifecycle: process_lifecycle,
        })
    }

    async fn request_launcher_admission(
        self: &Arc<Self>,
        channel: AdmissionChannel,
    ) -> Result<(LauncherAdmissionResponse, Arc<Secret>), AdmissionRequestError> {
        let first = self
            .access_for_request()
            .await
            .map_err(AdmissionRequestError::Auth)?;
        match self.api.launcher_admission(&first, channel).await {
            Ok(response) => Ok((response, first)),
            Err(error) if error.is_unauthorized() => {
                let second = self
                    .refresh_access(Some(&first), true)
                    .await
                    .map_err(AdmissionRequestError::Auth)?;
                self.api
                    .launcher_admission(&second, channel)
                    .await
                    .map(|response| (response, second))
                    .map_err(AdmissionRequestError::Api)
            }
            Err(error) => Err(AdmissionRequestError::Api(error)),
        }
    }

    async fn derive_admission_profile(
        &self,
        used_token: &Arc<Secret>,
        response: &LauncherAdmissionResponse,
    ) -> Result<LauncherProfile, AuthError> {
        let state = self.state.lock().await;
        if !state
            .access
            .as_ref()
            .is_some_and(|access| Arc::ptr_eq(used_token, &access.token))
        {
            return Err(AuthError::SessionChanged);
        }
        let mut profile = state.profile.clone().ok_or(AuthError::SessionChanged)?;
        if profile.user_id != response.user_id {
            return Err(ContractError::InvalidField("userId").into());
        }
        profile.launcher_nick = Some(response.launcher_nick.clone());
        profile.launcher_role = response.launcher_role;
        profile.launcher_permissions = response.launcher_permissions.clone();
        profile.subscription_level = response.entitlement.level;
        profile.entitlement = response.entitlement.clone();
        Ok(profile)
    }

    /// Must only be called while the caller owns both `refresh_gate` and `process_lock`.
    /// The persisted credential fingerprint binds the RAM access token/profile to the exact
    /// cross-process session generation which won the most recent refresh-token rotation.
    async fn recheck_locked_session(
        &self,
        token: &Arc<Secret>,
    ) -> Result<LockedSessionIdentity, AuthError> {
        let persisted = self
            .credentials
            .load()
            .await?
            .ok_or(AuthError::CredentialChanged)?;
        validate_refresh_token(&persisted).map_err(|_| AuthError::CredentialChanged)?;
        let persisted_fingerprint = refresh_fingerprint(&persisted);

        let state = self.state.lock().await;
        let access = state.access.as_ref().ok_or(AuthError::SessionChanged)?;
        if !Arc::ptr_eq(token, &access.token) {
            return Err(AuthError::SessionChanged);
        }
        if access.refresh_fingerprint != persisted_fingerprint {
            return Err(AuthError::CredentialChanged);
        }
        let profile = state.profile.as_ref().ok_or(AuthError::SessionChanged)?;
        profile.validate().map_err(AuthError::from)?;
        let user_id = Uuid::parse_str(&profile.user_id)
            .map_err(|_| AuthError::from(ContractError::InvalidField("userId")))?;
        Ok(LockedSessionIdentity {
            user_id,
            launcher_nick: profile.launcher_nick.clone(),
        })
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

    async fn access_for_request(self: &Arc<Self>) -> Result<Arc<Secret>, AuthError> {
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
        self: &Arc<Self>,
        rejected: Option<&Arc<Secret>>,
        force: bool,
    ) -> Result<Arc<Secret>, AuthError> {
        let manager = Arc::clone(self);
        let rejected = rejected.cloned();
        tokio::spawn(async move { manager.refresh_access_core(rejected.as_ref(), force).await })
            .await
            .map_err(|_| AuthError::Api("auth refresh worker failed".into()))?
    }

    async fn refresh_access_core(
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
                let is_fresh = access.refresh_at > Instant::now();
                if is_fresh && (was_replaced || !force) {
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
        let refresh_fingerprint = refresh_fingerprint(&response.refresh_token);
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
            refresh_fingerprint,
        });
        Ok(token)
    }

    async fn commit_profile_response(
        &self,
        token: &Arc<Secret>,
        expected_user_id: Uuid,
        profile: LauncherProfile,
    ) -> Result<AuthSnapshot, AuthError> {
        profile.validate().map_err(AuthError::from)?;
        let response_user_id = Uuid::parse_str(&profile.user_id)
            .map_err(|_| AuthError::from(ContractError::InvalidField("userId")))?;
        if response_user_id != expected_user_id {
            return Err(AuthError::from(ContractError::InvalidField("userId")));
        }
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

fn launch_admission_failure(error: ApiError) -> LaunchAdmissionError {
    if error.is_unauthorized() {
        LaunchAdmissionError::Denied(LauncherAdmissionReason::InvalidSession)
    } else if let Some(reason) = error.admission_reason() {
        LaunchAdmissionError::Denied(reason)
    } else {
        LaunchAdmissionError::Auth(error.into())
    }
}

fn launch_auth_failure(error: AuthError) -> LaunchAdmissionError {
    match error {
        AuthError::SignedOut => {
            LaunchAdmissionError::Denied(LauncherAdmissionReason::InvalidSession)
        }
        other => LaunchAdmissionError::Auth(other),
    }
}

fn refresh_fingerprint(refresh: &Secret) -> [u8; 32] {
    Sha256::digest(refresh.expose().as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use std::{
        collections::VecDeque,
        sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    };

    use async_trait::async_trait;
    use jiff::SignedDuration;

    use super::*;
    use crate::auth::credential_store::MemoryCredentialStore;
    use crate::auth::process_lock::{MemoryRefreshProcessLock, ProcessLockError};
    use crate::auth::types::LauncherSpawnAdmissionResponse;
    use crate::auth::types::{
        EntitlementSnapshot, LauncherAdmissionReason, LauncherAdmissionResponse, LauncherRole,
        PollStatus, SubscriptionLevel, TelegramChallengeResponse, TokenType,
    };

    struct FakeApi {
        refreshes: AtomicUsize,
        active_refreshes: AtomicUsize,
        max_active_refreshes: AtomicUsize,
        profile_gets: AtomicUsize,
        nickname_calls: AtomicUsize,
        admission_calls: AtomicUsize,
        spawn_admission_calls: AtomicUsize,
        logouts: AtomicUsize,
        confirm_next_poll: AtomicBool,
        reject_next_get: AtomicBool,
        reject_all_get: AtomicBool,
        reject_next_refresh: AtomicBool,
        reject_next_nickname: AtomicBool,
        reject_all_nickname: AtomicBool,
        reject_next_admission: AtomicBool,
        reject_all_admissions: AtomicBool,
        fail_logout: AtomicBool,
        admission_error: std::sync::Mutex<Option<&'static str>>,
        admission_timestamp: std::sync::Mutex<Option<String>>,
        gate_next_admission: AtomicBool,
        admission_started: tokio::sync::Notify,
        allow_admission: tokio::sync::Notify,
        gate_next_nickname: AtomicBool,
        nickname_started: tokio::sync::Notify,
        allow_nickname: tokio::sync::Notify,
        gate_next_profile_get: AtomicBool,
        profile_get_started: tokio::sync::Notify,
        allow_profile_get: tokio::sync::Notify,
        current_nickname: std::sync::Mutex<Option<String>>,
        scripted_patch_response_nicknames: std::sync::Mutex<VecDeque<Option<String>>>,
        spawn_access_generations: std::sync::Mutex<Vec<usize>>,
        spawn_purpose: std::sync::Mutex<String>,
        spawn_contract_version: std::sync::Mutex<u32>,
        scripted_spawn_nicknames: std::sync::Mutex<VecDeque<String>>,
        scripted_expires_in: std::sync::Mutex<VecDeque<u64>>,
    }

    struct GatedCredentialStore {
        inner: MemoryCredentialStore,
        gate_next_replace: AtomicBool,
        replace_started: tokio::sync::Notify,
        allow_replace: tokio::sync::Notify,
    }

    impl GatedCredentialStore {
        fn with(value: Secret) -> Self {
            Self::with_gate(value, true)
        }

        fn unarmed(value: Secret) -> Self {
            Self::with_gate(value, false)
        }

        fn with_gate(value: Secret, armed: bool) -> Self {
            Self {
                inner: MemoryCredentialStore::with(value),
                gate_next_replace: AtomicBool::new(armed),
                replace_started: tokio::sync::Notify::new(),
                allow_replace: tokio::sync::Notify::new(),
            }
        }

        fn arm_next_replace(&self) {
            assert!(!self.gate_next_replace.swap(true, Ordering::AcqRel));
        }

        async fn wait_until_replace_started(&self) {
            if !self.gate_next_replace.load(Ordering::Acquire) {
                return;
            }
            loop {
                let notified = self.replace_started.notified();
                if !self.gate_next_replace.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        }

        fn release_replace(&self) {
            self.allow_replace.notify_one();
        }

        async fn peek(&self) -> Option<String> {
            self.inner.peek().await
        }

        fn writes(&self) -> usize {
            self.inner.writes()
        }
    }

    #[async_trait]
    impl CredentialStore for GatedCredentialStore {
        async fn load(&self) -> Result<Option<Secret>, CredentialStoreError> {
            self.inner.load().await
        }

        async fn replace_if_current(
            &self,
            expected: Option<&Secret>,
            next: &Secret,
        ) -> Result<CredentialMutation, CredentialStoreError> {
            if self.gate_next_replace.swap(false, Ordering::AcqRel) {
                self.replace_started.notify_one();
                self.allow_replace.notified().await;
            }
            self.inner.replace_if_current(expected, next).await
        }

        async fn clear_if_current(
            &self,
            expected: &Secret,
        ) -> Result<CredentialMutation, CredentialStoreError> {
            self.inner.clear_if_current(expected).await
        }
    }

    impl FakeApi {
        fn new() -> Self {
            Self {
                refreshes: AtomicUsize::new(0),
                active_refreshes: AtomicUsize::new(0),
                max_active_refreshes: AtomicUsize::new(0),
                profile_gets: AtomicUsize::new(0),
                nickname_calls: AtomicUsize::new(0),
                admission_calls: AtomicUsize::new(0),
                spawn_admission_calls: AtomicUsize::new(0),
                logouts: AtomicUsize::new(0),
                confirm_next_poll: AtomicBool::new(false),
                reject_next_get: AtomicBool::new(false),
                reject_all_get: AtomicBool::new(false),
                reject_next_refresh: AtomicBool::new(false),
                reject_next_nickname: AtomicBool::new(false),
                reject_all_nickname: AtomicBool::new(false),
                reject_next_admission: AtomicBool::new(false),
                reject_all_admissions: AtomicBool::new(false),
                fail_logout: AtomicBool::new(false),
                admission_error: std::sync::Mutex::new(None),
                admission_timestamp: std::sync::Mutex::new(None),
                gate_next_admission: AtomicBool::new(false),
                admission_started: tokio::sync::Notify::new(),
                allow_admission: tokio::sync::Notify::new(),
                gate_next_nickname: AtomicBool::new(false),
                nickname_started: tokio::sync::Notify::new(),
                allow_nickname: tokio::sync::Notify::new(),
                gate_next_profile_get: AtomicBool::new(false),
                profile_get_started: tokio::sync::Notify::new(),
                allow_profile_get: tokio::sync::Notify::new(),
                current_nickname: std::sync::Mutex::new(Some("Player_1".into())),
                scripted_patch_response_nicknames: std::sync::Mutex::new(VecDeque::new()),
                spawn_access_generations: std::sync::Mutex::new(Vec::new()),
                spawn_purpose: std::sync::Mutex::new(
                    super::super::types::LAUNCH_SPAWN_PURPOSE.into(),
                ),
                spawn_contract_version: std::sync::Mutex::new(
                    super::super::types::LAUNCH_SPAWN_CONTRACT_VERSION,
                ),
                scripted_spawn_nicknames: std::sync::Mutex::new(VecDeque::new()),
                scripted_expires_in: std::sync::Mutex::new(VecDeque::new()),
            }
        }

        fn script_expires_in(&self, values: impl IntoIterator<Item = u64>) {
            self.scripted_expires_in.lock().unwrap().extend(values);
        }

        fn set_admission_timestamp(&self, value: impl Into<String>) {
            *self.admission_timestamp.lock().unwrap() = Some(value.into());
        }

        fn arm_next_admission(&self) {
            assert!(!self.gate_next_admission.swap(true, Ordering::AcqRel));
        }

        async fn wait_until_admission_started(&self) {
            if !self.gate_next_admission.load(Ordering::Acquire) {
                return;
            }
            loop {
                let notified = self.admission_started.notified();
                if !self.gate_next_admission.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        }

        fn release_admission(&self) {
            self.allow_admission.notify_one();
        }

        fn arm_next_nickname(&self) {
            assert!(!self.gate_next_nickname.swap(true, Ordering::AcqRel));
        }

        async fn wait_until_nickname_started(&self) {
            if !self.gate_next_nickname.load(Ordering::Acquire) {
                return;
            }
            loop {
                let notified = self.nickname_started.notified();
                if !self.gate_next_nickname.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        }

        fn release_nickname(&self) {
            self.allow_nickname.notify_one();
        }

        fn arm_next_profile_get(&self) {
            assert!(!self.gate_next_profile_get.swap(true, Ordering::AcqRel));
        }

        async fn wait_until_profile_get_started(&self) {
            if !self.gate_next_profile_get.load(Ordering::Acquire) {
                return;
            }
            loop {
                let notified = self.profile_get_started.notified();
                if !self.gate_next_profile_get.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        }

        fn release_profile_get(&self) {
            self.allow_profile_get.notify_one();
        }

        fn script_patch_response_nicknames(
            &self,
            values: impl IntoIterator<Item = Option<&'static str>>,
        ) {
            self.scripted_patch_response_nicknames
                .lock()
                .unwrap()
                .extend(values.into_iter().map(|value| value.map(str::to_owned)));
        }

        fn current_profile(&self) -> LauncherProfile {
            let mut profile = profile();
            profile.launcher_nick = self.current_nickname.lock().unwrap().clone();
            profile
        }

        fn set_spawn_proof(&self, purpose: &str, contract_version: u32) {
            *self.spawn_purpose.lock().unwrap() = purpose.to_owned();
            *self.spawn_contract_version.lock().unwrap() = contract_version;
        }

        fn script_spawn_nicknames(&self, values: impl IntoIterator<Item = &'static str>) {
            self.scripted_spawn_nicknames
                .lock()
                .unwrap()
                .extend(values.into_iter().map(str::to_owned));
        }

        async fn before_admission(
            &self,
            access_token: &Secret,
            spawn: bool,
        ) -> Result<(), ApiError> {
            self.admission_calls.fetch_add(1, Ordering::SeqCst);
            if spawn {
                self.spawn_admission_calls.fetch_add(1, Ordering::SeqCst);
                let generation = access_token
                    .expose()
                    .split('-')
                    .nth(1)
                    .and_then(|value| value.parse::<usize>().ok())
                    .unwrap_or(usize::MAX);
                self.spawn_access_generations
                    .lock()
                    .unwrap()
                    .push(generation);
            }
            if self.gate_next_admission.swap(false, Ordering::AcqRel) {
                self.admission_started.notify_one();
                self.allow_admission.notified().await;
            }
            if self.reject_all_admissions.load(Ordering::SeqCst)
                || self.reject_next_admission.swap(false, Ordering::SeqCst)
            {
                return Err(ApiError::Unauthorized);
            }
            if let Some(code) = *self.admission_error.lock().unwrap() {
                return Err(ApiError::Http {
                    status: 403,
                    code: Some(code.into()),
                    message: String::new(),
                });
            }
            Ok(())
        }

        fn session(&self) -> SessionResponse {
            let generation = self.refreshes.load(Ordering::SeqCst);
            SessionResponse {
                token_type: TokenType::Bearer,
                access_token: Secret::new(format!("access-{generation}-{}", "a".repeat(32)))
                    .unwrap(),
                refresh_token: Secret::new(format!("refresh-{generation}-{}", "r".repeat(32)))
                    .unwrap(),
                expires_in: self
                    .scripted_expires_in
                    .lock()
                    .unwrap()
                    .pop_front()
                    .unwrap_or(900),
                profile: self.current_profile(),
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
            let response = self.current_profile();
            if self.gate_next_profile_get.swap(false, Ordering::AcqRel) {
                self.profile_get_started.notify_one();
                self.allow_profile_get.notified().await;
            }
            if self.reject_all_get.load(Ordering::SeqCst)
                || self.reject_next_get.swap(false, Ordering::SeqCst)
            {
                Err(ApiError::Unauthorized)
            } else {
                Ok(response)
            }
        }

        async fn update_nickname(
            &self,
            _access_token: &Secret,
            nickname: Option<&str>,
        ) -> Result<LauncherProfile, ApiError> {
            self.nickname_calls.fetch_add(1, Ordering::SeqCst);
            if self.gate_next_nickname.swap(false, Ordering::AcqRel) {
                self.nickname_started.notify_one();
                self.allow_nickname.notified().await;
            }
            if self.reject_all_nickname.load(Ordering::SeqCst)
                || self.reject_next_nickname.swap(false, Ordering::SeqCst)
            {
                return Err(ApiError::Unauthorized);
            }
            *self.current_nickname.lock().unwrap() = nickname.map(str::to_owned);
            let mut response = self.current_profile();
            if let Some(scripted) = self
                .scripted_patch_response_nicknames
                .lock()
                .unwrap()
                .pop_front()
            {
                response.launcher_nick = scripted;
            }
            Ok(response)
        }

        async fn launcher_admission(
            &self,
            access_token: &Secret,
            channel: AdmissionChannel,
        ) -> Result<LauncherAdmissionResponse, ApiError> {
            self.before_admission(access_token, false).await?;
            let profile = self.current_profile();
            Ok(LauncherAdmissionResponse {
                allowed: true,
                channel,
                admitted_at: self
                    .admission_timestamp
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| Timestamp::now().to_string()),
                session_id: "660e8400-e29b-41d4-a716-446655440000".into(),
                user_id: profile.user_id,
                launcher_nick: profile.launcher_nick.unwrap(),
                launcher_role: profile.launcher_role,
                launcher_permissions: profile.launcher_permissions,
                entitlement: profile.entitlement,
            })
        }

        async fn launcher_spawn_admission_v1(
            &self,
            access_token: &Secret,
            channel: AdmissionChannel,
        ) -> Result<LauncherSpawnAdmissionResponse, ApiError> {
            self.before_admission(access_token, true).await?;
            let mut profile = self.current_profile();
            if let Some(scripted) = self.scripted_spawn_nicknames.lock().unwrap().pop_front() {
                profile.launcher_nick = Some(scripted);
            }
            Ok(LauncherSpawnAdmissionResponse {
                purpose: self.spawn_purpose.lock().unwrap().clone(),
                contract_version: *self.spawn_contract_version.lock().unwrap(),
                allowed: true,
                channel,
                admitted_at: self
                    .admission_timestamp
                    .lock()
                    .unwrap()
                    .clone()
                    .unwrap_or_else(|| Timestamp::now().to_string()),
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

    #[test]
    fn native_access_failure_matrix_blocks_only_a_definite_signed_out_state() {
        assert_eq!(
            AuthError::SignedOut.into_native_access_failure(),
            NativeAccessFailure::Authentication
        );
        for error in [
            AuthError::Api("transport".into()),
            AuthError::Credentials("store".into()),
            AuthError::Contract("contract".into()),
            AuthError::ProcessLock("lock".into()),
            AuthError::CredentialChanged,
            AuthError::SessionChanged,
            AuthError::NoActiveChallenge,
            AuthError::OpenTelegramLogin,
        ] {
            assert!(matches!(
                error.into_native_access_failure(),
                NativeAccessFailure::Failed(_)
            ));
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
    async fn dropping_native_waiter_never_abandons_rotated_credential_persistence() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(GatedCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store.clone()));
        let waiter = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.native_access_token_completion_safe().await }
        });

        store.wait_until_replace_started().await;
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 1);
        assert!(store
            .peek()
            .await
            .unwrap()
            .starts_with("old-refresh-token-"));
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        store.release_replace();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if store
                    .peek()
                    .await
                    .is_some_and(|refresh| refresh.starts_with("refresh-1-"))
                    && manager.snapshot().await.authenticated
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached refresh must finish credential persistence");
    }

    #[tokio::test]
    async fn concurrent_rejection_of_old_token_rotates_again_when_the_winner_is_stale() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        let rejected = manager.native_access_token_completion_safe().await.unwrap();
        api.script_expires_in([1, 900]);
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let rotate = |rejected: NativeAccessToken| {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                manager
                    .native_access_token_after_rejection_completion_safe(rejected)
                    .await
                    .unwrap()
            })
        };
        let first = rotate(rejected.clone());
        let second = rotate(rejected);
        barrier.wait().await;
        let first = first.await.unwrap();
        let second = second.await.unwrap();

        assert_eq!(api.refreshes.load(Ordering::SeqCst), 3);
        let rotated = [first.expose(), second.expose()];
        assert!(rotated.iter().any(|token| token.starts_with("access-2-")));
        assert!(rotated.iter().any(|token| token.starts_with("access-3-")));
        let current = manager.native_access_token_completion_safe().await.unwrap();
        assert!(current.expose().starts_with("access-3-"));
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn aborted_rejected_token_waiter_does_not_duplicate_or_abandon_rotation() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(GatedCredentialStore::unarmed(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store.clone()));
        manager.restore().await.unwrap();
        let rejected = manager.native_access_token_completion_safe().await.unwrap();
        store.arm_next_replace();
        let barrier = Arc::new(tokio::sync::Barrier::new(3));

        let rotate = |rejected: NativeAccessToken| {
            let manager = Arc::clone(&manager);
            let barrier = Arc::clone(&barrier);
            tokio::spawn(async move {
                barrier.wait().await;
                manager
                    .native_access_token_after_rejection_completion_safe(rejected)
                    .await
            })
        };
        let abandoned = rotate(rejected.clone());
        let survivor = rotate(rejected);
        barrier.wait().await;
        store.wait_until_replace_started().await;
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(store.writes(), 1);
        abandoned.abort();
        assert!(abandoned.await.unwrap_err().is_cancelled());
        store.release_replace();

        let winner = survivor.await.unwrap().unwrap();
        assert!(winner.expose().starts_with("access-2-"));
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(store.writes(), 2);
        assert!(store.peek().await.unwrap().starts_with("refresh-2-"));
    }

    #[tokio::test]
    async fn failed_refresh_persistence_never_publishes_access_session() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        store.set_fail_writes(true);
        let manager = Arc::new(AuthSessionManager::new(api, store));

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
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.reject_next_get.store(true, Ordering::SeqCst);

        assert!(manager.refresh_profile().await.unwrap().authenticated);
        assert_eq!(api.profile_gets.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn authenticated_get_makes_no_third_request_after_second_401() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.reject_all_get.store(true, Ordering::SeqCst);

        assert!(matches!(
            manager.refresh_profile().await,
            Err(AuthError::Api(message)) if message.contains("unauthorized")
        ));
        assert_eq!(api.profile_gets.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn profile_get_first_then_nickname_patch_cannot_restore_the_old_profile() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.arm_next_profile_get();
        let refresh = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.refresh_profile().await }
        });
        api.wait_until_profile_get_started().await;
        let patch = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.update_nickname(Some("Newest_Nick")).await }
        });

        api.release_profile_get();
        assert_eq!(
            refresh
                .await
                .unwrap()
                .unwrap()
                .profile
                .unwrap()
                .launcher_nick
                .as_deref(),
            Some("Player_1")
        );
        assert_eq!(
            patch
                .await
                .unwrap()
                .unwrap()
                .profile
                .unwrap()
                .launcher_nick
                .as_deref(),
            Some("Newest_Nick")
        );
        assert_eq!(
            manager
                .snapshot()
                .await
                .profile
                .unwrap()
                .launcher_nick
                .as_deref(),
            Some("Newest_Nick")
        );
    }

    #[tokio::test]
    async fn spawn_lease_blocks_profile_publication_until_linearization_drop() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        let lease = manager
            .launch_admission(AdmissionChannel::Stable)
            .await
            .unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let refresh = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move {
                let _ = started_tx.send(());
                manager.refresh_profile().await
            }
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(api.profile_gets.load(Ordering::SeqCst), 0);

        drop(lease);
        assert!(refresh.await.unwrap().unwrap().authenticated);
        assert_eq!(api.profile_gets.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn ui_snapshots_never_contain_auth_or_challenge_secrets() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api, store));

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
        let manager = Arc::new(AuthSessionManager::new(api, store.clone()));

        assert!(!manager.restore().await.unwrap().authenticated);
        assert!(store.is_empty().await);
    }

    #[tokio::test]
    async fn logout_succeeds_locally_when_network_revocation_fails() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store.clone()));
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
        let manager = Arc::new(AuthSessionManager::new_with_process_lock(
            api,
            store.clone(),
            process_lock.clone(),
        ));
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
        let manager = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock,
        ));
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
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store.clone()));
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
    async fn dropping_confirmed_login_waiter_never_abandons_credential_persistence() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(GatedCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store.clone()));
        manager.begin_login(None).await.unwrap();
        api.confirm_next_poll.store(true, Ordering::SeqCst);
        let waiter = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.poll_login().await }
        });

        store.wait_until_replace_started().await;
        assert!(store
            .peek()
            .await
            .unwrap()
            .starts_with("old-refresh-token-"));
        waiter.abort();
        assert!(waiter.await.unwrap_err().is_cancelled());
        store.release_replace();

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if store
                    .peek()
                    .await
                    .is_some_and(|refresh| refresh.starts_with("refresh-0-"))
                    && manager.snapshot().await.authenticated
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("detached confirmed-login task must persist its credential");
    }

    #[tokio::test]
    async fn separate_managers_reload_rotated_credential_under_shared_process_lock() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_secs(1)));
        let first = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock.clone(),
        ));
        let second = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock,
        ));

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
        let manager = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock,
        ));

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
        let manager = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock,
        ));

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
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.reject_next_admission.store(true, Ordering::SeqCst);

        let admission = manager.admission(AdmissionChannel::Stable).await.unwrap();
        assert!(admission.allowed);
        assert_eq!(admission.role, Some(LauncherRole::Player));
        assert_eq!(api.admission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 0);
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
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
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

    #[tokio::test]
    async fn ui_admission_preview_never_overwrites_the_canonical_profile() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        *api.current_nickname.lock().unwrap() = Some("Preview_Only".into());

        let preview = manager.admission(AdmissionChannel::Stable).await.unwrap();
        assert_eq!(
            preview.profile.unwrap().launcher_nick.as_deref(),
            Some("Preview_Only")
        );
        assert_eq!(
            manager
                .snapshot()
                .await
                .profile
                .unwrap()
                .launcher_nick
                .as_deref(),
            Some("Player_1")
        );
    }

    #[tokio::test]
    async fn launch_admission_is_sealed_fresh_and_preserves_exact_uuid_and_nickname() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();

        let admission = manager
            .launch_admission(AdmissionChannel::Stable)
            .await
            .unwrap();

        assert_eq!(admission.channel(), AdmissionChannel::Stable);
        assert_eq!(
            admission.admission.user_id(),
            Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
        );
        assert_eq!(
            admission.minecraft_uuid(),
            "550e8400e29b41d4a716446655440000"
        );
        assert_eq!(admission.launcher_nick(), "Player_1");
        assert_eq!(
            admission.admission.session_id(),
            Uuid::parse_str("660e8400-e29b-41d4-a716-446655440000").unwrap()
        );
        assert!(
            Timestamp::now().duration_since(admission.admission.admitted_at())
                < SignedDuration::from_secs(5)
        );
        admission.revalidate_fresh(Timestamp::now()).unwrap();
        for invalid_now in [
            admission
                .admission
                .admitted_at()
                .checked_add(SignedDuration::from_secs(31))
                .unwrap(),
            admission
                .admission
                .admitted_at()
                .checked_sub(SignedDuration::from_secs(6))
                .unwrap(),
        ] {
            assert!(matches!(
                admission.revalidate_fresh(invalid_now),
                Err(AuthError::Contract(message)) if message.contains("admittedAt")
            ));
        }
        assert_eq!(api.admission_calls.load(Ordering::SeqCst), 1);
        assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn launch_admission_revalidation_observes_entitlement_expiry() {
        let admitted_at = Timestamp::now();
        let expires_at = admitted_at
            .checked_add(SignedDuration::from_secs(2))
            .unwrap();
        let admission = VerifiedLaunchAdmission::from_response(
            LauncherSpawnAdmissionResponse {
                purpose: super::super::types::LAUNCH_SPAWN_PURPOSE.into(),
                contract_version: super::super::types::LAUNCH_SPAWN_CONTRACT_VERSION,
                allowed: true,
                channel: AdmissionChannel::Stable,
                admitted_at: admitted_at.to_string(),
                session_id: "660e8400-e29b-41d4-a716-446655440000".into(),
                user_id: "550e8400-e29b-41d4-a716-446655440000".into(),
                launcher_nick: "Player_1".into(),
                launcher_role: LauncherRole::Player,
                launcher_permissions: Vec::new(),
                entitlement: EntitlementSnapshot {
                    active: true,
                    level: SubscriptionLevel::Novice,
                    expires_at: Some(expires_at.to_string()),
                    recalculated_at: Some(admitted_at.to_string()),
                },
            },
            AdmissionChannel::Stable,
            admitted_at,
        )
        .unwrap();

        let after_expiry = expires_at
            .checked_add(SignedDuration::from_secs(1))
            .unwrap();
        assert!(matches!(
            admission.revalidate_fresh(after_expiry),
            Err(AuthError::Contract(message)) if message.contains("entitlement.expiresAt")
        ));
    }

    #[tokio::test]
    async fn launch_admission_retries_exactly_one_401_with_versioned_spawn_post() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.reject_next_admission.store(true, Ordering::SeqCst);

        let lease = manager
            .launch_admission(AdmissionChannel::Stable)
            .await
            .unwrap();

        assert_eq!(api.admission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(*api.spawn_access_generations.lock().unwrap(), [1, 2]);
        drop(lease);
    }

    #[tokio::test]
    async fn launch_admission_makes_no_third_request_after_a_second_401() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.reject_all_admissions.store(true, Ordering::SeqCst);

        assert!(matches!(
            manager.launch_admission(AdmissionChannel::Stable).await,
            Err(LaunchAdmissionError::Denied(
                LauncherAdmissionReason::InvalidSession
            ))
        ));
        assert_eq!(api.admission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(*api.spawn_access_generations.lock().unwrap(), [1, 2]);
    }

    #[tokio::test]
    async fn stale_spawn_nickname_is_rejected_refreshed_and_retried_once() {
        let api = Arc::new(FakeApi::new());
        api.script_spawn_nicknames(["Stale_Name"]);
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();

        let lease = manager
            .launch_admission(AdmissionChannel::Stable)
            .await
            .unwrap();
        assert_eq!(lease.launcher_nick(), "Player_1");
        assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(*api.spawn_access_generations.lock().unwrap(), [1, 2]);
        drop(lease);
    }

    #[tokio::test]
    async fn repeated_stale_spawn_nickname_is_terminal_without_a_third_post() {
        let api = Arc::new(FakeApi::new());
        api.script_spawn_nicknames(["Stale_One", "Stale_Two"]);
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();

        assert!(matches!(
            manager.launch_admission(AdmissionChannel::Stable).await,
            Err(LaunchAdmissionError::Auth(AuthError::SessionChanged))
        ));
        assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn launch_admission_rejects_stale_and_future_server_timestamps() {
        for timestamp in ["2000-01-01T00:00:00Z", "2100-01-01T00:00:00Z"] {
            let api = Arc::new(FakeApi::new());
            api.set_admission_timestamp(timestamp);
            let store = Arc::new(MemoryCredentialStore::with(
                Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
            ));
            let manager = Arc::new(AuthSessionManager::new(api, store));
            manager.restore().await.unwrap();

            let error = match manager.launch_admission(AdmissionChannel::Stable).await {
                Ok(_) => panic!("stale or future admission unexpectedly succeeded"),
                Err(error) => error,
            };
            assert!(matches!(
                error,
                LaunchAdmissionError::Auth(AuthError::Contract(message))
                    if message.contains("admittedAt")
            ));
        }
    }

    #[tokio::test]
    async fn launch_admission_holds_local_lifecycle_through_linearization_and_drop() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.arm_next_admission();

        let launch = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.launch_admission(AdmissionChannel::Stable).await }
        });
        api.wait_until_admission_started().await;
        assert!(manager.refresh_gate.try_lock().is_err());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let logout = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move {
                let _ = started_tx.send(());
                manager.logout().await
            }
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(api.logouts.load(Ordering::SeqCst), 0);
        api.release_admission();
        let lease = launch.await.unwrap().unwrap();
        assert!(manager.refresh_gate.try_lock().is_err());
        assert_eq!(api.logouts.load(Ordering::SeqCst), 0);
        drop(lease);
        assert!(!logout.await.unwrap().unwrap().authenticated);
        assert_eq!(api.logouts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn launch_admission_holds_cross_process_session_generation_until_drop() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_secs(1)));
        let first = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock.clone(),
        ));
        let second = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock,
        ));
        first.restore().await.unwrap();
        let lease = first
            .launch_admission(AdmissionChannel::Stable)
            .await
            .unwrap();
        let writes_at_admission = store.writes();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let replacement = tokio::spawn(async move {
            let _ = started_tx.send(());
            second.restore().await
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(store.writes(), writes_at_admission);

        drop(lease);
        assert!(replacement.await.unwrap().unwrap().authenticated);
        assert_eq!(store.writes(), writes_at_admission + 1);
    }

    #[tokio::test]
    async fn cross_process_replacement_before_admission_reloads_exact_session_before_post() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_secs(1)));
        let first = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock.clone(),
        ));
        let second = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store,
            process_lock,
        ));
        first.restore().await.unwrap();
        second.restore().await.unwrap();

        let lease = first
            .launch_admission(AdmissionChannel::Stable)
            .await
            .unwrap();
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 3);
        assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*api.spawn_access_generations.lock().unwrap(), [3]);
        drop(lease);
    }

    #[tokio::test]
    async fn cross_process_logout_before_admission_never_posts_with_the_old_session() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let process_lock = Arc::new(MemoryRefreshProcessLock::new(Duration::from_secs(1)));
        let first = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store.clone(),
            process_lock.clone(),
        ));
        let second = Arc::new(AuthSessionManager::new_with_process_lock(
            api.clone(),
            store,
            process_lock,
        ));
        first.restore().await.unwrap();
        assert!(!second.logout().await.unwrap().authenticated);

        assert!(matches!(
            first.launch_admission(AdmissionChannel::Stable).await,
            Err(LaunchAdmissionError::Denied(
                LauncherAdmissionReason::InvalidSession
            ))
        ));
        assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 0);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn nickname_patch_drops_lifecycle_guards_and_retries_exactly_one_401() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.reject_next_nickname.store(true, Ordering::SeqCst);

        let snapshot = manager.update_nickname(Some("Retry_Nick")).await.unwrap();
        assert_eq!(
            snapshot.profile.unwrap().launcher_nick.as_deref(),
            Some("Retry_Nick")
        );
        assert_eq!(api.nickname_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn nickname_patch_never_makes_a_third_request_after_second_401() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.reject_all_nickname.store(true, Ordering::SeqCst);

        assert!(matches!(
            manager.update_nickname(Some("Never_Set")).await,
            Err(AuthError::Api(message)) if message.contains("unauthorized")
        ));
        assert_eq!(api.nickname_calls.load(Ordering::SeqCst), 2);
        assert_eq!(api.refreshes.load(Ordering::SeqCst), 2);
        assert_eq!(
            api.current_profile().launcher_nick.as_deref(),
            Some("Player_1")
        );
    }

    #[tokio::test]
    async fn nickname_patch_rejects_mismatched_server_nick_without_publishing_it() {
        for scripted in [Some("Wrong_Nick"), None] {
            let api = Arc::new(FakeApi::new());
            api.script_patch_response_nicknames([scripted]);
            let store = Arc::new(MemoryCredentialStore::with(
                Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
            ));
            let manager = Arc::new(AuthSessionManager::new(api, store));
            manager.restore().await.unwrap();

            assert!(matches!(
                manager.update_nickname(Some("Expected_Nick")).await,
                Err(AuthError::Contract(message)) if message.contains("launcherNick")
            ));
            assert_eq!(
                manager
                    .snapshot()
                    .await
                    .profile
                    .unwrap()
                    .launcher_nick
                    .as_deref(),
                Some("Player_1")
            );
        }
    }

    #[tokio::test]
    async fn nickname_patch_first_commits_before_final_admission_and_new_nick_is_sealed() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        api.arm_next_nickname();
        let patch = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.update_nickname(Some("New_Player")).await }
        });
        api.wait_until_nickname_started().await;
        let launch = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move { manager.launch_admission(AdmissionChannel::Stable).await }
        });
        assert!(manager.refresh_gate.try_lock().is_err());
        api.release_nickname();
        assert_eq!(
            patch
                .await
                .unwrap()
                .unwrap()
                .profile
                .unwrap()
                .launcher_nick
                .as_deref(),
            Some("New_Player")
        );
        let lease = launch.await.unwrap().unwrap();
        assert_eq!(lease.launcher_nick(), "New_Player");
        drop(lease);
    }

    #[tokio::test]
    async fn spawn_lease_first_blocks_nickname_patch_until_spawn_linearization_drop() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        let lease = manager
            .launch_admission(AdmissionChannel::Stable)
            .await
            .unwrap();
        assert!(manager.refresh_gate.try_lock().is_err());
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let patch = tokio::spawn({
            let manager = Arc::clone(&manager);
            async move {
                let _ = started_tx.send(());
                manager.update_nickname(Some("After_Spawn")).await
            }
        });
        started_rx.await.unwrap();
        tokio::task::yield_now().await;
        assert_eq!(api.nickname_calls.load(Ordering::SeqCst), 0);
        assert_eq!(lease.launcher_nick(), "Player_1");

        drop(lease);
        let snapshot = patch.await.unwrap().unwrap();
        assert_eq!(
            snapshot.profile.unwrap().launcher_nick.as_deref(),
            Some("After_Spawn")
        );
        assert_eq!(api.nickname_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn wrong_spawn_proof_is_terminal_and_never_refreshes_or_retries() {
        for (purpose, version, expected_field) in [
            ("status_preview", 1, "purpose"),
            ("minecraft_spawn", 2, "contractVersion"),
        ] {
            let api = Arc::new(FakeApi::new());
            api.set_spawn_proof(purpose, version);
            let store = Arc::new(MemoryCredentialStore::with(
                Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
            ));
            let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
            manager.restore().await.unwrap();

            assert!(matches!(
                manager.launch_admission(AdmissionChannel::Stable).await,
                Err(LaunchAdmissionError::Auth(AuthError::Contract(message)))
                    if message.contains(expected_field)
            ));
            assert_eq!(api.spawn_admission_calls.load(Ordering::SeqCst), 1);
            assert_eq!(api.refreshes.load(Ordering::SeqCst), 1);
        }
    }

    #[tokio::test]
    async fn launch_admission_preserves_a_typed_server_denial() {
        let api = Arc::new(FakeApi::new());
        let store = Arc::new(MemoryCredentialStore::with(
            Secret::new("old-refresh-token-".to_owned() + &"r".repeat(32)).unwrap(),
        ));
        let manager = Arc::new(AuthSessionManager::new(api.clone(), store));
        manager.restore().await.unwrap();
        *api.admission_error.lock().unwrap() = Some("subscription_required");

        assert!(matches!(
            manager.launch_admission(AdmissionChannel::Stable).await,
            Err(LaunchAdmissionError::Denied(
                LauncherAdmissionReason::SubscriptionRequired
            ))
        ));
    }
}
