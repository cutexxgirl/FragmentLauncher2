use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// Windows Credential Manager limits generic credential blobs to 2,560 bytes.
pub(crate) const MAX_SECRET_BYTES: usize = 2_560;
pub(crate) const MAX_RESPONSE_BYTES: usize = 64 * 1024;

/// Secret text which is deliberately neither serializable nor printable.
///
/// The inner allocation is overwritten before it is released. This does not
/// protect against copies made by the operating system, allocator, or HTTP
/// stack, but it prevents accidental token disclosure through Rust `Debug`
/// output and ordinary serialization.
pub(crate) struct Secret(Box<str>);

impl Secret {
    pub(crate) fn new(value: String) -> Result<Self, ContractError> {
        if value.is_empty() || value.len() > MAX_SECRET_BYTES {
            return Err(ContractError::InvalidField("secret"));
        }

        Ok(Self(value.into_boxed_str()))
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // SAFETY: replacing UTF-8 bytes with NUL bytes preserves valid UTF-8,
        // and the mutable reference is exclusive while `drop` is running.
        for byte in unsafe { self.0.as_bytes_mut() } {
            // Volatile writes prevent the compiler from removing the wipe as
            // an apparently dead store immediately before deallocation.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SubscriptionLevel {
    None,
    Novice,
    Legend,
    Spark,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LauncherRole {
    Player,
    Tester,
    Developer,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EntitlementSnapshot {
    pub active: bool,
    pub level: SubscriptionLevel,
    pub expires_at: Option<String>,
    pub recalculated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LauncherProfile {
    pub user_id: String,
    pub launcher_nick: Option<String>,
    #[serde(default)]
    pub launcher_nick_updated_at: Option<String>,
    #[serde(default)]
    pub launcher_nick_next_change_at: Option<String>,
    pub telegram_id: Option<String>,
    pub username: Option<String>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    #[serde(default)]
    pub avatar_url: Option<String>,
    #[serde(default)]
    pub telegram_avatar_url: Option<String>,
    #[serde(default)]
    pub photo_url: Option<String>,
    pub fid: Option<String>,
    pub launcher_role: LauncherRole,
    pub launcher_permissions: Vec<String>,
    pub subscription_level: SubscriptionLevel,
    pub entitlement: EntitlementSnapshot,
}

impl LauncherProfile {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        validate_uuid(&self.user_id, "userId")?;
        validate_optional_nickname(&self.launcher_nick)?;
        validate_optional_timestamp(&self.launcher_nick_updated_at, "launcherNickUpdatedAt")?;
        validate_optional_timestamp(
            &self.launcher_nick_next_change_at,
            "launcherNickNextChangeAt",
        )?;
        self.entitlement.validate()?;

        validate_optional_ascii_digits(&self.telegram_id, 20, "telegramId")?;
        validate_optional_text(&self.username, 64, "username")?;
        validate_optional_text(&self.first_name, 256, "firstName")?;
        validate_optional_text(&self.last_name, 256, "lastName")?;
        validate_optional_text(&self.fid, 128, "fid")?;
        validate_optional_url(&self.avatar_url, "avatarUrl")?;
        validate_optional_url(&self.telegram_avatar_url, "telegramAvatarUrl")?;
        validate_optional_url(&self.photo_url, "photoUrl")?;

        validate_launcher_permissions(&self.launcher_permissions)?;

        Ok(())
    }
}

impl EntitlementSnapshot {
    fn validate(&self) -> Result<(), ContractError> {
        validate_optional_timestamp(&self.expires_at, "entitlement.expiresAt")?;
        validate_optional_timestamp(&self.recalculated_at, "entitlement.recalculatedAt")
    }
}

/// Safe UI-facing session state. Tokens are intentionally absent.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AuthSnapshot {
    pub authenticated: bool,
    pub profile: Option<LauncherProfile>,
}

impl AuthSnapshot {
    pub(crate) fn signed_out() -> Self {
        Self {
            authenticated: false,
            profile: None,
        }
    }

    pub(crate) fn authenticated(profile: LauncherProfile) -> Self {
        Self {
            authenticated: true,
            profile: Some(profile),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TelegramLoginSnapshot {
    pub expires_at: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(
    tag = "status",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum TelegramPollSnapshot {
    Pending {
        expires_at: String,
    },
    Expired {
        expires_at: String,
    },
    Consumed {
        expires_at: String,
    },
    Confirmed {
        expires_at: String,
        auth: Box<AuthSnapshot>,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdmissionChannel {
    Stable,
    Dev,
}

impl AdmissionChannel {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Dev => "dev",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LauncherAdmissionReason {
    SubscriptionRequired,
    LauncherNicknameRequired,
    DevAccessRequired,
    AccountBanned,
    EntitlementVerificationUnavailable,
    LauncherAdmissionUnavailable,
    LauncherAdmissionBusy,
    InvalidSession,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct LauncherAdmissionSnapshot {
    pub allowed: bool,
    pub channel: AdmissionChannel,
    pub reason: Option<LauncherAdmissionReason>,
    pub profile: Option<LauncherProfile>,
    pub role: Option<LauncherRole>,
}

impl LauncherAdmissionSnapshot {
    pub(crate) fn denied(channel: AdmissionChannel, reason: LauncherAdmissionReason) -> Self {
        Self {
            allowed: false,
            channel,
            reason: Some(reason),
            profile: None,
            role: None,
        }
    }

    pub(crate) fn allowed(channel: AdmissionChannel, profile: LauncherProfile) -> Self {
        Self {
            allowed: true,
            channel,
            reason: None,
            role: Some(profile.launcher_role),
            profile: Some(profile),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub(crate) enum PollStatus {
    Pending,
    Expired,
    Consumed,
    Confirmed,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
pub(crate) enum TokenType {
    Bearer,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TelegramChallengeResponse {
    pub(crate) challenge_id: String,
    pub(crate) status: PollStatus,
    pub(crate) expires_at: String,
    pub(crate) poll_token: Secret,
    pub(crate) telegram_link: Secret,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct LauncherAdmissionResponse {
    pub(crate) allowed: bool,
    pub(crate) channel: AdmissionChannel,
    pub(crate) admitted_at: String,
    pub(crate) session_id: String,
    pub(crate) user_id: String,
    pub(crate) launcher_nick: String,
    pub(crate) launcher_role: LauncherRole,
    pub(crate) launcher_permissions: Vec<String>,
    pub(crate) entitlement: EntitlementSnapshot,
}

impl LauncherAdmissionResponse {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        if !self.allowed {
            return Err(ContractError::InvalidField("allowed"));
        }
        validate_timestamp(&self.admitted_at, "admittedAt")?;
        validate_uuid(&self.session_id, "sessionId")?;
        validate_uuid(&self.user_id, "userId")?;
        validate_optional_nickname(&Some(self.launcher_nick.clone()))?;
        validate_launcher_permissions(&self.launcher_permissions)?;
        self.entitlement.validate()
    }
}

impl TelegramChallengeResponse {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        validate_uuid(&self.challenge_id, "challengeId")?;
        if self.status != PollStatus::Pending {
            return Err(ContractError::InvalidField("status"));
        }
        validate_timestamp(&self.expires_at, "expiresAt")?;
        validate_poll_token(&self.poll_token)?;
        validate_telegram_link(self.telegram_link.expose())?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SessionResponse {
    pub(crate) token_type: TokenType,
    pub(crate) access_token: Secret,
    pub(crate) refresh_token: Secret,
    pub(crate) expires_in: u64,
    pub(crate) profile: LauncherProfile,
}

impl SessionResponse {
    pub(crate) fn validate(&self) -> Result<(), ContractError> {
        validate_token(&self.access_token, "accessToken")?;
        validate_token(&self.refresh_token, "refreshToken")?;
        if self.token_type != TokenType::Bearer || !(1..=86_400).contains(&self.expires_in) {
            return Err(ContractError::InvalidField("expiresIn"));
        }
        self.profile.validate()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct TelegramPollResponse {
    pub(crate) status: PollStatus,
    pub(crate) expires_at: String,
    #[serde(default)]
    pub(crate) token_type: Option<TokenType>,
    #[serde(default)]
    pub(crate) access_token: Option<Secret>,
    #[serde(default)]
    pub(crate) refresh_token: Option<Secret>,
    #[serde(default)]
    pub(crate) expires_in: Option<u64>,
    #[serde(default)]
    pub(crate) profile: Option<LauncherProfile>,
}

pub(crate) enum TelegramPollOutcome {
    Pending {
        expires_at: String,
    },
    Expired {
        expires_at: String,
    },
    Consumed {
        expires_at: String,
    },
    Confirmed {
        expires_at: String,
        session: Box<SessionResponse>,
    },
}

impl TelegramPollResponse {
    pub(crate) fn into_outcome(self) -> Result<TelegramPollOutcome, ContractError> {
        validate_timestamp(&self.expires_at, "expiresAt")?;

        match self.status {
            PollStatus::Confirmed => {
                let session = SessionResponse {
                    token_type: self
                        .token_type
                        .ok_or(ContractError::MissingField("tokenType"))?,
                    access_token: self
                        .access_token
                        .ok_or(ContractError::MissingField("accessToken"))?,
                    refresh_token: self
                        .refresh_token
                        .ok_or(ContractError::MissingField("refreshToken"))?,
                    expires_in: self
                        .expires_in
                        .ok_or(ContractError::MissingField("expiresIn"))?,
                    profile: self.profile.ok_or(ContractError::MissingField("profile"))?,
                };
                session.validate()?;
                Ok(TelegramPollOutcome::Confirmed {
                    expires_at: self.expires_at,
                    session: Box::new(session),
                })
            }
            PollStatus::Pending | PollStatus::Expired | PollStatus::Consumed => {
                if self.token_type.is_some()
                    || self.access_token.is_some()
                    || self.refresh_token.is_some()
                    || self.expires_in.is_some()
                    || self.profile.is_some()
                {
                    return Err(ContractError::UnexpectedField("session"));
                }

                match self.status {
                    PollStatus::Pending => Ok(TelegramPollOutcome::Pending {
                        expires_at: self.expires_at,
                    }),
                    PollStatus::Expired => Ok(TelegramPollOutcome::Expired {
                        expires_at: self.expires_at,
                    }),
                    PollStatus::Consumed => Ok(TelegramPollOutcome::Consumed {
                        expires_at: self.expires_at,
                    }),
                    PollStatus::Confirmed => unreachable!(),
                }
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BeginChallengeRequest<'a> {
    pub(crate) device_name: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PollChallengeRequest<'a> {
    pub(crate) poll_token: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RefreshRequest<'a> {
    pub(crate) refresh_token: &'a str,
}

#[derive(Debug, Serialize)]
pub(crate) struct NicknameRequest<'a> {
    pub(crate) nickname: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LogoutResponse {
    pub(crate) ok: bool,
}

#[derive(Deserialize)]
pub(crate) struct ApiErrorResponse {
    #[serde(default)]
    pub(crate) message: Option<String>,
    #[serde(default)]
    pub(crate) error: Option<ApiErrorValue>,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub(crate) enum ApiErrorValue {
    Code(String),
    Detail(ApiErrorDetail),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApiErrorDetail {
    #[serde(default)]
    pub(crate) message: Option<String>,
}

impl ApiErrorResponse {
    pub(crate) fn safe_parts(self) -> (Option<String>, Option<String>) {
        let (code, nested_message) = match self.error {
            Some(ApiErrorValue::Code(value)) => (bounded_error_code(value), None),
            Some(ApiErrorValue::Detail(detail)) => (
                None,
                detail
                    .message
                    .and_then(|value| bounded_error_text(value, 512)),
            ),
            None => (None, None),
        };
        let message = self
            .message
            .and_then(|value| bounded_error_text(value, 512))
            .or(nested_message);
        (code, message)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[allow(clippy::enum_variant_names)]
pub(crate) enum ContractError {
    #[error("Fragment API response is missing field {0}")]
    MissingField(&'static str),
    #[error("Fragment API response contains an unexpected {0} field")]
    UnexpectedField(&'static str),
    #[error("Fragment API response field {0} is invalid")]
    InvalidField(&'static str),
}

pub(crate) fn normalize_device_name(value: &str) -> Result<String, ContractError> {
    let value = value.trim();
    if value.is_empty() || value.len() > 120 || value.chars().any(char::is_control) {
        return Err(ContractError::InvalidField("deviceName"));
    }
    Ok(value.to_owned())
}

pub(crate) fn normalize_nickname(value: Option<&str>) -> Result<Option<String>, ContractError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim();
    if value.is_empty() {
        return Ok(None);
    }
    if value.len() > 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ContractError::InvalidField("nickname"));
    }
    Ok(Some(value.to_owned()))
}

pub(crate) fn validate_refresh_token(value: &Secret) -> Result<(), ContractError> {
    validate_token(value, "refreshToken")
}

fn validate_token(value: &Secret, field: &'static str) -> Result<(), ContractError> {
    if value.expose().len() < 32
        || value.expose().len() > MAX_SECRET_BYTES
        || !value
            .expose()
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn validate_poll_token(value: &Secret) -> Result<(), ContractError> {
    let value = value.expose();
    if !(24..=48).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ContractError::InvalidField("pollToken"));
    }
    Ok(())
}

fn validate_optional_nickname(value: &Option<String>) -> Result<(), ContractError> {
    if let Some(value) = value {
        if value.is_empty()
            || value.len() > 16
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        {
            return Err(ContractError::InvalidField("launcherNick"));
        }
    }
    Ok(())
}

fn validate_launcher_permissions(values: &[String]) -> Result<(), ContractError> {
    if values.len() > 32 {
        return Err(ContractError::InvalidField("launcherPermissions"));
    }
    for permission in values {
        if permission.is_empty()
            || permission.len() > 128
            || !permission
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        {
            return Err(ContractError::InvalidField("launcherPermissions"));
        }
    }
    Ok(())
}

fn validate_uuid(value: &str, field: &'static str) -> Result<(), ContractError> {
    Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| ContractError::InvalidField(field))
}

fn validate_timestamp(value: &str, field: &'static str) -> Result<(), ContractError> {
    if value.len() > 64 || jiff::Timestamp::from_str(value).is_err() {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn validate_optional_timestamp(
    value: &Option<String>,
    field: &'static str,
) -> Result<(), ContractError> {
    if let Some(value) = value {
        validate_timestamp(value, field)?;
    }
    Ok(())
}

fn validate_optional_ascii_digits(
    value: &Option<String>,
    max_len: usize,
    field: &'static str,
) -> Result<(), ContractError> {
    if let Some(value) = value {
        if value.is_empty()
            || value.len() > max_len
            || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(ContractError::InvalidField(field));
        }
    }
    Ok(())
}

fn validate_optional_text(
    value: &Option<String>,
    max_len: usize,
    field: &'static str,
) -> Result<(), ContractError> {
    if let Some(value) = value {
        if value.len() > max_len || value.chars().any(char::is_control) {
            return Err(ContractError::InvalidField(field));
        }
    }
    Ok(())
}

fn validate_optional_url(value: &Option<String>, field: &'static str) -> Result<(), ContractError> {
    let Some(value) = value else {
        return Ok(());
    };
    if value.is_empty() || value.len() > 2_048 {
        return Err(ContractError::InvalidField(field));
    }
    if value.starts_with('/')
        && !value.starts_with("//")
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
    {
        return Ok(());
    }
    let parsed = url::Url::parse(value).map_err(|_| ContractError::InvalidField(field))?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(ContractError::InvalidField(field));
    }
    Ok(())
}

fn validate_telegram_link(value: &str) -> Result<(), ContractError> {
    if value.len() > 2_048
        || value.contains('\\')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ContractError::InvalidField("telegramLink"));
    }
    let parsed = url::Url::parse(value).map_err(|_| ContractError::InvalidField("telegramLink"))?;
    if parsed.scheme() != "https"
        || parsed.host_str() != Some("t.me")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.fragment().is_some()
        || parsed.as_str() != value
    {
        return Err(ContractError::InvalidField("telegramLink"));
    }
    let path = parsed.path().strip_prefix('/').unwrap_or_default();
    if path.is_empty()
        || path.contains('/')
        || path.len() > 64
        || !path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        || !path.to_ascii_lowercase().ends_with("bot")
    {
        return Err(ContractError::InvalidField("telegramLink"));
    }
    let query = parsed
        .query()
        .and_then(|query| query.strip_prefix("start=login_"))
        .ok_or(ContractError::InvalidField("telegramLink"))?;
    if !(24..=48).contains(&query.len())
        || !query
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(ContractError::InvalidField("telegramLink"));
    }
    Ok(())
}

fn bounded_error_text(value: String, max_len: usize) -> Option<String> {
    if value.is_empty() || value.len() > max_len || value.chars().any(char::is_control) {
        None
    } else {
        Some(value)
    }
}

fn bounded_error_code(value: String) -> Option<String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        None
    } else {
        Some(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_redacted_and_not_serializable() {
        let secret = Secret::new("a".repeat(32)).expect("valid secret");
        assert_eq!(format!("{secret:?}"), "Secret([REDACTED])");
    }

    #[test]
    fn nickname_matches_api_contract() {
        assert_eq!(
            normalize_nickname(Some(" Player_1 ")).unwrap(),
            Some("Player_1".into())
        );
        assert_eq!(normalize_nickname(Some("  ")).unwrap(), None);
        assert!(normalize_nickname(Some("bad-nick")).is_err());
        assert!(normalize_nickname(Some("0123456789abcdefg")).is_err());
    }

    #[test]
    fn poll_without_tokens_rejects_injected_session_fields() {
        let response = TelegramPollResponse {
            status: PollStatus::Pending,
            expires_at: "2026-07-11T12:00:00Z".into(),
            token_type: None,
            access_token: Some(Secret::new("a".repeat(32)).unwrap()),
            refresh_token: None,
            expires_in: None,
            profile: None,
        };
        assert_eq!(
            response.into_outcome().err(),
            Some(ContractError::UnexpectedField("session"))
        );
    }

    #[test]
    fn poll_snapshot_uses_camel_case_and_contains_no_native_state() {
        let snapshot = TelegramPollSnapshot::Pending {
            expires_at: "2026-07-11T12:00:00Z".into(),
        };
        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(json.contains("expiresAt"));
        assert!(!json.contains("expires_at"));
        assert!(!json.contains("challenge"));
        assert!(!json.contains("token"));
    }

    #[test]
    fn telegram_link_requires_exact_bot_start_contract() {
        let valid = format!("https://t.me/fragment_bot?start=login_{}", "a".repeat(24));
        assert!(validate_telegram_link(&valid).is_ok());
        for invalid in [
            "https://t.me/fragment_bot?start=login_short".to_string(),
            format!(
                "https://t.me/fragment_bot?start=login_{}&next=evil",
                "a".repeat(24)
            ),
            format!("https://t.me/not-a-bot?start=login_{}", "a".repeat(24)),
            format!("https://t.me/fragment_bot?start=login_{}\n", "a".repeat(24)),
        ] {
            assert!(validate_telegram_link(&invalid).is_err(), "{invalid}");
        }
    }
}
