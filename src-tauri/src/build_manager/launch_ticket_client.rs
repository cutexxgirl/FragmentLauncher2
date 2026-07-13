use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{Signature, VerifyingKey};
use futures_util::StreamExt;
use jiff::Timestamp;
use reqwest::{
    header::{
        self, HeaderMap, HeaderValue, ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING,
        CONTENT_TYPE,
    },
    redirect::Policy,
    Client, Response, StatusCode,
};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroize;

use super::types::{BuildChannel, PresetId};
use crate::auth::LauncherRole;

const LAUNCH_TICKET_URL: &str = "https://fragmc.ru/api/spark2/v1/launch-ticket";
const LAUNCH_KEYS_URL: &str = "https://fragmc.ru/api/spark2/v1/launch-keys";
const LAUNCH_TICKET_PATH: &str = "/api/spark2/v1/launch-ticket";
const LAUNCH_KEYS_PATH: &str = "/api/spark2/v1/launch-keys";
const MAX_RESPONSE_BYTES: usize = 16 * 1024;
const MAX_TICKET_BYTES: usize = 4 * 1024;
const MAX_ACCESS_TOKEN_BYTES: usize = 2_560;
const MAX_LAUNCH_KEYS: usize = 9;
const MAX_LAUNCH_TICKET_LIFETIME: Duration = Duration::from_secs(60);
const MAX_CLOCK_SKEW_SECONDS: i64 = 5;
const KEY_CACHE_LIFETIME: Duration = Duration::from_secs(30);
const MAX_RETRY_AFTER: Duration = Duration::from_secs(5);
const PURPOSE: &str = "launch_ticket";
const CONTRACT_VERSION: u32 = 1;
const ISSUER: &str = "fragment-spark2";
const AUDIENCE: &str = "fragment-launch-guard";
const JWS_TYPE: &str = "fragment-launch+jwt";
const BINDING_HASH_DOMAIN: &str = "ru.fragmc.spark2.launch-binding.v3";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LaunchTicketForbiddenReason {
    SubscriptionRequired,
    DevAccessRequired,
    AccountBanned,
    EntitlementUnavailable,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LaunchTicketConflictReason {
    ReleaseChanged,
    ChallengeRejected,
    ChallengeConflict,
    IdentityChanged,
    NicknameRequired,
    Other,
}

#[derive(Debug, Error)]
pub(super) enum LaunchTicketClientError {
    #[error("Spark launch-ticket authentication was rejected")]
    Authentication,
    #[error("Spark launch-ticket authorization was denied ({0:?})")]
    Forbidden(LaunchTicketForbiddenReason),
    #[error("Spark launch-ticket binding was rejected ({0:?})")]
    Conflict(LaunchTicketConflictReason),
    #[error("Spark launch-ticket service is temporarily unavailable")]
    Retryable { retry_after: Option<Duration> },
    #[error("Spark launch-ticket response exceeded its size limit")]
    ResponseTooLarge,
    #[error("Spark launch-ticket response was not exact JSON")]
    InvalidContentType,
    #[error("Spark launch-ticket contract or signature was invalid")]
    InvalidResponse,
    #[error("Spark launch-ticket endpoint returned HTTP {0}")]
    Http(StatusCode),
    #[error("Spark launch-ticket request context was invalid")]
    InvalidRequest,
    #[error("Spark launch-ticket client could not be initialized")]
    ClientSetup,
}

impl LaunchTicketClientError {
    pub(super) const fn requires_token_rotation(&self) -> bool {
        matches!(self, Self::Authentication)
    }

    pub(super) const fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable { .. })
    }

    pub(super) const fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Retryable { retry_after } => *retry_after,
            _ => None,
        }
    }
}

/// The immutable Fragment identity which was admitted for the already-running Java process.
/// These values are request preconditions; Spark remains the identity authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExpectedLaunchIdentity {
    user_id: Uuid,
    device_session_id: Uuid,
    launcher_nick: String,
    launcher_role: LauncherRole,
}

impl ExpectedLaunchIdentity {
    pub(super) fn new(
        user_id: Uuid,
        device_session_id: Uuid,
        launcher_nick: String,
        launcher_role: LauncherRole,
    ) -> Result<Self, LaunchTicketClientError> {
        if user_id.is_nil() || device_session_id.is_nil() || !valid_nickname(&launcher_nick) {
            return Err(LaunchTicketClientError::InvalidRequest);
        }
        Ok(Self {
            user_id,
            device_session_id,
            launcher_nick,
            launcher_role,
        })
    }

    pub(super) const fn user_id(&self) -> Uuid {
        self.user_id
    }

    pub(super) const fn device_session_id(&self) -> Uuid {
        self.device_session_id
    }

    pub(super) fn launcher_nick(&self) -> &str {
        &self.launcher_nick
    }

    pub(super) const fn launcher_role(&self) -> LauncherRole {
        self.launcher_role
    }
}

/// Exact immutable request identity. Retrying is safe only with this same value and access
/// session; callers must never replace any field after an ambiguous response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LaunchTicketRequestContext {
    channel: BuildChannel,
    preset: PresetId,
    release_id: String,
    challenge_id: Uuid,
    connection_id: Uuid,
    launcher_instance_id: Uuid,
    identity: ExpectedLaunchIdentity,
}

impl LaunchTicketRequestContext {
    pub(super) fn new(
        channel: BuildChannel,
        preset: PresetId,
        release_id: String,
        challenge_id: Uuid,
        connection_id: Uuid,
        launcher_instance_id: Uuid,
        identity: ExpectedLaunchIdentity,
    ) -> Result<Self, LaunchTicketClientError> {
        if !valid_release_id(&release_id)
            || challenge_id.is_nil()
            || connection_id.is_nil()
            || launcher_instance_id.is_nil()
        {
            return Err(LaunchTicketClientError::InvalidRequest);
        }
        Ok(Self {
            channel,
            preset,
            release_id,
            challenge_id,
            connection_id,
            launcher_instance_id,
            identity,
        })
    }

    pub(super) const fn channel(&self) -> BuildChannel {
        self.channel
    }

    pub(super) const fn preset(&self) -> PresetId {
        self.preset
    }

    pub(super) fn release_id(&self) -> &str {
        &self.release_id
    }

    pub(super) const fn challenge_id(&self) -> Uuid {
        self.challenge_id
    }

    pub(super) const fn connection_id(&self) -> Uuid {
        self.connection_id
    }

    pub(super) const fn launcher_instance_id(&self) -> Uuid {
        self.launcher_instance_id
    }

    pub(super) fn identity(&self) -> &ExpectedLaunchIdentity {
        &self.identity
    }
}

/// RAM-only compact ticket. It is intentionally non-cloneable, non-serializable and has no
/// `Display` implementation. The IPC broker should borrow `as_bytes` only for its bounded write.
pub(super) struct ValidatedLaunchTicket {
    ticket: OpaqueTicket,
    expires_at: Timestamp,
    monotonic_deadline: Instant,
}

impl ValidatedLaunchTicket {
    pub(super) fn as_bytes(&self) -> &[u8] {
        self.ticket.as_str().as_bytes()
    }

    pub(super) const fn expires_at(&self) -> Timestamp {
        self.expires_at
    }

    pub(super) const fn monotonic_deadline(&self) -> Instant {
        self.monotonic_deadline
    }

    pub(super) fn revalidate_fresh(&self) -> Result<(), LaunchTicketClientError> {
        if Instant::now() >= self.monotonic_deadline || Timestamp::now() >= self.expires_at {
            return Err(LaunchTicketClientError::InvalidResponse);
        }
        Ok(())
    }

    /// Consumes the validated capability without copying its compact JWS or extending either
    /// deadline. The caller must pass the vector directly, without an intervening await, to the
    /// IPC constructor which owns and zeroizes it on every success and error path.
    pub(super) fn into_delivery_parts(
        self,
    ) -> Result<(Vec<u8>, SystemTime, Instant), LaunchTicketClientError> {
        let Self {
            ticket,
            expires_at,
            monotonic_deadline,
        } = self;
        let seconds = u64::try_from(expires_at.as_second())
            .map_err(|_| LaunchTicketClientError::InvalidResponse)?;
        let expires_at = SystemTime::UNIX_EPOCH
            .checked_add(Duration::from_secs(seconds))
            .ok_or(LaunchTicketClientError::InvalidResponse)?;
        Ok((ticket.into_bytes(), expires_at, monotonic_deadline))
    }
}

impl fmt::Debug for ValidatedLaunchTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedLaunchTicket")
            .field("ticket", &"[REDACTED]")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(super) struct LaunchTicketClient {
    http: Client,
    ticket_url: Url,
    keys_url: Url,
    key_cache: Arc<Mutex<KeyCache>>,
}

impl fmt::Debug for LaunchTicketClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LaunchTicketClient")
            .finish_non_exhaustive()
    }
}

impl LaunchTicketClient {
    pub(super) fn new() -> Result<Self, LaunchTicketClientError> {
        let ticket_url =
            Url::parse(LAUNCH_TICKET_URL).map_err(|_| LaunchTicketClientError::ClientSetup)?;
        let keys_url =
            Url::parse(LAUNCH_KEYS_URL).map_err(|_| LaunchTicketClientError::ClientSetup)?;
        validate_production_url(&ticket_url, LAUNCH_TICKET_PATH)?;
        validate_production_url(&keys_url, LAUNCH_KEYS_PATH)?;
        Self::with_urls(ticket_url, keys_url, true)
    }

    #[cfg(test)]
    fn new_for_test(origin: &str) -> Self {
        let origin = Url::parse(origin).expect("test origin must be a valid URL");
        let ticket_url = origin
            .join(LAUNCH_TICKET_PATH)
            .expect("test ticket URL must be valid");
        let keys_url = origin
            .join(LAUNCH_KEYS_PATH)
            .expect("test key URL must be valid");
        Self::with_urls(ticket_url, keys_url, false).expect("test launch client")
    }

    fn with_urls(
        ticket_url: Url,
        keys_url: Url,
        https_only: bool,
    ) -> Result<Self, LaunchTicketClientError> {
        let http = Client::builder()
            .user_agent(concat!("FragmentLauncher/", env!("CARGO_PKG_VERSION")))
            .redirect(Policy::none())
            .https_only(https_only)
            .connect_timeout(Duration::from_secs(3))
            .read_timeout(Duration::from_secs(12))
            .timeout(Duration::from_secs(12))
            .build()
            .map_err(|_| LaunchTicketClientError::ClientSetup)?;
        Ok(Self {
            http,
            ticket_url,
            keys_url,
            key_cache: Arc::new(Mutex::new(KeyCache::default())),
        })
    }

    /// Performs exactly one HTTP ticket attempt. A caller may rotate once after `Authentication`,
    /// or repeat this exact context once after an ambiguous retryable result; this method never
    /// performs a hidden retry.
    pub(super) async fn issue(
        &self,
        expected: &LaunchTicketRequestContext,
        bearer_token: &str,
    ) -> Result<ValidatedLaunchTicket, LaunchTicketClientError> {
        let authorization = bearer_header(bearer_token)?;
        let request = LaunchTicketRequest::from(expected);
        let request_body =
            serde_json::to_vec(&request).map_err(|_| LaunchTicketClientError::InvalidRequest)?;
        let response = self
            .http
            .post(self.ticket_url.clone())
            .header(ACCEPT, "application/json")
            .header(ACCEPT_ENCODING, "identity")
            .header(CONTENT_TYPE, "application/json")
            .header(AUTHORIZATION, authorization)
            .body(request_body)
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = collect_bounded(response).await?;

        if !status.is_success() {
            return Err(classify_http_error(status, &headers, &body));
        }
        validate_json_response_headers(&headers)?;
        let response: LaunchTicketResponse =
            serde_json::from_slice(&body).map_err(|_| LaunchTicketClientError::InvalidResponse)?;
        let protected = parse_protected_header(response.ticket.as_str())?;
        let key = self.key_for_kid(&protected.kid).await?;
        validate_ticket_response(
            response,
            expected,
            &protected.kid,
            &key,
            Timestamp::now(),
            Instant::now(),
        )
    }

    async fn key_for_kid(&self, kid: &str) -> Result<VerifyingKey, LaunchTicketClientError> {
        if !valid_key_id(kid) {
            return Err(LaunchTicketClientError::InvalidResponse);
        }
        let mut cache = self.key_cache.lock().await;
        let now = Instant::now();
        if cache.expires_at.is_some_and(|expires_at| now < expires_at) {
            if let Some(key) = cache.keys.get(kid) {
                return Ok(*key);
            }
            // A signed ticket with an unknown key ID forces one bounded refresh. There is no
            // second refresh or key guessing path.
        }

        let keys = self.fetch_keys().await?;
        let key = keys
            .get(kid)
            .copied()
            .ok_or(LaunchTicketClientError::InvalidResponse)?;
        cache.keys = keys;
        cache.expires_at = Instant::now().checked_add(KEY_CACHE_LIFETIME);
        Ok(key)
    }

    async fn fetch_keys(&self) -> Result<HashMap<String, VerifyingKey>, LaunchTicketClientError> {
        let response = self
            .http
            .get(self.keys_url.clone())
            .header(ACCEPT, "application/json")
            .header(ACCEPT_ENCODING, "identity")
            .send()
            .await
            .map_err(transport_error)?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = collect_bounded(response).await?;
        if !status.is_success() {
            return Err(classify_keys_http_error(status, &headers));
        }
        validate_json_response_headers(&headers)?;
        let document: LaunchKeysResponse =
            serde_json::from_slice(&body).map_err(|_| LaunchTicketClientError::InvalidResponse)?;
        if document.keys.is_empty() || document.keys.len() > MAX_LAUNCH_KEYS {
            return Err(LaunchTicketClientError::InvalidResponse);
        }
        let mut keys = HashMap::with_capacity(document.keys.len());
        for jwk in document.keys {
            let (kid, key) = jwk.into_verifying_key()?;
            if keys.insert(kid, key).is_some() {
                return Err(LaunchTicketClientError::InvalidResponse);
            }
        }
        Ok(keys)
    }
}

#[derive(Default)]
struct KeyCache {
    keys: HashMap<String, VerifyingKey>,
    expires_at: Option<Instant>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LaunchTicketRequest<'a> {
    channel: BuildChannel,
    preset: PresetId,
    release_id: &'a str,
    challenge_id: Uuid,
    connection_id: Uuid,
    launcher_instance_id: Uuid,
    expected_user_id: Uuid,
    expected_device_session_id: Uuid,
    expected_launcher_nick: &'a str,
    expected_launcher_role: LauncherRole,
}

impl<'a> From<&'a LaunchTicketRequestContext> for LaunchTicketRequest<'a> {
    fn from(value: &'a LaunchTicketRequestContext) -> Self {
        Self {
            channel: value.channel,
            preset: value.preset,
            release_id: &value.release_id,
            challenge_id: value.challenge_id,
            connection_id: value.connection_id,
            launcher_instance_id: value.launcher_instance_id,
            expected_user_id: value.identity.user_id,
            expected_device_session_id: value.identity.device_session_id,
            expected_launcher_nick: &value.identity.launcher_nick,
            expected_launcher_role: value.identity.launcher_role,
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchTicketResponse {
    purpose: String,
    contract_version: u32,
    ticket: OpaqueTicket,
    expires_at: String,
    nonce: CanonicalUuid,
    jti: CanonicalUuid,
    binding: LaunchTicketBinding,
    minecraft_identity: MinecraftIdentity,
    delivery: LaunchTicketDelivery,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchTicketBinding {
    challenge_id: CanonicalUuid,
    connection_id: CanonicalUuid,
    channel: BuildChannel,
    preset: PresetId,
    release_id: String,
    user_id: CanonicalUuid,
    device_session_id: CanonicalUuid,
    launcher_instance_id: CanonicalUuid,
    launcher_nick: String,
    launcher_role: LauncherRole,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MinecraftIdentity {
    player_name: String,
    uuid: String,
    access_token: String,
    user_type: String,
    client_id: String,
    xuid: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchTicketDelivery {
    kind: String,
    audience: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchKeysResponse {
    keys: Vec<LaunchPublicJwk>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LaunchPublicJwk {
    kty: String,
    crv: String,
    x: String,
    kid: String,
    alg: String,
    #[serde(rename = "use")]
    key_use: String,
}

impl LaunchPublicJwk {
    fn into_verifying_key(self) -> Result<(String, VerifyingKey), LaunchTicketClientError> {
        if self.kty != "OKP"
            || self.crv != "Ed25519"
            || self.alg != "EdDSA"
            || self.key_use != "sig"
            || !valid_key_id(&self.kid)
            || self.x.len() != 43
        {
            return Err(LaunchTicketClientError::InvalidResponse);
        }
        let decoded = decode_base64url_bounded(&self.x, 32)?;
        if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != self.x {
            return Err(LaunchTicketClientError::InvalidResponse);
        }
        let bytes: [u8; 32] = decoded
            .try_into()
            .map_err(|_| LaunchTicketClientError::InvalidResponse)?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| LaunchTicketClientError::InvalidResponse)?;
        if key.is_weak() {
            return Err(LaunchTicketClientError::InvalidResponse);
        }
        Ok((self.kid, key))
    }
}

struct OpaqueTicket(String);

impl OpaqueTicket {
    fn new(mut value: String) -> Result<Self, LaunchTicketClientError> {
        if value.len() < 64 || value.len() > MAX_TICKET_BYTES || !valid_compact_jws_text(&value) {
            value.zeroize();
            return Err(LaunchTicketClientError::InvalidResponse);
        }
        Ok(Self(value))
    }

    fn as_str(&self) -> &str {
        &self.0
    }

    fn into_bytes(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0).into_bytes()
    }
}

impl fmt::Debug for OpaqueTicket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OpaqueTicket([REDACTED])")
    }
}

impl Drop for OpaqueTicket {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<'de> Deserialize<'de> for OpaqueTicket {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CanonicalUuid(Uuid);

impl CanonicalUuid {
    const fn get(self) -> Uuid {
        self.0
    }
}

impl<'de> Deserialize<'de> for CanonicalUuid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        let parsed = Uuid::parse_str(&value).map_err(|_| de::Error::custom("invalid UUID"))?;
        if parsed.is_nil() || parsed.hyphenated().to_string() != value {
            return Err(de::Error::custom("non-canonical UUID"));
        }
        Ok(Self(parsed))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtectedHeader {
    alg: String,
    kid: String,
    typ: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct LaunchTicketClaims {
    iss: String,
    aud: String,
    sub: CanonicalUuid,
    jti: CanonicalUuid,
    iat: i64,
    nbf: i64,
    exp: i64,
    user_id: CanonicalUuid,
    device_session_id: CanonicalUuid,
    launcher_instance_id: CanonicalUuid,
    channel: BuildChannel,
    preset: PresetId,
    release_id: String,
    connection_id: CanonicalUuid,
    challenge_id: CanonicalUuid,
    binding_hash: String,
    process_epoch: CanonicalUuid,
    redis_run_id: String,
    launcher_role: LauncherRole,
    launcher_nick: String,
    minecraft_uuid: String,
    nonce: CanonicalUuid,
}

fn validate_ticket_response(
    response: LaunchTicketResponse,
    expected: &LaunchTicketRequestContext,
    expected_kid: &str,
    key: &VerifyingKey,
    wall_now: Timestamp,
    monotonic_now: Instant,
) -> Result<ValidatedLaunchTicket, LaunchTicketClientError> {
    if response.purpose != PURPOSE
        || response.contract_version != CONTRACT_VERSION
        || response.binding.challenge_id.get() != expected.challenge_id
        || response.binding.connection_id.get() != expected.connection_id
        || response.binding.channel != expected.channel
        || response.binding.preset != expected.preset
        || response.binding.release_id != expected.release_id
        || response.binding.user_id.get() != expected.identity.user_id
        || response.binding.device_session_id.get() != expected.identity.device_session_id
        || response.binding.launcher_instance_id.get() != expected.launcher_instance_id
        || response.binding.launcher_nick != expected.identity.launcher_nick
        || response.binding.launcher_role != expected.identity.launcher_role
        || response.minecraft_identity.player_name != expected.identity.launcher_nick
        || response.minecraft_identity.uuid != expected.identity.user_id.simple().to_string()
        || response.minecraft_identity.access_token != "0"
        || response.minecraft_identity.user_type != "legacy"
        || !response.minecraft_identity.client_id.is_empty()
        || !response.minecraft_identity.xuid.is_empty()
        || response.delivery.kind != "local-ipc"
        || response.delivery.audience != AUDIENCE
    {
        return Err(LaunchTicketClientError::InvalidResponse);
    }

    let claims = verify_and_decode_claims(response.ticket.as_str(), expected_kid, key)?;
    let expected_binding_hash = launch_binding_hash(expected)?;
    if claims.iss != ISSUER
        || claims.aud != AUDIENCE
        || claims.sub.get() != expected.identity.user_id
        || claims.user_id.get() != expected.identity.user_id
        || claims.device_session_id.get() != expected.identity.device_session_id
        || claims.launcher_instance_id.get() != expected.launcher_instance_id
        || claims.channel != expected.channel
        || claims.preset != expected.preset
        || claims.release_id != expected.release_id
        || claims.connection_id.get() != expected.connection_id
        || claims.challenge_id.get() != expected.challenge_id
        || claims.launcher_role != expected.identity.launcher_role
        || claims.launcher_nick != expected.identity.launcher_nick
        || claims.minecraft_uuid != expected.identity.user_id.simple().to_string()
        || claims.binding_hash != expected_binding_hash
        || claims.nonce != response.nonce
        || claims.jti != response.jti
        || claims.nbf != claims.iat
        || claims.process_epoch.get().is_nil()
        || !valid_redis_run_id(&claims.redis_run_id)
    {
        return Err(LaunchTicketClientError::InvalidResponse);
    }

    let lifetime = claims
        .exp
        .checked_sub(claims.iat)
        .ok_or(LaunchTicketClientError::InvalidResponse)?;
    if !(1..=MAX_LAUNCH_TICKET_LIFETIME.as_secs() as i64).contains(&lifetime)
        || claims.iat > wall_now.as_second().saturating_add(MAX_CLOCK_SKEW_SECONDS)
        || claims.exp <= wall_now.as_second()
    {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    let expires_at = Timestamp::from_str(&response.expires_at)
        .map_err(|_| LaunchTicketClientError::InvalidResponse)?;
    if expires_at.as_second() != claims.exp || expires_at.subsec_nanosecond() != 0 {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    let remaining = expires_at.duration_since(wall_now);
    if remaining <= jiff::SignedDuration::ZERO {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    let monotonic_deadline = monotonic_now
        .checked_add(remaining.unsigned_abs().min(MAX_LAUNCH_TICKET_LIFETIME))
        .ok_or(LaunchTicketClientError::InvalidResponse)?;
    Ok(ValidatedLaunchTicket {
        ticket: response.ticket,
        expires_at,
        monotonic_deadline,
    })
}

fn parse_protected_header(ticket: &str) -> Result<ProtectedHeader, LaunchTicketClientError> {
    let (header, _, _) = compact_segments(ticket)?;
    let decoded = decode_base64url_bounded(header, 512)?;
    let protected: ProtectedHeader =
        serde_json::from_slice(&decoded).map_err(|_| LaunchTicketClientError::InvalidResponse)?;
    if protected.alg != "EdDSA" || protected.typ != JWS_TYPE || !valid_key_id(&protected.kid) {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    Ok(protected)
}

fn verify_and_decode_claims(
    ticket: &str,
    expected_kid: &str,
    key: &VerifyingKey,
) -> Result<LaunchTicketClaims, LaunchTicketClientError> {
    let (header_segment, payload_segment, signature_segment) = compact_segments(ticket)?;
    let protected = parse_protected_header(ticket)?;
    if protected.kid != expected_kid {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    let signature_bytes = decode_base64url_bounded(signature_segment, 64)?;
    let signature = Signature::from_slice(&signature_bytes)
        .map_err(|_| LaunchTicketClientError::InvalidResponse)?;
    let signed_length = header_segment
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(payload_segment.len()))
        .ok_or(LaunchTicketClientError::InvalidResponse)?;
    key.verify_strict(&ticket.as_bytes()[..signed_length], &signature)
        .map_err(|_| LaunchTicketClientError::InvalidResponse)?;
    let payload = decode_base64url_bounded(payload_segment, MAX_RESPONSE_BYTES)?;
    serde_json::from_slice(&payload).map_err(|_| LaunchTicketClientError::InvalidResponse)
}

fn compact_segments(ticket: &str) -> Result<(&str, &str, &str), LaunchTicketClientError> {
    if ticket.len() < 64 || ticket.len() > MAX_TICKET_BYTES || !valid_compact_jws_text(ticket) {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    let mut segments = ticket.split('.');
    let header = segments.next().unwrap_or_default();
    let payload = segments.next().unwrap_or_default();
    let signature = segments.next().unwrap_or_default();
    if header.is_empty() || payload.is_empty() || signature.is_empty() || segments.next().is_some()
    {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    Ok((header, payload, signature))
}

fn launch_binding_hash(
    expected: &LaunchTicketRequestContext,
) -> Result<String, LaunchTicketClientError> {
    let mut payload = BTreeMap::<&str, Value>::new();
    payload.insert(
        "challengeId",
        Value::String(expected.challenge_id.to_string()),
    );
    payload.insert("channel", Value::String(expected.channel.as_str().into()));
    payload.insert(
        "connectionId",
        Value::String(expected.connection_id.to_string()),
    );
    payload.insert(
        "deviceSessionId",
        Value::String(expected.identity.device_session_id.to_string()),
    );
    payload.insert(
        "launcherInstanceId",
        Value::String(expected.launcher_instance_id.to_string()),
    );
    payload.insert(
        "launcherNick",
        Value::String(expected.identity.launcher_nick.clone()),
    );
    payload.insert(
        "launcherRole",
        Value::String(role_name(expected.identity.launcher_role).into()),
    );
    payload.insert("preset", Value::String(expected.preset.as_str().into()));
    payload.insert("releaseId", Value::String(expected.release_id.clone()));
    payload.insert(
        "userId",
        Value::String(expected.identity.user_id.to_string()),
    );
    let mut envelope = BTreeMap::<&str, Value>::new();
    envelope.insert("domain", Value::String(BINDING_HASH_DOMAIN.into()));
    envelope.insert(
        "payload",
        serde_json::to_value(payload).map_err(|_| LaunchTicketClientError::InvalidResponse)?,
    );
    let canonical =
        serde_json::to_vec(&envelope).map_err(|_| LaunchTicketClientError::InvalidResponse)?;
    Ok(lower_hex(&Sha256::digest(canonical)))
}

fn validate_production_url(url: &Url, expected_path: &str) -> Result<(), LaunchTicketClientError> {
    if url.scheme() != "https"
        || url.host_str() != Some("fragmc.ru")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != expected_path
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(LaunchTicketClientError::ClientSetup);
    }
    Ok(())
}

fn bearer_header(token: &str) -> Result<HeaderValue, LaunchTicketClientError> {
    if token.len() < 16
        || token.len() > MAX_ACCESS_TOKEN_BYTES
        || token.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(LaunchTicketClientError::Authentication);
    }
    let mut bytes = SensitiveBody(Vec::with_capacity(7 + token.len()));
    bytes.0.extend_from_slice(b"Bearer ");
    bytes.0.extend_from_slice(token.as_bytes());
    let mut header =
        HeaderValue::from_bytes(&bytes.0).map_err(|_| LaunchTicketClientError::Authentication)?;
    header.set_sensitive(true);
    Ok(header)
}

struct SensitiveBody(Vec<u8>);

impl std::ops::Deref for SensitiveBody {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for SensitiveBody {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

async fn collect_bounded(response: Response) -> Result<SensitiveBody, LaunchTicketClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(LaunchTicketClientError::ResponseTooLarge);
    }
    let mut body = SensitiveBody(Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(MAX_RESPONSE_BYTES as u64) as usize,
    ));
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| LaunchTicketClientError::Retryable { retry_after: None })?;
        if body
            .0
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > MAX_RESPONSE_BYTES)
        {
            return Err(LaunchTicketClientError::ResponseTooLarge);
        }
        body.0.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn validate_json_response_headers(headers: &HeaderMap) -> Result<(), LaunchTicketClientError> {
    let content_types: Vec<_> = headers.get_all(CONTENT_TYPE).iter().collect();
    if content_types.len() != 1 {
        return Err(LaunchTicketClientError::InvalidContentType);
    }
    let content_type = content_types[0]
        .to_str()
        .map_err(|_| LaunchTicketClientError::InvalidContentType)?;
    let normalized = content_type.trim().to_ascii_lowercase();
    if normalized != "application/json" && normalized != "application/json; charset=utf-8" {
        return Err(LaunchTicketClientError::InvalidContentType);
    }
    let encodings: Vec<_> = headers.get_all(CONTENT_ENCODING).iter().collect();
    if encodings.len() > 1
        || encodings
            .first()
            .is_some_and(|value| value.to_str().ok() != Some("identity"))
    {
        return Err(LaunchTicketClientError::InvalidContentType);
    }
    Ok(())
}

fn classify_http_error(
    status: StatusCode,
    headers: &HeaderMap,
    body: &[u8],
) -> LaunchTicketClientError {
    let code = safe_error_code(body);
    if status == StatusCode::UNAUTHORIZED {
        return LaunchTicketClientError::Authentication;
    }
    if status == StatusCode::FORBIDDEN {
        let reason = match code.as_deref() {
            Some("subscription_required") => LaunchTicketForbiddenReason::SubscriptionRequired,
            Some("dev_access_required") => LaunchTicketForbiddenReason::DevAccessRequired,
            Some("account_banned") => LaunchTicketForbiddenReason::AccountBanned,
            Some("entitlement_verification_unavailable") | Some("launch_entitlement_expired") => {
                LaunchTicketForbiddenReason::EntitlementUnavailable
            }
            _ => LaunchTicketForbiddenReason::Other,
        };
        return LaunchTicketClientError::Forbidden(reason);
    }
    if status == StatusCode::CONFLICT {
        let reason = match code.as_deref() {
            Some("release_not_current") | Some("release_changed") => {
                LaunchTicketConflictReason::ReleaseChanged
            }
            Some("launch_challenge_missing")
            | Some("launch_challenge_invalid")
            | Some("launch_challenge_expired")
            | Some("launch_challenge_epoch_expired")
            | Some("launch_epoch_mismatch")
            | Some("launch_challenge_closed")
            | Some("launch_ticket_expired") => LaunchTicketConflictReason::ChallengeRejected,
            Some("launch_challenge_conflict") | Some("launch_ticket_finalize_conflict") => {
                LaunchTicketConflictReason::ChallengeConflict
            }
            Some("launch_identity_changed")
            | Some("launch_identity_mismatch")
            | Some("launch_session_mismatch") => LaunchTicketConflictReason::IdentityChanged,
            Some("launcher_nickname_required") => LaunchTicketConflictReason::NicknameRequired,
            _ => LaunchTicketConflictReason::Other,
        };
        return LaunchTicketClientError::Conflict(reason);
    }
    if retryable_status(status) {
        return LaunchTicketClientError::Retryable {
            retry_after: retry_after(headers),
        };
    }
    LaunchTicketClientError::Http(status)
}

/// The public JWK endpoint never receives a bearer token. Its 401 must not consume the caller's
/// one completion-safe access-token rotation after Spark may already have finalized a ticket.
fn classify_keys_http_error(status: StatusCode, headers: &HeaderMap) -> LaunchTicketClientError {
    if retryable_status(status) {
        LaunchTicketClientError::Retryable {
            retry_after: retry_after(headers),
        }
    } else {
        LaunchTicketClientError::Http(status)
    }
}

fn safe_error_code(body: &[u8]) -> Option<String> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let code = value.as_object()?.get("error")?.as_str()?;
    if code.len() > 64
        || code.is_empty()
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return None;
    }
    Some(code.to_owned())
}

fn transport_error(_error: reqwest::Error) -> LaunchTicketClientError {
    LaunchTicketClientError::Retryable { retry_after: None }
}

fn retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(Duration::from_secs(value.parse::<u64>().ok()?).min(MAX_RETRY_AFTER));
    }
    let timestamp = jiff::fmt::rfc2822::DateTimeParser::new()
        .parse_timestamp(value)
        .ok()?;
    let seconds = timestamp
        .as_second()
        .saturating_sub(Timestamp::now().as_second());
    Some(Duration::from_secs(seconds.max(0) as u64).min(MAX_RETRY_AFTER))
}

fn decode_base64url_bounded(
    value: &str,
    maximum: usize,
) -> Result<Vec<u8>, LaunchTicketClientError> {
    if value.is_empty()
        || value.contains('=')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    let maximum_encoded = maximum
        .checked_mul(4)
        .and_then(|length| length.checked_add(2))
        .map(|length| length / 3)
        .ok_or(LaunchTicketClientError::InvalidResponse)?;
    if value.len() > maximum_encoded {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| LaunchTicketClientError::InvalidResponse)?;
    if decoded.len() > maximum {
        return Err(LaunchTicketClientError::InvalidResponse);
    }
    Ok(decoded)
}

fn valid_compact_jws_text(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
        && value.bytes().filter(|byte| *byte == b'.').count() == 2
}

fn valid_release_id(value: &str) -> bool {
    value.len() == 28
        && value.starts_with("rel_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_nickname(value: &str) -> bool {
    (1..=16).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

fn valid_key_id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn valid_redis_run_id(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

const fn role_name(role: LauncherRole) -> &'static str {
    match role {
        LauncherRole::Player => "player",
        LauncherRole::Tester => "tester",
        LauncherRole::Developer => "developer",
    }
}

fn lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const RELEASE_ID: &str = "rel_0123456789abcdef01234567";
    const USER_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const SESSION_ID: &str = "00000000-0000-4000-8000-000000000066";
    const CHALLENGE_ID: &str = "00000000-0000-4000-8000-000000000088";
    const CONNECTION_ID: &str = "00000000-0000-4000-8000-000000000077";
    const INSTANCE_ID: &str = "00000000-0000-4000-8000-000000000099";
    const JTI: &str = "00000000-0000-4000-8000-000000000055";
    const NONCE: &str = "00000000-0000-4000-8000-000000000044";
    const PROCESS_EPOCH: &str = "00000000-0000-4000-8000-000000000033";
    const REDIS_RUN_ID: &str = "0123456789abcdef0123456789abcdef01234567";
    const KID: &str = "launch-key-1";

    fn context() -> LaunchTicketRequestContext {
        let identity = ExpectedLaunchIdentity::new(
            Uuid::parse_str(USER_ID).unwrap(),
            Uuid::parse_str(SESSION_ID).unwrap(),
            "Player_1".into(),
            LauncherRole::Tester,
        )
        .unwrap();
        LaunchTicketRequestContext::new(
            BuildChannel::Dev,
            PresetId::Low,
            RELEASE_ID.into(),
            Uuid::parse_str(CHALLENGE_ID).unwrap(),
            Uuid::parse_str(CONNECTION_ID).unwrap(),
            Uuid::parse_str(INSTANCE_ID).unwrap(),
            identity,
        )
        .unwrap()
    }

    fn signed_response(
        context: &LaunchTicketRequestContext,
        signing_key: &SigningKey,
        now: Timestamp,
    ) -> Value {
        let iat = now.as_second();
        let exp = iat + 60;
        let header = json!({ "alg": "EdDSA", "kid": KID, "typ": JWS_TYPE });
        let claims = json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": USER_ID,
            "jti": JTI,
            "iat": iat,
            "nbf": iat,
            "exp": exp,
            "userId": USER_ID,
            "deviceSessionId": SESSION_ID,
            "launcherInstanceId": INSTANCE_ID,
            "channel": "dev",
            "preset": "low",
            "releaseId": RELEASE_ID,
            "connectionId": CONNECTION_ID,
            "challengeId": CHALLENGE_ID,
            "bindingHash": launch_binding_hash(context).unwrap(),
            "processEpoch": PROCESS_EPOCH,
            "redisRunId": REDIS_RUN_ID,
            "launcherRole": "tester",
            "launcherNick": "Player_1",
            "minecraftUuid": USER_ID.replace('-', ""),
            "nonce": NONCE,
        });
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{header}.{payload}");
        let signature = signing_key.sign(signing_input.as_bytes());
        let ticket = format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        );
        json!({
            "purpose": PURPOSE,
            "contractVersion": CONTRACT_VERSION,
            "ticket": ticket,
            "expiresAt": Timestamp::new(exp, 0).unwrap().to_string(),
            "nonce": NONCE,
            "jti": JTI,
            "binding": {
                "challengeId": CHALLENGE_ID,
                "connectionId": CONNECTION_ID,
                "channel": "dev",
                "preset": "low",
                "releaseId": RELEASE_ID,
                "userId": USER_ID,
                "deviceSessionId": SESSION_ID,
                "launcherInstanceId": INSTANCE_ID,
                "launcherNick": "Player_1",
                "launcherRole": "tester"
            },
            "minecraftIdentity": {
                "playerName": "Player_1",
                "uuid": USER_ID.replace('-', ""),
                "accessToken": "0",
                "userType": "legacy",
                "clientId": "",
                "xuid": ""
            },
            "delivery": {
                "kind": "local-ipc",
                "audience": AUDIENCE
            }
        })
    }

    #[test]
    fn validates_exact_signed_response_and_never_prints_ticket() {
        let context = context();
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let now = Timestamp::now();
        let value = signed_response(&context, &signing_key, now);
        let sentinel = value["ticket"].as_str().unwrap().to_owned();
        let raw: LaunchTicketResponse = serde_json::from_value(value).unwrap();
        let ticket = validate_ticket_response(
            raw,
            &context,
            KID,
            &signing_key.verifying_key(),
            now,
            Instant::now(),
        )
        .unwrap();
        assert_eq!(ticket.as_bytes(), sentinel.as_bytes());
        let debug = format!("{ticket:?}");
        assert!(!debug.contains(&sentinel));
        assert!(!format!("{:?}", OpaqueTicket::new(sentinel.clone()).unwrap()).contains(&sentinel));
        let deadline = ticket.monotonic_deadline();
        let expires_at = ticket.expires_at();
        let (mut bytes, wall_expiry, moved_deadline) = ticket.into_delivery_parts().unwrap();
        assert_eq!(bytes, sentinel.as_bytes());
        assert_eq!(moved_deadline, deadline);
        assert_eq!(
            wall_expiry,
            SystemTime::UNIX_EPOCH
                .checked_add(Duration::from_secs(expires_at.as_second() as u64))
                .unwrap()
        );
        bytes.zeroize();
    }

    #[test]
    fn strict_contract_rejects_unknown_nested_fields_and_binding_drift() {
        let context = context();
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let now = Timestamp::now();
        let mut unknown = signed_response(&context, &signing_key, now);
        unknown["delivery"]["unexpected"] = Value::Bool(true);
        assert!(serde_json::from_value::<LaunchTicketResponse>(unknown).is_err());

        let mut drifted = signed_response(&context, &signing_key, now);
        drifted["binding"]["launcherInstanceId"] =
            Value::String("00000000-0000-4000-8000-000000000098".into());
        let raw: LaunchTicketResponse = serde_json::from_value(drifted).unwrap();
        assert!(validate_ticket_response(
            raw,
            &context,
            KID,
            &signing_key.verifying_key(),
            now,
            Instant::now(),
        )
        .is_err());
    }

    #[test]
    fn rejects_forged_signature_and_noncanonical_uuid() {
        let context = context();
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let wrong_key = SigningKey::from_bytes(&[12_u8; 32]);
        let now = Timestamp::now();
        let raw: LaunchTicketResponse =
            serde_json::from_value(signed_response(&context, &signing_key, now)).unwrap();
        assert!(validate_ticket_response(
            raw,
            &context,
            KID,
            &wrong_key.verifying_key(),
            now,
            Instant::now(),
        )
        .is_err());

        let mut noncanonical = signed_response(&context, &signing_key, now);
        noncanonical["binding"]["userId"] = Value::String(USER_ID.to_uppercase());
        assert!(serde_json::from_value::<LaunchTicketResponse>(noncanonical).is_err());
    }

    #[test]
    fn jwk_contract_is_strict_and_ed25519_only() {
        let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let x = URL_SAFE_NO_PAD.encode(signing_key.verifying_key().to_bytes());
        let valid: LaunchPublicJwk = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": x,
            "kid": KID,
            "alg": "EdDSA",
            "use": "sig"
        }))
        .unwrap();
        assert_eq!(
            valid.into_verifying_key().unwrap().1,
            signing_key.verifying_key()
        );

        let unknown = json!({
            "kty": "OKP", "crv": "Ed25519", "x": x, "kid": KID,
            "alg": "EdDSA", "use": "sig", "extra": true
        });
        assert!(serde_json::from_value::<LaunchPublicJwk>(unknown).is_err());

        let mut small_order = [0_u8; 32];
        small_order[0] = 1;
        let weak: LaunchPublicJwk = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": URL_SAFE_NO_PAD.encode(small_order),
            "kid": "weak-key",
            "alg": "EdDSA",
            "use": "sig"
        }))
        .unwrap();
        assert!(weak.into_verifying_key().is_err());
    }

    #[test]
    fn official_urls_and_error_classification_are_fail_closed() {
        assert!(validate_production_url(
            &Url::parse(LAUNCH_TICKET_URL).unwrap(),
            LAUNCH_TICKET_PATH
        )
        .is_ok());
        for rejected in [
            "http://fragmc.ru/api/spark2/v1/launch-ticket",
            "https://fragmc.ru:444/api/spark2/v1/launch-ticket",
            "https://fragmc.ru.evil.invalid/api/spark2/v1/launch-ticket",
            "https://user@fragmc.ru/api/spark2/v1/launch-ticket",
            "https://fragmc.ru/api/spark2/v1/launch-ticket?x=1",
        ] {
            assert!(
                validate_production_url(&Url::parse(rejected).unwrap(), LAUNCH_TICKET_PATH)
                    .is_err()
            );
        }

        let headers = HeaderMap::new();
        assert!(matches!(
            classify_http_error(StatusCode::UNAUTHORIZED, &headers, b"{}"),
            LaunchTicketClientError::Authentication
        ));
        assert!(matches!(
            classify_http_error(
                StatusCode::CONFLICT,
                &headers,
                br#"{"error":"launch_challenge_conflict"}"#
            ),
            LaunchTicketClientError::Conflict(LaunchTicketConflictReason::ChallengeConflict)
        ));
        assert!(matches!(
            classify_http_error(StatusCode::SERVICE_UNAVAILABLE, &headers, b"{}"),
            LaunchTicketClientError::Retryable { .. }
        ));
        let keys_unauthorized = classify_keys_http_error(StatusCode::UNAUTHORIZED, &headers);
        assert!(!keys_unauthorized.requires_token_rotation());
        assert!(matches!(
            keys_unauthorized,
            LaunchTicketClientError::Http(StatusCode::UNAUTHORIZED)
        ));
    }

    #[test]
    fn request_serialization_contains_every_identity_precondition() {
        let context = context();
        let request = LaunchTicketRequest::from(&context);
        assert_eq!(
            launch_binding_hash(&context).unwrap(),
            "7658510672cda227e566008d0b51a7948872ff4ba3d21c11f82f418e470533be"
        );
        assert_eq!(
            serde_json::to_value(request).unwrap(),
            json!({
                "channel": "dev",
                "preset": "low",
                "releaseId": RELEASE_ID,
                "challengeId": CHALLENGE_ID,
                "connectionId": CONNECTION_ID,
                "launcherInstanceId": INSTANCE_ID,
                "expectedUserId": USER_ID,
                "expectedDeviceSessionId": SESSION_ID,
                "expectedLauncherNick": "Player_1",
                "expectedLauncherRole": "tester"
            })
        );
    }

    #[test]
    fn bearer_header_is_sensitive_and_never_debug_prints_the_token() {
        let sentinel = "access-token-that-must-never-appear";
        let header = bearer_header(sentinel).unwrap();
        assert!(header.is_sensitive());
        assert!(!format!("{header:?}").contains(sentinel));
        assert!(!format!("{:?}", LaunchTicketClientError::Authentication).contains(sentinel));
    }

    #[test]
    fn test_constructor_uses_only_explicit_local_paths() {
        let client = LaunchTicketClient::new_for_test("http://127.0.0.1:18080/");
        assert_eq!(client.ticket_url.path(), LAUNCH_TICKET_PATH);
        assert_eq!(client.keys_url.path(), LAUNCH_KEYS_PATH);
    }
}
