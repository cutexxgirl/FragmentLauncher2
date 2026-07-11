use std::time::Duration;

use async_trait::async_trait;
use reqwest::header::{HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use serde::Serialize;
use url::Url;

use super::types::{
    AdmissionChannel, ApiErrorResponse, BeginChallengeRequest, ContractError,
    LauncherAdmissionReason, LauncherAdmissionResponse, LauncherProfile, LogoutResponse,
    NicknameRequest, PollChallengeRequest, RefreshRequest, Secret, SessionResponse,
    TelegramChallengeResponse, TelegramPollOutcome, TelegramPollResponse, MAX_RESPONSE_BYTES,
};

const API_BASE_URL: &str = "https://fragmc.ru/fragment-api/";

#[derive(Debug, thiserror::Error)]
pub(crate) enum ApiError {
    #[error("Fragment API origin is invalid")]
    InvalidOrigin,
    #[error("Fragment API request could not be sent ({0})")]
    Transport(&'static str),
    #[error("Fragment API returned an unauthorized response")]
    Unauthorized,
    #[error("Fragment API returned HTTP {status}{message}")]
    Http {
        status: u16,
        code: Option<String>,
        message: String,
    },
    #[error("Fragment API response is too large")]
    ResponseTooLarge,
    #[error("Fragment API response is not JSON")]
    InvalidContentType,
    #[error("Fragment API response is invalid")]
    InvalidResponse,
    #[error(transparent)]
    Contract(#[from] ContractError),
}

impl ApiError {
    pub(crate) fn is_unauthorized(&self) -> bool {
        matches!(self, Self::Unauthorized)
    }

    pub(crate) fn admission_reason(&self) -> Option<LauncherAdmissionReason> {
        let Self::Http { code, .. } = self else {
            return None;
        };
        match code.as_deref()? {
            "subscription_required" => Some(LauncherAdmissionReason::SubscriptionRequired),
            "launcher_nickname_required" => Some(LauncherAdmissionReason::LauncherNicknameRequired),
            "dev_access_required" => Some(LauncherAdmissionReason::DevAccessRequired),
            "account_banned" => Some(LauncherAdmissionReason::AccountBanned),
            "entitlement_verification_unavailable" => {
                Some(LauncherAdmissionReason::EntitlementVerificationUnavailable)
            }
            "launcher_admission_unavailable" => {
                Some(LauncherAdmissionReason::LauncherAdmissionUnavailable)
            }
            "launcher_admission_busy" => Some(LauncherAdmissionReason::LauncherAdmissionBusy),
            "invalid_session" => Some(LauncherAdmissionReason::InvalidSession),
            _ => None,
        }
    }
}

#[async_trait]
pub(crate) trait AuthApi: Send + Sync {
    async fn begin_challenge(
        &self,
        device_name: &str,
    ) -> Result<TelegramChallengeResponse, ApiError>;
    async fn poll_challenge(
        &self,
        challenge_id: &str,
        poll_token: &Secret,
    ) -> Result<TelegramPollOutcome, ApiError>;
    async fn refresh(&self, refresh_token: &Secret) -> Result<SessionResponse, ApiError>;
    async fn logout(&self, refresh_token: &Secret) -> Result<(), ApiError>;
    async fn get_profile(&self, access_token: &Secret) -> Result<LauncherProfile, ApiError>;
    async fn update_nickname(
        &self,
        access_token: &Secret,
        nickname: Option<&str>,
    ) -> Result<LauncherProfile, ApiError>;
    async fn launcher_admission(
        &self,
        access_token: &Secret,
        channel: AdmissionChannel,
    ) -> Result<LauncherAdmissionResponse, ApiError>;
}

pub(crate) struct FragmentApiClient {
    base_url: Url,
    http: reqwest::Client,
}

impl FragmentApiClient {
    pub(crate) fn new() -> Result<Self, ApiError> {
        let base_url = Url::parse(API_BASE_URL).map_err(|_| ApiError::InvalidOrigin)?;
        validate_official_origin(&base_url)?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(20))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("FragmentLauncher/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|_| ApiError::Transport("client setup"))?;
        Ok(Self { base_url, http })
    }

    fn endpoint(&self, relative: &str) -> Result<Url, ApiError> {
        if relative.is_empty()
            || relative.starts_with('/')
            || relative.contains("..")
            || relative.contains(['?', '#', '\\'])
        {
            return Err(ApiError::InvalidOrigin);
        }
        self.base_url
            .join(relative)
            .map_err(|_| ApiError::InvalidOrigin)
    }

    async fn json<T, B>(
        &self,
        method: Method,
        path: &str,
        body: Option<&B>,
        bearer: Option<&Secret>,
        sensitive: &[&Secret],
    ) -> Result<T, ApiError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        self.json_at_url(method, self.endpoint(path)?, body, bearer, sensitive)
            .await
    }

    async fn json_at_url<T, B>(
        &self,
        method: Method,
        url: Url,
        body: Option<&B>,
        bearer: Option<&Secret>,
        sensitive: &[&Secret],
    ) -> Result<T, ApiError>
    where
        T: DeserializeOwned,
        B: Serialize + ?Sized,
    {
        let mut request = self
            .http
            .request(method, url)
            .header(ACCEPT, "application/json")
            .header(CONTENT_TYPE, "application/json");
        if let Some(token) = bearer {
            request = request.header(AUTHORIZATION, bearer_header(token)?);
        }
        if let Some(body) = body {
            request = request.json(body);
        }

        let response = request.send().await.map_err(classify_transport_error)?;
        let status = response.status();
        let content_type_is_json = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
        {
            return Err(ApiError::ResponseTooLarge);
        }
        let body = read_bounded(response).await?;

        if status == StatusCode::UNAUTHORIZED {
            return Err(ApiError::Unauthorized);
        }
        if !status.is_success() {
            return Err(http_error(status, &body, sensitive));
        }
        if !content_type_is_json {
            return Err(ApiError::InvalidContentType);
        }
        serde_json::from_slice(&body).map_err(|_| ApiError::InvalidResponse)
    }
}

#[async_trait]
impl AuthApi for FragmentApiClient {
    async fn begin_challenge(
        &self,
        device_name: &str,
    ) -> Result<TelegramChallengeResponse, ApiError> {
        let response: TelegramChallengeResponse = self
            .json(
                Method::POST,
                "auth/telegram/challenges",
                Some(&BeginChallengeRequest { device_name }),
                None,
                &[],
            )
            .await?;
        response.validate()?;
        Ok(response)
    }

    async fn poll_challenge(
        &self,
        challenge_id: &str,
        poll_token: &Secret,
    ) -> Result<TelegramPollOutcome, ApiError> {
        let path = format!("auth/telegram/challenges/{challenge_id}/poll");
        let response: TelegramPollResponse = self
            .json(
                Method::POST,
                &path,
                Some(&PollChallengeRequest {
                    poll_token: poll_token.expose(),
                }),
                None,
                &[poll_token],
            )
            .await?;
        response.into_outcome().map_err(ApiError::from)
    }

    async fn refresh(&self, refresh_token: &Secret) -> Result<SessionResponse, ApiError> {
        let response: SessionResponse = self
            .json(
                Method::POST,
                "auth/refresh",
                Some(&RefreshRequest {
                    refresh_token: refresh_token.expose(),
                }),
                None,
                &[refresh_token],
            )
            .await?;
        response.validate()?;
        Ok(response)
    }

    async fn logout(&self, refresh_token: &Secret) -> Result<(), ApiError> {
        let response: LogoutResponse = self
            .json(
                Method::POST,
                "auth/logout",
                Some(&RefreshRequest {
                    refresh_token: refresh_token.expose(),
                }),
                None,
                &[refresh_token],
            )
            .await?;
        if !response.ok {
            return Err(ApiError::InvalidResponse);
        }
        Ok(())
    }

    async fn get_profile(&self, access_token: &Secret) -> Result<LauncherProfile, ApiError> {
        let response: LauncherProfile = self
            .json::<LauncherProfile, serde_json::Value>(
                Method::GET,
                "auth/me",
                None,
                Some(access_token),
                &[access_token],
            )
            .await?;
        response.validate()?;
        Ok(response)
    }

    async fn update_nickname(
        &self,
        access_token: &Secret,
        nickname: Option<&str>,
    ) -> Result<LauncherProfile, ApiError> {
        let response: LauncherProfile = self
            .json(
                Method::PATCH,
                "auth/me/nickname",
                Some(&NicknameRequest { nickname }),
                Some(access_token),
                &[access_token],
            )
            .await?;
        response.validate()?;
        Ok(response)
    }

    async fn launcher_admission(
        &self,
        access_token: &Secret,
        channel: AdmissionChannel,
    ) -> Result<LauncherAdmissionResponse, ApiError> {
        let mut url = self.endpoint("auth/launcher/admission")?;
        url.query_pairs_mut()
            .append_pair("channel", channel.as_str());
        let response: LauncherAdmissionResponse = self
            .json_at_url::<LauncherAdmissionResponse, serde_json::Value>(
                Method::GET,
                url,
                None,
                Some(access_token),
                &[access_token],
            )
            .await?;
        response.validate()?;
        if response.channel != channel {
            return Err(ApiError::Contract(ContractError::InvalidField("channel")));
        }
        Ok(response)
    }
}

fn validate_official_origin(url: &Url) -> Result<(), ApiError> {
    if url.scheme() != "https"
        || url.host_str() != Some("fragmc.ru")
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/fragment-api/"
    {
        return Err(ApiError::InvalidOrigin);
    }
    Ok(())
}

fn bearer_header(token: &Secret) -> Result<HeaderValue, ApiError> {
    let mut bytes = Vec::with_capacity(7 + token.expose().len());
    bytes.extend_from_slice(b"Bearer ");
    bytes.extend_from_slice(token.expose().as_bytes());
    let mut value = HeaderValue::from_bytes(&bytes).map_err(|_| ApiError::InvalidResponse)?;
    bytes.fill(0);
    value.set_sensitive(true);
    Ok(value)
}

struct ResponseBody(Vec<u8>);

impl std::ops::Deref for ResponseBody {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for ResponseBody {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            // Response JSON can contain access, refresh, and poll tokens.
            unsafe { std::ptr::write_volatile(byte, 0) };
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

async fn read_bounded(mut response: reqwest::Response) -> Result<ResponseBody, ApiError> {
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or(0)
            .min(MAX_RESPONSE_BYTES as u64) as usize,
    );
    while let Some(chunk) = response.chunk().await.map_err(classify_transport_error)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(ApiError::ResponseTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(ResponseBody(body))
}

fn classify_transport_error(error: reqwest::Error) -> ApiError {
    if error.is_timeout() {
        ApiError::Transport("timeout")
    } else if error.is_connect() {
        ApiError::Transport("connection")
    } else {
        ApiError::Transport("network")
    }
}

fn http_error(status: StatusCode, body: &[u8], sensitive: &[&Secret]) -> ApiError {
    let parsed = serde_json::from_slice::<ApiErrorResponse>(body).ok();
    let (mut code, mut message) = parsed
        .map(ApiErrorResponse::safe_parts)
        .unwrap_or((None, None));
    if !sensitive.is_empty() {
        // Authenticated/request-secret endpoints may echo a token or a token
        // prefix in free-form error text. Preserve only a constrained error
        // code and never surface their response message.
        message = None;
    }
    for secret in sensitive {
        let raw = secret.expose();
        if code
            .as_ref()
            .is_some_and(|value| value.contains(raw) || raw.contains(value))
        {
            code = None;
        }
        if message.as_ref().is_some_and(|value| value.contains(raw)) {
            message = None;
        }
    }
    let suffix = message
        .as_deref()
        .map(|value| format!(": {value}"))
        .unwrap_or_default();
    ApiError::Http {
        status: status.as_u16(),
        code,
        message: suffix,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_exact_official_api_origin_is_accepted() {
        assert!(validate_official_origin(&Url::parse(API_BASE_URL).unwrap()).is_ok());
        for rejected in [
            "http://fragmc.ru/fragment-api/",
            "https://fragmc.ru.evil.test/fragment-api/",
            "https://fragmc.ru:444/fragment-api/",
            "https://fragmc.ru/fragment-api/other/",
        ] {
            assert!(validate_official_origin(&Url::parse(rejected).unwrap()).is_err());
        }
    }

    #[test]
    fn sensitive_server_message_is_not_returned() {
        let secret = Secret::new("secret-that-must-never-appear-1234".into()).unwrap();
        let body = format!(r#"{{"message":"{}"}}"#, secret.expose());
        let error = http_error(StatusCode::BAD_REQUEST, body.as_bytes(), &[&secret]);
        assert!(!format!("{error:?}").contains(secret.expose()));
        assert!(!error.to_string().contains(secret.expose()));
    }
}
