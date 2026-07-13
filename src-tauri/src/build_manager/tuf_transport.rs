use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::{redirect::Policy, Client, StatusCode};
use serde::Deserialize;
use std::{
    error::Error,
    fmt,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::Url;

const MAX_TRANSPORT_CONTENT_LENGTH: u64 = 32 * 1024 * 1024;
const MAX_ERROR_BODY_BYTES: usize = 8 * 1024;

#[derive(Clone)]
pub struct SparkTufTransport {
    client: Client,
    bearer_token: String,
    origin: Url,
    metadata_prefix: String,
    targets_prefix: String,
}

impl fmt::Debug for SparkTufTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SparkTufTransport")
            .field("origin", &self.origin.as_str())
            .field("metadata_prefix", &self.metadata_prefix)
            .field("targets_prefix", &self.targets_prefix)
            .field("bearer_token", &"[redacted]")
            .finish()
    }
}

impl SparkTufTransport {
    pub fn new(
        bearer_token: String,
        origin: Url,
        metadata_prefix: String,
        targets_prefix: String,
    ) -> Result<Self, String> {
        if bearer_token.len() < 16
            || bearer_token.len() > 8192
            || bearer_token.chars().any(char::is_control)
        {
            return Err("Spark access token is invalid".into());
        }
        validate_origin(&origin)?;
        validate_prefix(&metadata_prefix)?;
        validate_prefix(&targets_prefix)?;
        if metadata_prefix == targets_prefix {
            return Err("TUF metadata and target prefixes must differ".into());
        }
        let client = Client::builder()
            .user_agent(concat!("FragmentLauncher/", env!("CARGO_PKG_VERSION")))
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .https_only(true)
            .build()
            .map_err(|error| format!("Cannot create Spark TUF HTTP client: {error}"))?;
        Ok(Self {
            client,
            bearer_token,
            origin,
            metadata_prefix,
            targets_prefix,
        })
    }

    fn validate_url(&self, url: &Url) -> Result<(), TransportError> {
        let same_origin = url.scheme() == self.origin.scheme()
            && url.host_str() == self.origin.host_str()
            && url.port_or_known_default() == self.origin.port_or_known_default();
        let path = url.path();
        let allowed_path =
            path.starts_with(&self.metadata_prefix) || path.starts_with(&self.targets_prefix);
        let safe_path = path.is_ascii()
            && !path.contains('%')
            && !path.contains('\\')
            && !path
                .split('/')
                .any(|segment| segment == ".." || segment == ".");
        if !same_origin
            || !allowed_path
            || !safe_path
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(TransportError::new(
                TransportErrorKind::UnsupportedUrlScheme,
                url.as_str(),
            ));
        }
        Ok(())
    }
}

#[async_trait]
impl Transport for SparkTufTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        self.validate_url(&url)?;
        let response = self
            .client
            .get(url.clone())
            .bearer_auth(&self.bearer_token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|error| {
                TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), error)
            })?;
        let status = response.status();
        if status == StatusCode::NOT_FOUND || status == StatusCode::GONE {
            return Err(TransportError::new(
                TransportErrorKind::FileNotFound,
                url.as_str(),
            ));
        }
        if !status.is_success() {
            let server_code = read_server_error_code(response).await;
            return Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                url.as_str(),
                SparkTufHttpError {
                    status,
                    server_code,
                },
            ));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_TRANSPORT_CONTENT_LENGTH)
        {
            return Err(TransportError::new_with_cause(
                TransportErrorKind::Other,
                url.as_str(),
                "Spark TUF response exceeds the transport limit",
            ));
        }
        let error_url = url.clone();
        let received = Arc::new(AtomicU64::new(0));
        let stream = response.bytes_stream().map(move |chunk| {
            let chunk = chunk.map_err(|error| {
                TransportError::new_with_cause(TransportErrorKind::Other, error_url.as_str(), error)
            })?;
            let total =
                received.fetch_add(chunk.len() as u64, Ordering::Relaxed) + chunk.len() as u64;
            if total > MAX_TRANSPORT_CONTENT_LENGTH {
                return Err(TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    error_url.as_str(),
                    "Spark TUF response exceeds the streamed transport limit",
                ));
            }
            Ok(chunk)
        });
        Ok(Box::pin(stream))
    }
}

#[derive(Debug)]
pub(super) struct SparkTufHttpError {
    status: StatusCode,
    server_code: Option<String>,
}

impl SparkTufHttpError {
    pub(super) fn launcher_error_code(&self) -> String {
        let server_code = self.server_code.as_deref();
        match self.status {
            StatusCode::UNAUTHORIZED => match server_code {
                Some("bearer_required") => "spark_auth_required".into(),
                Some("invalid_session") => "spark_session_invalid".into(),
                _ => "spark_auth_required".into(),
            },
            StatusCode::FORBIDDEN => match server_code {
                Some("subscription_required") => "spark_subscription_required".into(),
                Some("dev_access_required") => "spark_dev_access_required".into(),
                Some("launcher_admission_denied") => "spark_admission_denied".into(),
                _ => "spark_access_denied".into(),
            },
            StatusCode::TOO_MANY_REQUESTS => "spark_rate_limited".into(),
            status if status.is_server_error() => "spark_service_unavailable".into(),
            _ => "spark_repository_http_error".into(),
        }
    }
}

impl fmt::Display for SparkTufHttpError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Spark TUF HTTP status {}", self.status.as_u16())?;
        if let Some(code) = &self.server_code {
            write!(formatter, " ({code})")?;
        }
        Ok(())
    }
}

impl Error for SparkTufHttpError {}

#[derive(Deserialize)]
struct ServerErrorEnvelope {
    error: Option<String>,
}

async fn read_server_error_code(response: reqwest::Response) -> Option<String> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_ERROR_BODY_BYTES as u64)
    {
        return None;
    }
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let Ok(chunk) = chunk else {
            return None;
        };
        let next_len = body.len().checked_add(chunk.len())?;
        if next_len > MAX_ERROR_BODY_BYTES {
            return None;
        }
        body.extend_from_slice(&chunk);
    }
    let envelope: ServerErrorEnvelope = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return None,
    };
    envelope.error.filter(|code| valid_server_error_code(code))
}

fn valid_server_error_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 64
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_origin(origin: &Url) -> Result<(), String> {
    if origin.scheme() != "https"
        || origin.host_str().is_none()
        || !origin.username().is_empty()
        || origin.password().is_some()
        || origin.query().is_some()
        || origin.fragment().is_some()
        || origin.path() != "/"
    {
        return Err("Spark TUF origin must be a credential-free HTTPS origin".into());
    }
    Ok(())
}

fn validate_prefix(prefix: &str) -> Result<(), String> {
    if !prefix.starts_with('/')
        || !prefix.ends_with('/')
        || !prefix.is_ascii()
        || prefix.contains('%')
        || prefix.contains('\\')
        || prefix
            .split('/')
            .any(|segment| segment == ".." || segment == ".")
    {
        return Err("Spark TUF path prefix is unsafe".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn transport() -> SparkTufTransport {
        SparkTufTransport::new(
            "a-secure-test-access-token".into(),
            Url::parse("https://fragmc.ru/").unwrap(),
            "/api/spark2/v1/repositories/stable/metadata/".into(),
            "/api/spark2/v1/repositories/stable/targets/".into(),
        )
        .unwrap()
    }

    #[test]
    fn allows_only_the_exact_channel_repository_origin() {
        let transport = transport();
        assert!(transport
            .validate_url(
                &Url::parse(
                    "https://fragmc.ru/api/spark2/v1/repositories/stable/metadata/timestamp.json"
                )
                .unwrap()
            )
            .is_ok());
        for url in [
            "http://fragmc.ru/api/spark2/v1/repositories/stable/metadata/timestamp.json",
            "https://evil.invalid/api/spark2/v1/repositories/stable/metadata/timestamp.json",
            "https://fragmc.ru/api/spark2/v1/repositories/dev/metadata/timestamp.json",
            "https://fragmc.ru/api/spark2/v1/repositories/stable/metadata/timestamp.json?token=x",
            "https://fragmc.ru/api/spark2/v1/repositories/stable/metadata/%2e%2e/secrets",
        ] {
            assert!(transport.validate_url(&Url::parse(url).unwrap()).is_err());
        }
    }

    #[test]
    fn debug_output_never_contains_the_bearer_token() {
        let transport = transport();
        let debug = format!("{transport:?}");
        assert!(debug.contains("[redacted]"));
        assert!(!debug.contains("a-secure-test-access-token"));
    }

    #[test]
    fn maps_auth_statuses_to_stable_launcher_codes() {
        for (status, server_code, expected) in [
            (
                StatusCode::UNAUTHORIZED,
                Some("invalid_session"),
                "spark_session_invalid",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("subscription_required"),
                "spark_subscription_required",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("dev_access_required"),
                "spark_dev_access_required",
            ),
            (
                StatusCode::FORBIDDEN,
                Some("unknown"),
                "spark_access_denied",
            ),
        ] {
            let error = SparkTufHttpError {
                status,
                server_code: server_code.map(str::to_owned),
            };
            assert_eq!(error.launcher_error_code(), expected);
        }
    }

    #[test]
    fn accepts_only_bounded_machine_error_codes() {
        assert!(valid_server_error_code("dev_access_required"));
        assert!(!valid_server_error_code("Dev access required"));
        assert!(!valid_server_error_code(&"a".repeat(65)));
        assert!(!valid_server_error_code("token=secret"));
    }
}
