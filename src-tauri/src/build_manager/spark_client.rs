use super::types::{BuildChannel, PresetId};
use futures_util::StreamExt;
use reqwest::{
    header::{self, HeaderMap},
    redirect::Policy,
    Client, Response, StatusCode,
};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt, time::Duration};
use thiserror::Error;
use url::Url;

const SPARK_ORIGIN: &str = "https://fragmc.ru/";
const DOWNLOAD_PLAN_URL: &str = "https://fragmc.ru/api/spark2/v1/download-plan";
const OBJECT_PATH_PREFIX: &str = "/api/spark2/v1/objects/";
const MAX_PLAN_BYTES: usize = 4 * 1024 * 1024;
const MAX_PLAN_OBJECTS: usize = 128;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct SparkClient {
    plan_client: Client,
    object_client: Client,
    plan_url: Url,
    object_origin: Url,
}

impl fmt::Debug for SparkClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SparkClient")
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum SparkClientError {
    #[error("Fragment authentication expired")]
    Authentication,
    #[error("Fragment entitlement or channel permission was denied")]
    Forbidden,
    #[error("Spark selected another release; refresh TUF before continuing")]
    ReleaseChanged,
    #[error("Spark response is invalid: {0}")]
    InvalidResponse(String),
    #[error("Temporary Spark {operation} failure")]
    Retryable {
        operation: &'static str,
        retry_after: Option<Duration>,
    },
    #[error("Spark {operation} returned HTTP {status}")]
    Http {
        operation: &'static str,
        status: StatusCode,
    },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DownloadPlanRequest<'a> {
    channel: BuildChannel,
    preset: PresetId,
    release_id: &'a str,
    objects: &'a [String],
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DownloadPlanResponse {
    release_id: String,
    expires_in: u64,
    objects: Vec<DownloadPlanObject>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DownloadPlanObject {
    sha256: String,
    url: String,
}

#[derive(Clone)]
pub struct ObjectDownload {
    pub sha256: String,
    url: Url,
}

impl fmt::Debug for ObjectDownload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ObjectDownload")
            .field("sha256", &self.sha256)
            .field("url", &"[redacted signed URL]")
            .finish()
    }
}

impl SparkClient {
    pub fn new() -> Result<Self, String> {
        let (plan_client, object_client) = build_clients(true)?;
        Ok(Self {
            plan_client,
            object_client,
            plan_url: Url::parse(DOWNLOAD_PLAN_URL)
                .map_err(|_| "Spark download-plan URL is invalid".to_string())?,
            object_origin: Url::parse(SPARK_ORIGIN)
                .map_err(|_| "Spark object origin is invalid".to_string())?,
        })
    }

    #[cfg(test)]
    pub(super) fn new_for_test(origin: &str) -> Self {
        let object_origin = Url::parse(origin).expect("test origin must parse");
        assert!(object_origin.host_str().is_some());
        let plan_url = object_origin
            .join("/api/spark2/v1/download-plan")
            .expect("test plan URL must parse");
        let (plan_client, object_client) = build_clients(false).expect("test clients");
        Self {
            plan_client,
            object_client,
            plan_url,
            object_origin,
        }
    }

    pub async fn download_plan(
        &self,
        channel: BuildChannel,
        preset: PresetId,
        release_id: &str,
        hashes: &[String],
        bearer_token: &str,
    ) -> Result<HashMap<String, ObjectDownload>, SparkClientError> {
        validate_access_token(bearer_token)?;
        if !valid_release_id(release_id)
            || hashes.is_empty()
            || hashes.len() > MAX_PLAN_OBJECTS
            || hashes.iter().any(|hash| !valid_sha256(hash))
            || hashes
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                != hashes.len()
        {
            return Err(SparkClientError::InvalidResponse(
                "download plan request is unsafe".into(),
            ));
        }
        let response = self
            .plan_client
            .post(self.plan_url.clone())
            .bearer_auth(bearer_token)
            .json(&DownloadPlanRequest {
                channel,
                preset,
                release_id,
                objects: hashes,
            })
            .send()
            .await
            .map_err(|_| retryable("download-plan connection", None))?;
        let status = response.status();
        if status == StatusCode::UNAUTHORIZED {
            return Err(SparkClientError::Authentication);
        }
        if status == StatusCode::FORBIDDEN {
            return Err(SparkClientError::Forbidden);
        }
        if status == StatusCode::CONFLICT {
            return Err(SparkClientError::ReleaseChanged);
        }
        if is_retryable_status(status) {
            return Err(retryable(
                "download-plan response",
                retry_after(response.headers()),
            ));
        }
        if !status.is_success() {
            return Err(SparkClientError::Http {
                operation: "download plan",
                status,
            });
        }
        let bytes = collect_bounded(response, MAX_PLAN_BYTES).await?;
        let plan: DownloadPlanResponse = serde_json::from_slice(&bytes).map_err(|error| {
            if error.is_eof() {
                retryable("download-plan body", None)
            } else {
                SparkClientError::InvalidResponse(format!("download plan JSON: {error}"))
            }
        })?;
        if plan.release_id != release_id
            || plan.expires_in == 0
            || plan.expires_in > 15 * 60
            || plan.objects.len() != hashes.len()
        {
            return Err(SparkClientError::InvalidResponse(
                "download plan binding or expiry is invalid".into(),
            ));
        }
        let expected: std::collections::HashSet<_> = hashes.iter().cloned().collect();
        let mut result = HashMap::with_capacity(plan.objects.len());
        for object in plan.objects {
            if !expected.contains(&object.sha256) || result.contains_key(&object.sha256) {
                return Err(SparkClientError::InvalidResponse(
                    "download plan contains an unexpected or duplicate object".into(),
                ));
            }
            let url = validate_object_url(&object.url, &object.sha256, &self.object_origin)?;
            result.insert(
                object.sha256.clone(),
                ObjectDownload {
                    sha256: object.sha256,
                    url,
                },
            );
        }
        Ok(result)
    }

    pub async fn object_response(
        &self,
        object: &ObjectDownload,
        offset: u64,
    ) -> Result<Response, SparkClientError> {
        validate_object_url(object.url.as_str(), &object.sha256, &self.object_origin)?;
        let mut request = self
            .object_client
            .get(object.url.clone())
            .header(header::ACCEPT_ENCODING, "identity");
        if offset > 0 {
            request = request.header(header::RANGE, format!("bytes={offset}-"));
        }
        request
            .send()
            .await
            .map_err(|_| retryable("object connection", None))
    }
}

fn build_clients(https_only: bool) -> Result<(Client, Client), String> {
    let common = || {
        Client::builder()
            .user_agent(concat!("FragmentLauncher/", env!("CARGO_PKG_VERSION")))
            .redirect(Policy::none())
            .https_only(https_only)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
    };
    let plan_client = common()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| format!("Cannot create Spark plan client: {error}"))?;
    let object_client = common()
        .build()
        .map_err(|error| format!("Cannot create Spark object client: {error}"))?;
    Ok((plan_client, object_client))
}

fn validate_object_url(
    value: &str,
    expected_sha256: &str,
    origin: &Url,
) -> Result<Url, SparkClientError> {
    if !valid_sha256(expected_sha256) {
        return Err(SparkClientError::InvalidResponse(
            "expected object SHA-256 is invalid".into(),
        ));
    }
    let url = Url::parse(value)
        .map_err(|_| SparkClientError::InvalidResponse("object URL is malformed".into()))?;
    let expected_path = format!("{OBJECT_PATH_PREFIX}{expected_sha256}");
    let query: Vec<_> = url.query_pairs().collect();
    if url.scheme() != origin.scheme()
        || url.host_str() != origin.host_str()
        || url.port_or_known_default() != origin.port_or_known_default()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.path() != expected_path
        || query.len() != 1
        || query[0].0 != "token"
        || query[0].1.len() < 32
        || query[0].1.len() > 8192
        || query[0].1.chars().any(char::is_control)
    {
        return Err(SparkClientError::InvalidResponse(
            "object URL is outside the authorized Spark object route".into(),
        ));
    }
    Ok(url)
}

async fn collect_bounded(response: Response, maximum: usize) -> Result<Vec<u8>, SparkClientError> {
    if response
        .content_length()
        .is_some_and(|length| length > maximum as u64)
    {
        return Err(SparkClientError::InvalidResponse(
            "Spark response exceeds the declared size limit".into(),
        ));
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| retryable("download-plan body", None))?;
        if bytes
            .len()
            .checked_add(chunk.len())
            .is_none_or(|length| length > maximum)
        {
            return Err(SparkClientError::InvalidResponse(
                "Spark response exceeds the streamed size limit".into(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn validate_access_token(token: &str) -> Result<(), SparkClientError> {
    if token.len() < 16 || token.len() > 8192 || token.chars().any(char::is_control) {
        return Err(SparkClientError::Authentication);
    }
    Ok(())
}

fn valid_release_id(value: &str) -> bool {
    value.len() == 28
        && value.starts_with("rel_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS
    ) || status.is_server_error()
}

pub(super) fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let value = headers.get(header::RETRY_AFTER)?.to_str().ok()?.trim();
    if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        let seconds = value.parse::<u64>().ok()?;
        return Some(Duration::from_secs(seconds).min(MAX_RETRY_AFTER));
    }

    let timestamp = jiff::fmt::rfc2822::DateTimeParser::new()
        .parse_timestamp(value)
        .ok()?;
    let seconds = timestamp
        .as_second()
        .saturating_sub(jiff::Timestamp::now().as_second());
    Some(Duration::from_secs(seconds.max(0) as u64).min(MAX_RETRY_AFTER))
}

fn retryable(operation: &'static str, retry_after: Option<Duration>) -> SparkClientError {
    SparkClientError::Retryable {
        operation,
        retry_after,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HASH: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn production_origin() -> Url {
        Url::parse(SPARK_ORIGIN).unwrap()
    }

    #[test]
    fn accepts_only_exact_redacted_object_urls() {
        let valid = format!(
            "https://fragmc.ru/api/spark2/v1/objects/{HASH}?token={}",
            "x".repeat(64)
        );
        assert!(validate_object_url(&valid, HASH, &production_origin()).is_ok());
        for invalid in [
            format!(
                "http://fragmc.ru/api/spark2/v1/objects/{HASH}?token={}",
                "x".repeat(64)
            ),
            format!(
                "https://evil.invalid/api/spark2/v1/objects/{HASH}?token={}",
                "x".repeat(64)
            ),
            format!(
                "https://fragmc.ru/api/spark2/v1/objects/{}?token={}",
                "b".repeat(64),
                "x".repeat(64)
            ),
            format!(
                "https://fragmc.ru/api/spark2/v1/objects/{HASH}?token={}&extra=1",
                "x".repeat(64)
            ),
        ] {
            assert!(validate_object_url(&invalid, HASH, &production_origin()).is_err());
        }
    }

    #[test]
    fn signed_url_never_appears_in_validation_or_debug_errors() {
        let secret = "never-print-this-token".repeat(3);
        let malformed = format!("not a URL?token={secret}");
        let error = validate_object_url(&malformed, HASH, &production_origin()).unwrap_err();
        assert!(!error.to_string().contains(&secret));

        let value = format!("https://fragmc.ru/api/spark2/v1/objects/{HASH}?token={secret}");
        let object = ObjectDownload {
            sha256: HASH.into(),
            url: validate_object_url(&value, HASH, &production_origin()).unwrap(),
        };
        let debug = format!("{object:?}");
        assert!(debug.contains("[redacted signed URL]"));
        assert!(!debug.contains(&secret));
    }

    #[test]
    fn classifies_only_bounded_transient_http_statuses() {
        for status in [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_EARLY,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::SERVICE_UNAVAILABLE,
        ] {
            assert!(is_retryable_status(status));
        }
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::CONFLICT,
            StatusCode::NOT_FOUND,
        ] {
            assert!(!is_retryable_status(status));
        }
    }

    #[test]
    fn retry_after_is_parsed_and_clamped() {
        let mut headers = HeaderMap::new();
        headers.insert(header::RETRY_AFTER, "2".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(Duration::from_secs(2)));
        headers.insert(header::RETRY_AFTER, "9999".parse().unwrap());
        assert_eq!(retry_after(&headers), Some(MAX_RETRY_AFTER));
        headers.insert(
            header::RETRY_AFTER,
            "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap(),
        );
        assert_eq!(retry_after(&headers), Some(Duration::ZERO));
    }
}
