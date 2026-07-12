use super::{
    managed_fs::RelativeManagedPath,
    spark_client::{is_retryable_status, retry_after, SparkClient, SparkClientError},
    storage::{
        inspect_existing_ancestors, open_or_create_regular_single_link, open_regular_single_link,
    },
    types::{BuildChannel, PresetId},
};
use fs2::FileExt;
use futures_util::StreamExt;
use reqwest::{header, Response, StatusCode};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_PLAN_ATTEMPTS: u8 = 9;
const MAX_TRANSIENT_RETRIES: u8 = 4;
const MAX_OBJECT_AUTH_REPLANS: u8 = 1;
const MAX_RANGE_RESETS: u8 = 1;
const MAX_CLEAN_RETRIES: u8 = 1;
const BASE_RETRY_DELAY: Duration = Duration::from_millis(125);

/// Returns the one canonical managed path for a lowercase SHA-256 CAS object. Callers that
/// consume a previously downloaded object should derive its location from the signed digest,
/// rather than trusting a mutable absolute path carried in progress state.
pub(super) fn cas_object_relative_path(sha256: &str) -> Result<RelativeManagedPath, String> {
    validate_sha256(sha256)?;
    RelativeManagedPath::new(&format!("sha256/{}/{sha256}", &sha256[..2]))
        .map_err(|error| format!("Cannot construct canonical CAS object path: {error}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedObject {
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct VerifiedCasObject {
    pub path: PathBuf,
    pub sha256: String,
    pub size: u64,
    pub resumed_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct CasDownloader {
    cache_root: PathBuf,
    spark: SparkClient,
}

impl CasDownloader {
    pub fn new(cache_root: PathBuf, spark: SparkClient) -> Self {
        Self { cache_root, spark }
    }

    pub async fn ensure_object(
        &self,
        channel: BuildChannel,
        preset: PresetId,
        release_id: &str,
        expected: &ExpectedObject,
        bearer_token: &str,
    ) -> Result<VerifiedCasObject, String> {
        validate_expected(expected)?;
        let paths = CasPaths::new(&self.cache_root, &expected.sha256)?;
        paths.prepare()?;
        let lock = acquire_object_lock(&paths.lock).await?;
        let result = self
            .ensure_object_locked(channel, preset, release_id, expected, bearer_token, &paths)
            .await;
        let unlock = FileExt::unlock(&lock)
            .map_err(|error| format!("Cannot unlock CAS object {}: {error}", expected.sha256));
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    async fn ensure_object_locked(
        &self,
        channel: BuildChannel,
        preset: PresetId,
        release_id: &str,
        expected: &ExpectedObject,
        bearer_token: &str,
        paths: &CasPaths,
    ) -> Result<VerifiedCasObject, String> {
        if paths.final_path.exists() {
            match verify_file(&paths.final_path, expected) {
                Ok(()) => {
                    return Ok(VerifiedCasObject {
                        path: paths.final_path.clone(),
                        sha256: expected.sha256.clone(),
                        size: expected.size,
                        resumed_bytes: expected.size,
                    })
                }
                Err(error) => {
                    open_regular_single_link(&paths.final_path, false).map_err(|_| error)?;
                    fs::remove_file(&paths.final_path)
                        .map_err(|remove| format!("Cannot remove corrupt CAS object: {remove}"))?;
                }
            }
        }

        let mut original_partial = prepare_partial(&paths.partial, expected.size)?;
        let mut object_auth_replans = 0_u8;
        let mut range_resets = 0_u8;
        let mut clean_retries = 0_u8;
        let mut plan_attempts = 0_u8;
        let mut transient_retries = RetryBudget::default();
        loop {
            if plan_attempts >= MAX_PLAN_ATTEMPTS {
                return Err("CAS object download retry limit was reached".into());
            }
            plan_attempts += 1;
            let offset = fs::metadata(&paths.partial)
                .map_err(|error| format!("Cannot inspect CAS partial: {error}"))?
                .len();
            let plan = match self
                .spark
                .download_plan(
                    channel,
                    preset,
                    release_id,
                    std::slice::from_ref(&expected.sha256),
                    bearer_token,
                )
                .await
            {
                Ok(plan) => plan,
                Err(SparkClientError::Retryable { retry_after, .. }) => {
                    transient_retries.wait(retry_after).await?;
                    continue;
                }
                Err(error) => return Err(map_spark_error(error)),
            };
            let object = plan
                .get(&expected.sha256)
                .ok_or_else(|| "Spark omitted the requested CAS object".to_string())?;
            let response = match self.spark.object_response(object, offset).await {
                Ok(response) => response,
                Err(SparkClientError::Retryable { retry_after, .. }) => {
                    transient_retries.wait(retry_after).await?;
                    continue;
                }
                Err(error) => return Err(map_spark_error(error)),
            };
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                object_auth_replans += 1;
                if object_auth_replans > MAX_OBJECT_AUTH_REPLANS {
                    return Err("Spark object authorization expired repeatedly".into());
                }
                continue;
            }
            if status == StatusCode::CONFLICT {
                return Err("release_changed: Spark selected another release".into());
            }
            if is_retryable_status(status) {
                transient_retries
                    .wait(retry_after(response.headers()))
                    .await?;
                continue;
            }
            if status == StatusCode::RANGE_NOT_SATISFIABLE {
                if offset == expected.size && verify_file(&paths.partial, expected).is_ok() {
                    activate_partial(paths, expected)?;
                    return Ok(VerifiedCasObject {
                        path: paths.final_path.clone(),
                        sha256: expected.sha256.clone(),
                        size: expected.size,
                        resumed_bytes: original_partial,
                    });
                }
                truncate_partial(&paths.partial)?;
                original_partial = 0;
                range_resets += 1;
                if range_resets > MAX_RANGE_RESETS {
                    return Err("Spark rejected CAS range repeatedly".into());
                }
                continue;
            }

            let write_offset = validate_download_response(&response, offset, expected.size)?;
            if write_offset == 0 && offset > 0 {
                truncate_partial(&paths.partial)?;
                original_partial = 0;
            }
            match stream_response(response, &paths.partial, write_offset, expected.size).await {
                Ok(()) => {}
                Err(StreamResponseError::Retryable) => {
                    transient_retries.wait(None).await?;
                    continue;
                }
                Err(StreamResponseError::Fatal(error)) => return Err(error),
            }
            let length = fs::metadata(&paths.partial)
                .map_err(|error| format!("Cannot inspect downloaded CAS partial: {error}"))?
                .len();
            if length < expected.size {
                transient_retries.wait(None).await?;
                continue;
            }
            if length > expected.size {
                return Err("Spark object stream exceeded the signed size".into());
            }
            match verify_file(&paths.partial, expected) {
                Ok(()) => {
                    activate_partial(paths, expected)?;
                    return Ok(VerifiedCasObject {
                        path: paths.final_path.clone(),
                        sha256: expected.sha256.clone(),
                        size: expected.size,
                        resumed_bytes: original_partial,
                    });
                }
                Err(error) if clean_retries < MAX_CLEAN_RETRIES => {
                    let _ = error;
                    truncate_partial(&paths.partial)?;
                    original_partial = 0;
                    clean_retries += 1;
                }
                Err(error) => {
                    let _ = fs::remove_file(&paths.partial);
                    return Err(format!(
                        "CAS object failed SHA-256 after a clean retry: {error}"
                    ));
                }
            }
        }
    }
}

#[derive(Default)]
struct RetryBudget {
    used: u8,
}

impl RetryBudget {
    async fn wait(&mut self, retry_after: Option<Duration>) -> Result<(), String> {
        if self.used >= MAX_TRANSIENT_RETRIES {
            return Err("Spark temporary failure retry limit was reached".into());
        }
        let multiplier = 1_u32 << self.used;
        self.used += 1;
        let backoff = BASE_RETRY_DELAY.saturating_mul(multiplier);
        let jitter_window_ms = (backoff.as_millis() / 4).max(1) as u64;
        let jitter_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| u64::from(value.subsec_nanos()) % (jitter_window_ms + 1))
            .unwrap_or(0);
        let jittered_backoff = backoff.saturating_add(Duration::from_millis(jitter_ms));
        let delay = std::cmp::max(jittered_backoff, retry_after.unwrap_or_default());
        tokio::time::sleep(delay).await;
        Ok(())
    }
}

struct CasPaths {
    directory: PathBuf,
    final_path: PathBuf,
    partial: PathBuf,
    lock: PathBuf,
}

impl CasPaths {
    fn new(root: &Path, sha256: &str) -> Result<Self, String> {
        let relative = cas_object_relative_path(sha256)?;
        let directory = root.join("sha256").join(&sha256[..2]);
        Ok(Self {
            final_path: relative.join_to(root),
            partial: directory.join(format!(".{sha256}.part")),
            lock: root.join("locks").join(format!("{sha256}.lock")),
            directory,
        })
    }

    fn prepare(&self) -> Result<(), String> {
        inspect_existing_ancestors(&self.directory)?;
        fs::create_dir_all(&self.directory)
            .map_err(|error| format!("Cannot create CAS object directory: {error}"))?;
        if let Some(lock_root) = self.lock.parent() {
            inspect_existing_ancestors(lock_root)?;
            fs::create_dir_all(lock_root)
                .map_err(|error| format!("Cannot create CAS lock directory: {error}"))?;
            inspect_existing_ancestors(lock_root)?;
        }
        inspect_existing_ancestors(&self.directory)
    }
}

async fn acquire_object_lock(path: &Path) -> Result<File, String> {
    let file = open_or_create_regular_single_link(path)
        .map_err(|error| format!("Cannot open CAS object lock: {error}"))?;
    let started = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if started.elapsed() < Duration::from_secs(10) => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(format!("CAS object is locked by another process: {error}")),
        }
    }
}

fn prepare_partial(path: &Path, expected_size: u64) -> Result<u64, String> {
    if !path.exists() {
        OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .map_err(|error| format!("Cannot create CAS partial: {error}"))?;
        return Ok(0);
    }
    let file = open_regular_single_link(path, true)?;
    let length = file
        .metadata()
        .map_err(|error| format!("Cannot inspect CAS partial: {error}"))?
        .len();
    if length > expected_size {
        file.set_len(0)
            .map_err(|error| format!("Cannot reset oversized CAS partial: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Cannot flush reset CAS partial: {error}"))?;
        Ok(0)
    } else {
        Ok(length)
    }
}

fn truncate_partial(path: &Path) -> Result<(), String> {
    let file = open_regular_single_link(path, true)?;
    file.set_len(0)
        .map_err(|error| format!("Cannot truncate CAS partial: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("Cannot flush CAS partial: {error}"))
}

fn validate_download_response(
    response: &Response,
    requested_offset: u64,
    expected_size: u64,
) -> Result<u64, String> {
    let status = response.status();
    let write_offset = if requested_offset == 0 {
        if status != StatusCode::OK {
            return Err(format!("Fresh Spark object request returned HTTP {status}"));
        }
        0
    } else if status == StatusCode::PARTIAL_CONTENT {
        let header = response
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .ok_or_else(|| "Resumed Spark object response omitted Content-Range".to_string())?;
        let expected = format!(
            "bytes {requested_offset}-{}/{}",
            expected_size.saturating_sub(1),
            expected_size
        );
        if header != expected {
            return Err("Spark returned an invalid Content-Range".into());
        }
        requested_offset
    } else if status == StatusCode::OK {
        0
    } else {
        return Err(format!("Spark object request returned HTTP {status}"));
    };
    let expected_length = expected_size
        .checked_sub(write_offset)
        .ok_or_else(|| "CAS write offset exceeds signed object size".to_string())?;
    if response
        .content_length()
        .is_some_and(|length| length != expected_length)
    {
        return Err("Spark object Content-Length does not match the signed size".into());
    }
    Ok(write_offset)
}

async fn stream_response(
    response: Response,
    path: &Path,
    write_offset: u64,
    expected_size: u64,
) -> Result<(), StreamResponseError> {
    let mut file = open_regular_single_link(path, true)?;
    file.seek(SeekFrom::Start(write_offset))
        .map_err(|error| format!("Cannot seek CAS partial: {error}"))?;
    let mut written = write_offset;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                file.sync_all().map_err(|error| {
                    StreamResponseError::Fatal(format!(
                        "Cannot flush interrupted CAS partial: {error}"
                    ))
                })?;
                return Err(StreamResponseError::Retryable);
            }
        };
        written = written.checked_add(chunk.len() as u64).ok_or_else(|| {
            StreamResponseError::Fatal("CAS object byte counter overflowed".into())
        })?;
        if written > expected_size {
            return Err(StreamResponseError::Fatal(
                "Spark object stream exceeded the signed size".into(),
            ));
        }
        file.write_all(&chunk).map_err(|error| {
            StreamResponseError::Fatal(format!("Cannot write CAS partial: {error}"))
        })?;
    }
    file.sync_all().map_err(|error| {
        StreamResponseError::Fatal(format!("Cannot flush CAS partial: {error}"))
    })?;
    Ok(())
}

enum StreamResponseError {
    Retryable,
    Fatal(String),
}

impl From<String> for StreamResponseError {
    fn from(error: String) -> Self {
        Self::Fatal(error)
    }
}

fn verify_file(path: &Path, expected: &ExpectedObject) -> Result<(), String> {
    let mut file = open_regular_single_link(path, false)?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("Cannot inspect CAS file: {error}"))?;
    if metadata.len() != expected.size {
        return Err(format!(
            "CAS size mismatch: {}/{}",
            metadata.len(),
            expected.size
        ));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| format!("Cannot rewind CAS file: {error}"))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("Cannot hash CAS file: {error}"))?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    let actual = format!("{:x}", hash.finalize());
    if actual != expected.sha256 {
        return Err(format!("CAS SHA-256 mismatch: {actual}"));
    }
    Ok(())
}

fn activate_partial(paths: &CasPaths, expected: &ExpectedObject) -> Result<(), String> {
    verify_file(&paths.partial, expected)?;
    if paths.final_path.exists() {
        verify_file(&paths.final_path, expected)?;
        fs::remove_file(&paths.partial)
            .map_err(|error| format!("Cannot remove duplicate CAS partial: {error}"))?;
        return Ok(());
    }
    fs::rename(&paths.partial, &paths.final_path)
        .map_err(|error| format!("Cannot atomically activate CAS object: {error}"))?;
    verify_file(&paths.final_path, expected)
}

fn validate_expected(expected: &ExpectedObject) -> Result<(), String> {
    validate_sha256(&expected.sha256)
        .map_err(|_| "CAS expectation has an invalid SHA-256".to_string())
}

fn validate_sha256(sha256: &str) -> Result<(), String> {
    if sha256.len() != 64
        || !sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("CAS SHA-256 is invalid".into());
    }
    Ok(())
}

fn map_spark_error(error: SparkClientError) -> String {
    match error {
        SparkClientError::Authentication => {
            "auth_unavailable: Fragment authentication expired".into()
        }
        SparkClientError::Forbidden => {
            "access_forbidden: Fragment entitlement or channel permission was denied".into()
        }
        SparkClientError::ReleaseChanged => {
            "release_changed: Spark selected another release".into()
        }
        SparkClientError::Retryable { .. } => {
            "Spark temporary failure retry limit was reached".into()
        }
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::{TcpListener, TcpStream},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    const RELEASE_ID: &str = "rel_aaaaaaaaaaaaaaaaaaaaaaaa";
    const BEARER: &str = "fragment-access-token-for-tests";

    struct ScriptedResponse {
        expected_path: String,
        expected_range: Option<Option<String>>,
        status: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        body: Vec<u8>,
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-cas-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn spawn_server(
        listener: TcpListener,
        responses: Vec<ScriptedResponse>,
    ) -> thread::JoinHandle<()> {
        thread::spawn(move || {
            for scripted in responses {
                let (mut stream, _) = listener.accept().expect("accept test request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .expect("request timeout");
                let request = read_request(&mut stream);
                let first_line = request.lines().next().expect("HTTP request line");
                let path = first_line
                    .split_ascii_whitespace()
                    .nth(1)
                    .expect("HTTP request path");
                assert_eq!(path, scripted.expected_path);
                if let Some(ref expected) = scripted.expected_range {
                    let actual = request.lines().find_map(|line| {
                        line.split_once(':').and_then(|(name, value)| {
                            name.eq_ignore_ascii_case("range")
                                .then(|| value.trim().to_string())
                        })
                    });
                    assert_eq!(&actual, expected);
                }
                write_response(&mut stream, scripted);
            }
        })
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        let header_end = loop {
            let read = stream.read(&mut buffer).expect("read test request");
            assert!(read > 0, "request ended before headers");
            bytes.extend_from_slice(&buffer[..read]);
            if let Some(index) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                break index + 4;
            }
            assert!(bytes.len() < 64 * 1024, "test request headers too large");
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
            })
            .unwrap_or(0);
        while bytes.len() - header_end < content_length {
            let read = stream.read(&mut buffer).expect("read test request body");
            assert!(read > 0, "request body ended early");
            bytes.extend_from_slice(&buffer[..read]);
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn write_response(stream: &mut TcpStream, scripted: ScriptedResponse) {
        let mut head = format!("HTTP/1.1 {}\r\nConnection: close\r\n", scripted.status);
        if !scripted
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        {
            head.push_str(&format!("Content-Length: {}\r\n", scripted.body.len()));
        }
        for (name, value) in scripted.headers {
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        stream
            .write_all(head.as_bytes())
            .expect("write test headers");
        stream.write_all(&scripted.body).expect("write test body");
        stream.flush().expect("flush test response");
    }

    fn plan_body(origin: &str, hash: &str) -> Vec<u8> {
        format!(
            r#"{{"releaseId":"{RELEASE_ID}","expiresIn":60,"objects":[{{"sha256":"{hash}","url":"{origin}api/spark2/v1/objects/{hash}?token={}"}}]}}"#,
            "signed-object-token-".repeat(3)
        )
        .into_bytes()
    }

    #[test]
    fn verifies_cached_objects_and_rejects_same_size_corruption() {
        let root = temp_root("verify");
        fs::create_dir_all(&root).unwrap();
        let bytes = b"trusted-object";
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        let path = root.join("object");
        fs::write(&path, bytes).unwrap();
        assert!(verify_file(&path, &expected).is_ok());
        fs::write(&path, b"tampered-objec").unwrap();
        assert!(verify_file(&path, &expected).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn parses_exact_resume_content_ranges() {
        let expected = "bytes 10-99/100";
        assert_eq!(expected, format!("bytes {}-{}/{}", 10, 100 - 1, 100));
        assert_ne!("bytes 10-98/100", expected);
        assert_ne!("bytes 0-99/100", expected);
    }

    #[test]
    fn object_paths_are_content_addressed_and_sharded() {
        let hash = "ab".repeat(32);
        let paths = CasPaths::new(Path::new("cache"), &hash).unwrap();
        assert_eq!(paths.final_path, Path::new("cache/sha256/ab").join(&hash));
        assert_eq!(
            paths.partial,
            Path::new("cache/sha256/ab").join(format!(".{hash}.part"))
        );
        assert_eq!(
            cas_object_relative_path(&hash).unwrap().as_str(),
            format!("sha256/ab/{hash}")
        );
        assert!(cas_object_relative_path(&"AB".repeat(32)).is_err());
        assert!(cas_object_relative_path("../object").is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn every_transient_retry_fetches_a_fresh_download_plan() {
        let bytes = b"trusted-object";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}/");
        let plan_path = "/api/spark2/v1/download-plan".to_string();
        let object_path = format!(
            "/api/spark2/v1/objects/{hash}?token={}",
            "signed-object-token-".repeat(3)
        );
        let responses = vec![
            ScriptedResponse {
                expected_path: plan_path.clone(),
                expected_range: None,
                status: "503 Service Unavailable",
                headers: vec![("Retry-After", "0")],
                body: Vec::new(),
            },
            ScriptedResponse {
                expected_path: plan_path.clone(),
                expected_range: None,
                status: "200 OK",
                headers: vec![("Content-Type", "application/json")],
                body: plan_body(&origin, &hash),
            },
            ScriptedResponse {
                expected_path: object_path.clone(),
                expected_range: Some(None),
                status: "503 Service Unavailable",
                headers: vec![],
                body: Vec::new(),
            },
            ScriptedResponse {
                expected_path: plan_path,
                expected_range: None,
                status: "200 OK",
                headers: vec![("Content-Type", "application/json")],
                body: plan_body(&origin, &hash),
            },
            ScriptedResponse {
                expected_path: object_path,
                expected_range: Some(None),
                status: "200 OK",
                headers: vec![],
                body: bytes.to_vec(),
            },
        ];

        let server = spawn_server(listener, responses);
        let root = temp_root("transient-replan");
        let downloader = CasDownloader::new(root.clone(), SparkClient::new_for_test(&origin));
        let result = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                BEARER,
            )
            .await
            .unwrap();
        assert_eq!(fs::read(result.path).unwrap(), bytes);
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn interrupted_body_is_resumed_with_a_fresh_plan() {
        let bytes = b"trusted-object";
        let split = 7_usize;
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}/");
        let token = "signed-object-token-".repeat(3);
        let object_path = format!("/api/spark2/v1/objects/{hash}?token={token}");
        let responses = vec![
            ScriptedResponse {
                expected_path: "/api/spark2/v1/download-plan".into(),
                expected_range: None,
                status: "200 OK",
                headers: vec![("Content-Type", "application/json")],
                body: plan_body(&origin, &hash),
            },
            ScriptedResponse {
                expected_path: object_path.clone(),
                expected_range: Some(None),
                status: "200 OK",
                headers: vec![("Content-Length", "14")],
                body: bytes[..split].to_vec(),
            },
            ScriptedResponse {
                expected_path: "/api/spark2/v1/download-plan".into(),
                expected_range: None,
                status: "200 OK",
                headers: vec![("Content-Type", "application/json")],
                body: plan_body(&origin, &hash),
            },
            ScriptedResponse {
                expected_path: object_path,
                expected_range: Some(Some(format!("bytes={split}-"))),
                status: "206 Partial Content",
                headers: vec![("Content-Range", "bytes 7-13/14")],
                body: bytes[split..].to_vec(),
            },
        ];
        let server = spawn_server(listener, responses);
        let root = temp_root("body-replan");
        let downloader = CasDownloader::new(root.clone(), SparkClient::new_for_test(&origin));
        let result = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                BEARER,
            )
            .await
            .unwrap();
        assert_eq!(result.resumed_bytes, 0);
        assert_eq!(fs::read(result.path).unwrap(), bytes);
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_complete_partial_is_reset_after_416() {
        let bytes = b"trusted-object";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}/");
        let plan_path = "/api/spark2/v1/download-plan".to_string();
        let object_path = format!(
            "/api/spark2/v1/objects/{hash}?token={}",
            "signed-object-token-".repeat(3)
        );
        let responses = vec![
            ScriptedResponse {
                expected_path: plan_path.clone(),
                expected_range: None,
                status: "200 OK",
                headers: vec![("Content-Type", "application/json")],
                body: plan_body(&origin, &hash),
            },
            ScriptedResponse {
                expected_path: object_path.clone(),
                expected_range: Some(Some(format!("bytes={}-", bytes.len()))),
                status: "416 Range Not Satisfiable",
                headers: vec![],
                body: Vec::new(),
            },
            ScriptedResponse {
                expected_path: plan_path,
                expected_range: None,
                status: "200 OK",
                headers: vec![("Content-Type", "application/json")],
                body: plan_body(&origin, &hash),
            },
            ScriptedResponse {
                expected_path: object_path,
                expected_range: Some(None),
                status: "200 OK",
                headers: vec![],
                body: bytes.to_vec(),
            },
        ];
        let server = spawn_server(listener, responses);
        let root = temp_root("range-reset");
        let paths = CasPaths::new(&root, &hash).unwrap();
        paths.prepare().unwrap();
        fs::write(&paths.partial, vec![b'x'; bytes.len()]).unwrap();
        let downloader = CasDownloader::new(root.clone(), SparkClient::new_for_test(&origin));
        let result = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                BEARER,
            )
            .await
            .unwrap();
        assert_eq!(result.resumed_bytes, 0);
        assert_eq!(fs::read(result.path).unwrap(), bytes);
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resumes_only_from_an_exact_206_range() {
        let bytes = b"trusted-object";
        let split = 7_usize;
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}/");
        let token = "signed-object-token-".repeat(3);
        let responses = vec![
            ScriptedResponse {
                expected_path: "/api/spark2/v1/download-plan".into(),
                expected_range: None,
                status: "200 OK",
                headers: vec![("Content-Type", "application/json")],
                body: plan_body(&origin, &hash),
            },
            ScriptedResponse {
                expected_path: format!("/api/spark2/v1/objects/{hash}?token={token}"),
                expected_range: Some(Some(format!("bytes={split}-"))),
                status: "206 Partial Content",
                headers: vec![("Content-Range", "bytes 7-13/14")],
                body: bytes[split..].to_vec(),
            },
        ];
        let server = spawn_server(listener, responses);
        let root = temp_root("exact-206");
        let paths = CasPaths::new(&root, &hash).unwrap();
        paths.prepare().unwrap();
        fs::write(&paths.partial, &bytes[..split]).unwrap();
        let downloader = CasDownloader::new(root.clone(), SparkClient::new_for_test(&origin));
        let result = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                BEARER,
            )
            .await
            .unwrap();
        assert_eq!(result.resumed_bytes, split as u64);
        assert_eq!(fs::read(result.path).unwrap(), bytes);
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_full_200_response_restarts_instead_of_appending() {
        let bytes = b"trusted-object";
        let split = 7_usize;
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}/");
        let token = "signed-object-token-".repeat(3);
        let responses = vec![
            ScriptedResponse {
                expected_path: "/api/spark2/v1/download-plan".into(),
                expected_range: None,
                status: "200 OK",
                headers: vec![("Content-Type", "application/json")],
                body: plan_body(&origin, &hash),
            },
            ScriptedResponse {
                expected_path: format!("/api/spark2/v1/objects/{hash}?token={token}"),
                expected_range: Some(Some(format!("bytes={split}-"))),
                status: "200 OK",
                headers: vec![],
                body: bytes.to_vec(),
            },
        ];
        let server = spawn_server(listener, responses);
        let root = temp_root("full-200-reset");
        let paths = CasPaths::new(&root, &hash).unwrap();
        paths.prepare().unwrap();
        fs::write(&paths.partial, &bytes[..split]).unwrap();
        let downloader = CasDownloader::new(root.clone(), SparkClient::new_for_test(&origin));
        let result = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                BEARER,
            )
            .await
            .unwrap();
        assert_eq!(result.resumed_bytes, 0);
        assert_eq!(fs::read(result.path).unwrap(), bytes);
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn plan_entitlement_denial_is_terminal() {
        let bytes = b"trusted-object";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}/");
        let server = spawn_server(
            listener,
            vec![ScriptedResponse {
                expected_path: "/api/spark2/v1/download-plan".into(),
                expected_range: None,
                status: "403 Forbidden",
                headers: vec![],
                body: Vec::new(),
            }],
        );
        let root = temp_root("terminal-entitlement");
        let downloader = CasDownloader::new(root.clone(), SparkClient::new_for_test(&origin));
        let error = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                BEARER,
            )
            .await
            .unwrap_err();
        assert!(error.starts_with("access_forbidden:"));
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn repeated_object_authorization_failure_is_bounded() {
        let bytes = b"trusted-object";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}/");
        let object_path = format!(
            "/api/spark2/v1/objects/{hash}?token={}",
            "signed-object-token-".repeat(3)
        );
        let plan = || ScriptedResponse {
            expected_path: "/api/spark2/v1/download-plan".into(),
            expected_range: None,
            status: "200 OK",
            headers: vec![("Content-Type", "application/json")],
            body: plan_body(&origin, &hash),
        };
        let forbidden_object = || ScriptedResponse {
            expected_path: object_path.clone(),
            expected_range: Some(None),
            status: "403 Forbidden",
            headers: vec![],
            body: Vec::new(),
        };
        let server = spawn_server(
            listener,
            vec![plan(), forbidden_object(), plan(), forbidden_object()],
        );
        let root = temp_root("bounded-object-auth");
        let downloader = CasDownloader::new(root.clone(), SparkClient::new_for_test(&origin));
        let error = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                BEARER,
            )
            .await
            .unwrap_err();
        assert_eq!(error, "Spark object authorization expired repeatedly");
        server.join().unwrap();
        let _ = fs::remove_dir_all(root);
    }
}
