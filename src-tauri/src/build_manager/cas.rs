use super::{
    managed_fs::{
        ensure_directory_chain, open_or_create_lock_file, FileIdentity, GuardedDirectoryChain,
        ImmutableManagedFile, ManagedFsError, ManagedLockFile, RelativeManagedPath,
        ResumableCommitOutcome, ResumableManagedFile,
    },
    spark_client::{is_retryable_status, retry_after, SparkClient, SparkClientError},
    storage::OwnedCasRoot,
    types::{BuildChannel, PresetId},
};
use fs2::FileExt;
use futures_util::StreamExt;
use reqwest::{header, Response, StatusCode};
use std::{
    fmt,
    time::{Duration, Instant},
};
use uuid::Uuid;

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

#[derive(Debug)]
pub struct VerifiedCasObject {
    binding_nonce: Uuid,
    install_id: Uuid,
    install_root_identity: FileIdentity,
    objects_root_identity: FileIdentity,
    sha256: String,
    size: u64,
    resumed_bytes: u64,
}

pub struct CasDownloader<'root> {
    cache_root: &'root OwnedCasRoot,
    spark: SparkClient,
}

#[derive(Debug)]
pub(super) enum CasError {
    Failed(String),
    AppliedButDurabilityUnconfirmed { destination: String, detail: String },
}

impl fmt::Display for CasError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Failed(message) => formatter.write_str(message),
            Self::AppliedButDurabilityUnconfirmed {
                destination,
                detail,
            } => write!(
                formatter,
                "cas_durability_unconfirmed: CAS activation reached {destination}, but durability is unconfirmed: {detail}"
            ),
        }
    }
}

impl std::error::Error for CasError {}

impl From<String> for CasError {
    fn from(message: String) -> Self {
        Self::Failed(message)
    }
}

impl From<&str> for CasError {
    fn from(message: &str) -> Self {
        Self::Failed(message.to_owned())
    }
}

type CasResult<T> = Result<T, CasError>;

fn managed_error(context: &str, error: ManagedFsError) -> CasError {
    match error {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination,
            detail,
        } => CasError::AppliedButDurabilityUnconfirmed {
            destination: destination.display().to_string(),
            detail: format!("{context}: {detail}"),
        },
        other => CasError::Failed(format!("{context}: {other}")),
    }
}

impl VerifiedCasObject {
    pub(super) fn sha256(&self) -> &str {
        &self.sha256
    }

    pub(super) fn size(&self) -> u64 {
        self.size
    }

    pub(super) fn resumed_bytes(&self) -> u64 {
        self.resumed_bytes
    }

    pub(super) fn open(&self, root: &OwnedCasRoot) -> CasResult<ImmutableManagedFile> {
        root.revalidate().map_err(CasError::Failed)?;
        let (binding_nonce, install_id, install_identity, objects_identity) = root.binding();
        if binding_nonce != self.binding_nonce
            || install_id != self.install_id
            || install_identity != &self.install_root_identity
            || objects_identity != &self.objects_root_identity
        {
            return Err(CasError::Failed(
                "Verified CAS object belongs to another owned CAS root".into(),
            ));
        }
        let relative = cas_object_relative_path(&self.sha256).map_err(CasError::Failed)?;
        let mut file = ImmutableManagedFile::open(root.managed_root(), &relative)
            .map_err(|error| managed_error("Cannot lease verified CAS object", error))?;
        let digest = file
            .sha256(self.size)
            .map_err(|error| managed_error("Cannot re-audit verified CAS object", error))?;
        if digest.size != self.size || digest.sha256 != self.sha256 {
            return Err(CasError::Failed(
                "Verified CAS object changed after download".into(),
            ));
        }
        Ok(file)
    }
}

impl<'root> CasDownloader<'root> {
    pub fn new(cache_root: &'root OwnedCasRoot, spark: SparkClient) -> Self {
        Self { cache_root, spark }
    }

    pub async fn ensure_object(
        &self,
        channel: BuildChannel,
        preset: PresetId,
        release_id: &str,
        expected: &ExpectedObject,
        bearer_token: &str,
    ) -> CasResult<VerifiedCasObject> {
        validate_expected(expected).map_err(CasError::Failed)?;
        self.cache_root.revalidate().map_err(CasError::Failed)?;
        let paths = CasPaths::new(&expected.sha256).map_err(CasError::Failed)?;
        let guards = paths.prepare(self.cache_root)?;
        let lock = acquire_object_lock(self.cache_root, &paths.lock).await?;
        guards.revalidate()?;
        let result = self
            .ensure_object_locked(channel, preset, release_id, expected, bearer_token, &paths)
            .await;
        let unlock = FileExt::unlock(lock.file())
            .map_err(|error| format!("Cannot unlock CAS object {}: {error}", expected.sha256));
        drop(guards);
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(CasError::Failed(error)),
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
    ) -> CasResult<VerifiedCasObject> {
        match audit_existing_final(self.cache_root, expected, expected.size)? {
            ExistingFinal::Missing => {}
            ExistingFinal::Verified(_) => {
                discard_stale_partial(self.cache_root, paths, expected.size)?;
                return match audit_existing_final(self.cache_root, expected, expected.size)? {
                    ExistingFinal::Verified(object) => Ok(object),
                    ExistingFinal::Missing | ExistingFinal::Corrupt => Err(CasError::Failed(
                        "Cached CAS object changed during stale-partial cleanup".into(),
                    )),
                };
            }
            ExistingFinal::Corrupt => {
                super::managed_fs::quarantine_node(
                    self.cache_root.managed_root(),
                    paths.final_path.clone(),
                    &paths.quarantine,
                )
                .map_err(|error| managed_error("Cannot quarantine corrupt CAS object", error))?;
                self.cache_root.revalidate().map_err(CasError::Failed)?;
            }
        }

        let mut partial = ResumableManagedFile::open_or_create(
            self.cache_root.managed_root(),
            paths.partial.clone(),
            expected.size,
        )
        .map_err(|error| managed_error("Cannot open CAS partial", error))?;
        let mut original_partial = partial
            .len()
            .map_err(|error| managed_error("Cannot inspect CAS partial", error))?;
        if original_partial > expected.size {
            partial
                .truncate_zero()
                .map_err(|error| managed_error("Cannot reset oversized CAS partial", error))?;
            original_partial = 0;
        }
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
            self.cache_root.revalidate().map_err(CasError::Failed)?;
            let offset = partial
                .len()
                .map_err(|error| managed_error("Cannot inspect CAS partial", error))?;
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
                Err(error) => return Err(map_spark_error(error).into()),
            };
            let object = plan
                .get(&expected.sha256)
                .ok_or_else(|| CasError::Failed("Spark omitted the requested CAS object".into()))?;
            let response = match self.spark.object_response(object, offset).await {
                Ok(response) => response,
                Err(SparkClientError::Retryable { retry_after, .. }) => {
                    transient_retries.wait(retry_after).await?;
                    continue;
                }
                Err(error) => return Err(map_spark_error(error).into()),
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
                if offset == expected.size && partial_matches(&mut partial, expected)? {
                    return activate_partial(
                        self.cache_root,
                        paths,
                        expected,
                        partial,
                        original_partial,
                    );
                }
                partial
                    .truncate_zero()
                    .map_err(|error| managed_error("Cannot reset rejected CAS partial", error))?;
                original_partial = 0;
                range_resets += 1;
                if range_resets > MAX_RANGE_RESETS {
                    return Err("Spark rejected CAS range repeatedly".into());
                }
                continue;
            }

            let write_offset = validate_download_response(&response, offset, expected.size)
                .map_err(CasError::Failed)?;
            if write_offset == 0 && offset > 0 {
                partial
                    .truncate_zero()
                    .map_err(|error| managed_error("Cannot restart CAS partial", error))?;
                original_partial = 0;
            }
            match stream_response(response, &mut partial, write_offset, expected.size).await {
                Ok(()) => {}
                Err(StreamResponseError::Retryable) => {
                    transient_retries.wait(None).await?;
                    continue;
                }
                Err(StreamResponseError::Fatal(error)) => return Err(error),
            }
            let length = partial
                .len()
                .map_err(|error| managed_error("Cannot inspect downloaded CAS partial", error))?;
            if length < expected.size {
                transient_retries.wait(None).await?;
                continue;
            }
            if length > expected.size {
                return Err("Spark object stream exceeded the signed size".into());
            }
            match partial_matches(&mut partial, expected) {
                Ok(true) => {
                    return activate_partial(
                        self.cache_root,
                        paths,
                        expected,
                        partial,
                        original_partial,
                    );
                }
                Ok(false) if clean_retries < MAX_CLEAN_RETRIES => {
                    partial.truncate_zero().map_err(|error| {
                        managed_error("Cannot reset corrupt CAS partial", error)
                    })?;
                    original_partial = 0;
                    clean_retries += 1;
                }
                Ok(false) => {
                    partial.discard().map_err(|error| {
                        managed_error("Cannot discard corrupt CAS partial", error)
                    })?;
                    return Err(CasError::Failed(
                        "CAS object failed SHA-256 after a clean retry".into(),
                    ));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

#[derive(Default)]
struct RetryBudget {
    used: u8,
}

impl RetryBudget {
    async fn wait(&mut self, retry_after: Option<Duration>) -> CasResult<()> {
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
    directory: RelativeManagedPath,
    final_path: RelativeManagedPath,
    partial: RelativeManagedPath,
    lock: RelativeManagedPath,
    locks: RelativeManagedPath,
    quarantine: RelativeManagedPath,
}

impl CasPaths {
    fn new(sha256: &str) -> Result<Self, String> {
        let final_path = cas_object_relative_path(sha256)?;
        let directory = RelativeManagedPath::new(&format!("sha256/{}", &sha256[..2]))
            .map_err(|error| format!("Cannot construct CAS shard path: {error}"))?;
        let partial = directory
            .join_component(&format!(".{sha256}.part"))
            .map_err(|error| format!("Cannot construct CAS partial path: {error}"))?;
        let locks =
            RelativeManagedPath::new("locks").expect("the static CAS lock directory is valid");
        let lock = locks
            .join_component(&format!("{sha256}.lock"))
            .map_err(|error| format!("Cannot construct CAS lock path: {error}"))?;
        Ok(Self {
            final_path,
            partial,
            lock,
            locks,
            quarantine: RelativeManagedPath::new("quarantine")
                .expect("the static CAS quarantine directory is valid"),
            directory,
        })
    }

    fn prepare(&self, root: &OwnedCasRoot) -> CasResult<PreparedCasPaths> {
        root.revalidate().map_err(CasError::Failed)?;
        let directory = ensure_directory_chain(root.managed_root(), &self.directory)
            .map_err(|error| managed_error("Cannot prepare CAS shard directory", error))?;
        let locks = ensure_directory_chain(root.managed_root(), &self.locks)
            .map_err(|error| managed_error("Cannot prepare CAS lock directory", error))?;
        let quarantine = ensure_directory_chain(root.managed_root(), &self.quarantine)
            .map_err(|error| managed_error("Cannot prepare CAS quarantine directory", error))?;
        root.revalidate().map_err(CasError::Failed)?;
        Ok(PreparedCasPaths {
            _directory: directory,
            _locks: locks,
            _quarantine: quarantine,
        })
    }
}

struct PreparedCasPaths {
    _directory: GuardedDirectoryChain,
    _locks: GuardedDirectoryChain,
    _quarantine: GuardedDirectoryChain,
}

impl PreparedCasPaths {
    fn revalidate(&self) -> CasResult<()> {
        self._directory
            .revalidate()
            .map_err(|error| managed_error("CAS shard directory changed", error))?;
        self._locks
            .revalidate()
            .map_err(|error| managed_error("CAS lock directory changed", error))?;
        self._quarantine
            .revalidate()
            .map_err(|error| managed_error("CAS quarantine directory changed", error))
    }
}

async fn acquire_object_lock(
    root: &OwnedCasRoot,
    path: &RelativeManagedPath,
) -> CasResult<ManagedLockFile> {
    root.revalidate().map_err(CasError::Failed)?;
    let file = open_or_create_lock_file(root.managed_root(), path)
        .map_err(|error| managed_error("Cannot open CAS object lock", error))?;
    let started = Instant::now();
    loop {
        match file.file().try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if started.elapsed() < Duration::from_secs(10) => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => {
                return Err(CasError::Failed(format!(
                    "CAS object is locked by another process: {error}"
                )))
            }
        }
    }
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
    partial: &mut ResumableManagedFile,
    write_offset: u64,
    expected_size: u64,
) -> Result<(), StreamResponseError> {
    let mut written = write_offset;
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                partial.sync_all().map_err(|error| {
                    StreamResponseError::Fatal(managed_error(
                        "Cannot flush interrupted CAS partial",
                        error,
                    ))
                })?;
                return Err(StreamResponseError::Retryable);
            }
        };
        written = written.checked_add(chunk.len() as u64).ok_or_else(|| {
            StreamResponseError::Fatal(CasError::Failed(
                "CAS object byte counter overflowed".into(),
            ))
        })?;
        if written > expected_size {
            return Err(StreamResponseError::Fatal(CasError::Failed(
                "Spark object stream exceeded the signed size".into(),
            )));
        }
        partial
            .write_all_at(written - chunk.len() as u64, &chunk)
            .map_err(|error| {
                StreamResponseError::Fatal(managed_error("Cannot write CAS partial", error))
            })?;
    }
    partial.sync_all().map_err(|error| {
        StreamResponseError::Fatal(managed_error("Cannot flush CAS partial", error))
    })?;
    Ok(())
}

enum StreamResponseError {
    Retryable,
    Fatal(CasError),
}

enum ExistingFinal {
    Missing,
    Corrupt,
    Verified(VerifiedCasObject),
}

fn audit_existing_final(
    root: &OwnedCasRoot,
    expected: &ExpectedObject,
    resumed_bytes: u64,
) -> CasResult<ExistingFinal> {
    root.revalidate().map_err(CasError::Failed)?;
    let relative = cas_object_relative_path(&expected.sha256).map_err(CasError::Failed)?;
    let mut file = match ImmutableManagedFile::open(root.managed_root(), &relative) {
        Ok(file) => file,
        Err(ManagedFsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ExistingFinal::Missing)
        }
        Err(error) => return Err(managed_error("Cannot inspect canonical CAS object", error)),
    };
    if file.info().size != expected.size {
        return Ok(ExistingFinal::Corrupt);
    }
    let digest = file
        .sha256(expected.size)
        .map_err(|error| managed_error("Cannot hash canonical CAS object", error))?;
    if digest.size != expected.size || digest.sha256 != expected.sha256 {
        return Ok(ExistingFinal::Corrupt);
    }
    let (binding_nonce, install_id, install_identity, objects_identity) = root.binding();
    Ok(ExistingFinal::Verified(VerifiedCasObject {
        binding_nonce,
        install_id,
        install_root_identity: install_identity.clone(),
        objects_root_identity: objects_identity.clone(),
        sha256: expected.sha256.clone(),
        size: expected.size,
        resumed_bytes,
    }))
}

pub(super) fn verify_existing_object(
    root: &OwnedCasRoot,
    expected: &ExpectedObject,
    resumed_bytes: u64,
) -> CasResult<VerifiedCasObject> {
    validate_expected(expected).map_err(CasError::Failed)?;
    match audit_existing_final(root, expected, resumed_bytes)? {
        ExistingFinal::Verified(object) => Ok(object),
        ExistingFinal::Missing => Err(CasError::Failed("Canonical CAS object is missing".into())),
        ExistingFinal::Corrupt => Err(CasError::Failed(
            "Canonical CAS object does not match its signed digest".into(),
        )),
    }
}

fn partial_matches(
    partial: &mut ResumableManagedFile,
    expected: &ExpectedObject,
) -> CasResult<bool> {
    let digest = partial
        .sha256(expected.size)
        .map_err(|error| managed_error("Cannot hash CAS partial", error))?;
    Ok(digest.size == expected.size && digest.sha256 == expected.sha256)
}

fn discard_stale_partial(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    expected_size: u64,
) -> CasResult<()> {
    let Some(partial) = ResumableManagedFile::open_existing(
        root.managed_root(),
        paths.partial.clone(),
        expected_size,
    )
    .map_err(|error| managed_error("Cannot inspect stale CAS partial", error))?
    else {
        return Ok(());
    };
    partial
        .discard()
        .map_err(|error| managed_error("Cannot discard stale CAS partial", error))
}

fn activate_partial(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    expected: &ExpectedObject,
    mut partial: ResumableManagedFile,
    resumed_bytes: u64,
) -> CasResult<VerifiedCasObject> {
    if !partial_matches(&mut partial, expected)? {
        return Err(CasError::Failed(
            "CAS partial changed before activation".into(),
        ));
    }
    root.revalidate().map_err(CasError::Failed)?;
    match partial
        .commit_no_replace(paths.final_path.clone())
        .map_err(|error| managed_error("Cannot atomically activate CAS object", error))?
    {
        ResumableCommitOutcome::Committed(committed) => {
            if committed.size != expected.size {
                return Err(CasError::AppliedButDurabilityUnconfirmed {
                    destination: committed.destination.as_str().to_owned(),
                    detail: "committed CAS object has an unexpected size".into(),
                });
            }
        }
        ResumableCommitOutcome::DestinationExists(mut duplicate) => {
            let ExistingFinal::Verified(_) = audit_existing_final(root, expected, resumed_bytes)?
            else {
                return Err(CasError::Failed(
                    "Concurrent CAS winner is absent or does not match the signed object".into(),
                ));
            };
            if !partial_matches(&mut duplicate, expected)? {
                return Err(CasError::Failed(
                    "CAS partial changed while accepting a concurrent winner".into(),
                ));
            }
            duplicate.discard().map_err(|error| {
                managed_error("Cannot discard duplicate exact CAS partial", error)
            })?;
        }
    }
    root.revalidate().map_err(CasError::Failed)?;
    match audit_existing_final(root, expected, resumed_bytes)? {
        ExistingFinal::Verified(object) => Ok(object),
        ExistingFinal::Missing | ExistingFinal::Corrupt => Err(CasError::Failed(
            "Activated CAS object failed its final exact audit".into(),
        )),
    }
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
    use crate::build_manager::storage::select_install_directory;
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        fs::OpenOptions,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::PathBuf,
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

    fn owned_root(label: &str) -> (PathBuf, OwnedCasRoot) {
        let install = temp_root(label);
        let owned = select_install_directory(&install)
            .expect("claim test install")
            .into_owned_cas_root();
        (install, owned)
    }

    fn absolute(root: &OwnedCasRoot, relative: &RelativeManagedPath) -> PathBuf {
        relative.join_to(root.managed_root())
    }

    fn read_verified(root: &OwnedCasRoot, object: &VerifiedCasObject) -> Vec<u8> {
        object
            .open(root)
            .expect("open verified object")
            .read_bounded(object.size())
            .expect("read verified object")
    }

    fn write_partial(root: &OwnedCasRoot, hash: &str, bytes: &[u8]) {
        let paths = CasPaths::new(hash).expect("CAS paths");
        let guards = paths.prepare(root).expect("prepare CAS paths");
        fs::write(absolute(root, &paths.partial), bytes).expect("write partial");
        drop(guards);
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
        let (install, root) = owned_root("verify");
        let bytes = b"trusted-object";
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        let path = absolute(&root, &cas_object_relative_path(&expected.sha256).unwrap());
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        assert!(verify_existing_object(&root, &expected, 0).is_ok());
        fs::write(&path, b"tampered-objec").unwrap();
        assert!(verify_existing_object(&root, &expected, 0).is_err());
        drop(root);
        let _ = fs::remove_dir_all(install);
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
        let paths = CasPaths::new(&hash).unwrap();
        assert_eq!(paths.final_path.as_str(), format!("sha256/ab/{hash}"));
        assert_eq!(paths.partial.as_str(), format!("sha256/ab/.{hash}.part"));
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
        let (install, root) = owned_root("transient-replan");
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
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
        assert_eq!(read_verified(&root, &result), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
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
        let (install, root) = owned_root("body-replan");
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
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
        assert_eq!(result.resumed_bytes(), 0);
        assert_eq!(read_verified(&root, &result), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
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
        let (install, root) = owned_root("range-reset");
        write_partial(&root, &hash, &vec![b'x'; bytes.len()]);
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
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
        assert_eq!(result.resumed_bytes(), 0);
        assert_eq!(read_verified(&root, &result), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn oversized_partial_is_truncated_on_the_same_safe_handle() {
        let bytes = b"trusted-object";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let origin = format!("http://{address}/");
        let object_path = format!(
            "/api/spark2/v1/objects/{hash}?token={}",
            "signed-object-token-".repeat(3)
        );
        let server = spawn_server(
            listener,
            vec![
                ScriptedResponse {
                    expected_path: "/api/spark2/v1/download-plan".into(),
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
            ],
        );
        let (install, root) = owned_root("oversized-partial");
        write_partial(&root, &hash, &[b'x'; 32]);
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
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
            .expect("oversized partial resets");
        assert_eq!(result.resumed_bytes(), 0);
        assert_eq!(read_verified(&root, &result), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
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
        let (install, root) = owned_root("exact-206");
        write_partial(&root, &hash, &bytes[..split]);
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
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
        assert_eq!(result.resumed_bytes(), split as u64);
        assert_eq!(read_verified(&root, &result), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
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
        let (install, root) = owned_root("full-200-reset");
        write_partial(&root, &hash, &bytes[..split]);
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
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
        assert_eq!(result.resumed_bytes(), 0);
        assert_eq!(read_verified(&root, &result), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
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
        let (install, root) = owned_root("terminal-entitlement");
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
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
        assert!(error.to_string().starts_with("access_forbidden:"));
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
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
        let (install, root) = owned_root("bounded-object-auth");
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
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
        assert_eq!(
            error.to_string(),
            "Spark object authorization expired repeatedly"
        );
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn hardlinked_partial_and_lock_are_rejected_before_network_access() {
        for target in ["partial", "lock"] {
            let (install, root) = owned_root(&format!("hardlink-{target}"));
            let bytes = b"hardlink-fixture";
            let hash = format!("{:x}", Sha256::digest(bytes));
            let paths = CasPaths::new(&hash).unwrap();
            let guards = paths.prepare(&root).unwrap();
            let target_path = match target {
                "partial" => {
                    let path = absolute(&root, &paths.partial);
                    fs::write(&path, &bytes[..4]).unwrap();
                    path
                }
                "lock" => absolute(&root, &paths.lock),
                _ => unreachable!(),
            };
            if target == "lock" {
                fs::write(&target_path, b"").unwrap();
            }
            let alias = install.join(format!("{target}-alias"));
            if fs::hard_link(&target_path, &alias).is_ok() {
                let downloader =
                    CasDownloader::new(&root, SparkClient::new_for_test("http://127.0.0.1:9/"));
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
                    .expect_err("hardlinked managed node must fail closed");
                assert!(error.to_string().contains("single-link"));
                drop(downloader);
            }
            drop(guards);
            drop(root);
            fs::remove_dir_all(install).unwrap();
        }
    }

    #[test]
    fn linked_partial_is_never_followed() {
        let (install, root) = owned_root("linked-partial");
        let hash = "cd".repeat(32);
        let paths = CasPaths::new(&hash).unwrap();
        let guards = paths.prepare(&root).unwrap();
        let target = install.join("outside-partial-target");
        fs::write(&target, b"do-not-touch").unwrap();
        let partial_path = absolute(&root, &paths.partial);
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&target, &partial_path).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file(&target, &partial_path).is_ok();
        #[cfg(all(not(unix), not(windows)))]
        let linked = false;
        if linked {
            assert!(ResumableManagedFile::open_or_create(
                root.managed_root(),
                paths.partial.clone(),
                1024,
            )
            .is_err());
            assert_eq!(fs::read(&target).unwrap(), b"do-not-touch");
        }
        drop(guards);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[test]
    fn held_resumable_handle_denies_writer_and_parent_rename_on_windows() {
        let (install, root) = owned_root("held-partial");
        let hash = "ab".repeat(32);
        let paths = CasPaths::new(&hash).unwrap();
        let guards = paths.prepare(&root).unwrap();
        let partial =
            ResumableManagedFile::open_or_create(root.managed_root(), paths.partial.clone(), 1024)
                .unwrap();
        let partial_path = absolute(&root, &paths.partial);
        let shard = absolute(&root, &paths.directory);
        let moved = root.managed_root().join("sha256/moved-ab");
        #[cfg(windows)]
        {
            assert!(OpenOptions::new().write(true).open(&partial_path).is_err());
            assert!(fs::rename(&shard, &moved).is_err());
            assert_eq!(partial.len().unwrap(), 0);
        }
        #[cfg(not(windows))]
        {
            let _ = (&partial_path, &shard, &moved);
            assert_eq!(partial.len().unwrap(), 0);
        }
        drop(partial);
        drop(guards);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[test]
    fn exact_concurrent_winner_is_reaudited_and_duplicate_partial_is_removed() {
        let (install, root) = owned_root("exact-winner");
        let bytes = b"exact-concurrent-winner";
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        let paths = CasPaths::new(&expected.sha256).unwrap();
        let guards = paths.prepare(&root).unwrap();
        fs::write(absolute(&root, &paths.final_path), bytes).unwrap();
        fs::write(absolute(&root, &paths.partial), bytes).unwrap();
        let partial = ResumableManagedFile::open_or_create(
            root.managed_root(),
            paths.partial.clone(),
            expected.size,
        )
        .unwrap();
        let verified = activate_partial(&root, &paths, &expected, partial, 7)
            .expect("accept exact no-replace winner");
        assert_eq!(verified.resumed_bytes(), 7);
        assert_eq!(read_verified(&root, &verified), bytes);
        assert!(fs::symlink_metadata(absolute(&root, &paths.partial)).is_err());
        drop(guards);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cached_exact_final_discards_crash_leftover_partial_without_network() {
        let (install, root) = owned_root("cached-final-stale-partial");
        let bytes = b"already-complete-object";
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        let paths = CasPaths::new(&expected.sha256).unwrap();
        let guards = paths.prepare(&root).unwrap();
        fs::write(absolute(&root, &paths.final_path), bytes).unwrap();
        fs::write(absolute(&root, &paths.partial), b"stale").unwrap();
        drop(guards);
        let downloader =
            CasDownloader::new(&root, SparkClient::new_for_test("http://127.0.0.1:9/"));
        let verified = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &expected,
                BEARER,
            )
            .await
            .expect("cached object should not use network");
        assert_eq!(read_verified(&root, &verified), bytes);
        assert!(fs::symlink_metadata(absolute(&root, &paths.partial)).is_err());
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[test]
    fn durability_unknown_is_a_distinct_terminal_cas_error() {
        let error = managed_error(
            "final CAS parent flush",
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination: PathBuf::from("cache/objects/sha256/ab/object"),
                detail: "injected directory sync failure".into(),
            },
        );
        assert!(matches!(
            &error,
            CasError::AppliedButDurabilityUnconfirmed { .. }
        ));
        assert!(error.to_string().starts_with("cas_durability_unconfirmed:"));
    }
}
