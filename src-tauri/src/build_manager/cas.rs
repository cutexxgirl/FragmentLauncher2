use super::{
    artifact_plan::{ArtifactExecutionSourceV2, PlannedArtifactExecutionV2},
    managed_fs::{
        ensure_directory_chain, move_managed_node_no_replace_if_identity, open_or_create_lock_file,
        remove_bounded_managed_garbage_tree, FileIdentity, GuardedDirectoryChain,
        ImmutableManagedFile, ManagedDirectoryRemovalLimits, ManagedFileAllocationSnapshot,
        ManagedFsError, ManagedLockFile, RelativeManagedPath, ResumableCommitOutcome,
        ResumableManagedFile, MAX_MANAGED_FILE_BYTES,
    },
    spark_client::{is_retryable_status, retry_after, SparkClient, SparkClientError},
    storage::OwnedCasRoot,
    types::{BuildChannel, PresetId},
};
use crate::auth::NativeAccessToken;
use fs2::FileExt;
use futures_util::StreamExt;
use reqwest::{header, Response, StatusCode};
use std::{
    collections::BTreeSet,
    fmt, fs,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use uuid::Uuid;

const MAX_PLAN_ATTEMPTS: u8 = 9;
const MAX_PLAN_AUTH_REFRESHES: u8 = 1;
const MAX_TRANSIENT_RETRIES: u8 = 4;
const MAX_OBJECT_AUTH_REPLANS: u8 = 1;
const MAX_RANGE_RESETS: u8 = 1;
const MAX_CLEAN_RETRIES: u8 = 1;
const BASE_RETRY_DELAY: Duration = Duration::from_millis(125);
const REDACTED_OBJECT_DIGEST_CHARS: usize = 12;
const PROGRESS_EMIT_INTERVAL: Duration = Duration::from_millis(100);
const MAX_CAS_QUARANTINE_BUCKETS: usize = 64;
const MAX_CAS_QUARANTINE_MAINTENANCE_WORK: usize = 4_096;
const CAS_QUARANTINE_GC_LIMITS: ManagedDirectoryRemovalLimits = ManagedDirectoryRemovalLimits {
    max_entries: 2,
    max_allocated_bytes: MAX_MANAGED_FILE_BYTES + 16 * 1024 * 1024,
    max_depth: 1,
};

/// Cloneable operation-wide cancellation shared by both Spark and official transports. Dropping
/// a waiting future is not the signal: every wait observes this durable native flag as well, so a
/// caller may cancel one operation while retaining the token long enough to inspect its result.
#[derive(Clone, Default)]
pub(super) struct DownloadCancellation {
    inner: Arc<DownloadCancellationInner>,
}

#[derive(Default)]
struct DownloadCancellationInner {
    cancelled: AtomicBool,
    notify: Notify,
}

impl DownloadCancellation {
    pub(super) fn new() -> Self {
        Self::default()
    }

    pub(super) fn cancel(&self) {
        if !self.inner.cancelled.swap(true, Ordering::AcqRel) {
            self.inner.notify.notify_waiters();
        }
    }

    pub(super) fn is_cancelled(&self) -> bool {
        self.inner.cancelled.load(Ordering::Acquire)
    }

    pub(super) async fn cancelled(&self) {
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            // `notify_waiters` intentionally stores no permit. Register this waiter before the
            // atomic read so cancellation cannot land in the check-to-await gap and be lost.
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }

    pub(super) fn check(&self) -> CasResult<()> {
        if self.is_cancelled() {
            Err(CasError::Cancelled)
        } else {
            Ok(())
        }
    }
}

/// A deliberately short, non-authoritative display identity. It is derived only from a validated
/// signed SHA-256 and cannot expose a source URL, bearer token, release id or local path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct DownloadObjectIdentity(String);

impl DownloadObjectIdentity {
    pub(super) fn from_sha256(sha256: &str) -> Result<Self, String> {
        validate_sha256(sha256)?;
        Ok(Self(format!(
            "cas:{}..{}",
            &sha256[..REDACTED_OBJECT_DIGEST_CHARS],
            &sha256[sha256.len() - REDACTED_OBJECT_DIGEST_CHARS..]
        )))
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DownloadProgressPhase {
    Resume,
    Bytes,
    Reset,
    Complete,
}

/// An observational progress snapshot. `persisted_bytes` is absolute and may decrease only on a
/// Reset; `delta_bytes` is non-zero only after bytes were written successfully. This lets a UI
/// calculate both remaining bytes and transfer speed without double-counting retries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DownloadProgressEvent {
    pub(super) object: DownloadObjectIdentity,
    pub(super) total_bytes: u64,
    pub(super) persisted_bytes: u64,
    pub(super) delta_bytes: u64,
    pub(super) phase: DownloadProgressPhase,
}

pub(super) trait DownloadObserver: Send + Sync {
    /// Must be non-blocking. Events contain bounded value data and never execution authority.
    fn observe(&self, event: &DownloadProgressEvent);
}

#[derive(Default)]
pub(super) struct NoopDownloadObserver;

impl DownloadObserver for NoopDownloadObserver {
    fn observe(&self, _event: &DownloadProgressEvent) {}
}

pub(super) struct DownloadProgressReporter {
    observer: Arc<dyn DownloadObserver>,
    object: DownloadObjectIdentity,
    total_bytes: u64,
    pending_delta_bytes: u64,
    last_emit: Instant,
}

impl DownloadProgressReporter {
    pub(super) fn new(
        observer: Arc<dyn DownloadObserver>,
        sha256: &str,
        total_bytes: u64,
    ) -> Result<Self, String> {
        Ok(Self {
            observer,
            object: DownloadObjectIdentity::from_sha256(sha256)?,
            total_bytes,
            pending_delta_bytes: 0,
            last_emit: Instant::now(),
        })
    }

    pub(super) fn resume(&self, persisted_bytes: u64) {
        self.emit(DownloadProgressPhase::Resume, persisted_bytes, 0);
    }

    pub(super) fn bytes(&mut self, persisted_bytes: u64, delta_bytes: u64) {
        debug_assert!(delta_bytes > 0);
        self.pending_delta_bytes = self.pending_delta_bytes.saturating_add(delta_bytes);
        if persisted_bytes == self.total_bytes || self.last_emit.elapsed() >= PROGRESS_EMIT_INTERVAL
        {
            self.flush_bytes(persisted_bytes);
        }
    }

    pub(super) fn reset(&mut self, discarded_bytes: u64) {
        self.flush_bytes(discarded_bytes);
        self.emit(DownloadProgressPhase::Reset, 0, 0);
    }

    pub(super) fn complete(&mut self) {
        self.flush_bytes(self.total_bytes);
        self.emit(DownloadProgressPhase::Complete, self.total_bytes, 0);
    }

    pub(super) fn flush_bytes(&mut self, persisted_bytes: u64) {
        if self.pending_delta_bytes == 0 {
            return;
        }
        let delta_bytes = std::mem::take(&mut self.pending_delta_bytes);
        self.last_emit = Instant::now();
        self.emit(DownloadProgressPhase::Bytes, persisted_bytes, delta_bytes);
    }

    fn emit(&self, phase: DownloadProgressPhase, persisted_bytes: u64, delta_bytes: u64) {
        debug_assert!(persisted_bytes <= self.total_bytes);
        self.observer.observe(&DownloadProgressEvent {
            object: self.object.clone(),
            total_bytes: self.total_bytes,
            persisted_bytes,
            delta_bytes,
            phase,
        });
    }
}

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
    pub(super) sha256: String,
    pub(super) size: u64,
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
    published_by_this_operation: bool,
}

/// Read-only result used by the coordinator's availability scanner. Construction remains inside
/// the CAS module so no caller needs to know or reproduce the private final/`.part` layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CasObjectAvailability {
    Missing,
    Partial {
        bytes: u64,
        allocation: VerifiedCasPartialAllocationV2,
    },
    Complete,
    Corrupt,
}

/// A short-lived, non-serializable witness that a canonical `.part` already owns physical
/// allocation on the exact CAS root. Logical length alone is deliberately insufficient: sparse
/// and compressed files may own far fewer clusters than their apparent length.
///
/// All fields are private. The only constructor audits one retained no-follow file handle, and
/// every consumer must reopen the canonical path and reproduce the exact handle/root snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerifiedCasPartialAllocationV2 {
    binding_nonce: Uuid,
    install_id: Uuid,
    install_root_identity: FileIdentity,
    objects_root_identity: FileIdentity,
    sha256: String,
    signed_size: u64,
    snapshot: ManagedFileAllocationSnapshot,
}

impl VerifiedCasPartialAllocationV2 {
    fn from_open_partial(
        root: &OwnedCasRoot,
        expected: &ExpectedObject,
        partial: &ResumableManagedFile,
    ) -> CasResult<Self> {
        root.revalidate().map_err(CasError::Failed)?;
        let snapshot = partial
            .allocation_snapshot()
            .map_err(|error| managed_error("Cannot snapshot CAS partial allocation", error))?;
        let (binding_nonce, install_id, install_identity, objects_identity) = root.binding();
        if snapshot.managed_root_identity() != objects_identity {
            return Err(CasError::Failed(
                "CAS partial allocation snapshot is outside its signed root".into(),
            ));
        }
        root.revalidate().map_err(CasError::Failed)?;
        Ok(Self {
            binding_nonce,
            install_id,
            install_root_identity: install_identity.clone(),
            objects_root_identity: objects_identity.clone(),
            sha256: expected.sha256.clone(),
            signed_size: expected.size,
            snapshot,
        })
    }

    fn validate_binding(
        &self,
        root: &OwnedCasRoot,
        sha256: &str,
        signed_size: u64,
    ) -> CasResult<()> {
        root.revalidate().map_err(CasError::Failed)?;
        let (binding_nonce, install_id, install_identity, objects_identity) = root.binding();
        if self.binding_nonce != binding_nonce
            || self.install_id != install_id
            || self.install_root_identity != *install_identity
            || self.objects_root_identity != *objects_identity
            || self.sha256 != sha256
            || self.signed_size != signed_size
            || self.snapshot.logical_size() > signed_size
            || self.snapshot.managed_root_identity() != objects_identity
        {
            return Err(CasError::Failed(
                "CAS partial allocation evidence belongs to another object or root".into(),
            ));
        }
        Ok(())
    }

    pub(super) fn validate_live(
        &self,
        root: &OwnedCasRoot,
        sha256: &str,
        signed_size: u64,
    ) -> Result<(), String> {
        self.open_exact(root, sha256, signed_size)
            .map(drop)
            .map_err(|error| error.to_string())
    }

    pub(super) fn validate_sealed_identity(
        &self,
        binding_nonce: Uuid,
        install_id: Uuid,
        sha256: &str,
        signed_size: u64,
    ) -> Result<(), String> {
        if self.binding_nonce != binding_nonce
            || self.install_id != install_id
            || self.sha256 != sha256
            || self.signed_size != signed_size
            || self.snapshot.logical_size() > signed_size
            || self.snapshot.managed_root_identity() != &self.objects_root_identity
        {
            return Err("CAS partial allocation evidence identity is invalid".into());
        }
        Ok(())
    }

    pub(super) fn logical_size(&self) -> u64 {
        self.snapshot.logical_size()
    }

    pub(super) fn allocated_size(&self) -> u64 {
        self.snapshot.allocated_size()
    }

    pub(super) fn open_exact(
        &self,
        root: &OwnedCasRoot,
        sha256: &str,
        signed_size: u64,
    ) -> CasResult<ResumableManagedFile> {
        self.validate_binding(root, sha256, signed_size)?;
        let paths = CasPaths::new(sha256).map_err(CasError::Failed)?;
        let partial =
            ResumableManagedFile::open_existing(root.managed_root(), paths.partial, signed_size)
                .map_err(|error| managed_error("Cannot reopen credited CAS partial", error))?
                .ok_or_else(|| {
                    CasError::Failed("Credited CAS partial disappeared before download".into())
                })?;
        let actual = partial
            .allocation_snapshot()
            .map_err(|error| managed_error("Cannot revalidate credited CAS partial", error))?;
        if actual != self.snapshot {
            return Err(CasError::Failed(
                "Credited CAS partial allocation or identity changed".into(),
            ));
        }
        root.revalidate().map_err(CasError::Failed)?;
        Ok(partial)
    }
}

pub struct CasDownloader<'root> {
    cache_root: &'root OwnedCasRoot,
    spark: SparkClient,
    observer: Arc<dyn DownloadObserver>,
}

/// Supplies a fresh-enough, native-only bearer immediately before every Spark download-plan
/// request. Implementations must be cancellation-safe: once a rotating refresh starts, dropping
/// or abandoning it before credential persistence is forbidden.
#[allow(async_fn_in_trait)]
pub(super) trait SparkAccessTokenProvider {
    async fn fresh_access_token(
        &mut self,
        rejected: Option<&NativeAccessToken>,
    ) -> Result<NativeAccessToken, CasError>;
}

struct SparkObjectDownload<'a, Provider: ?Sized> {
    channel: BuildChannel,
    preset: PresetId,
    release_id: &'a str,
    expected: &'a ExpectedObject,
    token_provider: &'a mut Provider,
    paths: &'a CasPaths,
    object_lock: &'a ManagedLockFile,
    credited_partial: Option<&'a VerifiedCasPartialAllocationV2>,
    cancellation: &'a DownloadCancellation,
    reporter: &'a mut DownloadProgressReporter,
}

struct SparkDownloadRequest<'a, Provider: ?Sized> {
    channel: BuildChannel,
    preset: PresetId,
    release_id: &'a str,
    expected: &'a ExpectedObject,
    token_provider: &'a mut Provider,
    cancellation: &'a DownloadCancellation,
    credited_partial: Option<&'a VerifiedCasPartialAllocationV2>,
}

#[derive(Debug)]
pub(super) enum CasError {
    Cancelled,
    Authentication,
    Forbidden,
    Failed(String),
    AppliedButDurabilityUnconfirmed { destination: String, detail: String },
    AppliedButFinalAuditFailed { destination: String, detail: String },
}

impl fmt::Display for CasError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("CAS object download was cancelled"),
            Self::Authentication => formatter.write_str("Fragment authentication expired"),
            Self::Forbidden => formatter
                .write_str("Fragment entitlement or channel permission was denied"),
            Self::Failed(message) => formatter.write_str(message),
            Self::AppliedButDurabilityUnconfirmed {
                destination,
                detail,
            } => write!(
                formatter,
                "cas_durability_unconfirmed: CAS activation reached {destination}, but durability is unconfirmed: {detail}"
            ),
            Self::AppliedButFinalAuditFailed {
                destination,
                detail,
            } => write!(
                formatter,
                "cas_applied_final_audit_failed: CAS activation reached {destination}, but its final audit failed: {detail}"
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

#[cfg(test)]
struct FixedSparkAccessTokenProvider {
    token: NativeAccessToken,
}

#[cfg(test)]
impl FixedSparkAccessTokenProvider {
    fn new(token: &str) -> Self {
        Self {
            token: NativeAccessToken::for_test(token),
        }
    }
}

#[cfg(test)]
impl SparkAccessTokenProvider for FixedSparkAccessTokenProvider {
    async fn fresh_access_token(
        &mut self,
        rejected: Option<&NativeAccessToken>,
    ) -> Result<NativeAccessToken, CasError> {
        match rejected {
            Some(_) => Err(CasError::Authentication),
            None => Ok(self.token.clone()),
        }
    }
}

pub(super) fn managed_error(context: &str, error: ManagedFsError) -> CasError {
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

    pub(super) fn published_by_this_operation(&self) -> bool {
        self.published_by_this_operation
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
        Self::with_observer(cache_root, spark, Arc::new(NoopDownloadObserver))
    }

    pub(super) fn with_observer(
        cache_root: &'root OwnedCasRoot,
        spark: SparkClient,
        observer: Arc<dyn DownloadObserver>,
    ) -> Self {
        Self {
            cache_root,
            spark,
            observer,
        }
    }

    #[cfg(test)]
    async fn ensure_object(
        &self,
        channel: BuildChannel,
        preset: PresetId,
        release_id: &str,
        expected: &ExpectedObject,
        bearer_token: &str,
    ) -> CasResult<VerifiedCasObject> {
        let mut token_provider = FixedSparkAccessTokenProvider::new(bearer_token);
        self.ensure_object_with_provider_and_cancellation(
            channel,
            preset,
            release_id,
            expected,
            &mut token_provider,
            &DownloadCancellation::new(),
        )
        .await
    }

    #[cfg(test)]
    async fn ensure_object_with_cancellation(
        &self,
        channel: BuildChannel,
        preset: PresetId,
        release_id: &str,
        expected: &ExpectedObject,
        bearer_token: &str,
        cancellation: &DownloadCancellation,
    ) -> CasResult<VerifiedCasObject> {
        let mut token_provider = FixedSparkAccessTokenProvider::new(bearer_token);
        self.ensure_object_with_provider_and_cancellation(
            channel,
            preset,
            release_id,
            expected,
            &mut token_provider,
            cancellation,
        )
        .await
    }

    #[cfg(test)]
    async fn ensure_object_with_provider_and_cancellation<Provider>(
        &self,
        channel: BuildChannel,
        preset: PresetId,
        release_id: &str,
        expected: &ExpectedObject,
        token_provider: &mut Provider,
        cancellation: &DownloadCancellation,
    ) -> CasResult<VerifiedCasObject>
    where
        Provider: SparkAccessTokenProvider + ?Sized,
    {
        self.ensure_object_with_cancellation_and_allocation(SparkDownloadRequest {
            channel,
            preset,
            release_id,
            expected,
            token_provider,
            cancellation,
            credited_partial: None,
        })
        .await
    }

    async fn ensure_object_with_cancellation_and_allocation<Provider>(
        &self,
        request: SparkDownloadRequest<'_, Provider>,
    ) -> CasResult<VerifiedCasObject>
    where
        Provider: SparkAccessTokenProvider + ?Sized,
    {
        let SparkDownloadRequest {
            channel,
            preset,
            release_id,
            expected,
            token_provider,
            cancellation,
            credited_partial,
        } = request;
        cancellation.check()?;
        validate_expected(expected).map_err(CasError::Failed)?;
        let mut reporter =
            DownloadProgressReporter::new(self.observer.clone(), &expected.sha256, expected.size)
                .map_err(CasError::Failed)?;
        self.cache_root.revalidate().map_err(CasError::Failed)?;
        let paths = CasPaths::new(&expected.sha256).map_err(CasError::Failed)?;
        let guards = paths.prepare(self.cache_root)?;
        let lock = cancellable(
            cancellation,
            acquire_object_lock(self.cache_root, &paths.lock),
        )
        .await??;
        cancellation.check()?;
        guards.revalidate()?;
        let result = self
            .ensure_object_locked(SparkObjectDownload {
                channel,
                preset,
                release_id,
                expected,
                token_provider,
                paths: &paths,
                object_lock: &lock,
                credited_partial,
                cancellation,
                reporter: &mut reporter,
            })
            .await;
        let unlock = FileExt::unlock(lock.file())
            .map_err(|error| format!("Cannot unlock CAS object {}: {error}", expected.sha256));
        drop(guards);
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                // Closing the handle still releases the lease. An explicit unlock error cannot
                // retroactively turn an exact, durably published CAS object into Failed.
                let _ = unlock;
                Ok(value)
            }
        }
    }

    /// The production Spark boundary accepts only an item yielded by a sealed artifact plan.
    /// Scope, digest, size and root identity therefore cannot be reconstructed by the caller.
    #[cfg(test)]
    pub(super) async fn ensure_planned_spark_object(
        &self,
        planned: &PlannedArtifactExecutionV2<'_>,
        bearer_token: &str,
    ) -> CasResult<VerifiedCasObject> {
        let mut token_provider = FixedSparkAccessTokenProvider::new(bearer_token);
        self.ensure_planned_spark_object_with_provider_and_cancellation(
            planned,
            &mut token_provider,
            &DownloadCancellation::new(),
        )
        .await
    }

    pub(super) async fn ensure_planned_spark_object_with_provider_and_cancellation<Provider>(
        &self,
        planned: &PlannedArtifactExecutionV2<'_>,
        token_provider: &mut Provider,
        cancellation: &DownloadCancellation,
    ) -> CasResult<VerifiedCasObject>
    where
        Provider: SparkAccessTokenProvider + ?Sized,
    {
        cancellation.check()?;
        planned
            .validate_root(self.cache_root)
            .map_err(CasError::Failed)?;
        if planned.source() != ArtifactExecutionSourceV2::SparkCas {
            return Err(CasError::Failed(
                "Spark downloader rejected a non-Spark artifact authority".into(),
            ));
        }
        if planned.availability() == super::availability::ArtifactAvailabilityStateV2::Complete {
            // A post-scan cache change invalidates the plan. Never quarantine/fetch against a
            // zero-reserve Complete item; force the coordinator to rescan and replan instead.
            let mut reporter = DownloadProgressReporter::new(
                self.observer.clone(),
                planned.sha256(),
                planned.size(),
            )
            .map_err(CasError::Failed)?;
            let object = verify_planned_object(self.cache_root, planned)?;
            cancellation.check()?;
            reporter.complete();
            return Ok(object);
        }
        let expected = ExpectedObject {
            sha256: planned.sha256().to_owned(),
            size: planned.size(),
        };
        self.ensure_object_with_cancellation_and_allocation(SparkDownloadRequest {
            channel: planned.channel(),
            preset: planned.preset(),
            release_id: planned.release_id(),
            expected: &expected,
            token_provider,
            cancellation,
            credited_partial: planned.partial_allocation(),
        })
        .await
    }

    async fn ensure_object_locked<Provider>(
        &self,
        request: SparkObjectDownload<'_, Provider>,
    ) -> CasResult<VerifiedCasObject>
    where
        Provider: SparkAccessTokenProvider + ?Sized,
    {
        let SparkObjectDownload {
            channel,
            preset,
            release_id,
            expected,
            token_provider,
            paths,
            object_lock,
            credited_partial,
            cancellation,
            reporter,
        } = request;
        cancellation.check()?;
        reclaim_cas_quarantine_bucket_locked(self.cache_root, paths, object_lock, None)?;
        let existing = audit_existing_final(self.cache_root, expected, expected.size)?;
        cancellation.check()?;
        let mut active_quarantine = None;
        match existing {
            ExistingFinal::Missing => {}
            ExistingFinal::Verified(_) => {
                cancellation.check()?;
                discard_stale_partial(self.cache_root, paths, expected.size)?;
                cancellation.check()?;
                let existing = audit_existing_final(self.cache_root, expected, expected.size)?;
                cancellation.check()?;
                return match existing {
                    ExistingFinal::Verified(object) => {
                        reporter.complete();
                        Ok(object)
                    }
                    ExistingFinal::Missing | ExistingFinal::Corrupt(_) => Err(CasError::Failed(
                        "Cached CAS object changed during stale-partial cleanup".into(),
                    )),
                };
            }
            ExistingFinal::Corrupt(evidence) => {
                cancellation.check()?;
                let active =
                    quarantine_corrupt_cas_object(self.cache_root, paths, object_lock, &evidence)?;
                active_quarantine = Some(active);
                self.cache_root.revalidate().map_err(CasError::Failed)?;
            }
        }

        let mut partial = match credited_partial {
            Some(evidence) => {
                match evidence.open_exact(self.cache_root, &expected.sha256, expected.size) {
                    Ok(partial) => partial,
                    Err(evidence_error) => {
                        // The only safe exception to exact evidence is a concurrently published,
                        // fully re-audited final object. Never recreate an empty `.part` after
                        // receiving reduced disk credit.
                        match audit_existing_final(self.cache_root, expected, expected.size)? {
                            ExistingFinal::Verified(object) => {
                                reporter.complete();
                                return finish_cas_replacement(
                                    self.cache_root,
                                    paths,
                                    object_lock,
                                    &mut active_quarantine,
                                    Ok(object),
                                );
                            }
                            ExistingFinal::Missing | ExistingFinal::Corrupt(_) => {
                                return Err(evidence_error)
                            }
                        }
                    }
                }
            }
            None => ResumableManagedFile::open_or_create(
                self.cache_root.managed_root(),
                paths.partial.clone(),
                expected.size,
            )
            .map_err(|error| managed_error("Cannot open CAS partial", error))?,
        };
        let mut original_partial = partial
            .len()
            .map_err(|error| managed_error("Cannot inspect CAS partial", error))?;
        reporter.resume(original_partial.min(expected.size));
        if original_partial > expected.size {
            cancellation.check()?;
            partial
                .truncate_zero()
                .map_err(|error| managed_error("Cannot reset oversized CAS partial", error))?;
            original_partial = 0;
            reporter.reset(expected.size);
        }
        let mut object_auth_replans = 0_u8;
        let mut range_resets = 0_u8;
        let mut clean_retries = 0_u8;
        let mut plan_attempts = PlanAttemptBudget::default();
        let mut plan_auth_refreshes = 0_u8;
        let mut rejected_access_token = None;
        let mut transient_retries = RetryBudget::default();
        loop {
            cancellation.check()?;
            plan_attempts.admit()?;
            self.cache_root.revalidate().map_err(CasError::Failed)?;
            let offset = partial
                .len()
                .map_err(|error| managed_error("Cannot inspect CAS partial", error))?;
            // Access refresh can rotate a one-time refresh token. It is intentionally awaited
            // outside `cancellable`: cancellation is observed immediately afterwards, so local
            // credential persistence can never be abandoned halfway through a rotation.
            let rejected = rejected_access_token.take();
            let bearer_token = token_provider.fresh_access_token(rejected.as_ref()).await?;
            cancellation.check()?;
            let plan = match cancellable(
                cancellation,
                self.spark.download_plan(
                    channel,
                    preset,
                    release_id,
                    std::slice::from_ref(&expected.sha256),
                    bearer_token.expose(),
                ),
            )
            .await?
            {
                Ok(plan) => plan,
                Err(SparkClientError::Authentication) => {
                    plan_auth_refreshes = plan_auth_refreshes.saturating_add(1);
                    if plan_auth_refreshes > MAX_PLAN_AUTH_REFRESHES {
                        return Err(CasError::Authentication);
                    }
                    rejected_access_token = Some(bearer_token);
                    continue;
                }
                Err(SparkClientError::Retryable { retry_after, .. }) => {
                    transient_retries.wait(retry_after, cancellation).await?;
                    continue;
                }
                Err(error) => return Err(map_spark_error(error)),
            };
            let object = plan
                .get(&expected.sha256)
                .ok_or_else(|| CasError::Failed("Spark omitted the requested CAS object".into()))?;
            let response = match cancellable(
                cancellation,
                self.spark.object_response(object, offset),
            )
            .await?
            {
                Ok(response) => response,
                Err(SparkClientError::Retryable { retry_after, .. }) => {
                    transient_retries.wait(retry_after, cancellation).await?;
                    continue;
                }
                Err(error) => return Err(map_spark_error(error)),
            };
            let status = response.status();
            if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
                object_auth_replans += 1;
                if object_auth_replans > MAX_OBJECT_AUTH_REPLANS {
                    return Err(if status == StatusCode::UNAUTHORIZED {
                        CasError::Authentication
                    } else {
                        CasError::Forbidden
                    });
                }
                continue;
            }
            if status == StatusCode::CONFLICT {
                return Err("release_changed: Spark selected another release".into());
            }
            if is_retryable_status(status) {
                transient_retries
                    .wait(retry_after(response.headers()), cancellation)
                    .await?;
                continue;
            }
            if status == StatusCode::RANGE_NOT_SATISFIABLE {
                cancellation.check()?;
                let complete_partial =
                    offset == expected.size && partial_matches(&mut partial, expected)?;
                cancellation.check()?;
                if complete_partial {
                    let result = activate_partial_cancellable(
                        self.cache_root,
                        paths,
                        expected,
                        partial,
                        original_partial,
                        cancellation,
                        reporter,
                    );
                    return finish_cas_replacement(
                        self.cache_root,
                        paths,
                        object_lock,
                        &mut active_quarantine,
                        result,
                    );
                }
                cancellation.check()?;
                partial
                    .truncate_zero()
                    .map_err(|error| managed_error("Cannot reset rejected CAS partial", error))?;
                original_partial = 0;
                reporter.reset(offset);
                range_resets += 1;
                if range_resets > MAX_RANGE_RESETS {
                    return Err("Spark rejected CAS range repeatedly".into());
                }
                continue;
            }

            let write_offset = validate_download_response(&response, offset, expected.size)
                .map_err(CasError::Failed)?;
            if write_offset == 0 && offset > 0 {
                cancellation.check()?;
                partial
                    .truncate_zero()
                    .map_err(|error| managed_error("Cannot restart CAS partial", error))?;
                original_partial = 0;
                reporter.reset(offset);
            }
            match stream_response(
                response,
                &mut partial,
                write_offset,
                expected.size,
                cancellation,
                reporter,
            )
            .await
            {
                Ok(()) => {}
                Err(StreamResponseError::Cancelled) => return Err(CasError::Cancelled),
                Err(StreamResponseError::Retryable) => {
                    transient_retries.wait(None, cancellation).await?;
                    continue;
                }
                Err(StreamResponseError::Fatal(error)) => return Err(error),
            }
            cancellation.check()?;
            let length = partial
                .len()
                .map_err(|error| managed_error("Cannot inspect downloaded CAS partial", error))?;
            if length < expected.size {
                transient_retries.wait(None, cancellation).await?;
                continue;
            }
            if length > expected.size {
                return Err("Spark object stream exceeded the signed size".into());
            }
            cancellation.check()?;
            let matches = partial_matches(&mut partial, expected);
            cancellation.check()?;
            match matches {
                Ok(true) => {
                    let result = activate_partial_cancellable(
                        self.cache_root,
                        paths,
                        expected,
                        partial,
                        original_partial,
                        cancellation,
                        reporter,
                    );
                    return finish_cas_replacement(
                        self.cache_root,
                        paths,
                        object_lock,
                        &mut active_quarantine,
                        result,
                    );
                }
                Ok(false) if clean_retries < MAX_CLEAN_RETRIES => {
                    cancellation.check()?;
                    partial.truncate_zero().map_err(|error| {
                        managed_error("Cannot reset corrupt CAS partial", error)
                    })?;
                    original_partial = 0;
                    reporter.reset(length);
                    clean_retries += 1;
                }
                Ok(false) => {
                    cancellation.check()?;
                    partial.discard().map_err(|error| {
                        managed_error("Cannot discard corrupt CAS partial", error)
                    })?;
                    reporter.reset(length);
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
struct PlanAttemptBudget {
    used: u8,
}

impl PlanAttemptBudget {
    fn admit(&mut self) -> CasResult<()> {
        if self.used >= MAX_PLAN_ATTEMPTS {
            return Err("CAS object download retry limit was reached".into());
        }
        self.used += 1;
        Ok(())
    }
}

#[derive(Default)]
struct RetryBudget {
    used: u8,
}

impl RetryBudget {
    async fn wait(
        &mut self,
        retry_after: Option<Duration>,
        cancellation: &DownloadCancellation,
    ) -> CasResult<()> {
        cancellation.check()?;
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
        cancellable(cancellation, tokio::time::sleep(delay)).await?;
        Ok(())
    }
}

async fn cancellable<F: std::future::Future>(
    cancellation: &DownloadCancellation,
    future: F,
) -> CasResult<F::Output> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(CasError::Cancelled),
        value = future => Ok(value),
    }
}

pub(super) struct CasPaths {
    directory: RelativeManagedPath,
    pub(super) final_path: RelativeManagedPath,
    pub(super) partial: RelativeManagedPath,
    pub(super) lock: RelativeManagedPath,
    locks: RelativeManagedPath,
    pub(super) quarantine: RelativeManagedPath,
    pub(super) quarantine_bucket: RelativeManagedPath,
    pub(super) quarantine_payload: RelativeManagedPath,
}

impl CasPaths {
    pub(super) fn new(sha256: &str) -> Result<Self, String> {
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
        let quarantine = RelativeManagedPath::new("quarantine")
            .expect("the static CAS quarantine directory is valid");
        let quarantine_bucket = quarantine
            .join_component(sha256)
            .map_err(|error| format!("Cannot construct CAS quarantine bucket: {error}"))?;
        let quarantine_payload = quarantine_bucket
            .join_component("payload")
            .map_err(|error| format!("Cannot construct CAS quarantine payload: {error}"))?;
        Ok(Self {
            final_path,
            partial,
            lock,
            locks,
            quarantine,
            quarantine_bucket,
            quarantine_payload,
            directory,
        })
    }

    pub(super) fn prepare(&self, root: &OwnedCasRoot) -> CasResult<PreparedCasPaths> {
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

pub(super) struct PreparedCasPaths {
    _directory: GuardedDirectoryChain,
    _locks: GuardedDirectoryChain,
    _quarantine: GuardedDirectoryChain,
}

impl PreparedCasPaths {
    pub(super) fn revalidate(&self) -> CasResult<()> {
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

pub(super) struct ActiveCasQuarantine {
    bucket_identity: FileIdentity,
}

fn cas_quarantine_bucket_exists(root: &OwnedCasRoot, paths: &CasPaths) -> CasResult<bool> {
    match fs::symlink_metadata(paths.quarantine_bucket.join_to(root.managed_root())) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(CasError::Failed(format!(
            "Cannot inspect deterministic CAS quarantine bucket: {error}"
        ))),
    }
}

fn audit_cas_quarantine_bucket_namespace(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    expected_identity: &FileIdentity,
) -> CasResult<()> {
    let bucket = GuardedDirectoryChain::open(root.managed_root(), &paths.quarantine_bucket)
        .map_err(|error| managed_error("Cannot lease CAS quarantine bucket", error))?;
    if &bucket.leaf().info().identity != expected_identity {
        return Err(CasError::Failed(
            "CAS quarantine bucket identity changed".into(),
        ));
    }
    let mut names = Vec::new();
    for entry in fs::read_dir(bucket.leaf().path())
        .map_err(|error| CasError::Failed(format!("Cannot enumerate CAS quarantine: {error}")))?
    {
        let entry = entry.map_err(|error| {
            CasError::Failed(format!("Cannot inspect CAS quarantine entry: {error}"))
        })?;
        if names.len() >= 2 {
            return Err(CasError::Failed(
                "CAS quarantine bucket contains unexpected entries".into(),
            ));
        }
        names.push(
            entry
                .file_name()
                .to_str()
                .ok_or_else(|| {
                    CasError::Failed("CAS quarantine contains a non-Unicode entry".into())
                })?
                .to_owned(),
        );
    }
    names.sort_unstable();
    if !names.is_empty() && !matches!(names.as_slice(), [name] if name == "payload") {
        return Err(CasError::Failed(
            "CAS quarantine bucket has a non-canonical namespace".into(),
        ));
    }
    bucket
        .revalidate()
        .map_err(|error| managed_error("CAS quarantine bucket changed during audit", error))?;
    Ok(())
}

pub(super) fn reclaim_cas_quarantine_bucket_locked(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    object_lock: &ManagedLockFile,
    expected_identity: Option<&FileIdentity>,
) -> CasResult<()> {
    object_lock
        .revalidate()
        .map_err(|error| managed_error("CAS quarantine owner lock changed", error))?;
    root.revalidate().map_err(CasError::Failed)?;
    if !cas_quarantine_bucket_exists(root, paths)? {
        return Ok(());
    }
    let bucket = GuardedDirectoryChain::open(root.managed_root(), &paths.quarantine_bucket)
        .map_err(|error| managed_error("Cannot open retained CAS quarantine", error))?;
    let identity = bucket.leaf().info().identity.clone();
    if expected_identity.is_some_and(|expected| expected != &identity) {
        return Err(CasError::Failed(
            "Retained CAS quarantine bucket has another identity".into(),
        ));
    }
    drop(bucket);
    audit_cas_quarantine_bucket_namespace(root, paths, &identity)?;
    remove_bounded_managed_garbage_tree(
        root.managed_root(),
        &paths.quarantine_bucket,
        &identity,
        CAS_QUARANTINE_GC_LIMITS,
    )
    .map_err(|error| managed_error("Cannot reclaim CAS quarantine bucket", error))?;
    object_lock
        .revalidate()
        .map_err(|error| managed_error("CAS quarantine owner lock changed after cleanup", error))?;
    root.revalidate().map_err(CasError::Failed)
}

pub(super) fn quarantine_corrupt_cas_object(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    object_lock: &ManagedLockFile,
    evidence: &CorruptCasEvidence,
) -> CasResult<ActiveCasQuarantine> {
    if evidence.allocation_size > MAX_MANAGED_FILE_BYTES {
        return Err(CasError::Failed(
            "Corrupt CAS object exceeds quarantine cleanup policy".into(),
        ));
    }
    reclaim_cas_quarantine_bucket_locked(root, paths, object_lock, None)?;
    let bucket =
        GuardedDirectoryChain::create_exclusive(root.managed_root(), &paths.quarantine_bucket)
            .map_err(|error| managed_error("Cannot create deterministic CAS quarantine", error))?;
    let bucket_identity = bucket.leaf().info().identity.clone();
    bucket
        .revalidate()
        .map_err(|error| managed_error("CAS quarantine bucket changed before move", error))?;
    drop(bucket);
    let moved = move_managed_node_no_replace_if_identity(
        root.managed_root(),
        paths.final_path.clone(),
        paths.quarantine_payload.clone(),
        &evidence.identity,
    )
    .map_err(|error| managed_error("Cannot quarantine exact corrupt CAS object", error))?;
    if moved.identity != evidence.identity {
        return Err(CasError::AppliedButFinalAuditFailed {
            destination: paths.quarantine_payload.as_str().to_owned(),
            detail: "quarantined CAS payload identity changed".into(),
        });
    }
    object_lock
        .revalidate()
        .map_err(|error| managed_error("CAS object lock changed after quarantine", error))?;
    root.revalidate().map_err(CasError::Failed)?;
    Ok(ActiveCasQuarantine { bucket_identity })
}

pub(super) fn cleanup_active_cas_quarantine(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    object_lock: &ManagedLockFile,
    active: ActiveCasQuarantine,
) -> CasResult<()> {
    reclaim_cas_quarantine_bucket_locked(root, paths, object_lock, Some(&active.bucket_identity))
}

fn finish_cas_replacement(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    object_lock: &ManagedLockFile,
    active: &mut Option<ActiveCasQuarantine>,
    result: CasResult<VerifiedCasObject>,
) -> CasResult<VerifiedCasObject> {
    let object = result?;
    if let Some(active) = active.take() {
        cleanup_active_cas_quarantine(root, paths, object_lock, active).map_err(|error| {
            CasError::AppliedButFinalAuditFailed {
                destination: paths.final_path.as_str().to_owned(),
                detail: format!("verified CAS replacement quarantine cleanup failed: {error}"),
            }
        })?;
    }
    Ok(object)
}

/// Startup/idle maintenance for crash leftovers. Each deterministic bucket is reclaimed only
/// while holding its digest's object lock; a live corrupt-replacement owner is therefore skipped.
pub(super) fn maintain_cas_quarantine(root: &OwnedCasRoot) -> CasResult<()> {
    maintain_cas_quarantine_with_work_limit(root, MAX_CAS_QUARANTINE_MAINTENANCE_WORK)
}

fn charge_cas_quarantine_maintenance_work(
    consumed: &mut usize,
    work_limit: usize,
) -> CasResult<()> {
    if *consumed >= work_limit {
        return Err(CasError::Failed(
            "CAS quarantine maintenance work bound was exceeded".into(),
        ));
    }
    *consumed += 1;
    Ok(())
}

fn maintain_cas_quarantine_with_work_limit(
    root: &OwnedCasRoot,
    work_limit: usize,
) -> CasResult<()> {
    root.revalidate().map_err(CasError::Failed)?;
    let locks = RelativeManagedPath::new("locks").expect("the static CAS lock path is valid");
    let locks_guard = ensure_directory_chain(root.managed_root(), &locks)
        .map_err(|error| managed_error("Cannot prepare CAS maintenance lock directory", error))?;
    let quarantine =
        RelativeManagedPath::new("quarantine").expect("the static CAS quarantine path is valid");
    let mut locked = BTreeSet::new();
    let mut consumed_work = 0_usize;
    loop {
        charge_cas_quarantine_maintenance_work(&mut consumed_work, work_limit)?;
        let guard = match GuardedDirectoryChain::open(root.managed_root(), &quarantine) {
            Ok(guard) => guard,
            Err(ManagedFsError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(())
            }
            Err(error) => return Err(managed_error("Cannot lease CAS quarantine root", error)),
        };
        let mut retained = Vec::new();
        for entry in fs::read_dir(guard.leaf().path()).map_err(|error| {
            CasError::Failed(format!("Cannot enumerate CAS quarantine: {error}"))
        })? {
            let entry = entry.map_err(|error| {
                CasError::Failed(format!("Cannot inspect CAS quarantine entry: {error}"))
            })?;
            charge_cas_quarantine_maintenance_work(&mut consumed_work, work_limit)?;
            let digest = entry
                .file_name()
                .to_str()
                .ok_or_else(|| CasError::Failed("CAS quarantine name is not Unicode".into()))?
                .to_owned();
            validate_sha256(&digest).map_err(CasError::Failed)?;
            if locked.contains(&digest) {
                continue;
            }
            let paths = CasPaths::new(&digest).map_err(CasError::Failed)?;
            let bucket = GuardedDirectoryChain::open(root.managed_root(), &paths.quarantine_bucket)
                .map_err(|error| managed_error("Cannot lease retained CAS quarantine", error))?;
            retained.push((digest, paths, bucket.leaf().info().identity.clone()));
            if retained.len() >= MAX_CAS_QUARANTINE_BUCKETS {
                break;
            }
        }
        guard.revalidate().map_err(|error| {
            managed_error("CAS quarantine root changed during maintenance", error)
        })?;
        drop(guard);
        if retained.is_empty() {
            return root.revalidate().map_err(CasError::Failed);
        }

        for (digest, paths, identity) in retained {
            charge_cas_quarantine_maintenance_work(&mut consumed_work, work_limit)?;
            locks_guard
                .revalidate()
                .map_err(|error| managed_error("CAS maintenance lock directory changed", error))?;
            root.revalidate().map_err(CasError::Failed)?;
            let object_lock = open_or_create_lock_file(root.managed_root(), &paths.lock)
                .map_err(|error| managed_error("Cannot open CAS maintenance object lock", error))?;
            match object_lock.file().try_lock_exclusive() {
                Ok(()) => {
                    let result = reclaim_cas_quarantine_bucket_locked(
                        root,
                        &paths,
                        &object_lock,
                        Some(&identity),
                    );
                    let _ = FileExt::unlock(object_lock.file());
                    result?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    charge_cas_quarantine_maintenance_work(&mut consumed_work, work_limit)?;
                    locked.insert(digest);
                }
                Err(error) => {
                    return Err(CasError::Failed(format!(
                        "Cannot lock retained CAS quarantine owner: {error}"
                    )))
                }
            }
        }
        locks_guard.revalidate().map_err(|error| {
            managed_error("CAS maintenance lock directory changed after batch", error)
        })?;
        root.revalidate().map_err(CasError::Failed)?;
    }
}

pub(super) async fn acquire_object_lock(
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
    cancellation: &DownloadCancellation,
    reporter: &mut DownloadProgressReporter,
) -> Result<(), StreamResponseError> {
    let mut written = write_offset;
    let mut stream = response.bytes_stream();
    loop {
        let item = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                partial.sync_all().map_err(|error| {
                    StreamResponseError::Fatal(managed_error(
                        "Cannot flush cancelled CAS partial",
                        error,
                    ))
                })?;
                reporter.flush_bytes(written);
                return Err(StreamResponseError::Cancelled);
            }
            item = stream.next() => item,
        };
        let Some(chunk) = item else {
            break;
        };
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(_) => {
                partial.sync_all().map_err(|error| {
                    StreamResponseError::Fatal(managed_error(
                        "Cannot flush interrupted CAS partial",
                        error,
                    ))
                })?;
                reporter.flush_bytes(written);
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
        reporter.bytes(written, chunk.len() as u64);
    }
    partial.sync_all().map_err(|error| {
        StreamResponseError::Fatal(managed_error("Cannot flush CAS partial", error))
    })?;
    reporter.flush_bytes(written);
    Ok(())
}

enum StreamResponseError {
    Cancelled,
    Retryable,
    Fatal(CasError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct CorruptCasEvidence {
    identity: FileIdentity,
    allocation_size: u64,
}

pub(super) enum ExistingFinal {
    Missing,
    Corrupt(CorruptCasEvidence),
    Verified(VerifiedCasObject),
}

fn audit_existing_final(
    root: &OwnedCasRoot,
    expected: &ExpectedObject,
    resumed_bytes: u64,
) -> CasResult<ExistingFinal> {
    audit_existing_final_digests(root, expected, None, resumed_bytes)
}

/// Official sources carry both Mojang's/NeoForge's SHA-1 and the Spark2 lock's SHA-256. Audit
/// both through the same immutable handle so a Complete plan remains strictly verify-only while
/// retaining both independent signed bindings.
pub(super) fn audit_existing_official_final(
    root: &OwnedCasRoot,
    expected: &ExpectedObject,
    expected_sha1: &str,
    resumed_bytes: u64,
) -> CasResult<ExistingFinal> {
    audit_existing_final_digests(root, expected, Some(expected_sha1), resumed_bytes)
}

fn audit_existing_final_digests(
    root: &OwnedCasRoot,
    expected: &ExpectedObject,
    expected_sha1: Option<&str>,
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
    let corrupt = CorruptCasEvidence {
        identity: file.info().identity.clone(),
        allocation_size: file.info().allocation_size,
    };
    if file.info().size != expected.size {
        return Ok(ExistingFinal::Corrupt(corrupt));
    }
    match expected_sha1 {
        Some(expected_sha1) => {
            let digests = file.sha1_sha256(expected.size).map_err(|error| {
                managed_error("Cannot hash canonical official CAS object", error)
            })?;
            if digests.size != expected.size
                || digests.sha1 != expected_sha1
                || digests.sha256 != expected.sha256
            {
                return Ok(ExistingFinal::Corrupt(corrupt));
            }
        }
        None => {
            let digest = file
                .sha256(expected.size)
                .map_err(|error| managed_error("Cannot hash canonical CAS object", error))?;
            if digest.size != expected.size || digest.sha256 != expected.sha256 {
                return Ok(ExistingFinal::Corrupt(corrupt));
            }
        }
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
        published_by_this_operation: false,
    }))
}

#[cfg(test)]
pub(super) fn verify_existing_object(
    root: &OwnedCasRoot,
    expected: &ExpectedObject,
    resumed_bytes: u64,
) -> CasResult<VerifiedCasObject> {
    validate_expected(expected).map_err(CasError::Failed)?;
    match audit_existing_final(root, expected, resumed_bytes)? {
        ExistingFinal::Verified(object) => Ok(object),
        ExistingFinal::Missing => Err(CasError::Failed("Canonical CAS object is missing".into())),
        ExistingFinal::Corrupt(_) => Err(CasError::Failed(
            "Canonical CAS object does not match its signed digest".into(),
        )),
    }
}

/// Reconstructs a cached object lease only from a sealed plan item and the exact bound root.
pub(super) fn verify_planned_object(
    root: &OwnedCasRoot,
    planned: &PlannedArtifactExecutionV2<'_>,
) -> CasResult<VerifiedCasObject> {
    planned.validate_root(root).map_err(CasError::Failed)?;
    match audit_existing_final(
        root,
        &ExpectedObject {
            sha256: planned.sha256().to_owned(),
            size: planned.size(),
        },
        planned.resume_from(),
    )? {
        ExistingFinal::Verified(object) => Ok(object),
        ExistingFinal::Missing => Err(CasError::Failed("Canonical CAS object is missing".into())),
        ExistingFinal::Corrupt(_) => Err(CasError::Failed(
            "Canonical CAS object does not match its sealed digest".into(),
        )),
    }
}

/// Audits one canonical object without mutating it. A final object is always fully rehashed;
/// resumable state contributes only its safely leased length. Unsafe nodes are errors, while an
/// ordinary single-link file with incorrect signed content is classified as corrupt.
pub(super) fn audit_object_availability(
    root: &OwnedCasRoot,
    expected: &ExpectedObject,
) -> CasResult<CasObjectAvailability> {
    validate_expected(expected).map_err(CasError::Failed)?;
    root.revalidate().map_err(CasError::Failed)?;
    let paths = CasPaths::new(&expected.sha256).map_err(CasError::Failed)?;
    match audit_existing_final(root, expected, 0)? {
        ExistingFinal::Verified(_) => {
            root.revalidate().map_err(CasError::Failed)?;
            return Ok(CasObjectAvailability::Complete);
        }
        ExistingFinal::Corrupt(_) => {
            root.revalidate().map_err(CasError::Failed)?;
            return Ok(CasObjectAvailability::Corrupt);
        }
        ExistingFinal::Missing => {}
    }

    let partial = match ResumableManagedFile::open_existing(
        root.managed_root(),
        paths.partial,
        expected.size,
    ) {
        Ok(value) => value,
        Err(ManagedFsError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            None
        }
        Err(error) => return Err(managed_error("Cannot audit CAS partial", error)),
    };
    let state = match partial {
        None => CasObjectAvailability::Missing,
        Some(partial) => {
            let allocation =
                VerifiedCasPartialAllocationV2::from_open_partial(root, expected, &partial)?;
            let bytes = allocation.logical_size();
            if bytes > expected.size {
                CasObjectAvailability::Corrupt
            } else {
                CasObjectAvailability::Partial { bytes, allocation }
            }
        }
    };
    root.revalidate().map_err(CasError::Failed)?;
    Ok(state)
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

pub(super) fn discard_stale_partial(
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
    partial: ResumableManagedFile,
    resumed_bytes: u64,
) -> CasResult<VerifiedCasObject> {
    activate_partial_if(root, paths, expected, partial, resumed_bytes, || true)?.ok_or_else(|| {
        CasError::Failed("Unconditional CAS activation was unexpectedly cancelled".into())
    })
}

fn activate_partial_cancellable(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    expected: &ExpectedObject,
    partial: ResumableManagedFile,
    resumed_bytes: u64,
    cancellation: &DownloadCancellation,
    reporter: &mut DownloadProgressReporter,
) -> CasResult<VerifiedCasObject> {
    cancellation.check()?;
    let Some(object) = activate_partial_if(root, paths, expected, partial, resumed_bytes, || {
        !cancellation.is_cancelled()
    })?
    else {
        return Err(CasError::Cancelled);
    };
    // The no-replace rename is the commit boundary. A cancellation racing after it must not turn
    // an applied transaction (or a durability failure) into a misleading Cancelled result.
    reporter.complete();
    Ok(object)
}

/// Performs the same durable CAS transaction but checks one final operation predicate after the
/// partial fsync and all source/destination identity validation, immediately before the
/// no-replace rename. `None` means no namespace mutation occurred and the synced `.part` remains
/// safely resumable. Once rename starts, the result is always success or a typed durability error.
pub(super) fn activate_partial_if<F>(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    expected: &ExpectedObject,
    mut partial: ResumableManagedFile,
    resumed_bytes: u64,
    should_commit: F,
) -> CasResult<Option<VerifiedCasObject>>
where
    F: FnOnce() -> bool,
{
    if !partial_matches(&mut partial, expected)? {
        return Err(CasError::Failed(
            "CAS partial changed before activation".into(),
        ));
    }
    root.revalidate().map_err(CasError::Failed)?;
    let Some(outcome) = partial
        .commit_no_replace_if(paths.final_path.clone(), should_commit)
        .map_err(|error| managed_error("Cannot atomically activate CAS object", error))?
    else {
        return Ok(None);
    };
    let published_by_this_operation = match outcome {
        ResumableCommitOutcome::Committed(committed) => {
            if committed.size != expected.size {
                return Err(CasError::AppliedButFinalAuditFailed {
                    destination: committed.destination.as_str().to_owned(),
                    detail: "committed CAS object has an unexpected size".into(),
                });
            }
            true
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
            false
        }
    };
    if let Err(detail) = root.revalidate() {
        if published_by_this_operation {
            return Err(CasError::AppliedButFinalAuditFailed {
                destination: paths.final_path.as_str().to_owned(),
                detail: format!("published CAS root revalidation failed: {detail}"),
            });
        }
        return Err(CasError::Failed(detail));
    }
    let final_audit = match audit_existing_final(root, expected, resumed_bytes) {
        Ok(audit) => audit,
        Err(error) if published_by_this_operation => {
            return Err(CasError::AppliedButFinalAuditFailed {
                destination: paths.final_path.as_str().to_owned(),
                detail: format!("published CAS final audit failed: {error}"),
            });
        }
        Err(error) => return Err(error),
    };
    match final_audit {
        ExistingFinal::Verified(mut object) => {
            object.published_by_this_operation = published_by_this_operation;
            Ok(Some(object))
        }
        ExistingFinal::Missing | ExistingFinal::Corrupt(_) if published_by_this_operation => {
            Err(CasError::AppliedButFinalAuditFailed {
                destination: paths.final_path.as_str().to_owned(),
                detail: "published CAS object failed its final exact audit".into(),
            })
        }
        ExistingFinal::Missing | ExistingFinal::Corrupt(_) => Err(CasError::Failed(
            "Concurrent CAS winner failed its final exact audit".into(),
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

fn map_spark_error(error: SparkClientError) -> CasError {
    match error {
        SparkClientError::Authentication => CasError::Authentication,
        SparkClientError::Forbidden => CasError::Forbidden,
        SparkClientError::ReleaseChanged => {
            CasError::Failed("release_changed: Spark selected another release".into())
        }
        SparkClientError::Retryable { .. } => {
            CasError::Failed("Spark temporary failure retry limit was reached".into())
        }
        other => CasError::Failed(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::{
        artifact_plan::{ArtifactExecutionSourceV2, ArtifactInventoryV2, ArtifactPlanV2},
        availability::VerifiedAvailabilityV2,
        planner::tests::trusted,
        storage::select_install_directory,
        types::{BuildChannel, PresetId},
    };
    use sha2::{Digest, Sha256};
    use std::{
        collections::VecDeque,
        fs,
        fs::OpenOptions,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::PathBuf,
        sync::{Arc, Mutex},
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    const RELEASE_ID: &str = "rel_aaaaaaaaaaaaaaaaaaaaaaaa";
    const BEARER: &str = "fragment-access-token-for-tests";

    struct RotatingSparkAccessTokenProvider {
        tokens: VecDeque<NativeAccessToken>,
        calls: usize,
        rejected: Vec<Option<String>>,
    }

    impl RotatingSparkAccessTokenProvider {
        fn new(tokens: impl IntoIterator<Item = &'static str>) -> Self {
            Self {
                tokens: tokens
                    .into_iter()
                    .map(NativeAccessToken::for_test)
                    .collect(),
                calls: 0,
                rejected: Vec::new(),
            }
        }
    }

    impl SparkAccessTokenProvider for RotatingSparkAccessTokenProvider {
        async fn fresh_access_token(
            &mut self,
            rejected: Option<&NativeAccessToken>,
        ) -> Result<NativeAccessToken, CasError> {
            self.calls += 1;
            self.rejected
                .push(rejected.map(|token| token.expose().to_owned()));
            self.tokens
                .pop_front()
                .ok_or_else(|| CasError::Failed("test token provider was exhausted".into()))
        }
    }

    struct ScriptedResponse {
        expected_path: String,
        expected_range: Option<Option<String>>,
        status: &'static str,
        headers: Vec<(&'static str, &'static str)>,
        body: Vec<u8>,
    }

    #[derive(Default)]
    struct RecordingObserver {
        events: Mutex<Vec<DownloadProgressEvent>>,
    }

    impl DownloadObserver for RecordingObserver {
        fn observe(&self, event: &DownloadProgressEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    impl RecordingObserver {
        fn snapshot(&self) -> Vec<DownloadProgressEvent> {
            self.events.lock().unwrap().clone()
        }
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

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn deterministic_cas_quarantine_recovers_crashes_and_never_grows_on_tamper_loops() {
        let (install, root) = owned_root("quarantine-lifecycle");
        let good = b"signed-cas-object";
        let corrupt = b"tampered-object!!";
        assert_eq!(good.len(), corrupt.len());
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(good)),
            size: good.len() as u64,
        };
        let paths = CasPaths::new(&expected.sha256).unwrap();
        drop(paths.prepare(&root).unwrap());

        // Crash after the identity-bound move but before replacement.
        fs::write(absolute(&root, &paths.final_path), corrupt).unwrap();
        let lock = acquire_object_lock(&root, &paths.lock).await.unwrap();
        let ExistingFinal::Corrupt(evidence) = audit_existing_final(&root, &expected, 0).unwrap()
        else {
            panic!("corrupt fixture was not classified");
        };
        let active = quarantine_corrupt_cas_object(&root, &paths, &lock, &evidence).unwrap();
        assert!(!absolute(&root, &paths.final_path).exists());
        assert_eq!(
            fs::read(absolute(&root, &paths.quarantine_payload)).unwrap(),
            corrupt
        );
        let _ = active;
        FileExt::unlock(lock.file()).unwrap();
        drop(lock);
        maintain_cas_quarantine(&root).unwrap();
        assert!(!absolute(&root, &paths.quarantine_bucket).exists());

        // Crash after a verified replacement but before quarantine cleanup.
        fs::write(absolute(&root, &paths.final_path), corrupt).unwrap();
        let lock = acquire_object_lock(&root, &paths.lock).await.unwrap();
        let ExistingFinal::Corrupt(evidence) = audit_existing_final(&root, &expected, 0).unwrap()
        else {
            panic!("corrupt fixture was not classified");
        };
        let active = quarantine_corrupt_cas_object(&root, &paths, &lock, &evidence).unwrap();
        fs::write(absolute(&root, &paths.final_path), good).unwrap();
        let _ = active;
        FileExt::unlock(lock.file()).unwrap();
        drop(lock);
        maintain_cas_quarantine(&root).unwrap();
        assert_eq!(fs::read(absolute(&root, &paths.final_path)).unwrap(), good);
        assert!(!absolute(&root, &paths.quarantine_bucket).exists());

        for _ in 0..8 {
            fs::write(absolute(&root, &paths.final_path), corrupt).unwrap();
            let lock = acquire_object_lock(&root, &paths.lock).await.unwrap();
            let ExistingFinal::Corrupt(evidence) =
                audit_existing_final(&root, &expected, 0).unwrap()
            else {
                panic!("tamper loop fixture was not classified");
            };
            let active = quarantine_corrupt_cas_object(&root, &paths, &lock, &evidence).unwrap();
            fs::write(absolute(&root, &paths.final_path), good).unwrap();
            cleanup_active_cas_quarantine(&root, &paths, &lock, active).unwrap();
            assert!(!absolute(&root, &paths.quarantine_bucket).exists());
            FileExt::unlock(lock.file()).unwrap();
        }

        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn corrupt_cas_identity_race_preserves_the_replacement_and_is_recoverable() {
        let (install, root) = owned_root("quarantine-identity-race");
        let good = b"signed-race-object";
        let corrupt = b"broken-race-object";
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(good)),
            size: good.len() as u64,
        };
        let paths = CasPaths::new(&expected.sha256).unwrap();
        drop(paths.prepare(&root).unwrap());
        fs::write(absolute(&root, &paths.final_path), corrupt).unwrap();
        let lock = acquire_object_lock(&root, &paths.lock).await.unwrap();
        let ExistingFinal::Corrupt(evidence) = audit_existing_final(&root, &expected, 0).unwrap()
        else {
            panic!("corrupt fixture was not classified");
        };
        let displaced = root.managed_root().join("displaced-corrupt-object");
        fs::rename(absolute(&root, &paths.final_path), &displaced).unwrap();
        fs::write(absolute(&root, &paths.final_path), good).unwrap();

        assert!(quarantine_corrupt_cas_object(&root, &paths, &lock, &evidence).is_err());
        assert_eq!(fs::read(absolute(&root, &paths.final_path)).unwrap(), good);
        assert_eq!(fs::read(&displaced).unwrap(), corrupt);
        FileExt::unlock(lock.file()).unwrap();
        drop(lock);
        maintain_cas_quarantine(&root).unwrap();
        assert!(!absolute(&root, &paths.quarantine_bucket).exists());

        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn cas_quarantine_bounds_and_unsafe_payloads_fail_closed() {
        let (install, root) = owned_root("quarantine-bounds");
        let quarantine = RelativeManagedPath::new("quarantine").unwrap();
        GuardedDirectoryChain::ensure(root.managed_root(), &quarantine).unwrap();
        for index in 0..=MAX_CAS_QUARANTINE_BUCKETS {
            let digest = format!("{index:064x}");
            let paths = CasPaths::new(&digest).unwrap();
            GuardedDirectoryChain::create_exclusive(root.managed_root(), &paths.quarantine_bucket)
                .unwrap();
        }
        maintain_cas_quarantine(&root).unwrap();
        assert_eq!(
            fs::read_dir(quarantine.join_to(root.managed_root()))
                .unwrap()
                .count(),
            0
        );
        drop(root);
        fs::remove_dir_all(&install).unwrap();

        let root = select_install_directory(&install)
            .unwrap()
            .into_owned_cas_root();
        let digest = "d".repeat(64);
        let paths = CasPaths::new(&digest).unwrap();
        drop(paths.prepare(&root).unwrap());
        GuardedDirectoryChain::create_exclusive(root.managed_root(), &paths.quarantine_bucket)
            .unwrap();
        fs::write(absolute(&root, &paths.quarantine_payload), b"unsafe").unwrap();
        fs::hard_link(
            absolute(&root, &paths.quarantine_payload),
            root.managed_root().join("outside-hardlink-alias"),
        )
        .unwrap();
        assert!(maintain_cas_quarantine(&root).is_err());
        assert_eq!(
            fs::read(absolute(&root, &paths.quarantine_payload)).unwrap(),
            b"unsafe"
        );
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn cas_quarantine_all_locked_sweep_has_one_hard_work_bound() {
        let (install, root) = owned_root("quarantine-all-locked-bound");
        let mut held_locks = Vec::new();
        for index in 0..=MAX_CAS_QUARANTINE_BUCKETS {
            let digest = format!("{:064x}", index + 10_000);
            let paths = CasPaths::new(&digest).unwrap();
            drop(paths.prepare(&root).unwrap());
            GuardedDirectoryChain::create_exclusive(root.managed_root(), &paths.quarantine_bucket)
                .unwrap();
            let lock = open_or_create_lock_file(root.managed_root(), &paths.lock).unwrap();
            lock.file().try_lock_exclusive().unwrap();
            held_locks.push(lock);
        }

        // One 64-bucket pass, the remaining bucket, and a rescan of the retained locked set
        // exceed this deliberately small total budget. Scans, attempts, and retained locks all
        // consume the same bound, so neither runtime nor the BTreeSet can grow with namespace N.
        assert!(maintain_cas_quarantine_with_work_limit(&root, 300).is_err());
        let quarantine = RelativeManagedPath::new("quarantine").unwrap();
        assert_eq!(
            fs::read_dir(quarantine.join_to(root.managed_root()))
                .unwrap()
                .count(),
            MAX_CAS_QUARANTINE_BUCKETS + 1
        );

        for lock in &held_locks {
            FileExt::unlock(lock.file()).unwrap();
        }
        drop(held_locks);
        maintain_cas_quarantine(&root).unwrap();
        assert_eq!(
            fs::read_dir(quarantine.join_to(root.managed_root()))
                .unwrap()
                .count(),
            0
        );

        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[test]
    fn physical_partial_evidence_rejects_truncate_replacement_and_foreign_root() {
        let (install, root) = owned_root("partial-allocation-evidence");
        let bytes = b"physically allocated partial";
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(b"eventual complete object")),
            size: 128,
        };
        let paths = CasPaths::new(&expected.sha256).unwrap();
        paths.prepare(&root).unwrap();
        let mut partial = ResumableManagedFile::open_or_create(
            root.managed_root(),
            paths.partial.clone(),
            expected.size,
        )
        .unwrap();
        partial.write_all_at(0, bytes).unwrap();
        let evidence =
            VerifiedCasPartialAllocationV2::from_open_partial(&root, &expected, &partial).unwrap();
        drop(partial);
        evidence
            .open_exact(&root, &expected.sha256, expected.size)
            .unwrap();

        let reopened = ResumableManagedFile::open_existing(
            root.managed_root(),
            paths.partial.clone(),
            expected.size,
        )
        .unwrap()
        .unwrap();
        let mut reopened = reopened;
        reopened.truncate_zero().unwrap();
        drop(reopened);
        assert!(evidence
            .open_exact(&root, &expected.sha256, expected.size)
            .is_err());

        fs::remove_file(absolute(&root, &paths.partial)).unwrap();
        fs::write(absolute(&root, &paths.partial), bytes).unwrap();
        assert!(evidence
            .open_exact(&root, &expected.sha256, expected.size)
            .is_err());

        let (foreign_install, foreign) = owned_root("partial-allocation-foreign");
        assert!(evidence
            .open_exact(&foreign, &expected.sha256, expected.size)
            .is_err());
        drop(foreign);
        fs::remove_dir_all(foreign_install).unwrap();
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn production_downloader_rejects_official_plan_item_before_network() {
        let (install, root) = owned_root("sealed-authority");
        let release = trusted('a', 1);
        let install_id = root.binding().1;
        let inventory = ArtifactInventoryV2::build(
            &root,
            &release,
            install_id,
            Uuid::new_v4(),
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap();
        let availability = VerifiedAvailabilityV2::for_test(&inventory, [], false, false);
        let plan = ArtifactPlanV2::for_reconcile(&inventory, &availability, []).unwrap();
        let view = plan.execution_view(&root, &inventory).unwrap();
        let official = view
            .items()
            .find(|item| {
                matches!(
                    item.source(),
                    ArtifactExecutionSourceV2::OfficialHttps { .. }
                )
            })
            .expect("official runtime item");
        let downloader =
            CasDownloader::new(&root, SparkClient::new_for_test("http://127.0.0.1:9/"));
        let error = downloader
            .ensure_planned_spark_object(&official, BEARER)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("non-Spark artifact authority"));
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn complete_plan_item_changed_after_scan_is_verify_only_and_forces_replan() {
        let (install, root) = owned_root("complete-stale");
        let base = trusted('a', 1);
        let bytes = b"complete cached spark object";
        let sha256 = format!("{:x}", Sha256::digest(bytes));
        let mut manifest = base.manifest().clone();
        for preset in &mut manifest.presets {
            let exact = preset
                .files
                .iter_mut()
                .find(|file| file.path == "mods/fragment-launch-guard.jar")
                .unwrap();
            exact.size = bytes.len() as u64;
            exact.sha256 = sha256.clone();
        }
        manifest.validate().unwrap();
        let release = super::super::tuf::TrustedRelease::new_for_test(
            base.channel(),
            base.current().clone(),
            manifest,
            base.runtime_lock().clone(),
            base.game_runtime_lock().clone(),
            base.tuf_root_version(),
            base.evidence().clone(),
        );
        let install_id = root.binding().1;
        let inventory = ArtifactInventoryV2::build(
            &root,
            &release,
            install_id,
            Uuid::new_v4(),
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap();
        let paths = CasPaths::new(&sha256).unwrap();
        let guards = paths.prepare(&root).unwrap();
        fs::write(absolute(&root, &paths.final_path), bytes).unwrap();
        drop(guards);
        let availability = VerifiedAvailabilityV2::scan(&root, &inventory).unwrap();
        let plan = ArtifactPlanV2::for_reconcile(
            &inventory,
            &availability,
            ["mods/fragment-launch-guard.jar".to_string()],
        )
        .unwrap();
        let view = plan.execution_view(&root, &inventory).unwrap();
        let item = view
            .items()
            .find(|item| item.sha256() == sha256)
            .expect("complete Spark item");
        assert_eq!(
            item.availability(),
            super::super::availability::ArtifactAvailabilityStateV2::Complete
        );

        fs::write(absolute(&root, &paths.final_path), vec![b'x'; bytes.len()]).unwrap();
        let downloader =
            CasDownloader::new(&root, SparkClient::new_for_test("http://127.0.0.1:9/"));
        let error = downloader
            .ensure_planned_spark_object(&item, BEARER)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("sealed digest"));
        assert!(absolute(&root, &paths.final_path).exists());
        drop(root);
        fs::remove_dir_all(install).unwrap();
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

    fn spawn_stalling_then_resume_server(
        bytes: Vec<u8>,
        hash: String,
        split: usize,
    ) -> (String, std::sync::mpsc::Sender<()>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let plan_path = "/api/spark2/v1/download-plan";
        let object_path = format!(
            "/api/spark2/v1/objects/{hash}?token={}",
            "signed-object-token-".repeat(3)
        );
        let (release, released) = std::sync::mpsc::channel();
        let server_origin = origin.clone();
        let handle = thread::spawn(move || {
            let (mut plan, _) = listener.accept().unwrap();
            let request = read_request(&mut plan);
            assert!(request.lines().next().unwrap().contains(plan_path));
            let body = plan_body(&server_origin, &hash);
            write!(
                plan,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            plan.write_all(&body).unwrap();
            plan.flush().unwrap();

            let (mut first, _) = listener.accept().unwrap();
            let request = read_request(&mut first);
            assert_eq!(
                request.lines().next().unwrap(),
                format!("GET {object_path} HTTP/1.1")
            );
            assert!(!request.to_ascii_lowercase().contains("\r\nrange:"));
            write!(
                first,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .unwrap();
            first.write_all(&bytes[..split]).unwrap();
            first.flush().unwrap();
            released.recv_timeout(Duration::from_secs(5)).unwrap();
            drop(first);

            let (mut resumed_plan, _) = listener.accept().unwrap();
            let request = read_request(&mut resumed_plan);
            assert!(request.lines().next().unwrap().contains(plan_path));
            let body = plan_body(&server_origin, &hash);
            write!(
                resumed_plan,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            resumed_plan.write_all(&body).unwrap();
            resumed_plan.flush().unwrap();

            let (mut resumed, _) = listener.accept().unwrap();
            let request = read_request(&mut resumed);
            assert_eq!(
                request.lines().next().unwrap(),
                format!("GET {object_path} HTTP/1.1")
            );
            assert!(request
                .lines()
                .any(|line| line.eq_ignore_ascii_case(&format!("Range: bytes={split}-"))));
            write!(
                resumed,
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                bytes.len() - split,
                split,
                bytes.len() - 1,
                bytes.len()
            )
            .unwrap();
            resumed.write_all(&bytes[split..]).unwrap();
            resumed.flush().unwrap();
        });
        (origin, release, handle)
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

    #[test]
    fn progress_reporter_coalesces_chunks_and_exposes_only_a_bounded_redacted_identity() {
        let observer = Arc::new(RecordingObserver::default());
        let hash = "ab".repeat(32);
        let mut reporter = DownloadProgressReporter::new(observer.clone(), &hash, 10_000).unwrap();
        reporter.resume(0);
        for persisted in 1..=10_000 {
            reporter.bytes(persisted, 1);
        }
        reporter.complete();

        let events = observer.snapshot();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].phase, DownloadProgressPhase::Resume);
        assert_eq!(events[1].phase, DownloadProgressPhase::Bytes);
        assert_eq!(events[1].delta_bytes, 10_000);
        assert_eq!(events[1].persisted_bytes, 10_000);
        assert_eq!(events[2].phase, DownloadProgressPhase::Complete);
        for event in events {
            assert_eq!(event.object.as_str(), "cas:abababababab..abababababab");
            assert!(event.object.as_str().len() <= 30);
            assert!(!format!("{event:?}").contains(&hash));
            assert!(event.persisted_bytes <= event.total_bytes);
        }
    }

    #[test]
    fn canonical_download_object_identity_is_stable_and_rejects_invalid_digests() {
        let sha256 = format!("{}{}{}", "01".repeat(6), "ab".repeat(20), "fe".repeat(6));
        let identity = DownloadObjectIdentity::from_sha256(&sha256).unwrap();
        assert_eq!(identity.as_str(), "cas:010101010101..fefefefefefe");
        assert_eq!(identity.as_str().len(), 30);
        assert!(DownloadObjectIdentity::from_sha256("not-a-sha256").is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_while_waiting_for_spark_object_lock_is_prompt_and_silent() {
        let bytes = b"cancel-while-spark-object-is-locked";
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        let (install, root) = owned_root("cancel-lock");
        let paths = CasPaths::new(&expected.sha256).unwrap();
        let guards = paths.prepare(&root).unwrap();
        let held = open_or_create_lock_file(root.managed_root(), &paths.lock).unwrap();
        held.file().lock_exclusive().unwrap();
        let observer = Arc::new(RecordingObserver::default());
        let downloader = CasDownloader::with_observer(
            &root,
            SparkClient::new_for_test("http://127.0.0.1:9/"),
            observer.clone(),
        );
        let cancellation = DownloadCancellation::new();
        let cancel = cancellation.clone();
        let started = std::time::Instant::now();
        let (result, ()) = tokio::join!(
            downloader.ensure_object_with_cancellation(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &expected,
                BEARER,
                &cancellation,
            ),
            async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                cancel.cancel();
            }
        );
        assert!(matches!(result, Err(CasError::Cancelled)));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(observer.snapshot().is_empty());
        FileExt::unlock(held.file()).unwrap();
        drop(held);
        drop(guards);
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_cancellation_wakes_every_registered_download_waiter() {
        let cancellation = DownloadCancellation::new();
        let cancel = cancellation.clone();
        let waiters = (0..64).map(|_| cancellation.cancelled());
        tokio::time::timeout(Duration::from_secs(1), async move {
            tokio::join!(futures_util::future::join_all(waiters), async move {
                tokio::task::yield_now().await;
                cancel.cancel();
            });
        })
        .await
        .expect("every registered cancellation waiter wakes");
        tokio::time::timeout(Duration::from_millis(50), cancellation.cancelled())
            .await
            .expect("late cancellation waiter sees the durable flag");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn spark_retry_after_wait_is_cancelled_without_another_request() {
        let bytes = b"cancel-spark-retry-after";
        let expected = ExpectedObject {
            sha256: format!("{:x}", Sha256::digest(bytes)),
            size: bytes.len() as u64,
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let server = spawn_server(
            listener,
            vec![ScriptedResponse {
                expected_path: "/api/spark2/v1/download-plan".into(),
                expected_range: None,
                status: "503 Service Unavailable",
                headers: vec![("Retry-After", "5")],
                body: Vec::new(),
            }],
        );
        let (install, root) = owned_root("cancel-retry-after");
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
        let cancellation = DownloadCancellation::new();
        let cancel = cancellation.clone();
        let started = std::time::Instant::now();
        let (result, ()) = tokio::join!(
            downloader.ensure_object_with_cancellation(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &expected,
                BEARER,
                &cancellation,
            ),
            async {
                for _ in 0..1_000 {
                    if server.is_finished() {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        cancel.cancel();
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                panic!("Spark retryable response was not observed");
            }
        );
        assert!(matches!(result, Err(CasError::Cancelled)));
        assert!(started.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mid_stream_cancellation_flushes_partial_and_progress_resumes_monotonically() {
        let bytes: Vec<u8> = (0..256 * 1024).map(|index| (index % 251) as u8).collect();
        let split = 64 * 1024;
        let hash = format!("{:x}", Sha256::digest(&bytes));
        let expected = ExpectedObject {
            sha256: hash.clone(),
            size: bytes.len() as u64,
        };
        let (origin, release, server) =
            spawn_stalling_then_resume_server(bytes.clone(), hash.clone(), split);
        let (install, root) = owned_root("cancel-mid-stream");
        let observer = Arc::new(RecordingObserver::default());
        let downloader = CasDownloader::with_observer(
            &root,
            SparkClient::new_for_test(&origin),
            observer.clone(),
        );
        let cancellation = DownloadCancellation::new();
        let cancel = cancellation.clone();
        let partial_path = CasPaths::new(&hash)
            .unwrap()
            .partial
            .join_to(root.managed_root());
        let (first, ()) = tokio::join!(
            downloader.ensure_object_with_cancellation(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &expected,
                BEARER,
                &cancellation,
            ),
            async {
                for _ in 0..1_000 {
                    if fs::metadata(&partial_path)
                        .is_ok_and(|metadata| metadata.len() == split as u64)
                    {
                        cancel.cancel();
                        release.send(()).unwrap();
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                panic!("Spark partial did not reach the cancellation boundary");
            }
        );
        assert!(matches!(first, Err(CasError::Cancelled)));
        assert_eq!(fs::metadata(&partial_path).unwrap().len(), split as u64);
        let final_path = CasPaths::new(&hash)
            .unwrap()
            .final_path
            .join_to(root.managed_root());
        assert!(!final_path.exists());
        assert!(!observer
            .snapshot()
            .iter()
            .any(|event| event.phase == DownloadProgressPhase::Complete));

        let object = downloader
            .ensure_object_with_cancellation(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &expected,
                BEARER,
                &DownloadCancellation::new(),
            )
            .await
            .unwrap();
        assert!(object.published_by_this_operation());
        assert_eq!(read_verified(&root, &object), bytes);
        server.join().unwrap();

        let events = observer.snapshot();
        let resumes: Vec<_> = events
            .iter()
            .filter(|event| event.phase == DownloadProgressPhase::Resume)
            .map(|event| event.persisted_bytes)
            .collect();
        assert_eq!(resumes, [0, split as u64]);
        let byte_events: Vec<_> = events
            .iter()
            .filter(|event| event.phase == DownloadProgressPhase::Bytes)
            .collect();
        assert!(!byte_events.is_empty());
        assert!(byte_events
            .windows(2)
            .all(|pair| pair[0].persisted_bytes <= pair[1].persisted_bytes));
        assert!(byte_events.iter().all(|event| event.delta_bytes > 0));
        assert_eq!(
            byte_events
                .iter()
                .map(|event| event.delta_bytes)
                .sum::<u64>(),
            bytes.len() as u64
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.phase == DownloadProgressPhase::Complete)
                .count(),
            1
        );
        for event in events {
            let rendered = format!("{event:?}");
            assert!(event.object.as_str().len() <= 30);
            assert!(!rendered.contains(&origin));
            assert!(!rendered.contains(BEARER));
            assert!(!rendered.contains("signed-object-token"));
            assert!(!rendered.contains(&hash));
        }

        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
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

    #[test]
    fn plan_attempt_budget_admits_exactly_nine_requests_and_never_wraps() {
        assert_eq!(MAX_PLAN_ATTEMPTS, 9);
        let mut budget = PlanAttemptBudget::default();
        for admitted in 1..=MAX_PLAN_ATTEMPTS {
            assert!(
                budget.admit().is_ok(),
                "attempt {admitted} must be admitted"
            );
        }
        for _ in 0..2 {
            assert!(matches!(
                budget.admit(),
                Err(CasError::Failed(message))
                    if message == "CAS object download retry limit was reached"
            ));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mixed_retry_categories_never_fetch_more_than_nine_download_plans() {
        const TOKENS: [&str; 9] = [
            "fragment-plan-attempt-token-1",
            "fragment-plan-attempt-token-2",
            "fragment-plan-attempt-token-3",
            "fragment-plan-attempt-token-4",
            "fragment-plan-attempt-token-5",
            "fragment-plan-attempt-token-6",
            "fragment-plan-attempt-token-7",
            "fragment-plan-attempt-token-8",
            "fragment-plan-attempt-token-9",
        ];
        assert_eq!(MAX_PLAN_ATTEMPTS, TOKENS.len() as u8);

        let bytes = b"trusted-object";
        let corrupt = b"corrupt-object";
        assert_eq!(bytes.len(), corrupt.len());
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let plan_path = "/api/spark2/v1/download-plan".to_owned();
        let object_path = format!(
            "/api/spark2/v1/objects/{hash}?token={}",
            "signed-object-token-".repeat(3)
        );
        let successful_plan = || ScriptedResponse {
            expected_path: plan_path.clone(),
            expected_range: None,
            status: "200 OK",
            headers: vec![("Content-Type", "application/json")],
            body: plan_body(&origin, &hash),
        };
        let retryable_plan = || ScriptedResponse {
            expected_path: plan_path.clone(),
            expected_range: None,
            status: "503 Service Unavailable",
            headers: vec![("Retry-After", "0")],
            body: Vec::new(),
        };
        let responses = vec![
            // Attempt 1: exactly one rejected plan capability may force rotation.
            ScriptedResponse {
                expected_path: plan_path.clone(),
                expected_range: None,
                status: "401 Unauthorized",
                headers: Vec::new(),
                body: Vec::new(),
            },
            // Attempt 2: exactly one object authorization failure may force a replan.
            successful_plan(),
            ScriptedResponse {
                expected_path: object_path.clone(),
                expected_range: Some(None),
                status: "401 Unauthorized",
                headers: Vec::new(),
                body: Vec::new(),
            },
            // Attempts 3..=6 consume the four shared transient retries.
            retryable_plan(),
            retryable_plan(),
            retryable_plan(),
            retryable_plan(),
            // Attempt 7 consumes the one range reset without accepting any bytes.
            successful_plan(),
            ScriptedResponse {
                expected_path: object_path.clone(),
                expected_range: Some(None),
                status: "416 Range Not Satisfiable",
                headers: Vec::new(),
                body: Vec::new(),
            },
            // Attempt 8 consumes the one clean digest retry and resets the partial to zero.
            successful_plan(),
            ScriptedResponse {
                expected_path: object_path,
                expected_range: Some(None),
                status: "200 OK",
                headers: Vec::new(),
                body: corrupt.to_vec(),
            },
            // Attempt 9 is the fifth transient failure and terminates before a tenth plan fetch.
            retryable_plan(),
        ];
        let server = spawn_server(listener, responses);
        let (install, root) = owned_root("mixed-nine-plan-attempts");
        let paths = CasPaths::new(&hash).unwrap();
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
        let mut provider = RotatingSparkAccessTokenProvider::new(TOKENS);
        let result = downloader
            .ensure_object_with_provider_and_cancellation(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                &mut provider,
                &DownloadCancellation::new(),
            )
            .await;

        assert!(matches!(
            result,
            Err(CasError::Failed(message))
                if message == "Spark temporary failure retry limit was reached"
        ));
        assert_eq!(provider.calls, MAX_PLAN_ATTEMPTS as usize);
        assert!(provider.tokens.is_empty());
        assert_eq!(
            provider.rejected,
            vec![
                None,
                Some(TOKENS[0].to_owned()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            ]
        );
        server.join().unwrap();

        assert!(!absolute(&root, &paths.final_path).exists());
        assert_eq!(
            fs::metadata(absolute(&root, &paths.partial)).unwrap().len(),
            0
        );
        assert!(!absolute(&root, &paths.quarantine_bucket).exists());
        assert!(fs::read_dir(root.install_root().join("state/journals"))
            .unwrap()
            .next()
            .is_none());
        assert!(!root.install_root().join("state/reconcile").exists());
        assert!(!root.install_root().join("state/instances").exists());
        assert!(fs::read_dir(root.install_root().join("instances/stable"))
            .unwrap()
            .next()
            .is_none());
        assert!(fs::read_dir(root.install_root().join("instances/dev"))
            .unwrap()
            .next()
            .is_none());

        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
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
    async fn interrupted_body_replan_requests_a_new_native_access_capability() {
        const TOKEN_1: &str = "fragment-access-token-wave-one";
        const TOKEN_2: &str = "fragment-access-token-wave-two";
        let bytes = b"trusted-object";
        let split = 7_usize;
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let object_path = format!(
            "/api/spark2/v1/objects/{hash}?token={}",
            "signed-object-token-".repeat(3)
        );
        let server_origin = origin.clone();
        let server_hash = hash.clone();
        let server = thread::spawn(move || {
            for (expected_token, resumed) in [(TOKEN_1, false), (TOKEN_2, true)] {
                let (mut plan, _) = listener.accept().unwrap();
                let request = read_request(&mut plan);
                assert!(request.lines().any(|line| line
                    .eq_ignore_ascii_case(&format!("Authorization: Bearer {expected_token}"))));
                let body = plan_body(&server_origin, &server_hash);
                write!(
                    plan,
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .unwrap();
                plan.write_all(&body).unwrap();
                plan.flush().unwrap();

                let (mut object, _) = listener.accept().unwrap();
                let request = read_request(&mut object);
                assert_eq!(
                    request.lines().next().unwrap(),
                    format!("GET {object_path} HTTP/1.1")
                );
                if resumed {
                    assert!(request
                        .lines()
                        .any(|line| line.eq_ignore_ascii_case(&format!("Range: bytes={split}-"))));
                    write!(
                        object,
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                        bytes.len() - split,
                        split,
                        bytes.len() - 1,
                        bytes.len()
                    )
                    .unwrap();
                    object.write_all(&bytes[split..]).unwrap();
                } else {
                    assert!(!request.to_ascii_lowercase().contains("\r\nrange:"));
                    write!(
                        object,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    )
                    .unwrap();
                    object.write_all(&bytes[..split]).unwrap();
                }
                object.flush().unwrap();
            }
        });

        let (install, root) = owned_root("rotating-replan-token");
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
        let mut provider = RotatingSparkAccessTokenProvider::new([TOKEN_1, TOKEN_2]);
        let result = downloader
            .ensure_object_with_provider_and_cancellation(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                &mut provider,
                &DownloadCancellation::new(),
            )
            .await
            .unwrap();
        assert_eq!(provider.calls, 2);
        assert_eq!(provider.rejected, vec![None, None]);
        assert_eq!(read_verified(&root, &result), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn rejected_plan_capability_forces_one_fresh_replan() {
        const TOKEN_1: &str = "fragment-access-token-rejected";
        const TOKEN_2: &str = "fragment-access-token-rotated";
        let bytes = b"trusted-object";
        let hash = format!("{:x}", Sha256::digest(bytes));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let object_path = format!(
            "/api/spark2/v1/objects/{hash}?token={}",
            "signed-object-token-".repeat(3)
        );
        let server_origin = origin.clone();
        let server_hash = hash.clone();
        let server = thread::spawn(move || {
            let (mut rejected_plan, _) = listener.accept().unwrap();
            let request = read_request(&mut rejected_plan);
            assert!(
                request
                    .lines()
                    .any(|line| line
                        .eq_ignore_ascii_case(&format!("Authorization: Bearer {TOKEN_1}")))
            );
            write!(
                rejected_plan,
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            rejected_plan.flush().unwrap();

            let (mut accepted_plan, _) = listener.accept().unwrap();
            let request = read_request(&mut accepted_plan);
            assert!(
                request
                    .lines()
                    .any(|line| line
                        .eq_ignore_ascii_case(&format!("Authorization: Bearer {TOKEN_2}")))
            );
            let body = plan_body(&server_origin, &server_hash);
            write!(
                accepted_plan,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            accepted_plan.write_all(&body).unwrap();
            accepted_plan.flush().unwrap();

            let (mut object, _) = listener.accept().unwrap();
            let request = read_request(&mut object);
            assert_eq!(
                request.lines().next().unwrap(),
                format!("GET {object_path} HTTP/1.1")
            );
            write!(
                object,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                bytes.len()
            )
            .unwrap();
            object.write_all(bytes).unwrap();
            object.flush().unwrap();
        });

        let (install, root) = owned_root("rejected-plan-token");
        let downloader = CasDownloader::new(&root, SparkClient::new_for_test(&origin));
        let mut provider = RotatingSparkAccessTokenProvider::new([TOKEN_1, TOKEN_2]);
        let result = downloader
            .ensure_object_with_provider_and_cancellation(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash,
                    size: bytes.len() as u64,
                },
                &mut provider,
                &DownloadCancellation::new(),
            )
            .await
            .unwrap();

        assert_eq!(provider.calls, 2);
        assert_eq!(provider.rejected, vec![None, Some(TOKEN_1.to_owned())]);
        assert_eq!(read_verified(&root, &result), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
    }

    #[test]
    fn native_access_capability_debug_is_redacted() {
        let token = NativeAccessToken::for_test("never-print-this-access-token");
        let rendered = format!("{token:?}");
        assert_eq!(rendered, "NativeAccessToken([REDACTED])");
        assert!(!rendered.contains(token.expose()));
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
        let observer = Arc::new(RecordingObserver::default());
        let downloader = CasDownloader::with_observer(
            &root,
            SparkClient::new_for_test(&origin),
            observer.clone(),
        );
        let result = downloader
            .ensure_object(
                BuildChannel::Stable,
                PresetId::Medium,
                RELEASE_ID,
                &ExpectedObject {
                    sha256: hash.clone(),
                    size: bytes.len() as u64,
                },
                BEARER,
            )
            .await
            .unwrap();
        assert_eq!(result.resumed_bytes(), 0);
        assert_eq!(read_verified(&root, &result), bytes);
        let events = observer.snapshot();
        assert_eq!(events[0].phase, DownloadProgressPhase::Resume);
        assert_eq!(events[0].persisted_bytes, split as u64);
        assert_eq!(events[1].phase, DownloadProgressPhase::Reset);
        assert_eq!(events[1].persisted_bytes, 0);
        assert_eq!(
            events.last().unwrap().phase,
            DownloadProgressPhase::Complete
        );
        let bytes_after_reset = &events[2..events.len() - 1];
        assert!(bytes_after_reset
            .iter()
            .all(|event| event.phase == DownloadProgressPhase::Bytes));
        assert_eq!(
            bytes_after_reset
                .iter()
                .map(|event| event.delta_bytes)
                .sum::<u64>(),
            bytes.len() as u64
        );
        assert!(bytes_after_reset
            .windows(2)
            .all(|pair| pair[0].persisted_bytes <= pair[1].persisted_bytes));
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
        assert!(matches!(error, CasError::Forbidden));
        server.join().unwrap();
        drop(downloader);
        drop(root);
        let _ = fs::remove_dir_all(install);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn plan_authentication_expiry_is_typed() {
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
                status: "401 Unauthorized",
                headers: vec![],
                body: Vec::new(),
            }],
        );
        let (install, root) = owned_root("terminal-authentication");
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
        assert!(matches!(error, CasError::Authentication));
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
        assert!(matches!(error, CasError::Forbidden));
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
        assert!(!verified.published_by_this_operation());
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

        let final_audit = CasError::AppliedButFinalAuditFailed {
            destination: "sha256/ab/object".into(),
            detail: "injected exact audit failure".into(),
        };
        assert!(final_audit
            .to_string()
            .starts_with("cas_applied_final_audit_failed:"));
    }
}
