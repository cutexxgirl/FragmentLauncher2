#[cfg(test)]
use super::cas::{DownloadProgressEvent, DownloadProgressPhase};
use super::{
    artifact_plan::{ArtifactExecutionSourceV2, PlannedArtifactExecutionV2},
    availability::ArtifactAvailabilityStateV2,
    cas::{
        acquire_object_lock, activate_partial_if, audit_existing_official_final,
        cleanup_active_cas_quarantine, discard_stale_partial, managed_error,
        quarantine_corrupt_cas_object, reclaim_cas_quarantine_bucket_locked, ActiveCasQuarantine,
        CasError, CasPaths, DownloadCancellation, DownloadObserver, DownloadProgressReporter,
        ExistingFinal, ExpectedObject, NoopDownloadObserver, VerifiedCasObject,
        VerifiedCasPartialAllocationV2,
    },
    contracts::{
        official_game_host_is_allowed, validate_official_game_source, OFFICIAL_GAME_HOSTS,
    },
    managed_fs::{ManagedLockFile, ResumableManagedFile},
    spark_client::{is_retryable_status, retry_after},
    storage::OwnedCasRoot,
};
use fs2::FileExt;
use futures_util::StreamExt;
use reqwest::{
    dns::{Addrs, Name, Resolve, Resolving},
    header::{self, HeaderMap},
    redirect::Policy,
    tls::Version,
    Client, Response, StatusCode,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::Instant,
};
use url::Url;

const MAX_TRANSIENT_RETRIES: u8 = 4;
const MAX_RANGE_RESETS: u8 = 1;
const MAX_CLEAN_RETRIES: u8 = 1;
const GLOBAL_REQUEST_LIMIT: usize = 8;
const PER_ORIGIN_REQUEST_LIMIT: usize = 4;
const MAX_OPERATION_RETRIES: u32 = 128;
const MAX_CONSECUTIVE_TRANSIENT_FAILURES: u32 = 16;
const BASE_RETRY_DELAY: Duration = Duration::from_millis(125);
const MIN_ATTEMPT_TIME: Duration = Duration::from_secs(120);
const MAX_ATTEMPT_TIME: Duration = Duration::from_secs(30 * 60);
const MIN_TRANSFER_RATE_BYTES_PER_SECOND: u64 = 64 * 1024;

pub(super) type OfficialDownloadCancellation = DownloadCancellation;

#[derive(Debug, Error)]
pub(super) enum OfficialCasError {
    #[error("Official artifact download was cancelled")]
    Cancelled,
    #[error("Official artifact plan is invalid: {0}")]
    InvalidPlan(String),
    #[error("Official artifact response is invalid: {0}")]
    InvalidResponse(&'static str),
    #[error("Official artifact returned HTTP {0}")]
    Http(StatusCode),
    #[error("Official artifact transport failed")]
    Transport,
    #[error("Official artifact temporary failure retry limit was reached")]
    RetryExhausted,
    #[error("Official artifact operation retry circuit is open")]
    RetryCircuitOpen,
    #[error("Official artifact failed its signed size or digest checks")]
    Integrity,
    #[error(transparent)]
    Cas(CasError),
}

impl From<CasError> for OfficialCasError {
    fn from(error: CasError) -> Self {
        match error {
            CasError::Cancelled => Self::Cancelled,
            other => Self::Cas(other),
        }
    }
}

type OfficialResult<T> = Result<T, OfficialCasError>;

struct LockedOfficialCas<'a> {
    paths: &'a CasPaths,
    object_lock: &'a ManagedLockFile,
}

/// Official Mojang/NeoForge transport. Production construction fixes the WebPKI TLS client,
/// pinned DNS policy and concurrency ceilings. Its only production download entry point accepts
/// a non-constructible item yielded by the exact sealed ArtifactPlanV2 execution view.
pub(super) struct OfficialCasDownloader<'root> {
    cache_root: &'root OwnedCasRoot,
    transport: OfficialHttpTransport,
    gates: RequestGates,
    retry_governor: OperationRetryGovernor,
    observer: Arc<dyn DownloadObserver>,
}

impl fmt::Debug for OfficialCasDownloader<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OfficialCasDownloader")
            .finish_non_exhaustive()
    }
}

impl<'root> OfficialCasDownloader<'root> {
    pub(super) fn new(cache_root: &'root OwnedCasRoot) -> Result<Self, String> {
        Self::with_observer(cache_root, Arc::new(NoopDownloadObserver))
    }

    pub(super) fn with_observer(
        cache_root: &'root OwnedCasRoot,
        observer: Arc<dyn DownloadObserver>,
    ) -> Result<Self, String> {
        cache_root.revalidate()?;
        Ok(Self {
            cache_root,
            transport: OfficialHttpTransport::production()?,
            gates: RequestGates::new(),
            retry_governor: OperationRetryGovernor::new(),
            observer,
        })
    }

    #[cfg(test)]
    fn new_for_test(cache_root: &'root OwnedCasRoot, origin: &str) -> Self {
        Self {
            cache_root,
            transport: OfficialHttpTransport::for_test(origin),
            gates: RequestGates::new(),
            retry_governor: OperationRetryGovernor::new(),
            observer: Arc::new(NoopDownloadObserver),
        }
    }

    #[cfg(test)]
    fn new_for_test_with_observer(
        cache_root: &'root OwnedCasRoot,
        origin: &str,
        observer: Arc<dyn DownloadObserver>,
    ) -> Self {
        Self {
            cache_root,
            transport: OfficialHttpTransport::for_test(origin),
            gates: RequestGates::new(),
            retry_governor: OperationRetryGovernor::new(),
            observer,
        }
    }

    pub(super) async fn ensure_planned_official_object(
        &self,
        planned: &PlannedArtifactExecutionV2<'_>,
        cancellation: &OfficialDownloadCancellation,
    ) -> OfficialResult<VerifiedCasObject> {
        cancellation.check()?;
        planned
            .validate_root(self.cache_root)
            .map_err(OfficialCasError::InvalidPlan)?;
        let ArtifactExecutionSourceV2::OfficialHttps { url, sha1 } = planned.source() else {
            return Err(OfficialCasError::InvalidPlan(
                "official downloader rejected a non-official authority".into(),
            ));
        };
        let source = validate_official_game_source(url, sha1).map_err(|_| {
            OfficialCasError::InvalidPlan("official source binding is invalid".into())
        })?;
        let expected = OfficialExpectation {
            source,
            sha1: sha1.to_owned(),
            object: ExpectedObject {
                sha256: planned.sha256().to_owned(),
                size: planned.size(),
            },
            availability: planned.availability(),
        };
        if planned.availability() == ArtifactAvailabilityStateV2::Complete {
            let mut reporter = DownloadProgressReporter::new(
                self.observer.clone(),
                planned.sha256(),
                planned.size(),
            )
            .map_err(OfficialCasError::InvalidPlan)?;
            let object = verify_complete_official(
                self.cache_root,
                &expected,
                planned.resume_from(),
                cancellation,
            )?;
            reporter.complete();
            return Ok(object);
        }
        self.ensure_expected_with_allocation(
            &expected,
            planned.resume_from(),
            planned.partial_allocation(),
            cancellation,
        )
        .await
    }

    async fn ensure_expected(
        &self,
        expected: &OfficialExpectation,
        planned_resume_from: u64,
        cancellation: &OfficialDownloadCancellation,
    ) -> OfficialResult<VerifiedCasObject> {
        self.ensure_expected_with_allocation(expected, planned_resume_from, None, cancellation)
            .await
    }

    async fn ensure_expected_with_allocation(
        &self,
        expected: &OfficialExpectation,
        planned_resume_from: u64,
        credited_partial: Option<&VerifiedCasPartialAllocationV2>,
        cancellation: &OfficialDownloadCancellation,
    ) -> OfficialResult<VerifiedCasObject> {
        cancellation.check()?;
        let mut reporter = DownloadProgressReporter::new(
            self.observer.clone(),
            &expected.object.sha256,
            expected.object.size,
        )
        .map_err(OfficialCasError::InvalidPlan)?;
        self.retry_governor.ensure_open()?;
        self.cache_root.revalidate().map_err(CasError::Failed)?;
        validate_official_game_source(expected.source.as_str(), &expected.sha1).map_err(|_| {
            OfficialCasError::InvalidPlan("official source binding is invalid".into())
        })?;
        let paths = CasPaths::new(&expected.object.sha256)
            .map_err(|_| OfficialCasError::InvalidPlan("official SHA-256 is invalid".into()))?;
        let guards = paths.prepare(self.cache_root)?;
        let lock = cancellable(
            cancellation,
            acquire_object_lock(self.cache_root, &paths.lock),
        )
        .await??;
        cancellation.check()?;
        guards.revalidate()?;
        let result = self
            .ensure_expected_locked(
                expected,
                planned_resume_from,
                credited_partial,
                LockedOfficialCas {
                    paths: &paths,
                    object_lock: &lock,
                },
                cancellation,
                &mut reporter,
            )
            .await;
        let unlock = FileExt::unlock(lock.file()).map_err(|error| {
            CasError::Failed(format!("Cannot unlock official CAS object: {error}"))
        });
        drop(guards);
        match result {
            Err(error) => Err(error),
            Ok(value) => {
                // Drop still releases the lease. Never reinterpret an exact applied CAS result
                // as a generic failure because an explicit unlock call failed.
                let _ = unlock;
                Ok(value)
            }
        }
    }

    async fn ensure_expected_locked(
        &self,
        expected: &OfficialExpectation,
        planned_resume_from: u64,
        credited_partial: Option<&VerifiedCasPartialAllocationV2>,
        locked: LockedOfficialCas<'_>,
        cancellation: &OfficialDownloadCancellation,
        reporter: &mut DownloadProgressReporter,
    ) -> OfficialResult<VerifiedCasObject> {
        let LockedOfficialCas { paths, object_lock } = locked;
        cancellation.check()?;
        reclaim_cas_quarantine_bucket_locked(self.cache_root, paths, object_lock, None)?;
        let existing = audit_existing_official_final(
            self.cache_root,
            &expected.object,
            &expected.sha1,
            expected.object.size,
        )?;
        cancellation.check()?;
        let mut active_quarantine = None;
        match existing {
            ExistingFinal::Missing => {}
            ExistingFinal::Verified(_) => {
                cancellation.check()?;
                discard_stale_partial(self.cache_root, paths, expected.object.size)?;
                cancellation.check()?;
                let object = verify_complete_official(
                    self.cache_root,
                    expected,
                    expected.object.size,
                    cancellation,
                )?;
                reporter.complete();
                return Ok(object);
            }
            ExistingFinal::Corrupt(evidence) => {
                if expected.availability != ArtifactAvailabilityStateV2::Corrupt {
                    return Err(OfficialCasError::InvalidPlan(
                        "canonical CAS state changed after availability planning".into(),
                    ));
                }
                cancellation.check()?;
                active_quarantine = Some(quarantine_corrupt_cas_object(
                    self.cache_root,
                    paths,
                    object_lock,
                    &evidence,
                )?);
                self.cache_root.revalidate().map_err(CasError::Failed)?;
            }
        }

        cancellation.check()?;
        let mut partial = match credited_partial {
            Some(evidence) => match evidence.open_exact(
                self.cache_root,
                &expected.object.sha256,
                expected.object.size,
            ) {
                Ok(partial) => partial,
                Err(evidence_error) => match audit_existing_official_final(
                    self.cache_root,
                    &expected.object,
                    &expected.sha1,
                    expected.object.size,
                )? {
                    ExistingFinal::Verified(object) => {
                        reporter.complete();
                        return finish_official_replacement(
                            self.cache_root,
                            paths,
                            object_lock,
                            &mut active_quarantine,
                            object,
                        );
                    }
                    ExistingFinal::Missing | ExistingFinal::Corrupt(_) => {
                        return Err(evidence_error.into())
                    }
                },
            },
            None => ResumableManagedFile::open_or_create(
                self.cache_root.managed_root(),
                paths.partial.clone(),
                expected.object.size,
            )
            .map_err(|error| managed_error("Cannot open official CAS partial", error))?,
        };
        let mut original_partial = partial
            .len()
            .map_err(|error| managed_error("Cannot inspect official CAS partial", error))?;
        reporter.resume(original_partial.min(expected.object.size));
        if original_partial > expected.object.size {
            cancellation.check()?;
            let discarded = original_partial;
            partial.truncate_zero().map_err(|error| {
                managed_error("Cannot reset oversized official CAS partial", error)
            })?;
            original_partial = 0;
            reporter.reset(discarded.min(expected.object.size));
        }
        // Uncredited plans reserve the full signed allocation and may adapt to current partial
        // state. A credited plan reached this point only after reopening the exact physical
        // allocation witness above. In either case the retained handle drives Range from here.
        let _ = planned_resume_from;

        let mut retry_budget = OfficialRetryBudget::default();
        let mut range_resets = 0_u8;
        let mut clean_retries = 0_u8;
        let mut attempted = false;
        loop {
            cancellation.check()?;
            self.cache_root.revalidate().map_err(CasError::Failed)?;
            validate_official_game_source(expected.source.as_str(), &expected.sha1).map_err(
                |_| OfficialCasError::InvalidPlan("official source binding is invalid".into()),
            )?;
            let offset = partial
                .len()
                .map_err(|error| managed_error("Cannot inspect official CAS partial", error))?;
            let host = expected
                .source
                .host_str()
                .ok_or(OfficialCasError::InvalidPlan(
                    "official source has no host".into(),
                ))?;
            self.retry_governor.prepare_attempt(attempted)?;
            attempted = true;
            let permits = self.gates.acquire(host, cancellation).await?;
            self.retry_governor.ensure_open()?;
            let attempt_deadline = Instant::now() + attempt_timeout(expected.object.size);
            let response = match self
                .transport
                .get(&expected.source, offset, attempt_deadline, cancellation)
                .await
            {
                Ok(response) => response,
                Err(TransportError::Cancelled) => return Err(OfficialCasError::Cancelled),
                Err(TransportError::Retryable) => {
                    drop(permits);
                    self.wait_after_transient(&mut retry_budget, None, cancellation)
                        .await?;
                    continue;
                }
                Err(TransportError::Fatal) => return Err(OfficialCasError::Transport),
            };
            let status = response.status();
            if is_retryable_status(status) {
                let delay = retry_after(response.headers());
                drop(response);
                drop(permits);
                self.wait_after_transient(&mut retry_budget, delay, cancellation)
                    .await?;
                continue;
            }
            validate_identity_encoding(response.headers())?;
            if status == StatusCode::RANGE_NOT_SATISFIABLE {
                validate_range_not_satisfiable(&response, expected.object.size)?;
                drop(response);
                drop(permits);
                if offset == expected.object.size
                    && official_partial_matches_cancellable(&mut partial, expected, cancellation)?
                {
                    let object = activate_official(
                        self.cache_root,
                        paths,
                        expected,
                        partial,
                        original_partial,
                        cancellation,
                    )?;
                    let object = finish_official_replacement(
                        self.cache_root,
                        paths,
                        object_lock,
                        &mut active_quarantine,
                        object,
                    )?;
                    reporter.complete();
                    self.retry_governor.verified_success();
                    return Ok(object);
                }
                cancellation.check()?;
                let discarded = offset;
                partial.truncate_zero().map_err(|error| {
                    managed_error("Cannot reset rejected official CAS partial", error)
                })?;
                original_partial = 0;
                reporter.reset(discarded);
                range_resets = range_resets.saturating_add(1);
                if range_resets > MAX_RANGE_RESETS {
                    return Err(OfficialCasError::InvalidResponse(
                        "range was rejected repeatedly",
                    ));
                }
                continue;
            }
            if !status.is_success() {
                return Err(OfficialCasError::Http(status));
            }

            let write_offset = validate_download_response(&response, offset, expected.object.size)?;
            if write_offset == 0 && offset > 0 {
                // The origin ignored Range. Reset the already-open identity-stable handle; never
                // close and reopen the path between deciding to restart and writing byte zero.
                cancellation.check()?;
                let discarded = offset;
                partial
                    .truncate_zero()
                    .map_err(|error| managed_error("Cannot restart official CAS partial", error))?;
                original_partial = 0;
                reporter.reset(discarded);
            }
            match stream_response(
                response,
                &mut partial,
                write_offset,
                expected.object.size,
                attempt_deadline,
                cancellation,
                reporter,
            )
            .await
            {
                Ok(()) => {}
                Err(StreamError::Cancelled) => return Err(OfficialCasError::Cancelled),
                Err(StreamError::Retryable) => {
                    drop(permits);
                    self.wait_after_transient(&mut retry_budget, None, cancellation)
                        .await?;
                    continue;
                }
                Err(StreamError::Fatal(error)) => return Err(error),
            }
            drop(permits);
            cancellation.check()?;
            let length = partial.len().map_err(|error| {
                managed_error("Cannot inspect downloaded official CAS partial", error)
            })?;
            if length < expected.object.size {
                self.wait_after_transient(&mut retry_budget, None, cancellation)
                    .await?;
                continue;
            }
            if length > expected.object.size {
                return Err(OfficialCasError::InvalidResponse(
                    "body exceeded the signed size",
                ));
            }
            match official_partial_matches_cancellable(&mut partial, expected, cancellation) {
                Ok(true) => {
                    let object = activate_official(
                        self.cache_root,
                        paths,
                        expected,
                        partial,
                        original_partial,
                        cancellation,
                    )?;
                    let object = finish_official_replacement(
                        self.cache_root,
                        paths,
                        object_lock,
                        &mut active_quarantine,
                        object,
                    )?;
                    reporter.complete();
                    self.retry_governor.verified_success();
                    return Ok(object);
                }
                Ok(false) if clean_retries < MAX_CLEAN_RETRIES => {
                    cancellation.check()?;
                    let discarded = length;
                    partial.truncate_zero().map_err(|error| {
                        managed_error("Cannot reset corrupt official CAS partial", error)
                    })?;
                    original_partial = 0;
                    reporter.reset(discarded);
                    clean_retries += 1;
                }
                Ok(false) => {
                    cancellation.check()?;
                    let discarded = length;
                    partial.discard().map_err(|error| {
                        managed_error("Cannot discard corrupt official CAS partial", error)
                    })?;
                    reporter.reset(discarded);
                    return Err(OfficialCasError::Integrity);
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn wait_after_transient(
        &self,
        retry_budget: &mut OfficialRetryBudget,
        retry_after: Option<Duration>,
        cancellation: &OfficialDownloadCancellation,
    ) -> OfficialResult<()> {
        cancellation.check()?;
        self.retry_governor.transient_failure()?;
        retry_budget.wait(retry_after, cancellation).await
    }
}

struct OfficialExpectation {
    source: Url,
    sha1: String,
    object: ExpectedObject,
    availability: ArtifactAvailabilityStateV2,
}

fn verify_complete_official(
    root: &OwnedCasRoot,
    expected: &OfficialExpectation,
    resumed_bytes: u64,
    cancellation: &OfficialDownloadCancellation,
) -> OfficialResult<VerifiedCasObject> {
    cancellation.check()?;
    let existing =
        audit_existing_official_final(root, &expected.object, &expected.sha1, resumed_bytes)?;
    cancellation.check()?;
    match existing {
        ExistingFinal::Verified(object) => Ok(object),
        ExistingFinal::Missing => Err(OfficialCasError::InvalidPlan(
            "Complete official CAS object is missing; rescan required".into(),
        )),
        ExistingFinal::Corrupt(_) => Err(OfficialCasError::InvalidPlan(
            "Complete official CAS object changed; rescan required".into(),
        )),
    }
}

fn official_partial_matches(
    partial: &mut ResumableManagedFile,
    expected: &OfficialExpectation,
) -> OfficialResult<bool> {
    let digests = partial
        .sha1_sha256(expected.object.size)
        .map_err(|error| managed_error("Cannot hash official CAS partial", error))?;
    Ok(digests.size == expected.object.size
        && digests.sha1 == expected.sha1
        && digests.sha256 == expected.object.sha256)
}

fn official_partial_matches_cancellable(
    partial: &mut ResumableManagedFile,
    expected: &OfficialExpectation,
    cancellation: &OfficialDownloadCancellation,
) -> OfficialResult<bool> {
    cancellation.check()?;
    let matches = official_partial_matches(partial, expected)?;
    cancellation.check()?;
    Ok(matches)
}

fn finish_official_replacement(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    object_lock: &ManagedLockFile,
    active: &mut Option<ActiveCasQuarantine>,
    object: VerifiedCasObject,
) -> OfficialResult<VerifiedCasObject> {
    if let Some(active) = active.take() {
        cleanup_active_cas_quarantine(root, paths, object_lock, active).map_err(|error| {
            CasError::AppliedButFinalAuditFailed {
                destination: paths.final_path.as_str().to_owned(),
                detail: format!(
                    "verified official CAS replacement quarantine cleanup failed: {error}"
                ),
            }
        })?;
    }
    Ok(object)
}

fn activate_official(
    root: &OwnedCasRoot,
    paths: &CasPaths,
    expected: &OfficialExpectation,
    partial: ResumableManagedFile,
    resumed_bytes: u64,
    cancellation: &OfficialDownloadCancellation,
) -> OfficialResult<VerifiedCasObject> {
    // The dual digest is checked through the same handle immediately before the shared durable
    // CAS transaction performs its no-replace handle rename.
    let mut partial = partial;
    if !official_partial_matches_cancellable(&mut partial, expected, cancellation)? {
        return Err(OfficialCasError::Integrity);
    }
    cancellation.check()?;
    let Some(object) = activate_partial_if(
        root,
        paths,
        &expected.object,
        partial,
        resumed_bytes,
        || !cancellation.is_cancelled(),
    )?
    else {
        return Err(OfficialCasError::Cancelled);
    };
    // The no-replace rename attempt is the commit point. From here cancellation cannot replace
    // the applied/durability outcome; finish the exact final audit and report that truth.
    let final_audit =
        audit_existing_official_final(root, &expected.object, &expected.sha1, resumed_bytes);
    match final_audit {
        Ok(ExistingFinal::Verified(_)) => Ok(object),
        Ok(ExistingFinal::Missing | ExistingFinal::Corrupt(_))
            if object.published_by_this_operation() =>
        {
            Err(CasError::AppliedButFinalAuditFailed {
                destination: paths.final_path.as_str().to_owned(),
                detail: "published official CAS object failed its final dual-digest audit".into(),
            }
            .into())
        }
        Err(error) if object.published_by_this_operation() => {
            Err(CasError::AppliedButFinalAuditFailed {
                destination: paths.final_path.as_str().to_owned(),
                detail: format!("published official CAS final audit failed: {error}"),
            }
            .into())
        }
        Ok(ExistingFinal::Missing | ExistingFinal::Corrupt(_)) => Err(OfficialCasError::Integrity),
        Err(error) => Err(error.into()),
    }
}

#[derive(Default)]
struct OfficialRetryBudget {
    used: u8,
}

impl OfficialRetryBudget {
    async fn wait(
        &mut self,
        retry_after: Option<Duration>,
        cancellation: &OfficialDownloadCancellation,
    ) -> OfficialResult<()> {
        cancellation.check()?;
        if self.used >= MAX_TRANSIENT_RETRIES {
            return Err(OfficialCasError::RetryExhausted);
        }
        let multiplier = 1_u32 << self.used;
        self.used += 1;
        let backoff = BASE_RETRY_DELAY.saturating_mul(multiplier);
        let jitter_window_ms = backoff.as_millis().max(1) as u64;
        let jitter_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| u64::from(value.subsec_nanos()) % (jitter_window_ms + 1))
            .unwrap_or(0);
        let delay = std::cmp::max(
            // Full jitter prevents many objects released by one outage from synchronizing their
            // next attempt. Retry-After remains an authoritative bounded lower limit.
            Duration::from_millis(jitter_ms),
            retry_after.unwrap_or_default(),
        );
        cancellable(cancellation, tokio::time::sleep(delay)).await?;
        Ok(())
    }
}

struct OperationRetryGovernor {
    state: Mutex<OperationRetryState>,
}

#[derive(Default)]
struct OperationRetryState {
    retries_reserved: u32,
    consecutive_transient_failures: u32,
    open: bool,
}

impl OperationRetryGovernor {
    fn new() -> Self {
        Self {
            state: Mutex::new(OperationRetryState::default()),
        }
    }

    /// Reserves every network attempt after an object's first one, including transport/status
    /// retries, a range reset and a clean integrity retry. One outage therefore cannot multiply
    /// independently across all 4,006 official objects.
    fn prepare_attempt(&self, is_retry: bool) -> OfficialResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OfficialCasError::RetryCircuitOpen)?;
        if state.open {
            return Err(OfficialCasError::RetryCircuitOpen);
        }
        if is_retry {
            if state.retries_reserved >= MAX_OPERATION_RETRIES {
                state.open = true;
                return Err(OfficialCasError::RetryCircuitOpen);
            }
            state.retries_reserved += 1;
        }
        Ok(())
    }

    /// Rechecks after a possibly queued semaphore acquisition so work already waiting when the
    /// circuit opened cannot issue another request.
    fn ensure_open(&self) -> OfficialResult<()> {
        let state = self
            .state
            .lock()
            .map_err(|_| OfficialCasError::RetryCircuitOpen)?;
        if state.open {
            Err(OfficialCasError::RetryCircuitOpen)
        } else {
            Ok(())
        }
    }

    fn transient_failure(&self) -> OfficialResult<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OfficialCasError::RetryCircuitOpen)?;
        if state.open {
            return Err(OfficialCasError::RetryCircuitOpen);
        }
        state.consecutive_transient_failures =
            state.consecutive_transient_failures.saturating_add(1);
        if state.consecutive_transient_failures >= MAX_CONSECUTIVE_TRANSIENT_FAILURES {
            state.open = true;
            return Err(OfficialCasError::RetryCircuitOpen);
        }
        Ok(())
    }

    /// A verified committed object proves the operation is making progress. Never reopen a
    /// terminal circuit; after commit, mutex poisoning is also converted to a terminal circuit
    /// without replacing the already-applied success outcome.
    fn verified_success(&self) {
        match self.state.lock() {
            Ok(mut state) if !state.open => state.consecutive_transient_failures = 0,
            Ok(_) => {}
            Err(poisoned) => poisoned.into_inner().open = true,
        }
    }
}

struct RequestGates {
    global: Arc<Semaphore>,
    per_origin: BTreeMap<&'static str, Arc<Semaphore>>,
}

impl RequestGates {
    fn new() -> Self {
        Self {
            global: Arc::new(Semaphore::new(GLOBAL_REQUEST_LIMIT)),
            per_origin: OFFICIAL_GAME_HOSTS
                .into_iter()
                .map(|host| (host, Arc::new(Semaphore::new(PER_ORIGIN_REQUEST_LIMIT))))
                .collect(),
        }
    }

    async fn acquire(
        &self,
        host: &str,
        cancellation: &OfficialDownloadCancellation,
    ) -> OfficialResult<RequestPermits> {
        if !official_game_host_is_allowed(host) {
            return Err(OfficialCasError::InvalidPlan(
                "official request host is not allowed".into(),
            ));
        }
        let origin = self.per_origin.get(host).ok_or_else(|| {
            OfficialCasError::InvalidPlan("official request host has no gate".into())
        })?;
        let origin = cancellable(cancellation, origin.clone().acquire_owned())
            .await?
            .map_err(|_| OfficialCasError::Transport)?;
        let global = cancellable(cancellation, self.global.clone().acquire_owned())
            .await?
            .map_err(|_| OfficialCasError::Transport)?;
        Ok(RequestPermits {
            _global: global,
            _origin: origin,
        })
    }
}

struct RequestPermits {
    _global: OwnedSemaphorePermit,
    _origin: OwnedSemaphorePermit,
}

async fn cancellable<F: std::future::Future>(
    cancellation: &OfficialDownloadCancellation,
    future: F,
) -> OfficialResult<F::Output> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(OfficialCasError::Cancelled),
        value = future => Ok(value),
    }
}

struct OfficialHttpTransport {
    client: Client,
    #[cfg(test)]
    rewrite_origin: Option<Url>,
}

impl OfficialHttpTransport {
    fn production() -> Result<Self, String> {
        let resolver = Arc::new(PublicDnsResolver);
        let client = hardened_client(true, Some(resolver))?;
        Ok(Self {
            client,
            #[cfg(test)]
            rewrite_origin: None,
        })
    }

    #[cfg(test)]
    fn for_test(origin: &str) -> Self {
        let origin = Url::parse(origin).expect("test transport origin must parse");
        assert_eq!(origin.scheme(), "http");
        assert!(origin.host_str().is_some());
        assert!(origin.username().is_empty() && origin.password().is_none());
        Self {
            client: hardened_client(false, None).expect("test official client"),
            rewrite_origin: Some(origin),
        }
    }

    async fn get(
        &self,
        source: &Url,
        offset: u64,
        deadline: Instant,
        cancellation: &OfficialDownloadCancellation,
    ) -> Result<Response, TransportError> {
        let target = self.target_url(source).map_err(|_| TransportError::Fatal)?;
        let mut request = self
            .client
            .get(target.clone())
            .header(header::ACCEPT, "*/*")
            .header(header::ACCEPT_ENCODING, "identity");
        if offset > 0 {
            request = request.header(header::RANGE, format!("bytes={offset}-"));
        }
        let response = match cancellable_until(cancellation, deadline, request.send()).await {
            Err(WaitError::Cancelled) => return Err(TransportError::Cancelled),
            Err(WaitError::Deadline) => return Err(TransportError::Retryable),
            Ok(Ok(response)) => response,
            Ok(Err(error)) if error.is_timeout() || error.is_connect() || error.is_body() => {
                return Err(TransportError::Retryable)
            }
            Ok(Err(_)) => return Err(TransportError::Fatal),
        };
        if response.url() != &target {
            return Err(TransportError::Fatal);
        }
        Ok(response)
    }

    fn target_url(&self, source: &Url) -> Result<Url, ()> {
        #[cfg(test)]
        if let Some(origin) = &self.rewrite_origin {
            let mut target = origin.clone();
            target.set_path(source.path());
            target.set_query(source.query());
            target.set_fragment(None);
            return Ok(target);
        }
        Ok(source.clone())
    }
}

fn hardened_client(
    https_only: bool,
    resolver: Option<Arc<PublicDnsResolver>>,
) -> Result<Client, String> {
    let mut builder = Client::builder()
        .user_agent(concat!("FragmentLauncher/", env!("CARGO_PKG_VERSION")))
        .use_rustls_tls()
        .tls_built_in_root_certs(false)
        .tls_built_in_webpki_certs(true)
        .min_tls_version(Version::TLS_1_2)
        .redirect(Policy::none())
        .referer(false)
        .retry(reqwest::retry::never())
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_zstd()
        .no_deflate()
        .https_only(https_only)
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(PER_ORIGIN_REQUEST_LIMIT);
    if let Some(resolver) = resolver {
        builder = builder.dns_resolver(resolver);
    }
    builder
        .build()
        .map_err(|_| "Cannot create hardened official artifact client".into())
}

enum TransportError {
    Cancelled,
    Retryable,
    Fatal,
}

fn validate_identity_encoding(headers: &HeaderMap) -> OfficialResult<()> {
    if headers.contains_key(header::TRANSFER_ENCODING) {
        return Err(OfficialCasError::InvalidResponse(
            "Transfer-Encoding is forbidden for exact official objects",
        ));
    }
    let mut values = headers.get_all(header::CONTENT_ENCODING).iter();
    match (values.next(), values.next()) {
        (None, None) => Ok(()),
        (Some(value), None) if value.as_bytes().eq_ignore_ascii_case(b"identity") => Ok(()),
        _ => Err(OfficialCasError::InvalidResponse(
            "Content-Encoding is not identity",
        )),
    }
}

fn exact_content_length(headers: &HeaderMap) -> OfficialResult<u64> {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Err(OfficialCasError::InvalidResponse(
            "Content-Length is missing",
        ));
    };
    if values.next().is_some() {
        return Err(OfficialCasError::InvalidResponse(
            "Content-Length is duplicated",
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| OfficialCasError::InvalidResponse("Content-Length is invalid"))?;
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(OfficialCasError::InvalidResponse(
            "Content-Length is invalid",
        ));
    }
    value
        .parse()
        .map_err(|_| OfficialCasError::InvalidResponse("Content-Length is invalid"))
}

fn validate_download_response(
    response: &Response,
    requested_offset: u64,
    expected_size: u64,
) -> OfficialResult<u64> {
    let status = response.status();
    let write_offset = if requested_offset == 0 {
        if status != StatusCode::OK {
            return Err(OfficialCasError::InvalidResponse(
                "fresh request did not return 200",
            ));
        }
        reject_unexpected_content_range(response.headers())?;
        0
    } else if status == StatusCode::PARTIAL_CONTENT {
        let range = exact_single_header(response.headers(), header::CONTENT_RANGE)?;
        let expected = format!(
            "bytes {requested_offset}-{}/{}",
            expected_size.saturating_sub(1),
            expected_size
        );
        if range != expected {
            return Err(OfficialCasError::InvalidResponse(
                "Content-Range does not match the requested suffix",
            ));
        }
        requested_offset
    } else if status == StatusCode::OK {
        reject_unexpected_content_range(response.headers())?;
        0
    } else {
        return Err(OfficialCasError::InvalidResponse(
            "request returned an unexpected success status",
        ));
    };
    let expected_length =
        expected_size
            .checked_sub(write_offset)
            .ok_or(OfficialCasError::InvalidResponse(
                "write offset exceeds signed size",
            ))?;
    if exact_content_length(response.headers())? != expected_length {
        return Err(OfficialCasError::InvalidResponse(
            "Content-Length does not match the signed size",
        ));
    }
    Ok(write_offset)
}

fn reject_unexpected_content_range(headers: &HeaderMap) -> OfficialResult<()> {
    if headers.contains_key(header::CONTENT_RANGE) {
        Err(OfficialCasError::InvalidResponse(
            "200 response unexpectedly included Content-Range",
        ))
    } else {
        Ok(())
    }
}

fn validate_range_not_satisfiable(response: &Response, expected_size: u64) -> OfficialResult<()> {
    if exact_single_header(response.headers(), header::CONTENT_RANGE)?
        != format!("bytes */{expected_size}")
        || exact_content_length(response.headers())? != 0
    {
        return Err(OfficialCasError::InvalidResponse(
            "416 response is not bound to the signed size",
        ));
    }
    Ok(())
}

fn exact_single_header(headers: &HeaderMap, name: header::HeaderName) -> OfficialResult<String> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Err(OfficialCasError::InvalidResponse(
            "required response header is missing",
        ));
    };
    if values.next().is_some() {
        return Err(OfficialCasError::InvalidResponse(
            "required response header is duplicated",
        ));
    }
    value
        .to_str()
        .map(str::to_owned)
        .map_err(|_| OfficialCasError::InvalidResponse("required response header is invalid"))
}

async fn stream_response(
    response: Response,
    partial: &mut ResumableManagedFile,
    write_offset: u64,
    expected_size: u64,
    deadline: Instant,
    cancellation: &OfficialDownloadCancellation,
    reporter: &mut DownloadProgressReporter,
) -> Result<(), StreamError> {
    let mut written = write_offset;
    let mut stream = response.bytes_stream();
    loop {
        let item = tokio::select! {
            biased;
            _ = cancellation.cancelled() => {
                partial.sync_all().map_err(|error| {
                    StreamError::Fatal(managed_error("Cannot flush cancelled official CAS partial", error).into())
                })?;
                reporter.flush_bytes(written);
                return Err(StreamError::Cancelled);
            }
            _ = tokio::time::sleep_until(deadline) => {
                partial.sync_all().map_err(|error| {
                    StreamError::Fatal(managed_error("Cannot flush timed-out official CAS partial", error).into())
                })?;
                reporter.flush_bytes(written);
                return Err(StreamError::Retryable);
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
                    StreamError::Fatal(
                        managed_error("Cannot flush interrupted official CAS partial", error)
                            .into(),
                    )
                })?;
                reporter.flush_bytes(written);
                return Err(StreamError::Retryable);
            }
        };
        written = written
            .checked_add(chunk.len() as u64)
            .ok_or(StreamError::Fatal(OfficialCasError::InvalidResponse(
                "body size overflowed",
            )))?;
        if written > expected_size {
            return Err(StreamError::Fatal(OfficialCasError::InvalidResponse(
                "body exceeded the signed size",
            )));
        }
        partial
            .write_all_at(written - chunk.len() as u64, &chunk)
            .map_err(|error| {
                StreamError::Fatal(managed_error("Cannot write official CAS partial", error).into())
            })?;
        reporter.bytes(written, chunk.len() as u64);
    }
    partial.sync_all().map_err(|error| {
        StreamError::Fatal(managed_error("Cannot flush official CAS partial", error).into())
    })?;
    reporter.flush_bytes(written);
    Ok(())
}

fn attempt_timeout(size: u64) -> Duration {
    let transfer_seconds = size
        .div_ceil(MIN_TRANSFER_RATE_BYTES_PER_SECOND)
        .saturating_add(60);
    Duration::from_secs(transfer_seconds).clamp(MIN_ATTEMPT_TIME, MAX_ATTEMPT_TIME)
}

enum WaitError {
    Cancelled,
    Deadline,
}

async fn cancellable_until<F: std::future::Future>(
    cancellation: &OfficialDownloadCancellation,
    deadline: Instant,
    future: F,
) -> Result<F::Output, WaitError> {
    tokio::select! {
        biased;
        _ = cancellation.cancelled() => Err(WaitError::Cancelled),
        _ = tokio::time::sleep_until(deadline) => Err(WaitError::Deadline),
        value = future => Ok(value),
    }
}

enum StreamError {
    Cancelled,
    Retryable,
    Fatal(OfficialCasError),
}

#[derive(Debug)]
struct PublicDnsResolver;

impl Resolve for PublicDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_ascii_lowercase();
        if !official_game_host_is_allowed(&host) || host != name.as_str() {
            return Box::pin(async { Err(dns_error("official DNS name is not allowed")) });
        }
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|_| dns_error("official DNS resolution failed"))?
                .collect::<Vec<_>>();
            validate_public_address_set(addresses)
        })
    }
}

fn dns_error(message: &'static str) -> Box<dyn std::error::Error + Send + Sync> {
    Box::new(std::io::Error::other(message))
}

fn validate_public_address_set(
    addresses: Vec<SocketAddr>,
) -> Result<Addrs, Box<dyn std::error::Error + Send + Sync>> {
    if addresses.is_empty() || addresses.len() > 32 || addresses.iter().any(|address| {
        matches!(address, SocketAddr::V6(value) if value.scope_id() != 0 || value.flowinfo() != 0)
            || !is_public_ip(address.ip())
    }) {
        return Err(dns_error("official DNS answer is not entirely public"));
    }
    let unique = addresses.into_iter().collect::<BTreeSet<_>>();
    if unique.is_empty() {
        return Err(dns_error("official DNS answer is empty"));
    }
    Ok(Box::new(unique.into_iter()))
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(value) => is_public_ipv4(value),
        IpAddr::V6(value) => is_public_ipv6(value),
    }
}

fn is_public_ipv4(value: Ipv4Addr) -> bool {
    let [a, b, c, _] = value.octets();
    !(a == 0
        || a == 10
        || a == 127
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 31 && c == 196)
        || (a == 192 && b == 52 && c == 193)
        || (a == 192 && b == 88 && c == 99)
        || (a == 192 && b == 168)
        || (a == 192 && b == 175 && c == 48)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || a >= 224)
}

fn is_public_ipv6(value: Ipv6Addr) -> bool {
    if value.is_unspecified() || value.is_loopback() {
        return false;
    }
    let bytes = value.octets();
    if bytes[..10] == [0; 10] && bytes[10] == 0xff && bytes[11] == 0xff {
        return false;
    }
    if bytes[0] & 0xe0 != 0x20
        || (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] <= 0x01)
        || (bytes[0] == 0x20 && bytes[1] == 0x01 && bytes[2] == 0x0d && bytes[3] == 0xb8)
        || (bytes[0] == 0x20 && bytes[1] == 0x02)
        || (bytes[0] == 0x26
            && bytes[1] == 0x20
            && bytes[2] == 0x00
            && bytes[3] == 0x4f
            && bytes[4] == 0x80
            && bytes[5] == 0x00)
        || (bytes[0] == 0x3f && bytes[1] & 0xf0 == 0xf0)
        || (bytes[8..12] == [0x00, 0x00, 0x5e, 0xfe] || bytes[8..12] == [0x02, 0x00, 0x5e, 0xfe])
    {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_manager::{
        artifact_plan::{ArtifactExecutionSourceV2, ArtifactInventoryV2, ArtifactPlanV2},
        availability::VerifiedAvailabilityV2,
        cas::cas_object_relative_path,
        managed_fs::open_or_create_lock_file,
        planner::tests::trusted,
        storage::select_install_directory,
        types::{BuildChannel, PresetId},
    };
    use sha1::{Digest, Sha1};
    use sha2::Sha256;
    use std::{
        fs,
        io::{Read, Write},
        net::{TcpListener, TcpStream},
        path::PathBuf,
        sync::{
            atomic::{AtomicUsize, Ordering as AtomicOrdering},
            Arc, Mutex,
        },
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };
    use uuid::Uuid;

    struct ScriptedResponse {
        expected_range: Option<Option<String>>,
        status: &'static str,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        auto_content_length: bool,
    }

    #[derive(Default)]
    struct RecordingObserver {
        events: Mutex<Vec<super::DownloadProgressEvent>>,
    }

    impl DownloadObserver for RecordingObserver {
        fn observe(&self, event: &super::DownloadProgressEvent) {
            self.events.lock().unwrap().push(event.clone());
        }
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-official-cas-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn owned_root(label: &str) -> (PathBuf, OwnedCasRoot) {
        let install = temp_root(label);
        let root = select_install_directory(&install)
            .expect("claim test install")
            .into_owned_cas_root();
        (install, root)
    }

    fn expectation(bytes: &[u8], availability: ArtifactAvailabilityStateV2) -> OfficialExpectation {
        let sha1 = format!("{:x}", Sha1::digest(bytes));
        OfficialExpectation {
            source: Url::parse(&format!(
                "https://resources.download.minecraft.net/{}/{sha1}",
                &sha1[..2]
            ))
            .unwrap(),
            sha1,
            object: ExpectedObject {
                sha256: format!("{:x}", Sha256::digest(bytes)),
                size: bytes.len() as u64,
            },
            availability,
        }
    }

    fn write_partial(root: &OwnedCasRoot, expected: &OfficialExpectation, bytes: &[u8]) {
        let paths = CasPaths::new(&expected.object.sha256).unwrap();
        let guards = paths.prepare(root).unwrap();
        fs::write(paths.partial.join_to(root.managed_root()), bytes).unwrap();
        drop(guards);
    }

    fn write_final(root: &OwnedCasRoot, expected: &OfficialExpectation, bytes: &[u8]) {
        let paths = CasPaths::new(&expected.object.sha256).unwrap();
        let guards = paths.prepare(root).unwrap();
        fs::write(paths.final_path.join_to(root.managed_root()), bytes).unwrap();
        drop(guards);
    }

    fn read_verified(root: &OwnedCasRoot, object: &VerifiedCasObject) -> Vec<u8> {
        object
            .open(root)
            .unwrap()
            .read_bounded(object.size())
            .unwrap()
    }

    fn spawn_server(
        expected_path: String,
        responses: Vec<ScriptedResponse>,
    ) -> (String, Arc<AtomicUsize>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let handle = thread::spawn(move || {
            for scripted in responses {
                let (mut stream, _) = listener.accept().expect("accept official request");
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                observed.fetch_add(1, AtomicOrdering::SeqCst);
                let request = read_request(&mut stream);
                assert_request_hygiene(&request, &expected_path, scripted.expected_range.as_ref());
                write_response(&mut stream, scripted);
            }
        });
        (origin, count, handle)
    }

    fn spawn_stalling_then_resume_server(
        expected_path: String,
        bytes: Vec<u8>,
        split: usize,
    ) -> (String, std::sync::mpsc::Sender<()>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let (release, released) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            first
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_request(&mut first);
            assert_request_hygiene(&request, &expected_path, Some(&None));
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

            let (mut second, _) = listener.accept().unwrap();
            second
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let request = read_request(&mut second);
            assert_request_hygiene(
                &request,
                &expected_path,
                Some(&Some(format!("bytes={split}-"))),
            );
            write!(
                second,
                "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Range: bytes {}-{}/{}\r\nConnection: close\r\n\r\n",
                bytes.len() - split,
                split,
                bytes.len() - 1,
                bytes.len()
            )
            .unwrap();
            second.write_all(&bytes[split..]).unwrap();
            second.flush().unwrap();
        });
        (origin, release, handle)
    }

    fn spawn_outage_server() -> (String, Arc<AtomicUsize>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let origin = format!("http://{}/", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let observed = count.clone();
        let handle = thread::spawn(move || {
            let started = std::time::Instant::now();
            let mut last_request = None;
            loop {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        stream
                            .set_read_timeout(Some(Duration::from_secs(2)))
                            .unwrap();
                        let request = read_request(&mut stream);
                        assert_request_hygiene(
                            &request,
                            request
                                .lines()
                                .next()
                                .unwrap()
                                .split_ascii_whitespace()
                                .nth(1)
                                .unwrap(),
                            Some(&None),
                        );
                        observed.fetch_add(1, AtomicOrdering::SeqCst);
                        last_request = Some(std::time::Instant::now());
                        write!(
                            stream,
                            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 0\r\nConnection: close\r\n\r\n"
                        )
                        .unwrap();
                        stream.flush().unwrap();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if last_request
                            .is_some_and(|last| last.elapsed() >= Duration::from_millis(500))
                        {
                            break;
                        }
                        assert!(started.elapsed() < Duration::from_secs(10));
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(error) => panic!("outage server failed: {error}"),
                }
            }
        });
        (origin, count, handle)
    }

    fn read_request(stream: &mut TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut buffer = [0_u8; 4096];
        loop {
            let read = stream.read(&mut buffer).expect("read official request");
            assert!(read > 0, "request ended before headers");
            bytes.extend_from_slice(&buffer[..read]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
            assert!(bytes.len() < 64 * 1024);
        }
        String::from_utf8(bytes).unwrap()
    }

    fn assert_request_hygiene(
        request: &str,
        expected_path: &str,
        expected_range: Option<&Option<String>>,
    ) {
        let first = request.lines().next().unwrap();
        assert_eq!(first, format!("GET {expected_path} HTTP/1.1"));
        for forbidden in ["authorization", "cookie", "proxy-authorization", "referer"] {
            assert!(
                !request.lines().any(|line| {
                    line.split_once(':')
                        .is_some_and(|(name, _)| name.eq_ignore_ascii_case(forbidden))
                }),
                "forbidden request header: {forbidden}"
            );
        }
        let encoding = request.lines().find_map(|line| {
            line.split_once(':').and_then(|(name, value)| {
                name.eq_ignore_ascii_case("accept-encoding")
                    .then(|| value.trim())
            })
        });
        assert_eq!(encoding, Some("identity"));
        if let Some(expected) = expected_range {
            let actual = request.lines().find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("range")
                        .then(|| value.trim().to_owned())
                })
            });
            assert_eq!(&actual, expected);
        }
    }

    fn write_response(stream: &mut TcpStream, scripted: ScriptedResponse) {
        let mut head = format!("HTTP/1.1 {}\r\nConnection: close\r\n", scripted.status);
        if scripted.auto_content_length
            && !scripted
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        {
            head.push_str(&format!("Content-Length: {}\r\n", scripted.body.len()));
        }
        for (name, value) in scripted.headers {
            head.push_str(&name);
            head.push_str(": ");
            head.push_str(&value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&scripted.body).unwrap();
        stream.flush().unwrap();
    }

    fn ok(body: &[u8]) -> ScriptedResponse {
        ScriptedResponse {
            expected_range: Some(None),
            status: "200 OK",
            headers: Vec::new(),
            body: body.to_vec(),
            auto_content_length: true,
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_download_has_hygienic_headers_and_activates_dual_hashed_bytes() {
        let bytes = b"official dual-hashed object";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let (origin, requests, server) =
            spawn_server(expected.source.path().to_owned(), vec![ok(bytes)]);
        let (install, root) = owned_root("fresh");
        let observer = Arc::new(RecordingObserver::default());
        let downloader =
            OfficialCasDownloader::new_for_test_with_observer(&root, &origin, observer.clone());
        let object = downloader
            .ensure_expected(&expected, 0, &OfficialDownloadCancellation::new())
            .await
            .unwrap();
        assert_eq!(object.resumed_bytes(), 0);
        assert_eq!(read_verified(&root, &object), bytes);
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 1);
        let events = observer.events.lock().unwrap();
        assert_eq!(events.first().unwrap().phase, DownloadProgressPhase::Resume);
        assert_eq!(
            events.last().unwrap().phase,
            DownloadProgressPhase::Complete
        );
        assert!(events[1..events.len() - 1]
            .iter()
            .all(|event| event.phase == DownloadProgressPhase::Bytes));
        assert_eq!(events[0].persisted_bytes, 0);
        assert_eq!(
            events.iter().map(|event| event.delta_bytes).sum::<u64>(),
            bytes.len() as u64
        );
        assert!(events
            .windows(2)
            .all(|pair| pair[0].persisted_bytes <= pair[1].persisted_bytes));
        assert!(events.iter().all(|event| event.object.as_str().len() <= 30));
        drop(events);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test(flavor = "current_thread")]
    async fn corrupt_official_repair_reclaims_failure_crash_state_and_success_quarantine() {
        let bytes = b"official-quarantine-object";
        let corrupt = vec![b'x'; bytes.len()];
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Corrupt);
        let rejected = ScriptedResponse {
            expected_range: Some(None),
            status: "404 Not Found",
            headers: Vec::new(),
            body: Vec::new(),
            auto_content_length: true,
        };
        let (origin, _, server) =
            spawn_server(expected.source.path().to_owned(), vec![rejected, ok(bytes)]);
        let (install, root) = owned_root("corrupt-quarantine-recovery");
        write_final(&root, &expected, &corrupt);
        let paths = CasPaths::new(&expected.object.sha256).unwrap();
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);

        assert!(matches!(
            downloader
                .ensure_expected(&expected, 0, &OfficialDownloadCancellation::new())
                .await,
            Err(OfficialCasError::Http(StatusCode::NOT_FOUND))
        ));
        assert_eq!(
            fs::read(paths.quarantine_payload.join_to(root.managed_root())).unwrap(),
            corrupt
        );

        // The next exact object-lock owner treats the deterministic payload as crash residue,
        // removes it by identity, and can safely continue from canonical Missing.
        let object = downloader
            .ensure_expected(&expected, 0, &OfficialDownloadCancellation::new())
            .await
            .unwrap();
        assert_eq!(read_verified(&root, &object), bytes);
        assert!(!paths
            .quarantine_bucket
            .join_to(root.managed_root())
            .exists());
        server.join().unwrap();

        // A direct corrupt->verified replacement retains the bucket through activation and then
        // deletes it before reporting success.
        drop(object);
        fs::write(paths.final_path.join_to(root.managed_root()), &corrupt).unwrap();
        let (origin, _, server) = spawn_server(expected.source.path().to_owned(), vec![ok(bytes)]);
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let object = downloader
            .ensure_expected(&expected, 0, &OfficialDownloadCancellation::new())
            .await
            .unwrap();
        assert_eq!(read_verified(&root, &object), bytes);
        assert!(!paths
            .quarantine_bucket
            .join_to(root.managed_root())
            .exists());
        server.join().unwrap();

        drop(object);
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resumes_after_early_eof_using_the_live_same_handle_length() {
        let bytes = b"resume-after-an-interrupted-body";
        let split = 7_usize;
        let second_split = 14_usize;
        let expected = expectation(
            bytes,
            ArtifactAvailabilityStateV2::Partial {
                bytes: split as u64,
            },
        );
        let first = ScriptedResponse {
            expected_range: Some(Some(format!("bytes={split}-"))),
            status: "206 Partial Content",
            headers: vec![
                (
                    "Content-Range".into(),
                    format!("bytes {split}-{}/{}", bytes.len() - 1, bytes.len()),
                ),
                ("Content-Length".into(), (bytes.len() - split).to_string()),
            ],
            body: bytes[split..second_split].to_vec(),
            auto_content_length: false,
        };
        let second = ScriptedResponse {
            expected_range: Some(Some(format!("bytes={second_split}-"))),
            status: "206 Partial Content",
            headers: vec![
                (
                    "Content-Range".into(),
                    format!("bytes {second_split}-{}/{}", bytes.len() - 1, bytes.len()),
                ),
                (
                    "Content-Length".into(),
                    (bytes.len() - second_split).to_string(),
                ),
            ],
            body: bytes[second_split..].to_vec(),
            auto_content_length: false,
        };
        let (origin, requests, server) =
            spawn_server(expected.source.path().to_owned(), vec![first, second]);
        let (install, root) = owned_root("resume-eof");
        write_partial(&root, &expected, &bytes[..split]);
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let object = downloader
            .ensure_expected(
                &expected,
                split as u64,
                &OfficialDownloadCancellation::new(),
            )
            .await
            .unwrap();
        assert_eq!(object.resumed_bytes(), split as u64);
        assert_eq!(read_verified(&root, &object), bytes);
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 2);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ranged_200_resets_the_same_partial_handle_before_writing_full_body() {
        let bytes = b"origin-ignored-range";
        let split = 6_usize;
        let expected = expectation(
            bytes,
            ArtifactAvailabilityStateV2::Partial {
                bytes: split as u64,
            },
        );
        let mut response = ok(bytes);
        response.expected_range = Some(Some(format!("bytes={split}-")));
        let (origin, _, server) = spawn_server(expected.source.path().to_owned(), vec![response]);
        let (install, root) = owned_root("range-200");
        write_partial(&root, &expected, &bytes[..split]);
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let object = downloader
            .ensure_expected(
                &expected,
                split as u64,
                &OfficialDownloadCancellation::new(),
            )
            .await
            .unwrap();
        assert_eq!(object.resumed_bytes(), 0);
        assert_eq!(read_verified(&root, &object), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn strict_416_activates_only_an_exact_complete_partial() {
        let bytes = b"already-complete-partial";
        let expected = expectation(
            bytes,
            ArtifactAvailabilityStateV2::Partial {
                bytes: bytes.len() as u64,
            },
        );
        let response = ScriptedResponse {
            expected_range: Some(Some(format!("bytes={}-", bytes.len()))),
            status: "416 Range Not Satisfiable",
            headers: vec![
                ("Content-Range".into(), format!("bytes */{}", bytes.len())),
                ("Content-Length".into(), "0".into()),
            ],
            body: Vec::new(),
            auto_content_length: false,
        };
        let (origin, _, server) = spawn_server(expected.source.path().to_owned(), vec![response]);
        let (install, root) = owned_root("416-complete");
        write_partial(&root, &expected, bytes);
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let object = downloader
            .ensure_expected(
                &expected,
                bytes.len() as u64,
                &OfficialDownloadCancellation::new(),
            )
            .await
            .unwrap();
        assert_eq!(read_verified(&root, &object), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_complete_partial_after_416_is_reset_and_refetched_without_range() {
        let bytes = b"reset-invalid-complete";
        let expected = expectation(
            bytes,
            ArtifactAvailabilityStateV2::Partial {
                bytes: bytes.len() as u64,
            },
        );
        let rejected = ScriptedResponse {
            expected_range: Some(Some(format!("bytes={}-", bytes.len()))),
            status: "416 Range Not Satisfiable",
            headers: vec![
                ("Content-Range".into(), format!("bytes */{}", bytes.len())),
                ("Content-Length".into(), "0".into()),
            ],
            body: Vec::new(),
            auto_content_length: false,
        };
        let (origin, requests, server) =
            spawn_server(expected.source.path().to_owned(), vec![rejected, ok(bytes)]);
        let (install, root) = owned_root("416-reset");
        write_partial(&root, &expected, &vec![b'x'; bytes.len()]);
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let object = downloader
            .ensure_expected(
                &expected,
                bytes.len() as u64,
                &OfficialDownloadCancellation::new(),
            )
            .await
            .unwrap();
        assert_eq!(read_verified(&root, &object), bytes);
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 2);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sha1_mismatch_is_retried_clean_once_then_rejected_without_activation() {
        let bytes = b"same-sha256-wrong-declared-sha1";
        let mut expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        expected.sha1 = "a".repeat(40);
        expected.source = Url::parse(&format!(
            "https://resources.download.minecraft.net/aa/{}",
            expected.sha1
        ))
        .unwrap();
        let (origin, requests, server) = spawn_server(
            expected.source.path().to_owned(),
            vec![ok(bytes), ok(bytes)],
        );
        let (install, root) = owned_root("sha1-mismatch");
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let error = downloader
            .ensure_expected(&expected, 0, &OfficialDownloadCancellation::new())
            .await
            .unwrap_err();
        assert!(matches!(error, OfficialCasError::Integrity));
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 2);
        assert!(!cas_object_relative_path(&expected.object.sha256)
            .unwrap()
            .join_to(root.managed_root())
            .exists());
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn redirect_is_not_followed_or_automatically_retried() {
        let bytes = b"redirect target must never be fetched";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let redirect = ScriptedResponse {
            expected_range: Some(None),
            status: "302 Found",
            headers: vec![("Location".into(), "http://127.0.0.1:9/evil".into())],
            body: Vec::new(),
            auto_content_length: true,
        };
        let (origin, requests, server) =
            spawn_server(expected.source.path().to_owned(), vec![redirect]);
        let (install, root) = owned_root("redirect");
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        assert!(matches!(
            downloader
                .ensure_expected(&expected, 0, &OfficialDownloadCancellation::new(),)
                .await,
            Err(OfficialCasError::Http(StatusCode::FOUND))
        ));
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 1);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_content_length_and_forbidden_encodings_fail_closed() {
        let bytes = b"framing";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let response = ScriptedResponse {
            expected_range: Some(None),
            status: "200 OK",
            headers: Vec::new(),
            body: bytes.to_vec(),
            auto_content_length: false,
        };
        let (origin, _, server) = spawn_server(expected.source.path().to_owned(), vec![response]);
        let (install, root) = owned_root("missing-length");
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        assert!(matches!(
            downloader
                .ensure_expected(&expected, 0, &OfficialDownloadCancellation::new(),)
                .await,
            Err(OfficialCasError::InvalidResponse(
                "Content-Length is missing"
            ))
        ));
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();

        let mut headers = HeaderMap::new();
        headers.append(header::CONTENT_LENGTH, "7".parse().unwrap());
        headers.append(header::CONTENT_LENGTH, "7".parse().unwrap());
        assert!(exact_content_length(&headers).is_err());
        headers.clear();
        headers.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        assert!(validate_identity_encoding(&headers).is_err());
        headers.clear();
        headers.insert(header::TRANSFER_ENCODING, "chunked".parse().unwrap());
        headers.insert(header::CONTENT_LENGTH, "7".parse().unwrap());
        assert!(validate_identity_encoding(&headers).is_err());
        headers.clear();
        headers.insert(header::CONTENT_RANGE, "bytes 0-6/7".parse().unwrap());
        assert!(reject_unexpected_content_range(&headers).is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn pre_cancelled_operation_never_reaches_network() {
        let bytes = b"cancel-before-network";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let (install, root) = owned_root("pre-cancel");
        let downloader = OfficialCasDownloader::new_for_test(&root, "http://127.0.0.1:9/");
        let cancellation = OfficialDownloadCancellation::new();
        cancellation.cancel();
        assert!(matches!(
            downloader
                .ensure_expected(&expected, 0, &cancellation)
                .await,
            Err(OfficialCasError::Cancelled)
        ));
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cancellation_while_waiting_for_object_lock_releases_every_lease() {
        let bytes = b"cancel-while-object-locked";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let (install, root) = owned_root("cancel-lock");
        let paths = CasPaths::new(&expected.object.sha256).unwrap();
        let guards = paths.prepare(&root).unwrap();
        let held = open_or_create_lock_file(root.managed_root(), &paths.lock).unwrap();
        held.file().lock_exclusive().unwrap();
        let downloader = OfficialCasDownloader::new_for_test(&root, "http://127.0.0.1:9/");
        let cancellation = OfficialDownloadCancellation::new();
        let cancel = cancellation.clone();
        let (result, ()) = tokio::join!(
            downloader.ensure_expected(&expected, 0, &cancellation),
            async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                cancel.cancel();
            }
        );
        assert!(matches!(result, Err(OfficialCasError::Cancelled)));
        FileExt::unlock(held.file()).unwrap();
        drop(held);
        drop(guards);
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mid_body_cancellation_flushes_partial_releases_gate_and_resumes_safely() {
        let bytes = b"cancel-mid-body-then-resume-with-an-exact-range";
        let split = 13_usize;
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let (origin, release, server) = spawn_stalling_then_resume_server(
            expected.source.path().to_owned(),
            bytes.to_vec(),
            split,
        );
        let (install, root) = owned_root("cancel-body");
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let cancellation = OfficialDownloadCancellation::new();
        let cancel = cancellation.clone();
        let partial_path = CasPaths::new(&expected.object.sha256)
            .unwrap()
            .partial
            .join_to(root.managed_root());
        let (first, ()) = tokio::join!(
            downloader.ensure_expected(&expected, 0, &cancellation),
            async move {
                for _ in 0..500 {
                    if fs::metadata(&partial_path)
                        .is_ok_and(|metadata| metadata.len() == split as u64)
                    {
                        cancel.cancel();
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                panic!("partial body was not written before cancellation");
            }
        );
        assert!(matches!(first, Err(OfficialCasError::Cancelled)));
        release.send(()).unwrap();

        let second = downloader
            .ensure_expected(&expected, 0, &OfficialDownloadCancellation::new())
            .await
            .unwrap();
        assert_eq!(second.resumed_bytes(), split as u64);
        assert_eq!(read_verified(&root, &second), bytes);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn retry_after_backoff_is_cancellable_after_exactly_one_request() {
        let bytes = b"cancel-retry-after";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let response = ScriptedResponse {
            expected_range: Some(None),
            status: "503 Service Unavailable",
            headers: vec![("Retry-After".into(), "5".into())],
            body: Vec::new(),
            auto_content_length: true,
        };
        let (origin, requests, server) =
            spawn_server(expected.source.path().to_owned(), vec![response]);
        let (install, root) = owned_root("cancel-backoff");
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let cancellation = OfficialDownloadCancellation::new();
        let cancel = cancellation.clone();
        let observed = requests.clone();
        let (result, ()) = tokio::join!(
            downloader.ensure_expected(&expected, 0, &cancellation),
            async move {
                for _ in 0..500 {
                    if observed.load(AtomicOrdering::SeqCst) == 1 {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        cancel.cancel();
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
                panic!("retryable request was not observed");
            }
        );
        assert!(matches!(result, Err(OfficialCasError::Cancelled)));
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 1);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn concurrent_same_digest_downloads_once_and_the_loser_reaudits_winner() {
        let bytes = b"one-get-for-two-concurrent-callers";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let (origin, requests, server) =
            spawn_server(expected.source.path().to_owned(), vec![ok(bytes)]);
        let (install, root) = owned_root("same-digest");
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let cancellation_a = OfficialDownloadCancellation::new();
        let cancellation_b = OfficialDownloadCancellation::new();
        let (first, second) = tokio::join!(
            downloader.ensure_expected(&expected, 0, &cancellation_a),
            downloader.ensure_expected(&expected, 0, &cancellation_b),
        );
        let first = first.unwrap();
        let second = second.unwrap();
        assert_eq!(read_verified(&root, &first), bytes);
        assert_eq!(read_verified(&root, &second), bytes);
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 1);
        let paths = CasPaths::new(&expected.object.sha256).unwrap();
        assert!(!paths.partial.join_to(root.managed_root()).exists());
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn operation_circuit_bounds_many_object_outage_and_stops_new_requests() {
        let (origin, requests, server) = spawn_outage_server();
        let (install, root) = owned_root("operation-circuit");
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        let cancellation = OfficialDownloadCancellation::new();
        let expectations = (0..32)
            .map(|index| {
                expectation(
                    format!("outage-object-{index:02}").as_bytes(),
                    ArtifactAvailabilityStateV2::Missing,
                )
            })
            .collect::<Vec<_>>();
        let results = futures_util::future::join_all(
            expectations
                .iter()
                .map(|expected| downloader.ensure_expected(expected, 0, &cancellation)),
        )
        .await;
        assert!(results.iter().all(Result::is_err));
        assert!(results
            .iter()
            .any(|result| matches!(result, Err(OfficialCasError::RetryCircuitOpen))));
        server.join().unwrap();
        let bounded = requests.load(AtomicOrdering::SeqCst);
        assert!(bounded >= MAX_CONSECUTIVE_TRANSIENT_FAILURES as usize);
        assert!(bounded < MAX_CONSECUTIVE_TRANSIENT_FAILURES as usize + PER_ORIGIN_REQUEST_LIMIT);

        let before = requests.load(AtomicOrdering::SeqCst);
        let extra = expectation(
            b"must-not-start-after-circuit",
            ArtifactAvailabilityStateV2::Missing,
        );
        assert!(matches!(
            downloader.ensure_expected(&extra, 0, &cancellation).await,
            Err(OfficialCasError::RetryCircuitOpen)
        ));
        assert_eq!(requests.load(AtomicOrdering::SeqCst), before);
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[test]
    fn operation_retry_reservations_have_a_terminal_shared_cap() {
        let governor = OperationRetryGovernor::new();
        governor.prepare_attempt(false).unwrap();
        for _ in 0..MAX_OPERATION_RETRIES {
            governor.prepare_attempt(true).unwrap();
        }
        assert!(matches!(
            governor.prepare_attempt(true),
            Err(OfficialCasError::RetryCircuitOpen)
        ));
        assert!(matches!(
            governor.ensure_open(),
            Err(OfficialCasError::RetryCircuitOpen)
        ));
    }

    #[test]
    fn cancelled_precommit_keeps_a_synced_partial_and_never_publishes_final() {
        let bytes = b"cancel-at-last-safe-commit-boundary";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Missing);
        let (install, root) = owned_root("cancel-precommit");
        let paths = CasPaths::new(&expected.object.sha256).unwrap();
        let guards = paths.prepare(&root).unwrap();
        let mut partial = ResumableManagedFile::open_or_create(
            root.managed_root(),
            paths.partial.clone(),
            expected.object.size,
        )
        .unwrap();
        partial.write_all_at(0, bytes).unwrap();
        let result =
            activate_partial_if(&root, &paths, &expected.object, partial, 0, || false).unwrap();
        assert!(result.is_none());
        assert_eq!(
            fs::read(paths.partial.join_to(root.managed_root())).unwrap(),
            bytes
        );
        assert!(!paths.final_path.join_to(root.managed_root()).exists());
        drop(guards);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn malformed_resume_ranges_and_conflicting_ranged_200_fail_without_retry() {
        let bytes = b"strict-resume-framing";
        let split = 5_usize;
        let expected = expectation(
            bytes,
            ArtifactAvailabilityStateV2::Partial {
                bytes: split as u64,
            },
        );
        let wrong_206 = ScriptedResponse {
            expected_range: Some(Some(format!("bytes={split}-"))),
            status: "206 Partial Content",
            headers: vec![
                (
                    "Content-Range".into(),
                    format!("bytes {split}-{}/{}", bytes.len() - 2, bytes.len()),
                ),
                ("Content-Length".into(), (bytes.len() - split).to_string()),
            ],
            body: bytes[split..].to_vec(),
            auto_content_length: false,
        };
        let (origin, requests, server) =
            spawn_server(expected.source.path().to_owned(), vec![wrong_206]);
        let (install, root) = owned_root("bad-206");
        write_partial(&root, &expected, &bytes[..split]);
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        assert!(matches!(
            downloader
                .ensure_expected(
                    &expected,
                    split as u64,
                    &OfficialDownloadCancellation::new(),
                )
                .await,
            Err(OfficialCasError::InvalidResponse(_))
        ));
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 1);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();

        let expected = expectation(
            bytes,
            ArtifactAvailabilityStateV2::Partial {
                bytes: split as u64,
            },
        );
        let ranged_200 = ScriptedResponse {
            expected_range: Some(Some(format!("bytes={split}-"))),
            status: "200 OK",
            headers: vec![(
                "Content-Range".into(),
                format!("bytes 0-{}/{}", bytes.len() - 1, bytes.len()),
            )],
            body: bytes.to_vec(),
            auto_content_length: true,
        };
        let (origin, requests, server) =
            spawn_server(expected.source.path().to_owned(), vec![ranged_200]);
        let (install, root) = owned_root("bad-range-200");
        write_partial(&root, &expected, &bytes[..split]);
        let downloader = OfficialCasDownloader::new_for_test(&root, &origin);
        assert!(matches!(
            downloader
                .ensure_expected(
                    &expected,
                    split as u64,
                    &OfficialDownloadCancellation::new(),
                )
                .await,
            Err(OfficialCasError::InvalidResponse(_))
        ));
        assert_eq!(requests.load(AtomicOrdering::SeqCst), 1);
        server.join().unwrap();
        drop(downloader);
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn complete_verification_is_dual_hash_verify_only() {
        let bytes = b"complete-official-object";
        let expected = expectation(bytes, ArtifactAvailabilityStateV2::Complete);
        let (install, root) = owned_root("complete");
        write_final(&root, &expected, bytes);
        let cancellation = OfficialDownloadCancellation::new();
        let object = verify_complete_official(&root, &expected, 0, &cancellation).unwrap();
        assert_eq!(read_verified(&root, &object), bytes);
        let path = cas_object_relative_path(&expected.object.sha256)
            .unwrap()
            .join_to(root.managed_root());
        fs::write(&path, vec![b'x'; bytes.len()]).unwrap();
        assert!(verify_complete_official(&root, &expected, 0, &cancellation).is_err());
        assert!(
            path.exists(),
            "Complete verification must not quarantine or fetch"
        );
        drop(root);
        fs::remove_dir_all(install).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn sealed_boundary_rejects_spark_authority_and_another_root_before_network() {
        let (install_a, root_a) = owned_root("sealed-a");
        let (install_b, root_b) = owned_root("sealed-b");
        let release = trusted('a', 1);
        let inventory = ArtifactInventoryV2::build(
            &root_a,
            &release,
            root_a.binding().1,
            Uuid::new_v4(),
            BuildChannel::Stable,
            PresetId::Medium,
        )
        .unwrap();
        let availability = VerifiedAvailabilityV2::for_test(&inventory, [], false, false);
        let plan = ArtifactPlanV2::for_reconcile(&inventory, &availability, []).unwrap();
        let view = plan.execution_view(&root_a, &inventory).unwrap();
        let spark = view
            .items()
            .find(|item| item.source() == ArtifactExecutionSourceV2::SparkCas)
            .unwrap();
        let downloader_a = OfficialCasDownloader::new_for_test(&root_a, "http://127.0.0.1:9/");
        assert!(matches!(
            downloader_a
                .ensure_planned_official_object(&spark, &OfficialDownloadCancellation::new(),)
                .await,
            Err(OfficialCasError::InvalidPlan(_))
        ));

        let official = view
            .items()
            .find(|item| {
                matches!(
                    item.source(),
                    ArtifactExecutionSourceV2::OfficialHttps { .. }
                )
            })
            .unwrap();
        let downloader_b = OfficialCasDownloader::new_for_test(&root_b, "http://127.0.0.1:9/");
        assert!(matches!(
            downloader_b
                .ensure_planned_official_object(&official, &OfficialDownloadCancellation::new(),)
                .await,
            Err(OfficialCasError::InvalidPlan(_))
        ));
        drop(downloader_b);
        drop(downloader_a);
        drop(root_b);
        drop(root_a);
        fs::remove_dir_all(install_b).unwrap();
        fs::remove_dir_all(install_a).unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_gates_enforce_four_per_origin_and_eight_global_without_hot_origin_hoarding() {
        let gates = RequestGates::new();
        let cancellation = OfficialDownloadCancellation::new();
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                gates
                    .acquire("resources.download.minecraft.net", &cancellation)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(gates.global.available_permits(), 4);
        assert_eq!(
            gates.per_origin["resources.download.minecraft.net"].available_permits(),
            0
        );
        for _ in 0..4 {
            held.push(
                gates
                    .acquire("libraries.minecraft.net", &cancellation)
                    .await
                    .unwrap(),
            );
        }
        assert_eq!(gates.global.available_permits(), 0);
        drop(held);
        assert_eq!(gates.global.available_permits(), GLOBAL_REQUEST_LIMIT);

        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                gates
                    .acquire("piston-meta.mojang.com", &cancellation)
                    .await
                    .unwrap(),
            );
        }
        let waiting_cancellation = OfficialDownloadCancellation::new();
        let cancel = waiting_cancellation.clone();
        let (waiting, ()) = tokio::join!(
            gates.acquire("piston-meta.mojang.com", &waiting_cancellation),
            async move {
                tokio::time::sleep(Duration::from_millis(20)).await;
                cancel.cancel();
            }
        );
        assert!(matches!(waiting, Err(OfficialCasError::Cancelled)));
        assert_eq!(gates.global.available_permits(), 4);
        drop(held);
    }

    #[test]
    fn dns_filter_rejects_private_mixed_scoped_mapped_and_special_answers() {
        let public_v4: SocketAddr = "1.1.1.1:0".parse().unwrap();
        let public_v6: SocketAddr = "[2606:4700:4700::1111]:0".parse().unwrap();
        assert_eq!(
            validate_public_address_set(vec![public_v4, public_v6])
                .unwrap()
                .count(),
            2
        );
        for forbidden in [
            "127.0.0.1:0",
            "10.0.0.1:0",
            "192.0.2.1:0",
            "[::1]:0",
            "[::ffff:1.1.1.1]:0",
            "[2001:db8::1]:0",
            "[2002:0101:0101::1]:0",
        ] {
            let forbidden = forbidden.parse().unwrap();
            assert!(validate_public_address_set(vec![public_v4, forbidden]).is_err());
        }
        let scoped = SocketAddr::V6(std::net::SocketAddrV6::new(
            "2606:4700:4700::1111".parse().unwrap(),
            0,
            0,
            7,
        ));
        assert!(validate_public_address_set(vec![scoped]).is_err());
        assert!(validate_public_address_set(Vec::new()).is_err());
        assert!(validate_public_address_set(vec![public_v4; 33]).is_err());
    }

    #[test]
    fn central_source_validator_rejects_every_origin_and_binding_mutation() {
        let sha1 = "ab".repeat(20);
        let valid = format!(
            "https://resources.download.minecraft.net/{}/{sha1}",
            &sha1[..2]
        );
        assert!(validate_official_game_source(&valid, &sha1).is_ok());
        for invalid in [
            valid.replacen("https://", "http://", 1),
            valid.replacen("resources.download.minecraft.net", "evil.invalid", 1),
            format!("{valid}?query=1"),
            format!("{valid}#fragment"),
            format!(
                "https://user@resources.download.minecraft.net/{}/{sha1}",
                &sha1[..2]
            ),
            format!(
                "https://resources.download.minecraft.net:443/{}/{sha1}",
                &sha1[..2]
            ),
            format!(
                "https://resources.download.minecraft.net/aa/{}",
                "cd".repeat(20)
            ),
        ] {
            assert!(
                validate_official_game_source(&invalid, &sha1).is_err(),
                "{invalid}"
            );
        }
    }
}
