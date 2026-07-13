use super::{
    artifact_plan::{
        ArtifactExecutionSourceV2, ArtifactExecutionViewV2, ArtifactInventoryV2, ArtifactPlanV2,
    },
    availability::VerifiedAvailabilityV2,
    cas::{
        verify_planned_object, CasDownloader, CasError, DownloadCancellation,
        DownloadObjectIdentity, DownloadObserver, DownloadProgressEvent, DownloadProgressPhase,
        SparkAccessTokenProvider, VerifiedCasObject,
    },
    game_generation::{
        begin_game_generation, merge_processor_outputs, publish_game_generation,
        stage_official_game_files, BeginGameGeneration, StagedGameGeneration,
    },
    game_runtime_executor::{execute_game_runtime_processors, ProcessorExecutionError},
    game_runtime_materializer::materialize_processor_workspace,
    instance_state::{ActiveInstanceV2, InstanceOperationLock, InstanceStateStore},
    journal::{
        abandon_stale_pending_for_current_ready, advance_pending_to_recorded_successor,
        complete_pending_committed, complete_pending_rolled_back, detect_pending,
        detect_pending_transition, maintain_completed_reconcile_state, publish_pending,
        required_phase_bytes, supersede_stale_pending_with_current_plan, write_immutable_plan,
        JournalMutation, PendingJournalTransitionV2, PendingJournalV2, ReconcilePlanV2,
    },
    managed_fs::{
        ensure_directory_chain, open_or_create_lock_file, ImmutableManagedFile, ManagedLockFile,
        RelativeManagedPath,
    },
    mutable::{capture_minecraft_options_state, materialize_minecraft_options_state},
    official_cas::{OfficialCasDownloader, OfficialDownloadCancellation},
    planner::{
        authorize_current_plan_supersede, authorize_stale_pending_ready_abandon, decide_recovery,
        plan_build, plan_mutable_bootstrap, prepare_current_plan_supersede,
        CurrentPlanSupersedeRequestV2, MutableMaterializationProofV2, PlannedBuildState,
        PlannedBuildV2, PlannerRequestV2, RecoveryDecisionV2, RecoveryRequestV2,
    },
    reconcile_executor::{
        authorize_reconcile_staging_v2, bind_canonical_mutable_staging_source_v2,
        bind_exact_staging_source_v2, classify_untrusted_pending_identity_v2,
        recover_pending_reconcile_staging_v2, roll_forward_staged_v2,
        rollback_pending_reconcile_v2, write_reconcile_staging_with_checkpoint_v2,
        PendingReconcileRecoveryRequestV2, PendingReconcileStagingV2, ReconcileExecutorErrorV2,
        ReconcileStagingSourceV2, StagingWriterCheckpointErrorV2, StagingWriterCheckpointV2,
        TrustedReconcileStagingAuthorityV2, UntrustedPendingIdentityV2,
    },
    reconciler::{
        audit_current_reconcile_plan_instance, audit_release_instance, InstanceAudit,
        ReconcilePlanAuditV2,
    },
    release::FilePolicy,
    runtime::{
        install_runtime_with_control, RuntimeInstallControl, RuntimeInstallError,
        RuntimeInstallProgress, RuntimeInstallation,
    },
    settings_store::SettingsStore,
    spark_client::SparkClient,
    storage::{validate_owned_install_directory, OwnedCasRoot},
    tuf::{SparkTufClient, TrustedRelease, TufRefreshError},
    types::{BuildChannel, BuildPhase, PresetId, PrimaryAction},
};
use crate::auth::{AuthSessionManager, NativeAccessFailure, NativeAccessToken};
use futures_util::{stream::FuturesUnordered, StreamExt};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fmt,
    future::Future,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const COORDINATOR_LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const COORDINATOR_LOCK_POLL: Duration = Duration::from_millis(50);
const DOWNLOAD_CONCURRENCY: usize = 8;

#[derive(Clone)]
pub(super) struct BuildCoordinator {
    config: CoordinatorConfig,
}

impl BuildCoordinator {
    pub(super) fn new(config: CoordinatorConfig) -> Self {
        Self { config }
    }

    pub(super) async fn inspect(
        &self,
        install_directory: &Path,
        install_id: Uuid,
        channel: BuildChannel,
        preset: PresetId,
        auth: &Arc<AuthSessionManager>,
        observer: &ProgressObserver,
    ) -> Result<CoordinatorSnapshot, CoordinatorError> {
        inspect_operation(
            &self.config,
            install_directory,
            install_id,
            channel,
            preset,
            auth,
            observer,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) async fn run(
        &self,
        install_directory: &Path,
        install_id: Uuid,
        operation_id: Uuid,
        channel: BuildChannel,
        preset: PresetId,
        auth: &Arc<AuthSessionManager>,
        cancellation: &CoordinatorCancellation,
        observer: &ProgressObserver,
    ) -> Result<CoordinatorSnapshot, CoordinatorError> {
        run_operation(
            &self.config,
            install_directory,
            install_id,
            operation_id,
            channel,
            preset,
            auth,
            cancellation,
            observer,
        )
        .await
    }
}

#[derive(Clone)]
pub(super) struct TufRootAnchors {
    stable: Arc<[u8]>,
    dev: Arc<[u8]>,
}

impl TufRootAnchors {
    pub(super) fn production_fail_closed() -> Self {
        // Production roots are intentionally empty until Spark2 publication provisions audited,
        // offline-backed stable/dev anchors. An external file must never silently become trust.
        Self {
            stable: Arc::from([]),
            dev: Arc::from([]),
        }
    }

    #[cfg(test)]
    pub(super) fn for_test(stable: Vec<u8>, dev: Vec<u8>) -> Self {
        Self {
            stable: Arc::from(stable),
            dev: Arc::from(dev),
        }
    }

    fn for_channel(&self, channel: BuildChannel) -> Result<Arc<[u8]>, CoordinatorError> {
        let root = match channel {
            BuildChannel::Stable => Arc::clone(&self.stable),
            BuildChannel::Dev => Arc::clone(&self.dev),
        };
        if root.is_empty() {
            return Err(CoordinatorError::LauncherUpdateRequired(
                "В этой сборке лаунчера ещё нет production TUF-якоря Spark2".into(),
            ));
        }
        Ok(root)
    }
}

#[derive(Clone)]
pub(super) struct CoordinatorConfig {
    pub(super) tuf_state_root: PathBuf,
    pub(super) anchors: TufRootAnchors,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CoordinatorProgress {
    pub(super) phase: BuildPhase,
    pub(super) message: String,
    pub(super) current_file: Option<String>,
    pub(super) downloaded_bytes: u64,
    pub(super) total_bytes: u64,
    pub(super) speed_bytes_per_second: u64,
    pub(super) disk_free_bytes: u64,
    pub(super) disk_required_bytes: u64,
}

impl CoordinatorProgress {
    fn checking(message: impl Into<String>) -> Self {
        Self {
            phase: BuildPhase::Checking,
            message: message.into(),
            current_file: None,
            downloaded_bytes: 0,
            total_bytes: 0,
            speed_bytes_per_second: 0,
            disk_free_bytes: 0,
            disk_required_bytes: 0,
        }
    }
}

pub(super) type ProgressObserver = Arc<dyn Fn(CoordinatorProgress) + Send + Sync>;

struct CoordinatorDownloadObserver {
    observer: ProgressObserver,
    install_root: PathBuf,
    phase: BuildPhase,
    total_bytes: u64,
    required_bytes: u64,
    charges: BTreeMap<String, u64>,
    state: Mutex<DownloadAggregate>,
}

struct DownloadAggregate {
    persisted: BTreeMap<String, u64>,
    last_sample: Instant,
    last_total: u64,
    speed: u64,
}

impl DownloadAggregate {
    fn record(
        &mut self,
        key: String,
        persisted: u64,
        total_bytes: u64,
        now: Instant,
    ) -> (u64, u64) {
        self.persisted.insert(key, persisted);
        let aggregate = self
            .persisted
            .values()
            .copied()
            .fold(0_u64, u64::saturating_add)
            .min(total_bytes);
        let elapsed = now.saturating_duration_since(self.last_sample);
        if elapsed >= Duration::from_millis(250) || aggregate == total_bytes {
            let delta = aggregate.saturating_sub(self.last_total);
            self.speed = if delta == 0 || elapsed.is_zero() {
                0
            } else {
                ((delta as u128) * 1_000 / elapsed.as_millis().max(1)).min(u64::MAX as u128) as u64
            };
            self.last_sample = now;
            self.last_total = aggregate;
        }
        (aggregate, self.speed)
    }
}

fn charged_persisted(charges: &BTreeMap<String, u64>, key: &str, persisted: u64) -> u64 {
    persisted.min(charges.get(key).copied().unwrap_or(0))
}

impl CoordinatorDownloadObserver {
    fn new(
        observer: ProgressObserver,
        root: &OwnedCasRoot,
        phase: BuildPhase,
        total_bytes: u64,
        required_bytes: u64,
        charges: BTreeMap<String, u64>,
    ) -> Self {
        Self {
            observer,
            install_root: root.install_root().to_path_buf(),
            phase,
            total_bytes,
            required_bytes,
            charges,
            state: Mutex::new(DownloadAggregate {
                persisted: BTreeMap::new(),
                last_sample: Instant::now(),
                last_total: 0,
                speed: 0,
            }),
        }
    }
}

impl DownloadObserver for CoordinatorDownloadObserver {
    fn observe(&self, event: &DownloadProgressEvent) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let key = event.object.as_str().to_owned();
        let persisted = match event.phase {
            DownloadProgressPhase::Reset => 0,
            DownloadProgressPhase::Resume
            | DownloadProgressPhase::Bytes
            | DownloadProgressPhase::Complete => event.persisted_bytes,
        };
        let charged = charged_persisted(&self.charges, &key, persisted);
        let now = Instant::now();
        let (aggregate, speed) = state.record(key.clone(), charged, self.total_bytes, now);
        let free = fs2::available_space(&self.install_root).unwrap_or(0);
        (self.observer)(CoordinatorProgress {
            phase: self.phase,
            message: "Downloading signed build artifacts".into(),
            current_file: Some(key),
            downloaded_bytes: aggregate,
            total_bytes: self.total_bytes,
            speed_bytes_per_second: speed,
            disk_free_bytes: free,
            disk_required_bytes: self.required_bytes,
        });
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CoordinatorSnapshot {
    pub(super) state: PlannedBuildState,
    pub(super) installed_release_id: Option<String>,
    pub(super) available_release_id: String,
    pub(super) disk_free_bytes: u64,
    pub(super) disk_required_bytes: u64,
    pub(super) message: String,
}

impl CoordinatorSnapshot {
    pub(super) fn phase_action(&self) -> (BuildPhase, PrimaryAction) {
        match self.state {
            PlannedBuildState::Download => (BuildPhase::NotInstalled, PrimaryAction::Download),
            PlannedBuildState::Update => (BuildPhase::Outdated, PrimaryAction::Update),
            PlannedBuildState::Repair => (BuildPhase::RepairNeeded, PrimaryAction::Repair),
            PlannedBuildState::Ready => (BuildPhase::Ready, PrimaryAction::Play),
        }
    }
}

#[derive(Debug)]
pub(super) enum CoordinatorError {
    Cancelled,
    DiskInsufficient { available: u64, required: u64 },
    LauncherUpdateRequired(String),
    SubscriptionRequired(String),
    DevForbidden(String),
    Auth(String),
    Failed(String),
}

impl fmt::Display for CoordinatorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cancelled => formatter.write_str("Операция отменена"),
            Self::DiskInsufficient {
                available,
                required,
            } => write!(
                formatter,
                "Недостаточно места: доступно {available} байт, требуется {required} байт"
            ),
            Self::LauncherUpdateRequired(message)
            | Self::SubscriptionRequired(message)
            | Self::DevForbidden(message)
            | Self::Auth(message)
            | Self::Failed(message) => formatter.write_str(message),
        }
    }
}

impl std::error::Error for CoordinatorError {}

impl From<String> for CoordinatorError {
    fn from(value: String) -> Self {
        Self::Failed(value)
    }
}

#[derive(Clone, Default)]
pub(super) struct CoordinatorCancellation {
    cancelled: Arc<AtomicBool>,
    spark: DownloadCancellation,
    official: OfficialDownloadCancellation,
}

impl CoordinatorCancellation {
    pub(super) fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.spark.cancel();
        self.official.cancel();
    }

    pub(super) fn flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.cancelled)
    }

    fn check(&self) -> Result<(), CoordinatorError> {
        if self.cancelled.load(Ordering::Acquire) {
            Err(CoordinatorError::Cancelled)
        } else {
            Ok(())
        }
    }
}

fn select_attempt_cancellation<'a>(
    user: &'a CoordinatorCancellation,
    recovery: &'a CoordinatorCancellation,
    recovered_pending: bool,
) -> &'a CoordinatorCancellation {
    if recovered_pending {
        recovery
    } else {
        user
    }
}

fn rotate_attempt_operation_id(previous: Uuid) -> Uuid {
    loop {
        let candidate = Uuid::new_v4();
        if candidate != previous {
            return candidate;
        }
    }
}

struct OperationAuthority {
    root: OwnedCasRoot,
    install_id: Uuid,
    install_root: PathBuf,
}

/// Install-wide expansion lock. Stable and dev share the same runtime/CAS volume peak, so the
/// per-channel journal lock is deliberately nested under this one for every mutating operation.
struct CoordinatorOperationLock {
    file: ManagedLockFile,
    install_root: PathBuf,
}

struct InitialAttemptClassification {
    install_lock: CoordinatorOperationLock,
    channel_lock: InstanceOperationLock,
    pending: bool,
}

fn is_coordinator_lock_contention(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::WouldBlock | ErrorKind::PermissionDenied
    ) || {
        #[cfg(windows)]
        {
            // Windows reports an already-held fs2 lock as SHARING_VIOLATION (32) or
            // LOCK_VIOLATION (33), both of which map to `ErrorKind::Other` on supported Rust.
            matches!(error.raw_os_error(), Some(32 | 33))
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

impl Drop for CoordinatorOperationLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(self.file.file());
    }
}

impl CoordinatorOperationLock {
    fn acquire(root: &OwnedCasRoot) -> Result<Self, CoordinatorError> {
        root.revalidate().map_err(CoordinatorError::Failed)?;
        let state = RelativeManagedPath::new("state").map_err(|error| {
            CoordinatorError::Failed(format!("Cannot construct coordinator state path: {error}"))
        })?;
        ensure_directory_chain(root.install_root(), &state).map_err(|error| {
            CoordinatorError::Failed(format!("Cannot create coordinator state: {error}"))
        })?;
        let relative = RelativeManagedPath::new("state/coordinator-v2.lock").map_err(|error| {
            CoordinatorError::Failed(format!("Cannot construct coordinator lock path: {error}"))
        })?;
        let file = open_or_create_lock_file(root.install_root(), &relative).map_err(|error| {
            CoordinatorError::Failed(format!("Cannot open coordinator lock: {error}"))
        })?;
        let started = Instant::now();
        loop {
            match fs2::FileExt::try_lock_exclusive(file.file()) {
                Ok(()) => break,
                Err(error)
                    if is_coordinator_lock_contention(&error)
                        && started.elapsed() < COORDINATOR_LOCK_TIMEOUT =>
                {
                    thread::sleep(COORDINATOR_LOCK_POLL);
                }
                Err(error) => {
                    return Err(CoordinatorError::Failed(format!(
                        "Another launcher process is changing this installation: {error}"
                    )));
                }
            }
        }
        file.revalidate().map_err(|error| {
            CoordinatorError::Failed(format!(
                "Coordinator lock changed after acquisition: {error}"
            ))
        })?;
        root.revalidate().map_err(CoordinatorError::Failed)?;
        Ok(Self {
            file,
            install_root: root.install_root().to_path_buf(),
        })
    }

    fn revalidate(&self, root: &OwnedCasRoot) -> Result<(), CoordinatorError> {
        if root.install_root() != self.install_root {
            return Err(CoordinatorError::Failed(
                "Coordinator lock belongs to another installation".into(),
            ));
        }
        self.file.revalidate().map_err(|error| {
            CoordinatorError::Failed(format!("Coordinator lock changed: {error}"))
        })?;
        root.revalidate().map_err(CoordinatorError::Failed)
    }
}

fn acquire_initial_attempt_classification(
    authority: &OperationAuthority,
    state_store: &InstanceStateStore,
    channel: BuildChannel,
    caller: &CoordinatorCancellation,
    recovery: &CoordinatorCancellation,
) -> Result<InitialAttemptClassification, CoordinatorError> {
    // Caller cancellation is deliberately not consulted until the install-wide lock and the
    // channel journal lock both establish whether durable recovery owns this attempt.
    let install_lock = CoordinatorOperationLock::acquire(&authority.root)?;
    let channel_lock = state_store
        .acquire_operation_lock(channel)
        .map_err(|error| {
            CoordinatorError::Failed(format!("Cannot lock initial recovery check: {error}"))
        })?;
    let pending = detect_pending_transition(
        &authority.install_root,
        authority.install_id,
        channel,
        &channel_lock,
    )
    .map_err(CoordinatorError::Failed)?
    .is_some();
    select_attempt_cancellation(caller, recovery, pending).check()?;
    install_lock.revalidate(&authority.root)?;
    Ok(InitialAttemptClassification {
        install_lock,
        channel_lock,
        pending,
    })
}

fn validate_operation_root(
    install_directory: &Path,
    install_id: Uuid,
) -> Result<OperationAuthority, CoordinatorError> {
    let validated = validate_owned_install_directory(install_directory, install_id)
        .map_err(CoordinatorError::Failed)?;
    let install_root = validated.path().to_path_buf();
    let root = validated.into_owned_cas_root();
    root.revalidate().map_err(CoordinatorError::Failed)?;
    Ok(OperationAuthority {
        root,
        install_id,
        install_root,
    })
}

async fn access_token(
    auth: &Arc<AuthSessionManager>,
) -> Result<NativeAccessToken, CoordinatorError> {
    auth.native_access_token_completion_safe()
        .await
        .map_err(map_access_token_error)
}

async fn wait_for_cancellation(cancelled: Arc<AtomicBool>) {
    while !cancelled.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn map_access_token_error(error: crate::auth::AuthError) -> CoordinatorError {
    match error.into_native_access_failure() {
        NativeAccessFailure::Authentication => {
            CoordinatorError::Auth("Fragment authentication is required".into())
        }
        NativeAccessFailure::Failed(message) => CoordinatorError::Failed(format!(
            "Cannot refresh Fragment access capability: {message}"
        )),
    }
}

fn map_token_provider_error(error: crate::auth::AuthError) -> CasError {
    match error.into_native_access_failure() {
        NativeAccessFailure::Authentication => CasError::Authentication,
        NativeAccessFailure::Failed(message) => CasError::Failed(format!(
            "Cannot refresh Fragment access capability: {message}"
        )),
    }
}

/// Completes refresh-token rotation and credential persistence before observing cancellation.
/// Dropping an access-token request after the server rotated a one-time token would strand the
/// local session, so this helper deliberately contains no `select!` or cancellable wrapper.
async fn access_token_with_completion_safe_cancellation(
    auth: &Arc<AuthSessionManager>,
    cancellation: &CoordinatorCancellation,
) -> Result<NativeAccessToken, CoordinatorError> {
    cancellation.check()?;
    let token = access_token(auth).await?;
    cancellation.check()?;
    Ok(token)
}

struct CoordinatorSparkAccessTokenProvider<'a> {
    auth: Arc<AuthSessionManager>,
    cancellation: &'a CoordinatorCancellation,
    transport: &'a DownloadCancellation,
}

fn check_token_provider_cancellation(
    cancellation: &CoordinatorCancellation,
    transport: &DownloadCancellation,
) -> Result<(), CasError> {
    cancellation.check().map_err(|_| CasError::Cancelled)?;
    transport.check()
}

async fn finish_token_refresh_before_cancellation<F>(
    cancellation: &CoordinatorCancellation,
    transport: &DownloadCancellation,
    refresh: F,
) -> Result<NativeAccessToken, CasError>
where
    F: Future<Output = Result<NativeAccessToken, CasError>>,
{
    check_token_provider_cancellation(cancellation, transport)?;
    // The future is deliberately awaited directly. Its server-side rotation and local credential
    // persistence form one transaction which must survive cancellation.
    let token = refresh.await?;
    check_token_provider_cancellation(cancellation, transport)?;
    Ok(token)
}

impl SparkAccessTokenProvider for CoordinatorSparkAccessTokenProvider<'_> {
    async fn fresh_access_token(
        &mut self,
        rejected: Option<&NativeAccessToken>,
    ) -> Result<NativeAccessToken, CasError> {
        let auth = Arc::clone(&self.auth);
        let rejected = rejected.cloned();
        finish_token_refresh_before_cancellation(self.cancellation, self.transport, async move {
            match rejected {
                Some(rejected) => {
                    auth.native_access_token_after_rejection_completion_safe(rejected)
                        .await
                }
                None => auth.native_access_token_completion_safe().await,
            }
            .map_err(map_token_provider_error)
        })
        .await
    }
}

fn current_free_space(root: &OwnedCasRoot) -> Result<u64, CoordinatorError> {
    root.revalidate().map_err(CoordinatorError::Failed)?;
    fs2::available_space(root.install_root())
        .map_err(|error| CoordinatorError::Failed(format!("Не удалось проверить место: {error}")))
}

fn require_space(root: &OwnedCasRoot, required: u64) -> Result<u64, CoordinatorError> {
    let available = current_free_space(root)?;
    if available < required {
        return Err(CoordinatorError::DiskInsufficient {
            available,
            required,
        });
    }
    Ok(available)
}

fn download_object_identity(sha256: &str) -> String {
    DownloadObjectIdentity::from_sha256(sha256)
        .expect("sealed artifact SHA-256 is valid")
        .as_str()
        .to_owned()
}

#[derive(Default)]
struct DownloadTerminalError {
    failures: BTreeMap<(String, u8, String), CoordinatorError>,
    saw_cancelled: bool,
}

impl DownloadTerminalError {
    fn record(&mut self, object_identity: String, error: CoordinatorError) {
        match error {
            CoordinatorError::Cancelled => self.saw_cancelled = true,
            other => {
                let (class, detail) = match &other {
                    CoordinatorError::Auth(message) => (0, message.clone()),
                    CoordinatorError::SubscriptionRequired(message) => (1, message.clone()),
                    CoordinatorError::DevForbidden(message) => (2, message.clone()),
                    CoordinatorError::LauncherUpdateRequired(message) => (3, message.clone()),
                    CoordinatorError::DiskInsufficient {
                        available,
                        required,
                    } => (4, format!("{required:020}:{available:020}")),
                    CoordinatorError::Failed(message) => (5, message.clone()),
                    CoordinatorError::Cancelled => unreachable!("handled above"),
                };
                self.failures
                    .entry((object_identity, class, detail))
                    .or_insert(other);
            }
        }
    }

    fn into_error(mut self) -> Option<CoordinatorError> {
        self.failures
            .pop_first()
            .map(|(_, error)| error)
            .or_else(|| self.saw_cancelled.then_some(CoordinatorError::Cancelled))
    }

    fn is_empty(&self) -> bool {
        self.failures.is_empty() && !self.saw_cancelled
    }
}

async fn run_bounded_download_scheduler<I, Fut, T, E, Observe>(
    futures: I,
    concurrency: usize,
    mut observe: Observe,
) where
    I: IntoIterator<Item = Fut>,
    Fut: Future<Output = Result<T, E>>,
    Observe: FnMut(Result<T, E>) -> bool,
{
    assert!(concurrency > 0, "download concurrency must be non-zero");
    let mut queued = futures.into_iter();
    let mut active = FuturesUnordered::new();
    for _ in 0..concurrency {
        let Some(future) = queued.next() else {
            break;
        };
        active.push(future);
    }
    let mut admit_queued = true;
    while let Some(result) = active.next().await {
        if !observe(result) {
            admit_queued = false;
        }
        if admit_queued {
            if let Some(future) = queued.next() {
                active.push(future);
            }
        }
    }
}

struct DownloadExecutionRequest<'a> {
    root: &'a OwnedCasRoot,
    view: ArtifactExecutionViewV2<'a>,
    channel: BuildChannel,
    auth: &'a Arc<AuthSessionManager>,
    cancellation: &'a CoordinatorCancellation,
    observer: &'a ProgressObserver,
    phase: BuildPhase,
    total_bytes: u64,
    disk_required_bytes: u64,
}

async fn download_execution_view(
    request: DownloadExecutionRequest<'_>,
) -> Result<BTreeMap<String, VerifiedCasObject>, CoordinatorError> {
    let DownloadExecutionRequest {
        root,
        view,
        channel,
        auth,
        cancellation,
        observer,
        phase,
        total_bytes,
        disk_required_bytes,
    } = request;
    cancellation.check()?;
    let charges = view
        .items()
        .map(|item| {
            let key = download_object_identity(item.sha256());
            let charge = if item.availability()
                == super::availability::ArtifactAvailabilityStateV2::Complete
            {
                0
            } else {
                item.size()
            };
            (key, charge)
        })
        .collect::<BTreeMap<_, _>>();
    let progress: Arc<dyn DownloadObserver> = Arc::new(CoordinatorDownloadObserver::new(
        Arc::clone(observer),
        root,
        phase,
        total_bytes,
        disk_required_bytes,
        charges,
    ));
    let spark = CasDownloader::with_observer(
        root,
        SparkClient::new().map_err(CoordinatorError::Failed)?,
        Arc::clone(&progress),
    );
    let official =
        OfficialCasDownloader::with_observer(root, progress).map_err(CoordinatorError::Failed)?;
    let mut items = view.items().collect::<Vec<_>>();
    items.sort_by(|left, right| left.sha256().cmp(right.sha256()));
    let spark_fanout = cancellation.spark.clone();
    let official_fanout = cancellation.official.clone();
    let mut verified = BTreeMap::new();
    let mut terminal = DownloadTerminalError::default();
    // Admit deterministic, full-SHA-ordered waves. Every member starts before any result is
    // observed; the wave is fully drained, and no later token/future is constructed after error.
    for wave in items.chunks(DOWNLOAD_CONCURRENCY) {
        cancellation.check()?;
        let downloads = wave.iter().map(|item| {
            let spark = &spark;
            let official = &official;
            let spark_fanout = &spark_fanout;
            let official_fanout = &official_fanout;
            async move {
                let sha256 = item.sha256().to_owned();
                let result = match item.source() {
                    ArtifactExecutionSourceV2::SparkCas => {
                        let mut token_provider = CoordinatorSparkAccessTokenProvider {
                            auth: Arc::clone(auth),
                            cancellation,
                            transport: spark_fanout,
                        };
                        spark
                            .ensure_planned_spark_object_with_provider_and_cancellation(
                                item,
                                &mut token_provider,
                                spark_fanout,
                            )
                            .await
                            .map_err(|error| map_cas_error(error, channel))
                    }
                    ArtifactExecutionSourceV2::OfficialHttps { .. } => official
                        .ensure_planned_official_object(item, official_fanout)
                        .await
                        .map_err(|error| match error {
                            super::official_cas::OfficialCasError::Cancelled => {
                                CoordinatorError::Cancelled
                            }
                            other => CoordinatorError::Failed(other.to_string()),
                        }),
                };
                match result {
                    Ok(object) => Ok((sha256, object)),
                    Err(error) => Err((sha256, error)),
                }
            }
        });
        run_bounded_download_scheduler(downloads, wave.len(), |result| {
            match result {
                Ok((sha256, object)) if terminal.is_empty() => {
                    if verified.insert(sha256.clone(), object).is_some() {
                        terminal.record(
                            sha256,
                            CoordinatorError::Failed(
                                "План загрузки вернул повторяющийся CAS-объект".into(),
                            ),
                        );
                    }
                }
                Ok(_) => {}
                Err((sha256, error)) => {
                    terminal.record(sha256, error);
                }
            }
            terminal.is_empty()
        })
        .await;
        if !terminal.is_empty() {
            break;
        }
    }
    if let Some(error) = terminal.into_error() {
        return Err(error);
    }
    root.revalidate().map_err(CoordinatorError::Failed)?;
    Ok(verified)
}

async fn download_mutable_bootstrap(
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
    availability: &VerifiedAvailabilityV2,
    channel: BuildChannel,
    auth: &Arc<AuthSessionManager>,
    cancellation: &CoordinatorCancellation,
    observer: &ProgressObserver,
) -> Result<BTreeMap<String, VerifiedCasObject>, CoordinatorError> {
    let plan = plan_mutable_bootstrap(root, inventory, availability)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    let reserve = plan
        .validated_disk_download_reserve_bytes(root, inventory)
        .map_err(CoordinatorError::Failed)?;
    let required = required_phase_bytes(reserve).map_err(CoordinatorError::Failed)?;
    require_space(root, required)?;
    let repeated_reserve = plan
        .validated_disk_download_reserve_bytes(root, inventory)
        .map_err(CoordinatorError::Failed)?;
    if repeated_reserve != reserve {
        return Err(CoordinatorError::Failed(
            "Mutable bootstrap allocation changed across its disk admission boundary".into(),
        ));
    }
    let view = plan
        .execution_view(root, inventory)
        .map_err(CoordinatorError::Failed)?;
    download_execution_view(DownloadExecutionRequest {
        root,
        view,
        channel,
        auth,
        cancellation,
        observer,
        phase: BuildPhase::Downloading,
        total_bytes: plan.network_bytes(),
        disk_required_bytes: required,
    })
    .await
}

fn map_generation_error(error: super::game_generation::GameGenerationError) -> CoordinatorError {
    match error {
        super::game_generation::GameGenerationError::Cancelled => CoordinatorError::Cancelled,
        other => CoordinatorError::Failed(other.to_string()),
    }
}

fn channel_entitlement_error(channel: BuildChannel, message: String) -> CoordinatorError {
    match channel {
        BuildChannel::Stable => CoordinatorError::SubscriptionRequired(message),
        BuildChannel::Dev => CoordinatorError::DevForbidden(message),
    }
}

pub(super) fn map_tuf_refresh_error(
    error: TufRefreshError,
    channel: BuildChannel,
) -> CoordinatorError {
    match error {
        TufRefreshError::Authentication(message) => {
            CoordinatorError::Auth(TufRefreshError::Authentication(message).to_string())
        }
        TufRefreshError::Forbidden(code) => {
            let message = TufRefreshError::Forbidden(code.clone()).to_string();
            match code.as_str() {
                "spark_subscription_required" => CoordinatorError::SubscriptionRequired(message),
                "spark_dev_access_required" => CoordinatorError::DevForbidden(message),
                _ => channel_entitlement_error(channel, message),
            }
        }
        TufRefreshError::LauncherUpdateRequired(required) => {
            CoordinatorError::LauncherUpdateRequired(
                TufRefreshError::LauncherUpdateRequired(required).to_string(),
            )
        }
        TufRefreshError::Failed(message) => {
            CoordinatorError::Failed(TufRefreshError::Failed(message).to_string())
        }
    }
}

fn map_cas_error(error: super::cas::CasError, channel: BuildChannel) -> CoordinatorError {
    match error {
        super::cas::CasError::Cancelled => CoordinatorError::Cancelled,
        super::cas::CasError::Authentication => CoordinatorError::Auth(error.to_string()),
        super::cas::CasError::Forbidden => channel_entitlement_error(channel, error.to_string()),
        other => CoordinatorError::Failed(other.to_string()),
    }
}

fn map_processor_execution_error(error: ProcessorExecutionError) -> CoordinatorError {
    match error {
        ProcessorExecutionError::Cancelled => CoordinatorError::Cancelled,
        ProcessorExecutionError::Failed(message) => CoordinatorError::Failed(message),
    }
}

fn map_reconcile_executor_error(error: ReconcileExecutorErrorV2) -> CoordinatorError {
    match error {
        ReconcileExecutorErrorV2::Cancelled => CoordinatorError::Cancelled,
        ReconcileExecutorErrorV2::InsufficientSpace {
            required_bytes,
            available_bytes,
        } => CoordinatorError::DiskInsufficient {
            available: available_bytes,
            required: required_bytes,
        },
        other => CoordinatorError::Failed(other.to_string()),
    }
}

fn map_staging_writer_error(error: ReconcileExecutorErrorV2) -> CoordinatorError {
    map_reconcile_executor_error(error)
}

fn append_instance_path(
    channel: BuildChannel,
    manifest_path: &str,
) -> Result<RelativeManagedPath, CoordinatorError> {
    let mut relative = RelativeManagedPath::new(&format!("instances/{}", channel.as_str()))
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    for component in manifest_path.split('/') {
        relative = relative
            .join_component(component)
            .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    }
    Ok(relative)
}

fn read_local_mutable(
    root: &OwnedCasRoot,
    channel: BuildChannel,
    path: &str,
    maximum: usize,
) -> Result<Option<Vec<u8>>, CoordinatorError> {
    let relative = append_instance_path(channel, path)?;
    let mut file = match ImmutableManagedFile::open(root.install_root(), &relative) {
        Ok(file) => file,
        Err(super::managed_fs::ManagedFsError::Io { source, .. })
            if source.kind() == ErrorKind::NotFound =>
        {
            return Ok(None)
        }
        Err(error) => {
            return Err(CoordinatorError::Failed(format!(
                "Cannot lease mutable file {path}: {error}"
            )))
        }
    };
    let bytes = file.read_bounded(maximum as u64).map_err(|error| {
        CoordinatorError::Failed(format!("Cannot read mutable file {path}: {error}"))
    })?;
    file.revalidate().map_err(|error| {
        CoordinatorError::Failed(format!("Mutable file {path} changed while read: {error}"))
    })?;
    Ok(Some(bytes))
}

fn mutable_candidate(audit: &InstanceAudit, path: &str) -> bool {
    audit
        .validated_mutable_candidates
        .binary_search_by(|candidate| candidate.as_str().cmp(path))
        .is_ok()
}

fn reset_mutable_policy_state(
    state: &mut super::mutable::MutableSettingsState,
    policy: &super::contracts::MutableSettingsFile,
) {
    for field in &policy.fields {
        state.profile.remove(&field.setting_id);
        for preset in state.presets.values_mut() {
            preset.remove(&field.setting_id);
        }
    }
}

struct MutableProofRequest<'a> {
    root: &'a OwnedCasRoot,
    inventory: &'a ArtifactInventoryV2,
    trusted: &'a TrustedRelease,
    channel: BuildChannel,
    target_preset: PresetId,
    installed: Option<&'a ActiveInstanceV2>,
    audit: &'a InstanceAudit,
    defaults: &'a BTreeMap<String, VerifiedCasObject>,
    capture_local: bool,
}

fn prepare_mutable_proofs(
    request: MutableProofRequest<'_>,
) -> Result<
    (
        Vec<MutableMaterializationProofV2>,
        BTreeMap<String, super::mutable::MutableSettingsState>,
    ),
    CoordinatorError,
> {
    let MutableProofRequest {
        root,
        inventory,
        trusted,
        channel,
        target_preset,
        installed,
        audit,
        defaults,
        capture_local,
    } = request;
    let store = SettingsStore::new(root.install_root(), inventory.install_id());
    let mut proofs = Vec::new();
    let mut states = BTreeMap::new();
    for policy in &trusted.manifest().integrity.mutable_settings {
        let sha256 = inventory
            .mutable_default_sha256(&policy.path)
            .map_err(CoordinatorError::Failed)?;
        let object = defaults.get(sha256).ok_or_else(|| {
            CoordinatorError::Failed(format!(
                "Mutable bootstrap did not return signed default for {}",
                policy.path
            ))
        })?;
        let mut default = object.open(root).map_err(|error| {
            CoordinatorError::Failed(format!("Cannot lease mutable default: {error}"))
        })?;
        let signed_default = default.read_bounded(object.size()).map_err(|error| {
            CoordinatorError::Failed(format!(
                "Cannot read mutable default {}: {error}",
                policy.path
            ))
        })?;
        let local = if mutable_candidate(audit, &policy.path) {
            read_local_mutable(root, channel, &policy.path, policy.max_bytes)?
        } else {
            None
        };

        let loaded = store
            .load(channel, policy)
            .map_err(CoordinatorError::Failed)?;
        let mut state = loaded.state.clone();
        if capture_local {
            if let (Some(installed), Some(local)) = (installed, local.as_deref()) {
                if capture_minecraft_options_state(
                    local,
                    policy,
                    installed.preset.as_str(),
                    &mut state,
                )
                .is_err()
                {
                    state = loaded.state.clone();
                }
            }
        }
        let canonical = match materialize_minecraft_options_state(
            &signed_default,
            policy,
            target_preset.as_str(),
            &mut state,
        ) {
            Ok(bytes) => bytes,
            Err(_) => {
                reset_mutable_policy_state(&mut state, policy);
                materialize_minecraft_options_state(
                    &signed_default,
                    policy,
                    target_preset.as_str(),
                    &mut state,
                )
                .map_err(CoordinatorError::Failed)?
            }
        };
        if capture_local && state != loaded.state {
            let persisted = state.clone();
            store
                .update(channel, policy, move |current| {
                    *current = persisted;
                    Ok(())
                })
                .map_err(CoordinatorError::Failed)?;
        }
        let sha256 = format!("{:x}", Sha256::digest(&canonical));
        proofs.push(MutableMaterializationProofV2 {
            path: policy.path.clone(),
            size: canonical.len() as u64,
            sha256,
            current_matches: local.as_deref() == Some(canonical.as_slice()),
        });
        states.insert(policy.path.clone(), state);
        default.revalidate().map_err(|error| {
            CoordinatorError::Failed(format!(
                "Mutable default changed while materialized: {error}"
            ))
        })?;
    }
    proofs.sort_by_key(|proof| proof.path.to_lowercase());
    root.revalidate().map_err(CoordinatorError::Failed)?;
    Ok((proofs, states))
}

/// Rebuilds mutable recovery authority only from the freshly trusted inventory and already
/// verified CAS objects. Recovery deliberately performs no network I/O while a journal pointer
/// is durable. Missing defaults therefore produce no proofs, which the staging recovery API
/// converts into rollback-only authority rather than accepting plan-derived hashes.
fn cached_mutable_defaults(
    root: &OwnedCasRoot,
    inventory: &ArtifactInventoryV2,
    availability: &VerifiedAvailabilityV2,
) -> Result<Option<BTreeMap<String, VerifiedCasObject>>, CoordinatorError> {
    let bootstrap = plan_mutable_bootstrap(root, inventory, availability)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    let view = bootstrap
        .execution_view(root, inventory)
        .map_err(CoordinatorError::Failed)?;
    if view.items().any(|item| {
        item.availability() != super::availability::ArtifactAvailabilityStateV2::Complete
    }) {
        return Ok(None);
    }
    let mut defaults = BTreeMap::new();
    for item in view.items() {
        let object = verify_planned_object(root, &item)
            .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
        defaults.insert(item.sha256().to_owned(), object);
    }
    root.revalidate().map_err(CoordinatorError::Failed)?;
    Ok(Some(defaults))
}

async fn refresh_trusted_release(
    config: &CoordinatorConfig,
    channel: BuildChannel,
    auth: &Arc<AuthSessionManager>,
) -> Result<TrustedRelease, CoordinatorError> {
    let embedded_root = config.anchors.for_channel(channel)?;
    let token = access_token(auth).await?;
    refresh_trusted_release_transaction(
        config.tuf_state_root.clone(),
        embedded_root,
        channel,
        Arc::clone(auth),
        token,
    )
    .await
}

async fn refresh_trusted_release_with_cancellation(
    config: &CoordinatorConfig,
    channel: BuildChannel,
    auth: &Arc<AuthSessionManager>,
    cancellation: &CoordinatorCancellation,
) -> Result<TrustedRelease, CoordinatorError> {
    let embedded_root = config.anchors.for_channel(channel)?;
    let token = access_token_with_completion_safe_cancellation(auth, cancellation).await?;
    finish_tuf_refresh_before_cancellation(
        channel,
        cancellation,
        refresh_trusted_release_transaction(
            config.tuf_state_root.clone(),
            embedded_root,
            channel,
            Arc::clone(auth),
            token,
        ),
    )
    .await
}

/// The inspection/status and mutating operation callers deliberately share this exact
/// transaction. A TUF 401 rotates the exact rejected capability once, persists that rotation
/// completion-safely, and retries once; a second 401 and every non-auth failure are terminal.
async fn refresh_trusted_release_transaction(
    tuf_state_root: PathBuf,
    embedded_root: Arc<[u8]>,
    channel: BuildChannel,
    auth: Arc<AuthSessionManager>,
    token: NativeAccessToken,
) -> Result<TrustedRelease, CoordinatorError> {
    let client = SparkTufClient::new(tuf_state_root);
    refresh_tuf_with_single_auth_retry(
        channel,
        token,
        move |token| {
            let client = client.clone();
            let embedded_root = Arc::clone(&embedded_root);
            async move {
                let result = client
                    .refresh(channel, token.expose(), embedded_root.as_ref())
                    .await;
                (token, result)
            }
        },
        move |rejected| async move {
            auth.native_access_token_after_rejection_completion_safe(rejected)
                .await
        },
    )
    .await
}

fn map_tuf_refresh_task_result(
    result: Result<Result<TrustedRelease, CoordinatorError>, tokio::task::JoinError>,
) -> Result<TrustedRelease, CoordinatorError> {
    match result {
        Ok(result) => result,
        // A panic payload can contain arbitrary third-party text. Keep the native failure
        // deliberately generic so neither a bearer token nor repository response can escape.
        Err(_) => Err(CoordinatorError::Failed(
            "TUF refresh worker terminated before completion".into(),
        )),
    }
}

/// Once a refresh owns its staging generation, caller cancellation may stop waiting but must not
/// drop the transaction. The operation worker owns a current-thread Tokio runtime, so returning
/// early would destroy that runtime and abort a merely detached task. Cancellation therefore
/// changes only the eventual successful result: the worker still waits for durable commit or
/// bounded cleanup, and every real authentication/TUF failure keeps precedence.
async fn finish_tuf_refresh_before_cancellation<F>(
    _channel: BuildChannel,
    cancellation: &CoordinatorCancellation,
    refresh: F,
) -> Result<TrustedRelease, CoordinatorError>
where
    F: Future<Output = Result<TrustedRelease, CoordinatorError>> + Send + 'static,
{
    wait_for_tuf_refresh_task_or_cancellation(cancellation, tokio::spawn(refresh)).await
}

async fn wait_for_tuf_refresh_task_or_cancellation(
    cancellation: &CoordinatorCancellation,
    mut task: tokio::task::JoinHandle<Result<TrustedRelease, CoordinatorError>>,
) -> Result<TrustedRelease, CoordinatorError> {
    tokio::select! {
        biased;
        result = &mut task => {
            match map_tuf_refresh_task_result(result) {
                Ok(_) if cancellation.cancelled.load(Ordering::Acquire) => {
                    Err(CoordinatorError::Cancelled)
                }
                result => result,
            }
        },
        _ = wait_for_cancellation(cancellation.flag()) => {
            match map_tuf_refresh_task_result(task.await) {
                Ok(_) => Err(CoordinatorError::Cancelled),
                Err(error) => Err(error),
            }
        },
    }
}

async fn refresh_tuf_with_single_auth_retry<R, RFut, Rotate, RotateFut>(
    channel: BuildChannel,
    initial_token: NativeAccessToken,
    mut refresh: R,
    rotate: Rotate,
) -> Result<TrustedRelease, CoordinatorError>
where
    R: FnMut(NativeAccessToken) -> RFut + Send,
    RFut: Future<Output = (NativeAccessToken, Result<TrustedRelease, TufRefreshError>)> + Send,
    Rotate: FnOnce(NativeAccessToken) -> RotateFut + Send,
    RotateFut: Future<Output = Result<NativeAccessToken, crate::auth::AuthError>> + Send,
{
    let (rejected, first) = refresh(initial_token).await;
    match first {
        Err(TufRefreshError::Authentication(_)) => {
            // The exact rejected capability enters the session manager's forced single-flight
            // rotation. Rotation and persistence are completion-safe and happen at most once.
            let rotated = rotate(rejected).await.map_err(map_access_token_error)?;
            let (_, second) = refresh(rotated).await;
            second.map_err(|error| map_tuf_refresh_error(error, channel))
        }
        result => result.map_err(|error| map_tuf_refresh_error(error, channel)),
    }
}

fn snapshot_from_plan(
    planned: &PlannedBuildV2,
    installed: Option<&ActiveInstanceV2>,
    trusted: &TrustedRelease,
    free: u64,
) -> CoordinatorSnapshot {
    let message = match planned.state {
        PlannedBuildState::Download => "The build is not installed",
        PlannedBuildState::Update => "An update is available",
        PlannedBuildState::Repair => "The build needs repair",
        PlannedBuildState::Ready => "The build is ready",
    };
    CoordinatorSnapshot {
        state: planned.state,
        installed_release_id: installed.map(|value| value.release_id.clone()),
        available_release_id: trusted.manifest().release.id.clone(),
        disk_free_bytes: free,
        disk_required_bytes: planned.disk_budget_record.required_bytes,
        message: message.into(),
    }
}

struct PreparePlanRequest<'a> {
    authority: &'a OperationAuthority,
    config: &'a CoordinatorConfig,
    operation_id: Uuid,
    channel: BuildChannel,
    preset: PresetId,
    auth: &'a Arc<AuthSessionManager>,
    cancellation: &'a CoordinatorCancellation,
    observer: &'a ProgressObserver,
    capture_local: bool,
}

async fn prepare_plan(
    request: PreparePlanRequest<'_>,
) -> Result<PreparedCoordinatorPlan, CoordinatorError> {
    let PreparePlanRequest {
        authority,
        config,
        operation_id,
        channel,
        preset,
        auth,
        cancellation,
        observer,
        capture_local,
    } = request;
    cancellation.check()?;
    observer(CoordinatorProgress::checking(
        "Refreshing signed Spark2 metadata",
    ));
    let trusted =
        refresh_trusted_release_with_cancellation(config, channel, auth, cancellation).await?;
    cancellation.check()?;
    let inventory = ArtifactInventoryV2::build(
        &authority.root,
        &trusted,
        authority.install_id,
        operation_id,
        channel,
        preset,
    )
    .map_err(CoordinatorError::Failed)?;
    let initial_availability = VerifiedAvailabilityV2::scan(&authority.root, &inventory)
        .map_err(CoordinatorError::Failed)?;
    let defaults = download_mutable_bootstrap(
        &authority.root,
        &inventory,
        &initial_availability,
        channel,
        auth,
        cancellation,
        observer,
    )
    .await?;
    cancellation.check()?;
    let availability = VerifiedAvailabilityV2::scan(&authority.root, &inventory)
        .map_err(CoordinatorError::Failed)?;
    let state_store = InstanceStateStore::new(&authority.install_root, authority.install_id);
    let installed = state_store.load(channel).map_err(|error| {
        CoordinatorError::Failed(format!("Cannot read active instance marker: {error}"))
    })?;
    let audit =
        audit_release_instance(&authority.install_root, channel, trusted.manifest(), preset)
            .map_err(CoordinatorError::Failed)?;
    let (mutable_proofs, mutable_states) = prepare_mutable_proofs(MutableProofRequest {
        root: &authority.root,
        inventory: &inventory,
        trusted: &trusted,
        channel,
        target_preset: preset,
        installed: installed.as_ref(),
        audit: &audit,
        defaults: &defaults,
        capture_local,
    })?;
    let planned = plan_build(PlannerRequestV2 {
        install_id: authority.install_id,
        channel,
        preset,
        operation_id,
        trusted_release: &trusted,
        artifact_inventory: &inventory,
        cas_root: &authority.root,
        installed: installed.as_ref(),
        audit: &audit,
        mutable_files: &mutable_proofs,
        availability: &availability,
    })
    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    Ok(PreparedCoordinatorPlan {
        trusted,
        inventory,
        availability,
        installed,
        audit,
        mutable_defaults: defaults,
        mutable_proofs,
        mutable_states,
        planned,
    })
}

fn conservative_state(
    installed: Option<&ActiveInstanceV2>,
    trusted: &TrustedRelease,
    preset: PresetId,
) -> PlannedBuildState {
    match installed {
        None => PlannedBuildState::Download,
        Some(active)
            if active.release_id != trusted.manifest().release.id
                || active.preset != preset
                || active.release_manifest_sha256 != trusted.evidence().release_manifest.sha256
                || active.runtime_lock_sha256 != trusted.evidence().java_runtime_lock.sha256
                || active.game_runtime_lock_sha256
                    != trusted.evidence().game_runtime_lock.sha256 =>
        {
            PlannedBuildState::Update
        }
        Some(_) => PlannedBuildState::Repair,
    }
}

async fn prepare_inspection_plan(
    authority: &OperationAuthority,
    config: &CoordinatorConfig,
    operation_id: Uuid,
    channel: BuildChannel,
    preset: PresetId,
    auth: &Arc<AuthSessionManager>,
    observer: &ProgressObserver,
) -> Result<Result<PreparedCoordinatorPlan, CoordinatorSnapshot>, CoordinatorError> {
    observer(CoordinatorProgress::checking(
        "Refreshing signed Spark2 metadata",
    ));
    let trusted = refresh_trusted_release(config, channel, auth).await?;
    let inventory = ArtifactInventoryV2::build(
        &authority.root,
        &trusted,
        authority.install_id,
        operation_id,
        channel,
        preset,
    )
    .map_err(CoordinatorError::Failed)?;
    let availability = VerifiedAvailabilityV2::scan(&authority.root, &inventory)
        .map_err(CoordinatorError::Failed)?;
    let state_store = InstanceStateStore::new(&authority.install_root, authority.install_id);
    let installed = state_store
        .load(channel)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    let bootstrap = plan_mutable_bootstrap(&authority.root, &inventory, &availability)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    let mut defaults = BTreeMap::new();
    for item in bootstrap
        .execution_view(&authority.root, &inventory)
        .map_err(CoordinatorError::Failed)?
        .items()
    {
        if item.availability() != super::availability::ArtifactAvailabilityStateV2::Complete {
            let state = conservative_state(installed.as_ref(), &trusted, preset);
            return Ok(Err(CoordinatorSnapshot {
                state,
                installed_release_id: installed.as_ref().map(|value| value.release_id.clone()),
                available_release_id: trusted.manifest().release.id.clone(),
                disk_free_bytes: current_free_space(&authority.root)?,
                disk_required_bytes: required_phase_bytes(
                    bootstrap
                        .validated_disk_download_reserve_bytes(&authority.root, &inventory)
                        .map_err(CoordinatorError::Failed)?,
                )
                .map_err(CoordinatorError::Failed)?,
                message: "Signed settings defaults must be downloaded before an exact inspection"
                    .into(),
            }));
        }
        let object = verify_planned_object(&authority.root, &item)
            .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
        defaults.insert(item.sha256().to_owned(), object);
    }
    let audit =
        audit_release_instance(&authority.install_root, channel, trusted.manifest(), preset)
            .map_err(CoordinatorError::Failed)?;
    let (mutable_proofs, mutable_states) = prepare_mutable_proofs(MutableProofRequest {
        root: &authority.root,
        inventory: &inventory,
        trusted: &trusted,
        channel,
        target_preset: preset,
        installed: installed.as_ref(),
        audit: &audit,
        defaults: &defaults,
        capture_local: false,
    })?;
    let planned = plan_build(PlannerRequestV2 {
        install_id: authority.install_id,
        channel,
        preset,
        operation_id,
        trusted_release: &trusted,
        artifact_inventory: &inventory,
        cas_root: &authority.root,
        installed: installed.as_ref(),
        audit: &audit,
        mutable_files: &mutable_proofs,
        availability: &availability,
    })
    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    Ok(Ok(PreparedCoordinatorPlan {
        trusted,
        inventory,
        availability,
        installed,
        audit,
        mutable_defaults: defaults,
        mutable_proofs,
        mutable_states,
        planned,
    }))
}

struct PreparedCoordinatorPlan {
    trusted: TrustedRelease,
    inventory: ArtifactInventoryV2,
    availability: VerifiedAvailabilityV2,
    installed: Option<ActiveInstanceV2>,
    audit: InstanceAudit,
    mutable_defaults: BTreeMap<String, VerifiedCasObject>,
    mutable_proofs: Vec<MutableMaterializationProofV2>,
    mutable_states: BTreeMap<String, super::mutable::MutableSettingsState>,
    planned: PlannedBuildV2,
}

fn replan_verified_boundary(
    authority: &OperationAuthority,
    prepared: &PreparedCoordinatorPlan,
    operation_id: Uuid,
    channel: BuildChannel,
    preset: PresetId,
) -> Result<PlannedBuildV2, CoordinatorError> {
    let availability = VerifiedAvailabilityV2::scan(&authority.root, &prepared.inventory)
        .map_err(CoordinatorError::Failed)?;
    let installed = InstanceStateStore::new(&authority.install_root, authority.install_id)
        .load(channel)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    if installed != prepared.installed {
        return Err(CoordinatorError::Failed(
            "Active instance changed across a coordinator phase boundary".into(),
        ));
    }
    let audit = audit_release_instance(
        &authority.install_root,
        channel,
        prepared.trusted.manifest(),
        preset,
    )
    .map_err(CoordinatorError::Failed)?;
    let (mutable, _) = prepare_mutable_proofs(MutableProofRequest {
        root: &authority.root,
        inventory: &prepared.inventory,
        trusted: &prepared.trusted,
        channel,
        target_preset: preset,
        installed: installed.as_ref(),
        audit: &audit,
        defaults: &prepared.mutable_defaults,
        capture_local: false,
    })?;
    plan_build(PlannerRequestV2 {
        install_id: authority.install_id,
        channel,
        preset,
        operation_id,
        trusted_release: &prepared.trusted,
        artifact_inventory: &prepared.inventory,
        cas_root: &authority.root,
        installed: installed.as_ref(),
        audit: &audit,
        mutable_files: &mutable,
        availability: &availability,
    })
    .map_err(|error| CoordinatorError::Failed(error.to_string()))
}

pub(super) async fn inspect_operation(
    config: &CoordinatorConfig,
    install_directory: &Path,
    install_id: Uuid,
    channel: BuildChannel,
    preset: PresetId,
    auth: &Arc<AuthSessionManager>,
    observer: &ProgressObserver,
) -> Result<CoordinatorSnapshot, CoordinatorError> {
    let authority = validate_operation_root(install_directory, install_id)?;
    let install_lock = CoordinatorOperationLock::acquire(&authority.root)?;
    let state_store = InstanceStateStore::new(&authority.install_root, install_id);
    let channel_lock = state_store
        .acquire_operation_lock(channel)
        .map_err(|error| {
            CoordinatorError::Failed(format!("Cannot lock instance for inspection: {error}"))
        })?;
    let pending = detect_pending(&authority.install_root, install_id, channel, &channel_lock)
        .map_err(CoordinatorError::Failed)?;
    let installed = state_store
        .load_locked(&channel_lock)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    drop(channel_lock);
    if let Some(pending) = pending {
        let trusted = refresh_trusted_release(config, channel, auth).await?;
        let current = pending
            .plan
            .target
            .trusted_release
            .targets_match(trusted.evidence())
            && pending
                .plan
                .target
                .trusted_release
                .roles_are_monotonic_to(trusted.evidence())
            && pending.plan.target.release_id == trusted.manifest().release.id;
        return Ok(CoordinatorSnapshot {
            state: if current {
                PlannedBuildState::Repair
            } else {
                PlannedBuildState::Update
            },
            installed_release_id: installed.map(|value| value.release_id),
            available_release_id: trusted.manifest().release.id.clone(),
            disk_free_bytes: current_free_space(&authority.root)?,
            // A deserialized pending budget is not execution authority. Exact recovery space is
            // recomputed only after fresh trust/audit, so inspection reports it as unknown.
            disk_required_bytes: 0,
            message: if current {
                "An interrupted operation must be recovered".into()
            } else {
                "An interrupted old operation will be replaced by the current release".into()
            },
        });
    }
    let prepared = match prepare_inspection_plan(
        &authority,
        config,
        Uuid::new_v4(),
        channel,
        preset,
        auth,
        observer,
    )
    .await?
    {
        Ok(prepared) => prepared,
        Err(snapshot) => return Ok(snapshot),
    };
    install_lock.revalidate(&authority.root)?;
    let free = current_free_space(&authority.root)?;
    Ok(snapshot_from_plan(
        &prepared.planned,
        prepared.installed.as_ref(),
        &prepared.trusted,
        free,
    ))
}

fn require_fresh_budget(
    root: &OwnedCasRoot,
    planned: &PlannedBuildV2,
    inventory: &ArtifactInventoryV2,
) -> Result<u64, CoordinatorError> {
    let plan = planned
        .plan
        .as_ref()
        .ok_or_else(|| CoordinatorError::Failed("Ready plan has no disk authority".into()))?;
    let authority = planned.disk_budget_authority.as_ref().ok_or_else(|| {
        CoordinatorError::Failed("Non-ready plan has no canonical disk authority".into())
    })?;
    let assessment = authority
        .assess_space_for(plan, inventory, root)
        .map_err(CoordinatorError::Failed)?;
    if !assessment.fits() {
        return Err(CoordinatorError::DiskInsufficient {
            available: assessment.available_bytes(),
            required: assessment.required_bytes(),
        });
    }
    Ok(assessment.available_bytes())
}

struct StalePendingRecovery {
    pending: PendingJournalV2,
    untrusted_pending_identity: Option<UntrustedPendingIdentityV2>,
    observed_active: Option<ActiveInstanceV2>,
    current_failed_audit: Option<ReconcilePlanAuditV2>,
    current_failed_mutable: Vec<MutableMaterializationProofV2>,
}

fn transition_matches_recovery(
    stale: &StalePendingRecovery,
    transition: Option<&PendingJournalTransitionV2>,
) -> bool {
    transition
        .is_some_and(|actual| actual.pending == stale.pending && actual.durable_successor.is_none())
}

fn recovery_continuation_preset(
    trusted: &TrustedRelease,
    pending: &PendingJournalV2,
) -> Result<PresetId, CoordinatorError> {
    for candidate in [
        pending.plan.target.preset,
        PresetId::Medium,
        PresetId::Low,
        PresetId::High,
    ] {
        if trusted.manifest().selected_preset(candidate).is_ok() {
            return Ok(candidate);
        }
    }
    Err(CoordinatorError::Failed(
        "Fresh signed release exposes no preset for pending recovery".into(),
    ))
}

fn classify_stale_pending_identity(
    pending: &PendingJournalV2,
    trusted: &TrustedRelease,
) -> Result<UntrustedPendingIdentityV2, CoordinatorError> {
    classify_untrusted_pending_identity_v2(pending, trusted)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))
}

fn settle_pending_operation(
    authority: &OperationAuthority,
    channel: BuildChannel,
    trusted: &TrustedRelease,
    state_store: &InstanceStateStore,
    operation_lock: &InstanceOperationLock,
) -> Result<Option<StalePendingRecovery>, CoordinatorError> {
    for _ in 0..4 {
        let Some(pending) = detect_pending(
            &authority.install_root,
            authority.install_id,
            channel,
            operation_lock,
        )
        .map_err(CoordinatorError::Failed)?
        else {
            return Ok(None);
        };
        let active = state_store.load_locked(operation_lock).map_err(|error| {
            CoordinatorError::Failed(format!(
                "Cannot read active marker during recovery: {error}"
            ))
        })?;
        // This pure, sealed classification is deliberately first: a local pending target may
        // never be bypassed by comparing fresh roles only with an older (or absent) active marker.
        // No inventory, path, download or staging authority is constructed before it succeeds.
        let classified_pending_identity = classify_stale_pending_identity(&pending, trusted)?;
        let target_still_current = pending
            .plan
            .target
            .trusted_release
            .targets_match(trusted.evidence())
            && pending
                .plan
                .target
                .trusted_release
                .roles_are_monotonic_to(trusted.evidence())
            && pending.plan.target.release_id == trusted.manifest().release.id
            && trusted
                .manifest()
                .selected_preset(pending.plan.target.preset)
                .is_ok();
        if !target_still_current {
            // The stale local plan is classification data only. No path, desired-file set,
            // artifact inventory, audit or mutation authority is reconstructed from it.
            return Ok(Some(StalePendingRecovery {
                pending,
                untrusted_pending_identity: Some(classified_pending_identity),
                observed_active: active,
                current_failed_audit: None,
                current_failed_mutable: Vec::new(),
            }));
        }
        let fresh_inventory = ArtifactInventoryV2::build(
            &authority.root,
            trusted,
            authority.install_id,
            pending.plan.operation_id,
            channel,
            pending.plan.target.preset,
        )
        .map_err(CoordinatorError::Failed)?;
        let fresh_availability = VerifiedAvailabilityV2::scan(&authority.root, &fresh_inventory)
            .map_err(CoordinatorError::Failed)?;
        let install_paths = pending
            .plan
            .mutations
            .iter()
            .filter_map(|mutation| match mutation {
                JournalMutation::InstallFile {
                    destination_path, ..
                } => Some(destination_path.clone()),
                _ => None,
            });
        let fresh_artifact_plan =
            ArtifactPlanV2::for_reconcile(&fresh_inventory, &fresh_availability, install_paths)
                .map_err(CoordinatorError::Failed)?;
        // A local plan which cannot be rebound to fresh TUF remains classification data only.
        // `None` makes staging recovery return a non-mutating FreshSupersedeRequired identity.
        let fresh_plan_audit =
            audit_current_reconcile_plan_instance(&authority.install_root, &pending.plan, trusted)
                .ok();
        let native_audit = audit_release_instance(
            &authority.install_root,
            channel,
            trusted.manifest(),
            pending.plan.target.preset,
        )
        .map_err(CoordinatorError::Failed)?;
        let final_mutable = match cached_mutable_defaults(
            &authority.root,
            &fresh_inventory,
            &fresh_availability,
        )? {
            Some(defaults) => {
                prepare_mutable_proofs(MutableProofRequest {
                    root: &authority.root,
                    inventory: &fresh_inventory,
                    trusted,
                    channel,
                    target_preset: pending.plan.target.preset,
                    installed: active.as_ref(),
                    audit: &native_audit,
                    defaults: &defaults,
                    capture_local: false,
                })?
                .0
            }
            None => Vec::new(),
        };
        let recovery = recover_pending_reconcile_staging_v2(PendingReconcileRecoveryRequestV2 {
            pending: &pending,
            fresh_release: trusted,
            fresh_inventory: &fresh_inventory,
            fresh_artifact_plan: &fresh_artifact_plan,
            fresh_plan_audit: fresh_plan_audit.as_ref(),
            mutable_proofs: &final_mutable,
            operation_lock,
            cas_root: &authority.root,
        })
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
        let staging = match &recovery {
            PendingReconcileStagingV2::RollForward {
                authority: staging_authority,
                staged,
            } => staged
                .proofs_for(staging_authority, operation_lock, &authority.root)
                .map_err(|error| CoordinatorError::Failed(error.to_string()))?
                .to_vec(),
            PendingReconcileStagingV2::CurrentIncomplete(_)
            | PendingReconcileStagingV2::FreshSupersedeRequired(_)
            | PendingReconcileStagingV2::Historical(_) => Vec::new(),
        };
        let recovery_identity = match &recovery {
            PendingReconcileStagingV2::FreshSupersedeRequired(identity)
            | PendingReconcileStagingV2::Historical(identity) => Some(identity.clone()),
            PendingReconcileStagingV2::RollForward { .. }
            | PendingReconcileStagingV2::CurrentIncomplete(_) => None,
        };
        let final_audit = if active.as_ref() == Some(&pending.plan.target) && target_still_current {
            fresh_plan_audit
        } else {
            None
        };
        if matches!(
            &recovery,
            PendingReconcileStagingV2::FreshSupersedeRequired(_)
                | PendingReconcileStagingV2::Historical(_)
        ) {
            return Ok(Some(StalePendingRecovery {
                pending,
                untrusted_pending_identity: recovery_identity,
                observed_active: active,
                current_failed_audit: final_audit,
                current_failed_mutable: final_mutable,
            }));
        }
        let decision = decide_recovery(RecoveryRequestV2 {
            plan: &pending.plan,
            active_marker: active.as_ref(),
            fresh_release: trusted,
            staging_files: &staging,
            final_audit: final_audit.as_ref(),
            final_mutable_files: if final_audit.is_some() {
                &final_mutable
            } else {
                &[]
            },
        });
        match (decision, recovery) {
            (
                RecoveryDecisionV2::RollForward,
                PendingReconcileStagingV2::RollForward {
                    authority: staging_authority,
                    staged,
                },
            ) => {
                roll_forward_staged_v2(
                    &staging_authority,
                    operation_lock,
                    &authority.root,
                    *staged,
                )
                .map_err(map_reconcile_executor_error)?;
                state_store
                    .save_locked(operation_lock, &pending.plan.target)
                    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
            }
            (RecoveryDecisionV2::FinalizeCommittedTarget(authorization), _) => {
                complete_pending_committed(
                    &authority.install_root,
                    authority.install_id,
                    channel,
                    operation_lock,
                    &pending.pointer,
                    authorization,
                )
                .map_err(CoordinatorError::Failed)?;
            }
            (RecoveryDecisionV2::PrepareCurrentPlan, _) => {
                return Ok(Some(StalePendingRecovery {
                    pending,
                    untrusted_pending_identity: final_audit
                        .is_none()
                        .then_some(classified_pending_identity),
                    observed_active: active,
                    current_failed_audit: final_audit,
                    current_failed_mutable: final_mutable,
                }));
            }
            (
                RecoveryDecisionV2::RollbackRequired(_),
                PendingReconcileStagingV2::CurrentIncomplete(rollback_authority),
            ) => {
                let rollback = rollback_pending_reconcile_v2(
                    &rollback_authority,
                    operation_lock,
                    &authority.root,
                )
                .map_err(map_reconcile_executor_error)?;
                let current = state_store.load_locked(operation_lock).map_err(|error| {
                    CoordinatorError::Failed(format!("Cannot verify rollback marker: {error}"))
                })?;
                if current != pending.plan.base {
                    return Err(CoordinatorError::Failed(
                        "Rollback completed on disk but active marker is not the plan base".into(),
                    ));
                }
                complete_pending_rolled_back(
                    &authority.install_root,
                    authority.install_id,
                    channel,
                    operation_lock,
                    &pending.pointer,
                    rollback.into_completion(),
                )
                .map_err(CoordinatorError::Failed)?;
            }
            (
                RecoveryDecisionV2::RollbackRequired(_),
                PendingReconcileStagingV2::FreshSupersedeRequired(_)
                | PendingReconcileStagingV2::Historical(_),
            ) => {
                return Ok(Some(StalePendingRecovery {
                    pending,
                    untrusted_pending_identity: recovery_identity
                        .or(Some(classified_pending_identity)),
                    observed_active: active,
                    current_failed_audit: final_audit,
                    current_failed_mutable: final_mutable,
                }));
            }
            (RecoveryDecisionV2::SupersedeForRepair(_), _) => {
                return Ok(Some(StalePendingRecovery {
                    pending,
                    untrusted_pending_identity: final_audit
                        .is_none()
                        .then_some(classified_pending_identity),
                    observed_active: active,
                    current_failed_audit: final_audit,
                    current_failed_mutable: final_mutable,
                }));
            }
            (RecoveryDecisionV2::RecoveryRequired(reason), _) => {
                return Err(CoordinatorError::Failed(format!(
                    "Pending operation requires launcher recovery: {reason:?}"
                )))
            }
            _ => {
                return Err(CoordinatorError::Failed(
                    "Recovery planner and sealed staging authority disagree".into(),
                ))
            }
        }
    }
    Err(CoordinatorError::Failed(
        "Pending reconcile operation did not converge after bounded recovery".into(),
    ))
}

fn reconcile_sources<'a>(
    operation: &OperationAuthority,
    staging_authority: &TrustedReconcileStagingAuthorityV2<'_, '_>,
    inventory: &ArtifactInventoryV2,
    plan: &ReconcilePlanV2,
    operation_lock: &InstanceOperationLock,
    objects: &'a BTreeMap<String, VerifiedCasObject>,
    mutable_states: &mut BTreeMap<String, super::mutable::MutableSettingsState>,
) -> Result<Vec<ReconcileStagingSourceV2<'a>>, CoordinatorError> {
    let mut sources = Vec::new();
    for mutation in &plan.mutations {
        let JournalMutation::InstallFile {
            destination_path,
            staging_slot,
            ..
        } = mutation
        else {
            continue;
        };
        let desired = plan
            .desired_files
            .iter()
            .find(|file| file.path == *destination_path)
            .ok_or_else(|| {
                CoordinatorError::Failed("Install mutation has no desired file".into())
            })?;
        let source = match desired.policy {
            FilePolicy::Exact => {
                let object = objects.get(&desired.signed_sha256).ok_or_else(|| {
                    CoordinatorError::Failed(format!(
                        "Downloaded object set is missing {}",
                        desired.signed_sha256
                    ))
                })?;
                bind_exact_staging_source_v2(
                    staging_authority,
                    operation_lock,
                    &operation.root,
                    *staging_slot,
                    object,
                )
                .map_err(|error| CoordinatorError::Failed(error.to_string()))?
            }
            FilePolicy::ValidatedMutable => {
                let default_sha = inventory
                    .mutable_default_sha256(destination_path)
                    .map_err(CoordinatorError::Failed)?;
                let object = objects.get(default_sha).ok_or_else(|| {
                    CoordinatorError::Failed(format!(
                        "Downloaded object set is missing mutable default {default_sha}"
                    ))
                })?;
                let state = mutable_states.get_mut(destination_path).ok_or_else(|| {
                    CoordinatorError::Failed(format!(
                        "No persisted mutable state for {destination_path}"
                    ))
                })?;
                bind_canonical_mutable_staging_source_v2(
                    staging_authority,
                    operation_lock,
                    &operation.root,
                    *staging_slot,
                    object,
                    state,
                )
                .map_err(|error| CoordinatorError::Failed(error.to_string()))?
            }
        };
        sources.push(source);
    }
    Ok(sources)
}

fn require_staging_active(
    cancellation: &CoordinatorCancellation,
) -> Result<(), StagingWriterCheckpointErrorV2> {
    if cancellation.cancelled.load(Ordering::Acquire) {
        Err(StagingWriterCheckpointErrorV2::Cancelled)
    } else {
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
async fn abandon_stale_ready(
    authority: &OperationAuthority,
    install_lock: &CoordinatorOperationLock,
    state_store: &InstanceStateStore,
    config: &CoordinatorConfig,
    operation_id: Uuid,
    channel: BuildChannel,
    preset: PresetId,
    auth: &Arc<AuthSessionManager>,
    cancellation: &CoordinatorCancellation,
    observer: &ProgressObserver,
    stale: &StalePendingRecovery,
    prepared: &PreparedCoordinatorPlan,
) -> Result<CoordinatorSnapshot, CoordinatorError> {
    let active = stale.observed_active.as_ref().ok_or_else(|| {
        CoordinatorError::Failed(
            "A stale pending journal cannot be abandoned without an active instance".into(),
        )
    })?;
    let pending_identity = stale.untrusted_pending_identity.as_ref().ok_or_else(|| {
        CoordinatorError::Failed(
            "A stale pending journal cannot be abandoned without sealed identity classification"
                .into(),
        )
    })?;
    let authorization = authorize_stale_pending_ready_abandon(
        &stale.pending.plan,
        active,
        pending_identity,
        PlannerRequestV2 {
            install_id: authority.install_id,
            channel,
            preset,
            operation_id,
            trusted_release: &prepared.trusted,
            artifact_inventory: &prepared.inventory,
            cas_root: &authority.root,
            installed: prepared.installed.as_ref(),
            audit: &prepared.audit,
            mutable_files: &prepared.mutable_proofs,
            availability: &prepared.availability,
        },
    )
    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    {
        let channel_lock = state_store
            .acquire_operation_lock(channel)
            .map_err(|error| {
                CoordinatorError::Failed(format!("Cannot lock stale-ready completion: {error}"))
            })?;
        let observed = detect_pending(
            &authority.install_root,
            authority.install_id,
            channel,
            &channel_lock,
        )
        .map_err(CoordinatorError::Failed)?;
        let marker = state_store
            .load_locked(&channel_lock)
            .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
        if observed.as_ref() != Some(&stale.pending) || marker.as_ref() != Some(active) {
            return Err(CoordinatorError::Failed(
                "Stale-ready journal or active marker changed before abandon".into(),
            ));
        }
        abandon_stale_pending_for_current_ready(
            &authority.install_root,
            authority.install_id,
            channel,
            &channel_lock,
            &stale.pending.pointer,
            authorization,
        )
        .map_err(CoordinatorError::Failed)?;
    }
    install_lock.revalidate(&authority.root)?;
    let refreshed = prepare_plan(PreparePlanRequest {
        authority,
        config,
        operation_id,
        channel,
        preset,
        auth,
        cancellation,
        observer,
        capture_local: false,
    })
    .await?;
    if refreshed.planned.state != PlannedBuildState::Ready {
        return Err(CoordinatorError::Failed(
            "Instance changed after stale journal abandon and is no longer ready".into(),
        ));
    }
    let verify_lock = state_store
        .acquire_operation_lock(channel)
        .map_err(|error| {
            CoordinatorError::Failed(format!("Cannot verify stale-ready completion: {error}"))
        })?;
    if detect_pending(
        &authority.install_root,
        authority.install_id,
        channel,
        &verify_lock,
    )
    .map_err(CoordinatorError::Failed)?
    .is_some()
    {
        return Err(CoordinatorError::Failed(
            "A pending journal reappeared after ready abandon".into(),
        ));
    }
    let repeated_active = state_store
        .load_locked(&verify_lock)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    if repeated_active != refreshed.installed
        || repeated_active.as_ref() != stale.observed_active.as_ref()
    {
        return Err(CoordinatorError::Failed(
            "Active instance changed during post-abandon ready audit".into(),
        ));
    }
    let free = current_free_space(&authority.root)?;
    Ok(snapshot_from_plan(
        &refreshed.planned,
        refreshed.installed.as_ref(),
        &refreshed.trusted,
        free,
    ))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn run_operation(
    config: &CoordinatorConfig,
    install_directory: &Path,
    install_id: Uuid,
    operation_id: Uuid,
    channel: BuildChannel,
    preset: PresetId,
    auth: &Arc<AuthSessionManager>,
    cancellation: &CoordinatorCancellation,
    observer: &ProgressObserver,
) -> Result<CoordinatorSnapshot, CoordinatorError> {
    let mut attempt_operation_id = operation_id;
    for _ in 0..4 {
        let outcome = run_operation_attempt(
            config,
            install_directory,
            install_id,
            attempt_operation_id,
            channel,
            preset,
            auth,
            cancellation,
            observer,
        )
        .await?;
        if !maintain_idle_reconcile_state(install_directory, install_id, channel)? {
            attempt_operation_id = rotate_attempt_operation_id(attempt_operation_id);
            continue;
        }
        if !outcome.recovered_pending {
            return Ok(outcome.snapshot);
        }
        // The pre-existing durable operation is now fully converged and cleaned. Only at this
        // point may the original caller cancellation affect its still-unmodified request.
        cancellation.check()?;
        attempt_operation_id = rotate_attempt_operation_id(attempt_operation_id);
    }
    Err(CoordinatorError::Failed(
        "Concurrent pending reconcile activity did not converge after bounded retries".into(),
    ))
}

struct OperationAttemptOutcome {
    snapshot: CoordinatorSnapshot,
    recovered_pending: bool,
}

fn maintain_idle_reconcile_state(
    install_directory: &Path,
    install_id: Uuid,
    channel: BuildChannel,
) -> Result<bool, CoordinatorError> {
    let authority = validate_operation_root(install_directory, install_id)?;
    let install_lock = CoordinatorOperationLock::acquire(&authority.root)?;
    let state_store = InstanceStateStore::new(&authority.install_root, install_id);
    let channel_lock = state_store
        .acquire_operation_lock(channel)
        .map_err(|error| {
            CoordinatorError::Failed(format!("Cannot lock journal cleanup: {error}"))
        })?;
    if detect_pending_transition(&authority.install_root, install_id, channel, &channel_lock)
        .map_err(CoordinatorError::Failed)?
        .is_some()
    {
        return Ok(false);
    }
    maintain_completed_reconcile_state(&authority.install_root, install_id, channel, &channel_lock)
        .map_err(CoordinatorError::Failed)?;
    install_lock.revalidate(&authority.root)?;
    Ok(
        detect_pending_transition(&authority.install_root, install_id, channel, &channel_lock)
            .map_err(CoordinatorError::Failed)?
            .is_none(),
    )
}

#[allow(clippy::too_many_arguments)]
async fn run_operation_attempt(
    config: &CoordinatorConfig,
    install_directory: &Path,
    install_id: Uuid,
    operation_id: Uuid,
    channel: BuildChannel,
    preset: PresetId,
    auth: &Arc<AuthSessionManager>,
    cancellation: &CoordinatorCancellation,
    observer: &ProgressObserver,
) -> Result<OperationAttemptOutcome, CoordinatorError> {
    if operation_id.is_nil() || operation_id.get_version() != Some(uuid::Version::Random) {
        return Err(CoordinatorError::Failed(
            "Coordinator operation ID must be UUIDv4".into(),
        ));
    }
    let authority = validate_operation_root(install_directory, install_id)?;
    let state_store = InstanceStateStore::new(&authority.install_root, install_id);
    let recovery_cancellation = CoordinatorCancellation::default();

    // Observe the journal before cancellation, cleanup, auth, or network work. A durable pending
    // operation is assigned to the independent recovery control. A clean pre-cancelled request
    // returns before orphan maintenance can mutate disk or mask cancellation with a cleanup error.
    let InitialAttemptClassification {
        install_lock,
        channel_lock,
        pending: initially_pending,
    } = acquire_initial_attempt_classification(
        &authority,
        &state_store,
        channel,
        cancellation,
        &recovery_cancellation,
    )?;
    if !initially_pending {
        cancellation.check()?;
        maintain_completed_reconcile_state(
            &authority.install_root,
            install_id,
            channel,
            &channel_lock,
        )
        .map_err(CoordinatorError::Failed)?;
    }
    drop(channel_lock);
    install_lock.revalidate(&authority.root)?;
    if !initially_pending {
        cancellation.check()?;
    }

    let trust_cancellation =
        select_attempt_cancellation(cancellation, &recovery_cancellation, initially_pending);

    // Recovery is always settled before the new operation is planned. Cancellation is not
    // consulted while a durable pending pointer exists: that state must converge first.
    let recovery_release =
        refresh_trusted_release_with_cancellation(config, channel, auth, trust_cancellation)
            .await?;
    let mut operation_id = operation_id;
    let mut preset = preset;
    let recovered_pending;
    let stale_pending = {
        let channel_lock = state_store
            .acquire_operation_lock(channel)
            .map_err(|error| {
                CoordinatorError::Failed(format!("Cannot lock instance recovery: {error}"))
            })?;
        let transition =
            detect_pending_transition(&authority.install_root, install_id, channel, &channel_lock)
                .map_err(CoordinatorError::Failed)?;
        recovered_pending = transition.is_some();
        if let Some(transition) = transition {
            if let Some(successor) = transition.durable_successor {
                let pending = transition.pending;
                let observed_active = state_store
                    .load_locked(&channel_lock)
                    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
                if observed_active.as_ref() != successor.plan.base.as_ref() {
                    return Err(CoordinatorError::Failed(
                        "Recorded successor base does not match the active instance".into(),
                    ));
                }
                let advanced = advance_pending_to_recorded_successor(
                    &authority.install_root,
                    install_id,
                    channel,
                    &channel_lock,
                    &pending.pointer,
                    &successor.pointer,
                )
                .map_err(CoordinatorError::Failed)?;
                if advanced != successor {
                    return Err(CoordinatorError::Failed(
                        "Recorded successor pointer advance returned different journal bytes"
                            .into(),
                    ));
                }
                let repeated_active = state_store
                    .load_locked(&channel_lock)
                    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
                if repeated_active != observed_active
                    || repeated_active.as_ref() != successor.plan.base.as_ref()
                {
                    return Err(CoordinatorError::Failed(
                        "Active instance changed during recorded successor pointer advance".into(),
                    ));
                }
                None
            } else {
                settle_pending_operation(
                    &authority,
                    channel,
                    &recovery_release,
                    &state_store,
                    &channel_lock,
                )?
            }
        } else {
            maintain_completed_reconcile_state(
                &authority.install_root,
                install_id,
                channel,
                &channel_lock,
            )
            .map_err(CoordinatorError::Failed)?;
            None
        }
    };
    if recovered_pending && stale_pending.is_none() {
        // `settle_pending_operation` already finished the pre-existing journal without needing a
        // successor. Do not let the recovery control leak into the caller's fresh work: return
        // to the outer state machine, clean the now-idle journal, honor user cancellation, then
        // start the original request as a distinct attempt.
        install_lock.revalidate(&authority.root)?;
        let installed = state_store
            .load(channel)
            .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
        return Ok(OperationAttemptOutcome {
            snapshot: CoordinatorSnapshot {
                state: PlannedBuildState::Repair,
                installed_release_id: installed.as_ref().map(|value| value.release_id.clone()),
                available_release_id: recovery_release.manifest().release.id.clone(),
                disk_free_bytes: current_free_space(&authority.root)?,
                disk_required_bytes: 0,
                message: "Interrupted operation recovery completed".into(),
            },
            recovered_pending: true,
        });
    }
    if let Some(stale) = stale_pending.as_ref() {
        let channel_lock = state_store
            .acquire_operation_lock(channel)
            .map_err(|error| {
                CoordinatorError::Failed(format!("Cannot lock pending retry cleanup: {error}"))
            })?;
        let before =
            detect_pending_transition(&authority.install_root, install_id, channel, &channel_lock)
                .map_err(CoordinatorError::Failed)?;
        let active = state_store
            .load_locked(&channel_lock)
            .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
        if !transition_matches_recovery(stale, before.as_ref()) || active != stale.observed_active {
            return Err(CoordinatorError::Failed(
                "Pending transition changed before retry cleanup".into(),
            ));
        }
        maintain_completed_reconcile_state(
            &authority.install_root,
            install_id,
            channel,
            &channel_lock,
        )
        .map_err(CoordinatorError::Failed)?;
        let after =
            detect_pending_transition(&authority.install_root, install_id, channel, &channel_lock)
                .map_err(CoordinatorError::Failed)?;
        if !transition_matches_recovery(stale, after.as_ref()) {
            return Err(CoordinatorError::Failed(
                "Pending transition changed during retry cleanup".into(),
            ));
        }
        install_lock.revalidate(&authority.root)?;
    }
    if recovered_pending {
        operation_id = rotate_attempt_operation_id(operation_id);
        preset = recovery_continuation_preset(
            &recovery_release,
            stale_pending
                .as_ref()
                .map(|stale| &stale.pending)
                .expect("unsettled pending recovery retains its classification"),
        )?;
    }
    let cancellation =
        select_attempt_cancellation(cancellation, &recovery_cancellation, recovered_pending);
    install_lock.revalidate(&authority.root)?;
    cancellation.check()?;

    let mut prepared = prepare_plan(PreparePlanRequest {
        authority: &authority,
        config,
        operation_id,
        channel,
        preset,
        auth,
        cancellation,
        observer,
        capture_local: true,
    })
    .await?;
    if prepared.planned.state == PlannedBuildState::Ready {
        if let Some(stale) = stale_pending.as_ref() {
            let active = stale.observed_active.as_ref().ok_or_else(|| {
                CoordinatorError::Failed(
                    "A stale pending journal cannot be abandoned without an active instance".into(),
                )
            })?;
            let pending_identity = stale.untrusted_pending_identity.as_ref().ok_or_else(|| {
                CoordinatorError::Failed(
                    "A stale pending journal cannot be abandoned without sealed identity classification"
                        .into(),
                )
            })?;
            let authorization = authorize_stale_pending_ready_abandon(
                &stale.pending.plan,
                active,
                pending_identity,
                PlannerRequestV2 {
                    install_id,
                    channel,
                    preset,
                    operation_id,
                    trusted_release: &prepared.trusted,
                    artifact_inventory: &prepared.inventory,
                    cas_root: &authority.root,
                    installed: prepared.installed.as_ref(),
                    audit: &prepared.audit,
                    mutable_files: &prepared.mutable_proofs,
                    availability: &prepared.availability,
                },
            )
            .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
            {
                let channel_lock =
                    state_store
                        .acquire_operation_lock(channel)
                        .map_err(|error| {
                            CoordinatorError::Failed(format!(
                                "Cannot lock stale-ready journal completion: {error}"
                            ))
                        })?;
                let observed =
                    detect_pending(&authority.install_root, install_id, channel, &channel_lock)
                        .map_err(CoordinatorError::Failed)?;
                let marker = state_store
                    .load_locked(&channel_lock)
                    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
                if observed.as_ref() != Some(&stale.pending) || marker.as_ref() != Some(active) {
                    return Err(CoordinatorError::Failed(
                        "Stale-ready journal or active marker changed before abandon".into(),
                    ));
                }
                abandon_stale_pending_for_current_ready(
                    &authority.install_root,
                    install_id,
                    channel,
                    &channel_lock,
                    &stale.pending.pointer,
                    authorization,
                )
                .map_err(CoordinatorError::Failed)?;
            }
            install_lock.revalidate(&authority.root)?;
            let refreshed = prepare_plan(PreparePlanRequest {
                authority: &authority,
                config,
                operation_id,
                channel,
                preset,
                auth,
                cancellation,
                observer,
                capture_local: false,
            })
            .await?;
            if refreshed.planned.state != PlannedBuildState::Ready {
                return Err(CoordinatorError::Failed(
                    "Instance changed after stale journal abandon and is no longer ready".into(),
                ));
            }
            let verify_lock = state_store
                .acquire_operation_lock(channel)
                .map_err(|error| {
                    CoordinatorError::Failed(format!(
                        "Cannot verify stale-ready completion: {error}"
                    ))
                })?;
            if detect_pending(&authority.install_root, install_id, channel, &verify_lock)
                .map_err(CoordinatorError::Failed)?
                .is_some()
            {
                return Err(CoordinatorError::Failed(
                    "A pending journal reappeared after ready abandon".into(),
                ));
            }
            let repeated_active = state_store
                .load_locked(&verify_lock)
                .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
            if repeated_active != refreshed.installed
                || repeated_active.as_ref() != stale.observed_active.as_ref()
            {
                return Err(CoordinatorError::Failed(
                    "Active instance changed during post-abandon ready audit".into(),
                ));
            }
            let free = current_free_space(&authority.root)?;
            return Ok(OperationAttemptOutcome {
                snapshot: snapshot_from_plan(
                    &refreshed.planned,
                    refreshed.installed.as_ref(),
                    &refreshed.trusted,
                    free,
                ),
                recovered_pending,
            });
        }
        let free = current_free_space(&authority.root)?;
        return Ok(OperationAttemptOutcome {
            snapshot: snapshot_from_plan(
                &prepared.planned,
                prepared.installed.as_ref(),
                &prepared.trusted,
                free,
            ),
            recovered_pending,
        });
    }
    cancellation.check()?;
    require_fresh_budget(&authority.root, &prepared.planned, &prepared.inventory)?;
    let preparatory_plan =
        prepared.planned.plan.as_ref().ok_or_else(|| {
            CoordinatorError::Failed("Non-ready build has no reconcile plan".into())
        })?;
    let artifact_plan = prepared
        .planned
        .disk_budget_authority
        .as_ref()
        .ok_or_else(|| CoordinatorError::Failed("Non-ready build has no disk authority".into()))?
        .artifact_plan_for(preparatory_plan, &prepared.inventory, &authority.root)
        .map_err(CoordinatorError::Failed)?;
    let view = artifact_plan
        .execution_view(&authority.root, &prepared.inventory)
        .map_err(CoordinatorError::Failed)?;
    let mut objects = download_execution_view(DownloadExecutionRequest {
        root: &authority.root,
        view,
        channel,
        auth,
        cancellation,
        observer,
        phase: BuildPhase::Downloading,
        total_bytes: artifact_plan.network_bytes(),
        disk_required_bytes: prepared.planned.disk_budget_record.required_bytes,
    })
    .await?;
    cancellation.check()?;
    install_lock.revalidate(&authority.root)?;

    let after_download =
        replan_verified_boundary(&authority, &prepared, operation_id, channel, preset)?;
    if after_download.state == PlannedBuildState::Ready {
        if let Some(stale) = stale_pending.as_ref() {
            let ready = prepare_plan(PreparePlanRequest {
                authority: &authority,
                config,
                operation_id,
                channel,
                preset,
                auth,
                cancellation,
                observer,
                capture_local: false,
            })
            .await?;
            let snapshot = abandon_stale_ready(
                &authority,
                &install_lock,
                &state_store,
                config,
                operation_id,
                channel,
                preset,
                auth,
                cancellation,
                observer,
                stale,
                &ready,
            )
            .await?;
            return Ok(OperationAttemptOutcome {
                snapshot,
                recovered_pending,
            });
        }
        let free = current_free_space(&authority.root)?;
        return Ok(OperationAttemptOutcome {
            snapshot: snapshot_from_plan(
                &after_download,
                prepared.installed.as_ref(),
                &prepared.trusted,
                free,
            ),
            recovered_pending,
        });
    }
    require_fresh_budget(&authority.root, &after_download, &prepared.inventory)?;
    let after_download_availability =
        VerifiedAvailabilityV2::scan(&authority.root, &prepared.inventory)
            .map_err(CoordinatorError::Failed)?;
    let after_download_reconcile = after_download.plan.as_ref().ok_or_else(|| {
        CoordinatorError::Failed("Downloaded build unexpectedly has no reconcile plan".into())
    })?;
    let after_download_artifacts = after_download
        .disk_budget_authority
        .as_ref()
        .ok_or_else(|| CoordinatorError::Failed("Downloaded build has no disk authority".into()))?
        .artifact_plan_for(
            after_download_reconcile,
            &prepared.inventory,
            &authority.root,
        )
        .map_err(CoordinatorError::Failed)?;

    observer(CoordinatorProgress::checking(
        "Installing verified Java 25 runtime",
    ));
    let mut installed_runtime: Option<RuntimeInstallation> = None;
    if !after_download_availability.java_generation_complete() {
        let java_plan = after_download_artifacts
            .java_archive(&authority.root, &prepared.inventory)
            .map_err(CoordinatorError::Failed)?;
        let java = objects.get(java_plan.sha256()).ok_or_else(|| {
            CoordinatorError::Failed("Artifact download omitted the Java archive".into())
        })?;
        let java_observer = Arc::clone(observer);
        let java_root = authority.install_root.clone();
        let java_control = RuntimeInstallControl::new(
            cancellation.flag(),
            Arc::new(move |progress: RuntimeInstallProgress| {
                java_observer(CoordinatorProgress {
                    phase: BuildPhase::Updating,
                    message: "Installing verified Java 25 runtime".into(),
                    current_file: Some(format!("java-file-{}", progress.completed_files)),
                    downloaded_bytes: progress.completed_bytes,
                    total_bytes: progress.total_bytes,
                    speed_bytes_per_second: 0,
                    disk_free_bytes: fs2::available_space(&java_root).unwrap_or(0),
                    disk_required_bytes: 0,
                });
            }),
        );
        installed_runtime = Some(
            install_runtime_with_control(&authority.root, &java_plan, java, &java_control)
                .map_err(|error| match error {
                    RuntimeInstallError::Cancelled { .. } => CoordinatorError::Cancelled,
                    other => CoordinatorError::Failed(other.to_string()),
                })?,
        );
    }
    let runtime = installed_runtime
        .as_ref()
        .or_else(|| after_download_availability.java_installation())
        .ok_or_else(|| CoordinatorError::Failed("Verified Java runtime is unavailable".into()))?;
    cancellation.check()?;

    let after_java =
        replan_verified_boundary(&authority, &prepared, operation_id, channel, preset)?;
    if after_java.state == PlannedBuildState::Ready {
        if let Some(stale) = stale_pending.as_ref() {
            let ready = prepare_plan(PreparePlanRequest {
                authority: &authority,
                config,
                operation_id,
                channel,
                preset,
                auth,
                cancellation,
                observer,
                capture_local: false,
            })
            .await?;
            let snapshot = abandon_stale_ready(
                &authority,
                &install_lock,
                &state_store,
                config,
                operation_id,
                channel,
                preset,
                auth,
                cancellation,
                observer,
                stale,
                &ready,
            )
            .await?;
            return Ok(OperationAttemptOutcome {
                snapshot,
                recovered_pending,
            });
        }
        let free = current_free_space(&authority.root)?;
        return Ok(OperationAttemptOutcome {
            snapshot: snapshot_from_plan(
                &after_java,
                prepared.installed.as_ref(),
                &prepared.trusted,
                free,
            ),
            recovered_pending,
        });
    }
    require_fresh_budget(&authority.root, &after_java, &prepared.inventory)?;
    let after_java_availability =
        VerifiedAvailabilityV2::scan(&authority.root, &prepared.inventory)
            .map_err(CoordinatorError::Failed)?;
    let after_java_reconcile = after_java.plan.as_ref().ok_or_else(|| {
        CoordinatorError::Failed("Java-ready build unexpectedly has no reconcile plan".into())
    })?;
    let after_java_artifacts = after_java
        .disk_budget_authority
        .as_ref()
        .ok_or_else(|| CoordinatorError::Failed("Java-ready build has no disk authority".into()))?
        .artifact_plan_for(after_java_reconcile, &prepared.inventory, &authority.root)
        .map_err(CoordinatorError::Failed)?;

    observer(CoordinatorProgress::checking(
        "Materializing immutable Minecraft runtime",
    ));
    if !after_java_availability.game_generation_complete() {
        let mut official_objects =
            Vec::with_capacity(prepared.inventory.official_game_sha256().len());
        for sha256 in prepared.inventory.official_game_sha256() {
            official_objects.push(objects.remove(sha256).ok_or_else(|| {
                CoordinatorError::Failed(format!(
                    "Artifact download omitted official object {sha256}"
                ))
            })?);
        }
        let authority_plan = after_java_artifacts
            .game_generation(&authority.root, &prepared.inventory, official_objects)
            .map_err(CoordinatorError::Failed)?;
        match begin_game_generation(&authority.root, authority_plan)
            .map_err(map_generation_error)?
        {
            BeginGameGeneration::Installed(_) => {}
            BeginGameGeneration::Build(build) => {
                match stage_official_game_files(build, &cancellation.cancelled)
                    .map_err(map_generation_error)?
                {
                    StagedGameGeneration::Ready(ready) => {
                        publish_game_generation(ready, &cancellation.cancelled)
                            .map_err(map_generation_error)?;
                    }
                    StagedGameGeneration::NeedsProcessors(processor_build) => {
                        let workspace = materialize_processor_workspace(&processor_build)
                            .map_err(CoordinatorError::Failed)?;
                        let result = execute_game_runtime_processors(
                            workspace,
                            &processor_build,
                            runtime,
                            cancellation.flag(),
                        )
                        .map_err(map_processor_execution_error)?;
                        let ready = merge_processor_outputs(
                            processor_build,
                            result,
                            &cancellation.cancelled,
                        )
                        .map_err(map_generation_error)?;
                        publish_game_generation(ready, &cancellation.cancelled)
                            .map_err(map_generation_error)?;
                    }
                }
            }
        }
    }
    cancellation.check()?;
    install_lock.revalidate(&authority.root)?;

    // Re-audit and replan after downloads/generations. The journal receives only this fresh,
    // canonical budget and never the larger preparatory estimate.
    let final_availability = VerifiedAvailabilityV2::scan(&authority.root, &prepared.inventory)
        .map_err(CoordinatorError::Failed)?;
    let final_audit = audit_release_instance(
        &authority.install_root,
        channel,
        prepared.trusted.manifest(),
        preset,
    )
    .map_err(CoordinatorError::Failed)?;
    let final_defaults = download_mutable_bootstrap(
        &authority.root,
        &prepared.inventory,
        &final_availability,
        channel,
        auth,
        cancellation,
        observer,
    )
    .await?;
    let (final_mutable_proofs, final_mutable_states) =
        prepare_mutable_proofs(MutableProofRequest {
            root: &authority.root,
            inventory: &prepared.inventory,
            trusted: &prepared.trusted,
            channel,
            target_preset: preset,
            installed: prepared.installed.as_ref(),
            audit: &final_audit,
            defaults: &final_defaults,
            capture_local: false,
        })?;
    prepared.mutable_proofs = final_mutable_proofs;
    prepared.mutable_states = final_mutable_states;
    let final_plan = plan_build(PlannerRequestV2 {
        install_id,
        channel,
        preset,
        operation_id,
        trusted_release: &prepared.trusted,
        artifact_inventory: &prepared.inventory,
        cas_root: &authority.root,
        installed: prepared.installed.as_ref(),
        audit: &final_audit,
        mutable_files: &prepared.mutable_proofs,
        availability: &final_availability,
    })
    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    if final_plan.state == PlannedBuildState::Ready {
        if let Some(stale) = stale_pending.as_ref() {
            let ready = PreparedCoordinatorPlan {
                trusted: prepared.trusted,
                inventory: prepared.inventory,
                availability: final_availability,
                installed: prepared.installed,
                audit: final_audit,
                mutable_defaults: prepared.mutable_defaults,
                mutable_proofs: prepared.mutable_proofs,
                mutable_states: prepared.mutable_states,
                planned: final_plan,
            };
            let snapshot = abandon_stale_ready(
                &authority,
                &install_lock,
                &state_store,
                config,
                operation_id,
                channel,
                preset,
                auth,
                cancellation,
                observer,
                stale,
                &ready,
            )
            .await?;
            return Ok(OperationAttemptOutcome {
                snapshot,
                recovered_pending,
            });
        }
        let free = current_free_space(&authority.root)?;
        return Ok(OperationAttemptOutcome {
            snapshot: snapshot_from_plan(
                &final_plan,
                prepared.installed.as_ref(),
                &prepared.trusted,
                free,
            ),
            recovered_pending,
        });
    }
    cancellation.check()?;
    require_fresh_budget(&authority.root, &final_plan, &prepared.inventory)?;

    let mut ordinary_plan = None;
    let prepared_update = if let Some(stale) = stale_pending.as_ref() {
        Some(
            prepare_current_plan_supersede(
                &stale.pending.plan,
                stale.observed_active.as_ref(),
                &prepared.trusted,
                final_plan,
                &prepared.inventory,
                &authority.root,
            )
            .map_err(|error| CoordinatorError::Failed(error.to_string()))?,
        )
    } else {
        ordinary_plan = Some(final_plan);
        None
    };
    let plan = if let Some(update) = prepared_update.as_ref() {
        update.plan()
    } else {
        ordinary_plan
            .as_ref()
            .and_then(|planned| planned.plan.as_ref())
            .ok_or_else(|| {
                CoordinatorError::Failed("Prepared reconcile unexpectedly became empty".into())
            })?
    };

    let channel_lock = state_store
        .acquire_operation_lock(channel)
        .map_err(|error| {
            CoordinatorError::Failed(format!("Cannot lock instance commit: {error}"))
        })?;
    install_lock.revalidate(&authority.root)?;
    let observed_pending =
        detect_pending(&authority.install_root, install_id, channel, &channel_lock)
            .map_err(CoordinatorError::Failed)?;
    let pending_matches = match (stale_pending.as_ref(), observed_pending.as_ref()) {
        (None, None) => true,
        (Some(expected), Some(actual)) => {
            expected.pending.pointer == actual.pointer && expected.pending.plan == actual.plan
        }
        _ => false,
    };
    let observed_active = state_store
        .load_locked(&channel_lock)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    if !pending_matches
        || observed_active != prepared.installed
        || stale_pending
            .as_ref()
            .is_some_and(|stale| observed_active != stale.observed_active)
    {
        return Err(CoordinatorError::Failed(
            "Instance state changed after planning; operation must be replanned".into(),
        ));
    }
    // Maintenance is pending-aware: it leases and preserves the exact live pointer plus any
    // history-only durable successor while reclaiming orphan replacement roots from prior
    // pre-supersede failures. Running it unconditionally prevents bounded retry disk leaks.
    maintain_completed_reconcile_state(&authority.install_root, install_id, channel, &channel_lock)
        .map_err(CoordinatorError::Failed)?;
    let maintained_transition =
        detect_pending_transition(&authority.install_root, install_id, channel, &channel_lock)
            .map_err(CoordinatorError::Failed)?;
    let maintenance_preserved_state = match stale_pending.as_ref() {
        None => maintained_transition.is_none(),
        Some(expected) => transition_matches_recovery(expected, maintained_transition.as_ref()),
    };
    if !maintenance_preserved_state {
        return Err(CoordinatorError::Failed(
            "Pending reconcile transition changed during pre-staging maintenance".into(),
        ));
    }
    let final_artifact_plan = if let Some(update) = prepared_update.as_ref() {
        update.artifact_plan()
    } else {
        ordinary_plan
            .as_ref()
            .and_then(|planned| planned.disk_budget_authority.as_ref())
            .ok_or_else(|| CoordinatorError::Failed("Fresh plan has no disk authority".into()))?
            .artifact_plan_for(plan, &prepared.inventory, &authority.root)
            .map_err(CoordinatorError::Failed)?
    };
    let staging_authority = authorize_reconcile_staging_v2(
        plan,
        &prepared.trusted,
        &prepared.inventory,
        final_artifact_plan,
        &channel_lock,
        &authority.root,
    )
    .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    let sources = reconcile_sources(
        &authority,
        &staging_authority,
        &prepared.inventory,
        plan,
        &channel_lock,
        &objects,
        &mut prepared.mutable_states,
    )?;
    let staging_phase = match prepared.planned.state {
        PlannedBuildState::Download => BuildPhase::Downloading,
        PlannedBuildState::Update => BuildPhase::Updating,
        PlannedBuildState::Repair => BuildPhase::Repairing,
        PlannedBuildState::Ready => BuildPhase::Verifying,
    };
    let mut staging_slots = BTreeMap::<u32, (u64, u64)>::new();
    let staged = write_reconcile_staging_with_checkpoint_v2(
        &staging_authority,
        &channel_lock,
        &authority.root,
        sources,
        |checkpoint| {
            require_staging_active(cancellation)?;
            match checkpoint {
                StagingWriterCheckpointV2::Chunk {
                    staging_slot,
                    written_bytes,
                    total_bytes,
                } => {
                    staging_slots.insert(staging_slot, (written_bytes, total_bytes));
                    let written = staging_slots
                        .values()
                        .fold(0_u64, |total, (value, _)| total.saturating_add(*value));
                    let total = staging_slots
                        .values()
                        .fold(0_u64, |sum, (_, value)| sum.saturating_add(*value));
                    observer(CoordinatorProgress {
                        phase: staging_phase,
                        message: "Preparing verified instance staging".into(),
                        current_file: Some(format!("staging-slot-{staging_slot}")),
                        downloaded_bytes: written,
                        total_bytes: total,
                        speed_bytes_per_second: 0,
                        disk_free_bytes: current_free_space(&authority.root).map_err(|error| {
                            StagingWriterCheckpointErrorV2::Failed(error.to_string())
                        })?,
                        disk_required_bytes: plan.disk_budget.required_bytes,
                    });
                }
                StagingWriterCheckpointV2::BeforeCommit(_)
                | StagingWriterCheckpointV2::AfterCommit(_) => {}
            }
            Ok(())
        },
    )
    .map_err(map_staging_writer_error)?;
    staged
        .proofs_for(&staging_authority, &channel_lock, &authority.root)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    cancellation.check()?;
    if let (Some(stale), Some(update)) = (stale_pending.as_ref(), prepared_update.as_ref()) {
        let authorization = authorize_current_plan_supersede(CurrentPlanSupersedeRequestV2 {
            failed_plan: &stale.pending.plan,
            active_marker: stale.observed_active.as_ref(),
            fresh_release: &prepared.trusted,
            current_final_audit: stale.current_failed_audit.as_ref(),
            current_final_mutable_files: &stale.current_failed_mutable,
            untrusted_pending_identity: stale.untrusted_pending_identity.as_ref(),
            prepared_update: update,
            artifact_inventory: &prepared.inventory,
            cas_root: &authority.root,
        })
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
        cancellation.check()?;
        supersede_stale_pending_with_current_plan(
            &authority.install_root,
            install_id,
            channel,
            &channel_lock,
            &authority.root,
            &stale.pending.pointer,
            authorization,
            &staging_authority,
            &staged,
        )
        .map_err(CoordinatorError::Failed)?;
    } else {
        let pointer = write_immutable_plan(
            &authority.install_root,
            install_id,
            channel,
            &channel_lock,
            plan,
        )
        .map_err(CoordinatorError::Failed)?;
        cancellation.check()?;
        publish_pending(
            &authority.install_root,
            install_id,
            channel,
            &channel_lock,
            &pointer,
        )
        .map_err(CoordinatorError::Failed)?;
    }

    // No cancellation point below this line. The durable pending pointer must converge.
    roll_forward_staged_v2(&staging_authority, &channel_lock, &authority.root, staged)
        .map_err(map_reconcile_executor_error)?;
    state_store
        .save_locked(&channel_lock, &plan.target)
        .map_err(|error| CoordinatorError::Failed(error.to_string()))?;
    if settle_pending_operation(
        &authority,
        channel,
        &prepared.trusted,
        &state_store,
        &channel_lock,
    )?
    .is_some()
    {
        return Err(CoordinatorError::Failed(
            "Fresh operation unexpectedly became historical during finalization".into(),
        ));
    }
    maintain_completed_reconcile_state(&authority.install_root, install_id, channel, &channel_lock)
        .map_err(CoordinatorError::Failed)?;
    install_lock.revalidate(&authority.root)?;

    let completed_availability = VerifiedAvailabilityV2::scan(&authority.root, &prepared.inventory)
        .map_err(CoordinatorError::Failed)?;
    if !completed_availability.java_generation_complete()
        || !completed_availability.game_generation_complete()
    {
        return Err(CoordinatorError::Failed(
            "Runtime generation failed its final audit".into(),
        ));
    }
    let completed_audit = audit_release_instance(
        &authority.install_root,
        channel,
        prepared.trusted.manifest(),
        preset,
    )
    .map_err(CoordinatorError::Failed)?;
    let completed_mutable = prepare_mutable_proofs(MutableProofRequest {
        root: &authority.root,
        inventory: &prepared.inventory,
        trusted: &prepared.trusted,
        channel,
        target_preset: preset,
        installed: Some(&plan.target),
        audit: &completed_audit,
        defaults: &prepared.mutable_defaults,
        capture_local: false,
    })?
    .0;
    if completed_audit.needs_reconciliation()
        || completed_mutable.iter().any(|proof| !proof.current_matches)
    {
        return Err(CoordinatorError::Failed(
            "Committed instance failed its exact final audit".into(),
        ));
    }
    let free = current_free_space(&authority.root)?;
    Ok(OperationAttemptOutcome {
        snapshot: CoordinatorSnapshot {
            state: PlannedBuildState::Ready,
            installed_release_id: Some(plan.target.release_id.clone()),
            available_release_id: prepared.trusted.manifest().release.id.clone(),
            disk_free_bytes: free,
            disk_required_bytes: 0,
            message: "The build is ready".into(),
        },
        recovered_pending,
    })
}

#[cfg(test)]
mod tests {
    use super::super::{
        journal::{DiskBudgetV2, OperationKind, PlannedFileV2},
        planner::tests::trusted,
        reconcile_executor::RollbackCompletionAuthorizationV2,
        tuf::{TrustedReleaseEvidence, TrustedRoleVersions, TrustedTargetEvidence},
    };
    use super::*;
    use fs2::FileExt;
    use std::fs;

    const TEST_HASH_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const TEST_HASH_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const TEST_HASH_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const TEST_HASH_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

    struct TestInstall(PathBuf);

    impl TestInstall {
        fn new() -> Self {
            let path =
                std::env::temp_dir().join(format!("fragment-coordinator-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn root(&self) -> OwnedCasRoot {
            super::super::storage::select_install_directory(&self.0)
                .unwrap()
                .into_owned_cas_root()
        }
    }

    impl Drop for TestInstall {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn tree_snapshot(root: &Path) -> BTreeMap<PathBuf, Option<Vec<u8>>> {
        fn visit(base: &Path, directory: &Path, snapshot: &mut BTreeMap<PathBuf, Option<Vec<u8>>>) {
            let mut entries = fs::read_dir(directory)
                .unwrap()
                .map(|entry| entry.unwrap())
                .collect::<Vec<_>>();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let relative = path.strip_prefix(base).unwrap().to_path_buf();
                if entry.file_type().unwrap().is_dir() {
                    snapshot.insert(relative, None);
                    visit(base, &path, snapshot);
                } else {
                    let bytes = match fs::read(&path) {
                        Ok(bytes) => {
                            let mut snapshot = vec![0];
                            snapshot.extend(bytes);
                            snapshot
                        }
                        Err(_) => {
                            // Windows denies reads of the held operation lock. Its path and size
                            // may both be unavailable, so its stable path is the snapshot evidence.
                            vec![1]
                        }
                    };
                    snapshot.insert(relative, Some(bytes));
                }
            }
        }

        let mut snapshot = BTreeMap::new();
        visit(root, root, &mut snapshot);
        snapshot
    }

    fn active_for_trusted_release(
        install_id: Uuid,
        generation: u64,
        trusted: &TrustedRelease,
    ) -> ActiveInstanceV2 {
        ActiveInstanceV2::new(
            install_id,
            BuildChannel::Stable,
            generation,
            trusted.manifest().release.id.clone(),
            PresetId::Medium,
            trusted.evidence().release_manifest.sha256.clone(),
            trusted.manifest().runtime.java.runtime_lock_sha256.clone(),
            trusted.manifest().runtime.game.runtime_lock_sha256.clone(),
            trusted.evidence().clone(),
        )
        .unwrap()
    }

    fn empty_pending_install_plan(install_id: Uuid, channel: BuildChannel) -> ReconcilePlanV2 {
        let release_id = format!("rel_{}", "a".repeat(24));
        let target = ActiveInstanceV2::new(
            install_id,
            channel,
            1,
            release_id.clone(),
            PresetId::Medium,
            TEST_HASH_A.into(),
            TEST_HASH_C.into(),
            TEST_HASH_D.into(),
            TrustedReleaseEvidence {
                schema_version: 1,
                channel,
                roles: TrustedRoleVersions {
                    root: 1,
                    timestamp: 1,
                    snapshot: 1,
                    targets: 1,
                },
                current: TrustedTargetEvidence {
                    name: "current.json".into(),
                    length: 1,
                    sha256: TEST_HASH_B.into(),
                },
                release_manifest: TrustedTargetEvidence {
                    name: format!("release-{release_id}.json"),
                    length: 1,
                    sha256: TEST_HASH_A.into(),
                },
                java_runtime_lock: TrustedTargetEvidence {
                    name: format!("runtime-windows-x64-{TEST_HASH_C}.json"),
                    length: 1,
                    sha256: TEST_HASH_C.into(),
                },
                game_runtime_lock: TrustedTargetEvidence {
                    name: format!("game-runtime-windows-x64-{TEST_HASH_D}.json"),
                    length: 1,
                    sha256: TEST_HASH_D.into(),
                },
            },
        )
        .unwrap();
        ReconcilePlanV2 {
            schema_version: 2,
            install_id,
            operation_id: Uuid::new_v4(),
            channel,
            kind: OperationKind::Install,
            base: None,
            target,
            strict_roots: vec!["mods".into()],
            preserved_paths: Vec::new(),
            desired_files: vec![PlannedFileV2 {
                path: "mods/fragment.jar".into(),
                signed_size: 1,
                signed_sha256: TEST_HASH_B.into(),
                installed_size: 1,
                installed_sha256: TEST_HASH_B.into(),
                executable: false,
                policy: FilePolicy::Exact,
            }],
            disk_budget: DiskBudgetV2::new(0, 0, 0, 0).unwrap(),
            mutations: Vec::new(),
        }
    }

    fn pending_for_trusted_release(install_id: Uuid, trusted: &TrustedRelease) -> PendingJournalV2 {
        let mut plan = empty_pending_install_plan(install_id, BuildChannel::Stable);
        plan.target = active_for_trusted_release(install_id, 1, trusted);
        let pointer = super::super::journal::JournalPointerV2 {
            schema_version: 2,
            install_id,
            channel: BuildChannel::Stable,
            operation_id: plan.operation_id,
            plan_sha256: format!("{:x}", Sha256::digest(plan.canonical_bytes().unwrap())),
        };
        PendingJournalV2 { pointer, plan }
    }

    #[test]
    fn pending_role_evidence_is_checked_before_older_active_can_authorize_fresh_work() {
        let install_id = Uuid::new_v4();
        let active = trusted('c', 1);
        let pending_release = trusted('a', 3);
        let rolled_back_fresh = trusted('b', 2);
        let pending = pending_for_trusted_release(install_id, &pending_release);

        // An older active marker alone would accept role version 2. The pending role-3 evidence
        // must independently reject it at the pure classification boundary, before inventory,
        // downloads, staging or either stale-ready/supersede authorization can be constructed.
        assert!(active
            .evidence()
            .roles_are_monotonic_to(rolled_back_fresh.evidence()));
        assert!(classify_stale_pending_identity(&pending, &rolled_back_fresh).is_err());

        let advanced_fresh = trusted('b', 4);
        let identity = classify_stale_pending_identity(&pending, &advanced_fresh).unwrap();
        assert!(identity.is_historical());
        assert!(identity
            .validate_for(&pending.plan, &rolled_back_fresh)
            .is_err());
        assert!(identity
            .validate_for(&pending.plan, &advanced_fresh)
            .is_ok());
    }

    #[test]
    fn pending_role_rollback_fails_before_recovery_side_effects() {
        let install = TestInstall::new();
        let root = install.root();
        let install_id = root.binding().1;
        let install_root = root.install_root().to_path_buf();
        let authority = OperationAuthority {
            install_root: install_root.clone(),
            root,
            install_id,
        };
        let state_store = InstanceStateStore::new(&install_root, install_id);
        let operation_lock = state_store
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();

        // The active marker's role floor is deliberately older than the durable pending plan.
        // Comparing only active(1) -> fresh(2) would accept this rollback of pending evidence(3).
        let active_release = trusted('c', 1);
        let active = active_for_trusted_release(install_id, 1, &active_release);
        state_store.save_locked(&operation_lock, &active).unwrap();
        let pending_release = trusted('a', 3);
        let expected_pending = pending_for_trusted_release(install_id, &pending_release);
        let pointer = write_immutable_plan(
            &install_root,
            install_id,
            BuildChannel::Stable,
            &operation_lock,
            &expected_pending.plan,
        )
        .unwrap();
        assert_eq!(pointer, expected_pending.pointer);
        publish_pending(
            &install_root,
            install_id,
            BuildChannel::Stable,
            &operation_lock,
            &pointer,
        )
        .unwrap();
        let before = tree_snapshot(&install_root);

        let rolled_back_fresh = trusted('b', 2);
        let error = match settle_pending_operation(
            &authority,
            BuildChannel::Stable,
            &rolled_back_fresh,
            &state_store,
            &operation_lock,
        ) {
            Err(error) => error,
            Ok(_) => panic!("pending role rollback unexpectedly reached recovery"),
        };

        assert!(matches!(
            error,
            CoordinatorError::Failed(message)
                if message.contains("neither matches nor safely advances")
        ));
        assert_eq!(tree_snapshot(&install_root), before);
        assert_eq!(
            detect_pending(
                &install_root,
                install_id,
                BuildChannel::Stable,
                &operation_lock,
            )
            .unwrap(),
            Some(expected_pending)
        );
        assert_eq!(
            state_store.load_locked(&operation_lock).unwrap(),
            Some(active)
        );
    }

    #[test]
    fn progress_identity_matches_transport_redaction() {
        let sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        assert_eq!(
            download_object_identity(sha),
            DownloadObjectIdentity::from_sha256(sha).unwrap().as_str()
        );
    }

    #[test]
    fn progress_charge_excludes_complete_cached_objects() {
        let mut charges = BTreeMap::new();
        charges.insert("cas:cached".into(), 0);
        charges.insert("cas:network".into(), 100);
        assert_eq!(charged_persisted(&charges, "cas:cached", 900), 0);
        assert_eq!(charged_persisted(&charges, "cas:network", 40), 40);
        assert_eq!(charged_persisted(&charges, "cas:network", 140), 100);
        assert_eq!(charged_persisted(&charges, "cas:unknown", 50), 0);
    }

    #[test]
    fn download_progress_keeps_network_total_and_disk_reserve_distinct() {
        let install = TestInstall::new();
        let root = install.root();
        let identity = DownloadObjectIdentity::from_sha256(TEST_HASH_A).unwrap();
        let mut charges = BTreeMap::new();
        charges.insert(identity.as_str().to_owned(), 100);
        let captured = Arc::new(Mutex::new(None));
        let captured_for_observer = Arc::clone(&captured);
        let observer: ProgressObserver = Arc::new(move |progress| {
            *captured_for_observer.lock().unwrap() = Some(progress);
        });
        let download = CoordinatorDownloadObserver::new(
            observer,
            &root,
            BuildPhase::Downloading,
            100,
            1_000,
            charges,
        );

        download.observe(&DownloadProgressEvent {
            object: identity,
            total_bytes: 100,
            persisted_bytes: 25,
            delta_bytes: 25,
            phase: DownloadProgressPhase::Bytes,
        });

        let progress = captured.lock().unwrap().clone().unwrap();
        assert_eq!(progress.downloaded_bytes, 25);
        assert_eq!(progress.total_bytes, 100);
        assert_eq!(progress.disk_required_bytes, 1_000);
    }

    #[test]
    fn aggregate_handles_resume_reset_decrease_and_speed() {
        let started = Instant::now();
        let mut aggregate = DownloadAggregate {
            persisted: BTreeMap::new(),
            last_sample: started,
            last_total: 0,
            speed: 0,
        };
        let (total, speed) =
            aggregate.record("a".into(), 50, 100, started + Duration::from_secs(1));
        assert_eq!((total, speed), (50, 50));
        let (total, speed) = aggregate.record("a".into(), 0, 100, started + Duration::from_secs(2));
        assert_eq!((total, speed), (0, 0));
        let (total, speed) =
            aggregate.record("a".into(), 20, 100, started + Duration::from_secs(3));
        assert_eq!((total, speed), (20, 20));
        let (total, _) = aggregate.record("b".into(), 30, 100, started + Duration::from_secs(4));
        assert_eq!(total, 50);
    }

    #[test]
    fn cancellation_fans_out_and_remains_observable() {
        let cancellation = CoordinatorCancellation::default();
        assert!(cancellation.check().is_ok());
        cancellation.cancel();
        assert!(matches!(
            cancellation.check(),
            Err(CoordinatorError::Cancelled)
        ));
        assert!(cancellation.spark.is_cancelled());
        assert!(cancellation.official.is_cancelled());
        assert!(require_staging_active(&cancellation).is_err());
    }

    #[test]
    fn download_failure_precedes_cancellation_independent_of_completion_order() {
        for cancelled_first in [false, true] {
            let mut terminal = DownloadTerminalError::default();
            if cancelled_first {
                terminal.record("cas:bbbb".into(), CoordinatorError::Cancelled);
            }
            terminal.record(
                "cas:aaaa".into(),
                CoordinatorError::Failed("integrity failure".into()),
            );
            if !cancelled_first {
                terminal.record("cas:bbbb".into(), CoordinatorError::Cancelled);
            }
            assert!(matches!(
                terminal.into_error(),
                Some(CoordinatorError::Failed(message)) if message == "integrity failure"
            ));
        }
        let mut cancellation_only = DownloadTerminalError::default();
        cancellation_only.record("cas:aaaa".into(), CoordinatorError::Cancelled);
        assert!(matches!(
            cancellation_only.into_error(),
            Some(CoordinatorError::Cancelled)
        ));
    }

    #[test]
    fn tuf_and_cas_share_the_same_native_auth_failure_mapping() {
        use crate::auth::AuthError;

        assert!(matches!(
            map_access_token_error(AuthError::SignedOut),
            CoordinatorError::Auth(_)
        ));
        assert!(matches!(
            map_token_provider_error(AuthError::SignedOut),
            CasError::Authentication
        ));
        for error in [
            AuthError::CredentialChanged,
            AuthError::SessionChanged,
            AuthError::Api("temporary transport failure".into()),
        ] {
            assert!(matches!(
                map_access_token_error(error),
                CoordinatorError::Failed(_)
            ));
        }
        for error in [
            AuthError::CredentialChanged,
            AuthError::SessionChanged,
            AuthError::Api("temporary transport failure".into()),
        ] {
            assert!(matches!(
                map_token_provider_error(error),
                CasError::Failed(_)
            ));
        }
    }

    #[test]
    fn download_failures_use_stable_object_identity_not_completion_order() {
        for reverse_completion in [false, true] {
            let mut terminal = DownloadTerminalError::default();
            let failures = [
                ("cas:bbbb", "second identity failure"),
                ("cas:aaaa", "first identity failure"),
            ];
            let order: &[usize] = if reverse_completion { &[1, 0] } else { &[0, 1] };
            for index in order {
                let (identity, error) = &failures[*index];
                terminal.record(
                    identity.to_string(),
                    CoordinatorError::Failed((*error).into()),
                );
            }
            assert!(matches!(
                terminal.into_error(),
                Some(CoordinatorError::Failed(message)) if message == "first identity failure"
            ));
        }
    }

    #[test]
    fn duplicate_download_failure_identity_uses_stable_type_and_detail_priority() {
        for reverse_completion in [false, true] {
            let mut terminal = DownloadTerminalError::default();
            let order: &[u8] = if reverse_completion { &[1, 0] } else { &[0, 1] };
            for kind in order {
                let error = match kind {
                    0 => CoordinatorError::Failed("integrity-z".into()),
                    1 => CoordinatorError::Auth("authentication-a".into()),
                    _ => unreachable!(),
                };
                terminal.record("cas:aaaa".into(), error);
            }
            assert!(matches!(
                terminal.into_error(),
                Some(CoordinatorError::Auth(message)) if message == "authentication-a"
            ));
        }
    }

    #[test]
    fn durable_recovery_uses_an_independent_non_cancelled_control() {
        let user = CoordinatorCancellation::default();
        let recovery = CoordinatorCancellation::default();
        user.cancel();

        assert!(select_attempt_cancellation(&user, &recovery, true)
            .check()
            .is_ok());
        assert!(matches!(
            select_attempt_cancellation(&user, &recovery, false).check(),
            Err(CoordinatorError::Cancelled)
        ));
        assert!(!recovery.spark.is_cancelled());
        assert!(!recovery.official.is_cancelled());
    }

    #[tokio::test]
    async fn caller_cancellation_after_generation_creation_does_not_abandon_refresh_cleanup() {
        use tokio::sync::oneshot;

        let state_root =
            std::env::temp_dir().join(format!("fragment-tuf-cancel-{}", Uuid::new_v4()));
        let generation = state_root
            .join("generations")
            .join(Uuid::new_v4().to_string());
        let refresh_generation = generation.clone();
        let (created_tx, created_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let (cleaned_tx, cleaned_rx) = oneshot::channel();
        let refresh = async move {
            fs::create_dir_all(&refresh_generation).unwrap();
            created_tx.send(()).unwrap();
            release_rx.await.unwrap();
            fs::remove_dir_all(&refresh_generation).unwrap();
            cleaned_tx.send(()).unwrap();
            Ok::<TrustedRelease, CoordinatorError>(trusted('a', 1))
        };

        let cancellation = CoordinatorCancellation::default();
        let operation_cancellation = cancellation.clone();
        let operation = tokio::spawn(async move {
            finish_tuf_refresh_before_cancellation(
                BuildChannel::Stable,
                &operation_cancellation,
                refresh,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), created_rx)
            .await
            .expect("refresh must create its generation deterministically")
            .unwrap();

        cancellation.cancel();
        tokio::task::yield_now().await;
        assert!(
            !operation.is_finished(),
            "the production worker must retain the TUF transaction after cancellation"
        );
        assert!(generation.is_dir());

        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), cleaned_rx)
            .await
            .expect("detached refresh must finish its cleanup")
            .unwrap();
        let result = tokio::time::timeout(Duration::from_secs(1), operation)
            .await
            .expect("caller cancellation must return after refresh cleanup")
            .unwrap();
        assert!(matches!(result, Err(CoordinatorError::Cancelled)));
        assert!(fs::symlink_metadata(&generation).is_err());
        let _ = fs::remove_dir_all(state_root);
    }

    #[tokio::test]
    async fn completed_tuf_failure_precedes_simultaneous_cancellation() {
        let task = tokio::spawn(async {
            Err::<TrustedRelease, CoordinatorError>(CoordinatorError::Auth("expired".into()))
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("synthetic TUF task must complete");

        let cancellation = CoordinatorCancellation::default();
        cancellation.cancel();
        assert!(matches!(
            wait_for_tuf_refresh_task_or_cancellation(&cancellation, task).await,
            Err(CoordinatorError::Auth(_))
        ));
    }

    #[tokio::test]
    async fn tuf_worker_join_failure_is_generic_and_redacted() {
        let task = tokio::spawn(std::future::pending::<
            Result<TrustedRelease, CoordinatorError>,
        >());
        task.abort();
        let cancellation = CoordinatorCancellation::default();
        assert!(matches!(
            wait_for_tuf_refresh_task_or_cancellation(&cancellation, task).await,
            Err(CoordinatorError::Failed(message))
                if message == "TUF refresh worker terminated before completion"
                    && !message.contains("token")
        ));
    }

    #[tokio::test]
    async fn inspection_tuf_transaction_rotates_exact_rejected_token_once() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        for second_succeeds in [true, false] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let rotations = Arc::new(AtomicUsize::new(0));
            let observed = Arc::new(Mutex::new(Vec::<String>::new()));
            let refresh_attempts = Arc::clone(&attempts);
            let refresh_observed = Arc::clone(&observed);
            let rotate_count = Arc::clone(&rotations);

            let result = refresh_tuf_with_single_auth_retry(
                BuildChannel::Stable,
                NativeAccessToken::for_test("tuf-stale-token"),
                move |token| {
                    let attempts = Arc::clone(&refresh_attempts);
                    let observed = Arc::clone(&refresh_observed);
                    async move {
                        observed.lock().unwrap().push(token.expose().to_owned());
                        let attempt = attempts.fetch_add(1, AtomicOrdering::AcqRel);
                        let result = if attempt == 0 || !second_succeeds {
                            Err(TufRefreshError::Authentication(
                                "spark_session_invalid".into(),
                            ))
                        } else {
                            Ok(trusted('a', 1))
                        };
                        (token, result)
                    }
                },
                move |rejected| {
                    let rotations = Arc::clone(&rotate_count);
                    async move {
                        assert_eq!(rejected.expose(), "tuf-stale-token");
                        rotations.fetch_add(1, AtomicOrdering::AcqRel);
                        Ok(NativeAccessToken::for_test("tuf-rotated-token"))
                    }
                },
            )
            .await;

            assert_eq!(attempts.load(AtomicOrdering::Acquire), 2);
            assert_eq!(rotations.load(AtomicOrdering::Acquire), 1);
            assert_eq!(
                observed.lock().unwrap().as_slice(),
                ["tuf-stale-token", "tuf-rotated-token"]
            );
            if second_succeeds {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(CoordinatorError::Auth(_))));
            }
        }
    }

    #[tokio::test]
    async fn cancellable_operation_tuf_transaction_uses_the_same_exact_single_retry() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        for second_succeeds in [true, false] {
            let attempts = Arc::new(AtomicUsize::new(0));
            let rotations = Arc::new(AtomicUsize::new(0));
            let observed = Arc::new(Mutex::new(Vec::<String>::new()));
            let refresh_attempts = Arc::clone(&attempts);
            let refresh_observed = Arc::clone(&observed);
            let rotate_count = Arc::clone(&rotations);
            let transaction = async move {
                refresh_tuf_with_single_auth_retry(
                    BuildChannel::Stable,
                    NativeAccessToken::for_test("operation-stale-token"),
                    move |token| {
                        let attempts = Arc::clone(&refresh_attempts);
                        let observed = Arc::clone(&refresh_observed);
                        async move {
                            observed.lock().unwrap().push(token.expose().to_owned());
                            let attempt = attempts.fetch_add(1, AtomicOrdering::AcqRel);
                            let result = if attempt == 0 || !second_succeeds {
                                Err(TufRefreshError::Authentication(
                                    "spark_session_invalid".into(),
                                ))
                            } else {
                                Ok(trusted('b', 2))
                            };
                            (token, result)
                        }
                    },
                    move |rejected| {
                        let rotations = Arc::clone(&rotate_count);
                        async move {
                            assert_eq!(rejected.expose(), "operation-stale-token");
                            rotations.fetch_add(1, AtomicOrdering::AcqRel);
                            Ok(NativeAccessToken::for_test("operation-rotated-token"))
                        }
                    },
                )
                .await
            };
            let cancellation = CoordinatorCancellation::default();
            let result = finish_tuf_refresh_before_cancellation(
                BuildChannel::Stable,
                &cancellation,
                transaction,
            )
            .await;

            assert_eq!(attempts.load(AtomicOrdering::Acquire), 2);
            assert_eq!(rotations.load(AtomicOrdering::Acquire), 1);
            assert_eq!(
                observed.lock().unwrap().as_slice(),
                ["operation-stale-token", "operation-rotated-token"]
            );
            if second_succeeds {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(CoordinatorError::Auth(_))));
            }
        }
    }

    #[tokio::test]
    async fn tuf_non_auth_failure_never_rotates_token() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        let rotations = Arc::new(AtomicUsize::new(0));
        let rotate_count = Arc::clone(&rotations);
        let result = refresh_tuf_with_single_auth_retry(
            BuildChannel::Stable,
            NativeAccessToken::for_test("tuf-forbidden-token"),
            |token| async move {
                (
                    token,
                    Err(TufRefreshError::Forbidden(
                        "spark_subscription_required".into(),
                    )),
                )
            },
            move |_| {
                let rotations = Arc::clone(&rotate_count);
                async move {
                    rotations.fetch_add(1, AtomicOrdering::AcqRel);
                    Ok(NativeAccessToken::for_test("must-not-be-used"))
                }
            },
        )
        .await;

        assert_eq!(rotations.load(AtomicOrdering::Acquire), 0);
        assert!(matches!(
            result,
            Err(CoordinatorError::SubscriptionRequired(_))
        ));
    }

    #[tokio::test]
    async fn tuf_rotation_persistence_failure_precedes_cancellation() {
        use tokio::sync::oneshot;

        let (rotation_started_tx, rotation_started_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let transaction = async move {
            refresh_tuf_with_single_auth_retry(
                BuildChannel::Stable,
                NativeAccessToken::for_test("tuf-rejected-token"),
                |token| async move {
                    (
                        token,
                        Err(TufRefreshError::Authentication(
                            "spark_session_invalid".into(),
                        )),
                    )
                },
                move |rejected| async move {
                    assert_eq!(rejected.expose(), "tuf-rejected-token");
                    rotation_started_tx.send(()).unwrap();
                    release_rx.await.unwrap();
                    Err(crate::auth::AuthError::Credentials(
                        "credential persistence failed".into(),
                    ))
                },
            )
            .await
        };
        let cancellation = CoordinatorCancellation::default();
        let operation_cancellation = cancellation.clone();
        let operation = tokio::spawn(async move {
            finish_tuf_refresh_before_cancellation(
                BuildChannel::Stable,
                &operation_cancellation,
                transaction,
            )
            .await
        });
        rotation_started_rx.await.unwrap();

        cancellation.cancel();
        tokio::task::yield_now().await;
        assert!(!operation.is_finished());
        release_tx.send(()).unwrap();
        assert!(matches!(
            operation.await.unwrap(),
            Err(CoordinatorError::Failed(message))
                if message.contains("credential persistence failed")
        ));
    }

    #[tokio::test]
    async fn token_rotation_finishes_persistence_before_cancellation_is_reported() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use tokio::sync::Notify;

        const ROTATED: &str = "rotated-refresh-backed-access-token";
        let cancellation = CoordinatorCancellation::default();
        let transport = cancellation.spark.clone();
        let started = Arc::new(AtomicBool::new(false));
        let persisted = Arc::new(Mutex::new(None::<String>));
        let release = Arc::new(Notify::new());
        let refresh_started = Arc::clone(&started);
        let refresh_persisted = Arc::clone(&persisted);
        let refresh_release = Arc::clone(&release);
        let refresh = async move {
            refresh_started.store(true, AtomicOrdering::Release);
            refresh_release.notified().await;
            *refresh_persisted.lock().unwrap() = Some(ROTATED.into());
            Ok(NativeAccessToken::for_test(ROTATED))
        };
        let operation =
            finish_token_refresh_before_cancellation(&cancellation, &transport, refresh);
        let cancel = async {
            while !started.load(AtomicOrdering::Acquire) {
                tokio::task::yield_now().await;
            }
            cancellation.cancel();
            assert!(persisted.lock().unwrap().is_none());
            release.notify_one();
        };
        let (result, ()) = tokio::join!(operation, cancel);

        assert!(matches!(result, Err(CasError::Cancelled)));
        assert_eq!(persisted.lock().unwrap().as_deref(), Some(ROTATED));
    }

    #[tokio::test]
    async fn token_refresh_failure_precedes_concurrent_cancellation() {
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
        use tokio::sync::Notify;

        let cancellation = CoordinatorCancellation::default();
        let transport = cancellation.spark.clone();
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(Notify::new());
        let refresh_started = Arc::clone(&started);
        let refresh_release = Arc::clone(&release);
        let refresh = async move {
            refresh_started.store(true, AtomicOrdering::Release);
            refresh_release.notified().await;
            Err(CasError::Failed("credential persistence failed".into()))
        };
        let operation =
            finish_token_refresh_before_cancellation(&cancellation, &transport, refresh);
        let cancel = async {
            while !started.load(AtomicOrdering::Acquire) {
                tokio::task::yield_now().await;
            }
            cancellation.cancel();
            release.notify_one();
        };
        let (result, ()) = tokio::join!(operation, cancel);

        assert!(matches!(
            result,
            Err(CasError::Failed(message)) if message == "credential persistence failed"
        ));
    }

    #[test]
    fn game_generation_cancellation_preserves_the_cancelled_classification() {
        assert!(matches!(
            map_generation_error(super::super::game_generation::GameGenerationError::Cancelled),
            CoordinatorError::Cancelled
        ));
        assert!(matches!(
            map_generation_error(
                super::super::game_generation::GameGenerationError::
                    AppliedButDurabilityUnconfirmed {
                        destination: "runtime/minecraft/generations/example".into(),
                        detail: "sync failed".into(),
                    },
            ),
            CoordinatorError::Failed(_)
        ));
        assert!(matches!(
            map_processor_execution_error(ProcessorExecutionError::Cancelled),
            CoordinatorError::Cancelled
        ));
        assert!(matches!(
            map_processor_execution_error(ProcessorExecutionError::Failed(
                "NeoForge processor execution was cancelled".to_owned(),
            )),
            CoordinatorError::Failed(_)
        ));
        assert!(matches!(
            map_reconcile_executor_error(ReconcileExecutorErrorV2::InsufficientSpace {
                required_bytes: 10,
                available_bytes: 9,
            }),
            CoordinatorError::DiskInsufficient {
                available: 9,
                required: 10,
            }
        ));
        let cancelled = CoordinatorCancellation::default();
        cancelled.cancel();
        assert!(matches!(
            map_staging_writer_error(ReconcileExecutorErrorV2::Cancelled),
            CoordinatorError::Cancelled
        ));
        assert!(matches!(
            map_staging_writer_error(ReconcileExecutorErrorV2::InsufficientSpace {
                required_bytes: 11,
                available_bytes: 7,
            }),
            CoordinatorError::DiskInsufficient {
                available: 7,
                required: 11,
            }
        ));
        assert!(matches!(
            map_staging_writer_error(ReconcileExecutorErrorV2::Filesystem(
                "durability failure".into()
            )),
            CoordinatorError::Failed(_)
        ));
        assert!(matches!(
            map_tuf_refresh_error(
                TufRefreshError::Authentication("expired".into()),
                BuildChannel::Stable,
            ),
            CoordinatorError::Auth(_)
        ));
        assert!(matches!(
            map_tuf_refresh_error(
                TufRefreshError::Forbidden("spark_subscription_required".into()),
                BuildChannel::Dev,
            ),
            CoordinatorError::SubscriptionRequired(_)
        ));
        assert!(matches!(
            map_tuf_refresh_error(
                TufRefreshError::Forbidden("spark_dev_access_required".into()),
                BuildChannel::Stable,
            ),
            CoordinatorError::DevForbidden(_)
        ));
        assert!(matches!(
            map_tuf_refresh_error(
                TufRefreshError::Forbidden("spark_access_denied".into()),
                BuildChannel::Stable,
            ),
            CoordinatorError::SubscriptionRequired(_)
        ));
        assert!(matches!(
            map_tuf_refresh_error(
                TufRefreshError::Forbidden("spark_access_denied".into()),
                BuildChannel::Dev,
            ),
            CoordinatorError::DevForbidden(_)
        ));
        assert!(matches!(
            map_tuf_refresh_error(
                TufRefreshError::LauncherUpdateRequired("2.3.4".into()),
                BuildChannel::Stable,
            ),
            CoordinatorError::LauncherUpdateRequired(message) if message.contains("2.3.4")
        ));
        assert!(matches!(
            map_tuf_refresh_error(
                TufRefreshError::Failed("integrity".into()),
                BuildChannel::Stable,
            ),
            CoordinatorError::Failed(_)
        ));
        assert!(matches!(
            map_cas_error(
                super::super::cas::CasError::Authentication,
                BuildChannel::Dev,
            ),
            CoordinatorError::Auth(_)
        ));
        assert!(matches!(
            map_cas_error(super::super::cas::CasError::Forbidden, BuildChannel::Stable,),
            CoordinatorError::SubscriptionRequired(_)
        ));
        assert!(matches!(
            map_cas_error(super::super::cas::CasError::Forbidden, BuildChannel::Dev,),
            CoordinatorError::DevForbidden(_)
        ));
    }

    #[test]
    fn post_recovery_attempt_rotates_to_a_distinct_v4_operation_id() {
        let previous = Uuid::new_v4();
        let next = rotate_attempt_operation_id(previous);
        assert_ne!(next, previous);
        assert_eq!(next.get_version(), Some(uuid::Version::Random));
    }

    #[test]
    fn policy_reset_removes_only_that_policies_setting_ids() {
        use super::super::contracts::{
            MutableSettingField, MutableSettingsFile, MutableValidator, SettingScope,
            SettingSelector, SettingValueRule,
        };
        let policy = MutableSettingsFile {
            path: "options.txt".into(),
            validator: MutableValidator::MinecraftOptionsV1,
            max_bytes: 1024,
            unknown_key_policy: "drop".into(),
            duplicate_key_policy: "last".into(),
            invalid_value_policy: "default".into(),
            fields: vec![MutableSettingField {
                setting_id: "graphics".into(),
                scope: SettingScope::Profile,
                selector: SettingSelector::Exact {
                    key: "graphicsMode".into(),
                },
                value: SettingValueRule::String {
                    max_length: 16,
                    allowed_values: None,
                    allowed_prefixes: None,
                },
                renamed_from: Vec::new(),
            }],
        };
        let mut state = super::super::mutable::MutableSettingsState::new();
        state.profile.insert("graphics".into(), BTreeMap::new());
        state.profile.insert("controls".into(), BTreeMap::new());
        state
            .presets
            .entry("high".into())
            .or_default()
            .insert("graphics".into(), BTreeMap::new());
        reset_mutable_policy_state(&mut state, &policy);
        assert!(!state.profile.contains_key("graphics"));
        assert!(state.profile.contains_key("controls"));
        assert!(!state.presets["high"].contains_key("graphics"));
    }

    #[tokio::test]
    async fn bounded_download_stream_never_exceeds_limit() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        let active = Arc::new(AtomicUsize::new(0));
        let maximum = Arc::new(AtomicUsize::new(0));
        let jobs = (0..32).map(|_| {
            let active = Arc::clone(&active);
            let maximum = Arc::clone(&maximum);
            async move {
                let now = active.fetch_add(1, AtomicOrdering::AcqRel) + 1;
                maximum.fetch_max(now, AtomicOrdering::AcqRel);
                tokio::task::yield_now().await;
                active.fetch_sub(1, AtomicOrdering::AcqRel);
                Ok::<(), ()>(())
            }
        });
        let mut completed = 0_usize;
        run_bounded_download_scheduler(jobs, DOWNLOAD_CONCURRENCY, |result| {
            result.expect("synthetic download succeeds");
            completed += 1;
            true
        })
        .await;
        assert_eq!(completed, 32);
        assert!(maximum.load(AtomicOrdering::Acquire) <= DOWNLOAD_CONCURRENCY);
        assert!(maximum.load(AtomicOrdering::Acquire) > 1);
    }

    #[tokio::test]
    async fn first_failure_stops_admission_but_drains_started_failures_deterministically() {
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
        use tokio::sync::Notify;

        for completion_order in [[0_usize, 1_usize], [1, 0]] {
            let constructed = Arc::new(AtomicUsize::new(0));
            let token_requests = Arc::new(AtomicUsize::new(0));
            let started = Arc::new(AtomicUsize::new(0));
            let completed = Arc::new(AtomicUsize::new(0));
            let failed = Arc::new(AtomicUsize::new(0));
            let gates = Arc::new((0..17).map(|_| Notify::new()).collect::<Vec<_>>());
            let release_started = Arc::clone(&started);
            let release_completed = Arc::clone(&completed);
            let release_failed = Arc::clone(&failed);
            let release_gates = Arc::clone(&gates);
            let release = async move {
                while release_started.load(AtomicOrdering::Acquire) < DOWNLOAD_CONCURRENCY {
                    tokio::task::yield_now().await;
                }
                for index in 2..DOWNLOAD_CONCURRENCY {
                    release_gates[index].notify_one();
                }
                release_gates[completion_order[0]].notify_one();
                let first_failure_bit = 1_usize << completion_order[0];
                while release_failed.load(AtomicOrdering::Acquire) & first_failure_bit == 0 {
                    tokio::task::yield_now().await;
                }
                release_gates[completion_order[1]].notify_one();
                while release_completed.load(AtomicOrdering::Acquire) < DOWNLOAD_CONCURRENCY {
                    tokio::task::yield_now().await;
                }
            };
            let mut terminal = DownloadTerminalError::default();
            let identities = (0..17).collect::<Vec<_>>();
            let schedule = async {
                for wave in identities.chunks(DOWNLOAD_CONCURRENCY) {
                    let jobs = wave.iter().copied().map(|index| {
                        constructed.fetch_add(1, AtomicOrdering::AcqRel);
                        let token_requests = Arc::clone(&token_requests);
                        let started = Arc::clone(&started);
                        let completed = Arc::clone(&completed);
                        let failed = Arc::clone(&failed);
                        let gates = Arc::clone(&gates);
                        async move {
                            token_requests.fetch_add(1, AtomicOrdering::AcqRel);
                            started.fetch_add(1, AtomicOrdering::AcqRel);
                            gates[index].notified().await;
                            completed.fetch_add(1, AtomicOrdering::AcqRel);
                            match index {
                                0 => {
                                    failed.fetch_or(1, AtomicOrdering::AcqRel);
                                    Err((
                                        "cas:aaaa".to_owned(),
                                        CoordinatorError::Failed("first identity failure".into()),
                                    ))
                                }
                                1 => {
                                    failed.fetch_or(2, AtomicOrdering::AcqRel);
                                    Err((
                                        "cas:bbbb".to_owned(),
                                        CoordinatorError::Failed("second identity failure".into()),
                                    ))
                                }
                                _ => Ok(()),
                            }
                        }
                    });
                    run_bounded_download_scheduler(jobs, wave.len(), |result| {
                        if let Err((identity, error)) = result {
                            terminal.record(identity, error);
                        }
                        terminal.is_empty()
                    })
                    .await;
                    if !terminal.is_empty() {
                        break;
                    }
                }
            };
            tokio::join!(schedule, release);

            assert_eq!(
                constructed.load(AtomicOrdering::Acquire),
                DOWNLOAD_CONCURRENCY
            );
            assert_eq!(
                token_requests.load(AtomicOrdering::Acquire),
                DOWNLOAD_CONCURRENCY
            );
            assert_eq!(started.load(AtomicOrdering::Acquire), DOWNLOAD_CONCURRENCY);
            assert_eq!(
                completed.load(AtomicOrdering::Acquire),
                DOWNLOAD_CONCURRENCY
            );
            assert!(matches!(
                terminal.into_error(),
                Some(CoordinatorError::Failed(message)) if message == "first identity failure"
            ));
        }
    }

    #[test]
    fn fail_closed_anchors_never_fall_back_to_disk() {
        let anchors = TufRootAnchors::production_fail_closed();
        assert!(matches!(
            anchors.for_channel(BuildChannel::Stable),
            Err(CoordinatorError::LauncherUpdateRequired(_))
        ));
        assert!(matches!(
            anchors.for_channel(BuildChannel::Dev),
            Err(CoordinatorError::LauncherUpdateRequired(_))
        ));
        let test = TufRootAnchors::for_test(vec![1], vec![2]);
        assert_eq!(
            test.for_channel(BuildChannel::Stable).unwrap().as_ref(),
            &[1]
        );
        assert_eq!(test.for_channel(BuildChannel::Dev).unwrap().as_ref(), &[2]);
    }

    #[test]
    fn snapshot_maps_all_primary_actions() {
        for (state, expected) in [
            (PlannedBuildState::Download, PrimaryAction::Download),
            (PlannedBuildState::Update, PrimaryAction::Update),
            (PlannedBuildState::Repair, PrimaryAction::Repair),
            (PlannedBuildState::Ready, PrimaryAction::Play),
        ] {
            let snapshot = CoordinatorSnapshot {
                state,
                installed_release_id: None,
                available_release_id: "release".into(),
                disk_free_bytes: 0,
                disk_required_bytes: 0,
                message: String::new(),
            };
            assert_eq!(snapshot.phase_action().1, expected);
        }
    }

    #[test]
    fn install_wide_lock_is_identity_stable_and_contended() {
        let install = TestInstall::new();
        let root = install.root();
        let lock = CoordinatorOperationLock::acquire(&root).unwrap();
        lock.revalidate(&root).unwrap();
        let relative = RelativeManagedPath::new("state/coordinator-v2.lock").unwrap();
        let competing = open_or_create_lock_file(root.install_root(), &relative).unwrap();
        assert_eq!(competing.info().identity, lock.file.info().identity);
        assert!(competing.file().try_lock_exclusive().is_err());
    }

    #[test]
    fn pre_cancelled_caller_settles_pending_before_cancelling_clean_work() {
        let install = TestInstall::new();
        let root = install.root();
        let install_id = root.binding().1;
        let authority = OperationAuthority {
            install_root: root.install_root().to_path_buf(),
            root,
            install_id,
        };
        let state_store = InstanceStateStore::new(&authority.install_root, install_id);
        let seed_lock = state_store
            .acquire_operation_lock(BuildChannel::Stable)
            .unwrap();
        let plan = empty_pending_install_plan(install_id, BuildChannel::Stable);
        let pointer = write_immutable_plan(
            &authority.install_root,
            install_id,
            BuildChannel::Stable,
            &seed_lock,
            &plan,
        )
        .unwrap();
        publish_pending(
            &authority.install_root,
            install_id,
            BuildChannel::Stable,
            &seed_lock,
            &pointer,
        )
        .unwrap();
        drop(seed_lock);

        let held = CoordinatorOperationLock::acquire(&authority.root).unwrap();
        let caller = CoordinatorCancellation::default();
        let recovery = CoordinatorCancellation::default();
        caller.cancel();
        let released = Arc::new(AtomicBool::new(false));
        let released_by_holder = Arc::clone(&released);

        let release = thread::spawn(move || {
            thread::sleep(COORDINATOR_LOCK_POLL * 2);
            released_by_holder.store(true, Ordering::Release);
            drop(held);
        });

        // Exercise the production ordering seam: lock contention is resolved before the actual
        // journal is classified, and the pre-cancelled caller cannot suppress pending recovery.
        let InitialAttemptClassification {
            install_lock,
            channel_lock,
            pending,
        } = acquire_initial_attempt_classification(
            &authority,
            &state_store,
            BuildChannel::Stable,
            &caller,
            &recovery,
        )
        .unwrap();
        assert!(pending);
        assert!(released.load(Ordering::Acquire));
        assert!(complete_pending_rolled_back(
            &authority.install_root,
            install_id,
            BuildChannel::Stable,
            &channel_lock,
            &pointer,
            RollbackCompletionAuthorizationV2::for_completed_plan_test(&plan),
        )
        .unwrap());
        drop(channel_lock);
        drop(install_lock);
        release.join().unwrap();

        // Once exact settlement leaves no pending journal, the same production seam observes the
        // original caller cancellation before clean-state maintenance or fresh auth/network work.
        assert!(matches!(
            acquire_initial_attempt_classification(
                &authority,
                &state_store,
                BuildChannel::Stable,
                &caller,
                &recovery,
            ),
            Err(CoordinatorError::Cancelled)
        ));
    }
}
