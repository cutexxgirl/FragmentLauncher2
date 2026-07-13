use super::{
    contracts::{GameRuntimeLock, RuntimeLock, MAX_GAME_RUNTIME_LOCK_BYTES},
    managed_fs::{
        inspect_managed_node_nofollow, remove_bounded_managed_directory_tree,
        remove_verified_managed_file, FileDigests, ManagedDirectoryRemovalLimits, ManagedNodeKind,
        RelativeManagedPath,
    },
    release::{CurrentPointer, ReleaseManifest},
    storage::{
        inspect_existing_ancestors, open_or_create_regular_single_link, open_regular_single_link,
        replace_file,
    },
    tuf_transport::{SparkTufHttpError, SparkTufTransport},
    types::BuildChannel,
};
use fs2::FileExt;
use futures_util::StreamExt;
use jiff::Timestamp;
use semver::Version;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    error::Error as StdError,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tough::{ExpirationEnforcement, Limits, Repository, RepositoryLoader, TargetName};
use url::Url;
use uuid::Uuid;

const SPARK_ORIGIN: &str = "https://fragmc.ru/";
const MAX_TRUSTED_ROOT_BYTES: usize = 512 * 1024;
const MAX_RUNTIME_LOCK_BYTES: usize = 4 * 1024 * 1024;
const ACTIVE_STATE_LIMIT: usize = 16 * 1024;
const LATEST_KNOWN_TIME_LIMIT: usize = 64 * 1024;
const ACTIVE_STATE_SCHEMA_VERSION: u8 = 2;
const ACTIVE_FILE: &str = "active.json";
const RECOVERY_FILE: &str = "recovery.json";
const CLOCK_FILE: &str = "clock.json";
const CLOCK_RECOVERY_FILE: &str = "clock-recovery.json";
const CLOCK_STATE_LIMIT: usize = 4 * 1024;
const TRUST_FILE: &str = "trust.json";
const TRUST_RECOVERY_FILE: &str = "trust-recovery.json";
const TRUST_STATE_LIMIT: usize = 4 * 1024;
const GENERATION_LIFECYCLE_DIRECTORY: &str = "generation-lifecycle";
const GENERATION_LIFECYCLE_LIMIT: usize = 8 * 1024;
const GENERATION_LIFECYCLE_NAMESPACE_LIMIT: usize = 128;
const PRETRUST_ORPHAN_GENERATION_LIMIT: usize = 8;
const TUF_GENERATION_NAMESPACE_LIMIT: usize = 64;
const TUF_GENERATION_REMOVAL_LIMITS: ManagedDirectoryRemovalLimits =
    ManagedDirectoryRemovalLimits {
        max_entries: 64,
        max_allocated_bytes: 32 * 1024 * 1024,
        max_depth: 2,
    };
const DATASTORE_FILES: [&str; 5] = [
    "root.json",
    "timestamp.json",
    "snapshot.json",
    "targets.json",
    "latest_known_time.json",
];

const TRUSTED_RELEASE_EVIDENCE_SCHEMA_VERSION: u8 = 1;

#[derive(Debug)]
pub struct TrustedRelease {
    channel: BuildChannel,
    current: CurrentPointer,
    manifest: ReleaseManifest,
    runtime_lock: RuntimeLock,
    game_runtime_lock: GameRuntimeLock,
    tuf_root_version: u64,
    evidence: TrustedReleaseEvidence,
}

impl TrustedRelease {
    pub(super) fn channel(&self) -> BuildChannel {
        self.channel
    }

    pub(super) fn current(&self) -> &CurrentPointer {
        &self.current
    }

    pub(super) fn manifest(&self) -> &ReleaseManifest {
        &self.manifest
    }

    pub(super) fn runtime_lock(&self) -> &RuntimeLock {
        &self.runtime_lock
    }

    pub(super) fn game_runtime_lock(&self) -> &GameRuntimeLock {
        &self.game_runtime_lock
    }

    pub(super) fn tuf_root_version(&self) -> u64 {
        self.tuf_root_version
    }

    pub(super) fn evidence(&self) -> &TrustedReleaseEvidence {
        &self.evidence
    }

    #[cfg(test)]
    pub(super) fn new_for_test(
        channel: BuildChannel,
        current: CurrentPointer,
        manifest: ReleaseManifest,
        runtime_lock: RuntimeLock,
        game_runtime_lock: GameRuntimeLock,
        tuf_root_version: u64,
        evidence: TrustedReleaseEvidence,
    ) -> Self {
        Self {
            channel,
            current,
            manifest,
            runtime_lock,
            game_runtime_lock,
            tuf_root_version,
            evidence,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedRoleVersions {
    pub root: u64,
    pub timestamp: u64,
    pub snapshot: u64,
    pub targets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedTargetEvidence {
    pub name: String,
    pub length: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TrustedReleaseEvidence {
    pub schema_version: u8,
    pub channel: BuildChannel,
    pub roles: TrustedRoleVersions,
    pub current: TrustedTargetEvidence,
    pub release_manifest: TrustedTargetEvidence,
    pub java_runtime_lock: TrustedTargetEvidence,
    pub game_runtime_lock: TrustedTargetEvidence,
}

impl TrustedReleaseEvidence {
    #[allow(clippy::too_many_arguments)]
    pub fn validate_binding(
        &self,
        expected_channel: BuildChannel,
        release_id: &str,
        manifest_target: &str,
        runtime_target: &str,
        game_runtime_target: &str,
        release_manifest_sha256: &str,
        runtime_lock_sha256: &str,
        game_runtime_lock_sha256: &str,
    ) -> Result<(), String> {
        if self.schema_version != TRUSTED_RELEASE_EVIDENCE_SCHEMA_VERSION
            || self.channel != expected_channel
            || self.roles.root == 0
            || self.roles.timestamp == 0
            || self.roles.snapshot == 0
            || self.roles.targets == 0
        {
            return Err("Trusted release evidence identity or role versions are invalid".into());
        }
        validate_target_evidence(&self.current)?;
        validate_target_evidence(&self.release_manifest)?;
        validate_target_evidence(&self.java_runtime_lock)?;
        validate_target_evidence(&self.game_runtime_lock)?;
        if self.current.name != "current.json"
            || self.current.length > 8 * 1024
            || self.release_manifest.name != manifest_target
            || self.release_manifest.name != format!("release-{release_id}.json")
            || self.release_manifest.length > 16 * 1024 * 1024
            || self.java_runtime_lock.name != runtime_target
            || self.java_runtime_lock.length > MAX_RUNTIME_LOCK_BYTES as u64
            || self.game_runtime_lock.name != game_runtime_target
            || self.game_runtime_lock.length > MAX_GAME_RUNTIME_LOCK_BYTES as u64
            || self.release_manifest.sha256 != release_manifest_sha256
            || self.java_runtime_lock.sha256 != runtime_lock_sha256
            || self.game_runtime_lock.sha256 != game_runtime_lock_sha256
        {
            return Err("Trusted release evidence does not match its release targets".into());
        }
        Ok(())
    }

    pub fn targets_match(&self, newer: &Self) -> bool {
        self.channel == newer.channel
            && self.current == newer.current
            && self.release_manifest == newer.release_manifest
            && self.java_runtime_lock == newer.java_runtime_lock
            && self.game_runtime_lock == newer.game_runtime_lock
    }

    /// Returns whether `newer` preserves this release-evidence identity while advancing (or
    /// retaining) every trusted TUF role version. Target equality is intentionally independent:
    /// a legitimate new release changes target evidence but must still never roll roles back.
    pub fn roles_are_monotonic_to(&self, newer: &Self) -> bool {
        self.schema_version == newer.schema_version
            && self.channel == newer.channel
            && newer.roles.root >= self.roles.root
            && newer.roles.timestamp >= self.roles.timestamp
            && newer.roles.snapshot >= self.roles.snapshot
            && newer.roles.targets >= self.roles.targets
    }

    pub fn targets_match_and_roles_are_monotonic_to(&self, newer: &Self) -> bool {
        self.targets_match(newer) && self.roles_are_monotonic_to(newer)
    }
}

#[derive(Debug, Clone)]
pub struct SparkTufClient {
    state_root: PathBuf,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(super) enum TufRefreshError {
    #[error("Fragment authentication expired: {0}")]
    Authentication(String),
    #[error("Fragment entitlement or channel permission was denied: {0}")]
    Forbidden(String),
    #[error("Launcher update required: {0}")]
    LauncherUpdateRequired(String),
    #[error("{0}")]
    Failed(String),
}

impl From<String> for TufRefreshError {
    fn from(message: String) -> Self {
        if let Some(required) = message.strip_prefix("launcher_update_required:") {
            if !required.is_empty() && Version::parse(required).is_ok() {
                return Self::LauncherUpdateRequired(required.to_owned());
            }
        }
        match message.as_str() {
            "spark_auth_required" | "spark_session_invalid" => Self::Authentication(message),
            "spark_subscription_required"
            | "spark_dev_access_required"
            | "spark_admission_denied"
            | "spark_access_denied" => Self::Forbidden(message),
            _ => Self::Failed(message),
        }
    }
}

impl From<&str> for TufRefreshError {
    fn from(message: &str) -> Self {
        Self::from(message.to_owned())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveTufState {
    schema_version: u8,
    channel: BuildChannel,
    epoch: u64,
    current: GenerationPin,
    previous: Option<GenerationPin>,
    rollback_ledger: RoleVersions,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationPin {
    generation: Uuid,
    versions: RoleVersions,
    files: DatastoreHashes,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RoleVersions {
    root: u64,
    timestamp: u64,
    snapshot: u64,
    targets: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DatastoreHashes {
    root_json: String,
    timestamp_json: String,
    snapshot_json: String,
    targets_json: String,
    latest_known_time_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClockWitness {
    schema_version: u8,
    channel: BuildChannel,
    epoch: u64,
    latest_known_time: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TrustWitness {
    schema_version: u8,
    channel: BuildChannel,
    epoch: u64,
    established: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum GenerationLifecycleState {
    Staging,
    Prepared,
    Committed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct GenerationLifecycleWitness {
    schema_version: u8,
    channel: BuildChannel,
    generation: Uuid,
    state: GenerationLifecycleState,
    pin: Option<GenerationPin>,
}

struct GenerationLifecycleNamespace {
    records: BTreeMap<Uuid, (GenerationLifecycleWitness, Vec<u8>)>,
    temporaries: Vec<(String, Vec<u8>)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveGenerationSource {
    metadata: GenerationPin,
    trust_continuity: GenerationPin,
}

impl ActiveGenerationSource {
    fn is_recovery(&self) -> bool {
        self.metadata.generation != self.trust_continuity.generation
    }
}

impl SparkTufClient {
    pub fn new(state_root: PathBuf) -> Self {
        Self { state_root }
    }

    pub async fn refresh(
        &self,
        channel: BuildChannel,
        bearer_token: &str,
        embedded_root: &[u8],
    ) -> Result<TrustedRelease, TufRefreshError> {
        if embedded_root.is_empty() || embedded_root.len() > MAX_TRUSTED_ROOT_BYTES {
            return Err("Embedded TUF root is missing or oversized".into());
        }
        let channel_root = self.state_root.join(channel.as_str());
        let generations = channel_root.join("generations");
        let lifecycle = channel_root.join(GENERATION_LIFECYCLE_DIRECTORY);
        inspect_existing_ancestors(&channel_root)?;
        fs::create_dir_all(&generations)
            .map_err(|error| format!("Cannot create TUF state directories: {error}"))?;
        fs::create_dir_all(&lifecycle)
            .map_err(|error| format!("Cannot create TUF lifecycle directory: {error}"))?;
        inspect_existing_ancestors(&generations)?;
        inspect_existing_ancestors(&lifecycle)?;

        let lock = acquire_lock(&channel_root.join(".refresh.lock")).await?;
        recover_pretrust_orphan_generations(&channel_root, channel)?;
        let active = read_active_state(&channel_root, channel)?;
        if let Some(active) = active.as_ref() {
            select_active_generation(&channel_root, active)?;
            // A prior process may have made recovery.json durable and then died before one of
            // the lifecycle/trust/active replicas was replaced. Promote that exact, already
            // validated epoch idempotently before deriving another epoch. Without this barrier,
            // repeated crashes could advance recovery twice while active still lagged by two.
            normalize_active_recovery_prefix(&channel_root, active)?;
        }
        pre_admit_generation_slot(&channel_root, channel, active.as_ref())?;
        let active_clock_floor = active
            .as_ref()
            .map(|state| read_pinned_latest_known_time(&channel_root, &state.current))
            .transpose()?;
        let clock =
            advance_clock_witness_at(&channel_root, channel, Timestamp::now(), active_clock_floor)?;
        let generation_id = Uuid::new_v4();
        let generation = generations.join(generation_id.to_string());
        write_generation_lifecycle(
            &channel_root,
            &GenerationLifecycleWitness {
                schema_version: 1,
                channel,
                generation: generation_id,
                state: GenerationLifecycleState::Staging,
                pin: None,
            },
        )?;
        fs::create_dir(&generation)
            .map_err(|error| format!("Cannot create TUF staging generation: {error}"))?;
        sync_directory(&generations)?;
        let result = self
            .refresh_generation(
                channel,
                bearer_token,
                embedded_root,
                &channel_root,
                active.as_ref(),
                generation_id,
                &generation,
                &clock,
            )
            .await;
        if result.is_err() {
            // A crash between recovery.json and active.json can leave the new generation
            // referenced only by the durable recovery pointer. Never delete such a generation.
            if !generation_is_referenced(&channel_root, channel, generation_id) {
                let _ = remove_generation_bounded(&channel_root, generation_id);
                let _ = remove_generation_lifecycle(&channel_root, channel, generation_id);
            }
        }
        // Dropping the file also releases the lock. In particular, an unlock failure after a
        // committed active pointer must never turn a successful refresh into a reported failure.
        let _ = FileExt::unlock(&lock);
        drop(lock);
        result.map_err(TufRefreshError::from)
    }

    #[allow(clippy::too_many_arguments)]
    async fn refresh_generation(
        &self,
        channel: BuildChannel,
        bearer_token: &str,
        embedded_root: &[u8],
        channel_root: &Path,
        active: Option<&ActiveTufState>,
        generation_id: Uuid,
        generation: &Path,
        clock: &ClockWitness,
    ) -> Result<TrustedRelease, String> {
        let (trusted_root, source_pin) = if let Some(active) = active {
            let source = select_active_generation(channel_root, active)?;
            copy_datastore(channel_root, generation, &source)?;
            let root = select_trusted_root(
                embedded_root,
                &generation.join("root.json"),
                source.trust_continuity.versions.root,
                &source.trust_continuity.files.root_json,
            )?;
            (root, Some(source.metadata))
        } else {
            (embedded_root.to_vec(), None)
        };
        seed_latest_known_time(generation, clock.timestamp()?)?;

        let (metadata_url, targets_url, metadata_prefix, targets_prefix) =
            repository_urls(channel)?;
        let transport = SparkTufTransport::new(
            bearer_token.to_owned(),
            Url::parse(SPARK_ORIGIN).expect("constant Spark origin must parse"),
            metadata_prefix,
            targets_prefix,
        )?;
        let repository = RepositoryLoader::new(&trusted_root, metadata_url, targets_url)
            .transport(transport)
            .datastore(generation)
            .limits(Limits {
                max_root_size: MAX_TRUSTED_ROOT_BYTES as u64,
                max_targets_size: 8 * 1024 * 1024,
                max_timestamp_size: 256 * 1024,
                max_snapshot_size: 1024 * 1024,
                max_root_updates: 64,
            })
            .expiration_enforcement(ExpirationEnforcement::Safe)
            .load()
            .await
            .map_err(map_tuf_load_error)?;

        let generated_clock = read_latest_known_time(&generation.join("latest_known_time.json"))?;
        persist_clock_observation(channel_root, channel, generated_clock)?;

        let versions = repository_versions(&repository);
        if let Some(active) = active {
            enforce_rollback_ledger(generation, versions, active)?;
        }

        // Once TUF metadata has been authenticated, its rollback/freeze ledger is committed even
        // if an application-level target is malformed or temporarily unavailable. Otherwise a
        // later attempt could silently forget the newer timestamp/latest-known-time state.
        let release_result = read_trusted_release(&repository, channel, versions.root).await;
        drop(repository);
        let current_pin = sync_and_pin_datastore(generation, generation_id, versions)?;
        write_generation_lifecycle(
            channel_root,
            &GenerationLifecycleWitness {
                schema_version: 1,
                channel,
                generation: generation_id,
                state: GenerationLifecycleState::Prepared,
                pin: Some(current_pin.clone()),
            },
        )?;
        let next = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel,
            epoch: active.map_or(Ok(1), |value| {
                value
                    .epoch
                    .checked_add(1)
                    .ok_or_else(|| "TUF active-state epoch is exhausted".to_string())
            })?,
            rollback_ledger: versions,
            current: current_pin,
            previous: source_pin,
        };
        write_active_state_with_generation_lifecycle(channel_root, &next)?;
        // Cleanup is non-authoritative: after active.json is committed, failure to remove an old
        // generation must not make the caller discard the newly active generation.
        let _ = prune_generations(
            channel_root,
            channel,
            generation_id,
            next.previous.as_ref().map(|value| value.generation),
        );
        release_result
    }
}

async fn read_trusted_release(
    repository: &Repository,
    channel: BuildChannel,
    root_version: u64,
) -> Result<TrustedRelease, String> {
    let roles = TrustedRoleVersions::from(repository_versions(repository));
    if roles.root != root_version {
        return Err("Trusted TUF root version changed while reading the release".into());
    }
    let current_bytes = read_verified_target(repository, "current.json", 8 * 1024).await?;
    let current_evidence = target_evidence(repository, "current.json", &current_bytes)?;
    let current = CurrentPointer::parse_and_validate(&current_bytes, channel)?;
    let manifest_bytes =
        read_verified_target(repository, &current.manifest_target, 16 * 1024 * 1024).await?;
    let manifest_evidence = target_evidence(repository, &current.manifest_target, &manifest_bytes)?;
    let manifest = ReleaseManifest::parse_and_validate(&manifest_bytes)?;
    if manifest.release.id != current.release_id {
        return Err("TUF current target and release manifest do not match".into());
    }
    let required = Version::parse(&manifest.release.minimum_launcher_version)
        .map_err(|error| format!("Release launcher version is invalid: {error}"))?;
    let installed = Version::parse(env!("CARGO_PKG_VERSION"))
        .map_err(|error| format!("Launcher package version is invalid: {error}"))?;
    if installed < required {
        return Err(format!(
            "launcher_update_required:{}",
            manifest.release.minimum_launcher_version
        ));
    }

    enforce_exact_release_targets(repository, &current, &manifest)?;

    let runtime_bytes = read_verified_target(
        repository,
        &manifest.runtime.java.runtime_target,
        MAX_RUNTIME_LOCK_BYTES,
    )
    .await?;
    let runtime_evidence = target_evidence(
        repository,
        &manifest.runtime.java.runtime_target,
        &runtime_bytes,
    )?;
    let runtime_sha256 = format!("{:x}", Sha256::digest(&runtime_bytes));
    if runtime_sha256 != manifest.runtime.java.runtime_lock_sha256 {
        return Err("TUF runtime target hash does not match the release manifest".into());
    }
    let runtime_lock = RuntimeLock::parse_and_validate(&runtime_bytes)?;
    manifest.bind_runtime_lock(&runtime_lock)?;

    let game_runtime_bytes = read_verified_target(
        repository,
        &manifest.runtime.game.runtime_target,
        MAX_GAME_RUNTIME_LOCK_BYTES,
    )
    .await?;
    let game_runtime_evidence = target_evidence(
        repository,
        &manifest.runtime.game.runtime_target,
        &game_runtime_bytes,
    )?;
    let game_runtime_sha256 = format!("{:x}", Sha256::digest(&game_runtime_bytes));
    if game_runtime_sha256 != manifest.runtime.game.runtime_lock_sha256 {
        return Err("TUF game runtime target hash does not match the release manifest".into());
    }
    let game_runtime_lock = GameRuntimeLock::parse_and_validate(&game_runtime_bytes)?;
    manifest.bind_game_runtime_lock(&runtime_lock, &game_runtime_lock)?;

    let evidence = TrustedReleaseEvidence {
        schema_version: TRUSTED_RELEASE_EVIDENCE_SCHEMA_VERSION,
        channel,
        roles,
        current: current_evidence,
        release_manifest: manifest_evidence,
        java_runtime_lock: runtime_evidence,
        game_runtime_lock: game_runtime_evidence,
    };
    evidence.validate_binding(
        channel,
        &manifest.release.id,
        &current.manifest_target,
        &manifest.runtime.java.runtime_target,
        &manifest.runtime.game.runtime_target,
        &evidence.release_manifest.sha256,
        &manifest.runtime.java.runtime_lock_sha256,
        &manifest.runtime.game.runtime_lock_sha256,
    )?;

    Ok(TrustedRelease {
        channel,
        current,
        manifest,
        runtime_lock,
        game_runtime_lock,
        tuf_root_version: root_version,
        evidence,
    })
}

fn target_evidence(
    repository: &Repository,
    name: &str,
    bytes: &[u8],
) -> Result<TrustedTargetEvidence, String> {
    let target_name =
        TargetName::new(name).map_err(|error| format!("Unsafe TUF target name {name}: {error}"))?;
    let signed_length = repository
        .all_targets()
        .find_map(|(candidate, target)| (candidate == &target_name).then_some(target.length))
        .ok_or_else(|| format!("Signed TUF target is missing: {name}"))?;
    if signed_length != bytes.len() as u64 {
        return Err(format!(
            "Trusted TUF target evidence length mismatch: {name}"
        ));
    }
    Ok(TrustedTargetEvidence {
        name: name.to_owned(),
        length: signed_length,
        sha256: format!("{:x}", Sha256::digest(bytes)),
    })
}

fn validate_target_evidence(evidence: &TrustedTargetEvidence) -> Result<(), String> {
    if evidence.name.is_empty()
        || evidence.name.len() > 1024
        || evidence.length == 0
        || evidence.length > MAX_GAME_RUNTIME_LOCK_BYTES as u64
        || !is_sha256(&evidence.sha256)
    {
        return Err("Trusted TUF target evidence is invalid".into());
    }
    TargetName::new(&evidence.name)
        .map_err(|error| format!("Trusted TUF target evidence name is unsafe: {error}"))?;
    Ok(())
}

fn enforce_exact_release_targets(
    repository: &Repository,
    current: &CurrentPointer,
    manifest: &ReleaseManifest,
) -> Result<(), String> {
    let expected = BTreeSet::from([
        "current.json".to_owned(),
        current.manifest_target.clone(),
        manifest.runtime.java.runtime_target.clone(),
        manifest.runtime.game.runtime_target.clone(),
    ]);
    if expected.len() != 4 {
        return Err("Release TUF target bindings are not unique".into());
    }
    let actual_targets = repository
        .all_targets()
        .map(|(name, _)| name.raw().to_owned())
        .collect::<Vec<_>>();
    let actual = actual_targets.iter().cloned().collect::<BTreeSet<_>>();
    if actual.len() != actual_targets.len() {
        return Err("Signed TUF release target set contains duplicate names".into());
    }
    if actual == expected {
        return Ok(());
    }

    let missing = expected.difference(&actual).cloned().collect::<Vec<_>>();
    let extra = actual.difference(&expected).cloned().collect::<Vec<_>>();
    Err(format!(
        "Signed TUF release target set is not exact (missing: {}; extra: {})",
        if missing.is_empty() {
            "none".to_owned()
        } else {
            missing.join(", ")
        },
        if extra.is_empty() {
            "none".to_owned()
        } else {
            extra.join(", ")
        }
    ))
}

async fn read_verified_target(
    repository: &Repository,
    name: &str,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let target_name =
        TargetName::new(name).map_err(|error| format!("Unsafe TUF target name {name}: {error}"))?;
    let signed_length = repository
        .all_targets()
        .find_map(|(candidate, target)| (candidate == &target_name).then_some(target.length))
        .ok_or_else(|| format!("Signed TUF target is missing: {name}"))?;
    if signed_length > maximum as u64 {
        return Err(format!(
            "Verified TUF target exceeds launcher limit: {name}"
        ));
    }
    let stream = repository
        .read_target(&target_name)
        .await
        .map_err(|error| {
            typed_tuf_error(&error)
                .unwrap_or_else(|| format!("Cannot read verified TUF target {name}: {error}"))
        })?
        .ok_or_else(|| format!("Signed TUF target is missing: {name}"))?;
    let capacity = usize::try_from(signed_length)
        .map_err(|_| format!("Verified TUF target length is unsupported: {name}"))?;
    let mut bytes = Vec::with_capacity(capacity);
    let mut stream = Box::pin(stream);
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|error| {
            typed_tuf_error(&error)
                .unwrap_or_else(|| format!("TUF target verification failed for {name}: {error}"))
        })?;
        let next_length = bytes
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| format!("Verified TUF target length overflow: {name}"))?;
        if next_length > maximum || next_length > capacity {
            return Err(format!(
                "Verified TUF target exceeds launcher limit: {name}"
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() != capacity {
        return Err(format!(
            "Verified TUF target has an unexpected length: {name}"
        ));
    }
    Ok(bytes)
}

fn repository_urls(channel: BuildChannel) -> Result<(Url, Url, String, String), String> {
    let metadata_prefix = format!("/api/spark2/v1/repositories/{}/metadata/", channel.as_str());
    let targets_prefix = format!("/api/spark2/v1/repositories/{}/targets/", channel.as_str());
    let origin = Url::parse(SPARK_ORIGIN).expect("constant Spark origin must parse");
    let metadata = origin
        .join(metadata_prefix.trim_start_matches('/'))
        .map_err(|error| format!("Cannot build Spark metadata URL: {error}"))?;
    let targets = origin
        .join(targets_prefix.trim_start_matches('/'))
        .map_err(|error| format!("Cannot build Spark targets URL: {error}"))?;
    Ok((metadata, targets, metadata_prefix, targets_prefix))
}

async fn acquire_lock(path: &Path) -> Result<File, String> {
    let lock = open_or_create_regular_single_link(path)
        .map_err(|error| format!("Cannot open TUF refresh lock: {error}"))?;
    let started = Instant::now();
    loop {
        match lock.try_lock_exclusive() {
            Ok(()) => return Ok(lock),
            Err(error) if started.elapsed() < Duration::from_secs(5) => {
                let _ = error;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => return Err(format!("TUF refresh is already running: {error}")),
        }
    }
}

impl ClockWitness {
    fn timestamp(&self) -> Result<Timestamp, String> {
        self.latest_known_time
            .parse::<Timestamp>()
            .map_err(|error| format!("TUF clock witness timestamp is invalid: {error}"))
    }
}

fn read_clock_witness(
    channel_root: &Path,
    channel: BuildChannel,
) -> Result<Option<ClockWitness>, String> {
    let active = read_clock_pointer(&channel_root.join(CLOCK_FILE), channel);
    let recovery = read_clock_pointer(&channel_root.join(CLOCK_RECOVERY_FILE), channel);
    match (active, recovery) {
        (Ok(None), Ok(None)) => Ok(None),
        (Ok(Some(active)), Ok(Some(recovery))) => {
            if recovery.epoch < active.epoch || recovery.epoch > active.epoch.saturating_add(1) {
                return Err("TUF clock pointers have an invalid epoch order".into());
            }
            if recovery.epoch == active.epoch && recovery != active {
                return Err("TUF clock pointers are ambiguous".into());
            }
            Ok(Some(if recovery.epoch > active.epoch {
                recovery
            } else {
                active
            }))
        }
        (Ok(None), Ok(Some(recovery))) | (Err(_), Ok(Some(recovery))) => Ok(Some(recovery)),
        (Ok(Some(_)), Ok(None)) => {
            Err("TUF clock recovery pointer is missing for an active clock".into())
        }
        (Ok(Some(_)), Err(error)) => Err(format!(
            "TUF clock recovery pointer is corrupt and may hide a newer epoch: {error}"
        )),
        (Err(active_error), Err(recovery_error)) => Err(format!(
            "Both TUF clock pointers are corrupt: {active_error}; {recovery_error}"
        )),
        (Err(error), Ok(None)) | (Ok(None), Err(error)) => Err(error),
    }
}

fn read_clock_pointer(path: &Path, channel: BuildChannel) -> Result<Option<ClockWitness>, String> {
    if namespace_path_is_absent(path)? {
        return Ok(None);
    }
    let bytes = read_bounded(path, CLOCK_STATE_LIMIT)?;
    let witness: ClockWitness = serde_json::from_slice(&bytes)
        .map_err(|error| format!("TUF clock pointer is corrupt: {error}"))?;
    if witness.schema_version != 1
        || witness.channel != channel
        || witness.epoch == 0
        || witness.latest_known_time.len() > 64
    {
        return Err("TUF clock pointer is invalid".into());
    }
    witness.timestamp()?;
    Ok(Some(witness))
}

fn advance_clock_witness_at(
    channel_root: &Path,
    channel: BuildChannel,
    now: Timestamp,
    floor: Option<Timestamp>,
) -> Result<ClockWitness, String> {
    let existing = read_clock_witness(channel_root, channel)?;
    if let Some(existing) = existing.as_ref() {
        // Complete an interrupted recovery-first write before advancing again. Rewriting the
        // same witness is idempotent and prevents repeated crashes from producing an epoch gap.
        write_clock_witness(channel_root, existing)?;
    }
    if floor.is_some() && existing.is_none() {
        return Err("TUF clock witness is missing for an active v2 state".into());
    }
    let existing_time = existing.as_ref().map(ClockWitness::timestamp).transpose()?;
    if existing_time.is_some_and(|value| now < value) || floor.is_some_and(|value| now < value) {
        return Err("TUF monotonic clock moved backwards".into());
    }
    let epoch = existing.map_or(Ok(1), |witness| {
        witness
            .epoch
            .checked_add(1)
            .ok_or_else(|| "TUF clock epoch is exhausted".to_string())
    })?;
    let next = ClockWitness {
        schema_version: 1,
        channel,
        epoch,
        latest_known_time: now.to_string(),
    };
    write_clock_witness(channel_root, &next)?;
    Ok(next)
}

fn persist_clock_observation(
    channel_root: &Path,
    channel: BuildChannel,
    observed: Timestamp,
) -> Result<(), String> {
    let current = read_clock_witness(channel_root, channel)?
        .ok_or_else(|| "TUF clock witness disappeared during refresh".to_string())?;
    // This path can itself follow an interrupted advance. Normalize the selected recovery
    // witness before it is ever incremented by a later observation.
    write_clock_witness(channel_root, &current)?;
    let current_time = current.timestamp()?;
    if observed <= current_time {
        return Ok(());
    }
    let next = ClockWitness {
        schema_version: 1,
        channel,
        epoch: current
            .epoch
            .checked_add(1)
            .ok_or_else(|| "TUF clock epoch is exhausted".to_string())?,
        latest_known_time: observed.to_string(),
    };
    write_clock_witness(channel_root, &next)
}

fn write_clock_witness(channel_root: &Path, witness: &ClockWitness) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(witness)
        .map_err(|error| format!("Cannot serialize TUF clock witness: {error}"))?;
    if bytes.len() > CLOCK_STATE_LIMIT {
        return Err("TUF clock witness exceeds launcher limit".into());
    }
    write_pointer_file(channel_root, CLOCK_RECOVERY_FILE, &bytes)?;
    write_pointer_file(channel_root, CLOCK_FILE, &bytes)
}

fn read_latest_known_time(path: &Path) -> Result<Timestamp, String> {
    let bytes = read_bounded(path, LATEST_KNOWN_TIME_LIMIT)?;
    serde_json::from_slice::<Timestamp>(&bytes)
        .map_err(|error| format!("TUF latest-known-time is invalid: {error}"))
}

fn read_pinned_latest_known_time(
    channel_root: &Path,
    pin: &GenerationPin,
) -> Result<Timestamp, String> {
    let directory = generation_path(channel_root, pin.generation);
    verify_generation_directory(&directory)?;
    let path = directory.join("latest_known_time.json");
    let bytes = read_bounded(&path, LATEST_KNOWN_TIME_LIMIT)?;
    if format!("{:x}", Sha256::digest(&bytes)) != pin.files.latest_known_time_json {
        return Err("Pinned TUF latest-known-time is corrupt".into());
    }
    serde_json::from_slice::<Timestamp>(&bytes)
        .map_err(|error| format!("Pinned TUF latest-known-time is invalid: {error}"))
}

fn seed_latest_known_time(directory: &Path, timestamp: Timestamp) -> Result<(), String> {
    let bytes = serde_json::to_vec(&timestamp)
        .map_err(|error| format!("Cannot serialize TUF latest-known-time: {error}"))?;
    let destination = directory.join("latest_known_time.json");
    let temporary = directory.join(format!(".latest-known-time-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("Cannot create TUF clock seed: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("Cannot write TUF clock seed: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Cannot flush TUF clock seed: {error}"))?;
        drop(file);
        replace_file(&temporary, &destination)?;
        sync_directory(directory)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn read_trust_witness(
    channel_root: &Path,
    channel: BuildChannel,
) -> Result<Option<TrustWitness>, String> {
    let active = read_trust_pointer(&channel_root.join(TRUST_FILE), channel);
    let recovery = read_trust_pointer(&channel_root.join(TRUST_RECOVERY_FILE), channel);
    match (active, recovery) {
        (Ok(None), Ok(None)) => Ok(None),
        (Ok(Some(active)), Ok(Some(recovery))) => {
            if recovery.epoch < active.epoch || recovery.epoch > active.epoch.saturating_add(1) {
                return Err("TUF trust witnesses have an invalid epoch order".into());
            }
            if recovery.epoch == active.epoch && recovery != active {
                return Err("TUF trust witnesses are ambiguous".into());
            }
            Ok(Some(if recovery.epoch > active.epoch {
                recovery
            } else {
                active
            }))
        }
        (Ok(None), Ok(Some(recovery))) | (Err(_), Ok(Some(recovery))) => Ok(Some(recovery)),
        (Ok(Some(_)), Ok(None)) => Err("TUF trust recovery witness is missing".into()),
        (Ok(Some(_)), Err(error)) => Err(format!(
            "TUF trust recovery witness is corrupt and may hide a newer epoch: {error}"
        )),
        (Err(active_error), Err(recovery_error)) => Err(format!(
            "Both TUF trust witnesses are corrupt: {active_error}; {recovery_error}"
        )),
        (Err(error), Ok(None)) | (Ok(None), Err(error)) => Err(error),
    }
}

fn read_trust_pointer(path: &Path, channel: BuildChannel) -> Result<Option<TrustWitness>, String> {
    if namespace_path_is_absent(path)? {
        return Ok(None);
    }
    let bytes = read_bounded(path, TRUST_STATE_LIMIT)?;
    let witness: TrustWitness = serde_json::from_slice(&bytes)
        .map_err(|error| format!("TUF trust witness is corrupt: {error}"))?;
    if witness.schema_version != 1
        || witness.channel != channel
        || witness.epoch == 0
        || !witness.established
    {
        return Err("TUF trust witness is invalid".into());
    }
    Ok(Some(witness))
}

fn write_trust_witness(channel_root: &Path, witness: &TrustWitness) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(witness)
        .map_err(|error| format!("Cannot serialize TUF trust witness: {error}"))?;
    if bytes.len() > TRUST_STATE_LIMIT {
        return Err("TUF trust witness exceeds launcher limit".into());
    }
    write_pointer_file(channel_root, TRUST_RECOVERY_FILE, &bytes)?;
    write_pointer_file(channel_root, TRUST_FILE, &bytes)
}

fn namespace_path_is_absent(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(format!(
            "Cannot inspect TUF state namespace {}: {error}",
            path.display()
        )),
    }
}

fn ensure_generation_lifecycle_directory(channel_root: &Path) -> Result<PathBuf, String> {
    let directory = channel_root.join(GENERATION_LIFECYCLE_DIRECTORY);
    fs::create_dir_all(&directory)
        .map_err(|error| format!("Cannot create TUF lifecycle directory: {error}"))?;
    inspect_existing_ancestors(&directory)?;
    Ok(directory)
}

fn generation_lifecycle_path(channel_root: &Path, generation: Uuid) -> PathBuf {
    channel_root
        .join(GENERATION_LIFECYCLE_DIRECTORY)
        .join(format!("{generation}.json"))
}

fn validate_generation_lifecycle(
    witness: &GenerationLifecycleWitness,
    channel: BuildChannel,
    generation: Uuid,
) -> Result<(), String> {
    if witness.schema_version != 1 || witness.channel != channel || witness.generation != generation
    {
        return Err("TUF generation lifecycle identity is invalid".into());
    }
    match (witness.state, witness.pin.as_ref()) {
        (GenerationLifecycleState::Staging, None) => Ok(()),
        (GenerationLifecycleState::Prepared | GenerationLifecycleState::Committed, Some(pin))
            if pin.generation == generation =>
        {
            validate_generation_pin(pin)
        }
        _ => Err("TUF generation lifecycle transition is invalid".into()),
    }
}

fn write_generation_lifecycle(
    channel_root: &Path,
    witness: &GenerationLifecycleWitness,
) -> Result<(), String> {
    validate_generation_lifecycle(witness, witness.channel, witness.generation)?;
    let directory = ensure_generation_lifecycle_directory(channel_root)?;
    let bytes = serde_json::to_vec_pretty(witness)
        .map_err(|error| format!("Cannot serialize TUF generation lifecycle: {error}"))?;
    if bytes.len() > GENERATION_LIFECYCLE_LIMIT {
        return Err("TUF generation lifecycle exceeds launcher limit".into());
    }
    write_pointer_file(&directory, &format!("{}.json", witness.generation), &bytes)
}

fn read_generation_lifecycle(
    channel_root: &Path,
    channel: BuildChannel,
    generation: Uuid,
) -> Result<Option<(GenerationLifecycleWitness, Vec<u8>)>, String> {
    let path = generation_lifecycle_path(channel_root, generation);
    if namespace_path_is_absent(&path)? {
        return Ok(None);
    }
    let bytes = read_bounded(&path, GENERATION_LIFECYCLE_LIMIT)?;
    let witness: GenerationLifecycleWitness = serde_json::from_slice(&bytes)
        .map_err(|error| format!("TUF generation lifecycle is corrupt: {error}"))?;
    validate_generation_lifecycle(&witness, channel, generation)?;
    Ok(Some((witness, bytes)))
}

fn lifecycle_records_bounded(
    channel_root: &Path,
    channel: BuildChannel,
) -> Result<GenerationLifecycleNamespace, String> {
    let directory = ensure_generation_lifecycle_directory(channel_root)?;
    let mut records = BTreeMap::new();
    let mut temporaries = Vec::new();
    let mut entry_count = 0_usize;
    for entry in fs::read_dir(&directory)
        .map_err(|error| format!("Cannot inspect TUF lifecycle namespace: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("Cannot inspect TUF lifecycle entry: {error}"))?;
        entry_count = entry_count
            .checked_add(1)
            .ok_or_else(|| "TUF lifecycle namespace entry count overflowed".to_string())?;
        if entry_count > GENERATION_LIFECYCLE_NAMESPACE_LIMIT {
            return Err("TUF lifecycle namespace exceeds launcher limit".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "TUF lifecycle entry has a non-UTF-8 name".to_string())?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Cannot inspect TUF lifecycle entry: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!("Unsafe TUF lifecycle entry: {name}"));
        }
        let bytes = read_bounded(&entry.path(), GENERATION_LIFECYCLE_LIMIT)?;
        if is_generation_lifecycle_temporary_name(&name) {
            temporaries.push((name, bytes));
            continue;
        }
        let id_text = name
            .strip_suffix(".json")
            .ok_or_else(|| format!("TUF lifecycle entry has an invalid name: {name}"))?;
        let generation = Uuid::parse_str(id_text)
            .map_err(|_| format!("TUF lifecycle entry has an invalid name: {name}"))?;
        if name != format!("{generation}.json") {
            return Err(format!("TUF lifecycle entry is not canonical: {name}"));
        }
        let witness: GenerationLifecycleWitness = serde_json::from_slice(&bytes)
            .map_err(|error| format!("TUF generation lifecycle is corrupt: {error}"))?;
        validate_generation_lifecycle(&witness, channel, generation)?;
        if records.insert(generation, (witness, bytes)).is_some() {
            return Err("TUF lifecycle namespace contains duplicate generations".into());
        }
    }
    Ok(GenerationLifecycleNamespace {
        records,
        temporaries,
    })
}

fn is_generation_lifecycle_temporary_name(name: &str) -> bool {
    if !name.is_ascii() || name.len() != 83 || !name.starts_with('.') || !name.ends_with(".tmp") {
        return false;
    }
    let body = &name[1..name.len() - 4];
    let destination = &body[..41];
    let separator = body.as_bytes()[41];
    let transaction = &body[42..];
    let Some(generation) = destination.strip_suffix(".json") else {
        return false;
    };
    separator == b'-'
        && Uuid::parse_str(generation).is_ok_and(|id| generation == id.to_string())
        && Uuid::parse_str(transaction).is_ok_and(|id| transaction == id.to_string())
}

fn remove_lifecycle_namespace_file(
    channel_root: &Path,
    name: &str,
    bytes: &[u8],
) -> Result<(), String> {
    let relative_text = format!("{GENERATION_LIFECYCLE_DIRECTORY}/{name}");
    let relative = RelativeManagedPath::new(&relative_text)
        .map_err(|error| format!("Cannot bind TUF lifecycle cleanup path: {error}"))?;
    let expected = FileDigests {
        size: bytes.len() as u64,
        sha1: format!("{:x}", Sha1::digest(bytes)),
        sha256: format!("{:x}", Sha256::digest(bytes)),
    };
    remove_verified_managed_file(channel_root, &relative, &expected)
        .map_err(|error| format!("Cannot remove TUF lifecycle namespace file: {error}"))
}

fn remove_generation_lifecycle(
    channel_root: &Path,
    channel: BuildChannel,
    generation: Uuid,
) -> Result<(), String> {
    let Some((_, bytes)) = read_generation_lifecycle(channel_root, channel, generation)? else {
        return Ok(());
    };
    remove_lifecycle_namespace_file(channel_root, &format!("{generation}.json"), &bytes)
}

fn generation_ids_bounded(channel_root: &Path, maximum: usize) -> Result<Vec<Uuid>, String> {
    let generations = channel_root.join("generations");
    inspect_existing_ancestors(&generations)?;
    let mut ids = Vec::new();
    for entry in fs::read_dir(&generations)
        .map_err(|error| format!("Cannot inspect TUF generations: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Cannot inspect TUF generation: {error}"))?;
        if ids.len() == maximum {
            return Err("TUF generation namespace exceeds launcher cleanup limit".into());
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "TUF generation has a non-UTF-8 name".to_string())?;
        let id = Uuid::parse_str(&name)
            .map_err(|_| format!("TUF generation has an invalid name: {name}"))?;
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Cannot inspect TUF generation: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!("Unsafe TUF generation entry: {name}"));
        }
        ids.push(id);
    }
    ids.sort_unstable_by_key(|id| id.as_u128());
    Ok(ids)
}

fn remove_generation_bounded(channel_root: &Path, generation: Uuid) -> Result<(), String> {
    let relative_path = format!("generations/{generation}");
    let relative = RelativeManagedPath::new(&relative_path)
        .map_err(|error| format!("Cannot bind TUF generation cleanup path: {error}"))?;
    let (identity, kind, reparse_tag) = inspect_managed_node_nofollow(channel_root, &relative)
        .map_err(|error| format!("Cannot inspect TUF generation for cleanup: {error}"))?;
    if kind != ManagedNodeKind::Directory || reparse_tag != 0 {
        return Err("TUF generation cleanup target is not a real directory".into());
    }
    remove_bounded_managed_directory_tree(
        channel_root,
        &relative,
        &identity,
        TUF_GENERATION_REMOVAL_LIMITS,
    )
    .map_err(|error| format!("Cannot remove bounded TUF generation: {error}"))?;
    Ok(())
}

/// Deletes only lifecycle-bound staging/prepared generations that never crossed the durable
/// recovery-pointer boundary. A committed, missing or corrupt lifecycle record is preservation
/// evidence, never deletion authority. Therefore losing every small state pointer after a valid
/// commit cannot erase the last rollback witness or silently re-enable bootstrap.
fn recover_pretrust_orphan_generations(
    channel_root: &Path,
    channel: BuildChannel,
) -> Result<(), String> {
    for name in [ACTIVE_FILE, RECOVERY_FILE, TRUST_FILE, TRUST_RECOVERY_FILE] {
        if !namespace_path_is_absent(&channel_root.join(name))? {
            return Ok(());
        }
    }

    let generations = generation_ids_bounded(channel_root, PRETRUST_ORPHAN_GENERATION_LIMIT)?;
    let lifecycle = lifecycle_records_bounded(channel_root, channel)?;
    let records = lifecycle.records;
    if records
        .values()
        .any(|(witness, _)| witness.state == GenerationLifecycleState::Committed)
    {
        return Err("Committed TUF lifecycle exists without state pointers".into());
    }
    for generation in &generations {
        match records.get(generation) {
            Some((witness, _))
                if matches!(
                    witness.state,
                    GenerationLifecycleState::Staging | GenerationLifecycleState::Prepared
                ) => {}
            _ => {
                return Err(
                    "TUF generation without deletable pre-trust lifecycle must be preserved".into(),
                )
            }
        }
    }

    for generation in generations {
        remove_generation_bounded(channel_root, generation)?;
        remove_generation_lifecycle(channel_root, channel, generation)?;
    }
    for (generation, (witness, _)) in records {
        if matches!(
            witness.state,
            GenerationLifecycleState::Staging | GenerationLifecycleState::Prepared
        ) {
            remove_generation_lifecycle(channel_root, channel, generation)?;
        }
    }
    for (name, bytes) in lifecycle.temporaries {
        remove_lifecycle_namespace_file(channel_root, &name, &bytes)?;
    }
    if !generations_are_empty(channel_root)? {
        return Err("TUF pre-trust generation namespace changed during recovery".into());
    }
    Ok(())
}

fn pre_admit_generation_slot(
    channel_root: &Path,
    channel: BuildChannel,
    active: Option<&ActiveTufState>,
) -> Result<(), String> {
    let ids = generation_ids_bounded(channel_root, TUF_GENERATION_NAMESPACE_LIMIT)?;
    let Some(active) = active else {
        if !ids.is_empty() {
            return Err("TUF bootstrap generation namespace is not empty after recovery".into());
        }
        return Ok(());
    };

    let keep: HashSet<_> = [
        Some(active.current.generation),
        active.previous.as_ref().map(|pin| pin.generation),
    ]
    .into_iter()
    .flatten()
    .collect();
    for generation in ids {
        if !keep.contains(&generation) {
            remove_generation_bounded(channel_root, generation)?;
            let _ = remove_generation_lifecycle(channel_root, channel, generation);
        }
    }
    if generation_ids_bounded(channel_root, TUF_GENERATION_NAMESPACE_LIMIT)?.len()
        >= TUF_GENERATION_NAMESPACE_LIMIT
    {
        return Err("TUF generation namespace has no slot for a refresh transaction".into());
    }
    for pin in std::iter::once(&active.current).chain(active.previous.iter()) {
        write_generation_lifecycle(
            channel_root,
            &GenerationLifecycleWitness {
                schema_version: 1,
                channel,
                generation: pin.generation,
                state: GenerationLifecycleState::Committed,
                pin: Some(pin.clone()),
            },
        )?;
    }
    Ok(())
}

fn generations_are_empty(channel_root: &Path) -> Result<bool, String> {
    let generations = channel_root.join("generations");
    inspect_existing_ancestors(&generations)?;
    let mut entries = fs::read_dir(&generations)
        .map_err(|error| format!("Cannot inspect TUF generations for bootstrap: {error}"))?;
    Ok(entries.next().is_none())
}

fn read_active_state(
    channel_root: &Path,
    channel: BuildChannel,
) -> Result<Option<ActiveTufState>, String> {
    let active_path = channel_root.join(ACTIVE_FILE);
    let recovery_path = channel_root.join(RECOVERY_FILE);
    let active_exists = !namespace_path_is_absent(&active_path)?;
    let recovery_exists = !namespace_path_is_absent(&recovery_path)?;
    if !active_exists && !recovery_exists {
        return match read_trust_witness(channel_root, channel) {
            Ok(None) if generations_are_empty(channel_root)? => Ok(None),
            Ok(None) => Err(
                "TUF state pointers and trust witness are missing while generations exist".into(),
            ),
            Ok(Some(_)) => Err("TUF state pointers are missing after trust was established".into()),
            Err(error) => Err(format!(
                "TUF state pointers are missing and trust witness is invalid: {error}"
            )),
        };
    }

    let active = read_pointer_if_valid(&active_path, channel);
    let recovery = read_pointer_if_valid(&recovery_path, channel);
    let (selected, recovery_authoritative) = match (active, recovery) {
        (Ok(Some(active)), Ok(Some(recovery))) => {
            if recovery.epoch < active.epoch || recovery.epoch > active.epoch.saturating_add(1) {
                return Err("TUF active and recovery pointers have an invalid epoch order".into());
            }
            if recovery.epoch == active.epoch && recovery != active {
                return Err("TUF active and recovery pointers are ambiguous".into());
            }
            if recovery.epoch > active.epoch {
                (recovery, true)
            } else {
                (active, false)
            }
        }
        (Ok(Some(_)), Ok(None)) => {
            return Err("TUF recovery pointer is missing for an active v2 state".into());
        }
        (Ok(None), Ok(Some(recovery))) | (Err(_), Ok(Some(recovery))) => (recovery, true),
        (Ok(Some(_)), Err(error)) => {
            return Err(format!(
                "TUF recovery pointer is corrupt and may hide a newer epoch: {error}"
            ));
        }
        (Err(active_error), Err(recovery_error)) => {
            return Err(format!(
                "Both TUF state pointers are corrupt: {active_error}; {recovery_error}"
            ));
        }
        (Err(error), Ok(None)) | (Ok(None), Err(error)) => return Err(error),
        (Ok(None), Ok(None)) => unreachable!("both absent was handled above"),
    };

    match read_trust_witness(channel_root, channel) {
        Ok(Some(witness)) => {
            if witness.epoch > selected.epoch || selected.epoch - witness.epoch > 1 {
                return Err("TUF trust witness and active state epochs are inconsistent".into());
            }
        }
        Ok(None) if recovery_authoritative => {
            // First-commit crash window: recovery.json is already durable, while the trust
            // witness (written next) may not exist yet. The recovery pointer itself preserves
            // the complete exact-pinned trust state.
        }
        Ok(None) => return Err("TUF trust witness is missing for committed active state".into()),
        Err(error) => return Err(error),
    }
    Ok(Some(selected))
}

fn read_pointer_if_valid(
    path: &Path,
    channel: BuildChannel,
) -> Result<Option<ActiveTufState>, String> {
    if namespace_path_is_absent(path)? {
        return Ok(None);
    }
    let bytes = read_bounded(path, ACTIVE_STATE_LIMIT)?;
    let active: ActiveTufState = serde_json::from_slice(&bytes)
        .map_err(|error| format!("TUF state pointer is corrupt: {error}"))?;
    validate_active_shape(&active, channel)?;
    Ok(Some(active))
}

fn validate_active_shape(active: &ActiveTufState, channel: BuildChannel) -> Result<(), String> {
    if active.schema_version != ACTIVE_STATE_SCHEMA_VERSION
        || active.channel != channel
        || active.epoch == 0
        || active.rollback_ledger != active.current.versions
    {
        return Err("TUF active state is invalid".into());
    }
    validate_generation_pin(&active.current)?;
    if let Some(previous) = &active.previous {
        validate_generation_pin(previous)?;
        if previous.generation == active.current.generation
            || !active.rollback_ledger.dominates(previous.versions)
        {
            return Err("TUF previous generation pointer is invalid".into());
        }
    }
    Ok(())
}

fn validate_generation_pin(pin: &GenerationPin) -> Result<(), String> {
    if !pin.versions.is_valid() || pin.files.values().any(|hash| !is_sha256(hash)) {
        return Err("TUF generation pin is invalid".into());
    }
    Ok(())
}

fn select_active_generation(
    channel_root: &Path,
    active: &ActiveTufState,
) -> Result<ActiveGenerationSource, String> {
    match verify_datastore_pin(channel_root, &active.current) {
        Ok(()) => Ok(ActiveGenerationSource {
            metadata: active.current.clone(),
            trust_continuity: active.current.clone(),
        }),
        Err(current_error) => {
            verify_pinned_current_trust(channel_root, &active.current).map_err(|trust_error| {
                format!(
                    "TUF active datastore failed verification and its trust-continuity files are unavailable: {current_error}; {trust_error}"
                )
            })?;
            let previous = active.previous.as_ref().ok_or_else(|| {
                format!("TUF active datastore failed verification: {current_error}")
            })?;
            verify_datastore_pin(channel_root, previous).map_err(|previous_error| {
                format!(
                    "TUF active and previous datastores failed verification: {current_error}; {previous_error}"
                )
            })?;
            Ok(ActiveGenerationSource {
                metadata: previous.clone(),
                trust_continuity: active.current.clone(),
            })
        }
    }
}

fn verify_pinned_current_trust(channel_root: &Path, current: &GenerationPin) -> Result<(), String> {
    let directory = generation_path(channel_root, current.generation);
    verify_generation_directory(&directory)?;
    for name in ["root.json", "latest_known_time.json"] {
        let bytes = read_bounded(&directory.join(name), datastore_limit(name))?;
        let expected = current
            .files
            .get(name)
            .expect("trust-continuity file must have a pin");
        if format!("{:x}", Sha256::digest(&bytes)) != expected {
            return Err(format!(
                "Pinned TUF trust-continuity file is corrupt: {name}"
            ));
        }
        if name == "root.json" && root_version(&bytes)? != current.versions.root {
            return Err("Pinned current TUF root version is inconsistent".into());
        }
        if name == "latest_known_time.json" {
            serde_json::from_slice::<Timestamp>(&bytes)
                .map_err(|error| format!("Pinned current TUF clock is invalid: {error}"))?;
        }
    }
    Ok(())
}

fn select_trusted_root(
    embedded_root: &[u8],
    cached_root_path: &Path,
    cached_version: u64,
    cached_sha256: &str,
) -> Result<Vec<u8>, String> {
    let cached_root = read_bounded(cached_root_path, MAX_TRUSTED_ROOT_BYTES)?;
    let cached_hash = format!("{:x}", Sha256::digest(&cached_root));
    if cached_hash != cached_sha256 || root_version(&cached_root)? != cached_version {
        return Err("Cached TUF root does not match active trusted state".into());
    }
    let embedded_version = root_version(embedded_root)?;
    if embedded_version == cached_version {
        let embedded_json: serde_json::Value = serde_json::from_slice(embedded_root)
            .map_err(|error| format!("Embedded TUF root JSON is invalid: {error}"))?;
        let cached_json: serde_json::Value = serde_json::from_slice(&cached_root)
            .map_err(|error| format!("Cached TUF root JSON is invalid: {error}"))?;
        if cached_json != embedded_json {
            return Err("Embedded and cached TUF roots differ at the same version".into());
        }
    }
    // Once an active state exists, continuity always starts at its exact pinned root. A newer
    // embedded root is reached through the ordinary sequential TUF root-rotation chain.
    Ok(cached_root)
}

fn root_version(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() || bytes.len() > MAX_TRUSTED_ROOT_BYTES {
        return Err("TUF root is missing or oversized".into());
    }
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("TUF root JSON is invalid: {error}"))?;
    value
        .get("signed")
        .and_then(|signed| signed.get("version"))
        .and_then(serde_json::Value::as_u64)
        .filter(|version| *version > 0)
        .ok_or_else(|| "TUF root version is invalid".into())
}

fn copy_datastore(
    channel_root: &Path,
    destination: &Path,
    source: &ActiveGenerationSource,
) -> Result<(), String> {
    let metadata_directory = generation_path(channel_root, source.metadata.generation);
    let trust_directory = generation_path(channel_root, source.trust_continuity.generation);
    verify_datastore_pin(channel_root, &source.metadata)?;
    if source.is_recovery() {
        verify_pinned_current_trust(channel_root, &source.trust_continuity)?;
    }
    for name in DATASTORE_FILES {
        let use_current_trust =
            source.is_recovery() && matches!(name, "root.json" | "latest_known_time.json");
        let (directory, pin) = if use_current_trust {
            (&trust_directory, &source.trust_continuity)
        } else {
            (&metadata_directory, &source.metadata)
        };
        let bytes = read_bounded(&directory.join(name), datastore_limit(name))?;
        let expected = pin
            .files
            .get(name)
            .expect("fixed datastore name must have a hash");
        if format!("{:x}", Sha256::digest(&bytes)) != expected {
            return Err(format!("Pinned TUF datastore file is corrupt: {name}"));
        }
        let destination_path = destination.join(name);
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&destination_path)
            .map_err(|error| format!("Cannot stage TUF datastore file {name}: {error}"))?;
        output
            .write_all(&bytes)
            .map_err(|error| format!("Cannot stage TUF datastore file {name}: {error}"))?;
        output
            .sync_all()
            .map_err(|error| format!("Cannot flush staged TUF datastore file {name}: {error}"))?;
    }
    Ok(())
}

fn active_state_bytes(active: &ActiveTufState) -> Result<Vec<u8>, String> {
    validate_active_shape(active, active.channel)?;
    let bytes = serde_json::to_vec_pretty(active)
        .map_err(|error| format!("Cannot serialize TUF active state: {error}"))?;
    if bytes.len() > ACTIVE_STATE_LIMIT {
        return Err("TUF active state exceeds launcher limit".into());
    }
    Ok(bytes)
}

fn write_active_state(channel_root: &Path, active: &ActiveTufState) -> Result<(), String> {
    let bytes = active_state_bytes(active)?;
    // The recovery pointer is written first. If the process dies before active.json is replaced,
    // startup selects the higher recovery epoch. The independent trust witness is committed
    // between recovery and active so deleting both state pointers can never look like bootstrap.
    write_pointer_file(channel_root, RECOVERY_FILE, &bytes)?;
    write_trust_witness(
        channel_root,
        &TrustWitness {
            schema_version: 1,
            channel: active.channel,
            epoch: active.epoch,
            established: true,
        },
    )?;
    write_pointer_file(channel_root, ACTIVE_FILE, &bytes)
}

fn write_active_state_with_generation_lifecycle(
    channel_root: &Path,
    active: &ActiveTufState,
) -> Result<(), String> {
    let bytes = active_state_bytes(active)?;
    // Prepared remains safely discardable until recovery.json is durable. Once that pointer
    // exists it is authoritative even if the following lifecycle/trust/active writes crash.
    write_pointer_file(channel_root, RECOVERY_FILE, &bytes)?;
    write_generation_lifecycle(
        channel_root,
        &GenerationLifecycleWitness {
            schema_version: 1,
            channel: active.channel,
            generation: active.current.generation,
            state: GenerationLifecycleState::Committed,
            pin: Some(active.current.clone()),
        },
    )?;
    write_trust_witness(
        channel_root,
        &TrustWitness {
            schema_version: 1,
            channel: active.channel,
            epoch: active.epoch,
            established: true,
        },
    )?;
    write_pointer_file(channel_root, ACTIVE_FILE, &bytes)
}

fn normalize_active_recovery_prefix(
    channel_root: &Path,
    active: &ActiveTufState,
) -> Result<(), String> {
    // The caller has already selected and verified the exact generation under the refresh lock.
    // Replaying the normal commit prefix with the same epoch repairs every possible crash
    // boundary without creating a new epoch or trusting an unreferenced generation.
    write_active_state_with_generation_lifecycle(channel_root, active)
}

fn write_pointer_file(channel_root: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    let destination = channel_root.join(name);
    let temporary = channel_root.join(format!(".{name}-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("Cannot create temporary TUF state: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("Cannot write temporary TUF state: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Cannot flush temporary TUF state: {error}"))?;
        drop(file);
        replace_file(&temporary, &destination)?;
        sync_directory(channel_root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_bounded(path: &Path, maximum: usize) -> Result<Vec<u8>, String> {
    let mut file = open_regular_single_link(path, false)?;
    let length = file
        .metadata()
        .map_err(|error| format!("Cannot inspect trusted state {}: {error}", path.display()))?
        .len();
    if length > maximum as u64 {
        return Err(format!("Trusted state file is unsafe: {}", path.display()));
    }
    let capacity = usize::try_from(length)
        .map_err(|_| format!("Trusted state file is oversized: {}", path.display()))?;
    let mut bytes = Vec::with_capacity(capacity);
    let read_limit = maximum
        .checked_add(1)
        .ok_or_else(|| "Trusted state read limit overflowed".to_string())?;
    Read::by_ref(&mut file)
        .take(read_limit as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("Cannot read trusted state {}: {error}", path.display()))?;
    if bytes.len() > maximum {
        return Err(format!("Trusted state file is unsafe: {}", path.display()));
    }
    if bytes.len() != capacity {
        return Err(format!(
            "Trusted state file changed while reading: {}",
            path.display()
        ));
    }
    Ok(bytes)
}

impl RoleVersions {
    fn is_valid(self) -> bool {
        self.root > 0 && self.timestamp > 0 && self.snapshot > 0 && self.targets > 0
    }

    fn dominates(self, older: Self) -> bool {
        self.root >= older.root
            && self.timestamp >= older.timestamp
            && self.snapshot >= older.snapshot
            && self.targets >= older.targets
    }
}

impl From<RoleVersions> for TrustedRoleVersions {
    fn from(value: RoleVersions) -> Self {
        Self {
            root: value.root,
            timestamp: value.timestamp,
            snapshot: value.snapshot,
            targets: value.targets,
        }
    }
}

impl DatastoreHashes {
    fn values(&self) -> impl Iterator<Item = &str> {
        [
            self.root_json.as_str(),
            self.timestamp_json.as_str(),
            self.snapshot_json.as_str(),
            self.targets_json.as_str(),
            self.latest_known_time_json.as_str(),
        ]
        .into_iter()
    }

    fn get(&self, name: &str) -> Option<&str> {
        match name {
            "root.json" => Some(&self.root_json),
            "timestamp.json" => Some(&self.timestamp_json),
            "snapshot.json" => Some(&self.snapshot_json),
            "targets.json" => Some(&self.targets_json),
            "latest_known_time.json" => Some(&self.latest_known_time_json),
            _ => None,
        }
    }

    fn from_map(mut hashes: BTreeMap<&'static str, String>) -> Result<Self, String> {
        let mut take = |name| {
            hashes
                .remove(name)
                .ok_or_else(|| format!("TUF datastore hash is missing for {name}"))
        };
        let value = Self {
            root_json: take("root.json")?,
            timestamp_json: take("timestamp.json")?,
            snapshot_json: take("snapshot.json")?,
            targets_json: take("targets.json")?,
            latest_known_time_json: take("latest_known_time.json")?,
        };
        if !hashes.is_empty() {
            return Err("TUF datastore hash set contains unexpected entries".into());
        }
        Ok(value)
    }
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn generation_path(channel_root: &Path, generation: Uuid) -> PathBuf {
    channel_root
        .join("generations")
        .join(generation.to_string())
}

fn datastore_limit(name: &str) -> usize {
    match name {
        "root.json" => MAX_TRUSTED_ROOT_BYTES,
        "timestamp.json" => 256 * 1024,
        "snapshot.json" => 1024 * 1024,
        "targets.json" => 8 * 1024 * 1024,
        "latest_known_time.json" => LATEST_KNOWN_TIME_LIMIT,
        _ => 0,
    }
}

fn verify_datastore_directory(directory: &Path) -> Result<(), String> {
    verify_generation_directory(directory)?;
    let expected: HashSet<_> = DATASTORE_FILES.into_iter().collect();
    let mut actual = HashSet::new();
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("Cannot read TUF datastore directory: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Cannot inspect TUF datastore: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "TUF datastore contains a non-UTF-8 name".to_string())?;
        if !expected.contains(name.as_str()) || !actual.insert(name.clone()) {
            return Err(format!("TUF datastore contains an unexpected file: {name}"));
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Cannot inspect TUF datastore file {name}: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err(format!("Unsafe TUF datastore file: {name}"));
        }
    }
    if actual.len() != expected.len() {
        return Err("TUF datastore is missing a committed file".into());
    }
    Ok(())
}

fn verify_generation_directory(directory: &Path) -> Result<(), String> {
    inspect_existing_ancestors(directory)?;
    let metadata = fs::symlink_metadata(directory)
        .map_err(|error| format!("Cannot inspect TUF datastore directory: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("TUF datastore path is not a safe directory".into());
    }
    Ok(())
}

fn verify_datastore_pin(channel_root: &Path, pin: &GenerationPin) -> Result<(), String> {
    let directory = generation_path(channel_root, pin.generation);
    verify_datastore_directory(&directory)?;
    for name in DATASTORE_FILES {
        let bytes = read_bounded(&directory.join(name), datastore_limit(name))?;
        let actual = format!("{:x}", Sha256::digest(&bytes));
        let expected = pin
            .files
            .get(name)
            .expect("fixed datastore name must have a hash");
        if actual != expected {
            return Err(format!("TUF datastore hash mismatch: {name}"));
        }
    }
    verify_datastore_versions(&directory, pin.versions)
}

fn verify_datastore_versions(directory: &Path, expected: RoleVersions) -> Result<(), String> {
    let actual = RoleVersions {
        root: metadata_version(&read_bounded(
            &directory.join("root.json"),
            MAX_TRUSTED_ROOT_BYTES,
        )?)?,
        timestamp: metadata_version(&read_bounded(
            &directory.join("timestamp.json"),
            datastore_limit("timestamp.json"),
        )?)?,
        snapshot: metadata_version(&read_bounded(
            &directory.join("snapshot.json"),
            datastore_limit("snapshot.json"),
        )?)?,
        targets: metadata_version(&read_bounded(
            &directory.join("targets.json"),
            datastore_limit("targets.json"),
        )?)?,
    };
    if actual != expected {
        return Err("TUF datastore metadata versions do not match the active pin".into());
    }
    Ok(())
}

fn metadata_version(bytes: &[u8]) -> Result<u64, String> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| format!("TUF metadata JSON is invalid: {error}"))?;
    value
        .get("signed")
        .and_then(|signed| signed.get("version"))
        .and_then(serde_json::Value::as_u64)
        .filter(|version| *version > 0)
        .ok_or_else(|| "TUF metadata version is invalid".into())
}

fn sync_and_pin_datastore(
    directory: &Path,
    generation: Uuid,
    versions: RoleVersions,
) -> Result<GenerationPin, String> {
    verify_datastore_directory(directory)?;
    let mut hashes = BTreeMap::new();
    for name in DATASTORE_FILES {
        let file = open_regular_single_link(&directory.join(name), true)?;
        file.sync_all().map_err(|error| {
            format!("Cannot flush committed TUF datastore file {name}: {error}")
        })?;
        drop(file);
        let bytes = read_bounded(&directory.join(name), datastore_limit(name))?;
        hashes.insert(name, format!("{:x}", Sha256::digest(&bytes)));
    }
    verify_datastore_versions(directory, versions)?;
    verify_datastore_directory(directory)?;
    sync_directory(directory)?;
    let parent = directory
        .parent()
        .ok_or_else(|| "TUF generation directory has no parent".to_string())?;
    sync_directory(parent)?;
    Ok(GenerationPin {
        generation,
        versions,
        files: DatastoreHashes::from_map(hashes)?,
    })
}

fn repository_versions(repository: &Repository) -> RoleVersions {
    RoleVersions {
        root: repository.root().signed.version.get(),
        timestamp: repository.timestamp().signed.version.get(),
        snapshot: repository.snapshot().signed.version.get(),
        targets: repository.targets().signed.version.get(),
    }
}

fn enforce_rollback_ledger(
    datastore: &Path,
    current: RoleVersions,
    active: &ActiveTufState,
) -> Result<(), String> {
    let ledger = active.rollback_ledger;
    if !current.dominates(ledger) {
        return Err("TUF repository is older than the committed rollback ledger".into());
    }
    for (name, current_version, ledger_version) in [
        ("root.json", current.root, ledger.root),
        ("timestamp.json", current.timestamp, ledger.timestamp),
        ("snapshot.json", current.snapshot, ledger.snapshot),
        ("targets.json", current.targets, ledger.targets),
    ] {
        if current_version == ledger_version {
            let bytes = read_bounded(&datastore.join(name), datastore_limit(name))?;
            let actual = format!("{:x}", Sha256::digest(&bytes));
            let expected = active
                .current
                .files
                .get(name)
                .expect("fixed TUF metadata name must have a hash");
            if actual != expected {
                return Err(format!(
                    "TUF metadata changed without a monotonic version increase: {name}"
                ));
            }
        }
    }
    Ok(())
}

fn map_tuf_load_error(error: tough::error::Error) -> String {
    typed_tuf_error(&error).unwrap_or_else(|| format!("TUF metadata refresh failed: {error}"))
}

fn typed_tuf_error(error: &(dyn StdError + 'static)) -> Option<String> {
    let mut source: &(dyn StdError + 'static) = error;
    loop {
        if let Some(http) = source.downcast_ref::<SparkTufHttpError>() {
            return Some(http.launcher_error_code());
        }
        let Some(next) = source.source() else {
            break;
        };
        source = next;
    }
    None
}

fn generation_is_referenced(channel_root: &Path, channel: BuildChannel, generation: Uuid) -> bool {
    match read_active_state(channel_root, channel) {
        Ok(Some(active)) => {
            active.current.generation == generation
                || active
                    .previous
                    .as_ref()
                    .is_some_and(|pin| pin.generation == generation)
        }
        Ok(None) => false,
        // Ambiguous state must fail safe. A later successful refresh can prune the orphan.
        Err(_) => true,
    }
}

#[cfg(not(windows))]
fn sync_directory(directory: &Path) -> Result<(), String> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            format!(
                "Cannot flush TUF directory {}: {error}",
                directory.display()
            )
        })
}

#[cfg(windows)]
fn sync_directory(directory: &Path) -> Result<(), String> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| {
            format!(
                "Cannot flush TUF directory {}: {error}",
                directory.display()
            )
        })
}

fn prune_generations(
    channel_root: &Path,
    channel: BuildChannel,
    current: Uuid,
    previous: Option<Uuid>,
) -> Result<(), String> {
    let keep: HashSet<_> = [Some(current), previous].into_iter().flatten().collect();
    for id in generation_ids_bounded(channel_root, TUF_GENERATION_NAMESPACE_LIMIT)? {
        if !keep.contains(&id) {
            remove_generation_bounded(channel_root, id)?;
            let _ = remove_generation_lifecycle(channel_root, channel, id);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::{contracts, release};
    use super::*;
    use std::{
        num::NonZeroU64,
        time::{SystemTime, UNIX_EPOCH},
    };
    use tough::{
        editor::{signed::PathExists, RepositoryEditor},
        key_source::{KeySource, LocalKeySource},
        FilesystemTransport,
    };

    fn evidence_for_semantics(version: u64) -> TrustedReleaseEvidence {
        let target = |name: &str, marker: char| TrustedTargetEvidence {
            name: name.into(),
            length: 1,
            sha256: marker.to_string().repeat(64),
        };
        TrustedReleaseEvidence {
            schema_version: TRUSTED_RELEASE_EVIDENCE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            roles: TrustedRoleVersions {
                root: version,
                timestamp: version,
                snapshot: version,
                targets: version,
            },
            current: target("current.json", 'a'),
            release_manifest: target("release-rel_aaaaaaaaaaaaaaaaaaaaaaaa.json", 'b'),
            java_runtime_lock: target("runtime-windows-x64.json", 'c'),
            game_runtime_lock: target("game-runtime-windows-x64.json", 'd'),
        }
    }

    #[test]
    fn every_tuf_role_is_independently_rollback_protected() {
        let old = evidence_for_semantics(2);
        for roles in [
            TrustedRoleVersions {
                root: 1,
                ..old.roles
            },
            TrustedRoleVersions {
                timestamp: 1,
                ..old.roles
            },
            TrustedRoleVersions {
                snapshot: 1,
                ..old.roles
            },
            TrustedRoleVersions {
                targets: 1,
                ..old.roles
            },
        ] {
            let mut rollback = old.clone();
            rollback.roles = roles;
            assert!(!old.roles_are_monotonic_to(&rollback));
            assert!(!old.targets_match_and_roles_are_monotonic_to(&rollback));
        }
    }

    #[test]
    fn role_monotonicity_and_each_signed_target_binding_are_independent() {
        let old = evidence_for_semantics(1);
        let mut higher = old.clone();
        higher.roles = TrustedRoleVersions {
            root: 2,
            timestamp: 2,
            snapshot: 2,
            targets: 2,
        };
        assert!(old.roles_are_monotonic_to(&higher));
        assert!(old.targets_match(&higher));
        assert!(old.targets_match_and_roles_are_monotonic_to(&higher));

        for changed in 0..4 {
            let mut candidate = higher.clone();
            match changed {
                0 => candidate.current.sha256 = "e".repeat(64),
                1 => candidate.release_manifest.sha256 = "e".repeat(64),
                2 => candidate.java_runtime_lock.sha256 = "e".repeat(64),
                3 => candidate.game_runtime_lock.sha256 = "e".repeat(64),
                _ => unreachable!(),
            }
            assert!(old.roles_are_monotonic_to(&candidate));
            assert!(!old.targets_match(&candidate));
            assert!(!old.targets_match_and_roles_are_monotonic_to(&candidate));
        }
    }

    #[test]
    fn refresh_error_preserves_http_authentication_classification() {
        assert!(matches!(
            TufRefreshError::from("spark_session_invalid".to_owned()),
            TufRefreshError::Authentication(_)
        ));
        assert!(matches!(
            TufRefreshError::from("spark_subscription_required".to_owned()),
            TufRefreshError::Forbidden(_)
        ));
        assert_eq!(
            TufRefreshError::from("launcher_update_required:2.3.4".to_owned()),
            TufRefreshError::LauncherUpdateRequired("2.3.4".into())
        );
        assert!(matches!(
            TufRefreshError::from("launcher_update_required:not-semver".to_owned()),
            TufRefreshError::Failed(_)
        ));
        assert!(matches!(
            TufRefreshError::from("TUF metadata signature failed".to_owned()),
            TufRefreshError::Failed(_)
        ));
    }

    const TEST_TUF_ROOT: &[u8] = include_bytes!("../../tests/fixtures/tuf-test-root.json");
    // Fixed PKCS#8 v1 Ed25519 key used only for the local test root above. `tough` 0.24 accepts
    // this DER form directly; no production root or online signer is involved.
    const TEST_TUF_KEY: &[u8] = &[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20, 0xd9, 0xa8, 0xeb, 0xc3, 0x17, 0x44, 0xd7, 0x33, 0x2b, 0x1c, 0xc2, 0x7c, 0xe0, 0x35,
        0x7b, 0x9e, 0x1e, 0xb8, 0x33, 0x24, 0x73, 0xef, 0x7e, 0x5c, 0x7d, 0x15, 0x27, 0x03, 0x69,
        0x92, 0xeb, 0x3f,
    ];

    struct ReleasePayloads {
        current: Vec<u8>,
        manifest: Vec<u8>,
        java: Vec<u8>,
        game: Vec<u8>,
        manifest_target: String,
        java_target: String,
        game_target: String,
        java_sha256: String,
        game_sha256: String,
    }

    #[derive(Clone, Copy)]
    enum FixtureShape {
        Exact,
        MissingGame,
        SignedExtra,
    }

    fn release_payloads() -> ReleasePayloads {
        let mut java = contracts::tests::runtime_lock();
        let game_template = contracts::tests::game_runtime_lock();
        java["minecraft"]["versionJsonUrl"] =
            game_template["provenance"]["minecraftVersionJson"]["url"].clone();
        java["minecraft"]["versionJsonSha1"] =
            game_template["provenance"]["minecraftVersionJson"]["sha1"].clone();
        let java_archive_size = java["java"]["archive"]["size"].clone();
        let java_archive_sha256 = java["java"]["archive"]["sha256"].clone();
        let java = serde_json::to_vec(&java).expect("Java runtime fixture must serialize");
        let java_sha256 = format!("{:x}", Sha256::digest(&java));
        let runtime_lock = contracts::RuntimeLock::parse_and_validate(&java)
            .expect("Java runtime fixture must validate");
        let game = contracts::tests::verified_game_runtime_lock_for(
            &java_sha256,
            &runtime_lock.java.archive.sha256,
            &runtime_lock
                .extracted_tree_sha256()
                .expect("Java runtime tree digest must compute"),
        );
        let game = serde_json::to_vec(&game).expect("game runtime fixture must serialize");
        let game_sha256 = format!("{:x}", Sha256::digest(&game));
        let java_target = format!("runtime-windows-x64-{java_sha256}.json");
        let game_target = format!("game-runtime-windows-x64-{game_sha256}.json");

        let mut manifest = release::tests::manifest();
        manifest["runtime"]["java"]["runtimeTarget"] =
            serde_json::Value::String(java_target.clone());
        manifest["runtime"]["java"]["runtimeLockSha256"] =
            serde_json::Value::String(java_sha256.clone());
        manifest["runtime"]["java"]["archive"]["size"] = java_archive_size;
        manifest["runtime"]["java"]["archive"]["sha256"] = java_archive_sha256;
        manifest["runtime"]["game"]["runtimeTarget"] =
            serde_json::Value::String(game_target.clone());
        manifest["runtime"]["game"]["runtimeLockSha256"] =
            serde_json::Value::String(game_sha256.clone());
        let release_id = manifest["release"]["id"]
            .as_str()
            .expect("release fixture must have an ID");
        let manifest_target = format!("release-{release_id}.json");
        let current = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1,
            "channel": "stable",
            "releaseId": release_id,
            "manifestTarget": manifest_target,
        }))
        .expect("current fixture must serialize");

        ReleasePayloads {
            current,
            manifest: serde_json::to_vec(&manifest).expect("release fixture must serialize"),
            java,
            game,
            manifest_target,
            java_target,
            game_target,
            java_sha256,
            game_sha256,
        }
    }

    async fn signed_release_repository(
        directory: &Path,
        payloads: &ReleasePayloads,
        shape: FixtureShape,
    ) -> (Repository, PathBuf) {
        let source = directory.join("source-targets");
        let metadata = directory.join("metadata");
        let published = directory.join("targets");
        fs::create_dir_all(&source).expect("fixture source directory must be created");
        let root_path = directory.join("root.json");
        let key_path = directory.join("test-key.pk8");
        fs::write(&root_path, TEST_TUF_ROOT).expect("test root must be written");
        fs::write(&key_path, TEST_TUF_KEY).expect("test key must be written");

        let current_path = source.join("current.json");
        let manifest_path = source.join(&payloads.manifest_target);
        let java_path = source.join(&payloads.java_target);
        let game_path = source.join(&payloads.game_target);
        fs::write(&current_path, &payloads.current).expect("current target must be written");
        fs::write(&manifest_path, &payloads.manifest).expect("manifest target must be written");
        fs::write(&java_path, &payloads.java).expect("Java target must be written");
        fs::write(&game_path, &payloads.game).expect("game target must be written");
        let mut target_paths = vec![current_path, manifest_path, java_path];
        if !matches!(shape, FixtureShape::MissingGame) {
            target_paths.push(game_path);
        }
        if matches!(shape, FixtureShape::SignedExtra) {
            let extra = source.join("unexpected-signed-target.json");
            fs::write(&extra, br#"{"unexpected":true}"#).expect("extra target must be written");
            target_paths.push(extra);
        }

        let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource { path: key_path })];
        let one = NonZeroU64::new(1).expect("one is non-zero");
        let expires = || timestamp("2999-01-01T00:00:00Z");
        let mut editor = RepositoryEditor::new(&root_path)
            .await
            .expect("test root must authenticate");
        editor
            .targets_version(one)
            .expect("targets version must be set")
            .targets_expires(expires())
            .expect("targets expiration must be set")
            .snapshot_version(one)
            .snapshot_expires(expires())
            .timestamp_version(one)
            .timestamp_expires(expires())
            .add_target_paths(target_paths)
            .await
            .expect("fixture targets must be indexed");
        let signed = editor
            .sign(&keys)
            .await
            .expect("fixture metadata must be signed");
        signed
            .write(&metadata)
            .await
            .expect("fixture metadata must be published");
        signed
            .copy_targets(&source, &published, PathExists::Fail)
            .await
            .expect("fixture targets must be published");

        let repository = RepositoryLoader::new(
            &TEST_TUF_ROOT,
            Url::from_directory_path(&metadata).expect("metadata path must form a file URL"),
            Url::from_directory_path(&published).expect("target path must form a file URL"),
        )
        .transport(FilesystemTransport)
        .expiration_enforcement(ExpirationEnforcement::Safe)
        .load()
        .await
        .expect("signed fixture repository must authenticate");
        (repository, published)
    }

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-tuf-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn root(version: u64) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({ "signed": { "version": version } })).unwrap()
    }

    fn versions(version: u64) -> RoleVersions {
        RoleVersions {
            root: version,
            timestamp: version,
            snapshot: version,
            targets: version,
        }
    }

    fn timestamp(value: &str) -> Timestamp {
        value.parse().unwrap()
    }

    fn create_datastore(channel_root: &Path, version: u64) -> GenerationPin {
        let generation = Uuid::new_v4();
        let directory = generation_path(channel_root, generation);
        fs::create_dir_all(&directory).unwrap();
        for name in [
            "root.json",
            "timestamp.json",
            "snapshot.json",
            "targets.json",
        ] {
            fs::write(directory.join(name), root(version)).unwrap();
        }
        fs::write(
            directory.join("latest_known_time.json"),
            format!("\"2026-07-{:02}T00:00:00Z\"", 10 + version),
        )
        .unwrap();
        sync_and_pin_datastore(&directory, generation, versions(version)).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn trusted_release_requires_an_untampered_exact_four_target_repository() {
        let directory = temp_root("signed-release-e2e");
        fs::create_dir_all(&directory).expect("fixture root must be created");
        let payloads = release_payloads();

        let (repository, published) =
            signed_release_repository(&directory.join("exact"), &payloads, FixtureShape::Exact)
                .await;
        fs::write(
            published.join("unsigned-historical-target.bin"),
            b"not present in signed targets metadata",
        )
        .expect("an unsigned historical object must be materialized");
        assert_eq!(repository.all_targets().count(), 4);
        let signed_versions = repository_versions(&repository);
        assert_eq!(signed_versions, versions(1));
        let trusted = read_trusted_release(&repository, BuildChannel::Stable, signed_versions.root)
            .await
            .expect("the exact signed release must be trusted");
        assert_eq!(trusted.tuf_root_version, 1);
        assert_eq!(trusted.channel, BuildChannel::Stable);
        assert_eq!(trusted.current.manifest_target, payloads.manifest_target);
        assert_eq!(
            trusted.manifest.runtime.java.runtime_target,
            payloads.java_target
        );
        assert_eq!(
            trusted.manifest.runtime.java.runtime_lock_sha256,
            payloads.java_sha256
        );
        assert_eq!(
            trusted.manifest.runtime.game.runtime_target,
            payloads.game_target
        );
        assert_eq!(
            trusted.manifest.runtime.game.runtime_lock_sha256,
            payloads.game_sha256
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&payloads.java)),
            trusted.manifest.runtime.java.runtime_lock_sha256
        );
        assert_eq!(
            format!("{:x}", Sha256::digest(&payloads.game)),
            trusted.manifest.runtime.game.runtime_lock_sha256
        );
        assert_eq!(trusted.runtime_lock.java.major, 25);
        assert_eq!(
            trusted.game_runtime_lock.id,
            "minecraft-1.21.1-neoforge-21.1.235-windows-x64"
        );

        let published_game =
            published.join(format!("{}.{}", payloads.game_sha256, payloads.game_target));
        let mut tampered = fs::read(&published_game).expect("published game target must exist");
        let midpoint = tampered.len() / 2;
        tampered[midpoint] ^= 1;
        fs::write(&published_game, tampered).expect("published target must be tampered");
        let tamper_error =
            read_trusted_release(&repository, BuildChannel::Stable, signed_versions.root)
                .await
                .expect_err("TUF must reject tampered target bytes");
        let normalized = tamper_error.to_ascii_lowercase();
        assert!(
            normalized.contains("hash") || normalized.contains("verif"),
            "unexpected tamper error: {tamper_error}"
        );

        fs::write(&published_game, &payloads.game).expect("game target must be restored");
        fs::remove_file(&published_game).expect("published game target must be removed");
        let missing_file_error =
            read_trusted_release(&repository, BuildChannel::Stable, signed_versions.root)
                .await
                .expect_err("TUF must reject a missing signed target file");
        assert!(
            missing_file_error.contains(&payloads.game_target),
            "unexpected missing-file error: {missing_file_error}"
        );
        drop(repository);

        let (missing, _) = signed_release_repository(
            &directory.join("missing"),
            &payloads,
            FixtureShape::MissingGame,
        )
        .await;
        assert_eq!(missing.all_targets().count(), 3);
        let missing_error = read_trusted_release(&missing, BuildChannel::Stable, 1)
            .await
            .expect_err("a referenced missing target must fail closed");
        assert!(missing_error.contains("target set is not exact"));
        assert!(missing_error.contains(&payloads.game_target));
        drop(missing);

        let (extra, _) = signed_release_repository(
            &directory.join("extra"),
            &payloads,
            FixtureShape::SignedExtra,
        )
        .await;
        assert_eq!(extra.all_targets().count(), 5);
        let extra_error = read_trusted_release(&extra, BuildChannel::Stable, 1)
            .await
            .expect_err("a signed fifth target must fail closed");
        assert!(extra_error.contains("target set is not exact"));
        assert!(extra_error.contains("unexpected-signed-target.json"));
        drop(extra);

        fs::remove_dir_all(directory).expect("fixture root must be removed");
    }

    #[test]
    fn builds_channel_isolated_repository_urls() {
        let (metadata, targets, metadata_prefix, targets_prefix) =
            repository_urls(BuildChannel::Dev).unwrap();
        assert_eq!(
            metadata.as_str(),
            "https://fragmc.ru/api/spark2/v1/repositories/dev/metadata/"
        );
        assert_eq!(
            targets.as_str(),
            "https://fragmc.ru/api/spark2/v1/repositories/dev/targets/"
        );
        assert!(metadata_prefix.contains("/dev/"));
        assert!(targets_prefix.contains("/dev/"));
    }

    #[test]
    fn refuses_corrupt_or_ambiguous_cached_roots() {
        let directory = temp_root("cached-root");
        fs::create_dir_all(&directory).unwrap();
        let cached_path = directory.join("root.json");
        fs::write(&cached_path, root(2)).unwrap();
        assert!(select_trusted_root(&root(1), &cached_path, 2, &"0".repeat(64)).is_err());

        let cached = root(2);
        let hash = format!("{:x}", Sha256::digest(&cached));
        assert_eq!(
            select_trusted_root(&root(1), &cached_path, 2, &hash).unwrap(),
            cached
        );
        assert_eq!(
            select_trusted_root(&root(3), &cached_path, 2, &hash).unwrap(),
            cached
        );

        let formatted =
            serde_json::to_vec_pretty(&serde_json::json!({ "signed": { "version": 2 } })).unwrap();
        assert_eq!(
            select_trusted_root(&formatted, &cached_path, 2, &hash).unwrap(),
            cached
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn active_state_is_atomic_and_channel_bound() {
        let directory = temp_root("active-state");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 2);
        let previous = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 2,
            rollback_ledger: current.versions,
            current,
            previous: Some(previous),
        };
        write_active_state(&directory, &active).unwrap();
        assert_eq!(
            read_active_state(&directory, BuildChannel::Stable).unwrap(),
            Some(active)
        );
        assert!(read_active_state(&directory, BuildChannel::Dev).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn exact_generation_limit_is_prepruned_before_admitting_a_refresh() {
        let directory = temp_root("generation-preprune");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 2);
        let previous = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 2,
            rollback_ledger: current.versions,
            current: current.clone(),
            previous: Some(previous.clone()),
        };
        for _ in 0..(TUF_GENERATION_NAMESPACE_LIMIT - 2) {
            fs::create_dir(generation_path(&directory, Uuid::new_v4())).unwrap();
        }
        assert_eq!(
            generation_ids_bounded(&directory, TUF_GENERATION_NAMESPACE_LIMIT)
                .unwrap()
                .len(),
            TUF_GENERATION_NAMESPACE_LIMIT
        );
        select_active_generation(&directory, &active).unwrap();

        pre_admit_generation_slot(&directory, BuildChannel::Stable, Some(&active)).unwrap();

        let remaining = generation_ids_bounded(&directory, TUF_GENERATION_NAMESPACE_LIMIT)
            .unwrap()
            .into_iter()
            .collect::<HashSet<_>>();
        assert_eq!(
            remaining,
            HashSet::from([current.generation, previous.generation])
        );
        for pin in [&current, &previous] {
            let (lifecycle, _) =
                read_generation_lifecycle(&directory, BuildChannel::Stable, pin.generation)
                    .unwrap()
                    .unwrap();
            assert_eq!(lifecycle.state, GenerationLifecycleState::Committed);
            assert_eq!(lifecycle.pin.as_ref(), Some(pin));
        }
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn over_limit_generation_namespace_fails_before_preprune_mutation() {
        let directory = temp_root("generation-over-limit");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 2);
        let previous = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 2,
            rollback_ledger: current.versions,
            current,
            previous: Some(previous),
        };
        let mut paths = fs::read_dir(directory.join("generations"))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect::<Vec<_>>();
        for _ in paths.len()..=TUF_GENERATION_NAMESPACE_LIMIT {
            let path = generation_path(&directory, Uuid::new_v4());
            fs::create_dir(&path).unwrap();
            paths.push(path);
        }
        assert_eq!(paths.len(), TUF_GENERATION_NAMESPACE_LIMIT + 1);

        assert!(
            pre_admit_generation_slot(&directory, BuildChannel::Stable, Some(&active)).is_err()
        );
        assert!(paths.iter().all(|path| path.is_dir()));
        assert!(namespace_path_is_absent(&directory.join(GENERATION_LIFECYCLE_DIRECTORY)).unwrap());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn active_v2_never_ignores_a_missing_or_corrupt_recovery_pointer() {
        let directory = temp_root("pointer-fail-closed");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 2);
        let previous = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 2,
            rollback_ledger: current.versions,
            current,
            previous: Some(previous),
        };
        write_active_state(&directory, &active).unwrap();

        fs::remove_file(directory.join(RECOVERY_FILE)).unwrap();
        assert!(read_active_state(&directory, BuildChannel::Stable).is_err());

        write_pointer_file(
            &directory,
            RECOVERY_FILE,
            br#"{"schemaVersion":2,"epoch":3"#,
        )
        .unwrap();
        assert!(read_active_state(&directory, BuildChannel::Stable).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn recovery_pointer_is_authoritative_when_active_is_missing() {
        let directory = temp_root("pointer-recovery");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 1,
            rollback_ledger: current.versions,
            current,
            previous: None,
        };
        write_active_state(&directory, &active).unwrap();
        write_generation_lifecycle(
            &directory,
            &GenerationLifecycleWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                generation: active.current.generation,
                state: GenerationLifecycleState::Committed,
                pin: Some(active.current.clone()),
            },
        )
        .unwrap();
        fs::remove_file(directory.join(ACTIVE_FILE)).unwrap();
        assert_eq!(
            read_active_state(&directory, BuildChannel::Stable).unwrap(),
            Some(active)
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn established_trust_can_never_be_misread_as_fresh_bootstrap() {
        let directory = temp_root("trust-established");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 1,
            rollback_ledger: current.versions,
            current,
            previous: None,
        };
        write_active_state(&directory, &active).unwrap();
        write_generation_lifecycle(
            &directory,
            &GenerationLifecycleWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                generation: active.current.generation,
                state: GenerationLifecycleState::Committed,
                pin: Some(active.current.clone()),
            },
        )
        .unwrap();
        fs::remove_file(directory.join(ACTIVE_FILE)).unwrap();
        fs::remove_file(directory.join(RECOVERY_FILE)).unwrap();
        assert!(read_active_state(&directory, BuildChannel::Stable).is_err());

        fs::remove_file(directory.join(TRUST_FILE)).unwrap();
        fs::remove_file(directory.join(TRUST_RECOVERY_FILE)).unwrap();
        assert!(recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).is_err());
        assert!(generation_path(&directory, active.current.generation).is_dir());
        assert!(read_active_state(&directory, BuildChannel::Stable).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn generation_without_lifecycle_is_preserved_as_ambiguous_trust() {
        let directory = temp_root("missing-lifecycle");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let generation = create_datastore(&directory, 1);

        assert!(recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).is_err());
        assert!(generation_path(&directory, generation.generation).is_dir());
        assert!(read_active_state(&directory, BuildChannel::Stable).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn corrupt_lifecycle_never_authorizes_generation_cleanup() {
        let directory = temp_root("corrupt-lifecycle");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let generation = create_datastore(&directory, 1);
        let lifecycle = ensure_generation_lifecycle_directory(&directory).unwrap();
        fs::write(
            lifecycle.join(format!("{}.json", generation.generation)),
            b"{corrupt",
        )
        .unwrap();

        assert!(recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).is_err());
        assert!(generation_path(&directory, generation.generation).is_dir());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn failed_first_bootstrap_with_only_clock_witness_remains_retryable() {
        let directory = temp_root("trust-failed-bootstrap");
        fs::create_dir_all(directory.join("generations")).unwrap();
        advance_clock_witness_at(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:00:00Z"),
            None,
        )
        .unwrap();
        assert!(read_active_state(&directory, BuildChannel::Stable)
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn crash_prefix_pretrust_generation_is_removed_and_never_adopted() {
        let directory = temp_root("pretrust-orphan");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let clock = advance_clock_witness_at(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:00:00Z"),
            None,
        )
        .unwrap();
        let orphan_id = Uuid::new_v4();
        let orphan = generation_path(&directory, orphan_id);
        write_generation_lifecycle(
            &directory,
            &GenerationLifecycleWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                generation: orphan_id,
                state: GenerationLifecycleState::Staging,
                pin: None,
            },
        )
        .unwrap();
        fs::create_dir(&orphan).unwrap();
        // Even plausible-looking bytes created before recovery.json are not trust authority.
        fs::write(orphan.join("root.json"), TEST_TUF_ROOT).unwrap();
        fs::write(
            directory.join(format!(".{RECOVERY_FILE}-crash.tmp")),
            br#"{"uncommitted":true}"#,
        )
        .unwrap();

        recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).unwrap();
        recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).unwrap();

        assert!(fs::symlink_metadata(&orphan).is_err());
        assert!(generations_are_empty(&directory).unwrap());
        assert_eq!(
            read_clock_witness(&directory, BuildChannel::Stable)
                .unwrap()
                .unwrap(),
            clock
        );
        assert!(read_active_state(&directory, BuildChannel::Stable)
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn prepared_generation_without_recovery_pointer_is_discarded() {
        let directory = temp_root("prepared-orphan");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let prepared = create_datastore(&directory, 1);
        write_generation_lifecycle(
            &directory,
            &GenerationLifecycleWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                generation: prepared.generation,
                state: GenerationLifecycleState::Prepared,
                pin: Some(prepared.clone()),
            },
        )
        .unwrap();

        recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).unwrap();

        assert!(generations_are_empty(&directory).unwrap());
        assert!(
            read_generation_lifecycle(&directory, BuildChannel::Stable, prepared.generation,)
                .unwrap()
                .is_none()
        );
        assert!(read_active_state(&directory, BuildChannel::Stable)
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn lifecycle_temporary_crash_prefix_does_not_block_bootstrap() {
        let directory = temp_root("lifecycle-temporary");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let lifecycle = ensure_generation_lifecycle_directory(&directory).unwrap();
        let temporary_name = format!(".{}.json-{}.tmp", Uuid::new_v4(), Uuid::new_v4());
        let temporary = lifecycle.join(&temporary_name);
        fs::write(&temporary, br#"{"schemaVersion":1"#).unwrap();
        assert!(is_generation_lifecycle_temporary_name(&temporary_name));

        recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).unwrap();

        assert!(fs::symlink_metadata(&temporary).is_err());
        assert!(read_active_state(&directory, BuildChannel::Stable)
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn corrupt_pointer_namespace_preserves_orphan_and_fails_closed() {
        let directory = temp_root("pretrust-ambiguous");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let orphan = generation_path(&directory, Uuid::new_v4());
        fs::create_dir(&orphan).unwrap();
        fs::write(directory.join(RECOVERY_FILE), b"{corrupt").unwrap();

        recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).unwrap();

        assert!(orphan.is_dir());
        assert!(read_active_state(&directory, BuildChannel::Stable).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn pretrust_generation_count_limit_rejects_before_any_cleanup() {
        let directory = temp_root("pretrust-limit");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let orphans = (0..=PRETRUST_ORPHAN_GENERATION_LIMIT)
            .map(|_| {
                let orphan = generation_path(&directory, Uuid::new_v4());
                fs::create_dir(&orphan).unwrap();
                orphan
            })
            .collect::<Vec<_>>();

        assert!(recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).is_err());
        assert!(orphans.iter().all(|orphan| orphan.is_dir()));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn first_commit_recovery_pointer_survives_pre_witness_crash_window() {
        let directory = temp_root("trust-write-order");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 1,
            rollback_ledger: current.versions,
            current,
            previous: None,
        };
        let bytes = serde_json::to_vec_pretty(&active).unwrap();
        write_generation_lifecycle(
            &directory,
            &GenerationLifecycleWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                generation: active.current.generation,
                state: GenerationLifecycleState::Prepared,
                pin: Some(active.current.clone()),
            },
        )
        .unwrap();
        write_pointer_file(&directory, RECOVERY_FILE, &bytes).unwrap();
        recover_pretrust_orphan_generations(&directory, BuildChannel::Stable).unwrap();
        assert!(generation_path(&directory, active.current.generation).is_dir());
        assert_eq!(
            read_active_state(&directory, BuildChannel::Stable).unwrap(),
            Some(active.clone())
        );
        select_active_generation(&directory, &active).unwrap();
        pre_admit_generation_slot(&directory, BuildChannel::Stable, Some(&active)).unwrap();
        assert_eq!(
            read_generation_lifecycle(&directory, BuildChannel::Stable, active.current.generation,)
                .unwrap()
                .unwrap()
                .0
                .state,
            GenerationLifecycleState::Committed
        );

        write_trust_witness(
            &directory,
            &TrustWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                epoch: 1,
                established: true,
            },
        )
        .unwrap();
        assert_eq!(
            read_active_state(&directory, BuildChannel::Stable).unwrap(),
            Some(active)
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn every_recovery_first_crash_boundary_is_normalized_before_the_next_active_epoch() {
        for crash_boundary in 0..=4 {
            let directory = temp_root(&format!("active-prefix-{crash_boundary}"));
            fs::create_dir_all(directory.join("generations")).unwrap();
            let first = create_datastore(&directory, 1);
            let first_state = ActiveTufState {
                schema_version: ACTIVE_STATE_SCHEMA_VERSION,
                channel: BuildChannel::Stable,
                epoch: 1,
                rollback_ledger: first.versions,
                current: first,
                previous: None,
            };
            write_active_state_with_generation_lifecycle(&directory, &first_state).unwrap();

            let second = create_datastore(&directory, 2);
            let second_state = ActiveTufState {
                schema_version: ACTIVE_STATE_SCHEMA_VERSION,
                channel: BuildChannel::Stable,
                epoch: 2,
                rollback_ledger: second.versions,
                current: second,
                previous: Some(first_state.current.clone()),
            };
            write_generation_lifecycle(
                &directory,
                &GenerationLifecycleWitness {
                    schema_version: 1,
                    channel: BuildChannel::Stable,
                    generation: second_state.current.generation,
                    state: GenerationLifecycleState::Prepared,
                    pin: Some(second_state.current.clone()),
                },
            )
            .unwrap();
            let second_bytes = active_state_bytes(&second_state).unwrap();
            write_pointer_file(&directory, RECOVERY_FILE, &second_bytes).unwrap();

            if crash_boundary >= 1 {
                write_generation_lifecycle(
                    &directory,
                    &GenerationLifecycleWitness {
                        schema_version: 1,
                        channel: BuildChannel::Stable,
                        generation: second_state.current.generation,
                        state: GenerationLifecycleState::Committed,
                        pin: Some(second_state.current.clone()),
                    },
                )
                .unwrap();
            }
            let second_trust = TrustWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                epoch: 2,
                established: true,
            };
            let second_trust_bytes = serde_json::to_vec_pretty(&second_trust).unwrap();
            if crash_boundary >= 2 {
                write_pointer_file(&directory, TRUST_RECOVERY_FILE, &second_trust_bytes).unwrap();
            }
            if crash_boundary >= 3 {
                write_pointer_file(&directory, TRUST_FILE, &second_trust_bytes).unwrap();
            }
            if crash_boundary >= 4 {
                write_pointer_file(&directory, ACTIVE_FILE, &second_bytes).unwrap();
            }

            let selected = read_active_state(&directory, BuildChannel::Stable)
                .unwrap()
                .unwrap();
            assert_eq!(selected, second_state);
            select_active_generation(&directory, &selected).unwrap();
            normalize_active_recovery_prefix(&directory, &selected).unwrap();

            for name in [ACTIVE_FILE, RECOVERY_FILE] {
                assert_eq!(
                    read_pointer_if_valid(&directory.join(name), BuildChannel::Stable)
                        .unwrap()
                        .unwrap(),
                    second_state
                );
            }
            for name in [TRUST_FILE, TRUST_RECOVERY_FILE] {
                assert_eq!(
                    read_trust_pointer(&directory.join(name), BuildChannel::Stable)
                        .unwrap()
                        .unwrap(),
                    second_trust
                );
            }
            assert_eq!(
                read_generation_lifecycle(
                    &directory,
                    BuildChannel::Stable,
                    second_state.current.generation,
                )
                .unwrap()
                .unwrap()
                .0
                .state,
                GenerationLifecycleState::Committed
            );

            // Model the immediately following transaction dying after its recovery write. The
            // repaired active epoch is only one behind, so the next startup remains recoverable.
            let third = create_datastore(&directory, 3);
            let third_state = ActiveTufState {
                schema_version: ACTIVE_STATE_SCHEMA_VERSION,
                channel: BuildChannel::Stable,
                epoch: 3,
                rollback_ledger: third.versions,
                current: third,
                previous: Some(second_state.current.clone()),
            };
            write_generation_lifecycle(
                &directory,
                &GenerationLifecycleWitness {
                    schema_version: 1,
                    channel: BuildChannel::Stable,
                    generation: third_state.current.generation,
                    state: GenerationLifecycleState::Prepared,
                    pin: Some(third_state.current.clone()),
                },
            )
            .unwrap();
            write_pointer_file(
                &directory,
                RECOVERY_FILE,
                &active_state_bytes(&third_state).unwrap(),
            )
            .unwrap();
            assert_eq!(
                read_active_state(&directory, BuildChannel::Stable).unwrap(),
                Some(third_state)
            );
            let _ = fs::remove_dir_all(directory);
        }
    }

    #[test]
    fn durable_clock_survives_failed_refresh_and_rejects_rollback() {
        let directory = temp_root("clock-monotonic");
        fs::create_dir_all(&directory).unwrap();
        let first = advance_clock_witness_at(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:00:00Z"),
            None,
        )
        .unwrap();
        assert_eq!(first.epoch, 1);

        // No metadata generation is committed here: this models a failed network/load attempt.
        let second = advance_clock_witness_at(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:05:00Z"),
            None,
        )
        .unwrap();
        assert_eq!(second.epoch, 2);
        assert_eq!(
            read_clock_witness(&directory, BuildChannel::Stable)
                .unwrap()
                .unwrap(),
            second
        );
        assert!(advance_clock_witness_at(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:04:59Z"),
            None,
        )
        .is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn interrupted_clock_recovery_is_normalized_before_every_later_advance() {
        for active_write_completed in [false, true] {
            let directory = temp_root(&format!("clock-prefix-{active_write_completed}"));
            fs::create_dir_all(&directory).unwrap();
            let first = ClockWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                epoch: 1,
                latest_known_time: "2026-07-11T10:00:00Z".into(),
            };
            write_clock_witness(&directory, &first).unwrap();
            let second = ClockWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                epoch: 2,
                latest_known_time: "2026-07-11T10:01:00Z".into(),
            };
            let second_bytes = serde_json::to_vec_pretty(&second).unwrap();
            write_pointer_file(&directory, CLOCK_RECOVERY_FILE, &second_bytes).unwrap();
            if active_write_completed {
                write_pointer_file(&directory, CLOCK_FILE, &second_bytes).unwrap();
            }

            let third = advance_clock_witness_at(
                &directory,
                BuildChannel::Stable,
                timestamp("2026-07-11T10:02:00Z"),
                None,
            )
            .unwrap();
            assert_eq!(third.epoch, 3);

            // A second recovery-only crash must still be healed rather than accumulating a gap.
            let fourth = ClockWitness {
                schema_version: 1,
                channel: BuildChannel::Stable,
                epoch: 4,
                latest_known_time: "2026-07-11T10:03:00Z".into(),
            };
            write_pointer_file(
                &directory,
                CLOCK_RECOVERY_FILE,
                &serde_json::to_vec_pretty(&fourth).unwrap(),
            )
            .unwrap();
            let fifth = advance_clock_witness_at(
                &directory,
                BuildChannel::Stable,
                timestamp("2026-07-11T10:04:00Z"),
                None,
            )
            .unwrap();
            assert_eq!(fifth.epoch, 5);
            assert_eq!(
                read_clock_pointer(&directory.join(CLOCK_FILE), BuildChannel::Stable)
                    .unwrap()
                    .unwrap(),
                fifth
            );
            assert_eq!(
                read_clock_pointer(&directory.join(CLOCK_RECOVERY_FILE), BuildChannel::Stable,)
                    .unwrap()
                    .unwrap(),
                fifth
            );
            let _ = fs::remove_dir_all(directory);
        }
    }

    #[test]
    fn active_state_requires_an_existing_clock_witness() {
        let directory = temp_root("clock-active-floor");
        fs::create_dir_all(&directory).unwrap();
        assert!(advance_clock_witness_at(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:01:00Z"),
            Some(timestamp("2026-07-11T10:00:00Z")),
        )
        .is_err());
        assert!(read_clock_witness(&directory, BuildChannel::Stable)
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn clock_pointer_recovery_is_authoritative_and_fail_closed() {
        let directory = temp_root("clock-recovery");
        fs::create_dir_all(&directory).unwrap();
        let witness = advance_clock_witness_at(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:00:00Z"),
            None,
        )
        .unwrap();
        fs::remove_file(directory.join(CLOCK_FILE)).unwrap();
        assert_eq!(
            read_clock_witness(&directory, BuildChannel::Stable)
                .unwrap()
                .unwrap(),
            witness
        );

        write_clock_witness(&directory, &witness).unwrap();
        fs::remove_file(directory.join(CLOCK_RECOVERY_FILE)).unwrap();
        assert!(read_clock_witness(&directory, BuildChannel::Stable).is_err());
        fs::write(directory.join(CLOCK_RECOVERY_FILE), b"{corrupt").unwrap();
        assert!(read_clock_witness(&directory, BuildChannel::Stable).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn successful_load_observation_advances_clock_to_the_maximum() {
        let directory = temp_root("clock-observation");
        fs::create_dir_all(&directory).unwrap();
        advance_clock_witness_at(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:00:00Z"),
            None,
        )
        .unwrap();
        persist_clock_observation(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:01:00Z"),
        )
        .unwrap();
        let advanced = read_clock_witness(&directory, BuildChannel::Stable)
            .unwrap()
            .unwrap();
        assert_eq!(
            advanced.timestamp().unwrap(),
            timestamp("2026-07-11T10:01:00Z")
        );

        persist_clock_observation(
            &directory,
            BuildChannel::Stable,
            timestamp("2026-07-11T10:00:30Z"),
        )
        .unwrap();
        assert_eq!(
            read_clock_witness(&directory, BuildChannel::Stable)
                .unwrap()
                .unwrap()
                .timestamp()
                .unwrap(),
            timestamp("2026-07-11T10:01:00Z")
        );
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn exact_pins_reject_extra_missing_and_corrupt_files() {
        let directory = temp_root("exact-pin");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let pin = create_datastore(&directory, 1);
        let datastore = generation_path(&directory, pin.generation);
        assert!(verify_datastore_pin(&directory, &pin).is_ok());

        fs::write(datastore.join("unexpected.json"), b"{}").unwrap();
        assert!(verify_datastore_pin(&directory, &pin).is_err());
        fs::remove_file(datastore.join("unexpected.json")).unwrap();
        fs::write(datastore.join("targets.json"), root(2)).unwrap();
        assert!(verify_datastore_pin(&directory, &pin).is_err());
        fs::remove_file(datastore.join("targets.json")).unwrap();
        assert!(verify_datastore_pin(&directory, &pin).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn corrupt_current_metadata_recovers_with_current_root_and_time() {
        let directory = temp_root("fallback");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 2);
        let previous = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 2,
            rollback_ledger: current.versions,
            current: current.clone(),
            previous: Some(previous.clone()),
        };
        fs::write(
            generation_path(&directory, current.generation).join("timestamp.json"),
            b"corrupt",
        )
        .unwrap();
        let selected = select_active_generation(&directory, &active).unwrap();
        assert!(selected.is_recovery());
        assert_eq!(selected.metadata, previous);
        assert_eq!(selected.trust_continuity, current);

        let staged = directory.join("staged");
        fs::create_dir(&staged).unwrap();
        copy_datastore(&directory, &staged, &selected).unwrap();
        let current_path = generation_path(&directory, current.generation);
        let previous_path = generation_path(&directory, previous.generation);
        assert_eq!(
            fs::read(staged.join("root.json")).unwrap(),
            fs::read(current_path.join("root.json")).unwrap()
        );
        assert_eq!(
            fs::read(staged.join("latest_known_time.json")).unwrap(),
            fs::read(current_path.join("latest_known_time.json")).unwrap()
        );
        assert_eq!(
            fs::read(staged.join("snapshot.json")).unwrap(),
            fs::read(previous_path.join("snapshot.json")).unwrap()
        );
        let current_root_hash = current.files.root_json.clone();
        assert_eq!(
            root_version(
                &select_trusted_root(
                    &root(1),
                    &staged.join("root.json"),
                    current.versions.root,
                    &current_root_hash,
                )
                .unwrap()
            )
            .unwrap(),
            2
        );
        assert!(enforce_rollback_ledger(&previous_path, versions(1), &active).is_err());
        let refreshed = create_datastore(&directory, 2);
        let refreshed_path = generation_path(&directory, refreshed.generation);
        assert!(enforce_rollback_ledger(&refreshed_path, versions(2), &active).is_ok());
        fs::write(
            refreshed_path.join("targets.json"),
            br#"{"signed":{"version":2,"fork":true}}"#,
        )
        .unwrap();
        assert!(enforce_rollback_ledger(&refreshed_path, versions(2), &active).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn fallback_rejects_a_corrupt_current_root() {
        let directory = temp_root("fallback-root");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 2);
        let previous = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 2,
            rollback_ledger: current.versions,
            current: current.clone(),
            previous: Some(previous),
        };
        fs::write(
            generation_path(&directory, current.generation).join("root.json"),
            b"corrupt",
        )
        .unwrap();
        assert!(select_active_generation(&directory, &active).is_err());
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn fallback_rejects_a_corrupt_current_latest_known_time() {
        let directory = temp_root("fallback-time");
        fs::create_dir_all(directory.join("generations")).unwrap();
        let current = create_datastore(&directory, 2);
        let previous = create_datastore(&directory, 1);
        let active = ActiveTufState {
            schema_version: ACTIVE_STATE_SCHEMA_VERSION,
            channel: BuildChannel::Stable,
            epoch: 2,
            rollback_ledger: current.versions,
            current: current.clone(),
            previous: Some(previous),
        };
        fs::write(
            generation_path(&directory, current.generation).join("latest_known_time.json"),
            b"corrupt",
        )
        .unwrap();
        assert!(select_active_generation(&directory, &active).is_err());
        let _ = fs::remove_dir_all(directory);
    }
}
