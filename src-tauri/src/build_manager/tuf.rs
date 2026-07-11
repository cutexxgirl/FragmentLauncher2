use super::{
    contracts::RuntimeLock,
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
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
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
const DATASTORE_FILES: [&str; 5] = [
    "root.json",
    "timestamp.json",
    "snapshot.json",
    "targets.json",
    "latest_known_time.json",
];

#[derive(Debug)]
pub struct TrustedRelease {
    pub channel: BuildChannel,
    pub current: CurrentPointer,
    pub manifest: ReleaseManifest,
    pub runtime_lock: RuntimeLock,
    pub tuf_root_version: u64,
}

#[derive(Debug, Clone)]
pub struct SparkTufClient {
    state_root: PathBuf,
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
    ) -> Result<TrustedRelease, String> {
        if embedded_root.is_empty() || embedded_root.len() > MAX_TRUSTED_ROOT_BYTES {
            return Err("Embedded TUF root is missing or oversized".into());
        }
        let channel_root = self.state_root.join(channel.as_str());
        let generations = channel_root.join("generations");
        inspect_existing_ancestors(&channel_root)?;
        fs::create_dir_all(&generations)
            .map_err(|error| format!("Cannot create TUF state directories: {error}"))?;
        inspect_existing_ancestors(&generations)?;

        let lock = acquire_lock(&channel_root.join(".refresh.lock")).await?;
        let active = read_active_state(&channel_root, channel)?;
        let active_clock_floor = active
            .as_ref()
            .map(|state| read_pinned_latest_known_time(&channel_root, &state.current))
            .transpose()?;
        let clock =
            advance_clock_witness_at(&channel_root, channel, Timestamp::now(), active_clock_floor)?;
        let generation_id = Uuid::new_v4();
        let generation = generations.join(generation_id.to_string());
        fs::create_dir(&generation)
            .map_err(|error| format!("Cannot create TUF staging generation: {error}"))?;
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
                let _ = fs::remove_dir_all(&generation);
            }
        }
        // Dropping the file also releases the lock. In particular, an unlock failure after a
        // committed active pointer must never turn a successful refresh into a reported failure.
        let _ = FileExt::unlock(&lock);
        drop(lock);
        result
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
        write_active_state(channel_root, &next)?;
        // Cleanup is non-authoritative: after active.json is committed, failure to remove an old
        // generation must not make the caller discard the newly active generation.
        let _ = prune_generations(
            channel_root,
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
    let current_bytes = read_verified_target(repository, "current.json", 8 * 1024).await?;
    let current = CurrentPointer::parse_and_validate(&current_bytes, channel)?;
    let manifest_bytes =
        read_verified_target(repository, &current.manifest_target, 16 * 1024 * 1024).await?;
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

    let runtime_bytes = read_verified_target(
        repository,
        &manifest.runtime.java.runtime_target,
        MAX_RUNTIME_LOCK_BYTES,
    )
    .await?;
    let runtime_sha256 = format!("{:x}", Sha256::digest(&runtime_bytes));
    if runtime_sha256 != manifest.runtime.java.runtime_lock_sha256 {
        return Err("TUF runtime target hash does not match the release manifest".into());
    }
    let runtime_lock = RuntimeLock::parse_and_validate(&runtime_bytes)?;
    manifest.bind_runtime_lock(&runtime_lock)?;

    Ok(TrustedRelease {
        channel,
        current,
        manifest,
        runtime_lock,
        tuf_root_version: root_version,
    })
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
    if !path.exists() {
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
    if !path.exists() {
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
    let active_exists = active_path.exists();
    let recovery_exists = recovery_path.exists();
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
    if !path.exists() {
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

fn write_active_state(channel_root: &Path, active: &ActiveTufState) -> Result<(), String> {
    validate_active_shape(active, active.channel)?;
    let bytes = serde_json::to_vec_pretty(active)
        .map_err(|error| format!("Cannot serialize TUF active state: {error}"))?;
    if bytes.len() > ACTIVE_STATE_LIMIT {
        return Err("TUF active state exceeds launcher limit".into());
    }
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
    current: Uuid,
    previous: Option<Uuid>,
) -> Result<(), String> {
    let keep: HashSet<_> = [Some(current), previous].into_iter().flatten().collect();
    let generations = channel_root.join("generations");
    for entry in fs::read_dir(&generations)
        .map_err(|error| format!("Cannot inspect TUF generations: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Cannot inspect TUF generation: {error}"))?;
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
        if !keep.contains(&id) {
            fs::remove_dir_all(entry.path())
                .map_err(|error| format!("Cannot prune old TUF generation: {error}"))?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        fs::remove_file(directory.join(ACTIVE_FILE)).unwrap();
        fs::remove_file(directory.join(RECOVERY_FILE)).unwrap();
        assert!(read_active_state(&directory, BuildChannel::Stable).is_err());

        fs::remove_file(directory.join(TRUST_FILE)).unwrap();
        fs::remove_file(directory.join(TRUST_RECOVERY_FILE)).unwrap();
        assert!(read_active_state(&directory, BuildChannel::Stable).is_err());
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
        write_pointer_file(&directory, RECOVERY_FILE, &bytes).unwrap();
        assert_eq!(
            read_active_state(&directory, BuildChannel::Stable).unwrap(),
            Some(active.clone())
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
