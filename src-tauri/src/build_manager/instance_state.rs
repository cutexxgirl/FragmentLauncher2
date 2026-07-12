use super::{
    managed_fs::{
        atomic_write_small, ensure_directory_chain, open_or_create_lock_file, ImmutableManagedFile,
        ManagedFsError, ManagedLockFile, RelativeManagedPath,
    },
    tuf::TrustedReleaseEvidence,
    types::{BuildChannel, PresetId},
};
use fs2::FileExt;
use serde::{
    de::{MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Number, Value};
use std::{
    collections::HashSet,
    fmt,
    io::ErrorKind,
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const ACTIVE_INSTANCE_SCHEMA_VERSION: u8 = 2;
const ACTIVE_INSTANCE_LIMIT: usize = 16 * 1024;
const OPERATION_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const OPERATION_LOCK_POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(super) type InstanceStateResult<T> = Result<T, InstanceStateError>;

#[derive(Debug)]
pub(super) enum InstanceStateError {
    Invalid(String),
    RecoveryRequired {
        channel: BuildChannel,
        backup: Box<ActiveInstanceV2>,
        detail: String,
    },
    AppliedButDurabilityUnconfirmed {
        destination: PathBuf,
        detail: String,
    },
    AppliedButVerificationUnconfirmed {
        destination: PathBuf,
        detail: String,
    },
    ManagedFs(ManagedFsError),
}

impl From<ManagedFsError> for InstanceStateError {
    fn from(error: ManagedFsError) -> Self {
        match error {
            ManagedFsError::AppliedButDurabilityUnconfirmed {
                destination,
                detail,
            } => Self::AppliedButDurabilityUnconfirmed {
                destination,
                detail,
            },
            other => Self::ManagedFs(other),
        }
    }
}

impl fmt::Display for InstanceStateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => formatter.write_str(message),
            Self::RecoveryRequired {
                channel,
                backup,
                detail,
            } => write!(
                formatter,
                "instance_recovery_required: {} channel backup generation {} is available, but is not committed: {detail}",
                channel.as_str(),
                backup.generation
            ),
            Self::AppliedButDurabilityUnconfirmed {
                destination,
                detail,
            } => write!(
                formatter,
                "Active instance write reached {}, but durability is unconfirmed: {detail}",
                destination.display()
            ),
            Self::AppliedButVerificationUnconfirmed {
                destination,
                detail,
            } => write!(
                formatter,
                "Active instance write reached {}, but post-commit verification is unconfirmed: {detail}",
                destination.display()
            ),
            Self::ManagedFs(error) => write!(formatter, "Managed instance state error: {error}"),
        }
    }
}

impl std::error::Error for InstanceStateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ManagedFs(error) => Some(error),
            _ => None,
        }
    }
}

/// The small, atomically replaced commit point for an installed channel instance.
///
/// This marker is only a local progress record. Callers must still audit the instance against a
/// freshly trusted release before returning `ready` or launching the game.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ActiveInstanceV2 {
    pub schema_version: u8,
    pub install_id: Uuid,
    pub channel: BuildChannel,
    pub generation: u64,
    pub release_id: String,
    pub preset: PresetId,
    pub release_manifest_sha256: String,
    pub runtime_lock_sha256: String,
    pub game_runtime_lock_sha256: String,
    pub trusted_release: TrustedReleaseEvidence,
}

impl ActiveInstanceV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        install_id: Uuid,
        channel: BuildChannel,
        generation: u64,
        release_id: String,
        preset: PresetId,
        release_manifest_sha256: String,
        runtime_lock_sha256: String,
        game_runtime_lock_sha256: String,
        trusted_release: TrustedReleaseEvidence,
    ) -> Result<Self, String> {
        let marker = Self {
            schema_version: ACTIVE_INSTANCE_SCHEMA_VERSION,
            install_id,
            channel,
            generation,
            release_id,
            preset,
            release_manifest_sha256,
            runtime_lock_sha256,
            game_runtime_lock_sha256,
            trusted_release,
        };
        marker.validate(install_id, channel)?;
        Ok(marker)
    }

    pub fn validate(
        &self,
        expected_install_id: Uuid,
        expected_channel: BuildChannel,
    ) -> Result<(), String> {
        if self.schema_version != ACTIVE_INSTANCE_SCHEMA_VERSION {
            return Err(format!(
                "Unsupported active instance schema {}",
                self.schema_version
            ));
        }
        if self.install_id != expected_install_id || self.channel != expected_channel {
            return Err("Active instance belongs to another installation or channel".into());
        }
        if self.generation == 0 || self.generation == u64::MAX {
            return Err("Active instance generation must be positive and advanceable".into());
        }
        if !valid_release_id(&self.release_id) {
            return Err("Active instance release ID is invalid".into());
        }
        if !is_sha256(&self.release_manifest_sha256)
            || !is_sha256(&self.runtime_lock_sha256)
            || !is_sha256(&self.game_runtime_lock_sha256)
        {
            return Err("Active instance release binding SHA-256 is invalid".into());
        }
        self.trusted_release.validate_binding(
            expected_channel,
            &self.release_id,
            &self.trusted_release.release_manifest.name,
            &self.trusted_release.java_runtime_lock.name,
            &self.trusted_release.game_runtime_lock.name,
            &self.release_manifest_sha256,
            &self.runtime_lock_sha256,
            &self.game_runtime_lock_sha256,
        )?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct InstanceStateStore {
    install_root: PathBuf,
    install_id: Uuid,
}

/// An exclusive, cross-process lock for one channel's instance state and reconciler operation.
/// Stable and dev use distinct lock files and may therefore make progress independently.
pub struct InstanceOperationLock {
    file: ManagedLockFile,
    install_root: PathBuf,
    install_id: Uuid,
    channel: BuildChannel,
}

impl fmt::Debug for InstanceOperationLock {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InstanceOperationLock")
            .field("install_id", &self.install_id)
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

impl Drop for InstanceOperationLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(self.file.file());
    }
}

impl InstanceOperationLock {
    pub(super) fn validate_scope(
        &self,
        install_root: &Path,
        install_id: Uuid,
        channel: BuildChannel,
    ) -> InstanceStateResult<()> {
        if self.install_root != install_root
            || self.install_id != install_id
            || self.channel != channel
        {
            return Err(InstanceStateError::Invalid(
                "Instance operation lock belongs to another root, installation, or channel".into(),
            ));
        }

        // The fields above are private construction-time scope tokens. Reopening the expected
        // lock file and comparing its stable filesystem identity additionally detects an unlink
        // and replacement on platforms where another local process can rename an open file.
        let expected_path = InstanceStatePaths::new(channel).lock;
        let expected = open_or_create_lock_file(install_root, &expected_path)?;
        if expected.info().identity != self.file.info().identity {
            return Err(InstanceStateError::Invalid(
                "Instance operation lock file identity no longer matches its scope".into(),
            ));
        }
        Ok(())
    }
}

impl InstanceStateStore {
    pub fn new(install_root: &Path, install_id: Uuid) -> Self {
        Self {
            install_root: install_root.to_path_buf(),
            install_id,
        }
    }

    pub fn load(&self, channel: BuildChannel) -> InstanceStateResult<Option<ActiveInstanceV2>> {
        let lock = self.acquire_operation_lock(channel)?;
        self.load_locked(&lock)
    }

    pub fn load_locked(
        &self,
        lock: &InstanceOperationLock,
    ) -> InstanceStateResult<Option<ActiveInstanceV2>> {
        self.validate_lock(lock)?;
        Ok(self
            .load_record_locked(lock.channel)?
            .map(|record| record.marker))
    }

    pub fn save(&self, marker: &ActiveInstanceV2) -> InstanceStateResult<()> {
        marker
            .validate(self.install_id, marker.channel)
            .map_err(InstanceStateError::Invalid)?;
        let lock = self.acquire_operation_lock(marker.channel)?;
        self.save_locked(&lock, marker)
    }

    pub fn save_locked(
        &self,
        lock: &InstanceOperationLock,
        marker: &ActiveInstanceV2,
    ) -> InstanceStateResult<()> {
        self.validate_lock(lock)?;
        marker
            .validate(self.install_id, lock.channel)
            .map_err(InstanceStateError::Invalid)?;
        let paths = self.paths(lock.channel);
        paths.prepare(&self.install_root)?;

        let current = self.load_record_locked(lock.channel)?;
        match current.as_ref() {
            Some(record) if record.marker == *marker => return Ok(()),
            Some(record) => {
                let expected = record.marker.generation.checked_add(1).ok_or_else(|| {
                    InstanceStateError::Invalid(
                        "Active instance generation counter is exhausted".into(),
                    )
                })?;
                if marker.generation != expected {
                    return Err(InstanceStateError::Invalid(format!(
                        "Active instance generation must advance exactly from {} to {expected}, not {}",
                        record.marker.generation, marker.generation
                    )));
                }
            }
            None if marker.generation != 1 => {
                return Err(InstanceStateError::Invalid(
                    "The first active instance generation must be 1".into(),
                ));
            }
            _ => {}
        }

        if let Some(record) = current {
            atomic_write_small(
                &self.install_root,
                paths.backup.clone(),
                &record.bytes,
                ACTIVE_INSTANCE_LIMIT,
            )?;
            verify_committed_record(
                &self.install_root,
                &paths.backup,
                self.install_id,
                lock.channel,
                &record,
                "active instance backup",
            )?;
        }

        let bytes = serialize_marker(marker).map_err(InstanceStateError::Invalid)?;
        atomic_write_small(
            &self.install_root,
            paths.primary.clone(),
            &bytes,
            ACTIVE_INSTANCE_LIMIT,
        )?;
        let expected = MarkerRecord {
            marker: marker.clone(),
            bytes,
        };
        verify_committed_record(
            &self.install_root,
            &paths.primary,
            self.install_id,
            lock.channel,
            &expected,
            "active instance marker",
        )?;
        Ok(())
    }

    pub fn acquire_operation_lock(
        &self,
        channel: BuildChannel,
    ) -> InstanceStateResult<InstanceOperationLock> {
        let paths = self.paths(channel);
        paths.prepare(&self.install_root)?;
        let file = open_or_create_lock_file(&self.install_root, &paths.lock)?;
        let started = Instant::now();
        loop {
            match file.file().try_lock_exclusive() {
                Ok(()) => {
                    return Ok(InstanceOperationLock {
                        file,
                        install_root: self.install_root.clone(),
                        install_id: self.install_id,
                        channel,
                    })
                }
                Err(error)
                    if is_lock_contended(&error) && started.elapsed() < OPERATION_LOCK_TIMEOUT =>
                {
                    thread::sleep(OPERATION_LOCK_POLL_INTERVAL);
                }
                Err(error) => {
                    return Err(InstanceStateError::Invalid(format!(
                        "Instance {} is locked by another launcher process: {error}",
                        channel.as_str()
                    )))
                }
            }
        }
    }

    pub fn try_acquire_operation_lock(
        &self,
        channel: BuildChannel,
    ) -> InstanceStateResult<Option<InstanceOperationLock>> {
        let paths = self.paths(channel);
        paths.prepare(&self.install_root)?;
        let file = open_or_create_lock_file(&self.install_root, &paths.lock)?;
        match file.file().try_lock_exclusive() {
            Ok(()) => Ok(Some(InstanceOperationLock {
                file,
                install_root: self.install_root.clone(),
                install_id: self.install_id,
                channel,
            })),
            Err(error) if is_lock_contended(&error) => Ok(None),
            Err(error) => Err(InstanceStateError::Invalid(format!(
                "Cannot lock instance {}: {error}",
                channel.as_str()
            ))),
        }
    }

    fn load_record_locked(
        &self,
        channel: BuildChannel,
    ) -> InstanceStateResult<Option<MarkerRecord>> {
        let paths = self.paths(channel);
        paths.prepare(&self.install_root)?;
        let primary = read_record(&self.install_root, &paths.primary, self.install_id, channel);
        match primary {
            Ok(record) => Ok(Some(record)),
            Err(LoadFailure::Future(version)) => Err(InstanceStateError::Invalid(format!(
                "launcher_update_required: active instance schema {version}"
            ))),
            Err(primary_failure @ (LoadFailure::Missing | LoadFailure::Corrupt(_))) => {
                match read_record(
                    &self.install_root,
                    &paths.backup,
                    self.install_id,
                    channel,
                ) {
                    Ok(backup) => Err(InstanceStateError::RecoveryRequired {
                        channel,
                        backup: Box::new(backup.marker),
                        detail: primary_failure.to_string(),
                    }),
                    Err(LoadFailure::Future(version)) => {
                        Err(InstanceStateError::Invalid(format!(
                            "launcher_update_required: active instance schema {version}"
                        )))
                    }
                    Err(LoadFailure::Missing) if matches!(primary_failure, LoadFailure::Missing) => {
                        Ok(None)
                    }
                    Err(backup_failure) => Err(InstanceStateError::Invalid(format!(
                        "No verified active instance state remains; primary: {primary_failure}; backup: {backup_failure}"
                    ))),
                }
            }
        }
    }

    fn validate_lock(&self, lock: &InstanceOperationLock) -> InstanceStateResult<()> {
        lock.validate_scope(&self.install_root, self.install_id, lock.channel)
    }

    fn paths(&self, channel: BuildChannel) -> InstanceStatePaths {
        InstanceStatePaths::new(channel)
    }
}

struct InstanceStatePaths {
    directory: RelativeManagedPath,
    primary: RelativeManagedPath,
    backup: RelativeManagedPath,
    lock: RelativeManagedPath,
}

impl InstanceStatePaths {
    fn new(channel: BuildChannel) -> Self {
        let directory = RelativeManagedPath::new(&format!("state/instances/{}", channel.as_str()))
            .expect("constant instance state path must be valid");
        Self {
            primary: directory
                .join_component("active.json")
                .expect("constant active marker name must be valid"),
            backup: directory
                .join_component("active.json.bak")
                .expect("constant active backup name must be valid"),
            lock: directory
                .join_component(".operation.lock")
                .expect("constant operation lock name must be valid"),
            directory,
        }
    }

    fn prepare(&self, install_root: &Path) -> InstanceStateResult<()> {
        drop(ensure_directory_chain(install_root, &self.directory)?);
        Ok(())
    }
}

#[derive(Debug)]
struct MarkerRecord {
    marker: ActiveInstanceV2,
    bytes: Vec<u8>,
}

#[derive(Debug)]
enum LoadFailure {
    Missing,
    Future(u64),
    Corrupt(String),
}

impl fmt::Display for LoadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("active instance state is missing"),
            Self::Future(version) => {
                write!(
                    formatter,
                    "unsupported future active instance schema {version}"
                )
            }
            Self::Corrupt(message) => write!(formatter, "corrupt active instance state: {message}"),
        }
    }
}

fn read_record(
    install_root: &Path,
    path: &RelativeManagedPath,
    install_id: Uuid,
    channel: BuildChannel,
) -> Result<MarkerRecord, LoadFailure> {
    let mut file = match ImmutableManagedFile::open(install_root, path) {
        Ok(file) => file,
        Err(error) if managed_error_is_missing(&error) => return Err(LoadFailure::Missing),
        Err(error) => return Err(LoadFailure::Corrupt(error.to_string())),
    };
    let bytes = file
        .read_bounded(ACTIVE_INSTANCE_LIMIT as u64)
        .map_err(|error| LoadFailure::Corrupt(error.to_string()))?;
    if bytes.is_empty() {
        return Err(LoadFailure::Corrupt("marker is empty".into()));
    }

    let value = parse_without_duplicate_keys(&bytes).map_err(LoadFailure::Corrupt)?;
    let version = value
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| LoadFailure::Corrupt("schemaVersion must be an integer".into()))?;
    if version > u64::from(ACTIVE_INSTANCE_SCHEMA_VERSION) {
        return Err(LoadFailure::Future(version));
    }
    let marker: ActiveInstanceV2 = serde_json::from_value(value)
        .map_err(|error| LoadFailure::Corrupt(format!("invalid marker schema: {error}")))?;
    marker
        .validate(install_id, channel)
        .map_err(LoadFailure::Corrupt)?;
    Ok(MarkerRecord { marker, bytes })
}

fn verify_committed_record(
    install_root: &Path,
    path: &RelativeManagedPath,
    install_id: Uuid,
    channel: BuildChannel,
    expected: &MarkerRecord,
    label: &str,
) -> InstanceStateResult<()> {
    let destination = path.join_to(install_root);
    let verified = read_record(install_root, path, install_id, channel).map_err(|failure| {
        InstanceStateError::AppliedButVerificationUnconfirmed {
            destination: destination.clone(),
            detail: format!("cannot verify {label}: {failure}"),
        }
    })?;
    if verified.marker != expected.marker || verified.bytes != expected.bytes {
        return Err(InstanceStateError::AppliedButVerificationUnconfirmed {
            destination,
            detail: format!("{label} changed during post-commit verification"),
        });
    }
    Ok(())
}

fn serialize_marker(marker: &ActiveInstanceV2) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec_pretty(marker)
        .map_err(|error| format!("Cannot serialize active instance marker: {error}"))?;
    if bytes.is_empty() || bytes.len() > ACTIVE_INSTANCE_LIMIT {
        return Err("Serialized active instance marker exceeds its size limit".into());
    }
    Ok(bytes)
}

fn managed_error_is_missing(error: &ManagedFsError) -> bool {
    matches!(
        error,
        ManagedFsError::Io { source, .. } if source.kind() == ErrorKind::NotFound
    )
}

fn valid_release_id(value: &str) -> bool {
    value.len() == 28
        && value.starts_with("rel_")
        && value.as_bytes()[4..]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_lock_contended(error: &std::io::Error) -> bool {
    if error.kind() == ErrorKind::WouldBlock {
        return true;
    }
    #[cfg(windows)]
    {
        // LockFileEx reports ERROR_LOCK_VIOLATION. Some filesystems surface the closely related
        // ERROR_SHARING_VIOLATION instead; both mean that another launcher currently owns the
        // operation lock rather than that the lock file is corrupt.
        matches!(error.raw_os_error(), Some(32 | 33))
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn parse_without_duplicate_keys(bytes: &[u8]) -> Result<Value, String> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err("JSON must not contain a UTF-8 BOM".into());
    }
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = NoDuplicateValue::deserialize(&mut deserializer)
        .map_err(|error| format!("invalid JSON: {error}"))?
        .0;
    deserializer
        .end()
        .map_err(|error| format!("trailing JSON data: {error}"))?;
    Ok(value)
}

struct NoDuplicateValue(Value);

impl<'de> Deserialize<'de> for NoDuplicateValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(NoDuplicateVisitor)
    }
}

struct NoDuplicateVisitor;

impl<'de> Visitor<'de> for NoDuplicateVisitor {
    type Value = NoDuplicateValue;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a JSON value without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(Number::from(value))))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Number(Number::from(value))))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Self::Value, E> {
        Number::from_f64(value)
            .map(|number| NoDuplicateValue(Value::Number(number)))
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(NoDuplicateValue(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        NoDuplicateValue::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element::<NoDuplicateValue>()? {
            values.push(value.0);
        }
        Ok(NoDuplicateValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        let mut keys = HashSet::new();
        while let Some(key) = object.next_key::<String>()? {
            if !keys.insert(key.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicate JSON key: {key}"
                )));
            }
            let value = object.next_value::<NoDuplicateValue>()?;
            values.insert(key, value.0);
        }
        Ok(NoDuplicateValue(Value::Object(values)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "fragment-instance-state-{label}-{}",
                Uuid::new_v4()
            ));
            fs::create_dir_all(&path).expect("create fixture root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn marker(
        install_id: Uuid,
        channel: BuildChannel,
        generation: u64,
        release_suffix: char,
    ) -> ActiveInstanceV2 {
        let release_id = format!("rel_{}", release_suffix.to_string().repeat(24));
        let release_hash = "b".repeat(64);
        let runtime_hash = "c".repeat(64);
        let game_hash = "d".repeat(64);
        ActiveInstanceV2::new(
            install_id,
            channel,
            generation,
            release_id.clone(),
            PresetId::Medium,
            release_hash.clone(),
            runtime_hash.clone(),
            game_hash.clone(),
            TrustedReleaseEvidence {
                schema_version: 1,
                channel,
                roles: super::super::tuf::TrustedRoleVersions {
                    root: 1,
                    timestamp: 1,
                    snapshot: 1,
                    targets: 1,
                },
                current: super::super::tuf::TrustedTargetEvidence {
                    name: "current.json".into(),
                    length: 1,
                    sha256: "a".repeat(64),
                },
                release_manifest: super::super::tuf::TrustedTargetEvidence {
                    name: format!("release-{release_id}.json"),
                    length: 1,
                    sha256: release_hash,
                },
                java_runtime_lock: super::super::tuf::TrustedTargetEvidence {
                    name: format!("runtime-windows-x64-{runtime_hash}.json"),
                    length: 1,
                    sha256: runtime_hash,
                },
                game_runtime_lock: super::super::tuf::TrustedTargetEvidence {
                    name: format!("game-runtime-windows-x64-{game_hash}.json"),
                    length: 1,
                    sha256: game_hash,
                },
            },
        )
        .expect("valid marker")
    }

    #[test]
    fn round_trips_and_rejects_generation_rollback() {
        let root = TestRoot::new("roundtrip");
        let install_id = Uuid::new_v4();
        let store = InstanceStateStore::new(&root.0, install_id);
        let first = marker(install_id, BuildChannel::Stable, 1, 'a');
        let second = marker(install_id, BuildChannel::Stable, 2, 'b');
        store.save(&first).expect("save first generation");
        assert_eq!(
            store.load(BuildChannel::Stable).unwrap(),
            Some(first.clone())
        );
        store.save(&second).expect("save second generation");
        assert_eq!(store.load(BuildChannel::Stable).unwrap(), Some(second));
        assert!(store.save(&first).is_err());
        assert!(store
            .save(&marker(install_id, BuildChannel::Stable, 4, 'c'))
            .is_err());
        let mut exhausted = marker(install_id, BuildChannel::Stable, 1, 'd');
        exhausted.generation = u64::MAX;
        assert!(exhausted
            .validate(install_id, BuildChannel::Stable)
            .is_err());
    }

    #[test]
    fn stable_and_dev_markers_and_locks_are_isolated() {
        let root = TestRoot::new("channels");
        let install_id = Uuid::new_v4();
        let store = InstanceStateStore::new(&root.0, install_id);
        let stable = marker(install_id, BuildChannel::Stable, 1, 'a');
        let dev = marker(install_id, BuildChannel::Dev, 1, 'b');
        store.save(&stable).unwrap();
        store.save(&dev).unwrap();
        assert_eq!(store.load(BuildChannel::Stable).unwrap(), Some(stable));
        assert_eq!(store.load(BuildChannel::Dev).unwrap(), Some(dev));

        let stable_lock = store.acquire_operation_lock(BuildChannel::Stable).unwrap();
        assert!(store
            .try_acquire_operation_lock(BuildChannel::Stable)
            .unwrap()
            .is_none());
        let dev_lock = store
            .try_acquire_operation_lock(BuildChannel::Dev)
            .unwrap()
            .expect("dev has an independent lock");
        drop(dev_lock);
        drop(stable_lock);
    }

    #[test]
    fn operation_lock_scope_rejects_cross_channel_install_and_root_use() {
        let root = TestRoot::new("lock-scope");
        let other_root = TestRoot::new("lock-scope-other");
        let install_id = Uuid::new_v4();
        let store = InstanceStateStore::new(&root.0, install_id);
        let lock = store.acquire_operation_lock(BuildChannel::Stable).unwrap();

        lock.validate_scope(&root.0, install_id, BuildChannel::Stable)
            .unwrap();
        assert!(lock
            .validate_scope(&root.0, install_id, BuildChannel::Dev)
            .is_err());
        assert!(lock
            .validate_scope(&root.0, Uuid::new_v4(), BuildChannel::Stable)
            .is_err());
        assert!(lock
            .validate_scope(&other_root.0, install_id, BuildChannel::Stable)
            .is_err());
    }

    #[test]
    fn exposes_backup_as_recovery_only_when_primary_is_corrupt() {
        let root = TestRoot::new("backup");
        let install_id = Uuid::new_v4();
        let store = InstanceStateStore::new(&root.0, install_id);
        let first = marker(install_id, BuildChannel::Stable, 1, 'a');
        let second = marker(install_id, BuildChannel::Stable, 2, 'b');
        store.save(&first).unwrap();
        store.save(&second).unwrap();
        let primary = store.paths(BuildChannel::Stable).primary;
        let primary_path = primary.join_to(&root.0);
        fs::write(&primary_path, b"truncated").unwrap();

        let error = store.load(BuildChannel::Stable).unwrap_err();
        assert!(matches!(
            error,
            InstanceStateError::RecoveryRequired { backup, .. } if *backup == first
        ));
        assert_eq!(fs::read(primary_path).unwrap(), b"truncated");
    }

    #[test]
    fn rejects_unknown_duplicate_future_and_oversized_state() {
        let root = TestRoot::new("strict");
        let install_id = Uuid::new_v4();
        let store = InstanceStateStore::new(&root.0, install_id);
        let paths = store.paths(BuildChannel::Stable);
        paths.prepare(&root.0).unwrap();
        let primary = paths.primary.join_to(&root.0);

        let valid = marker(install_id, BuildChannel::Stable, 1, 'a');
        let mut value = serde_json::to_value(&valid).unwrap();
        value["unexpected"] = Value::Bool(true);
        fs::write(&primary, serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(store.load(BuildChannel::Stable).is_err());

        let duplicate = format!(
            "{{\"schemaVersion\":2,\"schemaVersion\":2,\"installId\":\"{install_id}\",\"channel\":\"stable\",\"generation\":1,\"releaseId\":\"rel_{}\",\"preset\":\"medium\",\"runtimeLockSha256\":\"{}\"}}",
            "a".repeat(24),
            "b".repeat(64)
        );
        fs::write(&primary, duplicate).unwrap();
        assert!(store.load(BuildChannel::Stable).is_err());

        value = serde_json::to_value(&valid).unwrap();
        value["schemaVersion"] = Value::Number(Number::from(3));
        fs::write(&primary, serde_json::to_vec(&value).unwrap()).unwrap();
        let future = store.load(BuildChannel::Stable).unwrap_err();
        assert!(future.to_string().contains("launcher_update_required"));

        fs::write(&primary, vec![b'x'; ACTIVE_INSTANCE_LIMIT + 1]).unwrap();
        assert!(store.load(BuildChannel::Stable).is_err());
    }

    #[test]
    fn rejects_cross_install_and_cross_channel_markers() {
        let root = TestRoot::new("namespace");
        let install_id = Uuid::new_v4();
        let store = InstanceStateStore::new(&root.0, install_id);
        let paths = store.paths(BuildChannel::Stable);
        paths.prepare(&root.0).unwrap();
        let primary = paths.primary.join_to(&root.0);

        let foreign_install = marker(Uuid::new_v4(), BuildChannel::Stable, 1, 'a');
        fs::write(&primary, serialize_marker(&foreign_install).unwrap()).unwrap();
        assert!(store.load(BuildChannel::Stable).is_err());

        let foreign_channel = marker(install_id, BuildChannel::Dev, 1, 'b');
        fs::write(&primary, serialize_marker(&foreign_channel).unwrap()).unwrap();
        assert!(store.load(BuildChannel::Stable).is_err());
    }

    #[test]
    fn recognizes_platform_lock_contention_errors() {
        assert!(is_lock_contended(&std::io::Error::from(
            ErrorKind::WouldBlock
        )));
        assert!(!is_lock_contended(&std::io::Error::from(
            ErrorKind::InvalidData
        )));
        #[cfg(windows)]
        {
            assert!(is_lock_contended(&std::io::Error::from_raw_os_error(32)));
            assert!(is_lock_contended(&std::io::Error::from_raw_os_error(33)));
        }
    }

    #[test]
    fn preserves_applied_but_unconfirmed_durability_as_a_distinct_error() {
        let destination = PathBuf::from("P:/Fragment/state/instances/stable/active.json");
        let error = InstanceStateError::from(ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination: destination.clone(),
            detail: "directory flush failed".into(),
        });
        assert!(matches!(
            error,
            InstanceStateError::AppliedButDurabilityUnconfirmed {
                destination: actual,
                ..
            } if actual == destination
        ));
    }

    #[test]
    fn post_commit_readback_mismatch_remains_an_unconfirmed_applied_write() {
        let root = TestRoot::new("post-commit-readback");
        let install_id = Uuid::new_v4();
        let store = InstanceStateStore::new(&root.0, install_id);
        let paths = store.paths(BuildChannel::Stable);
        paths.prepare(&root.0).unwrap();
        let expected_marker = marker(install_id, BuildChannel::Stable, 1, 'a');
        let expected = MarkerRecord {
            bytes: serialize_marker(&expected_marker).unwrap(),
            marker: expected_marker,
        };
        let different = marker(install_id, BuildChannel::Stable, 2, 'b');
        fs::write(
            paths.primary.join_to(&root.0),
            serialize_marker(&different).unwrap(),
        )
        .unwrap();

        let error = verify_committed_record(
            &root.0,
            &paths.primary,
            install_id,
            BuildChannel::Stable,
            &expected,
            "injected marker",
        )
        .unwrap_err();
        assert!(matches!(
            error,
            InstanceStateError::AppliedButVerificationUnconfirmed { .. }
        ));
    }
}
