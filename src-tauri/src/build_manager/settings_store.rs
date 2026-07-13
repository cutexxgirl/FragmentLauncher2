use super::{
    contracts::{MutableSettingsFile, MutableValidator},
    managed_fs::{
        ensure_directory_chain, open_or_create_lock_file, quarantine_node_if_identity,
        remove_verified_managed_file, ExclusiveManagedFile, FileDigests, GuardedDirectoryChain,
        ImmutableManagedFile, ManagedFsError, ManagedLockFile, ManagedNodeKind,
        RelativeManagedPath,
    },
    mutable::{MutableSettingsState, SettingValues},
    types::BuildChannel,
};
use fs2::FileExt;
use serde::{
    de::{DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Number, Value};
use sha1::{Digest, Sha1};
use sha2::Sha256;
use std::{
    collections::{BTreeMap, HashSet},
    fmt, fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

const SETTINGS_SCHEMA_VERSION: u8 = 1;
const ABSOLUTE_SETTINGS_LIMIT: usize = 16 * 1024 * 1024;
const MAX_QUARANTINE_FILES: usize = 8;
const MAX_QUARANTINE_SCAN_FILES: usize = MAX_QUARANTINE_FILES * 2;

type SettingsBucket = BTreeMap<String, SettingValues>;

#[derive(Debug, Clone)]
pub struct LoadedSettings {
    pub state: MutableSettingsState,
    pub generation: u64,
    pub warning: Option<String>,
    verified_bytes: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct SettingsStore {
    install_root: PathBuf,
    install_id: Uuid,
    process_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SettingsEnvelope {
    schema_version: u8,
    install_id: Uuid,
    channel: BuildChannel,
    manifest_path: String,
    validator: MutableValidator,
    generation: u64,
    profile: SettingsBucket,
    presets: PersistedPresets,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PersistedPresets {
    low: SettingsBucket,
    medium: SettingsBucket,
    high: SettingsBucket,
}

impl SettingsStore {
    pub fn new(install_root: &Path, install_id: Uuid) -> Self {
        Self {
            install_root: install_root.to_path_buf(),
            install_id,
            process_lock: Arc::new(Mutex::new(())),
        }
    }

    pub fn load(
        &self,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
    ) -> Result<LoadedSettings, String> {
        let _guard = self
            .process_lock
            .lock()
            .map_err(|_| "Mutable settings store lock is poisoned".to_string())?;
        self.with_file_lock(channel, policy, |lock, paths, maximum| {
            self.load_locked(lock, channel, policy, paths, maximum)
        })
    }

    pub fn update<T>(
        &self,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        operation: impl FnOnce(&mut MutableSettingsState) -> Result<T, String>,
    ) -> Result<(T, LoadedSettings), String> {
        let _guard = self
            .process_lock
            .lock()
            .map_err(|_| "Mutable settings store lock is poisoned".to_string())?;
        self.with_file_lock(channel, policy, |lock, paths, maximum| {
            let mut loaded = self.load_locked(lock, channel, policy, paths, maximum)?;
            let value = operation(&mut loaded.state)?;
            loaded.state.migrate_all(std::slice::from_ref(policy))?;
            let generation = loaded
                .generation
                .checked_add(1)
                .ok_or_else(|| "Mutable settings generation overflowed".to_string())?;
            let envelope =
                envelope_from_state(self.install_id, channel, policy, generation, &loaded.state);
            self.save_envelope_locked(
                lock,
                paths,
                maximum,
                channel,
                policy,
                loaded.verified_bytes.as_deref(),
                &envelope,
            )?;
            let verified = load_envelope(
                &self.install_root,
                &paths.primary,
                maximum,
                self.install_id,
                channel,
                policy,
            )
            .map_err(|failure| failure.to_string())?;
            Ok((
                value,
                LoadedSettings {
                    state: state_from_envelope(&verified.envelope, policy)?,
                    generation,
                    warning: loaded.warning,
                    verified_bytes: Some(verified.bytes),
                },
            ))
        })
    }

    fn with_file_lock<T>(
        &self,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        operation: impl FnOnce(&SettingsOperationLock, &SettingsPaths, usize) -> Result<T, String>,
    ) -> Result<T, String> {
        policy.validate()?;
        let maximum = settings_limit(policy)?;
        let paths = SettingsPaths::new(channel, policy)?;
        paths.prepare(&self.install_root)?;
        let lock_file = open_or_create_lock_file(&self.install_root, &paths.lock)
            .map_err(|error| format!("Cannot open mutable settings lock: {error}"))?;
        let started = Instant::now();
        loop {
            match lock_file.file().try_lock_exclusive() {
                Ok(()) => break,
                Err(_) if started.elapsed() < Duration::from_secs(5) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => {
                    return Err(format!(
                        "Mutable settings are locked by another launcher process: {error}"
                    ));
                }
            }
        }
        let lock = SettingsOperationLock {
            file: lock_file,
            install_root: self.install_root.clone(),
            install_id: self.install_id,
            channel,
            namespace: paths.namespace.clone(),
        };
        lock.validate_scope(self, &paths)?;
        self.cleanup_stale_staging_locked(&lock, &paths, maximum, policy)?;
        operation(&lock, &paths, maximum)
    }

    fn load_locked(
        &self,
        lock: &SettingsOperationLock,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
    ) -> Result<LoadedSettings, String> {
        lock.validate_scope(self, paths)?;
        match load_envelope(
            &self.install_root,
            &paths.primary,
            maximum,
            self.install_id,
            channel,
            policy,
        ) {
            Ok(verified) => {
                self.validate_primary_backup_relation(channel, policy, paths, maximum, &verified)?;
                loaded_settings(verified, policy, None)
            }
            Err(primary_failure @ (LoadFailure::Missing | LoadFailure::Corrupt(_))) => {
                let primary_missing = matches!(primary_failure, LoadFailure::Missing);
                match load_envelope_leased(
                    &self.install_root,
                    &paths.backup,
                    maximum,
                    self.install_id,
                    channel,
                    policy,
                ) {
                    Ok((verified, lease)) => self.restore_backup_locked(
                        lock,
                        channel,
                        policy,
                        paths,
                        maximum,
                        primary_failure,
                        verified,
                        lease,
                    ),
                    Err(LoadFailure::Future(version)) => Err(format!(
                        "launcher_update_required: mutable settings schema {version}"
                    )),
                    Err(backup_failure @ (LoadFailure::Missing | LoadFailure::Corrupt(_))) => {
                        let backup_missing = matches!(backup_failure, LoadFailure::Missing);
                        if !primary_missing {
                            self.quarantine_corrupt_locked(
                                lock,
                                channel,
                                policy,
                                paths,
                                maximum,
                                &paths.primary,
                                "primary",
                            )?;
                        }
                        if !backup_missing {
                            self.quarantine_corrupt_locked(
                                lock,
                                channel,
                                policy,
                                paths,
                                maximum,
                                &paths.backup,
                                "backup",
                            )?;
                        }
                        self.prune_quarantine_locked(lock, paths)?;
                        let mut state = MutableSettingsState::new();
                        state.migrate_all(std::slice::from_ref(policy))?;
                        Ok(LoadedSettings {
                            state,
                            generation: 0,
                            warning: if primary_missing && backup_missing {
                                None
                            } else {
                                Some(
                                    "Mutable settings were reset to signed defaults because no verified state remained"
                                        .into(),
                                )
                            },
                            verified_bytes: None,
                        })
                    }
                }
            }
            Err(LoadFailure::Future(version)) => Err(format!(
                "launcher_update_required: mutable settings schema {version}"
            )),
        }
    }
}

struct SettingsPaths {
    namespace: String,
    channel: BuildChannel,
    directory: RelativeManagedPath,
    primary: RelativeManagedPath,
    backup: RelativeManagedPath,
    staging: RelativeManagedPath,
    lock: RelativeManagedPath,
    quarantine: RelativeManagedPath,
}

impl SettingsPaths {
    fn new(channel: BuildChannel, policy: &MutableSettingsFile) -> Result<Self, String> {
        let filename = match policy.validator {
            MutableValidator::MinecraftOptionsV1 => "minecraft-options-v1.json",
            _ => return Err("Mutable validator has no persisted settings namespace".into()),
        };
        let directory =
            RelativeManagedPath::new(&format!("state/settings/v1/{}", channel.as_str()))
                .map_err(|error| error.to_string())?;
        Ok(Self {
            namespace: format!(
                "{}:{filename}:{}",
                channel.as_str(),
                policy.path.to_ascii_lowercase()
            ),
            channel,
            primary: directory
                .join_component(filename)
                .map_err(|error| error.to_string())?,
            backup: directory
                .join_component(&format!("{filename}.bak"))
                .map_err(|error| error.to_string())?,
            staging: directory
                .join_component(".settings-publish.tmp")
                .map_err(|error| error.to_string())?,
            lock: directory
                .join_component(".settings.lock")
                .map_err(|error| error.to_string())?,
            quarantine: directory
                .join_component("quarantine")
                .map_err(|error| error.to_string())?,
            directory,
        })
    }

    fn prepare(&self, install_root: &Path) -> Result<(), String> {
        drop(
            ensure_directory_chain(install_root, &self.directory)
                .map_err(|error| error.to_string())?,
        );
        drop(
            ensure_directory_chain(install_root, &self.quarantine)
                .map_err(|error| error.to_string())?,
        );
        Ok(())
    }
}

struct SettingsOperationLock {
    file: ManagedLockFile,
    install_root: PathBuf,
    install_id: Uuid,
    channel: BuildChannel,
    namespace: String,
}

impl Drop for SettingsOperationLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(self.file.file());
    }
}

impl SettingsOperationLock {
    fn validate_scope(&self, store: &SettingsStore, paths: &SettingsPaths) -> Result<(), String> {
        if self.install_root != store.install_root
            || self.install_id != store.install_id
            || self.namespace != paths.namespace
            || self.channel != paths.channel
        {
            return Err(
                "Mutable settings lock belongs to another root, installation, channel, or namespace"
                    .into(),
            );
        }
        self.file
            .revalidate()
            .map_err(|error| format!("Mutable settings lock changed: {error}"))?;
        let expected = open_or_create_lock_file(&store.install_root, &paths.lock)
            .map_err(|error| format!("Cannot revalidate mutable settings lock: {error}"))?;
        if expected.info().identity != self.file.info().identity {
            return Err("Mutable settings lock filesystem identity changed".into());
        }
        Ok(())
    }
}

#[derive(Clone)]
struct VerifiedEnvelope {
    envelope: SettingsEnvelope,
    bytes: Vec<u8>,
}

fn load_envelope(
    install_root: &Path,
    path: &RelativeManagedPath,
    maximum: usize,
    install_id: Uuid,
    channel: BuildChannel,
    policy: &MutableSettingsFile,
) -> Result<VerifiedEnvelope, LoadFailure> {
    load_envelope_leased(install_root, path, maximum, install_id, channel, policy)
        .map(|(verified, _lease)| verified)
}

fn load_envelope_leased(
    install_root: &Path,
    path: &RelativeManagedPath,
    maximum: usize,
    install_id: Uuid,
    channel: BuildChannel,
    policy: &MutableSettingsFile,
) -> Result<(VerifiedEnvelope, ImmutableManagedFile), LoadFailure> {
    let file = match ImmutableManagedFile::open(install_root, path) {
        Ok(file) => file,
        Err(error) if managed_error_is_missing(&error) => return Err(LoadFailure::Missing),
        Err(error) => return Err(LoadFailure::Corrupt(error.to_string())),
    };
    let bytes = file
        .read_bounded_shared(ABSOLUTE_SETTINGS_LIMIT as u64)
        .map_err(|error| LoadFailure::Corrupt(error.to_string()))?;
    file.revalidate()
        .map_err(|error| LoadFailure::Corrupt(error.to_string()))?;
    let verified = parse_envelope_bytes(bytes, maximum, install_id, channel, policy)?;
    Ok((verified, file))
}

fn parse_envelope_bytes(
    bytes: Vec<u8>,
    maximum: usize,
    install_id: Uuid,
    channel: BuildChannel,
    policy: &MutableSettingsFile,
) -> Result<VerifiedEnvelope, LoadFailure> {
    if bytes.is_empty() {
        return Err(LoadFailure::Corrupt(
            "mutable settings file is empty".into(),
        ));
    }
    let value: Value = parse_without_duplicate_keys(&bytes).map_err(LoadFailure::Corrupt)?;
    let schema_version = value
        .get("schemaVersion")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            LoadFailure::Corrupt("mutable settings schemaVersion must be an integer".into())
        })?;
    if schema_version > u64::from(SETTINGS_SCHEMA_VERSION) {
        return Err(LoadFailure::Future(schema_version));
    }
    if bytes.len() > maximum {
        return Err(LoadFailure::Corrupt(
            "mutable settings v1 file exceeds its signed storage limit".into(),
        ));
    }
    let envelope: SettingsEnvelope = serde_json::from_value(value)
        .map_err(|error| LoadFailure::Corrupt(format!("invalid settings schema: {error}")))?;
    if envelope.schema_version != SETTINGS_SCHEMA_VERSION
        || envelope.install_id != install_id
        || envelope.channel != channel
        || !envelope.manifest_path.eq_ignore_ascii_case(&policy.path)
        || envelope.validator != policy.validator
    {
        return Err(LoadFailure::Corrupt(
            "mutable settings namespace does not match this installation/release".into(),
        ));
    }
    if envelope.generation == 0 || envelope.generation == u64::MAX {
        return Err(LoadFailure::Corrupt(
            "mutable settings generation must be positive and advanceable".into(),
        ));
    }
    state_from_envelope(&envelope, policy).map_err(LoadFailure::Corrupt)?;
    Ok(VerifiedEnvelope { envelope, bytes })
}

fn managed_error_is_missing(error: &ManagedFsError) -> bool {
    matches!(
        error,
        ManagedFsError::Io { source, .. } if source.kind() == ErrorKind::NotFound
    )
}

fn managed_mutation_error(context: &str, error: ManagedFsError) -> String {
    match error {
        ManagedFsError::AppliedButDurabilityUnconfirmed {
            destination,
            detail,
        } => format!(
            "settings_applied_but_durability_unconfirmed: {context} reached {}: {detail}",
            destination.display()
        ),
        other => format!("Cannot {context}: {other}"),
    }
}

enum LoadFailure {
    Missing,
    Future(u64),
    Corrupt(String),
}

impl fmt::Display for LoadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing => formatter.write_str("mutable settings state is missing"),
            Self::Future(version) => {
                write!(
                    formatter,
                    "unsupported future mutable settings schema {version}"
                )
            }
            Self::Corrupt(message) => write!(formatter, "corrupt mutable settings: {message}"),
        }
    }
}

fn state_from_envelope(
    envelope: &SettingsEnvelope,
    policy: &MutableSettingsFile,
) -> Result<MutableSettingsState, String> {
    let mut state = MutableSettingsState {
        schema_version: SETTINGS_SCHEMA_VERSION,
        profile: envelope.profile.clone(),
        presets: BTreeMap::from([
            ("low".into(), envelope.presets.low.clone()),
            ("medium".into(), envelope.presets.medium.clone()),
            ("high".into(), envelope.presets.high.clone()),
        ]),
    };
    state.migrate_all(std::slice::from_ref(policy))?;
    Ok(state)
}

fn envelope_from_state(
    install_id: Uuid,
    channel: BuildChannel,
    policy: &MutableSettingsFile,
    generation: u64,
    state: &MutableSettingsState,
) -> SettingsEnvelope {
    SettingsEnvelope {
        schema_version: SETTINGS_SCHEMA_VERSION,
        install_id,
        channel,
        manifest_path: policy.path.to_ascii_lowercase(),
        validator: policy.validator,
        generation,
        profile: state.profile.clone(),
        presets: PersistedPresets {
            low: state.presets.get("low").cloned().unwrap_or_default(),
            medium: state.presets.get("medium").cloned().unwrap_or_default(),
            high: state.presets.get("high").cloned().unwrap_or_default(),
        },
    }
}

struct ManagedQuarantine {
    relative: RelativeManagedPath,
    digests: FileDigests,
}

enum CorruptPreparation {
    Missing,
    AlreadyDesired(VerifiedEnvelope),
    Quarantined(ManagedQuarantine),
}

struct QuarantineEntry {
    relative: RelativeManagedPath,
    digests: FileDigests,
    lease: ImmutableManagedFile,
}

impl SettingsStore {
    fn validate_primary_backup_relation(
        &self,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
        primary: &VerifiedEnvelope,
    ) -> Result<(), String> {
        match load_envelope(
            &self.install_root,
            &paths.backup,
            maximum,
            self.install_id,
            channel,
            policy,
        ) {
            Ok(backup) if backup.bytes == primary.bytes => Ok(()),
            Ok(backup)
                if backup.envelope.generation.checked_add(1)
                    == Some(primary.envelope.generation) =>
            {
                Ok(())
            }
            Ok(backup) => Err(format!(
                "Ambiguous valid mutable settings state: primary generation {} and backup generation {} are not an exact recovery pair",
                primary.envelope.generation, backup.envelope.generation
            )),
            Err(LoadFailure::Future(version)) => Err(format!(
                "launcher_update_required: mutable settings backup schema {version}"
            )),
            Err(LoadFailure::Missing | LoadFailure::Corrupt(_)) => Ok(()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn restore_backup_locked(
        &self,
        lock: &SettingsOperationLock,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
        primary_failure: LoadFailure,
        backup: VerifiedEnvelope,
        backup_lease: ImmutableManagedFile,
    ) -> Result<LoadedSettings, String> {
        lock.validate_scope(self, paths)?;
        backup_lease
            .revalidate()
            .map_err(|error| error.to_string())?;
        let quarantine = match primary_failure {
            LoadFailure::Missing => None,
            LoadFailure::Corrupt(_) => match self.prepare_corrupt_locked(
                lock,
                channel,
                policy,
                paths,
                maximum,
                &paths.primary,
                Some(&backup),
                "primary",
            )? {
                CorruptPreparation::Missing => None,
                CorruptPreparation::AlreadyDesired(current) => {
                    return loaded_settings(
                        current,
                        policy,
                        Some("Mutable settings primary was already restored exactly".into()),
                    );
                }
                CorruptPreparation::Quarantined(quarantine) => Some(quarantine),
            },
            LoadFailure::Future(version) => {
                return Err(format!(
                    "launcher_update_required: mutable settings schema {version}"
                ));
            }
        };
        let recovered = self.publish_no_replace_locked(
            lock,
            channel,
            policy,
            paths,
            maximum,
            &paths.primary,
            &backup,
            Some(&backup_lease),
        )?;
        if let Some(quarantine) = quarantine {
            self.cleanup_applied_quarantine(lock, paths, quarantine, "backup recovery")?;
        }
        lock.validate_scope(self, paths).map_err(|error| {
            format!(
                "settings_applied_but_verification_unconfirmed: recovered primary lock scope changed: {error}"
            )
        })?;
        loaded_settings(
            recovered,
            policy,
            Some("Mutable settings primary was restored from its verified backup".into()),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn prepare_corrupt_locked(
        &self,
        lock: &SettingsOperationLock,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
        source: &RelativeManagedPath,
        desired: Option<&VerifiedEnvelope>,
        label: &str,
    ) -> Result<CorruptPreparation, String> {
        lock.validate_scope(self, paths)?;
        let mut lease = match ImmutableManagedFile::open(&self.install_root, source) {
            Ok(lease) => lease,
            Err(error) if managed_error_is_missing(&error) => {
                return Ok(CorruptPreparation::Missing);
            }
            Err(error) => {
                return Err(format!(
                    "Unsafe mutable settings {label} cannot be quarantined automatically: {error}"
                ));
            }
        };
        let bytes = lease
            .read_bounded_shared(ABSOLUTE_SETTINGS_LIMIT as u64)
            .map_err(|error| {
                format!("Unsafe mutable settings {label} cannot be read for quarantine: {error}")
            })?;
        lease.revalidate().map_err(|error| error.to_string())?;
        match parse_envelope_bytes(bytes, maximum, self.install_id, channel, policy) {
            Ok(current) if desired.is_some_and(|desired| current.bytes == desired.bytes) => {
                return Ok(CorruptPreparation::AlreadyDesired(current));
            }
            Ok(current) => {
                return Err(format!(
                    "Mutable settings {label} became valid generation {} during recovery; refusing to quarantine it",
                    current.envelope.generation
                ));
            }
            Err(LoadFailure::Future(version)) => {
                return Err(format!(
                    "launcher_update_required: mutable settings schema {version}"
                ));
            }
            Err(LoadFailure::Corrupt(_)) => {}
            Err(LoadFailure::Missing) => {
                return Err(format!(
                    "Opened mutable settings {label} unexpectedly parsed as missing"
                ));
            }
        }
        let identity = lease.info().identity.clone();
        let digests = lease
            .sha1_sha256(ABSOLUTE_SETTINGS_LIMIT as u64)
            .map_err(|error| error.to_string())?;
        lease.revalidate().map_err(|error| error.to_string())?;
        self.prune_quarantine_locked(lock, paths)?;
        drop(lease);
        lock.validate_scope(self, paths)?;
        let quarantined = quarantine_node_if_identity(
            &self.install_root,
            source.clone(),
            &paths.quarantine,
            &identity,
            ManagedNodeKind::File,
        )
        .map_err(|error| managed_mutation_error("quarantine exact mutable settings", error))?;
        Ok(CorruptPreparation::Quarantined(ManagedQuarantine {
            relative: quarantined.destination,
            digests,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn quarantine_corrupt_locked(
        &self,
        lock: &SettingsOperationLock,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
        source: &RelativeManagedPath,
        label: &str,
    ) -> Result<(), String> {
        match self
            .prepare_corrupt_locked(lock, channel, policy, paths, maximum, source, None, label)?
        {
            CorruptPreparation::Missing | CorruptPreparation::Quarantined(_) => Ok(()),
            CorruptPreparation::AlreadyDesired(_) => Err(format!(
                "Mutable settings {label} unexpectedly matched an absent recovery target"
            )),
        }
    }

    fn cleanup_stale_staging_locked(
        &self,
        lock: &SettingsOperationLock,
        paths: &SettingsPaths,
        maximum: usize,
        policy: &MutableSettingsFile,
    ) -> Result<(), String> {
        lock.validate_scope(self, paths)?;
        let mut lease = match ImmutableManagedFile::open(&self.install_root, &paths.staging) {
            Ok(lease) => lease,
            Err(error) if managed_error_is_missing(&error) => return Ok(()),
            Err(error) => {
                return Err(format!(
                    "Unsafe mutable settings staging cannot be cleaned automatically: {error}"
                ));
            }
        };
        let bytes = lease
            .read_bounded_shared(ABSOLUTE_SETTINGS_LIMIT as u64)
            .map_err(|error| format!("Cannot audit stale mutable settings staging: {error}"))?;
        lease.revalidate().map_err(|error| error.to_string())?;
        if let Err(LoadFailure::Future(version)) =
            parse_envelope_bytes(bytes, maximum, self.install_id, lock.channel, policy)
        {
            return Err(format!(
                "launcher_update_required: mutable settings staging schema {version}"
            ));
        }
        let digests = lease
            .sha1_sha256(ABSOLUTE_SETTINGS_LIMIT as u64)
            .map_err(|error| format!("Cannot hash stale mutable settings staging: {error}"))?;
        lease.revalidate().map_err(|error| error.to_string())?;
        drop(lease);
        lock.validate_scope(self, paths)?;
        remove_verified_managed_file(&self.install_root, &paths.staging, &digests)
            .map_err(|error| managed_mutation_error("remove stale settings staging", error))
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_no_replace_locked(
        &self,
        lock: &SettingsOperationLock,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
        destination: &RelativeManagedPath,
        desired: &VerifiedEnvelope,
        source_lease: Option<&ImmutableManagedFile>,
    ) -> Result<VerifiedEnvelope, String> {
        if desired.bytes.is_empty() || desired.bytes.len() > maximum {
            return Err("Mutable settings publish payload exceeds its signed limit".into());
        }
        self.cleanup_stale_staging_locked(lock, paths, maximum, policy)?;
        let staging_relative = paths.staging.clone();
        let mut staging =
            ExclusiveManagedFile::create(&self.install_root, staging_relative.clone()).map_err(
                |error| format!("Cannot create exclusive mutable settings staging: {error}"),
            )?;
        if let Err(error) = staging.file_mut().write_all(&desired.bytes) {
            drop(staging);
            return Err(self.precommit_error_with_staging_cleanup(
                lock,
                paths,
                maximum,
                policy,
                format!("Cannot write mutable settings staging: {error}"),
            ));
        }
        let staging = match staging.sync() {
            Ok(staging) => staging,
            Err(error) => {
                return Err(self.precommit_error_with_staging_cleanup(
                    lock,
                    paths,
                    maximum,
                    policy,
                    format!("Cannot sync mutable settings staging: {error}"),
                ));
            }
        };
        if let Err(error) = lock.validate_scope(self, paths) {
            drop(staging);
            return Err(
                self.precommit_error_with_staging_cleanup(lock, paths, maximum, policy, error)
            );
        }
        if let Some(source_lease) = source_lease {
            if let Err(error) = source_lease.revalidate() {
                drop(staging);
                return Err(self.precommit_error_with_staging_cleanup(
                    lock,
                    paths,
                    maximum,
                    policy,
                    error.to_string(),
                ));
            }
        }
        let digests = digests_for_bytes(&desired.bytes);
        let committed = match staging.rename_no_replace(destination.clone()) {
            Ok(committed) => {
                if committed.size != desired.bytes.len() as u64 {
                    return Err(
                        "settings_applied_but_verification_unconfirmed: committed settings size differs"
                            .into(),
                    );
                }
                desired.clone()
            }
            Err(ManagedFsError::Conflict(_)) => {
                remove_verified_managed_file(&self.install_root, &staging_relative, &digests)
                    .map_err(|error| {
                        managed_mutation_error("remove exact collided settings staging", error)
                    })?;
                match load_envelope(
                    &self.install_root,
                    destination,
                    maximum,
                    self.install_id,
                    channel,
                    policy,
                ) {
                    Ok(current) if current.bytes == desired.bytes => current,
                    Ok(current) => {
                        return Err(format!(
                            "Mutable settings publish collision preserved divergent generation {}",
                            current.envelope.generation
                        ));
                    }
                    Err(LoadFailure::Future(version)) => {
                        return Err(format!(
                            "launcher_update_required: mutable settings schema {version}"
                        ));
                    }
                    Err(failure) => {
                        return Err(format!(
                            "Mutable settings publish collision left no exact committed destination: {failure}"
                        ));
                    }
                }
            }
            Err(error @ ManagedFsError::AppliedButDurabilityUnconfirmed { .. }) => {
                return Err(managed_mutation_error("publish mutable settings", error));
            }
            Err(error) => {
                return Err(self.precommit_error_with_staging_cleanup(
                    lock,
                    paths,
                    maximum,
                    policy,
                    managed_mutation_error("publish mutable settings", error),
                ));
            }
        };
        verify_envelope(
            &self.install_root,
            destination,
            maximum,
            self.install_id,
            channel,
            policy,
            &committed,
        )?;
        Ok(committed)
    }

    fn precommit_error_with_staging_cleanup(
        &self,
        lock: &SettingsOperationLock,
        paths: &SettingsPaths,
        maximum: usize,
        policy: &MutableSettingsFile,
        error: String,
    ) -> String {
        match self.cleanup_stale_staging_locked(lock, paths, maximum, policy) {
            Ok(()) => error,
            Err(cleanup) => format!("{error}; staging cleanup also failed: {cleanup}"),
        }
    }

    fn quarantine_verified_locked(
        &self,
        lock: &SettingsOperationLock,
        paths: &SettingsPaths,
        source: &RelativeManagedPath,
        verified: &VerifiedEnvelope,
        lease: ImmutableManagedFile,
        _label: &str,
    ) -> Result<ManagedQuarantine, String> {
        lock.validate_scope(self, paths)?;
        lease.revalidate().map_err(|error| error.to_string())?;
        let identity = lease.info().identity.clone();
        let digests = digests_for_bytes(&verified.bytes);
        self.prune_quarantine_locked(lock, paths)?;
        drop(lease);
        lock.validate_scope(self, paths)?;
        let quarantined = quarantine_node_if_identity(
            &self.install_root,
            source.clone(),
            &paths.quarantine,
            &identity,
            ManagedNodeKind::File,
        )
        .map_err(|error| managed_mutation_error("quarantine exact settings record", error))?;
        Ok(ManagedQuarantine {
            relative: quarantined.destination,
            digests,
        })
    }

    fn cleanup_applied_quarantine(
        &self,
        lock: &SettingsOperationLock,
        paths: &SettingsPaths,
        quarantine: ManagedQuarantine,
        label: &str,
    ) -> Result<(), String> {
        lock.validate_scope(self, paths).map_err(|error| {
            format!("settings_applied_but_verification_unconfirmed: {label} lock changed: {error}")
        })?;
        remove_verified_managed_file(
            &self.install_root,
            &quarantine.relative,
            &quarantine.digests,
        )
        .map_err(|error| match error {
            error @ ManagedFsError::AppliedButDurabilityUnconfirmed { .. } => {
                managed_mutation_error("clean exact applied settings quarantine", error)
            }
            other => format!(
                "settings_applied_but_verification_unconfirmed: {label} exact quarantine cleanup failed: {other}"
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn save_envelope_locked(
        &self,
        lock: &SettingsOperationLock,
        paths: &SettingsPaths,
        maximum: usize,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        previous_verified_bytes: Option<&[u8]>,
        envelope: &SettingsEnvelope,
    ) -> Result<(), String> {
        lock.validate_scope(self, paths)?;
        let desired = VerifiedEnvelope {
            envelope: envelope.clone(),
            bytes: serialize_envelope(envelope, maximum)?,
        };
        match previous_verified_bytes {
            Some(previous_bytes) => {
                let (current, current_lease) = load_envelope_leased(
                    &self.install_root,
                    &paths.primary,
                    maximum,
                    self.install_id,
                    channel,
                    policy,
                )
                .map_err(|failure| {
                    format!("Mutable settings primary changed before update: {failure}")
                })?;
                if current.bytes != previous_bytes
                    || desired.envelope.generation
                        != current.envelope.generation.checked_add(1).ok_or_else(|| {
                            "Mutable settings generation counter is exhausted".to_string()
                        })?
                {
                    return Err(
                        "Mutable settings primary diverged while the update was prepared".into(),
                    );
                }
                current_lease
                    .revalidate()
                    .map_err(|error| error.to_string())?;
                self.replace_backup_locked(
                    lock,
                    channel,
                    policy,
                    paths,
                    maximum,
                    &current,
                    &current_lease,
                )?;
                current_lease
                    .revalidate()
                    .map_err(|error| error.to_string())?;
                self.replace_verified_with_authority_locked(
                    lock,
                    channel,
                    policy,
                    paths,
                    maximum,
                    &paths.primary,
                    &current,
                    current_lease,
                    &desired,
                    "settings primary",
                )?;
            }
            None => {
                if desired.envelope.generation != 1 {
                    return Err("First mutable settings generation must be 1".into());
                }
                match load_envelope(
                    &self.install_root,
                    &paths.primary,
                    maximum,
                    self.install_id,
                    channel,
                    policy,
                ) {
                    Err(LoadFailure::Missing) => {}
                    Err(LoadFailure::Future(version)) => {
                        return Err(format!(
                            "launcher_update_required: mutable settings schema {version}"
                        ));
                    }
                    Ok(current) => {
                        return Err(format!(
                            "Mutable settings primary generation {} appeared before first save",
                            current.envelope.generation
                        ));
                    }
                    Err(LoadFailure::Corrupt(error)) => {
                        return Err(format!(
                            "Corrupt mutable settings primary appeared before first save: {error}"
                        ));
                    }
                }
                self.publish_no_replace_locked(
                    lock,
                    channel,
                    policy,
                    paths,
                    maximum,
                    &paths.primary,
                    &desired,
                    None,
                )?;
            }
        }
        self.prune_quarantine_locked(lock, paths)?;
        verify_envelope(
            &self.install_root,
            &paths.primary,
            maximum,
            self.install_id,
            channel,
            policy,
            &desired,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn replace_backup_locked(
        &self,
        lock: &SettingsOperationLock,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
        primary: &VerifiedEnvelope,
        primary_lease: &ImmutableManagedFile,
    ) -> Result<(), String> {
        let quarantine = match load_envelope_leased(
            &self.install_root,
            &paths.backup,
            maximum,
            self.install_id,
            channel,
            policy,
        ) {
            Ok((backup, lease)) => {
                if backup.bytes != primary.bytes
                    && backup.envelope.generation.checked_add(1)
                        != Some(primary.envelope.generation)
                {
                    return Err(format!(
                        "Ambiguous mutable settings backup generation {} before update",
                        backup.envelope.generation
                    ));
                }
                Some(self.quarantine_verified_locked(
                    lock,
                    paths,
                    &paths.backup,
                    &backup,
                    lease,
                    "settings backup",
                )?)
            }
            Err(LoadFailure::Missing) => None,
            Err(LoadFailure::Future(version)) => {
                return Err(format!(
                    "launcher_update_required: mutable settings backup schema {version}"
                ));
            }
            Err(LoadFailure::Corrupt(_)) => match self.prepare_corrupt_locked(
                lock,
                channel,
                policy,
                paths,
                maximum,
                &paths.backup,
                None,
                "backup",
            )? {
                CorruptPreparation::Missing => None,
                CorruptPreparation::Quarantined(quarantine) => Some(quarantine),
                CorruptPreparation::AlreadyDesired(_) => {
                    return Err("Corrupt backup unexpectedly became a desired record".into());
                }
            },
        };
        primary_lease
            .revalidate()
            .map_err(|error| error.to_string())?;
        self.publish_no_replace_locked(
            lock,
            channel,
            policy,
            paths,
            maximum,
            &paths.backup,
            primary,
            Some(primary_lease),
        )?;
        if let Some(quarantine) = quarantine {
            self.cleanup_applied_quarantine(lock, paths, quarantine, "settings backup")?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn replace_verified_with_authority_locked(
        &self,
        lock: &SettingsOperationLock,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
        destination: &RelativeManagedPath,
        current: &VerifiedEnvelope,
        current_lease: ImmutableManagedFile,
        desired: &VerifiedEnvelope,
        label: &str,
    ) -> Result<(), String> {
        let quarantine = self.quarantine_verified_locked(
            lock,
            paths,
            destination,
            current,
            current_lease,
            label,
        )?;
        self.publish_no_replace_locked(
            lock,
            channel,
            policy,
            paths,
            maximum,
            destination,
            desired,
            None,
        )?;
        self.cleanup_applied_quarantine(lock, paths, quarantine, label)
    }

    fn prune_quarantine_locked(
        &self,
        lock: &SettingsOperationLock,
        paths: &SettingsPaths,
    ) -> Result<(), String> {
        lock.validate_scope(self, paths)?;
        let guard = GuardedDirectoryChain::open(&self.install_root, &paths.quarantine)
            .map_err(|error| format!("Cannot open mutable settings quarantine: {error}"))?;
        let names = read_quarantine_names(&guard, &paths.quarantine)?;
        if names.len() > MAX_QUARANTINE_SCAN_FILES {
            return Err("Mutable settings quarantine exceeds its bounded scan capacity".into());
        }
        let mut entries = Vec::with_capacity(names.len());
        for name in &names {
            let relative = paths
                .quarantine
                .join_component(name)
                .map_err(|error| error.to_string())?;
            let mut lease = ImmutableManagedFile::open(&self.install_root, &relative)
                .map_err(|error| format!("Unsafe mutable settings quarantine entry: {error}"))?;
            let digests = lease
                .sha1_sha256(ABSOLUTE_SETTINGS_LIMIT as u64)
                .map_err(|error| format!("Cannot hash quarantine entry: {error}"))?;
            entries.push(QuarantineEntry {
                relative,
                digests,
                lease,
            });
        }
        guard.revalidate().map_err(|error| error.to_string())?;
        if read_quarantine_names(&guard, &paths.quarantine)? != names {
            return Err("Mutable settings quarantine changed during its exact audit".into());
        }
        let remove_count = entries.len().saturating_sub(MAX_QUARANTINE_FILES);
        for entry in entries.drain(..remove_count) {
            entry
                .lease
                .revalidate()
                .map_err(|error| error.to_string())?;
            drop(entry.lease);
            lock.validate_scope(self, paths)?;
            remove_verified_managed_file(&self.install_root, &entry.relative, &entry.digests)
                .map_err(|error| {
                    managed_mutation_error("prune exact settings quarantine entry", error)
                })?;
        }
        drop(entries);
        guard.revalidate().map_err(|error| error.to_string())?;
        if read_quarantine_names(&guard, &paths.quarantine)?.len() > MAX_QUARANTINE_FILES {
            return Err("Mutable settings quarantine remained above its retention limit".into());
        }
        Ok(())
    }
}

fn serialize_envelope(envelope: &SettingsEnvelope, maximum: usize) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec_pretty(envelope)
        .map_err(|error| format!("Cannot serialize mutable settings: {error}"))?;
    if bytes.len() > maximum {
        return Err("Mutable settings state exceeds its signed storage limit".into());
    }
    Ok(bytes)
}

fn settings_limit(policy: &MutableSettingsFile) -> Result<usize, String> {
    policy
        .max_bytes
        .checked_mul(8)
        .and_then(|value| value.checked_add(1024 * 1024))
        .map(|value| value.clamp(256 * 1024, ABSOLUTE_SETTINGS_LIMIT))
        .ok_or_else(|| "Mutable settings storage limit overflowed".into())
}

fn loaded_settings(
    verified: VerifiedEnvelope,
    policy: &MutableSettingsFile,
    warning: Option<String>,
) -> Result<LoadedSettings, String> {
    Ok(LoadedSettings {
        generation: verified.envelope.generation,
        state: state_from_envelope(&verified.envelope, policy)?,
        warning,
        verified_bytes: Some(verified.bytes),
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_envelope(
    install_root: &Path,
    path: &RelativeManagedPath,
    maximum: usize,
    install_id: Uuid,
    channel: BuildChannel,
    policy: &MutableSettingsFile,
    expected: &VerifiedEnvelope,
) -> Result<(), String> {
    let verified = load_envelope(install_root, path, maximum, install_id, channel, policy)
        .map_err(|failure| {
            format!(
                "settings_applied_but_verification_unconfirmed: cannot read committed settings: {failure}"
            )
        })?;
    if verified.bytes != expected.bytes || verified.envelope != expected.envelope {
        return Err(
            "settings_applied_but_verification_unconfirmed: committed settings changed during post-readback"
                .into(),
        );
    }
    Ok(())
}

fn digests_for_bytes(bytes: &[u8]) -> FileDigests {
    let mut sha1 = Sha1::new();
    sha1.update(bytes);
    let mut sha256 = Sha256::new();
    sha256.update(bytes);
    FileDigests {
        size: bytes.len() as u64,
        sha1: format!("{:x}", sha1.finalize()),
        sha256: format!("{:x}", sha256.finalize()),
    }
}

fn read_quarantine_names(
    guard: &GuardedDirectoryChain,
    quarantine: &RelativeManagedPath,
) -> Result<Vec<String>, String> {
    guard.revalidate().map_err(|error| error.to_string())?;
    let path = quarantine.join_to(guard.root_path());
    let mut names = Vec::new();
    for entry in fs::read_dir(&path)
        .map_err(|error| format!("Cannot enumerate mutable settings quarantine: {error}"))?
    {
        let entry = entry
            .map_err(|error| format!("Cannot read mutable settings quarantine entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Mutable settings quarantine contains a non-Unicode name".to_string())?;
        quarantine
            .join_component(&name)
            .map_err(|error| format!("Unsafe mutable settings quarantine name: {error}"))?;
        Uuid::parse_str(&name)
            .map_err(|_| "Mutable settings quarantine contains an unknown entry".to_string())?;
        names.push(name);
        if names.len() > MAX_QUARANTINE_SCAN_FILES {
            return Err("Mutable settings quarantine exceeds its bounded scan capacity".into());
        }
    }
    names.sort_unstable();
    guard.revalidate().map_err(|error| error.to_string())?;
    Ok(names)
}

fn parse_without_duplicate_keys<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
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
    serde_json::from_value(value).map_err(|error| format!("invalid settings schema: {error}"))
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
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fragment-settings-store-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ))
    }

    fn policy() -> MutableSettingsFile {
        serde_json::from_value(serde_json::json!({
            "path": "options.txt",
            "validator": "minecraft-options-v1",
            "maxBytes": 4096,
            "unknownKeyPolicy": "drop",
            "duplicateKeyPolicy": "reject",
            "invalidValuePolicy": "use-default",
            "fields": [
                {
                    "settingId": "minecraft.controls.keybindings",
                    "scope": "profile",
                    "selector": { "kind": "prefix", "prefix": "key_" },
                    "value": { "type": "string", "maxLength": 128, "allowedPrefixes": ["key.keyboard."] },
                    "renamedFrom": []
                },
                {
                    "settingId": "minecraft.video.render-distance",
                    "scope": "preset",
                    "selector": { "kind": "exact", "key": "renderDistance" },
                    "value": { "type": "integer", "minimum": 2, "maximum": 32 },
                    "renamedFrom": []
                }
            ]
        }))
        .unwrap()
    }

    fn paths(channel: BuildChannel, policy: &MutableSettingsFile) -> SettingsPaths {
        SettingsPaths::new(channel, policy).unwrap()
    }

    fn future_bytes(
        install_id: Uuid,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        generation: u64,
    ) -> Vec<u8> {
        let mut envelope = serde_json::to_value(envelope_from_state(
            install_id,
            channel,
            policy,
            generation,
            &MutableSettingsState::new(),
        ))
        .unwrap();
        envelope["schemaVersion"] = serde_json::json!(2);
        envelope["introducedByLauncherV2"] = serde_json::json!({ "safe": true });
        serde_json::to_vec(&envelope).unwrap()
    }

    #[test]
    fn round_trips_profile_and_separate_preset_buckets() {
        let root = temp_root("roundtrip");
        fs::create_dir_all(&root).unwrap();
        let store = SettingsStore::new(&root, Uuid::new_v4());
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |state| {
                state.profile.insert(
                    "minecraft.controls.keybindings".into(),
                    BTreeMap::from([("key_forward".into(), "key.keyboard.w".into())]),
                );
                state.presets.entry("low".into()).or_default().insert(
                    "minecraft.video.render-distance".into(),
                    BTreeMap::from([("renderDistance".into(), "10".into())]),
                );
                state.presets.entry("high".into()).or_default().insert(
                    "minecraft.video.render-distance".into(),
                    BTreeMap::from([("renderDistance".into(), "28".into())]),
                );
                Ok(())
            })
            .unwrap();
        let loaded = store.load(BuildChannel::Stable, &policy).unwrap();
        assert_eq!(loaded.generation, 1);
        assert_eq!(
            loaded.presets_value("low", "minecraft.video.render-distance", "renderDistance"),
            Some("10")
        );
        assert_eq!(
            loaded.presets_value("high", "minecraft.video.render-distance", "renderDistance"),
            Some("28")
        );
        assert!(store
            .load(BuildChannel::Dev, &policy)
            .unwrap()
            .state
            .profile
            .is_empty());
        assert!(store
            .load(BuildChannel::Dev, &policy)
            .unwrap()
            .warning
            .is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn restores_valid_backup_and_rejects_future_schema() {
        let root = temp_root("recovery");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        let paths = paths(BuildChannel::Stable, &policy);
        fs::write(paths.primary.join_to(&root), b"corrupt").unwrap();
        let loaded = store.load(BuildChannel::Stable, &policy).unwrap();
        assert_eq!(loaded.generation, 1);
        assert!(loaded.warning.is_some());

        fs::write(
            paths.primary.join_to(&root),
            future_bytes(install_id, BuildChannel::Stable, &policy, 3),
        )
        .unwrap();
        assert!(store
            .load(BuildChannel::Stable, &policy)
            .unwrap_err()
            .contains("launcher_update_required"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn semantic_corruption_uses_the_verified_backup() {
        let root = temp_root("semantic-recovery");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        let paths = paths(BuildChannel::Stable, &policy);
        let mut primary: Value =
            serde_json::from_slice(&fs::read(paths.primary.join_to(&root)).unwrap()).unwrap();
        primary["profile"] = Value::Object(
            (0..513)
                .map(|index| (format!("untrusted.{index}"), serde_json::json!({})))
                .collect(),
        );
        fs::write(
            paths.primary.join_to(&root),
            serde_json::to_vec(&primary).unwrap(),
        )
        .unwrap();

        let loaded = store.load(BuildChannel::Stable, &policy).unwrap();
        assert_eq!(loaded.generation, 1);
        assert!(loaded.warning.is_some());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn crash_missing_primary_restores_exact_backup_bytes() {
        let root = temp_root("missing-primary-crash");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        let paths = paths(BuildChannel::Stable, &policy);
        let primary = paths.primary.join_to(&root);
        let backup = paths.backup.join_to(&root);
        let expected = fs::read(&backup).unwrap();
        fs::remove_file(&primary).unwrap();

        let loaded = store.load(BuildChannel::Stable, &policy).unwrap();
        assert_eq!(loaded.generation, 1);
        assert_eq!(fs::read(primary).unwrap(), expected);
        assert_eq!(fs::read(backup).unwrap(), expected);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn crash_staging_is_bounded_cleaned_and_future_staging_is_preserved() {
        let root = temp_root("staging-crash");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        let paths = paths(BuildChannel::Stable, &policy);
        let staging = paths.staging.join_to(&root);
        fs::write(&staging, b"partial-crash-write").unwrap();

        assert_eq!(
            store
                .load(BuildChannel::Stable, &policy)
                .unwrap()
                .generation,
            1
        );
        assert!(!staging.exists());

        let future = future_bytes(install_id, BuildChannel::Stable, &policy, 2);
        fs::write(&staging, &future).unwrap();
        let error = store.load(BuildChannel::Stable, &policy).unwrap_err();
        assert!(error.contains("launcher_update_required"));
        assert_eq!(fs::read(&staging).unwrap(), future);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn future_backup_with_valid_primary_is_preserved_and_rejected() {
        let root = temp_root("future-backup");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        let paths = paths(BuildChannel::Stable, &policy);
        let primary_path = paths.primary.join_to(&root);
        let backup_path = paths.backup.join_to(&root);
        let primary_before = fs::read(&primary_path).unwrap();
        let future = future_bytes(install_id, BuildChannel::Stable, &policy, 3);
        fs::write(&backup_path, &future).unwrap();

        let error = store.load(BuildChannel::Stable, &policy).unwrap_err();
        assert!(error.contains("launcher_update_required"));
        assert_eq!(fs::read(primary_path).unwrap(), primary_before);
        assert_eq!(fs::read(backup_path).unwrap(), future);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn same_generation_divergent_backup_is_ambiguous_and_preserved() {
        let root = temp_root("divergent-backup");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        let paths = paths(BuildChannel::Stable, &policy);
        let primary_path = paths.primary.join_to(&root);
        let backup_path = paths.backup.join_to(&root);
        let primary_before = fs::read(&primary_path).unwrap();
        let mut divergent: Value = serde_json::from_slice(&primary_before).unwrap();
        divergent["profile"] = serde_json::json!({
            "minecraft.controls.keybindings": { "key_forward": "key.keyboard.z" }
        });
        let divergent = serde_json::to_vec_pretty(&divergent).unwrap();
        fs::write(&backup_path, &divergent).unwrap();

        let error = store.load(BuildChannel::Stable, &policy).unwrap_err();
        assert!(error.contains("Ambiguous valid mutable settings state"));
        assert_eq!(fs::read(primary_path).unwrap(), primary_before);
        assert_eq!(fs::read(backup_path).unwrap(), divergent);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn commit_boundary_future_collision_is_never_replaced() {
        let root = temp_root("future-commit-collision");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        let expected_future = future_bytes(install_id, BuildChannel::Stable, &policy, 3);

        let error = store
            .with_file_lock(BuildChannel::Stable, &policy, |lock, paths, maximum| {
                let (backup, backup_lease) = load_envelope_leased(
                    &root,
                    &paths.backup,
                    maximum,
                    install_id,
                    BuildChannel::Stable,
                    &policy,
                )
                .map_err(|failure| failure.to_string())?;
                let primary = paths.primary.join_to(&root);
                fs::remove_file(&primary).unwrap();
                fs::write(&primary, &expected_future).unwrap();
                store
                    .publish_no_replace_locked(
                        lock,
                        BuildChannel::Stable,
                        &policy,
                        paths,
                        maximum,
                        &paths.primary,
                        &backup,
                        Some(&backup_lease),
                    )
                    .map(|_| ())
            })
            .unwrap_err();
        assert!(error.contains("launcher_update_required"));
        let paths = paths(BuildChannel::Stable, &policy);
        assert_eq!(
            fs::read(paths.primary.join_to(&root)).unwrap(),
            expected_future
        );
        assert!(!fs::read_dir(paths.directory.join_to(&root))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".settings-")));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn exact_lock_filesystem_identity_is_required() {
        let root = temp_root("lock-identity");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        let stable = paths(BuildChannel::Stable, &policy);
        let dev = paths(BuildChannel::Dev, &policy);
        stable.prepare(&root).unwrap();
        dev.prepare(&root).unwrap();
        let wrong_file = open_or_create_lock_file(&root, &dev.lock).unwrap();
        wrong_file.file().try_lock_exclusive().unwrap();
        let forged = SettingsOperationLock {
            file: wrong_file,
            install_root: root.clone(),
            install_id,
            channel: BuildChannel::Stable,
            namespace: stable.namespace.clone(),
        };

        let error = forged.validate_scope(&store, &stable).unwrap_err();
        assert!(error.contains("identity"));
        drop(forged);
        let _ = fs::remove_dir_all(root);
    }

    #[cfg(windows)]
    #[test]
    fn reparse_primary_and_quarantine_entries_are_never_followed() {
        use std::os::windows::fs::symlink_file;

        let root = temp_root("reparse-primary");
        let outside = temp_root("reparse-outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let install_id = Uuid::new_v4();
        let store = SettingsStore::new(&root, install_id);
        let policy = policy();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        store
            .update(BuildChannel::Stable, &policy, |_| Ok(()))
            .unwrap();
        let paths = paths(BuildChannel::Stable, &policy);
        let primary = paths.primary.join_to(&root);
        let sentinel = outside.join("sentinel.json");
        fs::write(&sentinel, b"outside-must-not-change").unwrap();
        fs::remove_file(&primary).unwrap();
        if symlink_file(&sentinel, &primary).is_err() {
            let _ = fs::remove_dir_all(root);
            let _ = fs::remove_dir_all(outside);
            return;
        }

        let error = store.load(BuildChannel::Stable, &policy).unwrap_err();
        assert!(error.contains("Unsafe mutable settings primary"));
        assert_eq!(fs::read(&sentinel).unwrap(), b"outside-must-not-change");
        assert!(fs::symlink_metadata(&primary)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[cfg(windows)]
    #[test]
    fn reparse_parent_is_rejected_without_touching_outside_directory() {
        use std::os::windows::fs::symlink_dir;

        let root = temp_root("reparse-parent");
        let outside = temp_root("reparse-parent-outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        if symlink_dir(&outside, root.join("state")).is_err() {
            let _ = fs::remove_dir_all(root);
            let _ = fs::remove_dir_all(outside);
            return;
        }
        let store = SettingsStore::new(&root, Uuid::new_v4());
        assert!(store.load(BuildChannel::Stable, &policy()).is_err());
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(outside);
    }

    #[test]
    fn canonical_namespace_survives_manifest_path_casing() {
        let root = temp_root("namespace-casing");
        fs::create_dir_all(&root).unwrap();
        let store = SettingsStore::new(&root, Uuid::new_v4());
        let lower = policy();
        store
            .update(BuildChannel::Stable, &lower, |_| Ok(()))
            .unwrap();
        let mut upper = policy();
        upper.path = "OPTIONS.TXT".into();
        assert_eq!(
            store.load(BuildChannel::Stable, &upper).unwrap().generation,
            1
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn independent_store_instances_serialize_updates() {
        let root = temp_root("concurrent-stores");
        fs::create_dir_all(&root).unwrap();
        let install_id = Uuid::new_v4();
        let mut workers = Vec::new();
        for index in 0..8 {
            let root = root.clone();
            workers.push(std::thread::spawn(move || {
                let store = SettingsStore::new(&root, install_id);
                let policy = policy();
                store
                    .update(BuildChannel::Stable, &policy, |state| {
                        state
                            .profile
                            .entry("minecraft.controls.keybindings".into())
                            .or_default()
                            .insert(format!("key_custom_{index}"), "key.keyboard.a".into());
                        Ok(())
                    })
                    .map(|_| ())
            }));
        }
        for worker in workers {
            worker.join().unwrap().unwrap();
        }
        let loaded = SettingsStore::new(&root, install_id)
            .load(BuildChannel::Stable, &policy())
            .unwrap();
        assert_eq!(loaded.generation, 8);
        assert_eq!(
            loaded.state.profile["minecraft.controls.keybindings"].len(),
            8
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn rejects_duplicate_json_keys_and_bom() {
        assert!(parse_without_duplicate_keys::<Value>(br#"{"a":1,"a":2}"#).is_err());
        assert!(parse_without_duplicate_keys::<Value>(b"\xef\xbb\xbf{}").is_err());
    }

    impl LoadedSettings {
        fn presets_value(&self, preset: &str, id: &str, key: &str) -> Option<&str> {
            self.state
                .presets
                .get(preset)?
                .get(id)?
                .get(key)
                .map(String::as_str)
        }
    }
}
