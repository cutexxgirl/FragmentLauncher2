use super::{
    contracts::{MutableSettingsFile, MutableValidator},
    mutable::{MutableSettingsState, SettingValues},
    storage::{
        inspect_existing_ancestors, open_or_create_regular_single_link, open_regular_single_link,
        replace_file,
    },
    types::BuildChannel,
};
use fs2::FileExt;
use serde::{
    de::{DeserializeOwned, MapAccess, SeqAccess, Visitor},
    Deserialize, Deserializer, Serialize,
};
use serde_json::{Map, Number, Value};
use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use uuid::Uuid;

const SETTINGS_SCHEMA_VERSION: u8 = 1;
const ABSOLUTE_SETTINGS_LIMIT: usize = 16 * 1024 * 1024;
const MAX_QUARANTINE_FILES: usize = 8;

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
    root: PathBuf,
    install_id: Uuid,
    process_lock: Arc<Mutex<()>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedPresets {
    low: SettingsBucket,
    medium: SettingsBucket,
    high: SettingsBucket,
}

impl SettingsStore {
    pub fn new(install_root: &Path, install_id: Uuid) -> Self {
        Self {
            root: install_root.join("state").join("settings").join("v1"),
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
        self.with_file_lock(channel, policy, |paths, maximum| {
            self.load_locked(channel, policy, paths, maximum)
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
        self.with_file_lock(channel, policy, |paths, maximum| {
            let mut loaded = self.load_locked(channel, policy, paths, maximum)?;
            let value = operation(&mut loaded.state)?;
            loaded.state.migrate_all(std::slice::from_ref(policy))?;
            let generation = loaded
                .generation
                .checked_add(1)
                .ok_or_else(|| "Mutable settings generation overflowed".to_string())?;
            let envelope =
                envelope_from_state(self.install_id, channel, policy, generation, &loaded.state);
            save_envelope(paths, maximum, loaded.verified_bytes.as_deref(), &envelope)?;
            let verified = load_envelope(&paths.primary, maximum, self.install_id, channel, policy)
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
        operation: impl FnOnce(&SettingsPaths, usize) -> Result<T, String>,
    ) -> Result<T, String> {
        policy.validate()?;
        let maximum = settings_limit(policy)?;
        let paths = SettingsPaths::new(&self.root, channel, policy)?;
        paths.prepare()?;
        let lock = open_lock(&paths.lock)?;
        let started = Instant::now();
        loop {
            match lock.try_lock_exclusive() {
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
        let result = operation(&paths, maximum);
        let unlock = FileExt::unlock(&lock)
            .map_err(|error| format!("Cannot unlock mutable settings store: {error}"));
        match (result, unlock) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
        }
    }

    fn load_locked(
        &self,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
        paths: &SettingsPaths,
        maximum: usize,
    ) -> Result<LoadedSettings, String> {
        match load_envelope(&paths.primary, maximum, self.install_id, channel, policy) {
            Ok(verified) => Ok(LoadedSettings {
                generation: verified.envelope.generation,
                state: state_from_envelope(&verified.envelope, policy)?,
                warning: None,
                verified_bytes: Some(verified.bytes),
            }),
            Err(primary_failure @ (LoadFailure::Missing | LoadFailure::Corrupt(_))) => {
                let primary_missing = matches!(primary_failure, LoadFailure::Missing);
                match load_envelope(&paths.backup, maximum, self.install_id, channel, policy) {
                    Ok(verified) => {
                        atomic_write(&paths.primary, &verified.bytes)?;
                        Ok(LoadedSettings {
                            generation: verified.envelope.generation,
                            state: state_from_envelope(&verified.envelope, policy)?,
                            warning: Some(
                                "Mutable settings primary was restored from its verified backup"
                                    .into(),
                            ),
                            verified_bytes: Some(verified.bytes),
                        })
                    }
                    Err(LoadFailure::Future(version)) => Err(format!(
                        "launcher_update_required: mutable settings schema {version}"
                    )),
                    Err(backup_failure @ (LoadFailure::Missing | LoadFailure::Corrupt(_))) => {
                        let backup_missing = matches!(backup_failure, LoadFailure::Missing);
                        quarantine_if_present(&paths.primary, &paths.quarantine)?;
                        quarantine_if_present(&paths.backup, &paths.quarantine)?;
                        prune_quarantine(&paths.quarantine)?;
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
    directory: PathBuf,
    primary: PathBuf,
    backup: PathBuf,
    lock: PathBuf,
    quarantine: PathBuf,
}

impl SettingsPaths {
    fn new(
        root: &Path,
        channel: BuildChannel,
        policy: &MutableSettingsFile,
    ) -> Result<Self, String> {
        let filename = match policy.validator {
            MutableValidator::MinecraftOptionsV1 => "minecraft-options-v1.json",
            _ => return Err("Mutable validator has no persisted settings namespace".into()),
        };
        let directory = root.join(channel.as_str());
        Ok(Self {
            primary: directory.join(filename),
            backup: directory.join(format!("{filename}.bak")),
            lock: directory.join(".settings.lock"),
            quarantine: directory.clone(),
            directory,
        })
    }

    fn prepare(&self) -> Result<(), String> {
        inspect_existing_ancestors(&self.directory)?;
        fs::create_dir_all(&self.directory)
            .map_err(|error| format!("Cannot create mutable settings directory: {error}"))?;
        inspect_existing_ancestors(&self.directory)
    }
}

fn open_lock(path: &Path) -> Result<File, String> {
    open_or_create_regular_single_link(path)
        .map_err(|error| format!("Cannot open mutable settings lock: {error}"))
}

struct VerifiedEnvelope {
    envelope: SettingsEnvelope,
    bytes: Vec<u8>,
}

fn load_envelope(
    path: &Path,
    maximum: usize,
    install_id: Uuid,
    channel: BuildChannel,
    policy: &MutableSettingsFile,
) -> Result<VerifiedEnvelope, LoadFailure> {
    if !path.exists() {
        return Err(LoadFailure::Missing);
    }
    let mut file = open_regular_single_link(path, false).map_err(LoadFailure::Corrupt)?;
    let length = file
        .metadata()
        .map_err(|error| LoadFailure::Corrupt(error.to_string()))?
        .len();
    if length == 0 || length > ABSOLUTE_SETTINGS_LIMIT as u64 {
        return Err(LoadFailure::Corrupt(
            "mutable settings file is empty or oversized".into(),
        ));
    }
    let mut bytes = Vec::with_capacity((length as usize).min(ABSOLUTE_SETTINGS_LIMIT));
    Read::by_ref(&mut file)
        .take((ABSOLUTE_SETTINGS_LIMIT as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| LoadFailure::Corrupt(error.to_string()))?;
    if bytes.len() > ABSOLUTE_SETTINGS_LIMIT {
        return Err(LoadFailure::Corrupt(
            "mutable settings file grew beyond its signed limit while reading".into(),
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
    state_from_envelope(&envelope, policy).map_err(LoadFailure::Corrupt)?;
    Ok(VerifiedEnvelope { envelope, bytes })
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

fn save_envelope(
    paths: &SettingsPaths,
    maximum: usize,
    previous_verified_bytes: Option<&[u8]>,
    envelope: &SettingsEnvelope,
) -> Result<(), String> {
    if let Some(existing) = previous_verified_bytes {
        if existing.len() > maximum {
            return Err("Refusing to back up oversized mutable settings".into());
        }
        atomic_write(&paths.backup, existing)?;
    }
    let bytes = serialize_envelope(envelope, maximum)?;
    atomic_write(&paths.primary, &bytes)
}

fn serialize_envelope(envelope: &SettingsEnvelope, maximum: usize) -> Result<Vec<u8>, String> {
    let bytes = serde_json::to_vec_pretty(envelope)
        .map_err(|error| format!("Cannot serialize mutable settings: {error}"))?;
    if bytes.len() > maximum {
        return Err("Mutable settings state exceeds its signed storage limit".into());
    }
    Ok(bytes)
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| "Mutable settings path has no parent".to_string())?;
    let temporary = parent.join(format!(".settings-{}.tmp", Uuid::new_v4()));
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("Cannot create temporary mutable settings: {error}"))?;
        file.write_all(bytes)
            .map_err(|error| format!("Cannot write temporary mutable settings: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Cannot flush temporary mutable settings: {error}"))?;
        drop(file);
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn settings_limit(policy: &MutableSettingsFile) -> Result<usize, String> {
    policy
        .max_bytes
        .checked_mul(8)
        .and_then(|value| value.checked_add(1024 * 1024))
        .map(|value| value.clamp(256 * 1024, ABSOLUTE_SETTINGS_LIMIT))
        .ok_or_else(|| "Mutable settings storage limit overflowed".into())
}

fn quarantine_if_present(path: &Path, quarantine: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    open_regular_single_link(path, false)?;
    inspect_existing_ancestors(quarantine)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "Mutable settings filename is invalid".to_string())?;
    fs::rename(
        path,
        quarantine.join(format!(".settings-corrupt-{}-{name}", Uuid::new_v4())),
    )
    .map_err(|error| format!("Cannot quarantine corrupt mutable settings: {error}"))
}

fn prune_quarantine(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Ok(());
    }
    inspect_existing_ancestors(path)?;
    let mut files = Vec::new();
    for entry in fs::read_dir(path)
        .map_err(|error| format!("Cannot inspect mutable settings quarantine: {error}"))?
    {
        let entry = entry.map_err(|error| format!("Cannot inspect quarantine entry: {error}"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "Mutable settings directory contains a non-UTF-8 entry".to_string())?;
        if !name.starts_with(".settings-corrupt-") {
            continue;
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| format!("Cannot inspect quarantine entry: {error}"))?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Err("Mutable settings quarantine contains an unsafe entry".into());
        }
        files.push((metadata.modified().ok(), entry.path()));
    }
    files.sort_by_key(|(modified, _)| *modified);
    let remove_count = files.len().saturating_sub(MAX_QUARANTINE_FILES);
    for (_, file) in files.into_iter().take(remove_count) {
        fs::remove_file(file)
            .map_err(|error| format!("Cannot prune mutable settings quarantine: {error}"))?;
    }
    Ok(())
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
        let paths = SettingsPaths::new(&store.root, BuildChannel::Stable, &policy).unwrap();
        fs::write(&paths.primary, b"corrupt").unwrap();
        let loaded = store.load(BuildChannel::Stable, &policy).unwrap();
        assert_eq!(loaded.generation, 1);
        assert!(loaded.warning.is_some());

        let mut envelope = serde_json::to_value(envelope_from_state(
            install_id,
            BuildChannel::Stable,
            &policy,
            3,
            &MutableSettingsState::new(),
        ))
        .unwrap();
        envelope["schemaVersion"] = serde_json::json!(2);
        envelope["introducedByLauncherV2"] = serde_json::json!({ "safe": true });
        atomic_write(&paths.primary, &serde_json::to_vec(&envelope).unwrap()).unwrap();
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
        let paths = SettingsPaths::new(&store.root, BuildChannel::Stable, &policy).unwrap();
        let mut primary: Value =
            serde_json::from_slice(&fs::read(&paths.primary).unwrap()).unwrap();
        primary["profile"] = Value::Object(
            (0..513)
                .map(|index| (format!("untrusted.{index}"), serde_json::json!({})))
                .collect(),
        );
        atomic_write(&paths.primary, &serde_json::to_vec(&primary).unwrap()).unwrap();

        let loaded = store.load(BuildChannel::Stable, &policy).unwrap();
        assert_eq!(loaded.generation, 1);
        assert!(loaded.warning.is_some());
        let _ = fs::remove_dir_all(root);
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
