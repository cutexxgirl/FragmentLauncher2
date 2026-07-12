use super::{
    contracts::{
        is_sha256, valid_java25_version, valid_setting_id, validate_manifest_path, GameRuntimeLock,
        MutableSettingsFile, RuntimeLock, JAVA_DISTRIBUTION, JAVA_IMAGE_TYPE, JAVA_MAJOR, JAVA_VM,
    },
    neoforge::{
        MINECRAFT_VERSION, NEOFORGE_INSTALLER_SHA256, NEOFORGE_INSTALLER_URL, NEOFORGE_VERSION,
    },
    types::{BuildChannel, PresetId},
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use unicode_normalization::UnicodeNormalization;
use url::Url;

const REQUIRED_STRICT_ROOTS: [&str; 4] = ["mods", "resourcepacks", "shaderpacks", "config"];
const REQUIRED_LAUNCH_GUARD: &str = "mods/fragment-launch-guard.jar";
const MAX_FILES_PER_PRESET: usize = 200_000;

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CurrentPointer {
    pub schema_version: u8,
    pub channel: BuildChannel,
    pub release_id: String,
    pub manifest_target: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseManifest {
    pub schema_version: u8,
    pub project: ReleaseProject,
    pub release: ReleaseIdentity,
    pub runtime: ReleaseRuntime,
    pub integrity: ReleaseIntegrity,
    pub presets: Vec<ReleasePreset>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseProject {
    pub id: String,
    pub display_name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseIdentity {
    pub id: String,
    pub version: String,
    pub created_at: String,
    pub minimum_launcher_version: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseRuntime {
    pub minecraft: String,
    pub loader: ReleaseLoader,
    pub java: ReleaseJava,
    pub game: ReleaseGame,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseLoader {
    pub kind: String,
    pub version: String,
    pub installer_url: String,
    pub installer_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseJava {
    pub major: u8,
    pub architecture: String,
    pub distribution: String,
    pub image_type: String,
    pub vm: String,
    pub version: String,
    pub runtime_target: String,
    pub runtime_lock_sha256: String,
    pub archive: ReleaseObject,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseGame {
    pub platform: String,
    pub runtime_target: String,
    pub runtime_lock_sha256: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseObject {
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseIntegrity {
    pub unknown_policy: String,
    pub strict_roots: Vec<String>,
    pub preserved_paths: Vec<String>,
    pub locked_paths: Vec<String>,
    pub preset_override_paths: Vec<String>,
    pub mutable_settings: Vec<MutableSettingsFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleasePreset {
    pub id: PresetId,
    pub display_name: String,
    pub jvm: ReleaseJvm,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseJvm {
    pub min_memory_mi_b: u64,
    pub max_memory_mi_b: u64,
    #[serde(default)]
    pub extra_arguments: Vec<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilePolicy {
    Exact,
    ValidatedMutable,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default)]
    pub executable: bool,
    pub policy: FilePolicy,
}

impl CurrentPointer {
    pub fn parse_and_validate(
        bytes: &[u8],
        expected_channel: BuildChannel,
    ) -> Result<Self, String> {
        if bytes.len() > 8 * 1024 {
            return Err("TUF current target exceeds the launcher limit".into());
        }
        let current: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("TUF current target is invalid: {error}"))?;
        if current.schema_version != 1 || current.channel != expected_channel {
            return Err("TUF current target belongs to another schema or channel".into());
        }
        if !valid_release_id(&current.release_id)
            || current.manifest_target != format!("release-{}.json", current.release_id)
        {
            return Err("TUF current target has an invalid release binding".into());
        }
        validate_manifest_path(&current.manifest_target)?;
        Ok(current)
    }
}

impl ReleaseManifest {
    pub fn parse_and_validate(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 16 * 1024 * 1024 {
            return Err("Release manifest exceeds the launcher limit".into());
        }
        let manifest: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("Release manifest JSON is invalid: {error}"))?;
        // Spark derives release IDs with json-canonicalize, whose JCS/ECMAScript number
        // serialization must not be approximated with serde_json (mutable numeric bounds are
        // part of the derivation). TUF authenticates these exact bytes and the refresh caller
        // separately binds current.releaseId to release.id, so a lossy duplicate check would add
        // compatibility failures rather than another trust boundary.
        manifest.validate()?;
        Ok(manifest)
    }

    pub fn validate(&self) -> Result<(), String> {
        self.validate_identity()?;
        self.validate_runtime()?;
        self.validate_integrity()?;
        self.validate_presets()?;
        self.validate_cross_fields()
    }

    pub fn bind_runtime_lock(&self, lock: &RuntimeLock) -> Result<(), String> {
        let java = &self.runtime.java;
        if java.major != lock.java.major
            || java.architecture != lock.java.architecture
            || java.distribution != lock.java.distribution
            || java.image_type != lock.java.image_type
            || java.vm != lock.java.vm
            || java.version != lock.java.version
            || java.archive.size != lock.java.archive.size
            || java.archive.sha256 != lock.java.archive.sha256
            || lock.minecraft.version != self.runtime.minecraft
        {
            return Err("Runtime lock does not match the signed release manifest".into());
        }
        Ok(())
    }

    pub fn bind_game_runtime_lock(
        &self,
        java_lock: &RuntimeLock,
        lock: &GameRuntimeLock,
    ) -> Result<(), String> {
        if self.runtime.game.platform != "windows-x64"
            || lock.platform.os != "windows"
            || lock.platform.architecture != "x64"
            || lock.provenance.neo_forge_installer.url != self.runtime.loader.installer_url
            || lock.provenance.neo_forge_installer.sha256 != self.runtime.loader.installer_sha256
            || lock.id
                != format!(
                    "minecraft-{}-{}-{}-windows-x64",
                    self.runtime.minecraft, self.runtime.loader.kind, self.runtime.loader.version
                )
        {
            return Err("Game runtime lock does not match the signed release manifest".into());
        }
        if java_lock.minecraft.version != self.runtime.minecraft
            || java_lock.minecraft.version_json_url != lock.provenance.minecraft_version_json.url
            || java_lock.minecraft.version_json_sha1 != lock.provenance.minecraft_version_json.sha1
        {
            return Err(
                "Managed Java and game runtime locks disagree on Minecraft metadata".into(),
            );
        }
        lock.verification.offline_processors.bind_java_runtime(
            &self.runtime.java.runtime_lock_sha256,
            &java_lock.java.archive.sha256,
            &java_lock.extracted_tree_sha256()?,
            &java_lock.java.version,
        )?;
        Ok(())
    }

    pub fn selected_preset(&self, preset: PresetId) -> Result<&ReleasePreset, String> {
        self.presets
            .iter()
            .find(|candidate| candidate.id == preset)
            .ok_or_else(|| "Selected preset is missing from the release".into())
    }

    fn validate_identity(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !valid_project_id(&self.project.id)
            || !safe_text(&self.project.display_name, 1, 100, false)
            || !valid_release_id(&self.release.id)
            || !safe_text(&self.release.version, 1, 64, true)
            || self.release.created_at.parse::<jiff::Timestamp>().is_err()
            || semver::Version::parse(&self.release.minimum_launcher_version).is_err()
            || self
                .release
                .notes
                .as_ref()
                .is_some_and(|notes| notes.chars().count() > 4000 || notes.contains('\0'))
        {
            return Err("Release identity is invalid or unsupported".into());
        }
        Ok(())
    }

    fn validate_runtime(&self) -> Result<(), String> {
        let java = &self.runtime.java;
        let game = &self.runtime.game;
        if self.runtime.minecraft != MINECRAFT_VERSION
            || self.runtime.loader.kind != "neoforge"
            || self.runtime.loader.version != NEOFORGE_VERSION
            || self.runtime.loader.installer_url != NEOFORGE_INSTALLER_URL
            || self.runtime.loader.installer_sha256 != NEOFORGE_INSTALLER_SHA256
            || java.major != JAVA_MAJOR
            || java.architecture != "x64"
            || java.distribution != JAVA_DISTRIBUTION
            || java.image_type != JAVA_IMAGE_TYPE
            || java.vm != JAVA_VM
            || !valid_java25_version(&java.version)
            || java.archive.size == 0
            || !is_sha256(&java.archive.sha256)
            || !is_sha256(&java.runtime_lock_sha256)
            || game.platform != "windows-x64"
            || !is_sha256(&game.runtime_lock_sha256)
        {
            return Err("Release runtime identity is invalid or unsupported".into());
        }
        validate_manifest_path(&java.runtime_target)?;
        if java.runtime_target != format!("runtime-windows-x64-{}.json", java.runtime_lock_sha256) {
            return Err("Runtime target is not bound to its signed SHA-256".into());
        }
        validate_manifest_path(&game.runtime_target)?;
        if game.runtime_target
            != format!("game-runtime-windows-x64-{}.json", game.runtime_lock_sha256)
        {
            return Err("Game runtime target is not bound to its signed SHA-256".into());
        }
        Ok(())
    }

    fn validate_integrity(&self) -> Result<(), String> {
        let integrity = &self.integrity;
        if integrity.unknown_policy != "delete"
            || integrity.strict_roots.is_empty()
            || integrity.locked_paths.is_empty()
            || integrity.preset_override_paths.is_empty()
            || integrity.mutable_settings.len() > 128
        {
            return Err("Release integrity policy is incomplete".into());
        }
        for paths in [
            &integrity.strict_roots,
            &integrity.preserved_paths,
            &integrity.locked_paths,
            &integrity.preset_override_paths,
        ] {
            validate_path_list(paths)?;
        }
        for required in REQUIRED_STRICT_ROOTS {
            if !integrity.strict_roots.iter().any(|root| root == required) {
                return Err(format!("Required strict root is missing: {required}"));
            }
        }
        if !integrity
            .locked_paths
            .iter()
            .any(|path| path == REQUIRED_LAUNCH_GUARD)
        {
            return Err("Required Fragment launch guard is not locked".into());
        }
        for strict in &integrity.strict_roots {
            if integrity
                .preserved_paths
                .iter()
                .any(|preserved| paths_overlap(strict, preserved))
            {
                return Err(format!("Strict and preserved paths overlap: {strict}"));
            }
        }
        for locked in &integrity.locked_paths {
            if !is_within_any(locked, &integrity.strict_roots) {
                return Err(format!("Locked path is outside strict roots: {locked}"));
            }
            if integrity
                .mutable_settings
                .iter()
                .any(|settings| paths_overlap(locked, &settings.path))
            {
                return Err(format!("Locked path overlaps mutable settings: {locked}"));
            }
        }
        for override_path in &integrity.preset_override_paths {
            if !is_within_any(override_path, &integrity.strict_roots)
                || integrity
                    .locked_paths
                    .iter()
                    .any(|locked| paths_overlap(override_path, locked))
            {
                return Err(format!("Unsafe preset override path: {override_path}"));
            }
        }

        let mut mutable_paths = HashSet::new();
        let mut setting_ids = HashSet::new();
        for settings in &integrity.mutable_settings {
            settings.validate()?;
            let path = path_key(&settings.path);
            if !mutable_paths.insert(path.clone())
                || integrity
                    .preserved_paths
                    .iter()
                    .any(|preserved| paths_overlap(&path, preserved))
            {
                return Err(format!(
                    "Unsafe or duplicate mutable path: {}",
                    settings.path
                ));
            }
            for existing in &mutable_paths {
                if existing != &path && paths_overlap(existing, &path) {
                    return Err(format!("Mutable paths overlap: {}", settings.path));
                }
            }
            for field in &settings.fields {
                for identity in std::iter::once(&field.setting_id).chain(&field.renamed_from) {
                    if !valid_setting_id(identity) || !setting_ids.insert(identity.clone()) {
                        return Err(format!("Duplicate mutable setting identity: {identity}"));
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_presets(&self) -> Result<(), String> {
        if self.presets.len() != 3 {
            return Err("Release must contain exactly three presets".into());
        }
        let mut ids = HashSet::new();
        for preset in &self.presets {
            if !ids.insert(preset.id)
                || !safe_text(&preset.display_name, 1, 100, false)
                || preset.jvm.min_memory_mi_b < 1024
                || preset.jvm.max_memory_mi_b < 2048
                || preset.jvm.max_memory_mi_b < preset.jvm.min_memory_mi_b
                || preset.jvm.extra_arguments.len() > 64
                || preset.files.len() > MAX_FILES_PER_PRESET
            {
                return Err(format!("Preset {} is invalid", preset.id.as_str()));
            }
            for argument in &preset.jvm.extra_arguments {
                if argument.is_empty()
                    || argument.len() > 1024
                    || argument.chars().any(char::is_control)
                    || forbidden_jvm_argument(argument)
                {
                    return Err(format!("Forbidden preset JVM argument: {argument}"));
                }
            }
            validate_file_list(&preset.files)?;
        }
        if ![PresetId::Low, PresetId::Medium, PresetId::High]
            .into_iter()
            .all(|id| ids.contains(&id))
        {
            return Err("low, medium and high must each occur exactly once".into());
        }
        Ok(())
    }

    fn validate_cross_fields(&self) -> Result<(), String> {
        let preset_files: Vec<HashMap<String, &ManifestFile>> = self
            .presets
            .iter()
            .map(|preset| {
                preset
                    .files
                    .iter()
                    .map(|file| (path_key(&file.path), file))
                    .collect()
            })
            .collect();
        let mutable_paths: HashSet<String> = self
            .integrity
            .mutable_settings
            .iter()
            .map(|settings| path_key(&settings.path))
            .collect();

        for locked in &self.integrity.locked_paths {
            let key = path_key(locked);
            let files: Vec<_> = preset_files.iter().map(|preset| preset.get(&key)).collect();
            if files.iter().any(|file| file.is_none()) {
                return Err(format!("Locked path is missing: {locked}"));
            }
            let first = files[0].expect("checked above");
            if files.iter().flatten().any(|file| {
                file.sha256 != first.sha256
                    || file.size != first.size
                    || file.executable != first.executable
                    || file.policy != FilePolicy::Exact
            }) {
                return Err(format!("Locked path differs or is mutable: {locked}"));
            }
        }

        let all_paths: HashSet<_> = preset_files
            .iter()
            .flat_map(|preset| preset.keys().cloned())
            .collect();
        for path in all_paths {
            if self
                .integrity
                .preserved_paths
                .iter()
                .any(|preserved| paths_overlap(&path, preserved))
            {
                return Err(format!("Managed file overlaps preserved data: {path}"));
            }
            let expected_policy = if mutable_paths.contains(&path) {
                FilePolicy::ValidatedMutable
            } else {
                FilePolicy::Exact
            };
            let files: Vec<_> = preset_files
                .iter()
                .map(|preset| preset.get(&path))
                .collect();
            if files
                .iter()
                .flatten()
                .any(|file| file.policy != expected_policy)
            {
                return Err(format!(
                    "Manifest file policy does not match integrity rules: {path}"
                ));
            }
            let may_differ = self
                .integrity
                .preset_override_paths
                .iter()
                .any(|override_path| is_within(&path, override_path));
            if !may_differ {
                if files.iter().any(|file| file.is_none()) {
                    return Err(format!("Non-preset file is missing from a preset: {path}"));
                }
                let first = files[0].expect("checked above");
                if files.iter().flatten().any(|file| {
                    file.sha256 != first.sha256
                        || file.size != first.size
                        || file.executable != first.executable
                }) {
                    return Err(format!("Non-preset file differs between presets: {path}"));
                }
            }
        }
        for mutable_path in mutable_paths {
            if preset_files
                .iter()
                .any(|preset| !preset.contains_key(&mutable_path))
            {
                return Err(format!(
                    "Mutable settings default is missing from a preset: {mutable_path}"
                ));
            }
        }
        Ok(())
    }
}

fn validate_file_list(files: &[ManifestFile]) -> Result<(), String> {
    let mut seen = BTreeMap::new();
    for file in files {
        validate_manifest_path(&file.path)?;
        if !is_sha256(&file.sha256) {
            return Err(format!(
                "Manifest file has an invalid SHA-256: {}",
                file.path
            ));
        }
        let key = path_key(&file.path);
        if seen.insert(key.clone(), file.path.clone()).is_some() {
            return Err(format!("Duplicate manifest path: {}", file.path));
        }
        let segments: Vec<_> = key.split('/').collect();
        for index in 1..segments.len() {
            if seen.contains_key(&segments[..index].join("/")) {
                return Err(format!("Manifest file/directory collision: {}", file.path));
            }
        }
    }
    for key in seen.keys() {
        let segments: Vec<_> = key.split('/').collect();
        for index in 1..segments.len() {
            if seen.contains_key(&segments[..index].join("/")) {
                return Err(format!("Manifest file/directory collision: {key}"));
            }
        }
    }
    Ok(())
}

fn validate_path_list(paths: &[String]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for path in paths {
        validate_manifest_path(path)?;
        if !seen.insert(path_key(path)) {
            return Err(format!("Duplicate integrity path: {path}"));
        }
    }
    Ok(())
}

fn valid_project_id(value: &str) -> bool {
    (2..=64).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_release_id(value: &str) -> bool {
    value.len() == 28
        && value.starts_with("rel_")
        && value[4..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn safe_text(value: &str, minimum: usize, maximum: usize, trim: bool) -> bool {
    let length = value.chars().count();
    value.nfc().collect::<String>() == value
        && (minimum..=maximum).contains(&length)
        && !value.chars().any(char::is_control)
        && (!trim || value.trim() == value)
}

fn path_key(path: &str) -> String {
    path.to_lowercase()
}

fn paths_overlap(left: &str, right: &str) -> bool {
    let left = path_key(left);
    let right = path_key(right);
    left == right
        || left.starts_with(&format!("{right}/"))
        || right.starts_with(&format!("{left}/"))
}

fn is_within(path: &str, root: &str) -> bool {
    let path = path_key(path);
    let root = path_key(root);
    path == root || path.starts_with(&format!("{root}/"))
}

fn is_within_any(path: &str, roots: &[String]) -> bool {
    roots.iter().any(|root| is_within(path, root))
}

fn forbidden_jvm_argument(argument: &str) -> bool {
    let normalized = argument.trim().to_lowercase();
    normalized.starts_with('@')
        || normalized.starts_with("-javaagent")
        || normalized.starts_with("-agentlib")
        || normalized.starts_with("-agentpath")
        || normalized.starts_with("-xbootclasspath")
        || normalized == "-cp"
        || normalized == "-classpath"
        || normalized.starts_with("--class-path")
        || normalized.starts_with("-djava.system.class.loader")
        || normalized.starts_with("-djdk.attach.allowattachself")
        || normalized.starts_with("-dloader.path")
}

fn is_https_url(value: &str) -> bool {
    Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.fragment().is_none()
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn manifest() -> serde_json::Value {
        let exact_file = serde_json::json!({
            "path": "mods/fragment-launch-guard.jar",
            "size": 4,
            "sha256": "a".repeat(64),
            "executable": false,
            "policy": "exact"
        });
        let options = serde_json::json!({
            "path": "options.txt",
            "size": 22,
            "sha256": "b".repeat(64),
            "executable": false,
            "policy": "validated-mutable"
        });
        let preset = |id: &str| {
            serde_json::json!({
                "id": id,
                "displayName": id,
                "jvm": { "minMemoryMiB": 2048, "maxMemoryMiB": 4096, "extraArguments": [] },
                "files": [exact_file.clone(), options.clone()]
            })
        };
        let runtime_hash = "c".repeat(64);
        serde_json::json!({
            "schemaVersion": 1,
            "project": { "id": "fragment", "displayName": "Fragment" },
            "release": {
                "id": "rel_aaaaaaaaaaaaaaaaaaaaaaaa",
                "version": "1.0.0",
                "createdAt": "2026-07-11T00:00:00Z",
                "minimumLauncherVersion": "1.0.0"
            },
            "runtime": {
                "minecraft": "1.21.1",
                "loader": {
                    "kind": "neoforge",
                    "version": "21.1.235",
                    "installerUrl": NEOFORGE_INSTALLER_URL,
                    "installerSha256": NEOFORGE_INSTALLER_SHA256
                },
                "java": {
                    "major": 25,
                    "architecture": "x64",
                    "distribution": "eclipse-temurin",
                    "imageType": "jre",
                    "vm": "hotspot",
                    "version": "25.0.3+9",
                    "runtimeTarget": format!("runtime-windows-x64-{runtime_hash}.json"),
                    "runtimeLockSha256": runtime_hash,
                    "archive": { "size": 123, "sha256": "d".repeat(64) }
                },
                "game": {
                    "platform": "windows-x64",
                    "runtimeTarget": format!("game-runtime-windows-x64-{runtime_hash}.json"),
                    "runtimeLockSha256": runtime_hash
                }
            },
            "integrity": {
                "unknownPolicy": "delete",
                "strictRoots": ["mods", "resourcepacks", "shaderpacks", "config"],
                "preservedPaths": ["saves", "screenshots", "logs"],
                "lockedPaths": ["mods/fragment-launch-guard.jar"],
                "presetOverridePaths": ["config/graphics.toml"],
                "mutableSettings": [{
                    "path": "options.txt",
                    "validator": "minecraft-options-v1",
                    "maxBytes": 4096,
                    "unknownKeyPolicy": "drop",
                    "duplicateKeyPolicy": "reject",
                    "invalidValuePolicy": "use-default",
                    "fields": [{
                        "settingId": "minecraft.video.render-distance",
                        "scope": "preset",
                        "selector": { "kind": "exact", "key": "renderDistance" },
                        "value": { "type": "integer", "minimum": 2, "maximum": 32 },
                        "renamedFrom": []
                    }]
                }]
            },
            "presets": [preset("low"), preset("medium"), preset("high")]
        })
    }

    #[test]
    fn accepts_a_complete_signed_release_contract() {
        let bytes = serde_json::to_vec(&manifest()).expect("fixture must serialize");
        let release = ReleaseManifest::parse_and_validate(&bytes).expect("manifest must validate");
        assert_eq!(
            release.selected_preset(PresetId::High).unwrap().id,
            PresetId::High
        );
    }

    #[test]
    fn rejects_case_folded_integrity_bypasses_and_mutable_mods() {
        let mut strict_preserved = manifest();
        strict_preserved["integrity"]["preservedPaths"] = serde_json::json!(["Config/custom"]);
        assert!(ReleaseManifest::parse_and_validate(
            &serde_json::to_vec(&strict_preserved).unwrap()
        )
        .is_err());

        let mut mutable_guard = manifest();
        mutable_guard["integrity"]["mutableSettings"][0]["path"] =
            serde_json::json!("MODS/fragment-launch-guard.jar");
        assert!(
            ReleaseManifest::parse_and_validate(&serde_json::to_vec(&mutable_guard).unwrap())
                .is_err()
        );
    }

    #[test]
    fn accepts_unknown_optional_fields_and_rejects_runtime_target_mismatch() {
        let mut unknown = manifest();
        unknown["futureTopLevel"] = serde_json::json!({ "enabled": true });
        unknown["project"]["tagline"] = serde_json::json!("future optional project metadata");
        unknown["release"]["fallbackUrl"] = serde_json::json!("https://evil.invalid");
        unknown["runtime"]["loader"]["mirrorUrls"] = serde_json::json!([]);
        unknown["runtime"]["java"]["vendorHint"] = serde_json::json!("future vendor metadata");
        unknown["runtime"]["java"]["archive"]["format"] = serde_json::json!("zip");
        unknown["runtime"]["game"]["publisherHint"] = serde_json::json!("future metadata");
        unknown["integrity"]["repairPolicy"] = serde_json::json!("future-policy");
        unknown["integrity"]["mutableSettings"][0]["futureValidatorOption"] =
            serde_json::json!(true);
        unknown["integrity"]["mutableSettings"][0]["fields"][0]["description"] =
            serde_json::json!("future field metadata");
        unknown["integrity"]["mutableSettings"][0]["fields"][0]["selector"]["caseSensitive"] =
            serde_json::json!(true);
        unknown["integrity"]["mutableSettings"][0]["fields"][0]["value"]["step"] =
            serde_json::json!(1);
        unknown["presets"][0]["icon"] = serde_json::json!("low");
        unknown["presets"][0]["jvm"]["gcPolicy"] = serde_json::json!("future-default");
        unknown["presets"][0]["files"][0]["downloadHint"] = serde_json::json!("future-hint");
        assert!(
            ReleaseManifest::parse_and_validate(&serde_json::to_vec(&unknown).unwrap()).is_ok()
        );

        let mut mismatch = manifest();
        mismatch["runtime"]["java"]["runtimeLockSha256"] = serde_json::json!("e".repeat(64));
        assert!(
            ReleaseManifest::parse_and_validate(&serde_json::to_vec(&mismatch).unwrap()).is_err()
        );

        let mut game_mismatch = manifest();
        game_mismatch["runtime"]["game"]["runtimeLockSha256"] = serde_json::json!("e".repeat(64));
        assert!(
            ReleaseManifest::parse_and_validate(&serde_json::to_vec(&game_mismatch).unwrap())
                .is_err()
        );
    }

    #[test]
    fn rejects_unknown_schema_enum_and_discriminator_values() {
        let mut unknown_schema = manifest();
        unknown_schema["schemaVersion"] = serde_json::json!(2);
        assert!(
            ReleaseManifest::parse_and_validate(&serde_json::to_vec(&unknown_schema).unwrap())
                .is_err()
        );

        let mut unknown_preset = manifest();
        unknown_preset["presets"][0]["id"] = serde_json::json!("ultra");
        assert!(
            ReleaseManifest::parse_and_validate(&serde_json::to_vec(&unknown_preset).unwrap())
                .is_err()
        );

        let mut unknown_policy = manifest();
        unknown_policy["presets"][0]["files"][0]["policy"] = serde_json::json!("generated");
        assert!(
            ReleaseManifest::parse_and_validate(&serde_json::to_vec(&unknown_policy).unwrap())
                .is_err()
        );

        let mut unknown_validator = manifest();
        unknown_validator["integrity"]["mutableSettings"][0]["validator"] =
            serde_json::json!("future-validator-v2");
        assert!(ReleaseManifest::parse_and_validate(
            &serde_json::to_vec(&unknown_validator).unwrap()
        )
        .is_err());

        let mut unknown_selector = manifest();
        unknown_selector["integrity"]["mutableSettings"][0]["fields"][0]["selector"]["kind"] =
            serde_json::json!("glob");
        assert!(ReleaseManifest::parse_and_validate(
            &serde_json::to_vec(&unknown_selector).unwrap()
        )
        .is_err());

        let mut unknown_value_rule = manifest();
        unknown_value_rule["integrity"]["mutableSettings"][0]["fields"][0]["value"]["type"] =
            serde_json::json!("vector");
        assert!(ReleaseManifest::parse_and_validate(
            &serde_json::to_vec(&unknown_value_rule).unwrap()
        )
        .is_err());
    }

    #[test]
    fn current_pointer_is_bound_to_channel_release_and_target() {
        let mut current = serde_json::json!({
            "schemaVersion": 1,
            "channel": "dev",
            "releaseId": "rel_aaaaaaaaaaaaaaaaaaaaaaaa",
            "manifestTarget": "release-rel_aaaaaaaaaaaaaaaaaaaaaaaa.json"
        });
        current["futureOptionalField"] = serde_json::json!(true);
        let bytes = serde_json::to_vec(&current).unwrap();
        assert!(CurrentPointer::parse_and_validate(&bytes, BuildChannel::Dev).is_ok());
        assert!(CurrentPointer::parse_and_validate(&bytes, BuildChannel::Stable).is_err());

        current["schemaVersion"] = serde_json::json!(2);
        let bytes = serde_json::to_vec(&current).unwrap();
        assert!(CurrentPointer::parse_and_validate(&bytes, BuildChannel::Dev).is_err());

        current["schemaVersion"] = serde_json::json!(1);
        current["channel"] = serde_json::json!("canary");
        let bytes = serde_json::to_vec(&current).unwrap();
        assert!(CurrentPointer::parse_and_validate(&bytes, BuildChannel::Dev).is_err());
    }

    #[test]
    fn validates_https_urls_without_credentials() {
        assert!(is_https_url("https://fragmc.ru/api/spark2/"));
        assert!(!is_https_url("http://fragmc.ru/api/spark2/"));
        assert!(!is_https_url("https://user:pass@fragmc.ru/api/spark2/"));
    }
}
