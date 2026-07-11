use serde::Deserialize;
use std::collections::HashSet;
use unicode_normalization::UnicodeNormalization;

pub const JAVA_MAJOR: u8 = 25;
pub const JAVA_DISTRIBUTION: &str = "eclipse-temurin";
pub const JAVA_IMAGE_TYPE: &str = "jre";
pub const JAVA_VM: &str = "hotspot";

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeLock {
    pub schema_version: u8,
    pub id: String,
    pub platform: String,
    pub java: RuntimeJava,
    pub minecraft: RuntimeMinecraft,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeJava {
    pub major: u8,
    pub architecture: String,
    pub distribution: String,
    pub image_type: String,
    pub vm: String,
    pub version: String,
    pub vendor: String,
    pub license: RuntimeLicense,
    pub archive: RuntimeArchive,
    pub executable: String,
    pub console_executable: String,
    pub files: Vec<RuntimeFile>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeLicense {
    pub spdx: String,
    pub url: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeArchive {
    pub url: String,
    pub checksum_url: String,
    pub signature_url: String,
    pub signing_key_fingerprint: String,
    pub size: u64,
    pub sha256: String,
    pub format: String,
    pub strip_prefix: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeMinecraft {
    pub version: String,
    pub version_manifest_url: String,
    pub version_json_url: String,
    pub version_json_sha1: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutableSettingsFile {
    pub path: String,
    pub validator: MutableValidator,
    pub max_bytes: usize,
    pub unknown_key_policy: String,
    pub duplicate_key_policy: String,
    pub invalid_value_policy: String,
    pub fields: Vec<MutableSettingField>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub enum MutableValidator {
    #[serde(rename = "minecraft-options-v1")]
    MinecraftOptionsV1,
    #[serde(rename = "structured-properties-v1")]
    StructuredPropertiesV1,
    #[serde(rename = "structured-json-v1")]
    StructuredJsonV1,
    #[serde(rename = "structured-toml-v1")]
    StructuredTomlV1,
    #[serde(rename = "shader-options-v1")]
    ShaderOptionsV1,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutableSettingField {
    pub setting_id: String,
    pub scope: SettingScope,
    pub selector: SettingSelector,
    pub value: SettingValueRule,
    #[serde(default)]
    pub renamed_from: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SettingScope {
    Profile,
    Preset,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum SettingSelector {
    Exact { key: String },
    Prefix { prefix: String },
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "lowercase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum SettingValueRule {
    Boolean,
    Integer {
        minimum: i64,
        maximum: i64,
    },
    Number {
        minimum: f64,
        maximum: f64,
    },
    String {
        max_length: usize,
        #[serde(default)]
        allowed_values: Option<Vec<String>>,
        #[serde(default)]
        allowed_prefixes: Option<Vec<String>>,
    },
}

impl RuntimeLock {
    pub fn parse_and_validate(bytes: &[u8]) -> Result<Self, String> {
        let lock: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("Runtime lock JSON is invalid: {error}"))?;
        lock.validate()?;
        Ok(lock)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || self.platform != "windows-x64"
            || self.java.major != JAVA_MAJOR
            || self.java.architecture != "x64"
            || self.java.distribution != JAVA_DISTRIBUTION
            || self.java.image_type != JAVA_IMAGE_TYPE
            || self.java.vm != JAVA_VM
            || !self.java.version.starts_with("25.")
        {
            return Err("Unsupported managed Java runtime identity".into());
        }
        if !valid_java25_version(&self.java.version)
            || self.id != format!("temurin-jre-{}-windows-x64-hotspot", self.java.version)
        {
            return Err("Managed Java version identity is invalid".into());
        }
        if self.java.vendor != "Eclipse Temurin"
            || self.java.license.spdx != "GPL-2.0-only WITH Classpath-exception-2.0"
            || self.java.license.url != "https://openjdk.org/legal/gplv2+ce.html"
            || self.java.archive.format != "zip"
            || self.java.archive.signing_key_fingerprint
                != "3B04D753C9050D9A5D343F39843C48A565F8F04B"
            || !self
                .java
                .archive
                .url
                .starts_with("https://github.com/adoptium/temurin25-binaries/releases/download/")
            || !self
                .java
                .archive
                .checksum_url
                .starts_with("https://github.com/adoptium/temurin25-binaries/releases/download/")
            || !self.java.archive.checksum_url.ends_with(".sha256.txt")
            || !self
                .java
                .archive
                .signature_url
                .starts_with("https://github.com/adoptium/temurin25-binaries/releases/download/")
            || !self.java.archive.signature_url.ends_with(".sig")
            || !is_sha256(&self.java.archive.sha256)
            || self.java.archive.size == 0
        {
            return Err("Managed Java archive identity is invalid".into());
        }
        validate_manifest_path(&self.java.archive.strip_prefix)?;
        validate_manifest_path(&self.java.executable)?;
        validate_manifest_path(&self.java.console_executable)?;

        let mut paths = HashSet::new();
        for file in &self.java.files {
            validate_manifest_path(&file.path)?;
            if !is_sha256(&file.sha256) {
                return Err(format!("Invalid runtime file SHA-256: {}", file.path));
            }
            let key = file.path.to_lowercase();
            if !paths.insert(key) {
                return Err(format!("Duplicate runtime path: {}", file.path));
            }
        }
        for path in &paths {
            let segments: Vec<_> = path.split('/').collect();
            for index in 1..segments.len() {
                if paths.contains(&segments[..index].join("/")) {
                    return Err(format!("Runtime file/directory collision: {path}"));
                }
            }
        }
        for executable in [&self.java.executable, &self.java.console_executable] {
            if !self
                .java
                .files
                .iter()
                .any(|file| file.path.eq_ignore_ascii_case(executable))
            {
                return Err(format!("Runtime entrypoint is missing: {executable}"));
            }
        }
        if self.minecraft.version != "1.21.1"
            || !self
                .minecraft
                .version_manifest_url
                .starts_with("https://piston-meta.mojang.com/")
            || !self
                .minecraft
                .version_json_url
                .starts_with("https://piston-meta.mojang.com/")
            || !is_lower_hex(&self.minecraft.version_json_sha1, 40)
        {
            return Err("Minecraft runtime identity is invalid".into());
        }
        Ok(())
    }
}

impl MutableSettingsFile {
    pub fn validate(&self) -> Result<(), String> {
        validate_manifest_path(&self.path)?;
        let lower = self.path.to_lowercase();
        if lower == "mods"
            || lower.starts_with("mods/")
            || lower == "resourcepacks"
            || lower.starts_with("resourcepacks/")
        {
            return Err("Mutable settings are forbidden under mods/resourcepacks".into());
        }
        if self.max_bytes < 64 || self.max_bytes > 1024 * 1024 {
            return Err("Mutable settings maxBytes is invalid".into());
        }
        if self.unknown_key_policy != "drop"
            || self.duplicate_key_policy != "reject"
            || self.invalid_value_policy != "use-default"
        {
            return Err("Unsupported mutable settings behavior".into());
        }
        if self.validator != MutableValidator::MinecraftOptionsV1 {
            return Err("Mutable validator is not implemented by this launcher".into());
        }
        if !self.path.eq_ignore_ascii_case("options.txt") {
            return Err("minecraft-options-v1 is valid only for options.txt".into());
        }
        if self.fields.is_empty() || self.fields.len() > 512 {
            return Err("Mutable settings field count is invalid".into());
        }

        let mut identities = HashSet::new();
        for field in &self.fields {
            if !valid_setting_id(&field.setting_id) || !identities.insert(&field.setting_id) {
                return Err(format!(
                    "Duplicate or invalid settingId: {}",
                    field.setting_id
                ));
            }
            for old_id in &field.renamed_from {
                if !valid_setting_id(old_id) || !identities.insert(old_id) {
                    return Err(format!("Duplicate or invalid renamed settingId: {old_id}"));
                }
            }
            if field.renamed_from.len() > 16 {
                return Err("Too many renamed mutable setting IDs".into());
            }
            match &field.selector {
                SettingSelector::Exact { key } if !valid_setting_string(key, 256, true) => {
                    return Err("Invalid exact mutable setting selector".into());
                }
                SettingSelector::Prefix { prefix } if !valid_setting_string(prefix, 256, true) => {
                    return Err("Invalid prefix mutable setting selector".into());
                }
                _ => {}
            }
            validate_rule(&field.value)?;
        }
        for left in 0..self.fields.len() {
            for right in left + 1..self.fields.len() {
                if selectors_overlap(&self.fields[left].selector, &self.fields[right].selector) {
                    return Err("Mutable setting selectors overlap".into());
                }
            }
        }
        Ok(())
    }
}

pub fn validate_manifest_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.contains('\\')
        || path.starts_with('/')
        || path == "."
        || path.starts_with("../")
        || path.contains("/../")
        || path.nfc().collect::<String>() != path
    {
        return Err(format!("Unsafe manifest path: {path}"));
    }
    for segment in path.split('/') {
        let lower = segment.to_ascii_lowercase();
        if segment.is_empty()
            || segment == "."
            || segment == ".."
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || segment
                .chars()
                .any(|value| value.is_control() || "<>:\"|?*".contains(value))
            || is_reserved_windows_name(&lower)
        {
            return Err(format!("Unsafe manifest path: {path}"));
        }
    }
    Ok(())
}

fn is_reserved_windows_name(segment: &str) -> bool {
    let stem = segment.split('.').next().unwrap_or(segment);
    matches!(stem, "con" | "prn" | "aux" | "nul")
        || (stem.len() == 4
            && (stem.starts_with("com") || stem.starts_with("lpt"))
            && matches!(stem.as_bytes()[3], b'1'..=b'9'))
}

fn is_sha256(value: &str) -> bool {
    is_lower_hex(value, 64)
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_java25_version(value: &str) -> bool {
    let Some((feature, build)) = value.split_once('+') else {
        return false;
    };
    let mut parts = feature.split('.');
    parts.next() == Some("25")
        && parts.next().is_some_and(numeric_component)
        && parts.next().is_some_and(numeric_component)
        && parts.next().is_none()
        && numeric_component(build)
}

fn numeric_component(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn valid_setting_id(value: &str) -> bool {
    (3..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"._-".contains(&byte)
        })
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn validate_rule(rule: &SettingValueRule) -> Result<(), String> {
    match rule {
        SettingValueRule::Integer { minimum, maximum } if maximum < minimum => {
            Err("Integer setting range is invalid".into())
        }
        SettingValueRule::Number { minimum, maximum }
            if !minimum.is_finite() || !maximum.is_finite() || maximum < minimum =>
        {
            Err("Number setting range is invalid".into())
        }
        SettingValueRule::String {
            max_length,
            allowed_values,
            allowed_prefixes,
        } => {
            if !(1..=4096).contains(max_length) {
                return Err("String setting maxLength is invalid".into());
            }
            if allowed_values.is_none() && allowed_prefixes.is_none() {
                return Err("String settings require an allowlist".into());
            }
            if allowed_values
                .as_ref()
                .is_some_and(|values| values.len() > 512)
                || allowed_prefixes
                    .as_ref()
                    .is_some_and(|values| values.len() > 64)
            {
                return Err("String setting allowlist is too large".into());
            }
            for values in [allowed_values.as_ref(), allowed_prefixes.as_ref()]
                .into_iter()
                .flatten()
            {
                let unique: HashSet<_> = values.iter().collect();
                if unique.len() != values.len() {
                    return Err("String setting allowlist contains duplicates".into());
                }
                if values.is_empty()
                    || values
                        .iter()
                        .any(|value| !valid_setting_string(value, 4096, false))
                {
                    return Err("String setting allowlist contains an invalid value".into());
                }
            }
            if allowed_prefixes.as_ref().is_some_and(|values| {
                values
                    .iter()
                    .any(|value| value.is_empty() || value.chars().count() > 256)
            }) {
                return Err("String setting prefix is too long".into());
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn valid_setting_string(value: &str, max_length: usize, trim: bool) -> bool {
    !value.is_empty()
        && value.nfc().collect::<String>() == value
        && value.chars().count() <= max_length
        && !value.chars().any(char::is_control)
        && (!trim || value.trim() == value)
}

fn selectors_overlap(left: &SettingSelector, right: &SettingSelector) -> bool {
    match (left, right) {
        (SettingSelector::Exact { key: left }, SettingSelector::Exact { key: right }) => {
            left == right
        }
        (SettingSelector::Prefix { prefix: left }, SettingSelector::Prefix { prefix: right }) => {
            left.starts_with(right) || right.starts_with(left)
        }
        (SettingSelector::Prefix { prefix }, SettingSelector::Exact { key })
        | (SettingSelector::Exact { key }, SettingSelector::Prefix { prefix }) => {
            key.starts_with(prefix)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime_lock() -> serde_json::Value {
        serde_json::json!({
            "schemaVersion": 1,
            "id": "temurin-jre-25.0.3+9-windows-x64-hotspot",
            "platform": "windows-x64",
            "java": {
                "major": 25,
                "architecture": "x64",
                "distribution": "eclipse-temurin",
                "imageType": "jre",
                "vm": "hotspot",
                "version": "25.0.3+9",
                "vendor": "Eclipse Temurin",
                "license": {
                    "spdx": "GPL-2.0-only WITH Classpath-exception-2.0",
                    "url": "https://openjdk.org/legal/gplv2+ce.html"
                },
                "archive": {
                    "url": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/runtime.zip",
                    "checksumUrl": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/runtime.zip.sha256.txt",
                    "signatureUrl": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.3%2B9/runtime.zip.sig",
                    "signingKeyFingerprint": "3B04D753C9050D9A5D343F39843C48A565F8F04B",
                    "size": 123,
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "format": "zip",
                    "stripPrefix": "jdk-25.0.3+9-jre"
                },
                "executable": "bin/javaw.exe",
                "consoleExecutable": "bin/java.exe",
                "files": [
                    {
                        "path": "bin/java.exe",
                        "size": 1,
                        "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    },
                    {
                        "path": "bin/javaw.exe",
                        "size": 1,
                        "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
                    }
                ]
            },
            "minecraft": {
                "version": "1.21.1",
                "versionManifestUrl": "https://piston-meta.mojang.com/mc/game/version_manifest_v2.json",
                "versionJsonUrl": "https://piston-meta.mojang.com/1.21.1.json",
                "versionJsonSha1": "8344022e055c6c052047107a80e33d96c48e9fba"
            }
        })
    }

    #[test]
    fn accepts_the_pinned_java_25_identity() {
        let bytes = serde_json::to_vec(&runtime_lock()).expect("fixture must serialize");
        let lock = RuntimeLock::parse_and_validate(&bytes).expect("runtime lock must validate");
        assert_eq!(lock.java.major, 25);
        assert_eq!(lock.java.image_type, "jre");
    }

    #[test]
    fn rejects_java_21_and_case_colliding_runtime_files() {
        let mut old_java = runtime_lock();
        old_java["java"]["major"] = serde_json::json!(21);
        let bytes = serde_json::to_vec(&old_java).expect("fixture must serialize");
        assert!(RuntimeLock::parse_and_validate(&bytes).is_err());

        let mut collision = runtime_lock();
        let duplicate = collision["java"]["files"][0].clone();
        collision["java"]["files"]
            .as_array_mut()
            .expect("files must be an array")
            .push(duplicate);
        let bytes = serde_json::to_vec(&collision).expect("fixture must serialize");
        assert!(RuntimeLock::parse_and_validate(&bytes).is_err());
    }

    #[test]
    fn rejects_unknown_security_fields() {
        let mut lock = runtime_lock();
        lock["java"]["archive"]["fallbackUrl"] = serde_json::json!("https://evil.invalid");
        let bytes = serde_json::to_vec(&lock).expect("fixture must serialize");
        assert!(RuntimeLock::parse_and_validate(&bytes).is_err());
    }
}
