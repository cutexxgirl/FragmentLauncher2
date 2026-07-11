use super::contracts::{
    valid_setting_string, MutableSettingField, MutableSettingsFile, MutableValidator, SettingScope,
    SettingSelector, SettingValueRule,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SanitizedSettings {
    pub bytes: Vec<u8>,
    pub dropped_keys: Vec<String>,
    pub reset_keys: Vec<String>,
}

type SettingValues = BTreeMap<String, String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MutableSettingsState {
    #[serde(deserialize_with = "deserialize_settings_state_version")]
    pub schema_version: u8,
    #[serde(default)]
    pub profile: BTreeMap<String, SettingValues>,
    #[serde(default)]
    pub presets: BTreeMap<String, BTreeMap<String, SettingValues>>,
}

impl Default for MutableSettingsState {
    fn default() -> Self {
        Self {
            schema_version: settings_state_version(),
            profile: BTreeMap::new(),
            presets: BTreeMap::new(),
        }
    }
}

impl MutableSettingsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn migrate(&mut self, policy: &MutableSettingsFile) -> Result<(), String> {
        policy.validate()?;
        if self.schema_version != settings_state_version() {
            return Err("Unsupported mutable settings state version".into());
        }
        for field in &policy.fields {
            migrate_bucket(&mut self.profile, field);
            for preset in self.presets.values_mut() {
                migrate_bucket(preset, field);
            }
        }
        Ok(())
    }
}

pub fn capture_minecraft_options_state(
    local: &[u8],
    policy: &MutableSettingsFile,
    preset: &str,
    state: &mut MutableSettingsState,
) -> Result<Vec<String>, String> {
    validate_preset_id(preset)?;
    policy.validate()?;
    state.migrate(policy)?;
    if local.len() > policy.max_bytes {
        return Err("Local mutable settings exceed maxBytes".into());
    }
    let parsed = parse_options(local, policy, false)?;
    let mut captured: BTreeMap<String, SettingValues> = BTreeMap::new();
    for (key, value) in parsed.values {
        let Some(field) = find_field(policy, &key) else {
            continue;
        };
        if validate_value(&value, &field.value) {
            captured
                .entry(field.setting_id.clone())
                .or_default()
                .insert(key, value);
        }
    }
    for field in &policy.fields {
        let target = match field.scope {
            SettingScope::Profile => &mut state.profile,
            SettingScope::Preset => state.presets.entry(preset.to_owned()).or_default(),
        };
        if let Some(values) = captured.remove(&field.setting_id) {
            target.insert(field.setting_id.clone(), values);
        } else {
            target.remove(&field.setting_id);
        }
    }
    Ok(parsed.dropped_keys)
}

pub fn materialize_minecraft_options_state(
    signed_default: &[u8],
    policy: &MutableSettingsFile,
    preset: &str,
    state: &mut MutableSettingsState,
) -> Result<Vec<u8>, String> {
    validate_preset_id(preset)?;
    policy.validate()?;
    state.migrate(policy)?;
    if signed_default.len() > policy.max_bytes {
        return Err("Signed mutable default exceeds maxBytes".into());
    }
    let defaults = parse_options(signed_default, policy, true)?;
    let mut output = defaults.values.clone();
    for field in &policy.fields {
        let values = match field.scope {
            SettingScope::Profile => state.profile.get(&field.setting_id),
            SettingScope::Preset => state
                .presets
                .get(preset)
                .and_then(|settings| settings.get(&field.setting_id)),
        };
        for (key, value) in values.into_iter().flatten() {
            if selector_matches(&field.selector, key) && validate_value(value, &field.value) {
                output.insert(key.clone(), value.clone());
            }
        }
    }
    serialize_options(output, &defaults.order, policy.max_bytes)
}

pub fn sanitize_minecraft_options(
    signed_default: &[u8],
    local: Option<&[u8]>,
    policy: &MutableSettingsFile,
    preset_changed: bool,
) -> Result<SanitizedSettings, String> {
    policy.validate()?;
    if policy.validator != MutableValidator::MinecraftOptionsV1 {
        return Err("Mutable validator is not implemented by this launcher".into());
    }
    if signed_default.len() > policy.max_bytes {
        return Err("Signed mutable default exceeds maxBytes".into());
    }
    let defaults = parse_options(signed_default, policy, true)?;
    let local_values = match local {
        Some(bytes) if bytes.len() <= policy.max_bytes => parse_options(bytes, policy, false)?,
        Some(_) => return Err("Local mutable settings exceed maxBytes".into()),
        None => ParsedOptions::default(),
    };

    let mut output = defaults.values.clone();
    let mut dropped_keys = local_values.dropped_keys;
    let mut reset_keys = Vec::new();
    for (key, value) in local_values.values {
        let Some(field) = find_field(policy, &key) else {
            dropped_keys.push(key);
            continue;
        };
        if preset_changed && field.scope == SettingScope::Preset {
            if defaults.values.contains_key(&key) {
                reset_keys.push(key);
            }
            continue;
        }
        if validate_value(&value, &field.value) {
            output.insert(key, value);
        } else {
            reset_keys.push(key);
        }
    }

    let bytes = serialize_options(output, &defaults.order, policy.max_bytes)?;

    dropped_keys.sort();
    dropped_keys.dedup();
    reset_keys.sort();
    reset_keys.dedup();
    Ok(SanitizedSettings {
        bytes,
        dropped_keys,
        reset_keys,
    })
}

#[derive(Default)]
struct ParsedOptions {
    values: BTreeMap<String, String>,
    order: Vec<String>,
    dropped_keys: Vec<String>,
}

fn parse_options(
    bytes: &[u8],
    policy: &MutableSettingsFile,
    strict_default: bool,
) -> Result<ParsedOptions, String> {
    if bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
        return Err("Mutable settings must not contain a UTF-8 BOM".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "Mutable settings are not valid UTF-8")?;
    let mut parsed = ParsedOptions::default();
    for (line_index, raw_line) in text.lines().enumerate() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if line.len() > 8192 {
            return Err(format!(
                "Mutable settings line {} is too long",
                line_index + 1
            ));
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| format!("Invalid mutable setting on line {}", line_index + 1))?;
        if !valid_setting_string(key, 256, true) {
            if strict_default {
                return Err(format!("Signed default contains an invalid key: {key}"));
            }
            parsed.dropped_keys.push(key.to_owned());
            continue;
        }
        if parsed.values.contains_key(key) {
            return Err(format!("Duplicate or empty mutable setting key: {key}"));
        }
        let Some(field) = find_field(policy, key) else {
            if strict_default {
                return Err(format!("Signed default contains unknown key: {key}"));
            }
            parsed.dropped_keys.push(key.to_owned());
            continue;
        };
        if strict_default && !validate_value(value, &field.value) {
            return Err(format!("Signed default contains invalid value: {key}"));
        }
        parsed.order.push(key.to_owned());
        parsed.values.insert(key.to_owned(), value.to_owned());
    }
    if strict_default {
        for field in &policy.fields {
            if let SettingSelector::Exact { key } = &field.selector {
                if !parsed.values.contains_key(key) {
                    return Err(format!("Signed default is missing required key: {key}"));
                }
            }
        }
    }
    Ok(parsed)
}

fn find_field<'a>(policy: &'a MutableSettingsFile, key: &str) -> Option<&'a MutableSettingField> {
    policy
        .fields
        .iter()
        .find(|field| selector_matches(&field.selector, key))
}

fn selector_matches(selector: &SettingSelector, key: &str) -> bool {
    match selector {
        SettingSelector::Exact { key: expected } => expected == key,
        SettingSelector::Prefix { prefix } => key.starts_with(prefix),
    }
}

fn validate_value(value: &str, rule: &SettingValueRule) -> bool {
    match rule {
        SettingValueRule::Boolean => matches!(value, "true" | "false"),
        SettingValueRule::Integer { minimum, maximum } => parse_canonical_integer(value)
            .is_some_and(|parsed| parsed >= *minimum && parsed <= *maximum),
        SettingValueRule::Number { minimum, maximum } => parse_canonical_number(value)
            .is_some_and(|parsed| parsed.is_finite() && parsed >= *minimum && parsed <= *maximum),
        SettingValueRule::String {
            max_length,
            allowed_values,
            allowed_prefixes,
        } => {
            valid_setting_string(value, *max_length, false)
                && allowed_values
                    .as_ref()
                    .is_none_or(|values| values.iter().any(|allowed| allowed == value))
                && allowed_prefixes
                    .as_ref()
                    .is_none_or(|prefixes| prefixes.iter().any(|prefix| value.starts_with(prefix)))
        }
    }
}

fn parse_canonical_integer(value: &str) -> Option<i64> {
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    value.parse::<i64>().ok()
}

fn parse_canonical_number(value: &str) -> Option<f64> {
    if !has_canonical_decimal_grammar(value) {
        return None;
    }
    value.parse::<f64>().ok()
}

fn has_canonical_decimal_grammar(value: &str) -> bool {
    let unsigned = value.strip_prefix('-').unwrap_or(value);
    if unsigned.is_empty() || unsigned.starts_with('+') {
        return false;
    }
    let mut exponent_split = unsigned.split(['e', 'E']);
    let mantissa = exponent_split.next().unwrap_or_default();
    let exponent = exponent_split.next();
    if exponent_split.next().is_some() {
        return false;
    }
    let mantissa_valid = if let Some((whole, fraction)) = mantissa.split_once('.') {
        (!whole.is_empty() || !fraction.is_empty())
            && whole.bytes().all(|byte| byte.is_ascii_digit())
            && fraction.bytes().all(|byte| byte.is_ascii_digit())
    } else {
        !mantissa.is_empty() && mantissa.bytes().all(|byte| byte.is_ascii_digit())
    };
    if !mantissa_valid {
        return false;
    }
    exponent.is_none_or(|value| {
        let digits = value
            .strip_prefix('+')
            .or_else(|| value.strip_prefix('-'))
            .unwrap_or(value);
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn serialize_options(
    mut values: BTreeMap<String, String>,
    default_order: &[String],
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut serialized = String::new();
    for key in default_order {
        if let Some(value) = values.remove(key) {
            serialized.push_str(key);
            serialized.push(':');
            serialized.push_str(&value);
            serialized.push('\n');
        }
    }
    for (key, value) in values {
        serialized.push_str(&key);
        serialized.push(':');
        serialized.push_str(&value);
        serialized.push('\n');
    }
    if serialized.len() > max_bytes {
        return Err("Sanitized mutable settings exceed maxBytes".into());
    }
    Ok(serialized.into_bytes())
}

fn migrate_bucket(bucket: &mut BTreeMap<String, SettingValues>, field: &MutableSettingField) {
    if bucket.contains_key(&field.setting_id) {
        return;
    }
    for old_id in &field.renamed_from {
        if let Some(values) = bucket.remove(old_id) {
            bucket.insert(field.setting_id.clone(), values);
            return;
        }
    }
}

fn validate_preset_id(preset: &str) -> Result<(), String> {
    if matches!(preset, "low" | "medium" | "high") {
        Ok(())
    } else {
        Err("Unknown settings preset".into())
    }
}

const fn settings_state_version() -> u8 {
    1
}

fn deserialize_settings_state_version<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u8::deserialize(deserializer)?;
    if version == settings_state_version() {
        Ok(version)
    } else {
        Err(serde::de::Error::custom(
            "Unsupported mutable settings state version",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
                    "value": {
                        "type": "string",
                        "maxLength": 128,
                        "allowedPrefixes": ["key.keyboard.", "key.mouse."]
                    },
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
        .expect("test policy must parse")
    }

    #[test]
    fn preserves_allowed_values_and_drops_unknown_keys() {
        let result = sanitize_minecraft_options(
            b"key_key.forward:key.keyboard.w\nrenderDistance:12\n",
            Some(b"key_key.forward:key.keyboard.up\nrenderDistance:20\ncheat:true\n"),
            &policy(),
            false,
        )
        .expect("settings must sanitize");

        assert_eq!(
            result.bytes,
            b"key_key.forward:key.keyboard.up\nrenderDistance:20\n"
        );
        assert_eq!(result.dropped_keys, vec!["cheat"]);
        assert!(result.reset_keys.is_empty());
    }

    #[test]
    fn preset_change_resets_quality_but_keeps_controls() {
        let result = sanitize_minecraft_options(
            b"key_key.forward:key.keyboard.w\nrenderDistance:8\n",
            Some(b"key_key.forward:key.keyboard.up\nrenderDistance:24\n"),
            &policy(),
            true,
        )
        .expect("settings must sanitize");

        assert_eq!(
            result.bytes,
            b"key_key.forward:key.keyboard.up\nrenderDistance:8\n"
        );
        assert_eq!(result.reset_keys, vec!["renderDistance"]);
    }

    #[test]
    fn rejects_duplicate_keys_and_oversized_files() {
        assert!(sanitize_minecraft_options(
            b"key_key.forward:key.keyboard.w\nrenderDistance:8\n",
            Some(b"renderDistance:8\nrenderDistance:9\n"),
            &policy(),
            false,
        )
        .is_err());

        let oversized = vec![b'x'; 4097];
        assert!(sanitize_minecraft_options(
            b"key_key.forward:key.keyboard.w\nrenderDistance:8\n",
            Some(&oversized),
            &policy(),
            false,
        )
        .is_err());
    }

    #[test]
    fn rejects_a_utf8_bom_for_signed_and_local_settings() {
        let default = b"key_key.forward:key.keyboard.w\nrenderDistance:8\n";
        let with_bom = b"\xef\xbb\xbfkey_key.forward:key.keyboard.w\nrenderDistance:8\n";
        assert!(sanitize_minecraft_options(with_bom, None, &policy(), false).is_err());
        assert!(sanitize_minecraft_options(default, Some(with_bom), &policy(), false).is_err());
    }

    #[test]
    fn uses_the_same_canonical_numeric_grammar_as_the_publisher() {
        assert_eq!(parse_canonical_integer("12"), Some(12));
        assert_eq!(parse_canonical_integer("-12"), Some(-12));
        assert_eq!(parse_canonical_integer("+12"), None);
        assert!(has_canonical_decimal_grammar("0.5"));
        assert!(has_canonical_decimal_grammar("1e-3"));
        assert!(!has_canonical_decimal_grammar("0x10"));
        assert!(!has_canonical_decimal_grammar("+0.5"));
        assert!(!has_canonical_decimal_grammar("NaN"));
        assert!(!valid_setting_string("", 256, true));
    }

    #[test]
    fn restores_profile_and_per_preset_values() {
        let policy = policy();
        let mut state = MutableSettingsState::new();
        capture_minecraft_options_state(
            b"key_key.forward:key.keyboard.w\nrenderDistance:20\n",
            &policy,
            "low",
            &mut state,
        )
        .expect("low state must capture");
        capture_minecraft_options_state(
            b"key_key.forward:key.keyboard.up\nrenderDistance:30\n",
            &policy,
            "high",
            &mut state,
        )
        .expect("high state must capture");

        let low = materialize_minecraft_options_state(
            b"key_key.forward:key.keyboard.a\nrenderDistance:8\n",
            &policy,
            "low",
            &mut state,
        )
        .expect("low state must materialize");
        let high = materialize_minecraft_options_state(
            b"key_key.forward:key.keyboard.a\nrenderDistance:12\n",
            &policy,
            "high",
            &mut state,
        )
        .expect("high state must materialize");

        assert_eq!(low, b"key_key.forward:key.keyboard.up\nrenderDistance:20\n");
        assert_eq!(
            high,
            b"key_key.forward:key.keyboard.up\nrenderDistance:30\n"
        );
    }

    #[test]
    fn migrates_a_renamed_setting_id_without_executable_scripts() {
        let mut policy = policy();
        let quality = policy
            .fields
            .iter_mut()
            .find(|field| field.setting_id == "minecraft.video.render-distance")
            .expect("quality field must exist");
        quality.renamed_from = vec!["minecraft.video.old-render-distance".into()];

        let mut state = MutableSettingsState::new();
        state.presets.entry("low".into()).or_default().insert(
            "minecraft.video.old-render-distance".into(),
            BTreeMap::from([("renderDistance".into(), "18".into())]),
        );
        let result = materialize_minecraft_options_state(
            b"key_key.forward:key.keyboard.w\nrenderDistance:8\n",
            &policy,
            "low",
            &mut state,
        )
        .expect("renamed state must materialize");

        assert_eq!(
            result,
            b"key_key.forward:key.keyboard.w\nrenderDistance:18\n"
        );
        assert!(state.presets["low"].contains_key("minecraft.video.render-distance"));
        assert!(!state.presets["low"].contains_key("minecraft.video.old-render-distance"));
    }

    #[test]
    fn requires_an_explicit_settings_state_schema_version() {
        assert_eq!(MutableSettingsState::default().schema_version, 1);
        for value in [
            serde_json::json!({ "profile": {}, "presets": {} }),
            serde_json::json!({ "schemaVersion": 0, "profile": {}, "presets": {} }),
            serde_json::json!({ "schemaVersion": 2, "profile": {}, "presets": {} }),
        ] {
            assert!(serde_json::from_value::<MutableSettingsState>(value).is_err());
        }
    }
}
