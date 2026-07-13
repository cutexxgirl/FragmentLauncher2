use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    process::Command,
};

pub const MINECRAFT_VERSION: &str = "1.21.1";
pub const NEOFORGE_VERSION: &str = "21.1.235";
pub const NEOFORGE_PROFILE_ID: &str = "neoforge-21.1.235";
pub const NEOFORGE_INSTALLER_URL: &str = "https://maven.neoforged.net/releases/net/neoforged/neoforge/21.1.235/neoforge-21.1.235-installer.jar";
pub const NEOFORGE_INSTALLER_SHA256: &str =
    "58edd322dc3cbbcd5c75d9a44f93d01211fda2953665483077ddd41fbecf942c";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct InstalledVersion {
    id: String,
    inherits_from: String,
    main_class: String,
}

pub fn install_client(
    java_executable: &Path,
    installer: &Path,
    launcher_root: &Path,
) -> Result<(), String> {
    verify_installer(installer)?;
    ensure_launcher_profiles(launcher_root)?;

    let mut command = Command::new(java_executable);
    command
        .arg("-jar")
        .arg(installer)
        .arg("--install-client")
        .arg(launcher_root)
        .current_dir(launcher_root)
        .env_remove("JAVA_TOOL_OPTIONS")
        .env_remove("_JAVA_OPTIONS")
        .env_remove("JDK_JAVA_OPTIONS");

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x08000000;
        command.creation_flags(CREATE_NO_WINDOW);
    }

    let status = super::process_supervisor::spawn_command_with_inheritance_lock(&mut command)
        .and_then(|mut child| child.wait())
        .map_err(|error| format!("Не удалось запустить установщик NeoForge: {error}"))?;
    if !status.success() {
        return Err(format!(
            "Установщик NeoForge завершился с кодом {}",
            status.code().unwrap_or(-1)
        ));
    }
    validate_installed_profile(launcher_root)
}

pub fn verify_installer(path: &Path) -> Result<(), String> {
    let mut file = File::open(path)
        .map_err(|error| format!("Не удалось открыть установщик NeoForge: {error}"))?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("Не удалось проверить установщик NeoForge: {error}"))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    let actual = format!("{:x}", digest.finalize());
    if actual != NEOFORGE_INSTALLER_SHA256 {
        return Err("Контрольная сумма установщика NeoForge не совпала.".into());
    }
    Ok(())
}

fn ensure_launcher_profiles(launcher_root: &Path) -> Result<(), String> {
    fs::create_dir_all(launcher_root)
        .map_err(|error| format!("Не удалось создать runtime Minecraft: {error}"))?;
    let profile = launcher_root.join("launcher_profiles.json");
    if profile.exists() {
        let value: serde_json::Value =
            serde_json::from_slice(&fs::read(&profile).map_err(|error| {
                format!("Не удалось прочитать launcher_profiles.json: {error}")
            })?)
            .map_err(|error| format!("launcher_profiles.json повреждён: {error}"))?;
        if !value.is_object() {
            return Err("launcher_profiles.json должен содержать JSON-объект.".into());
        }
        return Ok(());
    }
    fs::write(&profile, b"{\n  \"profiles\": {}\n}\n")
        .map_err(|error| format!("Не удалось подготовить launcher_profiles.json: {error}"))
}

fn validate_installed_profile(launcher_root: &Path) -> Result<(), String> {
    let version_path = launcher_root
        .join("versions")
        .join(NEOFORGE_PROFILE_ID)
        .join(format!("{NEOFORGE_PROFILE_ID}.json"));
    let profile: InstalledVersion = serde_json::from_slice(
        &fs::read(&version_path)
            .map_err(|error| format!("NeoForge не создал профиль запуска: {error}"))?,
    )
    .map_err(|error| format!("Профиль NeoForge повреждён: {error}"))?;
    if profile.id != NEOFORGE_PROFILE_ID
        || profile.inherits_from != MINECRAFT_VERSION
        || profile.main_class != "cpw.mods.bootstraplauncher.BootstrapLauncher"
    {
        return Err("Установщик создал неожиданный профиль NeoForge.".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn rejects_an_untrusted_installer() {
        let directory = std::env::temp_dir().join(format!(
            "fragment-neoforge-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&directory).expect("create temp directory");
        let installer = directory.join("installer.jar");
        fs::write(&installer, b"not-neoforge").expect("write fixture");
        assert!(verify_installer(&installer).is_err());
        let _ = fs::remove_dir_all(directory);
    }
}
