#[allow(dead_code)]
mod cas;
#[allow(dead_code)]
mod contracts;
#[allow(dead_code)]
mod game_runtime;
#[allow(dead_code)]
mod game_runtime_executor;
#[allow(dead_code)]
mod game_runtime_invocation;
#[allow(dead_code)]
mod game_runtime_materializer;
#[allow(dead_code)]
mod instance_state;
#[allow(dead_code)]
mod journal;
#[allow(dead_code)]
mod managed_fs;
#[allow(dead_code)]
mod mutable;
#[allow(dead_code)]
mod neoforge;
#[allow(dead_code)]
mod planner;
#[allow(dead_code)]
mod process_supervisor;
#[allow(dead_code)]
mod reconcile_executor;
#[allow(dead_code)]
mod reconciler;
#[allow(dead_code)]
mod release;
#[allow(dead_code)]
mod runtime;
#[allow(dead_code)]
mod settings_store;
#[allow(dead_code)]
mod spark_client;
mod storage;
#[allow(dead_code)]
mod tuf;
#[allow(dead_code)]
mod tuf_transport;
mod types;

use std::{path::PathBuf, sync::RwLock};

pub use types::{BuildChannel, BuildStatus, PresetId};

use storage::{
    load_config, save_config, select_install_directory, validate_owned_install_directory,
    BuildManagerConfig,
};

pub struct BuildManager {
    config_path: PathBuf,
    config: RwLock<BuildManagerConfig>,
    startup_warning: RwLock<Option<String>>,
}

impl BuildManager {
    pub fn new(config_path: PathBuf) -> Self {
        let mut loaded = load_config(&config_path);
        if let Some(path) = loaded.config.install_directory.as_deref() {
            let validation = loaded
                .config
                .install_id
                .ok_or_else(|| "В настройках отсутствует идентификатор папки.".to_string())
                .and_then(|install_id| validate_owned_install_directory(path, install_id));
            if let Err(error) = validation {
                loaded.warning = Some(format!("Сохранённая папка установки отклонена: {error}"));
                loaded.config.install_directory = None;
                loaded.config.install_id = None;
                if let Err(save_error) = save_config(&config_path, &loaded.config) {
                    loaded.warning = Some(format!(
                        "Сохранённая папка установки отклонена: {error}. Не удалось сбросить настройки: {save_error}"
                    ));
                }
            }
        }
        Self {
            config_path,
            config: RwLock::new(loaded.config),
            startup_warning: RwLock::new(loaded.warning),
        }
    }

    pub fn status(&self, channel: BuildChannel, preset: PresetId) -> Result<BuildStatus, String> {
        let config = self
            .config
            .read()
            .map_err(|_| "Менеджер сборки временно недоступен".to_string())?;
        let install_directory = config.install_directory.clone();
        let install_id = config.install_id;
        if let Some(message) = self
            .startup_warning
            .read()
            .map_err(|_| "Менеджер сборки временно недоступен".to_string())?
            .clone()
        {
            return Ok(BuildStatus::error(channel, preset, None, message));
        }
        let free_bytes = match install_directory.as_deref() {
            Some(path) => match install_id
                .ok_or_else(|| "Отсутствует идентификатор папки установки.".to_string())
                .and_then(|id| validate_owned_install_directory(path, id))
            {
                Ok(validated) => {
                    let _instance_directory =
                        validated.path().join("instances").join(match channel {
                            BuildChannel::Stable => "stable",
                            BuildChannel::Dev => "dev",
                        });
                    validated.free_bytes()
                }
                Err(error) => {
                    return Ok(BuildStatus::error(
                        channel,
                        preset,
                        install_directory.map(|path| path.to_string_lossy().into_owned()),
                        format!("Папка установки больше небезопасна: {error}"),
                    ))
                }
            },
            None => 0,
        };
        Ok(BuildStatus::not_installed(
            channel,
            preset,
            install_directory.map(|path| path.to_string_lossy().into_owned()),
            free_bytes,
        ))
    }

    pub fn set_install_directory(
        &self,
        path: PathBuf,
        channel: BuildChannel,
        preset: PresetId,
    ) -> Result<BuildStatus, String> {
        let validated = select_install_directory(&path)?;
        let mut config = self
            .config
            .write()
            .map_err(|_| "Менеджер сборки временно недоступен".to_string())?;
        let mut updated = config.clone();
        updated.install_directory = Some(validated.path().to_path_buf());
        updated.install_id = Some(validated.install_id());
        save_config(&self.config_path, &updated)?;
        *config = updated;
        *self
            .startup_warning
            .write()
            .map_err(|_| "Менеджер сборки временно недоступен".to_string())? = None;
        Ok(BuildStatus::not_installed(
            channel,
            preset,
            Some(validated.path().to_string_lossy().into_owned()),
            validated.free_bytes(),
        ))
    }
}
