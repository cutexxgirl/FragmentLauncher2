#[allow(dead_code)]
mod artifact_plan;
#[allow(dead_code)]
mod availability;
#[allow(dead_code)]
mod cas;
#[allow(dead_code)]
mod contracts;
mod coordinator;
#[allow(dead_code)]
mod game_generation;
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
mod official_cas;
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

use crate::auth::AuthSessionManager;
use coordinator::{
    BuildCoordinator, CoordinatorCancellation, CoordinatorConfig, CoordinatorError,
    CoordinatorProgress, CoordinatorSnapshot, ProgressObserver, TufRootAnchors,
};
use std::{
    collections::{HashMap, VecDeque},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, RwLock,
    },
    time::{Duration, Instant},
};
use storage::{
    load_config, save_config, select_install_directory, validate_owned_install_directory,
    BuildManagerConfig,
};
use tokio::sync::oneshot;
use types::{BuildPhase, PrimaryAction, TransferProgress};
use uuid::Uuid;

pub use types::{BuildChannel, BuildStatus, PresetId};

const STATUS_CACHE_TTL: Duration = Duration::from_secs(5);
const COMPLETED_OPERATION_RETENTION: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BuildKey {
    channel: BuildChannel,
    preset: PresetId,
}

impl BuildKey {
    const fn new(channel: BuildChannel, preset: PresetId) -> Self {
        Self { channel, preset }
    }
}

#[derive(Clone)]
struct CachedBuildStatus {
    status: BuildStatus,
    observed_at: Instant,
}

struct ActiveBuildOperation {
    key: BuildKey,
    operation_id: Uuid,
    cancellation: CoordinatorCancellation,
}

#[derive(Clone)]
struct CompletedBuildOperation {
    key: BuildKey,
    operation_id: Uuid,
    status: BuildStatus,
}

#[cfg(test)]
struct InstallTransitionTestHook {
    claimed: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ActiveBuildInspection {
    key: BuildKey,
    inspection_id: Uuid,
}

#[derive(Default)]
struct BuildRuntimeState {
    active: Option<ActiveBuildOperation>,
    inspection: Option<ActiveBuildInspection>,
    cached: HashMap<BuildKey, CachedBuildStatus>,
    completed_operations: VecDeque<CompletedBuildOperation>,
}

fn cached_status_blocks_operation_start(cached: &CachedBuildStatus) -> bool {
    cached.observed_at.elapsed() <= STATUS_CACHE_TTL
        && cached.status.primary_action == PrimaryAction::Play
}

fn contain_inspection_panic<F>(inspect: F) -> Result<CoordinatorSnapshot, CoordinatorError>
where
    F: FnOnce() -> Result<CoordinatorSnapshot, CoordinatorError>,
{
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(inspect)).unwrap_or_else(|_| {
        Err(CoordinatorError::Failed(
            "Worker проверки Spark2 аварийно завершился".into(),
        ))
    })
}

pub struct BuildManager {
    config_path: PathBuf,
    config: RwLock<BuildManagerConfig>,
    startup_warning: RwLock<Option<String>>,
    coordinator_config: CoordinatorConfig,
    install_transition: Mutex<()>,
    #[cfg(test)]
    install_transition_test_hook: Mutex<Option<InstallTransitionTestHook>>,
    runtime: Mutex<BuildRuntimeState>,
    revision: AtomicU64,
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
        let tuf_state_root = config_path.parent().map_or_else(
            || PathBuf::from("spark2-tuf-v2"),
            |parent| parent.join("spark2-tuf-v2"),
        );
        Self {
            config_path,
            config: RwLock::new(loaded.config),
            startup_warning: RwLock::new(loaded.warning),
            coordinator_config: CoordinatorConfig {
                tuf_state_root,
                anchors: TufRootAnchors::production_fail_closed(),
            },
            install_transition: Mutex::new(()),
            #[cfg(test)]
            install_transition_test_hook: Mutex::new(None),
            runtime: Mutex::new(BuildRuntimeState::default()),
            revision: AtomicU64::new(0),
        }
    }

    pub async fn status(
        self: &Arc<Self>,
        auth: Arc<AuthSessionManager>,
        channel: BuildChannel,
        preset: PresetId,
    ) -> Result<BuildStatus, String> {
        let install_transition = self.lock_install_transition()?;
        let key = BuildKey::new(channel, preset);
        let startup_warning = self.startup_warning()?;
        let installation = self.configured_installation()?;
        let install_hint = installation.as_ref().map(|(path, _)| path.as_path());

        let inspection = {
            let mut runtime = self.lock_runtime()?;
            if let Some(active) = runtime.active.as_ref() {
                let install = install_hint.ok_or_else(|| {
                    "РђРєС‚РёРІРЅР°СЏ РѕРїРµСЂР°С†РёСЏ Spark2 РїРѕС‚РµСЂСЏР»Р° РїСЂРёРІСЏР·РєСѓ Рє РїР°РїРєРµ СѓСЃС‚Р°РЅРѕРІРєРё".to_string()
                })?;
                return Ok(self.active_status_for(&runtime, active, key, install));
            }
            if let Some(message) = startup_warning {
                let status = BuildStatus::error(channel, preset, None, message);
                return Ok(self.publish_non_operation_status_locked(&mut runtime, status));
            }
            let Some(install) = install_hint else {
                let status = BuildStatus::not_installed(channel, preset, None, 0);
                return Ok(self.publish_non_operation_status_locked(&mut runtime, status));
            };
            if let Some(status) = self.cached_or_waiting_status(&runtime, key, install) {
                return Ok(status);
            }
            let inspection = ActiveBuildInspection {
                key,
                inspection_id: Uuid::new_v4(),
            };
            runtime.inspection = Some(inspection);
            inspection
        };
        let (install_directory, install_id) =
            installation.expect("an inspection is claimed only for a configured installation");
        drop(install_transition);

        let (sender, receiver) = oneshot::channel();
        let manager = Arc::clone(self);
        let coordinator_config = self.coordinator_config.clone();
        let install_for_worker = install_directory.clone();
        let worker = std::thread::Builder::new()
            .name(format!("spark2-inspect-{}", channel.as_str()))
            .spawn(move || {
                let result = contain_inspection_panic(|| {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map_err(|error| {
                            CoordinatorError::Failed(format!(
                                "Не удалось запустить проверку: {error}"
                            ))
                        })
                        .and_then(|runtime| {
                            let coordinator = BuildCoordinator::new(coordinator_config);
                            let observer: ProgressObserver = Arc::new(|_| {});
                            runtime.block_on(coordinator.inspect(
                                &install_for_worker,
                                install_id,
                                channel,
                                preset,
                                &auth,
                                &observer,
                            ))
                        })
                });
                let published = manager.finish_inspection(inspection, &install_for_worker, result);
                let _ = sender.send(published);
            });

        if let Err(error) = worker {
            self.clear_inspection(inspection)?;
            return self.publish_non_operation_status(self.error_status(
                key,
                Some(&install_directory),
                CoordinatorError::Failed(format!("Не удалось создать поток проверки: {error}")),
            ));
        }

        match receiver.await {
            Ok(published) => published,
            Err(_) => self.finish_inspection(
                inspection,
                &install_directory,
                Err(CoordinatorError::Failed(
                    "Поток проверки Spark2 завершился без результата".into(),
                )),
            ),
        }
    }

    pub fn start_operation(
        self: &Arc<Self>,
        auth: Arc<AuthSessionManager>,
        channel: BuildChannel,
        preset: PresetId,
    ) -> Result<BuildStatus, String> {
        let install_transition = self.lock_install_transition()?;
        let key = BuildKey::new(channel, preset);
        let startup_warning = self.startup_warning()?;
        let (install_directory, install_id) = self
            .configured_installation()?
            .ok_or_else(|| "Сначала выберите безопасную папку установки Fragment".to_string())?;
        validate_owned_install_directory(&install_directory, install_id)?;

        let operation_id = Uuid::new_v4();
        let cancellation = CoordinatorCancellation::default();
        let mut runtime = self.lock_runtime()?;
        if let Some(active) = runtime.active.as_ref() {
            return Ok(self.active_status_for(&runtime, active, key, &install_directory));
        }
        if runtime.inspection.is_some() {
            return Err("Дождитесь завершения текущей проверки сборки".into());
        }
        if let Some(message) = startup_warning {
            let status = BuildStatus::error(channel, preset, None, message);
            return Ok(self.publish_non_operation_status_locked(&mut runtime, status));
        }
        if runtime
            .cached
            .get(&key)
            .is_some_and(cached_status_blocks_operation_start)
        {
            return Ok(runtime.cached[&key].status.clone());
        }

        let phase = runtime
            .cached
            .get(&key)
            .map_or(BuildPhase::Checking, |cached| {
                match cached.status.primary_action {
                    PrimaryAction::Download => BuildPhase::Downloading,
                    PrimaryAction::Update => BuildPhase::Updating,
                    PrimaryAction::Repair => BuildPhase::Repairing,
                    _ => BuildPhase::Checking,
                }
            });
        let initial = self.with_next_revision(BuildStatus {
            operation_id: Some(operation_id),
            revision: 0,
            channel,
            preset,
            phase,
            primary_action: PrimaryAction::Busy,
            install_directory: Some(install_directory.to_string_lossy().into_owned()),
            installed_release_id: runtime
                .cached
                .get(&key)
                .and_then(|cached| cached.status.installed_release_id.clone()),
            available_release_id: runtime
                .cached
                .get(&key)
                .and_then(|cached| cached.status.available_release_id.clone()),
            message: "Подготавливаем безопасную операцию Spark2…".into(),
            operation_active: true,
            progress: runtime
                .cached
                .get(&key)
                .map_or_else(TransferProgress::default, |cached| {
                    cached.status.progress.clone()
                }),
        });
        runtime.cached.insert(
            key,
            CachedBuildStatus {
                status: initial.clone(),
                observed_at: Instant::now(),
            },
        );
        runtime.active = Some(ActiveBuildOperation {
            key,
            operation_id,
            cancellation: cancellation.clone(),
        });
        drop(runtime);
        drop(install_transition);

        let manager = Arc::clone(self);
        let coordinator_config = self.coordinator_config.clone();
        let install_for_worker = install_directory.clone();
        let worker = std::thread::Builder::new()
            .name(format!("spark2-operation-{operation_id}"))
            .spawn(move || {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build();
                    match runtime {
                        Ok(runtime) => {
                            let coordinator = BuildCoordinator::new(coordinator_config);
                            let observer_manager = Arc::clone(&manager);
                            let observer: ProgressObserver = Arc::new(move |progress| {
                                observer_manager.update_operation_progress(
                                    key,
                                    operation_id,
                                    progress,
                                );
                            });
                            let run = runtime.block_on(coordinator.run(
                                &install_for_worker,
                                install_id,
                                operation_id,
                                channel,
                                preset,
                                &auth,
                                &cancellation,
                                &observer,
                            ));
                            if matches!(&run, Err(CoordinatorError::Cancelled)) {
                                // Cancellation is observable only before a durable pending journal
                                // exists. Reinspect to restore Download/Update/Repair rather than
                                // leaving the UI in a synthetic blocked state.
                                runtime.block_on(coordinator.inspect(
                                    &install_for_worker,
                                    install_id,
                                    channel,
                                    preset,
                                    &auth,
                                    &observer,
                                ))
                            } else {
                                run
                            }
                        }
                        Err(error) => Err(CoordinatorError::Failed(format!(
                            "Не удалось запустить worker операции: {error}"
                        ))),
                    }
                }))
                .unwrap_or_else(|_| {
                    Err(CoordinatorError::Failed(
                        "Worker операции Spark2 аварийно завершился".into(),
                    ))
                });
                manager.finish_operation(key, operation_id, &install_for_worker, result);
            });
        if let Err(error) = worker {
            let mut runtime = self.lock_runtime()?;
            if runtime
                .active
                .as_ref()
                .is_some_and(|active| active.operation_id == operation_id)
            {
                runtime.active = None;
            }
            let status = self.with_next_revision(self.error_status(
                key,
                Some(&install_directory),
                CoordinatorError::Failed(format!("Не удалось создать поток операции: {error}")),
            ));
            runtime.cached.insert(
                key,
                CachedBuildStatus {
                    status: status.clone(),
                    observed_at: Instant::now(),
                },
            );
            return Ok(status);
        }
        Ok(initial)
    }

    pub fn cancel_operation(&self, operation_id: Uuid) -> Result<BuildStatus, String> {
        let mut runtime = self.lock_runtime()?;
        let active = runtime
            .active
            .as_ref()
            .ok_or_else(|| "Активной операции Spark2 нет".to_string())?;
        if active.operation_id != operation_id {
            return Err("Идентификатор операции устарел".into());
        }
        active.cancellation.cancel();
        let key = active.key;
        let cached = runtime
            .cached
            .get(&key)
            .ok_or_else(|| "Статус активной операции отсутствует".to_string())?;
        let mut status = cached.status.clone();
        status.message = "Безопасно останавливаем операцию…".into();
        status.revision = self.next_revision();
        runtime.cached.insert(
            key,
            CachedBuildStatus {
                status: status.clone(),
                observed_at: Instant::now(),
            },
        );
        Ok(status)
    }

    pub fn operation_status(
        &self,
        operation_id: Uuid,
        channel: BuildChannel,
        preset: PresetId,
    ) -> Result<BuildStatus, String> {
        let key = BuildKey::new(channel, preset);
        let runtime = self.lock_runtime()?;
        if let Some(active) = runtime
            .active
            .as_ref()
            .filter(|active| active.operation_id == operation_id)
        {
            if active.key != key {
                return Err("РРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ РѕРїРµСЂР°С†РёРё РЅРµ СЃРѕРѕС‚РІРµС‚СЃС‚РІСѓРµС‚ РІРµС‚РєРµ Рё РїСЂРµСЃРµС‚Сѓ".into());
            }
            if !runtime.cached.get(&key).is_some_and(|cached| {
                cached.status.operation_id == Some(operation_id)
                    && cached.status.operation_active
                    && cached.status.channel == channel
                    && cached.status.preset == preset
            }) {
                return Err(
                    "Active Spark2 operation status failed exact identity validation".into(),
                );
            }
            return runtime
                .cached
                .get(&key)
                .map(|cached| cached.status.clone())
                .ok_or_else(|| {
                    "РЎС‚Р°С‚СѓСЃ Р°РєС‚РёРІРЅРѕР№ РѕРїРµСЂР°С†РёРё Spark2 РѕС‚СЃСѓС‚СЃС‚РІСѓРµС‚"
                        .into()
                });
        }
        let completed = runtime
            .completed_operations
            .iter()
            .rev()
            .find(|completed| completed.operation_id == operation_id)
            .ok_or_else(|| {
                "Р—Р°РІРµСЂС€С‘РЅРЅР°СЏ РѕРїРµСЂР°С†РёСЏ Spark2 Р±РѕР»СЊС€Рµ РЅРµ РґРѕСЃС‚СѓРїРЅР°"
                    .to_string()
            })?;
        if completed.key != key {
            return Err("РРґРµРЅС‚РёС„РёРєР°С‚РѕСЂ РѕРїРµСЂР°С†РёРё РЅРµ СЃРѕРѕС‚РІРµС‚СЃС‚РІСѓРµС‚ РІРµС‚РєРµ Рё РїСЂРµСЃРµС‚Сѓ".into());
        }
        if completed.status.operation_id != Some(operation_id)
            || completed.status.operation_active
            || completed.status.channel != channel
            || completed.status.preset != preset
        {
            return Err(
                "Completed Spark2 operation status failed exact identity validation".into(),
            );
        }
        Ok(completed.status.clone())
    }

    pub fn set_install_directory(
        &self,
        path: PathBuf,
        channel: BuildChannel,
        preset: PresetId,
    ) -> Result<BuildStatus, String> {
        let _install_transition = self.lock_install_transition()?;
        #[cfg(test)]
        self.pause_install_transition_for_test();
        {
            let runtime = self.lock_runtime()?;
            if runtime.active.is_some() || runtime.inspection.is_some() {
                return Err("Нельзя менять папку во время операции или проверки Spark2".into());
            }
        }
        let validated = select_install_directory(&path)?;
        let mut runtime = self.lock_runtime()?;
        if runtime.active.is_some() || runtime.inspection.is_some() {
            return Err("Build ownership changed during install-directory selection".into());
        }
        let mut config = self
            .config
            .write()
            .map_err(|_| "Менеджер сборки временно недоступен".to_string())?;
        let mut startup_warning = self
            .startup_warning
            .write()
            .map_err(|_| "Launcher startup-warning state is unavailable".to_string())?;
        let mut updated = config.clone();
        updated.install_directory = Some(validated.path().to_path_buf());
        updated.install_id = Some(validated.install_id());
        save_config(&self.config_path, &updated)?;
        *config = updated;
        *startup_warning = None;
        let status = BuildStatus::not_installed(
            channel,
            preset,
            Some(validated.path().to_string_lossy().into_owned()),
            validated.free_bytes(),
        );
        runtime.cached.clear();
        runtime.completed_operations.clear();
        Ok(self.publish_non_operation_status_locked(&mut runtime, status))
    }

    fn configured_installation(&self) -> Result<Option<(PathBuf, Uuid)>, String> {
        let config = self
            .config
            .read()
            .map_err(|_| "Менеджер сборки временно недоступен".to_string())?;
        match (&config.install_directory, config.install_id) {
            (None, None) => Ok(None),
            (Some(path), Some(install_id)) => Ok(Some((path.clone(), install_id))),
            _ => Err("Настройки папки установки неполны".into()),
        }
    }

    fn startup_warning(&self) -> Result<Option<String>, String> {
        self.startup_warning
            .read()
            .map_err(|_| "Менеджер сборки временно недоступен".to_string())
            .map(|warning| warning.clone())
    }

    fn lock_runtime(&self) -> Result<std::sync::MutexGuard<'_, BuildRuntimeState>, String> {
        self.runtime
            .lock()
            .map_err(|_| "Runtime менеджера сборки повреждён".to_string())
    }

    fn lock_install_transition(&self) -> Result<std::sync::MutexGuard<'_, ()>, String> {
        self.install_transition
            .lock()
            .map_err(|_| "Install-directory transition authority is unavailable".to_string())
    }

    #[cfg(test)]
    fn pause_install_transition_for_test(&self) {
        let hook = self
            .install_transition_test_hook
            .lock()
            .expect("install transition test hook is healthy")
            .take();
        if let Some(hook) = hook {
            hook.claimed.wait();
            hook.release.wait();
        }
    }

    fn next_revision(&self) -> u64 {
        self.revision
            .fetch_add(1, Ordering::AcqRel)
            .saturating_add(1)
    }

    fn with_next_revision(&self, mut status: BuildStatus) -> BuildStatus {
        status.revision = self.next_revision();
        status
    }

    fn publish_non_operation_status(&self, status: BuildStatus) -> Result<BuildStatus, String> {
        let _install_transition = self.lock_install_transition()?;
        let configured_path = self
            .configured_installation()?
            .map(|(path, _)| path.to_string_lossy().into_owned());
        if status.install_directory != configured_path {
            return Err("A stale install-directory status cannot be published".into());
        }
        let mut runtime = self.lock_runtime()?;
        if runtime.active.is_some() || runtime.inspection.is_some() {
            return Err("A non-operation status cannot replace an active build owner".into());
        }
        Ok(self.publish_non_operation_status_locked(&mut runtime, status))
    }

    fn publish_non_operation_status_locked(
        &self,
        runtime: &mut BuildRuntimeState,
        status: BuildStatus,
    ) -> BuildStatus {
        let key = BuildKey::new(status.channel, status.preset);
        let status = self.with_next_revision(status);
        runtime.cached.insert(
            key,
            CachedBuildStatus {
                status: status.clone(),
                observed_at: Instant::now(),
            },
        );
        status
    }

    fn finish_inspection(
        &self,
        inspection: ActiveBuildInspection,
        install: &Path,
        result: Result<CoordinatorSnapshot, CoordinatorError>,
    ) -> Result<BuildStatus, String> {
        let mut runtime = self.lock_runtime()?;
        if runtime.inspection == Some(inspection) {
            runtime.inspection = None;
        } else {
            if let Some(active) = runtime.active.as_ref() {
                return Ok(self.active_status_for(&runtime, active, inspection.key, install));
            }
            if runtime.inspection.is_none() {
                if let Some(cached) = runtime.cached.get(&inspection.key) {
                    return Ok(cached.status.clone());
                }
            }
            return Err("Результат проверки Spark2 больше не владеет активной инспекцией".into());
        }
        if let Some(active) = runtime.active.as_ref() {
            return Ok(self.active_status_for(&runtime, active, inspection.key, install));
        }
        let status = match result {
            Ok(snapshot) => self.snapshot_status(inspection.key, install, snapshot, false, None),
            Err(error) => self.error_status(inspection.key, Some(install), error),
        };
        let status = self.with_next_revision(status);
        runtime.cached.insert(
            inspection.key,
            CachedBuildStatus {
                status: status.clone(),
                observed_at: Instant::now(),
            },
        );
        Ok(status)
    }

    fn clear_inspection(&self, inspection: ActiveBuildInspection) -> Result<(), String> {
        let mut runtime = self.lock_runtime()?;
        if runtime.inspection == Some(inspection) {
            runtime.inspection = None;
        }
        Ok(())
    }

    fn checking_status(&self, key: BuildKey, install: &Path, message: &str) -> BuildStatus {
        self.with_next_revision(BuildStatus {
            operation_id: None,
            revision: 0,
            channel: key.channel,
            preset: key.preset,
            phase: BuildPhase::Checking,
            primary_action: PrimaryAction::Busy,
            install_directory: Some(install.to_string_lossy().into_owned()),
            installed_release_id: None,
            available_release_id: None,
            message: message.into(),
            operation_active: false,
            progress: TransferProgress::default(),
        })
    }

    fn cached_or_waiting_status(
        &self,
        runtime: &BuildRuntimeState,
        key: BuildKey,
        install: &Path,
    ) -> Option<BuildStatus> {
        if let Some(cached) = runtime.cached.get(&key) {
            if cached.observed_at.elapsed() <= STATUS_CACHE_TTL {
                return Some(cached.status.clone());
            }
        }
        runtime
            .inspection
            .as_ref()
            .map(|_| self.checking_status(key, install, "Проверяем сборку Spark2…"))
    }

    fn active_status_for(
        &self,
        runtime: &BuildRuntimeState,
        active: &ActiveBuildOperation,
        requested: BuildKey,
        install: &Path,
    ) -> BuildStatus {
        if active.key == requested {
            if let Some(cached) = runtime.cached.get(&requested) {
                if cached.status.operation_id == Some(active.operation_id)
                    && cached.status.operation_active
                    && cached.status.channel == requested.channel
                    && cached.status.preset == requested.preset
                {
                    return cached.status.clone();
                }
            }
        }
        self.with_next_revision(BuildStatus {
            operation_id: None,
            revision: 0,
            channel: requested.channel,
            preset: requested.preset,
            phase: BuildPhase::Checking,
            primary_action: PrimaryAction::Busy,
            install_directory: Some(install.to_string_lossy().into_owned()),
            installed_release_id: None,
            available_release_id: None,
            message: "Другая сборка сейчас использует общий диск Fragment".into(),
            operation_active: false,
            progress: TransferProgress::default(),
        })
    }

    fn snapshot_status(
        &self,
        key: BuildKey,
        install: &Path,
        snapshot: CoordinatorSnapshot,
        operation_active: bool,
        operation_id: Option<Uuid>,
    ) -> BuildStatus {
        let (phase, primary_action) = snapshot.phase_action();
        BuildStatus {
            operation_id,
            revision: 0,
            channel: key.channel,
            preset: key.preset,
            phase,
            primary_action: if operation_active {
                PrimaryAction::Busy
            } else {
                primary_action
            },
            install_directory: Some(install.to_string_lossy().into_owned()),
            installed_release_id: snapshot.installed_release_id,
            available_release_id: Some(snapshot.available_release_id),
            message: snapshot.message,
            operation_active,
            progress: TransferProgress {
                disk_free_bytes: snapshot.disk_free_bytes,
                disk_required_bytes: snapshot.disk_required_bytes,
                ..TransferProgress::default()
            },
        }
    }

    fn error_status(
        &self,
        key: BuildKey,
        install: Option<&Path>,
        error: CoordinatorError,
    ) -> BuildStatus {
        let (phase, action, progress) = match &error {
            CoordinatorError::DiskInsufficient {
                available,
                required,
            } => (
                BuildPhase::DiskInsufficient,
                PrimaryAction::Retry,
                TransferProgress {
                    disk_free_bytes: *available,
                    disk_required_bytes: *required,
                    ..TransferProgress::default()
                },
            ),
            CoordinatorError::LauncherUpdateRequired(_) => (
                BuildPhase::LauncherUpdateRequired,
                PrimaryAction::Blocked,
                TransferProgress::default(),
            ),
            CoordinatorError::SubscriptionRequired(_) => (
                BuildPhase::SubscriptionRequired,
                PrimaryAction::Blocked,
                TransferProgress::default(),
            ),
            CoordinatorError::DevForbidden(_) => (
                BuildPhase::DevForbidden,
                PrimaryAction::Blocked,
                TransferProgress::default(),
            ),
            CoordinatorError::Auth(_) => (
                BuildPhase::AuthUnavailable,
                PrimaryAction::Blocked,
                TransferProgress::default(),
            ),
            CoordinatorError::Cancelled => (
                BuildPhase::Checking,
                PrimaryAction::Blocked,
                TransferProgress::default(),
            ),
            CoordinatorError::Failed(_) => (
                BuildPhase::Error,
                PrimaryAction::Retry,
                TransferProgress::default(),
            ),
        };
        BuildStatus {
            operation_id: None,
            revision: 0,
            channel: key.channel,
            preset: key.preset,
            phase,
            primary_action: action,
            install_directory: install.map(|path| path.to_string_lossy().into_owned()),
            installed_release_id: None,
            available_release_id: None,
            message: error.to_string(),
            operation_active: false,
            progress,
        }
    }

    fn update_operation_progress(
        &self,
        key: BuildKey,
        operation_id: Uuid,
        progress: CoordinatorProgress,
    ) {
        let Ok(mut runtime) = self.runtime.lock() else {
            return;
        };
        if !runtime
            .active
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id && active.key == key)
        {
            return;
        }
        let previous = runtime.cached.get(&key).map(|cached| &cached.status);
        let status = BuildStatus {
            operation_id: Some(operation_id),
            revision: self.next_revision(),
            channel: key.channel,
            preset: key.preset,
            phase: progress.phase,
            primary_action: PrimaryAction::Busy,
            install_directory: previous.and_then(|status| status.install_directory.clone()),
            installed_release_id: previous.and_then(|status| status.installed_release_id.clone()),
            available_release_id: previous.and_then(|status| status.available_release_id.clone()),
            message: progress.message,
            operation_active: true,
            progress: TransferProgress {
                current_file: progress.current_file,
                downloaded_bytes: progress.downloaded_bytes,
                total_bytes: progress.total_bytes,
                speed_bytes_per_second: progress.speed_bytes_per_second,
                remaining_bytes: progress
                    .total_bytes
                    .saturating_sub(progress.downloaded_bytes),
                disk_free_bytes: progress.disk_free_bytes,
                disk_required_bytes: progress.disk_required_bytes,
            },
        };
        runtime.cached.insert(
            key,
            CachedBuildStatus {
                status: status.clone(),
                observed_at: Instant::now(),
            },
        );
    }

    fn finish_operation(
        &self,
        key: BuildKey,
        operation_id: Uuid,
        install: &Path,
        result: Result<CoordinatorSnapshot, CoordinatorError>,
    ) {
        let Ok(mut runtime) = self.runtime.lock() else {
            return;
        };
        if !runtime
            .active
            .as_ref()
            .is_some_and(|active| active.operation_id == operation_id && active.key == key)
        {
            return;
        }
        runtime.active = None;
        let mut status = match result {
            Ok(snapshot) => self.snapshot_status(key, install, snapshot, false, Some(operation_id)),
            Err(error) => self.error_status(key, Some(install), error),
        };
        // Keep the completed operation ID on the terminal snapshot. The frontend uses this
        // tombstone to accept exactly one terminal transition and reject stale poll responses.
        status.operation_id = Some(operation_id);
        let status = self.with_next_revision(status);
        runtime.cached.insert(
            key,
            CachedBuildStatus {
                status: status.clone(),
                observed_at: Instant::now(),
            },
        );
        runtime
            .completed_operations
            .retain(|completed| completed.operation_id != operation_id);
        runtime
            .completed_operations
            .push_back(CompletedBuildOperation {
                key,
                operation_id,
                status,
            });
        while runtime.completed_operations.len() > COMPLETED_OPERATION_RETENTION {
            runtime.completed_operations.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use planner::PlannedBuildState;
    use std::{
        fs,
        sync::{mpsc, Barrier},
        thread,
    };

    fn test_manager(label: &str) -> (Arc<BuildManager>, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "fragment-launcher-manager-{label}-{}",
            Uuid::new_v4()
        ));
        fs::create_dir_all(&root).unwrap();
        let manager = Arc::new(BuildManager::new(root.join("manager.json")));
        (manager, root)
    }

    fn seed_active(manager: &BuildManager, key: BuildKey, operation_id: Uuid, install: &Path) {
        let status = BuildStatus {
            operation_id: Some(operation_id),
            revision: manager.next_revision(),
            channel: key.channel,
            preset: key.preset,
            phase: BuildPhase::Downloading,
            primary_action: PrimaryAction::Busy,
            install_directory: Some(install.to_string_lossy().into_owned()),
            installed_release_id: None,
            available_release_id: Some("release-1".into()),
            message: "active".into(),
            operation_active: true,
            progress: TransferProgress::default(),
        };
        let mut runtime = manager.runtime.lock().unwrap();
        runtime.cached.insert(
            key,
            CachedBuildStatus {
                status,
                observed_at: Instant::now(),
            },
        );
        runtime.active = Some(ActiveBuildOperation {
            key,
            operation_id,
            cancellation: CoordinatorCancellation::default(),
        });
    }

    fn seed_inspection(manager: &BuildManager, key: BuildKey) -> ActiveBuildInspection {
        let inspection = ActiveBuildInspection {
            key,
            inspection_id: Uuid::new_v4(),
        };
        manager.runtime.lock().unwrap().inspection = Some(inspection);
        inspection
    }

    fn ready_snapshot() -> CoordinatorSnapshot {
        CoordinatorSnapshot {
            state: PlannedBuildState::Ready,
            installed_release_id: Some("release-1".into()),
            available_release_id: "release-1".into(),
            disk_free_bytes: 42,
            disk_required_bytes: 0,
            message: "ready".into(),
        }
    }

    #[test]
    fn terminal_status_keeps_exact_operation_tombstone() {
        let (manager, root) = test_manager("terminal");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::High);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, key, operation_id, &root);

        manager.finish_operation(key, operation_id, &root, Ok(ready_snapshot()));

        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime.active.is_none());
        let terminal = &runtime.cached[&key].status;
        assert_eq!(terminal.operation_id, Some(operation_id));
        assert!(!terminal.operation_active);
        assert_eq!(terminal.primary_action, PrimaryAction::Play);
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_terminal_lookup_survives_cache_ttl_and_a_new_inspection() {
        let (manager, root) = test_manager("terminal-suspension");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::High);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, key, operation_id, &root);
        manager.finish_operation(key, operation_id, &root, Ok(ready_snapshot()));
        let terminal = manager
            .operation_status(operation_id, key.channel, key.preset)
            .unwrap();
        {
            let mut runtime = manager.runtime.lock().unwrap();
            runtime.cached.get_mut(&key).unwrap().observed_at =
                Instant::now() - STATUS_CACHE_TTL - Duration::from_secs(1);
        }
        let newer_inspection = seed_inspection(&manager, key);
        let ordinary = {
            let runtime = manager.runtime.lock().unwrap();
            manager
                .cached_or_waiting_status(&runtime, key, &root)
                .unwrap()
        };
        assert_eq!(ordinary.operation_id, None);
        assert_eq!(ordinary.primary_action, PrimaryAction::Busy);

        let resumed = manager
            .operation_status(operation_id, key.channel, key.preset)
            .unwrap();
        assert_eq!(resumed.operation_id, Some(operation_id));
        assert!(!resumed.operation_active);
        assert_eq!(resumed.revision, terminal.revision);
        assert!(manager
            .runtime
            .lock()
            .unwrap()
            .inspection
            .is_some_and(|owner| owner == newer_inspection));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn completed_operation_retention_is_bounded_and_keeps_the_newest_tombstones() {
        let (manager, root) = test_manager("terminal-retention-bound");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let mut operation_ids = Vec::new();
        for _ in 0..=COMPLETED_OPERATION_RETENTION {
            let operation_id = Uuid::new_v4();
            operation_ids.push(operation_id);
            seed_active(&manager, key, operation_id, &root);
            manager.finish_operation(key, operation_id, &root, Ok(ready_snapshot()));
        }

        let runtime = manager.runtime.lock().unwrap();
        assert_eq!(
            runtime.completed_operations.len(),
            COMPLETED_OPERATION_RETENTION
        );
        drop(runtime);
        assert!(manager
            .operation_status(operation_ids[0], key.channel, key.preset)
            .is_err());
        assert!(manager
            .operation_status(*operation_ids.last().unwrap(), key.channel, key.preset,)
            .is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn terminal_failure_keeps_its_tombstone_but_becomes_retryable() {
        let (manager, root) = test_manager("terminal-retry");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, key, operation_id, &root);

        manager.finish_operation(
            key,
            operation_id,
            &root,
            Err(CoordinatorError::Failed("temporary failure".into())),
        );

        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime.active.is_none());
        let terminal = &runtime.cached[&key].status;
        assert_eq!(terminal.operation_id, Some(operation_id));
        assert!(!terminal.operation_active);
        assert_eq!(terminal.phase, BuildPhase::Error);
        assert_eq!(terminal.primary_action, PrimaryAction::Retry);
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn entitlement_and_auth_failures_keep_distinct_blocked_phases() {
        let (manager, root) = test_manager("typed-blockers");
        let key = BuildKey::new(BuildChannel::Dev, PresetId::Low);
        for (error, expected) in [
            (
                CoordinatorError::SubscriptionRequired("subscription".into()),
                BuildPhase::SubscriptionRequired,
            ),
            (
                CoordinatorError::DevForbidden("dev".into()),
                BuildPhase::DevForbidden,
            ),
            (
                CoordinatorError::Auth("auth".into()),
                BuildPhase::AuthUnavailable,
            ),
        ] {
            let status = manager.error_status(key, Some(&root), error);
            assert_eq!(status.phase, expected);
            assert_eq!(status.primary_action, PrimaryAction::Blocked);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn minimum_launcher_code_reaches_the_explicit_blocked_phase() {
        let (manager, root) = test_manager("launcher-update-code");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let mapped = coordinator::map_tuf_refresh_error(
            tuf::TufRefreshError::from("launcher_update_required:2.3.4".to_owned()),
            BuildChannel::Stable,
        );
        let status = manager.error_status(key, Some(&root), mapped);
        assert_eq!(status.phase, BuildPhase::LauncherUpdateRequired);
        assert_eq!(status.primary_action, PrimaryAction::Blocked);
        assert!(status.message.contains("2.3.4"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn disk_failure_preserves_capacity_and_offers_a_real_retry() {
        let (manager, root) = test_manager("disk-retry");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Low);
        let status = manager.error_status(
            key,
            Some(&root),
            CoordinatorError::DiskInsufficient {
                available: 7,
                required: 11,
            },
        );
        assert_eq!(status.phase, BuildPhase::DiskInsufficient);
        assert_eq!(status.primary_action, PrimaryAction::Retry);
        assert_eq!(status.progress.disk_free_bytes, 7);
        assert_eq!(status.progress.disk_required_bytes, 11);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn only_a_fresh_cached_play_short_circuits_operation_start() {
        let (manager, root) = test_manager("cached-start-gate");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let status = |action| BuildStatus {
            operation_id: None,
            revision: 1,
            channel: key.channel,
            preset: key.preset,
            phase: BuildPhase::Ready,
            primary_action: action,
            install_directory: Some(root.to_string_lossy().into_owned()),
            installed_release_id: Some("release-1".into()),
            available_release_id: Some("release-1".into()),
            message: "cached".into(),
            operation_active: false,
            progress: TransferProgress::default(),
        };
        let fresh_play = CachedBuildStatus {
            status: status(PrimaryAction::Play),
            observed_at: Instant::now(),
        };
        let stale_play = CachedBuildStatus {
            status: status(PrimaryAction::Play),
            observed_at: Instant::now() - STATUS_CACHE_TTL - Duration::from_secs(1),
        };
        let blocked = CachedBuildStatus {
            status: status(PrimaryAction::Blocked),
            observed_at: Instant::now(),
        };
        let retry = CachedBuildStatus {
            status: status(PrimaryAction::Retry),
            observed_at: Instant::now(),
        };
        assert!(cached_status_blocks_operation_start(&fresh_play));
        assert!(!cached_status_blocks_operation_start(&stale_play));
        assert!(!cached_status_blocks_operation_start(&blocked));
        assert!(!cached_status_blocks_operation_start(&retry));
        drop(manager);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_rejects_stale_operation_id_without_changing_status() {
        let (manager, root) = test_manager("cancel-stale");
        let key = BuildKey::new(BuildChannel::Dev, PresetId::Low);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, key, operation_id, &root);
        let before = manager.runtime.lock().unwrap().cached[&key].status.clone();

        assert!(manager.cancel_operation(Uuid::new_v4()).is_err());

        let after = manager.runtime.lock().unwrap().cached[&key].status.clone();
        assert_eq!(after.operation_id, before.operation_id);
        assert_eq!(after.revision, before.revision);
        manager.cancel_operation(operation_id).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn worker_publishes_and_clears_before_a_dropped_response_is_observed() {
        let (manager, root) = test_manager("inspection-dropped-receiver");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::High);
        let inspection = seed_inspection(&manager, key);
        let before = manager.revision.load(Ordering::Acquire);

        let published = manager
            .finish_inspection(inspection, &root, Ok(ready_snapshot()))
            .unwrap();
        let (sender, receiver) = oneshot::channel();
        drop(receiver);
        assert!(sender.send(Ok::<_, String>(published.clone())).is_err());

        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime.inspection.is_none());
        assert_eq!(runtime.cached[&key].status.revision, published.revision);
        assert!(published.revision > before);
        drop(runtime);

        let repeated = manager
            .finish_inspection(
                inspection,
                &root,
                Err(CoordinatorError::Failed("late fallback".into())),
            )
            .unwrap();
        assert_eq!(repeated.revision, published.revision);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn stale_inspection_completion_cannot_clear_a_new_owner_or_rewrite_cache() {
        let (manager, root) = test_manager("inspection-stale-owner");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let stale = seed_inspection(&manager, key);
        let current = ActiveBuildInspection {
            key,
            inspection_id: Uuid::new_v4(),
        };
        let cached = manager.with_next_revision(BuildStatus::not_installed(
            key.channel,
            key.preset,
            Some(root.to_string_lossy().into_owned()),
            42,
        ));
        {
            let mut runtime = manager.runtime.lock().unwrap();
            runtime.inspection = Some(current);
            runtime.cached.insert(
                key,
                CachedBuildStatus {
                    status: cached.clone(),
                    observed_at: Instant::now(),
                },
            );
        }
        let before_revision = manager.revision.load(Ordering::Acquire);

        assert!(manager
            .finish_inspection(stale, &root, Ok(ready_snapshot()))
            .is_err());

        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime.inspection.is_some_and(|owner| owner == current));
        let preserved = &runtime.cached[&key].status;
        assert_eq!(preserved.revision, cached.revision);
        assert_eq!(preserved.phase, cached.phase);
        assert_eq!(preserved.primary_action, cached.primary_action);
        assert_eq!(preserved.message, cached.message);
        assert_eq!(preserved.operation_id, cached.operation_id);
        assert_eq!(manager.revision.load(Ordering::Acquire), before_revision);
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspection_panic_is_published_as_retry_and_never_strands_ownership() {
        let (manager, root) = test_manager("inspection-panic");
        let key = BuildKey::new(BuildChannel::Dev, PresetId::Low);
        let inspection = seed_inspection(&manager, key);
        let result = contain_inspection_panic(|| panic!("deterministic inspection panic"));

        let published = manager
            .finish_inspection(inspection, &root, result)
            .unwrap();
        assert_eq!(published.phase, BuildPhase::Error);
        assert_eq!(published.primary_action, PrimaryAction::Retry);
        assert!(manager.runtime.lock().unwrap().inspection.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn active_operation_wins_inspection_completion_without_revision_regression() {
        let (manager, root) = test_manager("inspection-active-priority");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let inspection = seed_inspection(&manager, key);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, key, operation_id, &root);
        let before = manager.revision.load(Ordering::Acquire);

        let published = manager
            .finish_inspection(inspection, &root, Ok(ready_snapshot()))
            .unwrap();
        assert_eq!(published.operation_id, Some(operation_id));
        assert!(published.operation_active);
        assert_eq!(published.revision, before);
        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime.inspection.is_none());
        assert_eq!(runtime.cached[&key].status.operation_id, Some(operation_id));
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn expired_cached_terminal_becomes_waiting_during_same_or_cross_key_inspection() {
        let (manager, root) = test_manager("inspection-expired-cache");
        let requested = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        for owner in [requested, BuildKey::new(BuildChannel::Dev, PresetId::High)] {
            let mut runtime = manager.runtime.lock().unwrap();
            runtime.cached.insert(
                requested,
                CachedBuildStatus {
                    status: BuildStatus {
                        operation_id: None,
                        revision: 1,
                        channel: requested.channel,
                        preset: requested.preset,
                        phase: BuildPhase::LauncherUpdateRequired,
                        primary_action: PrimaryAction::Blocked,
                        install_directory: Some(root.to_string_lossy().into_owned()),
                        installed_release_id: Some("release-1".into()),
                        available_release_id: Some("release-2".into()),
                        message: "stale blocker".into(),
                        operation_active: false,
                        progress: TransferProgress::default(),
                    },
                    observed_at: Instant::now() - STATUS_CACHE_TTL - Duration::from_secs(1),
                },
            );
            runtime.inspection = Some(ActiveBuildInspection {
                key: owner,
                inspection_id: Uuid::new_v4(),
            });
            let waiting = manager
                .cached_or_waiting_status(&runtime, requested, &root)
                .unwrap();
            assert_eq!(waiting.phase, BuildPhase::Checking);
            assert_eq!(waiting.primary_action, PrimaryAction::Busy);
            assert!(waiting.operation_id.is_none());
            assert!(!waiting.operation_active);
            runtime.inspection = None;
        }
        drop(manager);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_directory_change_is_blocked_during_inspection() {
        let (manager, root) = test_manager("inspection");
        seed_inspection(
            &manager,
            BuildKey::new(BuildChannel::Stable, PresetId::Medium),
        );
        let result = manager.set_install_directory(
            root.join("new-install"),
            BuildChannel::Stable,
            PresetId::Medium,
        );
        assert!(result.is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_directory_change_cannot_mutate_or_republish_an_active_operation() {
        let (manager, root) = test_manager("install-active-owner");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, key, operation_id, &root);
        let before = manager.runtime.lock().unwrap().cached[&key].status.clone();
        let candidate = root.join("must-not-be-claimed");

        let result = manager.set_install_directory(candidate.clone(), key.channel, key.preset);

        assert!(result.is_err());
        assert!(!candidate.exists());
        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime
            .active
            .as_ref()
            .is_some_and(|active| { active.operation_id == operation_id && active.key == key }));
        let after = &runtime.cached[&key].status;
        assert_eq!(after.operation_id, before.operation_id);
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.message, before.message);
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_transition_forces_status_to_observe_the_committed_root() {
        let (manager, root) = test_manager("install-transition-status");
        let selected = root.join("selected");
        let claimed = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        *manager.install_transition_test_hook.lock().unwrap() = Some(InstallTransitionTestHook {
            claimed: Arc::clone(&claimed),
            release: Arc::clone(&release),
        });

        let manager_for_set = Arc::clone(&manager);
        let selected_for_set = selected.clone();
        let setter = thread::spawn(move || {
            manager_for_set.set_install_directory(
                selected_for_set,
                BuildChannel::Stable,
                PresetId::Medium,
            )
        });
        claimed.wait();

        let auth = Arc::new(
            AuthSessionManager::production(root.join("auth-refresh.lock"))
                .expect("test auth manager initializes"),
        );
        let (attempting_tx, attempting_rx) = mpsc::channel();
        let (status_tx, status_rx) = mpsc::channel();
        let manager_for_status = Arc::clone(&manager);
        let status_thread = thread::spawn(move || {
            attempting_tx.send(()).unwrap();
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(manager_for_status.status(
                auth,
                BuildChannel::Stable,
                PresetId::Medium,
            ));
            status_tx.send(result).unwrap();
        });
        attempting_rx.recv().unwrap();
        assert!(matches!(
            status_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        release.wait();
        let set_status = setter.join().unwrap().unwrap();
        let observed = status_rx.recv().unwrap().unwrap();
        status_thread.join().unwrap();
        let selected = fs::canonicalize(selected).unwrap();
        let expected = selected.to_string_lossy().into_owned();
        assert_eq!(
            set_status.install_directory.as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(
            observed.install_directory.as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(observed.primary_action, PrimaryAction::Download);
        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime.active.is_none());
        assert!(runtime.inspection.is_none());
        drop(runtime);
        drop(manager);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn install_transition_forces_start_to_claim_only_the_committed_root() {
        let (manager, root) = test_manager("install-transition-start");
        let selected = root.join("selected");
        let claimed = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        *manager.install_transition_test_hook.lock().unwrap() = Some(InstallTransitionTestHook {
            claimed: Arc::clone(&claimed),
            release: Arc::clone(&release),
        });

        let manager_for_set = Arc::clone(&manager);
        let selected_for_set = selected.clone();
        let setter = thread::spawn(move || {
            manager_for_set.set_install_directory(
                selected_for_set,
                BuildChannel::Stable,
                PresetId::Medium,
            )
        });
        claimed.wait();

        let auth = Arc::new(
            AuthSessionManager::production(root.join("auth-refresh.lock"))
                .expect("test auth manager initializes"),
        );
        let (attempting_tx, attempting_rx) = mpsc::channel();
        let (start_tx, start_rx) = mpsc::channel();
        let manager_for_start = Arc::clone(&manager);
        let start_thread = thread::spawn(move || {
            attempting_tx.send(()).unwrap();
            let result =
                manager_for_start.start_operation(auth, BuildChannel::Stable, PresetId::Medium);
            start_tx.send(result).unwrap();
        });
        attempting_rx.recv().unwrap();
        assert!(matches!(
            start_rx.recv_timeout(Duration::from_millis(100)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));

        release.wait();
        let set_status = setter.join().unwrap().unwrap();
        let started = start_rx.recv().unwrap().unwrap();
        start_thread.join().unwrap();
        let selected = fs::canonicalize(selected).unwrap();
        let expected = selected.to_string_lossy().into_owned();
        assert_eq!(
            set_status.install_directory.as_deref(),
            Some(expected.as_str())
        );
        assert_eq!(
            started.install_directory.as_deref(),
            Some(expected.as_str())
        );
        assert!(started.operation_active);
        let operation_id = started
            .operation_id
            .expect("start claims an exact operation id");
        for _ in 0..200 {
            if manager
                .operation_status(operation_id, BuildChannel::Stable, PresetId::Medium)
                .is_ok_and(|status| !status.operation_active)
            {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(manager
            .operation_status(operation_id, BuildChannel::Stable, PresetId::Medium)
            .is_ok_and(|status| !status.operation_active));
        drop(manager);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_operation_publication_cannot_overwrite_an_active_operation() {
        let (manager, root) = test_manager("non-operation-active-owner");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, key, operation_id, &root);
        let before = manager.runtime.lock().unwrap().cached[&key].status.clone();

        let result = manager.publish_non_operation_status(BuildStatus::not_installed(
            key.channel,
            key.preset,
            Some(root.to_string_lossy().into_owned()),
            42,
        ));

        assert!(result.is_err());
        let after = &manager.runtime.lock().unwrap().cached[&key].status;
        assert_eq!(after.operation_id, before.operation_id);
        assert_eq!(after.revision, before.revision);
        assert_eq!(after.message, before.message);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn exact_active_lookup_rejects_a_corrupted_cached_identity() {
        let (manager, root) = test_manager("active-cache-identity");
        let key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, key, operation_id, &root);
        {
            let mut runtime = manager.runtime.lock().unwrap();
            let cached = runtime.cached.get_mut(&key).unwrap();
            cached.status.operation_id = Some(Uuid::new_v4());
        }

        let result = manager.operation_status(operation_id, key.channel, key.preset);

        assert!(result.is_err());
        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime
            .active
            .as_ref()
            .is_some_and(|active| { active.operation_id == operation_id && active.key == key }));
        let fallback =
            manager.active_status_for(&runtime, runtime.active.as_ref().unwrap(), key, &root);
        assert_eq!(fallback.operation_id, None);
        assert!(!fallback.operation_active);
        assert_eq!(fallback.primary_action, PrimaryAction::Busy);
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cross_key_status_never_rebinds_an_active_operation_id() {
        let (manager, root) = test_manager("active-cross-key");
        let active_key = BuildKey::new(BuildChannel::Stable, PresetId::Medium);
        let requested = BuildKey::new(BuildChannel::Dev, PresetId::High);
        let operation_id = Uuid::new_v4();
        seed_active(&manager, active_key, operation_id, &root);

        let status = {
            let runtime = manager.runtime.lock().unwrap();
            manager.active_status_for(&runtime, runtime.active.as_ref().unwrap(), requested, &root)
        };

        assert_eq!(status.channel, requested.channel);
        assert_eq!(status.preset, requested.preset);
        assert_eq!(status.operation_id, None);
        assert!(!status.operation_active);
        assert_eq!(status.primary_action, PrimaryAction::Busy);
        let runtime = manager.runtime.lock().unwrap();
        assert!(runtime.active.as_ref().is_some_and(|active| {
            active.operation_id == operation_id && active.key == active_key
        }));
        drop(runtime);
        fs::remove_dir_all(root).unwrap();
    }
}
