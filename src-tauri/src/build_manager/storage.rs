use super::managed_fs::{
    FileIdentity, GuardedDirectoryChain, ImmutableManagedFile, RelativeManagedPath,
};
use fs2::{available_space, FileExt};
use serde::{Deserialize, Serialize};
use std::{
    env,
    fs::{self, OpenOptions},
    io::{ErrorKind, Read, Write},
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

const OWNER_MARKER: &str = ".fragment-launcher-root.json";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BuildManagerConfig {
    pub install_directory: Option<PathBuf>,
    pub install_id: Option<Uuid>,
}

#[derive(Debug)]
pub struct LoadedConfig {
    pub config: BuildManagerConfig,
    pub warning: Option<String>,
}

pub struct ValidatedInstallDirectory {
    path: PathBuf,
    free_bytes: u64,
    install_id: Uuid,
    // The production coordinator consumes this lease in the next isolated integration slice.
    #[allow(dead_code)]
    cas_root: OwnedCasRoot,
}

/// A non-cloneable lease for the single CAS namespace owned by a validated Fragment install.
/// Its location is fixed to `<install>/cache/objects`; callers can never supply a CAS root.
pub(super) struct OwnedCasRoot {
    binding_nonce: Uuid,
    install_id: Uuid,
    install_root: PathBuf,
    objects_root: PathBuf,
    owner_marker: ImmutableManagedFile,
    owner_marker_bytes: Vec<u8>,
    objects_chain: GuardedDirectoryChain,
}

impl ValidatedInstallDirectory {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn free_bytes(&self) -> u64 {
        self.free_bytes
    }

    pub fn install_id(&self) -> Uuid {
        self.install_id
    }

    /// Consumes the fresh validation token so one validation cannot be rebound to multiple roots.
    #[allow(dead_code)]
    pub(super) fn into_owned_cas_root(self) -> OwnedCasRoot {
        self.cas_root
    }
}

impl OwnedCasRoot {
    fn bind(install_root: &Path, expected_install_id: Uuid) -> Result<Self, String> {
        let objects_relative =
            RelativeManagedPath::new("cache/objects").expect("the static CAS root path is valid");
        let objects_chain = GuardedDirectoryChain::open(install_root, &objects_relative)
            .map_err(|error| format!("Cannot bind the owned CAS directory: {error}"))?;
        objects_chain
            .revalidate()
            .map_err(|error| format!("Cannot revalidate the owned CAS directory: {error}"))?;

        let marker_relative =
            RelativeManagedPath::new(OWNER_MARKER).expect("the static owner marker path is valid");
        let owner_marker = ImmutableManagedFile::open(objects_chain.root_path(), &marker_relative)
            .map_err(|error| format!("Cannot lease the Fragment owner marker: {error}"))?;
        let marker_bytes = owner_marker
            .read_bounded_shared(4096)
            .map_err(|error| format!("Cannot read the leased Fragment owner marker: {error}"))?;
        let marker: OwnerMarker = serde_json::from_slice(&marker_bytes)
            .map_err(|_| "The leased Fragment owner marker is corrupt".to_string())?;
        if marker.schema_version != 1
            || marker.owner != "fragment-launcher"
            || marker.install_id != expected_install_id
        {
            return Err(
                "The leased Fragment owner marker does not match the validated install".into(),
            );
        }

        Ok(Self {
            binding_nonce: Uuid::new_v4(),
            install_id: expected_install_id,
            install_root: objects_chain.root_path().to_path_buf(),
            objects_root: objects_chain.leaf().path().to_path_buf(),
            owner_marker,
            owner_marker_bytes: marker_bytes,
            objects_chain,
        })
    }

    pub(super) fn managed_root(&self) -> &Path {
        &self.objects_root
    }

    /// The installation root is part of the same non-cloneable filesystem lease as the CAS.
    /// Native runtime auditors use this accessor so a caller cannot pair an owned CAS with an
    /// unrelated Java or game-runtime directory.
    pub(super) fn install_root(&self) -> &Path {
        &self.install_root
    }

    pub(super) fn binding(&self) -> (Uuid, Uuid, &FileIdentity, &FileIdentity) {
        (
            self.binding_nonce,
            self.install_id,
            self.objects_chain.root_identity(),
            &self.objects_chain.leaf().info().identity,
        )
    }

    pub(super) fn revalidate(&self) -> Result<(), String> {
        self.objects_chain
            .revalidate()
            .map_err(|error| format!("Owned CAS directory changed: {error}"))?;
        self.owner_marker
            .revalidate()
            .map_err(|error| format!("Owned Fragment marker changed: {error}"))?;
        if self
            .owner_marker
            .read_bounded_shared(4096)
            .map_err(|error| format!("Cannot re-read the owned Fragment marker: {error}"))?
            != self.owner_marker_bytes
        {
            return Err("Owned Fragment marker bytes changed".into());
        }
        if self.objects_chain.root_path() != self.install_root
            || self.objects_chain.leaf().path() != self.objects_root
        {
            return Err("Owned CAS binding changed".into());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OwnerMarker {
    schema_version: u8,
    owner: String,
    install_id: Uuid,
}

pub fn select_install_directory(input: &Path) -> Result<ValidatedInstallDirectory, String> {
    validate_install_directory(input, None, true)
}

pub fn validate_owned_install_directory(
    input: &Path,
    expected_install_id: Uuid,
) -> Result<ValidatedInstallDirectory, String> {
    validate_install_directory(input, Some(expected_install_id), false)
}

fn validate_install_directory(
    input: &Path,
    expected_install_id: Option<Uuid>,
    may_claim_empty_directory: bool,
) -> Result<ValidatedInstallDirectory, String> {
    validate_path_shape(input)?;
    reject_protected_directory(input)?;
    inspect_existing_ancestors(input)?;

    if may_claim_empty_directory {
        fs::create_dir_all(input).map_err(|error| format!("Не удалось создать папку: {error}"))?;
    } else if !input.is_dir() {
        return Err("Сохранённая папка Fragment больше не существует.".into());
    }

    let canonical = fs::canonicalize(input)
        .map_err(|error| format!("Не удалось проверить папку установки: {error}"))?;
    validate_path_shape(&canonical)?;
    reject_protected_directory(&canonical)?;
    inspect_existing_ancestors(&canonical)?;

    let marker = if may_claim_empty_directory {
        claim_or_verify_directory(&canonical)?
    } else {
        let marker = verify_owner_marker(&canonical)?;
        if Some(marker.install_id) != expected_install_id {
            return Err("Защитный идентификатор папки не совпадает с настройками лаунчера.".into());
        }
        marker
    };
    ensure_managed_layout(&canonical)?;
    inspect_existing_ancestors(&canonical.join("instances"))?;
    inspect_existing_ancestors(&canonical.join("cache"))?;
    let cas_root = OwnedCasRoot::bind(&canonical, marker.install_id)?;
    probe_filesystem(&cas_root.install_root)?;

    let free_bytes = available_space(&cas_root.install_root)
        .map_err(|error| format!("Не удалось определить свободное место: {error}"))?;
    Ok(ValidatedInstallDirectory {
        path: cas_root.install_root.clone(),
        free_bytes,
        install_id: marker.install_id,
        cas_root,
    })
}

pub fn load_config(path: &Path) -> LoadedConfig {
    if !path.exists() {
        return LoadedConfig {
            config: BuildManagerConfig::default(),
            warning: None,
        };
    }
    let parsed = fs::read_to_string(path)
        .map_err(|error| format!("Не удалось прочитать настройки сборки: {error}"))
        .and_then(|raw| {
            serde_json::from_str(&raw)
                .map_err(|error| format!("Настройки сборки повреждены: {error}"))
        });
    match parsed {
        Ok(config) => LoadedConfig {
            config,
            warning: None,
        },
        Err(message) => {
            let quarantine = path.with_extension(format!("corrupt-{}.json", Uuid::new_v4()));
            let quarantine_note = match fs::rename(path, &quarantine) {
                Ok(()) => format!(" Повреждённый файл перемещён в {}.", quarantine.display()),
                Err(error) => format!(" Не удалось изолировать файл: {error}."),
            };
            LoadedConfig {
                config: BuildManagerConfig::default(),
                warning: Some(format!("{message}{quarantine_note}")),
            }
        }
    }
}

pub fn save_config(path: &Path, config: &BuildManagerConfig) -> Result<(), String> {
    save_config_with_unlock(path, config, |lock_file| {
        FileExt::unlock(lock_file)
            .map_err(|error| format!("Не удалось снять блокировку настроек: {error}"))
    })
}

fn save_config_with_unlock<F>(
    path: &Path,
    config: &BuildManagerConfig,
    unlock_file: F,
) -> Result<(), String>
where
    F: FnOnce(&std::fs::File) -> Result<(), String>,
{
    let parent = path
        .parent()
        .ok_or_else(|| "Папка настроек недоступна".to_string())?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("Не удалось создать папку настроек: {error}"))?;
    let lock_path = path.with_extension("lock");
    let lock_file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|error| format!("Не удалось открыть блокировку настроек: {error}"))?;
    lock_file
        .lock_exclusive()
        .map_err(|error| format!("Не удалось заблокировать настройки: {error}"))?;
    let temporary = path.with_extension(format!("{}.tmp", Uuid::new_v4()));
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|error| format!("Не удалось подготовить настройки: {error}"))?;
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("Не удалось создать временные настройки: {error}"))?;
        file.write_all(&bytes)
            .map_err(|error| format!("Не удалось сохранить настройки: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Не удалось подтвердить настройки на диске: {error}"))?;
        drop(file);
        replace_file(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    let unlock = unlock_file(&lock_file);
    match result {
        Ok(()) => {
            // `replace_file` is the commit point. An explicit unlock failure cannot roll the
            // committed file back; dropping `lock_file` still releases the OS lease.
            let _ = unlock;
            Ok(())
        }
        Err(operation_error) => match unlock {
            Ok(()) => Err(operation_error),
            Err(unlock_error) => Err(format!(
                "{operation_error}; additionally failed to release the config lock: {unlock_error}"
            )),
        },
    }
}

fn validate_path_shape(path: &Path) -> Result<(), String> {
    if !path.is_absolute() {
        return Err("Выберите абсолютный путь к папке установки.".into());
    }
    if path.parent().is_none() {
        return Err("Нельзя устанавливать Fragment в корень диска.".into());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err("Путь установки содержит небезопасные компоненты.".into());
    }
    #[cfg(windows)]
    reject_windows_network_path(path)?;
    Ok(())
}

fn claim_or_verify_directory(path: &Path) -> Result<OwnerMarker, String> {
    let marker_path = path.join(OWNER_MARKER);
    if marker_path.exists() {
        return verify_owner_marker(path);
    }
    if fs::read_dir(path)
        .map_err(|error| format!("Не удалось проверить содержимое папки: {error}"))?
        .next()
        .is_some()
    {
        return Err(
            "Выберите пустую папку или ранее созданную папку Fragment. Это защищает чужие файлы от очистки."
                .into(),
        );
    }
    let marker = OwnerMarker {
        schema_version: 1,
        owner: "fragment-launcher".into(),
        install_id: Uuid::new_v4(),
    };
    let bytes = serde_json::to_vec_pretty(&marker)
        .map_err(|error| format!("Не удалось подготовить маркер установки: {error}"))?;
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&marker_path)
        .map_err(|error| format!("Не удалось создать маркер установки: {error}"))?;
    file.write_all(&bytes)
        .map_err(|error| format!("Не удалось сохранить маркер установки: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("Не удалось подтвердить маркер установки: {error}"))?;
    Ok(marker)
}

fn verify_owner_marker(path: &Path) -> Result<OwnerMarker, String> {
    let marker_path = path.join(OWNER_MARKER);
    let mut file = open_regular_single_link(&marker_path, false).map_err(|_| {
        "Папка не принадлежит Fragment Launcher: отсутствует безопасный защитный маркер."
    })?;
    let length = file
        .metadata()
        .map_err(|_| "Не удалось проверить защитный маркер Fragment.")?
        .len();
    const MAX_OWNER_MARKER_BYTES: u64 = 4096;
    if length == 0 || length > MAX_OWNER_MARKER_BYTES {
        return Err("Защитный маркер Fragment имеет небезопасный размер.".into());
    }
    let mut bytes = Vec::with_capacity(length as usize);
    Read::by_ref(&mut file)
        .take(MAX_OWNER_MARKER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Не удалось прочитать защитный маркер Fragment.")?;
    if bytes.len() as u64 != length {
        return Err("Защитный маркер Fragment изменился во время проверки.".into());
    }
    let marker: OwnerMarker =
        serde_json::from_slice(&bytes).map_err(|_| "Защитный маркер папки Fragment повреждён.")?;
    if marker.schema_version != 1 || marker.owner != "fragment-launcher" {
        return Err("Защитный маркер папки Fragment не распознан.".into());
    }
    Ok(marker)
}

fn ensure_managed_layout(path: &Path) -> Result<(), String> {
    for relative in [
        "instances/stable",
        "instances/dev",
        "cache/objects",
        "runtime/java",
        "runtime/minecraft",
        "staging",
        "backups",
        "state/settings/v1/stable",
        "state/settings/v1/dev",
        "state/journals",
    ] {
        let managed = path.join(relative);
        inspect_existing_ancestors(&managed)?;
        fs::create_dir_all(&managed).map_err(|error| {
            format!("Не удалось создать структуру Fragment ({relative}): {error}")
        })?;
        inspect_existing_ancestors(&managed)?;
    }
    Ok(())
}

fn probe_filesystem(path: &Path) -> Result<(), String> {
    let probe = path.join(format!(".spark2-probe-{}", Uuid::new_v4()));
    let renamed = probe.with_extension("renamed");
    let result = (|| -> Result<(), String> {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&probe)
            .map_err(|error| format!("Папка недоступна для записи: {error}"))?;
        file.write_all(b"fragment-spark2-probe")
            .map_err(|error| format!("Ошибка пробной записи: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("Файловая система не подтвердила запись: {error}"))?;
        drop(file);
        fs::rename(&probe, &renamed).map_err(|error| {
            format!("Файловая система не поддержала безопасное перемещение: {error}")
        })?;
        let bytes = fs::read(&renamed)
            .map_err(|error| format!("Не удалось повторно открыть пробный файл: {error}"))?;
        if bytes != b"fragment-spark2-probe" {
            return Err("Пробная запись была повреждена файловой системой.".into());
        }
        Ok(())
    })();
    let _ = fs::remove_file(&probe);
    let _ = fs::remove_file(&renamed);
    result
}

pub(super) fn inspect_existing_ancestors(path: &Path) -> Result<(), String> {
    for ancestor in path.ancestors() {
        if !ancestor.exists() {
            continue;
        }
        let metadata = fs::symlink_metadata(ancestor)
            .map_err(|error| format!("Не удалось проверить путь: {error}"))?;
        if metadata.file_type().is_symlink() {
            return Err("Ссылки и точки повторного разбора в пути установки запрещены.".into());
        }
        #[cfg(windows)]
        if is_windows_reparse_point(&metadata) {
            return Err("Ссылки и точки повторного разбора в пути установки запрещены.".into());
        }
    }
    Ok(())
}

pub(super) fn open_regular_single_link(path: &Path, write: bool) -> Result<fs::File, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect managed file {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "Managed file is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(windows)]
    let file = {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        OpenOptions::new()
            .read(true)
            .write(write)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(|error| format!("Cannot open managed file {}: {error}", path.display()))?
    };
    #[cfg(not(windows))]
    let file = OpenOptions::new()
        .read(true)
        .write(write)
        .open(path)
        .map_err(|error| format!("Cannot open managed file {}: {error}", path.display()))?;

    validate_regular_single_link_handle(&file, path)?;
    Ok(file)
}

pub(super) fn open_or_create_regular_single_link(path: &Path) -> Result<fs::File, String> {
    match OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(file) => {
            validate_regular_single_link_handle(&file, path)?;
            Ok(file)
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {
            open_regular_single_link(path, true)
        }
        Err(error) => Err(format!(
            "Cannot create managed file {}: {error}",
            path.display()
        )),
    }
}

fn validate_regular_single_link_handle(file: &fs::File, path: &Path) -> Result<(), String> {
    let metadata = file
        .metadata()
        .map_err(|error| format!("Cannot inspect managed file handle: {error}"))?;
    if !metadata.is_file() {
        return Err(format!(
            "Managed file handle is not a regular file: {}",
            path.display()
        ));
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::{
            Foundation::HANDLE,
            Storage::FileSystem::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION},
        };
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        let mut information = BY_HANDLE_FILE_INFORMATION::default();
        let handle = HANDLE(file.as_raw_handle().cast::<core::ffi::c_void>());
        if handle.0.is_null() {
            return Err(format!(
                "Managed file handle is invalid: {}",
                path.display()
            ));
        }
        unsafe { GetFileInformationByHandle(handle, &mut information) }
            .map_err(|error| format!("Cannot inspect managed file handle: {error}"))?;
        if information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || information.nNumberOfLinks != 1
        {
            return Err(format!(
                "Managed file is a reparse point or hard link: {}",
                path.display()
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if file
            .metadata()
            .map_err(|error| format!("Cannot inspect managed file: {error}"))?
            .nlink()
            != 1
        {
            return Err(format!("Managed file is a hard link: {}", path.display()));
        }
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn is_windows_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn reject_protected_directory(path: &Path) -> Result<(), String> {
    for variable in ["SystemRoot", "ProgramFiles", "ProgramFiles(x86)"] {
        let Some(value) = env::var_os(variable) else {
            continue;
        };
        let protected = PathBuf::from(value);
        if paths_overlap_protected_root(path, &protected)
            || fs::canonicalize(&protected)
                .ok()
                .is_some_and(|canonical| paths_overlap_protected_root(path, &canonical))
        {
            return Err("Выбранная системная папка защищена. Выберите другую.".into());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn paths_overlap_protected_root(candidate: &Path, protected: &Path) -> bool {
    let candidate = windows_path_key(candidate);
    let protected = windows_path_key(protected);
    candidate == protected || candidate.starts_with(&format!("{protected}\\"))
}

#[cfg(not(windows))]
fn paths_overlap_protected_root(candidate: &Path, protected: &Path) -> bool {
    candidate == protected || candidate.starts_with(protected)
}

#[cfg(windows)]
fn windows_path_key(path: &Path) -> String {
    let mut value = path.to_string_lossy().replace('/', "\\");
    if let Some(rest) = value.strip_prefix("\\\\?\\UNC\\") {
        value = format!("\\\\{rest}");
    } else if let Some(rest) = value.strip_prefix("\\\\?\\") {
        value = rest.to_string();
    }
    value.trim_end_matches('\\').to_lowercase()
}

#[cfg(windows)]
fn reject_windows_network_path(path: &Path) -> Result<(), String> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt, path::Prefix};
    use windows::{core::PCWSTR, Win32::Storage::FileSystem::GetDriveTypeW};

    let disk = match path.components().next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            Prefix::Disk(letter) | Prefix::VerbatimDisk(letter) => letter,
            _ => {
                return Err(
                    "Сетевые, UNC и служебные Windows-пути для сборки не поддерживаются.".into(),
                )
            }
        },
        _ => return Err("Путь установки должен находиться на локальном диске.".into()),
    };
    let root = format!("{}:\\", char::from(disk));
    let wide: Vec<u16> = OsStr::new(&root).encode_wide().chain(Some(0)).collect();
    const DRIVE_REMOTE: u32 = 4;
    if unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) } == DRIVE_REMOTE {
        return Err("Сетевой диск для сборки не поддерживается.".into());
    }
    Ok(())
}

#[cfg(windows)]
pub(super) fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    use std::os::windows::ffi::OsStrExt;
    use windows::{
        core::PCWSTR,
        Win32::Storage::FileSystem::{
            MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
        },
    };

    let source: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    let destination: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    unsafe {
        MoveFileExW(
            PCWSTR(source.as_ptr()),
            PCWSTR(destination.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
    }
    .map_err(|error| format!("Не удалось атомарно применить настройки: {error}"))
}

#[cfg(not(windows))]
pub(super) fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    fs::rename(source, destination)
        .map_err(|error| format!("Не удалось атомарно применить настройки: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::Arc,
        thread,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn committed_config_survives_an_explicit_unlock_failure() {
        let root =
            std::env::temp_dir().join(format!("fragment-storage-config-unlock-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let path = root.join("build-manager.json");
        let install_id = Uuid::new_v4();
        let config = BuildManagerConfig {
            install_directory: Some(root.join("selected")),
            install_id: Some(install_id),
        };

        let result = save_config_with_unlock(&path, &config, |_| {
            Err("injected unlock failure after replace".into())
        });

        assert!(result.is_ok());
        let loaded = load_config(&path);
        assert!(loaded.warning.is_none());
        assert_eq!(loaded.config.install_directory, config.install_directory);
        assert_eq!(loaded.config.install_id, Some(install_id));
        let lock_path = path.with_extension("lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(lock_path)
            .unwrap();
        lock_file
            .try_lock_exclusive()
            .expect("dropping the committed writer releases the lock");
        FileExt::unlock(&lock_file).unwrap();
        drop(lock_file);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_to_claim_a_non_empty_directory() {
        let root = std::env::temp_dir().join(format!(
            "fragment-storage-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        fs::create_dir_all(&root).expect("create fixture");
        fs::write(root.join("unrelated.txt"), b"keep me").expect("write fixture");
        assert!(select_install_directory(&root).is_err());
        assert!(root.join("unrelated.txt").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn binds_an_owned_directory_to_the_persisted_install_id() {
        let root = std::env::temp_dir().join(format!(
            "fragment-storage-owner-test-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let selected = select_install_directory(&root).expect("claim empty directory");
        assert!(validate_owned_install_directory(&root, selected.install_id()).is_ok());
        assert!(validate_owned_install_directory(&root, Uuid::new_v4()).is_err());
        drop(selected);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn owned_cas_marker_revalidation_is_cursor_independent() {
        let root = std::env::temp_dir().join(format!(
            "fragment-storage-cas-concurrency-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let owned = Arc::new(
            select_install_directory(&root)
                .expect("claim empty directory")
                .into_owned_cas_root(),
        );
        let threads = (0..8)
            .map(|_| {
                let owned = Arc::clone(&owned);
                thread::spawn(move || {
                    for _ in 0..100 {
                        owned.revalidate().expect("concurrent root revalidation");
                    }
                })
            })
            .collect::<Vec<_>>();
        for thread in threads {
            thread.join().expect("revalidation thread");
        }
        drop(owned);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn owned_cas_root_is_exactly_the_install_objects_directory() {
        let root = std::env::temp_dir().join(format!(
            "fragment-storage-exact-cas-root-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let validated = select_install_directory(&root).expect("claim empty directory");
        let expected = validated.path().join("cache/objects");
        let owned = validated.into_owned_cas_root();
        assert_eq!(owned.managed_root(), expected);
        assert_ne!(owned.managed_root(), root.join("cache"));
        assert_ne!(owned.managed_root(), root.join("objects"));
        drop(owned);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owned_cas_root_denies_or_detects_install_root_substitution() {
        let root = std::env::temp_dir().join(format!(
            "fragment-storage-root-substitution-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let moved = root.with_extension("moved");
        let owned = select_install_directory(&root)
            .expect("claim empty directory")
            .into_owned_cas_root();
        match fs::rename(&root, &moved) {
            Err(_) => owned.revalidate().expect("guarded root remains valid"),
            Ok(()) => {
                fs::create_dir(&root).expect("create substituted lexical root");
                assert!(owned.revalidate().is_err());
            }
        }
        drop(owned);
        let _ = fs::remove_dir_all(&root);
        let _ = fs::remove_dir_all(&moved);
    }
}
