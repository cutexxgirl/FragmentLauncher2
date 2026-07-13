use super::{
    contracts::{
        GameLaunchArgument, GameLaunchFragment, GameLaunchPlaceholder, GameRuntimeLock,
        GameRuntimeRole,
    },
    coordinator::PreparedGameLaunch,
    game_natives::NativeWorkspace,
    launch_guard_ipc::{LaunchGuardBootstrap, LAUNCH_GUARD_NONCE_ENV, LAUNCH_GUARD_PIPE_ENV},
    managed_fs::RelativeManagedPath,
    process_supervisor::ProcessSpec,
};
use crate::auth::{AdmissionChannel, LaunchAdmissionLease};
use std::{
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
};

const LAUNCHER_NAME: &str = "FragmentLauncher2";
const MAX_GAME_ARGUMENTS: usize = 1024;

/// The complete no-shell process specification for one exact signed release/admission pair.
/// There is intentionally no public constructor or mutable access to argv/environment.
pub(super) struct PreparedGameInvocation {
    executable: PathBuf,
    arguments: Vec<OsString>,
    cwd: PathBuf,
    environment: Vec<(OsString, OsString)>,
}

impl fmt::Debug for PreparedGameInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedGameInvocation")
            .field("executable", &self.executable)
            .field("argument_count", &self.arguments.len())
            .field("cwd", &self.cwd)
            .field("environment_key_count", &self.environment.len())
            .finish()
    }
}

impl PreparedGameInvocation {
    pub(super) fn process_spec(&self) -> ProcessSpec<'_> {
        ProcessSpec {
            executable: &self.executable,
            arguments: &self.arguments,
            cwd: &self.cwd,
            environment: &self.environment,
        }
    }
}

struct PlaceholderValues {
    fragment_nickname: OsString,
    fragment_uuid: OsString,
    game_directory: OsString,
    assets_root: OsString,
    assets_index_name: OsString,
    version_name: OsString,
    libraries_directory: OsString,
    natives_directory: OsString,
    scratch_temp_directory: OsString,
    logging_config_path: OsString,
    classpath: OsString,
    module_path: OsString,
    launcher_name: OsString,
    launcher_version: OsString,
    offline_access_token: OsString,
    offline_user_type: OsString,
    offline_client_id: OsString,
    offline_xuid: OsString,
    version_type: OsString,
}

impl PlaceholderValues {
    fn get(&self, placeholder: GameLaunchPlaceholder) -> &std::ffi::OsStr {
        match placeholder {
            GameLaunchPlaceholder::FragmentNickname => &self.fragment_nickname,
            GameLaunchPlaceholder::FragmentUuid => &self.fragment_uuid,
            GameLaunchPlaceholder::GameDirectory => &self.game_directory,
            GameLaunchPlaceholder::AssetsRoot => &self.assets_root,
            GameLaunchPlaceholder::AssetsIndexName => &self.assets_index_name,
            GameLaunchPlaceholder::VersionName => &self.version_name,
            GameLaunchPlaceholder::LibrariesDirectory => &self.libraries_directory,
            GameLaunchPlaceholder::NativesDirectory => &self.natives_directory,
            GameLaunchPlaceholder::ScratchTempDirectory => &self.scratch_temp_directory,
            GameLaunchPlaceholder::LoggingConfigPath => &self.logging_config_path,
            GameLaunchPlaceholder::Classpath => &self.classpath,
            GameLaunchPlaceholder::ModulePath => &self.module_path,
            GameLaunchPlaceholder::LauncherName => &self.launcher_name,
            GameLaunchPlaceholder::LauncherVersion => &self.launcher_version,
            GameLaunchPlaceholder::OfflineAccessToken => &self.offline_access_token,
            GameLaunchPlaceholder::OfflineUserType => &self.offline_user_type,
            GameLaunchPlaceholder::OfflineClientId => &self.offline_client_id,
            GameLaunchPlaceholder::OfflineXuid => &self.offline_xuid,
            GameLaunchPlaceholder::VersionType => &self.version_type,
        }
    }
}

pub(super) fn prepare_game_invocation(
    prepared: &PreparedGameLaunch,
    natives: &NativeWorkspace,
    admission: &LaunchAdmissionLease,
    launch_guard: &LaunchGuardBootstrap,
) -> Result<PreparedGameInvocation, String> {
    let expected_admission_channel = match prepared.channel() {
        super::types::BuildChannel::Stable => AdmissionChannel::Stable,
        super::types::BuildChannel::Dev => AdmissionChannel::Dev,
    };
    if admission.channel() != expected_admission_channel {
        return Err("Launch admission belongs to another channel".into());
    }
    if !natives.path().is_absolute()
        || !prepared.runtime().java().is_absolute()
        || !prepared.instance_root().is_absolute()
    {
        return Err("Launch capabilities contain a non-absolute path".into());
    }

    let lock = prepared.trusted().game_runtime_lock();
    let image = prepared.game().image();
    let classpath_paths = resolve_paths(image, &lock.launch.classpath)?;
    let module_paths = resolve_paths(image, &lock.launch.module_path)?;
    let classpath = std::env::join_paths(&classpath_paths)
        .map_err(|_| "Signed classpath cannot be represented as one OS argument".to_string())?;
    let module_path = std::env::join_paths(&module_paths)
        .map_err(|_| "Signed module path cannot be represented as one OS argument".to_string())?;
    let logging_relative = lock
        .files
        .iter()
        .find(|file| file.role == GameRuntimeRole::MinecraftLoggingConfig)
        .ok_or_else(|| "Signed game runtime has no logging configuration".to_string())?;
    let logging_config = resolve_path(image, &logging_relative.path)?;

    let values = PlaceholderValues {
        fragment_nickname: admission.launcher_nick().into(),
        fragment_uuid: admission.minecraft_uuid().into(),
        game_directory: prepared.instance_root().as_os_str().to_owned(),
        assets_root: image.join("assets").into_os_string(),
        assets_index_name: lock.launch.asset_index_name.clone().into(),
        version_name: lock.launch.version_name.clone().into(),
        libraries_directory: image.join("libraries").into_os_string(),
        natives_directory: natives.path().as_os_str().to_owned(),
        scratch_temp_directory: natives.temp_path().as_os_str().to_owned(),
        logging_config_path: logging_config.into_os_string(),
        classpath,
        module_path,
        launcher_name: LAUNCHER_NAME.into(),
        launcher_version: env!("CARGO_PKG_VERSION").into(),
        offline_access_token: lock.identity.access_token.clone().into(),
        offline_user_type: lock.identity.user_type.clone().into(),
        offline_client_id: lock.identity.client_id.clone().into(),
        offline_xuid: lock.identity.xuid.clone().into(),
        version_type: lock.launch.version_type.clone().into(),
    };

    let preset = prepared
        .trusted()
        .manifest()
        .selected_preset(prepared.preset())?;
    let mut arguments = Vec::with_capacity(
        2 + preset.jvm.extra_arguments.len()
            + lock.launch.jvm_arguments.len()
            + 1
            + lock.launch.game_arguments.len(),
    );
    arguments.push(format!("-Xms{}M", preset.jvm.min_memory_mi_b).into());
    arguments.push(format!("-Xmx{}M", preset.jvm.max_memory_mi_b).into());
    arguments.push(path_property("java.io.tmpdir", natives.temp_path()));
    arguments.push(path_property("user.home", natives.home_path()));
    arguments.extend(preset.jvm.extra_arguments.iter().cloned().map(Into::into));
    render_arguments(&lock.launch.jvm_arguments, &values, &mut arguments)?;
    arguments.push(lock.launch.main_class.clone().into());
    render_arguments(&lock.launch.game_arguments, &values, &mut arguments)?;
    if arguments.len() > MAX_GAME_ARGUMENTS {
        return Err("Prepared game argument count exceeds the launcher limit".into());
    }

    // No ambient Java hook/classpath variable is inherited. Writable locations use the separate
    // per-launch scratch tree; the exact DLL directory remains outside TEMP/HOME/APPDATA.
    let mut environment = vec![
        (
            OsString::from("TEMP"),
            natives.temp_path().as_os_str().to_owned(),
        ),
        (
            OsString::from("TMP"),
            natives.temp_path().as_os_str().to_owned(),
        ),
        (
            OsString::from("USERPROFILE"),
            natives.home_path().as_os_str().to_owned(),
        ),
        (
            OsString::from("HOME"),
            natives.home_path().as_os_str().to_owned(),
        ),
        (
            OsString::from("APPDATA"),
            natives.appdata_path().as_os_str().to_owned(),
        ),
        (
            OsString::from("LOCALAPPDATA"),
            natives.local_appdata_path().as_os_str().to_owned(),
        ),
    ];
    if let Some(system_root) = controlled_system_root()? {
        environment.push((OsString::from("SystemRoot"), system_root));
    }
    environment.extend(launch_guard.environment());

    let invocation = PreparedGameInvocation {
        executable: prepared.runtime().java().to_path_buf(),
        arguments,
        cwd: prepared.instance_root().to_path_buf(),
        environment,
    };
    validate_invocation(&invocation, lock, launch_guard)?;
    Ok(invocation)
}

fn resolve_paths(image: &std::path::Path, paths: &[String]) -> Result<Vec<PathBuf>, String> {
    paths.iter().map(|path| resolve_path(image, path)).collect()
}

fn resolve_path(image: &std::path::Path, relative: &str) -> Result<PathBuf, String> {
    let relative = RelativeManagedPath::new(relative).map_err(|error| error.to_string())?;
    let path = relative.join_to(image);
    if !path.starts_with(image) {
        return Err("Signed game path escaped the immutable image".into());
    }
    Ok(path)
}

fn path_property(name: &str, path: &std::path::Path) -> OsString {
    let mut value = OsString::from(format!("-D{name}="));
    value.push(path.as_os_str());
    value
}

fn render_arguments(
    source: &[GameLaunchArgument],
    values: &PlaceholderValues,
    destination: &mut Vec<OsString>,
) -> Result<(), String> {
    for argument in source {
        let rendered = match argument {
            GameLaunchArgument::Literal { value } => OsString::from(value),
            GameLaunchArgument::Template { fragments } => {
                if fragments.is_empty() {
                    return Err("Signed launch template has no fragments".into());
                }
                let mut value = OsString::new();
                for fragment in fragments {
                    match fragment {
                        GameLaunchFragment::Literal { value: literal } => value.push(literal),
                        GameLaunchFragment::Placeholder { name } => value.push(values.get(*name)),
                    }
                }
                value
            }
        };
        destination.push(rendered);
    }
    Ok(())
}

#[cfg(windows)]
fn controlled_system_root() -> Result<Option<OsString>, String> {
    use std::os::windows::ffi::OsStringExt;

    #[link(name = "kernel32")]
    extern "system" {
        #[link_name = "GetWindowsDirectoryW"]
        fn get_windows_directory_w(buffer: *mut u16, size: u32) -> u32;
    }

    const MAX_WINDOWS_DIRECTORY_UTF16: usize = 32_767;
    let mut buffer = vec![0_u16; 260];
    loop {
        let capacity = u32::try_from(buffer.len())
            .map_err(|_| "Windows directory buffer exceeds u32".to_string())?;
        // SAFETY: `buffer` contains exactly `capacity` writable UTF-16 code units and remains
        // alive for the duration of this synchronous kernel32 call.
        let length = unsafe { get_windows_directory_w(buffer.as_mut_ptr(), capacity) } as usize;
        if length == 0 {
            return Err("Windows did not provide its trusted system directory".into());
        }
        if length < buffer.len() {
            let value = OsString::from_wide(&buffer[..length]);
            let path = Path::new(&value);
            if value.is_empty() || !path.is_absolute() || !path.is_dir() {
                return Err("Kernel-provided Windows directory is invalid".into());
            }
            return Ok(Some(value));
        }
        if length > MAX_WINDOWS_DIRECTORY_UTF16 {
            return Err("Windows directory exceeds the launcher UTF-16 limit".into());
        }
        buffer.resize(
            length
                .checked_add(1)
                .ok_or_else(|| "Windows directory length overflow".to_string())?,
            0,
        );
    }
}

#[cfg(not(windows))]
fn controlled_system_root() -> Result<Option<OsString>, String> {
    Ok(None)
}

fn validate_invocation(
    invocation: &PreparedGameInvocation,
    lock: &GameRuntimeLock,
    launch_guard: &LaunchGuardBootstrap,
) -> Result<(), String> {
    if !invocation.executable.is_absolute()
        || !invocation.cwd.is_absolute()
        || lock.launch.main_class.is_empty()
    {
        return Err("Prepared game invocation lost a mandatory field".into());
    }
    let mut environment_keys = std::collections::HashSet::new();
    for (key, value) in &invocation.environment {
        let key = key.to_string_lossy().to_ascii_uppercase();
        if key.is_empty() || !environment_keys.insert(key) || value.is_empty() {
            return Err("Prepared game environment is empty or duplicated".into());
        }
    }
    for forbidden in [
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "CLASSPATH",
    ] {
        if invocation
            .environment
            .iter()
            .any(|(key, _)| key.to_string_lossy().eq_ignore_ascii_case(forbidden))
        {
            return Err("Prepared game environment contains an ambient Java hook".into());
        }
    }
    let expected_pipe = invocation.environment.iter().filter(|(key, value)| {
        key.to_string_lossy()
            .eq_ignore_ascii_case(LAUNCH_GUARD_PIPE_ENV)
            && value == launch_guard.pipe_name()
    });
    if expected_pipe.count() != 1 {
        return Err("Prepared game environment lost its launch-guard pipe binding".into());
    }
    let expected_nonce = invocation.environment.iter().filter(|(key, value)| {
        key.to_string_lossy()
            .eq_ignore_ascii_case(LAUNCH_GUARD_NONCE_ENV)
            && value == launch_guard.nonce_text()
    });
    if expected_nonce.count() != 1 {
        return Err("Prepared game environment lost its launch-guard bootstrap proof".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renderer_preserves_empty_offline_fields_and_os_paths_as_single_arguments() {
        let values = PlaceholderValues {
            fragment_nickname: "Fragment_1".into(),
            fragment_uuid: "550e8400e29b41d4a716446655440000".into(),
            game_directory: r"P:\Fragment Game".into(),
            assets_root: r"P:\runtime\assets".into(),
            assets_index_name: "17".into(),
            version_name: "1.21.1-neoforge-21.1.235".into(),
            libraries_directory: r"P:\runtime\libraries".into(),
            natives_directory: r"P:\runtime\natives".into(),
            scratch_temp_directory: r"P:\runtime\scratch\temp".into(),
            logging_config_path: r"P:\runtime\client.xml".into(),
            classpath: r"P:\a.jar;P:\b.jar".into(),
            module_path: r"P:\m.jar".into(),
            launcher_name: LAUNCHER_NAME.into(),
            launcher_version: "1.0.0".into(),
            offline_access_token: "0".into(),
            offline_user_type: "legacy".into(),
            offline_client_id: "".into(),
            offline_xuid: "".into(),
            version_type: "release".into(),
        };
        let path_template = |prefix: &str, placeholder: GameLaunchPlaceholder, suffix: &str| {
            GameLaunchArgument::Template {
                fragments: vec![
                    GameLaunchFragment::Literal {
                        value: prefix.to_string(),
                    },
                    GameLaunchFragment::Placeholder { name: placeholder },
                    GameLaunchFragment::Literal {
                        value: suffix.to_string(),
                    },
                ],
            }
        };
        let source = vec![
            GameLaunchArgument::Template {
                fragments: vec![GameLaunchFragment::Placeholder {
                    name: GameLaunchPlaceholder::FragmentNickname,
                }],
            },
            GameLaunchArgument::Template {
                fragments: vec![GameLaunchFragment::Placeholder {
                    name: GameLaunchPlaceholder::FragmentUuid,
                }],
            },
            GameLaunchArgument::Template {
                fragments: vec![GameLaunchFragment::Placeholder {
                    name: GameLaunchPlaceholder::GameDirectory,
                }],
            },
            GameLaunchArgument::Template {
                fragments: vec![GameLaunchFragment::Placeholder {
                    name: GameLaunchPlaceholder::OfflineClientId,
                }],
            },
            path_template(
                "-Djava.library.path=",
                GameLaunchPlaceholder::NativesDirectory,
                "",
            ),
            path_template(
                "-XX:HeapDumpPath=",
                GameLaunchPlaceholder::ScratchTempDirectory,
                "/MojangTricksIntelDriversForPerformance_javaw.exe_minecraft.exe.heapdump",
            ),
            path_template(
                "-XX:ErrorFile=",
                GameLaunchPlaceholder::ScratchTempDirectory,
                "/hs_err_pid%p.log",
            ),
            path_template(
                "-Djna.tmpdir=",
                GameLaunchPlaceholder::ScratchTempDirectory,
                "",
            ),
            path_template(
                "-Dorg.lwjgl.system.SharedLibraryExtractPath=",
                GameLaunchPlaceholder::ScratchTempDirectory,
                "",
            ),
            path_template(
                "-Dio.netty.native.workdir=",
                GameLaunchPlaceholder::ScratchTempDirectory,
                "",
            ),
        ];
        let mut rendered = Vec::new();
        render_arguments(&source, &values, &mut rendered).unwrap();
        assert_eq!(
            rendered,
            [
                OsString::from("Fragment_1"),
                OsString::from("550e8400e29b41d4a716446655440000"),
                OsString::from(r"P:\Fragment Game"),
                OsString::new(),
                OsString::from(r"-Djava.library.path=P:\runtime\natives"),
                OsString::from(
                    r"-XX:HeapDumpPath=P:\runtime\scratch\temp/MojangTricksIntelDriversForPerformance_javaw.exe_minecraft.exe.heapdump"
                ),
                OsString::from(r"-XX:ErrorFile=P:\runtime\scratch\temp/hs_err_pid%p.log"),
                OsString::from(r"-Djna.tmpdir=P:\runtime\scratch\temp"),
                OsString::from(
                    r"-Dorg.lwjgl.system.SharedLibraryExtractPath=P:\runtime\scratch\temp"
                ),
                OsString::from(r"-Dio.netty.native.workdir=P:\runtime\scratch\temp"),
            ]
        );
    }

    #[test]
    fn environment_hook_names_are_never_part_of_the_controlled_set() {
        for forbidden in [
            "JAVA_TOOL_OPTIONS",
            "_JAVA_OPTIONS",
            "JDK_JAVA_OPTIONS",
            "CLASSPATH",
        ] {
            assert_ne!(forbidden, "TEMP");
            assert_ne!(forbidden, "SystemRoot");
        }
    }

    #[cfg(windows)]
    #[test]
    fn ambient_system_root_override_cannot_affect_kernel_directory() {
        const CHILD: &str = "FRAGMENT_SYSTEM_ROOT_PROBE_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let ambient = std::env::var_os("SystemRoot").expect("child ambient SystemRoot");
            let trusted = controlled_system_root()
                .expect("query kernel Windows directory")
                .expect("Windows directory");
            assert_ne!(
                std::path::Path::new(&trusted),
                std::path::Path::new(&ambient),
                "kernel Windows directory followed the ambient override"
            );
            return;
        }

        let fake =
            std::env::temp_dir().join(format!("fragment-fake-system-root-{}", std::process::id()));
        std::fs::create_dir_all(&fake).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("build_manager::game_launch::tests::ambient_system_root_override_cannot_affect_kernel_directory")
            .arg("--nocapture")
            .env(CHILD, "1")
            .env("SystemRoot", &fake)
            .output()
            .expect("run isolated SystemRoot probe");
        let _ = std::fs::remove_dir_all(&fake);
        assert!(
            output.status.success(),
            "isolated SystemRoot probe failed:\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
