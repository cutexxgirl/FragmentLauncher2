use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs,
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::{Duration, Instant},
};
use tauri::Manager;

const TG_WS_PROXY_VERSION: &str = "v1.8.1";
const TG_WS_PROXY_FILE_NAME: &str = "TgWsProxy_windows.exe";
const TG_WS_PROXY_DOWNLOAD_URL: &str =
    "https://github.com/Flowseal/tg-ws-proxy/releases/download/v1.8.1/TgWsProxy_windows.exe";
const TG_WS_PROXY_SHA256: &str = "840f1c7dae30f492a305f8006256cc2e09426be104c14844cb9be44f966c178d";
const TG_WS_PROXY_PORT: u16 = 1443;

fn is_allowed_external_url(url: &str) -> bool {
    url.starts_with("https://t.me/")
        || url.starts_with("https://telegram.me/")
        || url.starts_with("tg://")
}

#[cfg(target_os = "windows")]
fn open_url_with_system(url: &str) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", url])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn open_url_with_system(url: &str) -> Result<(), String> {
    Command::new("open")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_url_with_system(url: &str) -> Result<(), String> {
    Command::new("xdg-open")
        .arg(url)
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(target_os = "windows")]
fn configure_windows_frame(window: &tauri::WebviewWindow) -> tauri::Result<()> {
    use windows::Win32::Graphics::Dwm::{
        DwmSetWindowAttribute, DWMWA_BORDER_COLOR, DWMWA_CAPTION_COLOR, DWMWA_COLOR_NONE,
        DWMWA_WINDOW_CORNER_PREFERENCE, DWMWCP_DONOTROUND,
    };

    let hwnd = window.hwnd()?;
    let transparent_system_color = DWMWA_COLOR_NONE;
    let corner_preference = DWMWCP_DONOTROUND;

    unsafe {
        DwmSetWindowAttribute(
            hwnd,
            DWMWA_BORDER_COLOR,
            &transparent_system_color as *const _ as _,
            std::mem::size_of_val(&transparent_system_color) as u32,
        )
        .ok();

        DwmSetWindowAttribute(
            hwnd,
            DWMWA_CAPTION_COLOR,
            &transparent_system_color as *const _ as _,
            std::mem::size_of_val(&transparent_system_color) as u32,
        )
        .ok();

        DwmSetWindowAttribute(
            hwnd,
            DWMWA_WINDOW_CORNER_PREFERENCE,
            &corner_preference as *const _ as _,
            std::mem::size_of_val(&corner_preference) as u32,
        )
        .ok();
    }

    Ok(())
}

#[cfg(not(target_os = "windows"))]
fn configure_windows_frame(_window: &tauri::WebviewWindow) -> tauri::Result<()> {
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LauncherStatus {
    app_name: &'static str,
    version: &'static str,
    profile: &'static str,
    services_connected: bool,
    updater_ready: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TgWsProxyStatus {
    supported: bool,
    installed: bool,
    running: bool,
    version: &'static str,
    path: Option<String>,
    shortcut_path: Option<String>,
    message: String,
}

#[derive(Deserialize)]
struct TgWsProxyConfig {
    host: Option<String>,
    port: Option<u16>,
    secret: Option<String>,
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn tg_ws_proxy_dir() -> Result<PathBuf, String> {
    let exe_path = std::env::current_exe().map_err(|error| error.to_string())?;
    let exe_dir = exe_path
        .parent()
        .ok_or_else(|| "launcher directory is not available".to_string())?;

    Ok(exe_dir.join("tg-ws-proxy"))
}

fn tg_ws_proxy_path() -> Result<PathBuf, String> {
    Ok(tg_ws_proxy_dir()?.join(TG_WS_PROXY_FILE_NAME))
}

fn tg_ws_proxy_config_path() -> Option<PathBuf> {
    std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .map(|path| path.join("TgWsProxy").join("config.json"))
}

fn tg_ws_proxy_shortcut_path() -> Option<PathBuf> {
    std::env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .map(|path| path.join("Desktop").join("TG WS Proxy.lnk"))
}

fn is_tg_ws_proxy_running() -> bool {
    let address = SocketAddr::from(([127, 0, 0, 1], TG_WS_PROXY_PORT));

    TcpStream::connect_timeout(&address, Duration::from_millis(350)).is_ok()
}

fn wait_for_tg_ws_proxy(timeout: Duration) -> bool {
    let started_at = Instant::now();

    while started_at.elapsed() < timeout {
        if is_tg_ws_proxy_running() {
            return true;
        }

        thread::sleep(Duration::from_millis(300));
    }

    is_tg_ws_proxy_running()
}

fn file_sha256(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    let digest = Sha256::digest(&bytes);

    Ok(format!("{:x}", digest))
}

async fn download_tg_ws_proxy(proxy_path: &Path) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .user_agent("FragmentLauncher/1.0")
        .build()
        .map_err(|error| error.to_string())?;

    let response = client
        .get(TG_WS_PROXY_DOWNLOAD_URL)
        .send()
        .await
        .map_err(|error| error.to_string())?;

    if !response.status().is_success() {
        return Err(format!(
            "TG WS Proxy download failed with HTTP {}",
            response.status()
        ));
    }

    let bytes = response.bytes().await.map_err(|error| error.to_string())?;
    let digest = format!("{:x}", Sha256::digest(&bytes));

    if digest != TG_WS_PROXY_SHA256 {
        return Err("TG WS Proxy checksum mismatch".into());
    }

    if let Some(parent) = proxy_path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }

    let temp_path = proxy_path.with_extension("exe.download");
    fs::write(&temp_path, &bytes).map_err(|error| error.to_string())?;
    fs::rename(&temp_path, proxy_path).map_err(|error| error.to_string())
}

fn ensure_tg_ws_proxy_file(proxy_path: &Path) -> Result<(), String> {
    if proxy_path.is_file() {
        match file_sha256(proxy_path) {
            Ok(hash) if hash == TG_WS_PROXY_SHA256 => return Ok(()),
            _ => {
                let _ = fs::remove_file(proxy_path);
            }
        }
    }

    Err("TG WS Proxy is not installed".into())
}

#[cfg(target_os = "windows")]
fn start_tg_ws_proxy_process(proxy_path: &Path) -> Result<(), String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    Command::new(proxy_path)
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map(|_| ())
        .map_err(|error| error.to_string())
}

#[cfg(not(target_os = "windows"))]
fn start_tg_ws_proxy_process(_proxy_path: &Path) -> Result<(), String> {
    Err("TG WS Proxy helper is supported on Windows only".into())
}

fn powershell_string(value: &Path) -> String {
    let escaped = value.to_string_lossy().replace('\'', "''");

    format!("'{escaped}'")
}

#[cfg(target_os = "windows")]
fn create_tg_ws_proxy_shortcut(proxy_path: &Path) -> Result<Option<PathBuf>, String> {
    use std::os::windows::process::CommandExt;

    const CREATE_NO_WINDOW: u32 = 0x08000000;

    let working_dir = proxy_path
        .parent()
        .ok_or_else(|| "TG WS Proxy directory is not available".to_string())?;
    let script = format!(
        "$desktop=[Environment]::GetFolderPath('Desktop');\
     if(-not $desktop){{exit 2}};\
     $path=Join-Path $desktop 'TG WS Proxy.lnk';\
     $shell=New-Object -ComObject WScript.Shell;\
     $shortcut=$shell.CreateShortcut($path);\
     $shortcut.TargetPath={};\
     $shortcut.WorkingDirectory={};\
     $shortcut.IconLocation=({},0) -join ',';\
     $shortcut.Save();\
     Write-Output $path",
        powershell_string(proxy_path),
        powershell_string(working_dir),
        powershell_string(proxy_path),
    );

    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            &script,
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|error| error.to_string())?;

    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }

    let shortcut_path = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if shortcut_path.is_empty() {
        return Ok(None);
    }

    Ok(Some(PathBuf::from(shortcut_path)))
}

#[cfg(not(target_os = "windows"))]
fn create_tg_ws_proxy_shortcut(_proxy_path: &Path) -> Result<Option<PathBuf>, String> {
    Ok(None)
}

fn read_tg_ws_proxy_config() -> Option<TgWsProxyConfig> {
    let config_path = tg_ws_proxy_config_path()?;
    let raw = fs::read_to_string(config_path).ok()?;

    serde_json::from_str(&raw).ok()
}

fn open_tg_ws_proxy_setup_link() -> Result<bool, String> {
    for _ in 0..16 {
        let Some(config) = read_tg_ws_proxy_config() else {
            thread::sleep(Duration::from_millis(250));
            continue;
        };
        let Some(secret) = config.secret.filter(|value| !value.is_empty()) else {
            thread::sleep(Duration::from_millis(250));
            continue;
        };

        let host = config.host.unwrap_or_else(|| "127.0.0.1".into());
        let port = config.port.unwrap_or(TG_WS_PROXY_PORT);
        let url = format!("tg://proxy?server={host}&port={port}&secret={secret}");

        return open_url_with_system(&url).map(|_| true);
    }

    Ok(false)
}

fn build_tg_ws_proxy_status(
    message: impl Into<String>,
    shortcut_path: Option<PathBuf>,
) -> Result<TgWsProxyStatus, String> {
    if !cfg!(target_os = "windows") {
        return Ok(TgWsProxyStatus {
            supported: false,
            installed: false,
            running: false,
            version: TG_WS_PROXY_VERSION,
            path: None,
            shortcut_path: None,
            message: "TG WS Proxy пока подключен только для Windows.".into(),
        });
    }

    let proxy_path = tg_ws_proxy_path()?;
    let installed = proxy_path.is_file();
    let running = is_tg_ws_proxy_running();
    let shortcut_path = shortcut_path
        .or_else(tg_ws_proxy_shortcut_path)
        .filter(|path| path.is_file());

    Ok(TgWsProxyStatus {
        supported: true,
        installed,
        running,
        version: TG_WS_PROXY_VERSION,
        path: installed.then(|| path_to_string(&proxy_path)),
        shortcut_path: shortcut_path.as_deref().map(path_to_string),
        message: message.into(),
    })
}

#[tauri::command]
fn launcher_status() -> LauncherStatus {
    LauncherStatus {
        app_name: "Fragment Launcher",
        version: env!("CARGO_PKG_VERSION"),
        profile: "singleplayer",
        services_connected: false,
        updater_ready: true,
    }
}

#[tauri::command]
fn open_external_url(url: String) -> Result<(), String> {
    if !is_allowed_external_url(&url) {
        return Err("external URL is not allowed".into());
    }

    open_url_with_system(&url)
}

#[tauri::command]
fn tg_ws_proxy_status() -> Result<TgWsProxyStatus, String> {
    let running = is_tg_ws_proxy_running();
    let message = if running {
        "TG WS Proxy работает.".to_string()
    } else {
        "TG WS Proxy ещё не установлен.".to_string()
    };

    build_tg_ws_proxy_status(message, None)
}

#[tauri::command]
async fn install_tg_ws_proxy() -> Result<TgWsProxyStatus, String> {
    if !cfg!(target_os = "windows") {
        return build_tg_ws_proxy_status("TG WS Proxy пока подключен только для Windows.", None);
    }

    let proxy_path = tg_ws_proxy_path()?;

    if ensure_tg_ws_proxy_file(&proxy_path).is_err() {
        download_tg_ws_proxy(&proxy_path).await?;
    }

    if !is_tg_ws_proxy_running() {
        start_tg_ws_proxy_process(&proxy_path)?;
    }

    let running = wait_for_tg_ws_proxy(Duration::from_secs(12));
    let shortcut_result = create_tg_ws_proxy_shortcut(&proxy_path);
    let shortcut_path = shortcut_result.as_ref().ok().cloned().flatten();
    let setup_link_opened = if running {
        open_tg_ws_proxy_setup_link().unwrap_or(false)
    } else {
        false
    };

    let mut message = if running && setup_link_opened {
        "TG WS Proxy работает. Подтвердите прокси в Telegram.".to_string()
    } else if running {
        "TG WS Proxy работает. Подключите прокси из окна утилиты.".to_string()
    } else {
        "TG WS Proxy установлен, но порт 127.0.0.1:1443 пока не отвечает.".to_string()
    };

    if shortcut_result.is_err() {
        message.push_str(" Ярлык на рабочем столе не создался.");
    }

    build_tg_ws_proxy_status(message, shortcut_path)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                configure_windows_frame(&window)?;
                window.center()?;
            }

            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            launcher_status,
            open_external_url,
            tg_ws_proxy_status,
            install_tg_ws_proxy
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
