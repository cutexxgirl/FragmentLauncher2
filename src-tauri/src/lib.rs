use serde::Serialize;
use tauri::Manager;

fn is_allowed_external_url(url: &str) -> bool {
  url.starts_with("https://t.me/")
    || url.starts_with("https://telegram.me/")
    || url.starts_with("tg://")
}

#[cfg(target_os = "windows")]
fn open_url_with_system(url: &str) -> Result<(), String> {
  use std::os::windows::process::CommandExt;

  const CREATE_NO_WINDOW: u32 = 0x08000000;

  std::process::Command::new("cmd")
    .args(["/C", "start", "", url])
    .creation_flags(CREATE_NO_WINDOW)
    .spawn()
    .map(|_| ())
    .map_err(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn open_url_with_system(url: &str) -> Result<(), String> {
  std::process::Command::new("open")
    .arg(url)
    .spawn()
    .map(|_| ())
    .map_err(|error| error.to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn open_url_with_system(url: &str) -> Result<(), String> {
  std::process::Command::new("xdg-open")
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
    .invoke_handler(tauri::generate_handler![launcher_status, open_external_url])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
