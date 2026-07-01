use serde::Serialize;
use tauri::Manager;

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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_updater::Builder::new().build())
    .setup(|app| {
      if let Some(window) = app.get_webview_window("main") {
        configure_windows_frame(&window)?;
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
    .invoke_handler(tauri::generate_handler![launcher_status])
    .run(tauri::generate_context!())
    .expect("error while running tauri application");
}
