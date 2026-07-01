use serde::Serialize;

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
