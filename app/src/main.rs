// SPDX-License-Identifier: AGPL-3.0-only
//! CtrlAltNotes native app (macOS, Windows and Linux). A thin Tauri shell around `ctrlaltnotes-service`,
//! the same backend the web version uses. Everything is self-contained: the encrypted vault
//! lives in the app's own data folder, there is no server, no port and no command line.
//!
//! Security notes:
//!   * The UI talks to the backend through ONE command, `rpc(cmd, args)`.
//!   * File-system choices (join a cloud vault, sync target, export) are made in native OS
//!     dialogs opened HERE, in Rust. The path never travels through the web page, so a
//!     compromised page can only ask the user to pick a location, never name one.
//!   * The window CSP allows no remote content and no inline script/style.
//!   * Keys are wiped when the window closes or the app exits (and on idle, by the service).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
#![forbid(unsafe_code)]

use ctrlaltnotes_service::{ApiError, Service, ServiceConfig};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::Arc;
use tauri::{AppHandle, Manager, RunEvent, State, WindowEvent};
use tauri_plugin_dialog::DialogExt;

/// Open the native dialog a path-taking command needs. `Ok(None)` = command takes no path.
fn host_path(app: &AppHandle, cmd: &str, args: &Value) -> Result<Option<PathBuf>, ApiError> {
    let kind = args
        .get("kind")
        .and_then(|k| k.as_str())
        .unwrap_or("folder");
    let dialog = app.dialog().file();
    let picked = match (cmd, kind) {
        ("join_vault", "bundle") => dialog
            .set_title("Choose your CtrlAltNotes vault file")
            .blocking_pick_file(),
        ("join_vault", _) => dialog
            .set_title("Choose the synced vault folder")
            .blocking_pick_folder(),
        ("set_sync", "bundle") => dialog
            .set_title("Choose or create the sync file")
            .set_file_name("ctrlaltnotes.canb")
            .blocking_save_file(),
        ("set_sync", _) => dialog
            .set_title("Choose the folder your cloud client syncs")
            .blocking_pick_folder(),
        ("open_vault_folder", _) => dialog
            .set_title("Choose a vault folder (an existing vault or an empty folder)")
            .blocking_pick_folder(),
        ("export_markdown", _) => dialog
            .set_title("Export unencrypted Markdown files to…")
            .blocking_pick_folder(),
        _ => return Ok(None),
    };
    match picked {
        None => Err(ApiError::Cancelled),
        Some(p) => p
            .into_path()
            .map(Some)
            .map_err(|_| ApiError::Bad("unsupported location".to_string())),
    }
}

/// The only entry point from the UI. Async so the blocking native dialogs never run on the
/// main/UI thread.
#[tauri::command]
async fn rpc(
    app: AppHandle,
    svc: State<'_, Arc<Service>>,
    cmd: String,
    args: Value,
) -> Result<Value, String> {
    let run = || -> Result<Value, ApiError> {
        if cmd == "open_vault_folder" {
            // only from the lock screen: never show the picker over an open vault
            let st = svc.dispatch("status", &Value::Object(Default::default()), None)?;
            if st.get("unlocked").and_then(|u| u.as_bool()) == Some(true) {
                return Err(ApiError::Bad("lock the vault first".to_string()));
            }
        }
        if cmd == "export_markdown" {
            // do not even show a dialog if the vault is locked
            let st = svc.dispatch("status", &Value::Object(Default::default()), None)?;
            if st.get("unlocked").and_then(|u| u.as_bool()) != Some(true) {
                return Err(ApiError::Locked);
            }
        }
        let path = host_path(&app, &cmd, &args)?;
        svc.dispatch(&cmd, &args, path.as_deref())
    };
    run().map_err(|e| e.wire())
}

/// Linux (WebKitGTK): the DMA-BUF renderer shows a blank or flickering window on many
/// NVIDIA / older Mesa setups. Turn it off unless the user chose a value themselves.
/// Must run before the webview (and any other thread) starts.
#[cfg(target_os = "linux")]
fn linux_webview_env() {
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
}

/// The window may only show the bundled UI. Any attempt to navigate it elsewhere (a link that
/// slipped past the opener, a script, a redirect) is refused, so a remote page can never end up in
/// the window that holds the IPC bridge. External links open in the system browser through the
/// opener plugin instead.
fn navigation_allowed(url: &tauri::Url) -> bool {
    match url.scheme() {
        // macOS / Linux serve the UI from tauri://localhost
        "tauri" => url.host_str() == Some("localhost"),
        // Windows (WebView2) serves it from http(s)://tauri.localhost
        "http" | "https" => url.host_str() == Some("tauri.localhost"),
        "about" => url.as_str() == "about:blank",
        _ => false,
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux_webview_env();
    let navigation_guard = tauri::plugin::Builder::<tauri::Wry>::new("navigation-guard")
        .on_navigation(|_, url| navigation_allowed(url))
        .build();
    let app = tauri::Builder::default()
        .plugin(navigation_guard)
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let dir = app.path().app_data_dir()?;
            let mut cfg = ServiceConfig::new(dir.join("vault"));
            cfg.settings_path = Some(dir.join("settings.json"));
            cfg.app_state_path = Some(dir.join("app.json"));
            cfg.can_pick_paths = true;
            app.manage(Service::new(cfg));
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { .. } | WindowEvent::Destroyed = event {
                if let Some(s) = window.app_handle().try_state::<Arc<Service>>() {
                    s.lock_now();
                }
            }
        })
        .invoke_handler(tauri::generate_handler![rpc])
        .build(tauri::generate_context!())
        .expect("error while building CtrlAltNotes");

    app.run(|handle, event| {
        if let RunEvent::Exit = event {
            if let Some(s) = handle.try_state::<Arc<Service>>() {
                s.lock_now();
            }
        }
    });
}
