//! Desktop host. Connects the UI to `secwet-core` via Tauri 2 commands.

pub mod clipboard;
pub mod commands;
mod dock_icon;
pub mod error;
pub mod state;

use tauri::{Manager, RunEvent, WindowEvent};

pub use error::UiError;
pub use state::AppState;

#[tauri::command]
fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app_state = AppState::default_state();

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_clipboard_manager::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            core_version,
            // 1. Lifecycle
            commands::vault_status,
            commands::vault_create,
            commands::vault_unlock,
            commands::vault_lock,
            // 2. Labels
            commands::labels_list,
            commands::label_create,
            commands::label_rename,
            commands::label_delete,
            commands::label_reorder,
            // 3. Items
            commands::items_list,
            commands::item_create,
            commands::item_rename,
            commands::item_delete,
            // 4. Environments
            commands::environments_list,
            commands::environment_add,
            commands::environment_rename,
            commands::environment_delete,
            // 5. Secrets
            commands::secrets_list,
            commands::secret_reveal,
            commands::secret_copy,
            commands::secret_create,
            commands::secret_update,
            commands::secret_delete,
            commands::secret_copy_to_environment,
            // 6. Files
            commands::files_list,
            commands::file_upload,
            commands::file_download,
            commands::file_rename,
            commands::file_delete,
            // 7. Notes
            commands::notes_list,
            commands::note_get,
            commands::note_create,
            commands::note_update,
            commands::note_delete,
            commands::note_copy_plain,
            commands::clipboard_copy_text,
            // 8. Overview & Dashboard
            commands::overview,
            commands::dashboard_get,
            commands::dashboard_set,
            // 9. Settings
            commands::settings_get,
            commands::settings_set,
            // 10. Backward Compatibility (Projects)
            commands::projects_list,
            commands::project_create,
            commands::project_rename,
            commands::project_delete,
        ])
        .on_window_event(|_window, event| {
            if let WindowEvent::ThemeChanged(theme) = event {
                if cfg!(debug_assertions) {
                    dock_icon::apply(*theme);
                }
            }
        })
        .build(tauri::generate_context!())
        .expect("error while building Secwet");

    app.run(|handle, event| {
        // Tauri sets the dev Dock icon when the event loop starts, so match the appearance after that.
        if let RunEvent::Ready = event {
            if cfg!(debug_assertions) {
                if let Some(theme) = handle
                    .get_webview_window("main")
                    .and_then(|w| w.theme().ok())
                {
                    dock_icon::apply(theme);
                }
            }
        }
    });
}
