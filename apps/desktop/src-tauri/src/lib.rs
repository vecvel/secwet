//! Desktop host. Connects the UI to `secwet-core` via Tauri 2 commands.

pub mod biometric;
pub mod cli_manager;
pub mod clipboard;
pub mod collab_commands;
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
        .plugin(tauri_plugin_dialog::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            core_version,
            // 1. Lifecycle
            commands::secwet_status,
            commands::secwet_create,
            commands::secwet_unlock,
            commands::secwet_lock,
            // 1.5. Spaces
            commands::spaces_list,
            commands::space_create,
            commands::space_rename,
            commands::space_delete,
            commands::space_reorder,
            // 2. Groups & Labels
            commands::groups_list,
            commands::group_create,
            commands::group_rename,
            commands::group_delete,
            commands::group_reorder,
            commands::group_move_to_space,
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
            // 6. Assets & Files
            commands::assets_list,
            commands::asset_upload,
            commands::asset_download,
            commands::asset_rename,
            commands::asset_delete,
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
            commands::system_device_name,
            commands::biometric_status,
            commands::biometric_authenticate,
            commands::cli_status,
            commands::cli_install,
            commands::cli_uninstall,
            // 10. Backward Compatibility (Projects)
            commands::projects_list,
            commands::project_create,
            commands::project_rename,
            commands::project_delete,
            // 11. Active Sessions
            commands::active_sessions_list,
            commands::active_session_stop,
            // 12. Recovery & Backup
            commands::recovery_key_create,
            commands::recovery_key_replace,
            commands::recovery_status,
            commands::workspace_export,
            commands::workspace_restore,
            // 13. Relay & Entitlements
            commands::relay_status,
            commands::relay_register,
            commands::relay_set_url,
            // 14. Devices & Pairing
            commands::devices_list,
            collab_commands::device_revoke,
            collab_commands::key_status,
            collab_commands::key_rotate,
            collab_commands::link_status,
            collab_commands::members_list,
            collab_commands::member_invite,
            collab_commands::member_set_grants,
            collab_commands::member_remove,
            collab_commands::invitation_revoke,
            collab_commands::invitation_accept,
            collab_commands::scope_nodes,
            collab_commands::my_access,
            collab_commands::invite_link_copy,
            commands::pairing_start,
            commands::pairing_poll,
            commands::pairing_approve,
            commands::pairing_cancel,
            commands::sync_now,
            commands::sync_status,
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
