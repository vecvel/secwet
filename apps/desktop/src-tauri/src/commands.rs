//! Tauri 2 IPC commands for Secwet Desktop.
//!
//! Every command is a thin wrapper over `secwet_app::AppState` (shared with
//! the mobile hosts). Only desktop pieces live here:
//! the native clipboard, file dialogs, biometrics and the CLI installer.

use std::path::PathBuf;
use std::sync::Arc;

use secwet_core::model::{
    ActiveSession, AssetMetaView, DashboardConfig, EnvironmentView, FileMetaView, ItemView,
    LabelView, NoteMetaView, NoteView, Overview, ProjectView, SecretMeta, SpaceView,
};
use secwet_core::secwet::Settings;
use tauri::{AppHandle, State};
use uuid::Uuid;

pub use secwet_app::commands::{
    system_device_name as system_device_name_impl, AssetDownloadDto, ExportSummaryDto,
    FileDownloadDto, NoteDraftDto, NoteUpdateDto, RecoveryStatusDto, SecretDraftDto,
    SettingsPatchDto, SyncStatusDto,
};

use crate::clipboard::TauriClipboard;
use crate::error::UiError;
use crate::state::{AppState, SecwetStatusDto};

// ============================================================================
// 1. Lifecycle
// ============================================================================

#[tauri::command]
pub fn secwet_status(state: State<'_, AppState>) -> Result<SecwetStatusDto, UiError> {
    state.secwet_status()
}

#[tauri::command]
pub fn secwet_create(
    state: State<'_, AppState>,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError> {
    state.secwet_create(device_name)
}

/// Async so the biometric prompt (when biometric unlock is on) never blocks
/// the UI thread; the check itself runs in the app layer. `recovery_key`
/// stands in for the check while the device cannot run it.
#[tauri::command]
pub async fn secwet_unlock(app: AppHandle, recovery_key: Option<String>) -> Result<(), UiError> {
    crate::biometric::blocking(app, move |state| {
        state.secwet_unlock_with(recovery_key.as_deref())
    })
    .await
}

#[tauri::command]
pub fn secwet_lock(state: State<'_, AppState>) -> Result<(), UiError> {
    state.secwet_lock()
}

// ============================================================================
// 1.5. Spaces
// ============================================================================

#[tauri::command]
pub fn spaces_list(state: State<'_, AppState>) -> Result<Vec<SpaceView>, UiError> {
    state.spaces_list()
}

#[tauri::command]
pub fn space_create(
    state: State<'_, AppState>,
    name: String,
    icon: Option<String>,
) -> Result<SpaceView, UiError> {
    state.space_create(name, icon)
}

#[tauri::command]
pub fn space_rename(
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
    icon: Option<String>,
) -> Result<SpaceView, UiError> {
    state.space_rename(id, name, icon)
}

#[tauri::command]
pub fn space_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.space_delete(id)
}

#[tauri::command]
pub fn space_reorder(state: State<'_, AppState>, ids: Vec<Uuid>) -> Result<(), UiError> {
    state.space_reorder(ids)
}

// ============================================================================
// 2. Groups (labels)
// ============================================================================

#[tauri::command]
pub fn labels_list(state: State<'_, AppState>) -> Result<Vec<LabelView>, UiError> {
    state.labels_list()
}

#[tauri::command]
pub fn groups_list(state: State<'_, AppState>) -> Result<Vec<LabelView>, UiError> {
    state.labels_list()
}

#[tauri::command]
pub fn label_create(
    state: State<'_, AppState>,
    name: String,
    icon: Option<String>,
    space_id: Option<Uuid>,
) -> Result<LabelView, UiError> {
    state.label_create_in_space(name, icon, space_id)
}

#[tauri::command]
pub fn group_create(
    state: State<'_, AppState>,
    name: String,
    icon: Option<String>,
    space_id: Option<Uuid>,
) -> Result<LabelView, UiError> {
    state.label_create_in_space(name, icon, space_id)
}

#[tauri::command]
pub fn group_move_to_space(
    state: State<'_, AppState>,
    id: Uuid,
    space_id: Uuid,
) -> Result<(), UiError> {
    state.label_move_to_space(id, space_id)
}

#[tauri::command]
pub fn label_rename(
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
    icon: Option<String>,
) -> Result<(), UiError> {
    state.label_rename(id, name, icon)
}

#[tauri::command]
pub fn group_rename(
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
    icon: Option<String>,
) -> Result<(), UiError> {
    state.label_rename(id, name, icon)
}

#[tauri::command]
pub fn label_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.label_delete(id)
}

#[tauri::command]
pub fn group_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.label_delete(id)
}

#[tauri::command]
pub fn label_reorder(state: State<'_, AppState>, ids: Vec<Uuid>) -> Result<(), UiError> {
    state.label_reorder(ids)
}

#[tauri::command]
pub fn group_reorder(state: State<'_, AppState>, ids: Vec<Uuid>) -> Result<(), UiError> {
    state.label_reorder(ids)
}

// ============================================================================
// 3. Items
// ============================================================================

#[tauri::command]
pub fn items_list(
    state: State<'_, AppState>,
    label_id: Option<Uuid>,
) -> Result<Vec<ItemView>, UiError> {
    state.items_list(label_id)
}

#[tauri::command]
pub fn item_create(
    state: State<'_, AppState>,
    label_id: Uuid,
    name: String,
    description: Option<String>,
) -> Result<ItemView, UiError> {
    state.item_create(label_id, name, description)
}

#[tauri::command]
pub fn item_rename(
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
    description: Option<String>,
) -> Result<(), UiError> {
    state.item_rename(id, name, description)
}

#[tauri::command]
pub fn item_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.item_delete(id)
}

// ============================================================================
// 4. Environments
// ============================================================================

#[tauri::command]
pub fn environments_list(
    state: State<'_, AppState>,
    item_id: Uuid,
) -> Result<Vec<EnvironmentView>, UiError> {
    state.environments_list(item_id)
}

#[tauri::command]
pub fn environment_add(
    state: State<'_, AppState>,
    item_id: Uuid,
    name: String,
) -> Result<EnvironmentView, UiError> {
    state.environment_add(item_id, name)
}

#[tauri::command]
pub fn environment_rename(
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
) -> Result<(), UiError> {
    state.environment_rename(id, name)
}

#[tauri::command]
pub fn environment_delete(
    state: State<'_, AppState>,
    id: Uuid,
    preserve_content: Option<bool>,
) -> Result<(), UiError> {
    state.environment_delete(id, preserve_content)
}

// ============================================================================
// 5. Secrets
// ============================================================================

#[tauri::command]
pub fn secrets_list(
    state: State<'_, AppState>,
    item_id: Option<Uuid>,
    environment_id: Option<Uuid>,
) -> Result<Vec<SecretMeta>, UiError> {
    state.secrets_list(item_id, environment_id)
}

#[tauri::command]
pub fn secret_reveal(state: State<'_, AppState>, id: Uuid) -> Result<String, UiError> {
    state.secret_reveal(id)
}

#[tauri::command]
pub fn secret_copy(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.secret_copy(Arc::new(TauriClipboard::new(app)), id)
}

#[tauri::command]
pub fn secret_create(
    state: State<'_, AppState>,
    draft: SecretDraftDto,
) -> Result<SecretMeta, UiError> {
    state.secret_create(draft)
}

#[tauri::command]
pub fn secret_update(
    state: State<'_, AppState>,
    id: Uuid,
    draft: SecretDraftDto,
) -> Result<SecretMeta, UiError> {
    state.secret_update(id, draft)
}

#[tauri::command]
pub fn secret_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.secret_delete(id)
}

#[tauri::command]
pub fn secret_copy_to_environment(
    state: State<'_, AppState>,
    id: Uuid,
    target_environment_id: Option<Uuid>,
) -> Result<SecretMeta, UiError> {
    state.secret_copy_to_environment(id, target_environment_id)
}

// ============================================================================
// 6. Assets (F5b) and their older `file_*` names
// ============================================================================

#[tauri::command]
pub fn assets_list(
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<AssetMetaView>, UiError> {
    state.assets_list(item_id, environment_id)
}

#[tauri::command]
pub fn files_list(
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<FileMetaView>, UiError> {
    state.files_list(item_id, environment_id)
}

#[tauri::command]
pub fn asset_upload(
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
    name: String,
    mime: Option<String>,
    bytes: Vec<u8>,
) -> Result<AssetMetaView, UiError> {
    state.asset_upload(item_id, environment_id, name, mime, bytes)
}

#[tauri::command]
pub fn file_upload(
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
    name: String,
    mime: Option<String>,
    bytes: Vec<u8>,
) -> Result<FileMetaView, UiError> {
    state.file_upload(item_id, environment_id, name, mime, bytes)
}

#[tauri::command]
pub fn asset_download(state: State<'_, AppState>, id: Uuid) -> Result<AssetDownloadDto, UiError> {
    state.asset_download(id)
}

#[tauri::command]
pub fn file_download(state: State<'_, AppState>, id: Uuid) -> Result<FileDownloadDto, UiError> {
    state.file_download(id)
}

#[tauri::command]
pub fn asset_rename(
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
) -> Result<AssetMetaView, UiError> {
    state.asset_rename(id, name)
}

#[tauri::command]
pub fn file_rename(
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
) -> Result<FileMetaView, UiError> {
    state.file_rename(id, name)
}

#[tauri::command]
pub fn asset_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.asset_delete(id)
}

#[tauri::command]
pub fn file_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.file_delete(id)
}

// ============================================================================
// 7. Notes
// ============================================================================

#[tauri::command]
pub fn notes_list(
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<NoteMetaView>, UiError> {
    state.notes_list(item_id, environment_id)
}

#[tauri::command]
pub fn note_get(state: State<'_, AppState>, id: Uuid) -> Result<NoteView, UiError> {
    state.note_get(id)
}

#[tauri::command]
pub fn note_create(state: State<'_, AppState>, draft: NoteDraftDto) -> Result<NoteView, UiError> {
    state.note_create(draft)
}

#[tauri::command]
pub fn note_update(
    state: State<'_, AppState>,
    id: Uuid,
    draft: NoteUpdateDto,
) -> Result<NoteView, UiError> {
    state.note_update(id, draft)
}

#[tauri::command]
pub fn note_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.note_delete(id)
}

#[tauri::command]
pub fn note_copy_plain(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.note_copy_plain(Arc::new(TauriClipboard::new(app)), id)
}

#[tauri::command]
pub fn clipboard_copy_text(
    app: AppHandle,
    state: State<'_, AppState>,
    text: String,
) -> Result<(), UiError> {
    state.clipboard_copy_text(Arc::new(TauriClipboard::new(app)), text)
}

// ============================================================================
// 8. Overview & Dashboard
// ============================================================================

#[tauri::command]
pub fn overview(state: State<'_, AppState>) -> Result<Overview, UiError> {
    state.overview()
}

#[tauri::command]
pub fn dashboard_get(state: State<'_, AppState>) -> Result<DashboardConfig, UiError> {
    state.dashboard_get()
}

#[tauri::command]
pub fn dashboard_set(state: State<'_, AppState>, config: DashboardConfig) -> Result<(), UiError> {
    state.dashboard_set(config)
}

// ============================================================================
// 9. Settings and the CLI (biometrics: crate::biometric)
// ============================================================================

#[tauri::command]
pub fn settings_get(state: State<'_, AppState>) -> Result<Settings, UiError> {
    state.settings_get()
}

#[tauri::command]
pub fn settings_set(
    state: State<'_, AppState>,
    settings: SettingsPatchDto,
) -> Result<Settings, UiError> {
    state.settings_set(settings)
}

#[tauri::command]
pub fn system_device_name() -> Result<String, UiError> {
    Ok(secwet_app::commands::system_device_name())
}

#[tauri::command]
pub fn cli_status() -> Result<crate::cli_manager::CliInstallStatus, UiError> {
    Ok(crate::cli_manager::get_cli_status())
}

#[tauri::command]
pub fn cli_install() -> Result<crate::cli_manager::CliInstallStatus, UiError> {
    crate::cli_manager::install_cli().map_err(UiError::internal)
}

#[tauri::command]
pub fn cli_uninstall() -> Result<crate::cli_manager::CliInstallStatus, UiError> {
    crate::cli_manager::uninstall_cli().map_err(UiError::internal)
}

// ============================================================================
// 10. Backward compatibility (projects)
// ============================================================================

#[tauri::command]
pub fn projects_list(state: State<'_, AppState>) -> Result<Vec<ProjectView>, UiError> {
    state.projects_list()
}

#[tauri::command]
pub fn project_create(
    state: State<'_, AppState>,
    name: String,
    environments: Vec<String>,
) -> Result<ProjectView, UiError> {
    state.project_create(name, environments)
}

#[tauri::command]
pub fn project_rename(state: State<'_, AppState>, id: Uuid, name: String) -> Result<(), UiError> {
    state.project_rename(id, name)
}

#[tauri::command]
pub fn project_delete(state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    state.project_delete(id)
}

// ============================================================================
// 11. Active sessions
// ============================================================================

#[tauri::command]
pub fn active_sessions_list(state: State<'_, AppState>) -> Result<Vec<ActiveSession>, UiError> {
    state.active_sessions_list()
}

#[tauri::command]
pub fn active_session_stop(state: State<'_, AppState>, session_id: String) -> Result<(), UiError> {
    state.active_session_stop(session_id)
}

// ============================================================================
// 12. Recovery & backup
// ============================================================================

#[tauri::command]
pub fn recovery_key_create(state: State<'_, AppState>) -> Result<String, UiError> {
    state.recovery_key_create()
}

#[tauri::command]
pub fn recovery_key_replace(state: State<'_, AppState>) -> Result<String, UiError> {
    state.recovery_key_replace()
}

#[tauri::command]
pub fn recovery_status(state: State<'_, AppState>) -> Result<RecoveryStatusDto, UiError> {
    state.recovery_status()
}

/// Asks for a `.secwet` archive path with the native file dialog.
fn pick_archive(app: &AppHandle, save: bool) -> Result<PathBuf, UiError> {
    use tauri_plugin_dialog::DialogExt;
    let dialog = app.dialog().file().add_filter("Secwet Archive", &["secwet"]);
    let (picked, cancelled) = if save {
        (dialog.blocking_save_file(), "Export cancelled")
    } else {
        (dialog.blocking_pick_file(), "Restore cancelled")
    };
    picked
        .ok_or_else(|| UiError::invalid("path", cancelled))?
        .into_path()
        .map_err(|e| UiError::invalid("path", e.to_string()))
}

#[tauri::command]
pub fn workspace_export(
    app: AppHandle,
    state: State<'_, AppState>,
    path: Option<PathBuf>,
    recovery_key: String,
) -> Result<ExportSummaryDto, UiError> {
    let path = match path {
        Some(p) => p,
        None => pick_archive(&app, true)?,
    };
    state.workspace_export(Some(path), recovery_key)
}

#[tauri::command]
pub fn workspace_restore(
    app: AppHandle,
    state: State<'_, AppState>,
    path: Option<PathBuf>,
    recovery_key: String,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError> {
    let path = match path {
        Some(p) => p,
        None => pick_archive(&app, false)?,
    };
    state.workspace_restore(Some(path), recovery_key, device_name)
}

// ============================================================================
// 13. Relay & entitlements
// ============================================================================

#[tauri::command]
pub async fn relay_status(
    state: State<'_, AppState>,
) -> Result<secwet_proto::RelayStatusDto, UiError> {
    state.relay_status().await
}

#[tauri::command]
pub async fn relay_register(
    state: State<'_, AppState>,
) -> Result<secwet_proto::RegisterSecwetResponse, UiError> {
    state.relay_register().await
}

#[tauri::command]
pub fn relay_set_url(state: State<'_, AppState>, url: String) -> Result<(), UiError> {
    state.relay_set_url(url)
}

// ============================================================================
// Plans
// ============================================================================

#[tauri::command]
pub fn plan_status(state: State<'_, AppState>) -> Result<secwet_app::PlanStatusDto, UiError> {
    state.plan_status()
}

#[tauri::command]
pub async fn plan_refresh(state: State<'_, AppState>) -> Result<secwet_app::PlanStatusDto, UiError> {
    state.plan_refresh().await
}

#[tauri::command]
pub async fn plan_activate(state: State<'_, AppState>) -> Result<secwet_app::PlanStatusDto, UiError> {
    state.plan_activate().await
}

// ============================================================================
// 14. Devices & pairing
// ============================================================================

#[tauri::command]
pub fn devices_list(state: State<'_, AppState>) -> Result<Vec<secwet_proto::DeviceDto>, UiError> {
    state.devices_list()
}

#[tauri::command]
pub async fn pairing_start(
    state: State<'_, AppState>,
) -> Result<secwet_proto::PairingSessionInfo, UiError> {
    state.pairing_start().await
}

#[tauri::command]
pub async fn pairing_poll(
    state: State<'_, AppState>,
) -> Result<secwet_proto::PairingPollResponse, UiError> {
    state.pairing_poll().await
}

#[tauri::command]
pub async fn pairing_approve(
    state: State<'_, AppState>,
) -> Result<secwet_proto::DeviceDto, UiError> {
    state.pairing_approve().await
}

#[tauri::command]
pub fn pairing_cancel(state: State<'_, AppState>) -> Result<(), UiError> {
    state.pairing_cancel()
}

// ============================================================================
// Sync
// ============================================================================

#[tauri::command]
pub async fn sync_now(state: State<'_, AppState>) -> Result<serde_json::Value, UiError> {
    let (pushed, pulled) = state.sync_now().await?;
    Ok(serde_json::json!({
        "pushed": pushed,
        "pulled": pulled,
    }))
}

#[tauri::command]
pub fn sync_status(state: State<'_, AppState>) -> Result<SyncStatusDto, UiError> {
    state.sync_status()
}
