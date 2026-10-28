//! Tauri 2 IPC commands implementation for Secwet Desktop.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §9.1 and `PROJECT.md`.
//!
//! Invariants:
//! - All commands return `Result<T, UiError>`.
//! - Secrets and file bytes are never exposed in listings or overview.
//! - Clipboard copy is executed entirely in Rust with 30s auto-clear.
//! - Events are emitted on mutations (`secwet://changed { scope }`) and lock (`secwet://locked`).
//! - Pure `*_impl` functions enable headless unit and adversarial testing.

use std::path::PathBuf;
use std::sync::Arc;

use secrecy::{ExposeSecret, SecretString};
use secwet_core::model::{
    ActiveSession, AssetMetaView, DashboardConfig, EnvironmentView, FileMetaView, ItemView,
    LabelView, NoteMetaView, NoteView, Overview, ProjectView, SecretDraft, SecretKind, SecretMeta,
    SpaceView,
};
use secwet_core::secwet::Settings;
use secwet_core::Secwet;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::clipboard::{extract_plain_text, AutoClearManager, ClipboardPort, TauriClipboard};
use crate::error::UiError;
use crate::state::{AppState, SecwetStatusDto};

// ============================================================================
// DTOs
// ============================================================================

/// Recovery status DTO for UI queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStatusDto {
    pub created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

/// Export summary DTO returned to frontend and callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportSummaryDto {
    pub file_path: String,
    pub spaces_count: usize,
    pub labels_count: usize,
    pub items_count: usize,
    pub environments_count: usize,
    pub secrets_count: usize,
    pub notes_count: usize,
    pub files_count: usize,
    pub bytes_written: usize,
    #[serde(default)]
    pub projects_count: usize,
    #[serde(default)]
    pub assets_count: usize,
}

#[derive(Debug, Clone)]
pub struct SecretDraftDto {
    pub item_id: Option<Uuid>,
    pub project_id: Option<Uuid>,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub kind: SecretKind,
    pub value: String,
    pub note: Option<String>,
}

fn empty_string_as_none<'de, D>(deserializer: D) -> Result<Option<Uuid>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    match opt.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => Uuid::parse_str(s).map(Some).map_err(serde::de::Error::custom),
    }
}

#[derive(Deserialize)]
struct RawSecretDraftDto {
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub item_id: Option<Uuid>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub project_id: Option<Uuid>,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub kind: SecretKind,
    pub value: String,
    pub note: Option<String>,
}

impl<'de> Deserialize<'de> for SecretDraftDto {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawSecretDraftDto::deserialize(deserializer)?;
        let effective_item = raw.item_id.or(raw.project_id);
        let effective_project = raw.project_id.or(raw.item_id);
        Ok(Self {
            item_id: effective_item,
            project_id: effective_project,
            environment_id: raw.environment_id,
            name: raw.name,
            kind: raw.kind,
            value: raw.value,
            note: raw.note,
        })
    }
}

impl From<SecretDraftDto> for SecretDraft {
    fn from(dto: SecretDraftDto) -> Self {
        let target_id = dto.item_id.or(dto.project_id).unwrap_or_else(Uuid::nil);
        SecretDraft::new(
            target_id,
            dto.environment_id,
            dto.name,
            dto.kind,
            dto.value,
            dto.note,
        )
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SettingsPatchDto {
    pub theme: Option<String>,
    #[serde(alias = "lock_minutes")]
    pub lock_timeout_minutes: Option<u32>,
    pub device_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetDownloadDto {
    pub meta: AssetMetaView,
    pub bytes: Vec<u8>,
}

pub type FileDownloadDto = AssetDownloadDto;

#[derive(Debug, Clone, Deserialize)]
pub struct NoteDraftDto {
    #[serde(alias = "project_id")]
    pub item_id: Uuid,
    #[serde(default, deserialize_with = "empty_string_as_none")]
    pub environment_id: Option<Uuid>,
    pub title: String,
    #[serde(alias = "body_html")]
    pub content: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NoteUpdateDto {
    pub title: Option<String>,
    #[serde(alias = "body_html")]
    pub content: Option<String>,
}

// ============================================================================
// 1. Lifecycle Implementation & Commands
// ============================================================================

pub fn secwet_status_impl(state: &AppState) -> Result<SecwetStatusDto, UiError> {
    let guard = state
        .secwet
        .lock()
        .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
    if let Some(secwet) = guard.as_ref() {
        Ok(SecwetStatusDto::Unlocked {
            secwet_id: secwet.secwet_id(),
        })
    } else {
        let status = Secwet::status(&state.data_dir)?;
        Ok(SecwetStatusDto::from(status))
    }
}

pub fn system_device_name_impl() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(output) = std::process::Command::new("scutil")
            .arg("--get")
            .arg("ComputerName")
            .output()
        {
            if output.status.success() {
                let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !name.is_empty() {
                    return name;
                }
            }
        }
    }

    #[cfg(windows)]
    {
        if let Ok(name) = std::env::var("COMPUTERNAME") {
            let trimmed = name.trim().to_string();
            if !trimmed.is_empty() {
                return trimmed;
            }
        }
    }

    if let Ok(output) = std::process::Command::new("hostname").output() {
        if output.status.success() {
            let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !name.is_empty() {
                let clean = name.strip_suffix(".local").unwrap_or(&name);
                return clean.to_string();
            }
        }
    }

    if let Ok(name) = std::env::var("HOSTNAME") {
        let trimmed = name.trim().to_string();
        if !trimmed.is_empty() {
            return trimmed;
        }
    }

    "Desktop".to_string()
}

pub fn secwet_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError> {
    let mut guard = state
        .secwet
        .lock()
        .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
    if guard.is_some() {
        return Err(UiError::already_initialized());
    }

    let real_dev = system_device_name_impl();
    let dev_name = match device_name.as_deref() {
        Some(name) if !name.trim().is_empty() && name != "desktop" => name.trim(),
        _ => &real_dev,
    };
    let secwet = Secwet::create(&state.data_dir, dev_name, state.keystore.as_ref())?;
    let secwet_id = secwet.secwet_id();
    *guard = Some(secwet);

    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "all" }));
    }
    Ok(SecwetStatusDto::Unlocked { secwet_id })
}

pub fn secwet_unlock_impl(app: Option<&AppHandle>, state: &AppState) -> Result<(), UiError> {
    let mut guard = state
        .secwet
        .lock()
        .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
    if guard.is_some() {
        return Ok(());
    }
    if state.in_flight.load(std::sync::atomic::Ordering::SeqCst) > 0 {
        // The store is out for a network call; opening a second copy of the
        // same database would race it.
        return Err(state.locked_or_busy());
    }

    let secwet = Secwet::unlock(&state.data_dir, state.keystore.as_ref())?;
    *guard = Some(secwet);

    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "all" }));
    }
    Ok(())
}

pub fn secwet_lock_impl(app: Option<&AppHandle>, state: &AppState) -> Result<(), UiError> {
    let mut guard = state
        .secwet
        .lock()
        .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
    state.lock_generation.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    if let Some(secwet) = guard.take() {
        secwet.lock();
    }
    if let Ok(mut links) = state.invite_links.lock() {
        links.clear();
    }

    if let Some(app) = app {
        let _ = app.emit("secwet://locked", ());
    }
    Ok(())
}

#[tauri::command]
pub fn secwet_status(state: State<'_, AppState>) -> Result<SecwetStatusDto, UiError> {
    secwet_status_impl(&state)
}

#[tauri::command]
pub fn secwet_create(
    app: AppHandle,
    state: State<'_, AppState>,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError> {
    secwet_create_impl(Some(&app), &state, device_name)
}

#[tauri::command]
pub fn secwet_unlock(app: AppHandle, state: State<'_, AppState>) -> Result<(), UiError> {
    secwet_unlock_impl(Some(&app), &state)
}

#[tauri::command]
pub fn secwet_lock(app: AppHandle, state: State<'_, AppState>) -> Result<(), UiError> {
    secwet_lock_impl(Some(&app), &state)
}

// ============================================================================
// 1.5. Spaces Implementation & Commands
// ============================================================================

pub fn spaces_list_impl(state: &AppState) -> Result<Vec<SpaceView>, UiError> {
    state.with_secwet(|v| v.list_spaces())
}

pub fn space_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    name: String,
    icon: Option<String>,
) -> Result<SpaceView, UiError> {
    let space = state.with_secwet_mut(|v| v.create_space(&name, icon))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "spaces" }));
    }
    Ok(space)
}

pub fn space_rename_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    name: String,
    icon: Option<String>,
) -> Result<SpaceView, UiError> {
    let space = state.with_secwet_mut(|v| v.rename_space(id, &name, icon))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "spaces" }));
    }
    Ok(space)
}

pub fn space_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.delete_space(id))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "spaces" }));
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "labels" }));
    }
    Ok(())
}

pub fn space_reorder_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    ids: Vec<Uuid>,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.reorder_spaces(&ids))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "spaces" }));
    }
    Ok(())
}

#[tauri::command]
pub fn spaces_list(state: State<'_, AppState>) -> Result<Vec<SpaceView>, UiError> {
    spaces_list_impl(&state)
}

#[tauri::command]
pub fn space_create(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    icon: Option<String>,
) -> Result<SpaceView, UiError> {
    space_create_impl(Some(&app), &state, name, icon)
}

#[tauri::command]
pub fn space_rename(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
    icon: Option<String>,
) -> Result<SpaceView, UiError> {
    space_rename_impl(Some(&app), &state, id, name, icon)
}

#[tauri::command]
pub fn space_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<(), UiError> {
    space_delete_impl(Some(&app), &state, id)
}

#[tauri::command]
pub fn space_reorder(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Vec<Uuid>,
) -> Result<(), UiError> {
    space_reorder_impl(Some(&app), &state, ids)
}

// ============================================================================
// 2. Labels Implementation & Commands
// ============================================================================

pub fn labels_list_impl(state: &AppState) -> Result<Vec<LabelView>, UiError> {
    state.with_secwet(|v| v.list_labels())
}

pub fn label_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    name: String,
    icon: Option<String>,
) -> Result<LabelView, UiError> {
    label_create_in_space_impl(app, state, name, icon, None)
}

pub fn label_create_in_space_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    name: String,
    icon: Option<String>,
    space_id: Option<Uuid>,
) -> Result<LabelView, UiError> {
    let label = state.with_secwet_mut(|v| v.create_label_in_space(&name, icon, space_id))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "labels" }));
    }
    Ok(label)
}

pub fn label_rename_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    name: String,
    icon: Option<String>,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.update_label(id, &name, icon))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "labels" }));
    }
    Ok(())
}

pub fn label_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.delete_label(id))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "labels" }));
    }
    Ok(())
}

pub fn label_reorder_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    ids: Vec<Uuid>,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.reorder_labels(&ids))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "labels" }));
    }
    Ok(())
}

#[tauri::command]
pub fn labels_list(state: State<'_, AppState>) -> Result<Vec<LabelView>, UiError> {
    labels_list_impl(&state)
}

#[tauri::command]
pub fn groups_list(state: State<'_, AppState>) -> Result<Vec<LabelView>, UiError> {
    labels_list_impl(&state)
}

#[tauri::command]
pub fn label_create(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    icon: Option<String>,
    space_id: Option<Uuid>,
) -> Result<LabelView, UiError> {
    label_create_in_space_impl(Some(&app), &state, name, icon, space_id)
}

#[tauri::command]
pub fn group_create(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    icon: Option<String>,
    space_id: Option<Uuid>,
) -> Result<LabelView, UiError> {
    label_create_in_space_impl(Some(&app), &state, name, icon, space_id)
}

#[tauri::command]
pub fn group_move_to_space(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    space_id: Uuid,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.move_label_to_space(id, space_id))?;
    let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "labels" }));
    Ok(())
}

#[tauri::command]
pub fn label_rename(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
    icon: Option<String>,
) -> Result<(), UiError> {
    label_rename_impl(Some(&app), &state, id, name, icon)
}

#[tauri::command]
pub fn group_rename(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
    icon: Option<String>,
) -> Result<(), UiError> {
    label_rename_impl(Some(&app), &state, id, name, icon)
}

#[tauri::command]
pub fn label_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<(), UiError> {
    label_delete_impl(Some(&app), &state, id)
}

#[tauri::command]
pub fn group_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<(), UiError> {
    label_delete_impl(Some(&app), &state, id)
}

#[tauri::command]
pub fn label_reorder(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Vec<Uuid>,
) -> Result<(), UiError> {
    label_reorder_impl(Some(&app), &state, ids)
}

#[tauri::command]
pub fn group_reorder(
    app: AppHandle,
    state: State<'_, AppState>,
    ids: Vec<Uuid>,
) -> Result<(), UiError> {
    label_reorder_impl(Some(&app), &state, ids)
}

// ============================================================================
// 3. Items Implementation & Commands
// ============================================================================

pub fn items_list_impl(
    state: &AppState,
    label_id: Option<Uuid>,
) -> Result<Vec<ItemView>, UiError> {
    state.with_secwet(|v| {
        if let Some(lid) = label_id {
            v.list_items(lid)
        } else {
            let labels = v.list_labels()?;
            let mut all_items = Vec::new();
            for l in labels {
                all_items.extend(v.list_items(l.id)?);
            }
            all_items.sort_by_key(|i| (i.position, i.id));
            Ok(all_items)
        }
    })
}

pub fn item_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    label_id: Uuid,
    name: String,
    description: Option<String>,
) -> Result<ItemView, UiError> {
    let item = state.with_secwet_mut(|v| v.create_item(label_id, &name, description))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "items" }));
    }
    Ok(item)
}

pub fn item_rename_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    name: String,
    description: Option<String>,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.rename_item(id, &name, description))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "items" }));
    }
    Ok(())
}

pub fn item_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.delete_item(id))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "items" }));
    }
    Ok(())
}

#[tauri::command]
pub fn items_list(
    state: State<'_, AppState>,
    label_id: Option<Uuid>,
) -> Result<Vec<ItemView>, UiError> {
    items_list_impl(&state, label_id)
}

#[tauri::command]
pub fn item_create(
    app: AppHandle,
    state: State<'_, AppState>,
    label_id: Uuid,
    name: String,
    description: Option<String>,
) -> Result<ItemView, UiError> {
    item_create_impl(Some(&app), &state, label_id, name, description)
}

#[tauri::command]
pub fn item_rename(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
    description: Option<String>,
) -> Result<(), UiError> {
    item_rename_impl(Some(&app), &state, id, name, description)
}

#[tauri::command]
pub fn item_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<(), UiError> {
    item_delete_impl(Some(&app), &state, id)
}

// ============================================================================
// 4. Environments Implementation & Commands
// ============================================================================

pub fn environments_list_impl(
    state: &AppState,
    item_id: Uuid,
) -> Result<Vec<EnvironmentView>, UiError> {
    state.with_secwet(|v| v.list_environments(item_id))
}

pub fn environment_add_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    item_id: Uuid,
    name: String,
) -> Result<EnvironmentView, UiError> {
    let env = state.with_secwet_mut(|v| v.add_environment(item_id, &name))?;
    if let Some(app) = app {
        let _ = app.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "environments" }),
        );
    }
    Ok(env)
}

pub fn environment_rename_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    name: String,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.rename_environment(id, &name))?;
    if let Some(app) = app {
        let _ = app.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "environments" }),
        );
    }
    Ok(())
}

pub fn environment_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    preserve_content: Option<bool>,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| {
        if let Some(preserve) = preserve_content {
            v.delete_environment_with_options(id, preserve)
        } else {
            v.delete_environment(id)
        }
    })?;
    if let Some(app) = app {
        let _ = app.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "environments" }),
        );
    }
    Ok(())
}

#[tauri::command]
pub fn environments_list(
    state: State<'_, AppState>,
    item_id: Uuid,
) -> Result<Vec<EnvironmentView>, UiError> {
    environments_list_impl(&state, item_id)
}

#[tauri::command]
pub fn environment_add(
    app: AppHandle,
    state: State<'_, AppState>,
    item_id: Uuid,
    name: String,
) -> Result<EnvironmentView, UiError> {
    environment_add_impl(Some(&app), &state, item_id, name)
}

#[tauri::command]
pub fn environment_rename(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
) -> Result<(), UiError> {
    environment_rename_impl(Some(&app), &state, id, name)
}

#[tauri::command]
pub fn environment_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    preserve_content: Option<bool>,
) -> Result<(), UiError> {
    environment_delete_impl(Some(&app), &state, id, preserve_content)
}

// ============================================================================
// 5. Secrets Implementation & Commands
// ============================================================================

pub fn secrets_list_impl(
    state: &AppState,
    item_id: Option<Uuid>,
    environment_id: Option<Uuid>,
) -> Result<Vec<SecretMeta>, UiError> {
    state.with_secwet(|v| {
        if let Some(iid) = item_id {
            v.list_secrets(iid, environment_id)
        } else if let Some(eid) = environment_id {
            v.list_environment_secrets(eid)
        } else {
            Err(secwet_core::Error::Invalid {
                field: "item_id",
                message: "Either item_id or environment_id must be provided.".to_string(),
            })
        }
    })
}

pub fn secret_reveal_impl(state: &AppState, id: Uuid) -> Result<String, UiError> {
    state.with_secwet(|v| {
        let secret = v.reveal_secret(id)?;
        Ok(secret.expose_secret().to_string())
    })
}

pub fn secret_copy_impl<C: ClipboardPort>(
    clipboard: Arc<C>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    let secret = state.with_secwet(|v| v.reveal_secret(id))?;
    let manager = AutoClearManager::new(
        clipboard,
        Arc::clone(&state.clipboard_generation),
        state.clear_duration,
    );
    manager
        .copy_secret(secret.expose_secret())
        .map_err(UiError::internal)?;
    Ok(())
}

pub fn secret_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    draft: SecretDraftDto,
) -> Result<SecretMeta, UiError> {
    let meta = state.with_secwet_mut(|v| v.create_secret(draft.into()))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "secrets" }));
    }
    Ok(meta)
}

pub fn secret_update_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    draft: SecretDraftDto,
) -> Result<SecretMeta, UiError> {
    let meta = state.with_secwet_mut(|v| v.update_secret(id, draft.into()))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "secrets" }));
    }
    Ok(meta)
}

pub fn secret_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.delete_secret(id))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "secrets" }));
    }
    Ok(())
}

pub fn secret_copy_to_environment_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    target_environment_id: Option<Uuid>,
) -> Result<SecretMeta, UiError> {
    let meta = state.with_secwet_mut(|v| v.copy_secret_to_environment(id, target_environment_id))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "secrets" }));
    }
    Ok(meta)
}

#[tauri::command]
pub fn secrets_list(
    state: State<'_, AppState>,
    item_id: Option<Uuid>,
    environment_id: Option<Uuid>,
) -> Result<Vec<SecretMeta>, UiError> {
    secrets_list_impl(&state, item_id, environment_id)
}

#[tauri::command]
pub fn secret_reveal(state: State<'_, AppState>, id: Uuid) -> Result<String, UiError> {
    secret_reveal_impl(&state, id)
}

#[tauri::command]
pub fn secret_copy(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    let clipboard = Arc::new(TauriClipboard::new(app));
    secret_copy_impl(clipboard, &state, id)
}

#[tauri::command]
pub fn secret_create(
    app: AppHandle,
    state: State<'_, AppState>,
    draft: SecretDraftDto,
) -> Result<SecretMeta, UiError> {
    secret_create_impl(Some(&app), &state, draft)
}

#[tauri::command]
pub fn secret_update(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    draft: SecretDraftDto,
) -> Result<SecretMeta, UiError> {
    secret_update_impl(Some(&app), &state, id, draft)
}

#[tauri::command]
pub fn secret_delete(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    secret_delete_impl(Some(&app), &state, id)
}

#[tauri::command]
pub fn secret_copy_to_environment(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    target_environment_id: Option<Uuid>,
) -> Result<SecretMeta, UiError> {
    secret_copy_to_environment_impl(Some(&app), &state, id, target_environment_id)
}

// ============================================================================
// 6. Files Implementation & Commands
// ============================================================================
// 6. Assets Implementation & Commands (F5b)
// ============================================================================

pub fn assets_list_impl(
    state: &AppState,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<AssetMetaView>, UiError> {
    state.with_secwet(|v| v.list_assets(item_id, environment_id))
}

pub fn files_list_impl(
    state: &AppState,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<FileMetaView>, UiError> {
    assets_list_impl(state, item_id, environment_id)
}

pub fn asset_upload_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    item_id: Uuid,
    environment_id: Option<Uuid>,
    name: String,
    mime: Option<String>,
    bytes: Vec<u8>,
) -> Result<AssetMetaView, UiError> {
    let meta = state.with_secwet_mut(|v| {
        v.upload_asset(item_id, environment_id, &name, &bytes, mime.as_deref())
    })?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "assets" }));
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "files" }));
    }
    Ok(meta)
}

pub fn file_upload_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    item_id: Uuid,
    environment_id: Option<Uuid>,
    name: String,
    mime: Option<String>,
    bytes: Vec<u8>,
) -> Result<FileMetaView, UiError> {
    asset_upload_impl(app, state, item_id, environment_id, name, mime, bytes)
}

pub fn asset_download_impl(
    state: &AppState,
    id: Uuid,
) -> Result<AssetDownloadDto, UiError> {
    state.with_secwet(|v| {
        let (meta, bytes) = v.download_asset(id)?;
        Ok(AssetDownloadDto { meta, bytes })
    })
}

pub fn file_download_impl(
    state: &AppState,
    id: Uuid,
) -> Result<FileDownloadDto, UiError> {
    asset_download_impl(state, id)
}

pub fn asset_rename_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    name: String,
) -> Result<AssetMetaView, UiError> {
    let meta = state.with_secwet_mut(|v| v.rename_asset(id, &name))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "assets" }));
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "files" }));
    }
    Ok(meta)
}

pub fn file_rename_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    name: String,
) -> Result<FileMetaView, UiError> {
    asset_rename_impl(app, state, id, name)
}

pub fn asset_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.delete_asset(id))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "assets" }));
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "files" }));
    }
    Ok(())
}

pub fn file_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    asset_delete_impl(app, state, id)
}

#[tauri::command]
pub fn assets_list(
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<AssetMetaView>, UiError> {
    assets_list_impl(&state, item_id, environment_id)
}

#[tauri::command]
pub fn files_list(
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<FileMetaView>, UiError> {
    assets_list_impl(&state, item_id, environment_id)
}

#[tauri::command]
pub fn asset_upload(
    app: AppHandle,
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
    name: String,
    mime: Option<String>,
    bytes: Vec<u8>,
) -> Result<AssetMetaView, UiError> {
    asset_upload_impl(Some(&app), &state, item_id, environment_id, name, mime, bytes)
}

#[tauri::command]
pub fn file_upload(
    app: AppHandle,
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
    name: String,
    mime: Option<String>,
    bytes: Vec<u8>,
) -> Result<FileMetaView, UiError> {
    asset_upload_impl(Some(&app), &state, item_id, environment_id, name, mime, bytes)
}

#[tauri::command]
pub fn asset_download(
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<AssetDownloadDto, UiError> {
    asset_download_impl(&state, id)
}

#[tauri::command]
pub fn file_download(
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<FileDownloadDto, UiError> {
    asset_download_impl(&state, id)
}

#[tauri::command]
pub fn asset_rename(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
) -> Result<AssetMetaView, UiError> {
    asset_rename_impl(Some(&app), &state, id, name)
}

#[tauri::command]
pub fn file_rename(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
) -> Result<FileMetaView, UiError> {
    asset_rename_impl(Some(&app), &state, id, name)
}

#[tauri::command]
pub fn asset_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<(), UiError> {
    asset_delete_impl(Some(&app), &state, id)
}

#[tauri::command]
pub fn file_delete(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
) -> Result<(), UiError> {
    asset_delete_impl(Some(&app), &state, id)
}

// ============================================================================
// 7. Notes Implementation & Commands
// ============================================================================

pub fn notes_list_impl(
    state: &AppState,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<NoteMetaView>, UiError> {
    state.with_secwet(|v| v.list_notes(item_id, environment_id))
}

pub fn note_get_impl(state: &AppState, id: Uuid) -> Result<NoteView, UiError> {
    state.with_secwet(|v| v.get_note(id))
}

pub fn note_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    draft: NoteDraftDto,
) -> Result<NoteView, UiError> {
    let note = state.with_secwet_mut(|v| {
        v.create_note(draft.item_id, draft.environment_id, &draft.title, &draft.content)
    })?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "notes" }));
    }
    Ok(note)
}

pub fn note_update_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    draft: NoteUpdateDto,
) -> Result<NoteView, UiError> {
    let note = state.with_secwet_mut(|v| {
        v.update_note(id, draft.title.as_deref(), draft.content.as_deref())
    })?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "notes" }));
    }
    Ok(note)
}

pub fn note_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.delete_note(id))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "notes" }));
    }
    Ok(())
}

pub fn note_copy_plain_impl<C: ClipboardPort>(
    clipboard: Arc<C>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    let note = state.with_secwet(|v| v.get_note(id))?;
    let plain_text = extract_plain_text(&note.content);
    let manager = AutoClearManager::new(
        clipboard,
        Arc::clone(&state.clipboard_generation),
        state.clear_duration,
    );
    manager
        .copy_secret(&plain_text)
        .map_err(UiError::internal)?;
    Ok(())
}

pub fn clipboard_copy_text_impl<C: ClipboardPort>(
    clipboard: Arc<C>,
    state: &AppState,
    text: String,
) -> Result<(), UiError> {
    state.with_secwet(|_| Ok(()))?;
    let plain_text = extract_plain_text(&text);
    let manager = AutoClearManager::new(
        clipboard,
        Arc::clone(&state.clipboard_generation),
        state.clear_duration,
    );
    manager
        .copy_secret(&plain_text)
        .map_err(UiError::internal)?;
    Ok(())
}

#[tauri::command]
pub fn notes_list(
    state: State<'_, AppState>,
    item_id: Uuid,
    environment_id: Option<Uuid>,
) -> Result<Vec<NoteMetaView>, UiError> {
    notes_list_impl(&state, item_id, environment_id)
}

#[tauri::command]
pub fn note_get(state: State<'_, AppState>, id: Uuid) -> Result<NoteView, UiError> {
    note_get_impl(&state, id)
}

#[tauri::command]
pub fn note_create(
    app: AppHandle,
    state: State<'_, AppState>,
    draft: NoteDraftDto,
) -> Result<NoteView, UiError> {
    note_create_impl(Some(&app), &state, draft)
}

#[tauri::command]
pub fn note_update(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    draft: NoteUpdateDto,
) -> Result<NoteView, UiError> {
    note_update_impl(Some(&app), &state, id, draft)
}

#[tauri::command]
pub fn note_delete(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    note_delete_impl(Some(&app), &state, id)
}

#[tauri::command]
pub fn note_copy_plain(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    let clipboard = Arc::new(TauriClipboard::new(app));
    note_copy_plain_impl(clipboard, &state, id)
}

#[tauri::command]
pub fn clipboard_copy_text(
    app: AppHandle,
    state: State<'_, AppState>,
    text: String,
) -> Result<(), UiError> {
    let clipboard = Arc::new(TauriClipboard::new(app));
    clipboard_copy_text_impl(clipboard, &state, text)
}

// ============================================================================
// 8. Overview & Dashboard Implementation & Commands
// ============================================================================

pub fn overview_impl(state: &AppState) -> Result<Overview, UiError> {
    state.with_secwet(|v| v.overview())
}

pub fn dashboard_get_impl(state: &AppState) -> Result<DashboardConfig, UiError> {
    state.with_secwet(|v| v.dashboard_config())
}

pub fn dashboard_set_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    config: DashboardConfig,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.set_dashboard_config(&config))?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "dashboard" }));
    }
    Ok(())
}

#[tauri::command]
pub fn overview(state: State<'_, AppState>) -> Result<Overview, UiError> {
    overview_impl(&state)
}

#[tauri::command]
pub fn dashboard_get(state: State<'_, AppState>) -> Result<DashboardConfig, UiError> {
    dashboard_get_impl(&state)
}

#[tauri::command]
pub fn dashboard_set(
    app: AppHandle,
    state: State<'_, AppState>,
    config: DashboardConfig,
) -> Result<(), UiError> {
    dashboard_set_impl(Some(&app), &state, config)
}

// ============================================================================
// 9. Settings Implementation & Commands
// ============================================================================

pub fn settings_get_impl(state: &AppState) -> Result<Settings, UiError> {
    state.with_secwet(|v| {
        let mut s = v.settings()?;
        if s.device_name.trim().is_empty()
            || s.device_name == "desktop"
            || s.device_name == "default-device"
        {
            s.device_name = system_device_name_impl();
        }
        Ok(s)
    })
}

#[tauri::command]
pub fn system_device_name() -> Result<String, UiError> {
    Ok(system_device_name_impl())
}

pub fn settings_set_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    settings: SettingsPatchDto,
) -> Result<Settings, UiError> {
    let updated = state.with_secwet_mut(|v| {
        let mut current = v.settings()?;
        if let Some(t) = settings.theme {
            current.theme = t;
        }
        if let Some(m) = settings.lock_timeout_minutes {
            current.lock_timeout_minutes = m;
        }
        if let Some(d) = settings.device_name {
            current.device_name = d;
        }
        v.set_settings(current.clone())?;
        Ok(current)
    })?;
    if let Some(app) = app {
        let _ = app.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "settings" }),
        );
    }
    Ok(updated)
}

#[tauri::command]
pub fn settings_get(state: State<'_, AppState>) -> Result<Settings, UiError> {
    settings_get_impl(&state)
}

#[tauri::command]
pub fn settings_set(
    app: AppHandle,
    state: State<'_, AppState>,
    settings: SettingsPatchDto,
) -> Result<Settings, UiError> {
    settings_set_impl(Some(&app), &state, settings)
}

// ============================================================================
// 10. Backward Compatibility (Projects) Implementation & Commands
// ============================================================================

pub fn projects_list_impl(state: &AppState) -> Result<Vec<ProjectView>, UiError> {
    state.with_secwet(|v| v.list_projects())
}

pub fn project_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    name: String,
    environments: Vec<String>,
) -> Result<ProjectView, UiError> {
    let project = state.with_secwet_mut(|v| v.create_project(&name, &environments))?;
    if let Some(app) = app {
        let _ = app.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "items" }),
        );
    }
    Ok(project)
}

pub fn project_rename_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    name: String,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.rename_project(id, &name))?;
    if let Some(app) = app {
        let _ = app.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "items" }),
        );
    }
    Ok(())
}

pub fn project_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_secwet_mut(|v| v.delete_project(id))?;
    if let Some(app) = app {
        let _ = app.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "items" }),
        );
    }
    Ok(())
}

#[tauri::command]
pub fn projects_list(state: State<'_, AppState>) -> Result<Vec<ProjectView>, UiError> {
    projects_list_impl(&state)
}

#[tauri::command]
pub fn project_create(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    environments: Vec<String>,
) -> Result<ProjectView, UiError> {
    project_create_impl(Some(&app), &state, name, environments)
}

#[tauri::command]
pub fn project_rename(
    app: AppHandle,
    state: State<'_, AppState>,
    id: Uuid,
    name: String,
) -> Result<(), UiError> {
    project_rename_impl(Some(&app), &state, id, name)
}

#[tauri::command]
pub fn project_delete(app: AppHandle, state: State<'_, AppState>, id: Uuid) -> Result<(), UiError> {
    project_delete_impl(Some(&app), &state, id)
}

#[tauri::command]
pub fn biometric_status() -> Result<crate::biometric::BiometricStatus, UiError> {
    Ok(crate::biometric::check_biometric_available())
}

#[tauri::command]
pub async fn biometric_authenticate(reason: Option<String>) -> Result<bool, UiError> {
    tokio::task::spawn_blocking(move || {
        crate::biometric::authenticate(reason.as_deref())
    })
    .await
    .map_err(|e| UiError::internal(format!("Biometric task join error: {}", e)))?
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

#[tauri::command]
pub fn active_sessions_list(state: State<'_, AppState>) -> Result<Vec<ActiveSession>, UiError> {
    state.with_secwet(|v| v.list_active_sessions())
}

#[tauri::command]
pub fn active_session_stop(
    app: AppHandle,
    state: State<'_, AppState>,
    session_id: String,
) -> Result<(), UiError> {
    state.with_secwet(|v| v.stop_active_session(&session_id))?;
    let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "sessions" }));
    Ok(())
}

// ============================================================================
// 12. Recovery & Backup
// ============================================================================

pub fn recovery_key_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
) -> Result<String, UiError> {
    let key = state.with_secwet_mut(|secwet| {
        secwet.create_recovery_key(state.keystore.as_ref())
    })?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "settings" }));
    }
    Ok(key.expose_secret().to_string())
}

#[tauri::command]
pub fn recovery_key_create(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, UiError> {
    recovery_key_create_impl(Some(&app), &state)
}

pub fn recovery_key_replace_impl(
    app: Option<&AppHandle>,
    state: &AppState,
) -> Result<String, UiError> {
    let key = state.with_secwet_mut(|secwet| {
        secwet.replace_recovery_key(state.keystore.as_ref())
    })?;
    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "settings" }));
    }
    Ok(key.expose_secret().to_string())
}

#[tauri::command]
pub fn recovery_key_replace(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, UiError> {
    recovery_key_replace_impl(Some(&app), &state)
}

pub fn recovery_status_impl(state: &AppState) -> Result<RecoveryStatusDto, UiError> {
    state.with_secwet(|secwet| {
        let status = secwet.recovery_status()?;
        Ok(RecoveryStatusDto {
            created: status.created,
            created_at: status.created_at,
        })
    })
}

#[tauri::command]
pub fn recovery_status(state: State<'_, AppState>) -> Result<RecoveryStatusDto, UiError> {
    recovery_status_impl(&state)
}

pub fn workspace_export_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    path: Option<PathBuf>,
    recovery_key: String,
) -> Result<ExportSummaryDto, UiError> {
    let out_path = match path {
        Some(p) => p,
        None => {
            let app = app.ok_or_else(|| {
                UiError::invalid("path", "Export path is required when running in headless mode")
            })?;
            use tauri_plugin_dialog::DialogExt;
            let file_path = app
                .dialog()
                .file()
                .add_filter("Secwet Archive", &["secwet"])
                .blocking_save_file()
                .ok_or_else(|| UiError::invalid("path", "Export cancelled"))?;
            file_path
                .into_path()
                .map_err(|e| UiError::invalid("path", e.to_string()))?
        }
    };

    let recovery_secret = SecretString::from(recovery_key);
    let summary = state.with_secwet(|secwet| {
        secwet.export_encrypted(&recovery_secret, &out_path)
    })?;

    Ok(ExportSummaryDto {
        file_path: out_path.to_string_lossy().to_string(),
        spaces_count: summary.spaces_count,
        labels_count: summary.labels_count,
        items_count: summary.items_count,
        environments_count: summary.environments_count,
        secrets_count: summary.secrets_count,
        notes_count: summary.notes_count,
        files_count: summary.files_count,
        bytes_written: summary.bytes_written,
        projects_count: summary.projects_count,
        assets_count: summary.assets_count,
    })
}

#[tauri::command]
pub fn workspace_export(
    app: AppHandle,
    state: State<'_, AppState>,
    path: Option<PathBuf>,
    recovery_key: String,
) -> Result<ExportSummaryDto, UiError> {
    workspace_export_impl(Some(&app), &state, path, recovery_key)
}

pub fn workspace_restore_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    path: Option<PathBuf>,
    recovery_key: String,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError> {
    let in_path = match path {
        Some(p) => p,
        None => {
            let app = app.ok_or_else(|| {
                UiError::invalid("path", "Restore path is required when running in headless mode")
            })?;
            use tauri_plugin_dialog::DialogExt;
            let file_path = app
                .dialog()
                .file()
                .add_filter("Secwet Archive", &["secwet"])
                .blocking_pick_file()
                .ok_or_else(|| UiError::invalid("path", "Restore cancelled"))?;
            file_path
                .into_path()
                .map_err(|e| UiError::invalid("path", e.to_string()))?
        }
    };

    // Close any open secwet instance before restoring to avoid file lock conflicts
    {
        let mut guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        if let Some(old) = guard.take() {
            old.lock();
        }
    }

    let real_dev = system_device_name_impl();
    let dev_name = match device_name.as_deref() {
        Some(name) if !name.trim().is_empty() && name != "desktop" => name.trim(),
        _ => &real_dev,
    };

    let recovery_secret = SecretString::from(recovery_key);
    let secwet = Secwet::restore_from_export(
        &state.data_dir,
        &in_path,
        &recovery_secret,
        dev_name,
        state.keystore.as_ref(),
    )?;

    let secwet_id = secwet.secwet_id();
    {
        let mut guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        *guard = Some(secwet);
    }

    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "all" }));
    }

    Ok(SecwetStatusDto::Unlocked { secwet_id })
}

#[tauri::command]
pub fn workspace_restore(
    app: AppHandle,
    state: State<'_, AppState>,
    path: Option<PathBuf>,
    recovery_key: String,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError> {
    workspace_restore_impl(Some(&app), &state, path, recovery_key, device_name)
}

pub async fn relay_status_impl(state: &AppState) -> Result<secwet_proto::RelayStatusDto, UiError> {
    let (relay_url, plan, device_id, secwet_id, sign_key, active_devices) = {
        let guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = guard.as_ref().ok_or_else(UiError::locked)?;
        (
            secwet.relay_url().map_err(UiError::from)?,
            secwet.plan().map_err(UiError::from)?,
            secwet.device_id().to_string(),
            secwet.secwet_id(),
            secwet.device_sign_key().clone(),
            secwet.active_devices_count().unwrap_or(1),
        )
    };

    let client = secwet_core::RelayClient::new(&relay_url, &device_id);
    let connected = client.health().await.is_ok();
    let mut device_limit = if plan == "pro" { 5 } else { 1 };
    let mut expires_at = None;

    if connected {
        if let Ok(ent) = client.get_entitlement(secwet_id, &sign_key).await {
            device_limit = ent.device_limit;
            expires_at = ent.expires_at;
        }
    }

    Ok(secwet_proto::RelayStatusDto {
        connected,
        relay_url,
        plan,
        device_limit,
        active_devices,
        expires_at,
        pending_outbox_count: 0,
    })
}

#[tauri::command]
pub async fn relay_status(
    state: State<'_, AppState>,
) -> Result<secwet_proto::RelayStatusDto, UiError> {
    relay_status_impl(&state).await
}

pub async fn relay_register_impl(
    state: &AppState,
) -> Result<secwet_proto::RegisterSecwetResponse, UiError> {
    let (relay_url, device_id, secwet_id, sign_pub, enc_pub, sign_key) = {
        let guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = guard.as_ref().ok_or_else(UiError::locked)?;
        (
            secwet.relay_url().map_err(UiError::from)?,
            secwet.device_id().to_string(),
            secwet.secwet_id(),
            secwet.device_sign_pub(),
            secwet.device_enc_pub(),
            secwet.device_sign_key().clone(),
        )
    };

    let client = secwet_core::RelayClient::new(&relay_url, &device_id);
    let res = client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .map_err(UiError::from)?;

    {
        let mut guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        if let Some(secwet) = guard.as_mut() {
            let _ = secwet.set_plan("pro");
        }
    }

    Ok(res)
}

#[tauri::command]
pub async fn relay_register(
    state: State<'_, AppState>,
) -> Result<secwet_proto::RegisterSecwetResponse, UiError> {
    relay_register_impl(&state).await
}

pub fn relay_set_url_impl(state: &AppState, url: String) -> Result<(), UiError> {
    let mut guard = state
        .secwet
        .lock()
        .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
    let secwet = guard.as_mut().ok_or_else(UiError::locked)?;
    secwet.set_relay_url(&url).map_err(UiError::from)
}

#[tauri::command]
pub fn relay_set_url(state: State<'_, AppState>, url: String) -> Result<(), UiError> {
    relay_set_url_impl(&state, url)
}

// ============================================================================
// 14. Devices & Pairing (F14)
// ============================================================================

pub fn devices_list_impl(state: &AppState) -> Result<Vec<secwet_proto::DeviceDto>, UiError> {
    state.with_secwet(|s| s.devices_list())
}

#[tauri::command]
pub fn devices_list(state: State<'_, AppState>) -> Result<Vec<secwet_proto::DeviceDto>, UiError> {
    devices_list_impl(&state)
}

pub fn device_revoke_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    device_id: String,
) -> Result<(), UiError> {
    state.with_secwet_mut(|s| s.device_revoke(&device_id))?;
    if let Some(handle) = app {
        let _ = handle.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "devices" }),
        );
    }
    Ok(())
}


pub async fn pairing_start_impl(
    state: &AppState,
) -> Result<secwet_proto::PairingSessionInfo, UiError> {
    let (secwet_id, relay_url, sign_key) = {
        let guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = guard.as_ref().ok_or_else(UiError::locked)?;
        let relay_url = secwet.relay_url().unwrap_or_else(|_| "http://127.0.0.1:8787".into());
        (
            secwet.secwet_id(),
            relay_url,
            secwet.device_sign_key().clone(),
        )
    };

    let (a_eph_secret, a_eph_pub) = secwet_core::crypto::generate_ephemeral_x25519();
    let client = secwet_core::RelayClient::new(&relay_url, "desktop");

    let (session_id, expires_at, qr_payload) = match client
        .create_pairing_session(secwet_id, a_eph_pub, &sign_key)
        .await
    {
        Ok(resp) => (resp.session_id, resp.expires_at, resp.qr_payload),
        Err(_) => {
            // Offline fallback / local pairing session
            let session_id = Uuid::new_v4();
            let expires = (chrono::Utc::now() + chrono::Duration::minutes(5)).to_rfc3339();
            let host = relay_url
                .trim_start_matches("http://")
                .trim_start_matches("https://");
            let qr = secwet_core::crypto::format_pairing_qr_payload(&session_id, &a_eph_pub, host);
            (session_id, expires, qr)
        }
    };

    let active_session = crate::state::ActivePairingSession {
        session_id,
        a_eph_secret,
        a_eph_pub,
        expires_at: expires_at.clone(),
        qr_payload: qr_payload.clone(),
        cached_peer: None,
    };

    {
        let mut guard = state
            .active_pairing
            .lock()
            .map_err(|_| UiError::internal("Active pairing mutex poisoned"))?;
        *guard = Some(active_session);
    }

    Ok(secwet_proto::PairingSessionInfo {
        session_id,
        expires_at,
        qr_payload,
    })
}

#[tauri::command]
pub async fn pairing_start(
    state: State<'_, AppState>,
) -> Result<secwet_proto::PairingSessionInfo, UiError> {
    pairing_start_impl(&state).await
}

pub async fn pairing_poll_impl(
    state: &AppState,
) -> Result<secwet_proto::PairingPollResponse, UiError> {
    let (session_id, a_eph_secret_bytes, a_eph_pub, relay_url, sign_key) = {
        let guard = state
            .active_pairing
            .lock()
            .map_err(|_| UiError::internal("Active pairing mutex poisoned"))?;
        let session = match guard.as_ref() {
            Some(s) => s,
            None => return Ok(secwet_proto::PairingPollResponse::Expired),
        };

        if let Some(peer) = &session.cached_peer {
            return Ok(secwet_proto::PairingPollResponse::Found {
                name: peer.profile.name.clone(),
                platform: peer.profile.platform.clone(),
                fingerprint: peer.fingerprint.clone(),
                code: peer.sas.clone(),
                device_id: peer.device_id.clone(),
            });
        }

        let s_guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = s_guard.as_ref().ok_or_else(UiError::locked)?;
        let relay_url = secwet.relay_url().unwrap_or_else(|_| "http://127.0.0.1:8787".into());

        (
            session.session_id,
            session.a_eph_secret.to_bytes(),
            session.a_eph_pub,
            relay_url,
            secwet.device_sign_key().clone(),
        )
    };

    let client = secwet_core::RelayClient::new(&relay_url, "desktop");
    let status_resp = match client.get_pairing_status(session_id, &sign_key).await {
        Ok(s) => s,
        Err(_) => return Ok(secwet_proto::PairingPollResponse::Waiting),
    };

    if status_resp.status == "joined" {
        if let Some(join_payload) = status_resp.join_payload {
            let secret = x25519_dalek::StaticSecret::from(a_eph_secret_bytes);
            let shared = secwet_core::crypto::compute_pairing_shared_secret(&secret, &join_payload.n_eph_pub)
                .map_err(|_| UiError::internal("Failed to compute pairing shared secret"))?;

            let profile = secwet_core::crypto::open_pairing_profile(&shared, &join_payload.sealed_profile)
                .map_err(|_| UiError::internal("Failed to open pairing profile"))?;

            let sas = secwet_core::crypto::compute_pairing_sas(
                &shared,
                &session_id,
                &a_eph_pub,
                &join_payload.n_eph_pub,
                &join_payload.sign_pub,
                &join_payload.enc_pub,
            )
            .map_err(|_| UiError::internal("Failed to compute pairing SAS"))?;

            let fingerprint = secwet_core::crypto::compute_fingerprint(&join_payload.sign_pub, &join_payload.enc_pub);
            let device_id = secwet_core::crypto::compute_device_id(&join_payload.sign_pub);

            let peer = crate::state::ActivePairingPeer {
                join_req: join_payload,
                profile: profile.clone(),
                sas: sas.clone(),
                fingerprint: fingerprint.clone(),
                device_id: device_id.clone(),
            };

            {
                let mut guard = state
                    .active_pairing
                    .lock()
                    .map_err(|_| UiError::internal("Active pairing mutex poisoned"))?;
                if let Some(session) = guard.as_mut() {
                    session.cached_peer = Some(peer);
                }
            }

            return Ok(secwet_proto::PairingPollResponse::Found {
                name: profile.name,
                platform: profile.platform,
                fingerprint,
                code: sas,
                device_id,
            });
        }
    } else if status_resp.status == "expired" {
        return Ok(secwet_proto::PairingPollResponse::Expired);
    } else if status_resp.status == "approved" {
        return Ok(secwet_proto::PairingPollResponse::Approved);
    }

    Ok(secwet_proto::PairingPollResponse::Waiting)
}

#[tauri::command]
pub async fn pairing_poll(
    state: State<'_, AppState>,
) -> Result<secwet_proto::PairingPollResponse, UiError> {
    pairing_poll_impl(&state).await
}

pub async fn pairing_approve_impl(
    app: Option<&AppHandle>,
    state: &AppState,
) -> Result<secwet_proto::DeviceDto, UiError> {
    let (session_id, peer, secwet_id, relay_url, sign_key, master_keys) = {
        let mut guard = state
            .active_pairing
            .lock()
            .map_err(|_| UiError::internal("Active pairing mutex poisoned"))?;
        let session = guard.take().ok_or_else(|| UiError::new("bad_request", None, "No active pairing session"))?;
        let peer = session.cached_peer.ok_or_else(|| UiError::new("bad_request", None, "No device has joined pairing yet"))?;

        let s_guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = s_guard.as_ref().ok_or_else(UiError::locked)?;
        let relay_url = secwet.relay_url().unwrap_or_else(|_| "http://127.0.0.1:8787".into());
        let secwet_id = secwet.secwet_id();
        let sign_key = secwet.device_sign_key().clone();

        // Every epoch must be wrapped: the relay refuses an approval that
        // leaves the new device without a key it needs.
        let mut master_keys = Vec::new();
        for ep in 1..=secwet.key_epoch() {
            let k_vec = secwet_core::collab::load_master_key(state.keystore.as_ref(), &secwet_id, ep)
                .map_err(UiError::from)?
                .ok_or_else(|| UiError::new("keystore_error", None, "A key this device needs is missing from secure storage."))?;
            let k: [u8; 32] = k_vec
                .as_slice()
                .try_into()
                .map_err(|_| UiError::new("keystore_error", None, "Secure storage error."))?;
            master_keys.push((ep, k));
        }

        (session.session_id, peer, secwet_id, relay_url, sign_key, master_keys)
    };

    // 1. Wrap master keys with HPKE for new device's enc_pub
    let wrapped_keys = secwet_core::crypto::wrap_master_keys_for_device(
        &master_keys,
        &peer.join_req.enc_pub,
        &peer.device_id,
        &secwet_id,
    )
    .map_err(|_| UiError::internal("Failed to wrap master keys for new device"))?;

    // 2. Create signed approval record
    let (approval, signature) = secwet_core::crypto::create_pairing_approval(
        &secwet_id,
        &session_id,
        &peer.device_id,
        &peer.join_req.sign_pub,
        &peer.join_req.enc_pub,
        &sign_key,
    )
    .map_err(|_| UiError::internal("Failed to sign pairing approval"))?;

    let approve_req = secwet_proto::PairingApproveRequest {
        approval,
        signature,
        wrapped_keys,
    };

    // 3. Post approval to the relay; a rejected approval must not be recorded locally.
    let device_label = state.with_secwet(|s| Ok(s.device_id().to_string()))?;
    let client = secwet_core::RelayClient::new(&relay_url, device_label);
    match client.approve_pairing(session_id, &approve_req, &sign_key).await {
        Ok(_) | Err(secwet_core::Error::Offline) => {}
        Err(e) => return Err(UiError::from(e)),
    }

    // 4. Record new device in local store
    let device_dto = {
        let mut guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = guard.as_mut().ok_or_else(UiError::locked)?;
        secwet.record_paired_device(
            &peer.device_id,
            &peer.profile.name,
            &peer.profile.platform,
            &peer.join_req.sign_pub,
            &peer.join_req.enc_pub,
        )
        .map_err(UiError::from)?
    };

    if let Some(handle) = app {
        let _ = handle.emit(
            "secwet://changed",
            serde_json::json!({ "scope": "devices" }),
        );
    }

    Ok(device_dto)
}

#[tauri::command]
pub async fn pairing_approve(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<secwet_proto::DeviceDto, UiError> {
    pairing_approve_impl(Some(&app), &state).await
}

#[tauri::command]
pub fn pairing_cancel(state: State<'_, AppState>) -> Result<(), UiError> {
    let mut guard = state
        .active_pairing
        .lock()
        .map_err(|_| UiError::internal("Active pairing mutex poisoned"))?;
    *guard = None;
    Ok(())
}

// ============================================================================
// Sync Commands (M6)
// ============================================================================

#[derive(Debug, Clone, serde::Serialize)]
pub struct SyncStatusDto {
    pub pending_outbox_count: u32,
    pub sync_cursor: u64,
}

#[tauri::command]
pub async fn sync_now(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, UiError> {
    let (pushed, pulled) = crate::collab_commands::sync_round_impl(Some(&app), &state).await?;
    Ok(serde_json::json!({
        "pushed": pushed,
        "pulled": pulled,
    }))
}

#[tauri::command]
pub fn sync_status(state: State<'_, AppState>) -> Result<SyncStatusDto, UiError> {
    state.with_secwet(|secwet| {
        let pending_outbox_count = secwet.pending_outbox_count().unwrap_or(0) as u32;
        let sync_cursor = secwet.sync_cursor().unwrap_or(0);
        Ok(SyncStatusDto {
            pending_outbox_count,
            sync_cursor,
        })
    })
}




