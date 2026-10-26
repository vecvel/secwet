//! Tauri 2 IPC commands implementation for Secwet Desktop.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §9.1 and `PROJECT.md`.
//!
//! Invariants:
//! - All commands return `Result<T, UiError>`.
//! - Secrets and file bytes are never exposed in listings or overview.
//! - Clipboard copy is executed entirely in Rust with 30s auto-clear.
//! - Events are emitted on mutations (`vault://changed { scope }`) and lock (`vault://locked`).
//! - Pure `*_impl` functions enable headless unit and adversarial testing.

use std::sync::Arc;

use secrecy::ExposeSecret;
use secwet_core::model::{
    AssetMetaView, DashboardConfig, EnvironmentView, FileMetaView, ItemView, LabelView,
    NoteMetaView, NoteView, Overview, ProjectView, SecretDraft, SecretKind, SecretMeta,
};
use secwet_core::vault::Settings;
use secwet_core::Vault;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::clipboard::{extract_plain_text, AutoClearManager, ClipboardPort, TauriClipboard};
use crate::error::UiError;
use crate::state::{AppState, VaultStatusDto};

// ============================================================================
// DTOs
// ============================================================================

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

pub fn vault_status_impl(state: &AppState) -> Result<VaultStatusDto, UiError> {
    let guard = state
        .vault
        .lock()
        .map_err(|_| UiError::internal("Vault mutex poisoned"))?;
    if let Some(vault) = guard.as_ref() {
        Ok(VaultStatusDto::Unlocked {
            vault_id: vault.vault_id(),
        })
    } else {
        let status = Vault::status(&state.data_dir)?;
        Ok(VaultStatusDto::from(status))
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

pub fn vault_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    device_name: Option<String>,
) -> Result<VaultStatusDto, UiError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| UiError::internal("Vault mutex poisoned"))?;
    if guard.is_some() {
        return Err(UiError::already_initialized());
    }

    let real_dev = system_device_name_impl();
    let dev_name = match device_name.as_deref() {
        Some(name) if !name.trim().is_empty() && name != "desktop" => name.trim(),
        _ => &real_dev,
    };
    let vault = Vault::create(&state.data_dir, dev_name, state.keystore.as_ref())?;
    let vault_id = vault.vault_id();
    *guard = Some(vault);

    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "all" }));
    }
    Ok(VaultStatusDto::Unlocked { vault_id })
}

pub fn vault_unlock_impl(app: Option<&AppHandle>, state: &AppState) -> Result<(), UiError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| UiError::internal("Vault mutex poisoned"))?;
    if guard.is_some() {
        return Ok(());
    }

    let vault = Vault::unlock(&state.data_dir, state.keystore.as_ref())?;
    *guard = Some(vault);

    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "all" }));
    }
    Ok(())
}

pub fn vault_lock_impl(app: Option<&AppHandle>, state: &AppState) -> Result<(), UiError> {
    let mut guard = state
        .vault
        .lock()
        .map_err(|_| UiError::internal("Vault mutex poisoned"))?;
    if let Some(vault) = guard.take() {
        vault.lock();
    }

    if let Some(app) = app {
        let _ = app.emit("vault://locked", ());
    }
    Ok(())
}

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> Result<VaultStatusDto, UiError> {
    vault_status_impl(&state)
}

#[tauri::command]
pub fn vault_create(
    app: AppHandle,
    state: State<'_, AppState>,
    device_name: Option<String>,
) -> Result<VaultStatusDto, UiError> {
    vault_create_impl(Some(&app), &state, device_name)
}

#[tauri::command]
pub fn vault_unlock(app: AppHandle, state: State<'_, AppState>) -> Result<(), UiError> {
    vault_unlock_impl(Some(&app), &state)
}

#[tauri::command]
pub fn vault_lock(app: AppHandle, state: State<'_, AppState>) -> Result<(), UiError> {
    vault_lock_impl(Some(&app), &state)
}

// ============================================================================
// 2. Labels Implementation & Commands
// ============================================================================

pub fn labels_list_impl(state: &AppState) -> Result<Vec<LabelView>, UiError> {
    state.with_vault(|v| v.list_labels())
}

pub fn label_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    name: String,
    icon: Option<String>,
) -> Result<LabelView, UiError> {
    let label = state.with_vault_mut(|v| v.create_label(&name, icon))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "labels" }));
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
    state.with_vault_mut(|v| v.update_label(id, &name, icon))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "labels" }));
    }
    Ok(())
}

pub fn label_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_vault_mut(|v| v.delete_label(id))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "labels" }));
    }
    Ok(())
}

pub fn label_reorder_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    ids: Vec<Uuid>,
) -> Result<(), UiError> {
    state.with_vault_mut(|v| v.reorder_labels(&ids))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "labels" }));
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
) -> Result<LabelView, UiError> {
    label_create_impl(Some(&app), &state, name, icon)
}

#[tauri::command]
pub fn group_create(
    app: AppHandle,
    state: State<'_, AppState>,
    name: String,
    icon: Option<String>,
) -> Result<LabelView, UiError> {
    label_create_impl(Some(&app), &state, name, icon)
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
    state.with_vault(|v| {
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
    let item = state.with_vault_mut(|v| v.create_item(label_id, &name, description))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "items" }));
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
    state.with_vault_mut(|v| v.rename_item(id, &name, description))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "items" }));
    }
    Ok(())
}

pub fn item_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_vault_mut(|v| v.delete_item(id))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "items" }));
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
    state.with_vault(|v| v.list_environments(item_id))
}

pub fn environment_add_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    item_id: Uuid,
    name: String,
) -> Result<EnvironmentView, UiError> {
    let env = state.with_vault_mut(|v| v.add_environment(item_id, &name))?;
    if let Some(app) = app {
        let _ = app.emit(
            "vault://changed",
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
    state.with_vault_mut(|v| v.rename_environment(id, &name))?;
    if let Some(app) = app {
        let _ = app.emit(
            "vault://changed",
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
    state.with_vault_mut(|v| {
        if let Some(preserve) = preserve_content {
            v.delete_environment_with_options(id, preserve)
        } else {
            v.delete_environment(id)
        }
    })?;
    if let Some(app) = app {
        let _ = app.emit(
            "vault://changed",
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
    state.with_vault(|v| {
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
    state.with_vault(|v| {
        let secret = v.reveal_secret(id)?;
        Ok(secret.expose_secret().to_string())
    })
}

pub fn secret_copy_impl<C: ClipboardPort>(
    clipboard: Arc<C>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    let secret = state.with_vault(|v| v.reveal_secret(id))?;
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
    let meta = state.with_vault_mut(|v| v.create_secret(draft.into()))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "secrets" }));
    }
    Ok(meta)
}

pub fn secret_update_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    draft: SecretDraftDto,
) -> Result<SecretMeta, UiError> {
    let meta = state.with_vault_mut(|v| v.update_secret(id, draft.into()))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "secrets" }));
    }
    Ok(meta)
}

pub fn secret_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_vault_mut(|v| v.delete_secret(id))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "secrets" }));
    }
    Ok(())
}

pub fn secret_copy_to_environment_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    target_environment_id: Option<Uuid>,
) -> Result<SecretMeta, UiError> {
    let meta = state.with_vault_mut(|v| v.copy_secret_to_environment(id, target_environment_id))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "secrets" }));
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
    state.with_vault(|v| v.list_assets(item_id, environment_id))
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
    let meta = state.with_vault_mut(|v| {
        v.upload_asset(item_id, environment_id, &name, &bytes, mime.as_deref())
    })?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "assets" }));
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "files" }));
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
    state.with_vault(|v| {
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
    let meta = state.with_vault_mut(|v| v.rename_asset(id, &name))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "assets" }));
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "files" }));
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
    state.with_vault_mut(|v| v.delete_asset(id))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "assets" }));
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "files" }));
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
    state.with_vault(|v| v.list_notes(item_id, environment_id))
}

pub fn note_get_impl(state: &AppState, id: Uuid) -> Result<NoteView, UiError> {
    state.with_vault(|v| v.get_note(id))
}

pub fn note_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    draft: NoteDraftDto,
) -> Result<NoteView, UiError> {
    let note = state.with_vault_mut(|v| {
        v.create_note(draft.item_id, draft.environment_id, &draft.title, &draft.content)
    })?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "notes" }));
    }
    Ok(note)
}

pub fn note_update_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
    draft: NoteUpdateDto,
) -> Result<NoteView, UiError> {
    let note = state.with_vault_mut(|v| {
        v.update_note(id, draft.title.as_deref(), draft.content.as_deref())
    })?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "notes" }));
    }
    Ok(note)
}

pub fn note_delete_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    state.with_vault_mut(|v| v.delete_note(id))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "notes" }));
    }
    Ok(())
}

pub fn note_copy_plain_impl<C: ClipboardPort>(
    clipboard: Arc<C>,
    state: &AppState,
    id: Uuid,
) -> Result<(), UiError> {
    let note = state.with_vault(|v| v.get_note(id))?;
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
    state.with_vault(|_| Ok(()))?;
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
    state.with_vault(|v| v.overview())
}

pub fn dashboard_get_impl(state: &AppState) -> Result<DashboardConfig, UiError> {
    state.with_vault(|v| v.dashboard_config())
}

pub fn dashboard_set_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    config: DashboardConfig,
) -> Result<(), UiError> {
    state.with_vault_mut(|v| v.set_dashboard_config(&config))?;
    if let Some(app) = app {
        let _ = app.emit("vault://changed", serde_json::json!({ "scope": "dashboard" }));
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
    state.with_vault(|v| {
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
    let updated = state.with_vault_mut(|v| {
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
            "vault://changed",
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
    state.with_vault(|v| v.list_projects())
}

pub fn project_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    name: String,
    environments: Vec<String>,
) -> Result<ProjectView, UiError> {
    let project = state.with_vault_mut(|v| v.create_project(&name, &environments))?;
    if let Some(app) = app {
        let _ = app.emit(
            "vault://changed",
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
    state.with_vault_mut(|v| v.rename_project(id, &name))?;
    if let Some(app) = app {
        let _ = app.emit(
            "vault://changed",
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
    state.with_vault_mut(|v| v.delete_project(id))?;
    if let Some(app) = app {
        let _ = app.emit(
            "vault://changed",
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

