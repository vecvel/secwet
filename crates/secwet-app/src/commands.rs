//! Store commands: lifecycle, spaces, groups, items, environments, secrets,
//! assets, notes, overview, settings, recovery, relay, devices and pairing.
//!
//! Invariants:
//! - All commands return `Result<T, UiError>`.
//! - Secrets and file bytes are never exposed in listings or overview.
//! - Clipboard copy is executed entirely in Rust with 30s auto-clear.
//! - Events are emitted on mutations (`secwet://changed { scope }`) and lock (`secwet://locked`).

use std::path::PathBuf;
use std::sync::atomic::Ordering;
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
use uuid::Uuid;
use zeroize::Zeroize;

use crate::clipboard::{extract_plain_text, AutoClearManager, ClipboardPort};
use crate::error::UiError;
use crate::events::AppEvent;
use crate::state::{ActivePairingPeer, ActivePairingSession, AppState, SecwetStatusDto};

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

#[derive(Debug, Clone, Serialize)]
pub struct SyncStatusDto {
    pub pending_outbox_count: u32,
    pub sync_cursor: u64,
}

/// This computer's or phone's name, for new device records.
pub fn system_device_name() -> String {
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

    // Mobile hosts pass the device name explicitly; apps cannot run `hostname` there.
    #[cfg(not(any(target_os = "ios", target_os = "android")))]
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

    if cfg!(any(target_os = "ios", target_os = "android")) {
        "Phone".to_string()
    } else {
        "Desktop".to_string()
    }
}

/// The name to record for this device: the caller's choice, else the system name.
fn effective_device_name(device_name: Option<&str>) -> String {
    match device_name {
        Some(name) if !name.trim().is_empty() && name != "desktop" => name.trim().to_string(),
        _ => system_device_name(),
    }
}

impl AppState {
    // ========================================================================
    // 1. Lifecycle
    // ========================================================================

    pub fn secwet_status(&self) -> Result<SecwetStatusDto, UiError> {
        let guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        if let Some(secwet) = guard.as_ref() {
            Ok(SecwetStatusDto::Unlocked {
                secwet_id: secwet.secwet_id(),
            })
        } else {
            let status = Secwet::status(&self.data_dir)?;
            Ok(SecwetStatusDto::from(status))
        }
    }

    pub fn secwet_create(&self, device_name: Option<String>) -> Result<SecwetStatusDto, UiError> {
        let mut guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        if guard.is_some() {
            return Err(UiError::already_initialized());
        }

        let dev_name = effective_device_name(device_name.as_deref());
        let secwet = Secwet::create(&self.data_dir, &dev_name, self.keystore.as_ref())?;
        let secwet_id = secwet.secwet_id();
        *guard = Some(secwet);
        drop(guard);

        self.emit_changed("all");
        Ok(SecwetStatusDto::Unlocked { secwet_id })
    }

    /// Opens the store with the keys from secure storage. When biometric
    /// unlock is on, the host's presence check must pass first (see
    /// `crate::biometric`); it blocks while the OS prompt is open.
    pub fn secwet_unlock(&self) -> Result<(), UiError> {
        self.secwet_unlock_with(None)
    }

    /// [`AppState::secwet_unlock`] with the store's recovery key in place of
    /// the biometric check, for when the device cannot run it.
    pub fn secwet_unlock_with(&self, recovery_key: Option<&str>) -> Result<(), UiError> {
        let open = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?
            .is_some();
        if !open {
            self.unlock_presence_gate(recovery_key)?;
        }

        let mut guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        if guard.is_some() {
            return Ok(());
        }
        if self.in_flight.load(Ordering::SeqCst) > 0 {
            // The store is out for a network call; opening a second copy of the
            // same database would race it.
            return Err(self.locked_or_busy());
        }

        let secwet = Secwet::unlock(&self.data_dir, self.keystore.as_ref())?;
        *guard = Some(secwet);
        drop(guard);

        self.emit_changed("all");
        Ok(())
    }

    /// Closes the store and drops its keys. Always works, even after a
    /// panic poisoned the store mutex: a command that cannot lock would
    /// leave the keys in memory. Locking also clears the poison, since the
    /// next unlock opens a fresh store from disk.
    pub fn secwet_lock(&self) -> Result<(), UiError> {
        let mut guard = self.secwet.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        self.lock_generation.fetch_add(1, Ordering::SeqCst);
        if let Some(secwet) = guard.take() {
            secwet.lock();
        }
        drop(guard);
        self.secwet.clear_poison();
        if let Ok(mut links) = self.invite_links.lock() {
            links.clear();
        }

        self.emit(AppEvent::Locked);
        Ok(())
    }

    // ========================================================================
    // 1.5. Spaces
    // ========================================================================

    pub fn spaces_list(&self) -> Result<Vec<SpaceView>, UiError> {
        self.with_secwet(|v| v.list_spaces())
    }

    pub fn space_create(&self, name: String, icon: Option<String>) -> Result<SpaceView, UiError> {
        let space = self.with_secwet_mut(|v| v.create_space(&name, icon))?;
        self.emit_changed("spaces");
        Ok(space)
    }

    pub fn space_rename(
        &self,
        id: Uuid,
        name: String,
        icon: Option<String>,
    ) -> Result<SpaceView, UiError> {
        let space = self.with_secwet_mut(|v| v.rename_space(id, &name, icon))?;
        self.emit_changed("spaces");
        Ok(space)
    }

    pub fn space_delete(&self, id: Uuid) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.delete_space(id))?;
        self.emit_changed("spaces");
        self.emit_changed("labels");
        Ok(())
    }

    pub fn space_reorder(&self, ids: Vec<Uuid>) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.reorder_spaces(&ids))?;
        self.emit_changed("spaces");
        Ok(())
    }

    // ========================================================================
    // 2. Groups (labels)
    // ========================================================================

    pub fn labels_list(&self) -> Result<Vec<LabelView>, UiError> {
        self.with_secwet(|v| v.list_labels())
    }

    pub fn label_create(&self, name: String, icon: Option<String>) -> Result<LabelView, UiError> {
        self.label_create_in_space(name, icon, None)
    }

    pub fn label_create_in_space(
        &self,
        name: String,
        icon: Option<String>,
        space_id: Option<Uuid>,
    ) -> Result<LabelView, UiError> {
        let label = self.with_secwet_mut(|v| v.create_label_in_space(&name, icon, space_id))?;
        self.emit_changed("labels");
        Ok(label)
    }

    pub fn label_rename(&self, id: Uuid, name: String, icon: Option<String>) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.update_label(id, &name, icon))?;
        self.emit_changed("labels");
        Ok(())
    }

    pub fn label_delete(&self, id: Uuid) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.delete_label(id))?;
        self.emit_changed("labels");
        Ok(())
    }

    pub fn label_reorder(&self, ids: Vec<Uuid>) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.reorder_labels(&ids))?;
        self.emit_changed("labels");
        Ok(())
    }

    pub fn label_move_to_space(&self, id: Uuid, space_id: Uuid) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.move_label_to_space(id, space_id))?;
        self.emit_changed("labels");
        Ok(())
    }

    // ========================================================================
    // 3. Items
    // ========================================================================

    pub fn items_list(&self, label_id: Option<Uuid>) -> Result<Vec<ItemView>, UiError> {
        self.with_secwet(|v| {
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

    pub fn item_create(
        &self,
        label_id: Uuid,
        name: String,
        description: Option<String>,
    ) -> Result<ItemView, UiError> {
        let item = self.with_secwet_mut(|v| v.create_item(label_id, &name, description))?;
        self.emit_changed("items");
        Ok(item)
    }

    pub fn item_rename(
        &self,
        id: Uuid,
        name: String,
        description: Option<String>,
    ) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.rename_item(id, &name, description))?;
        self.emit_changed("items");
        Ok(())
    }

    pub fn item_delete(&self, id: Uuid) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.delete_item(id))?;
        self.emit_changed("items");
        Ok(())
    }

    // ========================================================================
    // 4. Environments
    // ========================================================================

    pub fn environments_list(&self, item_id: Uuid) -> Result<Vec<EnvironmentView>, UiError> {
        self.with_secwet(|v| v.list_environments(item_id))
    }

    pub fn environment_add(&self, item_id: Uuid, name: String) -> Result<EnvironmentView, UiError> {
        let env = self.with_secwet_mut(|v| v.add_environment(item_id, &name))?;
        self.emit_changed("environments");
        Ok(env)
    }

    pub fn environment_rename(&self, id: Uuid, name: String) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.rename_environment(id, &name))?;
        self.emit_changed("environments");
        Ok(())
    }

    pub fn environment_delete(
        &self,
        id: Uuid,
        preserve_content: Option<bool>,
    ) -> Result<(), UiError> {
        self.with_secwet_mut(|v| {
            if let Some(preserve) = preserve_content {
                v.delete_environment_with_options(id, preserve)
            } else {
                v.delete_environment(id)
            }
        })?;
        self.emit_changed("environments");
        Ok(())
    }

    // ========================================================================
    // 5. Secrets
    // ========================================================================

    pub fn secrets_list(
        &self,
        item_id: Option<Uuid>,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<SecretMeta>, UiError> {
        self.with_secwet(|v| {
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

    pub fn secret_reveal(&self, id: Uuid) -> Result<String, UiError> {
        self.with_secwet(|v| {
            let secret = v.reveal_secret(id)?;
            Ok(secret.expose_secret().to_string())
        })
    }

    /// Copies a secret value to `clipboard`; it is cleared after 30 seconds
    /// unless the user copied something else meanwhile.
    pub fn secret_copy<C: ClipboardPort + ?Sized>(
        &self,
        clipboard: Arc<C>,
        id: Uuid,
    ) -> Result<(), UiError> {
        let secret = self.with_secwet(|v| v.reveal_secret(id))?;
        self.auto_clear(clipboard)
            .copy_secret(secret.expose_secret())
            .map_err(UiError::internal)
    }

    pub fn secret_create(&self, draft: SecretDraftDto) -> Result<SecretMeta, UiError> {
        let meta = self.with_secwet_mut(|v| v.create_secret(draft.into()))?;
        self.emit_changed("secrets");
        Ok(meta)
    }

    pub fn secret_update(&self, id: Uuid, draft: SecretDraftDto) -> Result<SecretMeta, UiError> {
        let meta = self.with_secwet_mut(|v| v.update_secret(id, draft.into()))?;
        self.emit_changed("secrets");
        Ok(meta)
    }

    pub fn secret_delete(&self, id: Uuid) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.delete_secret(id))?;
        self.emit_changed("secrets");
        Ok(())
    }

    pub fn secret_copy_to_environment(
        &self,
        id: Uuid,
        target_environment_id: Option<Uuid>,
    ) -> Result<SecretMeta, UiError> {
        let meta =
            self.with_secwet_mut(|v| v.copy_secret_to_environment(id, target_environment_id))?;
        self.emit_changed("secrets");
        Ok(meta)
    }

    // ========================================================================
    // 6. Assets (F5b); `file_*` names are kept for older callers.
    // ========================================================================

    pub fn assets_list(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<AssetMetaView>, UiError> {
        self.with_secwet(|v| v.list_assets(item_id, environment_id))
    }

    pub fn files_list(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<FileMetaView>, UiError> {
        self.assets_list(item_id, environment_id)
    }

    pub fn asset_upload(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        name: String,
        mime: Option<String>,
        mut bytes: Vec<u8>,
    ) -> Result<AssetMetaView, UiError> {
        let result = self.with_secwet_mut(|v| {
            v.upload_asset(item_id, environment_id, &name, &bytes, mime.as_deref())
        });
        // The plaintext file is sealed by now; wipe this copy.
        bytes.zeroize();
        let meta = result?;
        self.emit_changed("assets");
        self.emit_changed("files");
        Ok(meta)
    }

    pub fn file_upload(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        name: String,
        mime: Option<String>,
        bytes: Vec<u8>,
    ) -> Result<FileMetaView, UiError> {
        self.asset_upload(item_id, environment_id, name, mime, bytes)
    }

    pub fn asset_download(&self, id: Uuid) -> Result<AssetDownloadDto, UiError> {
        self.with_secwet(|v| {
            let (meta, bytes) = v.download_asset(id)?;
            Ok(AssetDownloadDto { meta, bytes })
        })
    }

    pub fn file_download(&self, id: Uuid) -> Result<FileDownloadDto, UiError> {
        self.asset_download(id)
    }

    pub fn asset_rename(&self, id: Uuid, name: String) -> Result<AssetMetaView, UiError> {
        let meta = self.with_secwet_mut(|v| v.rename_asset(id, &name))?;
        self.emit_changed("assets");
        self.emit_changed("files");
        Ok(meta)
    }

    pub fn file_rename(&self, id: Uuid, name: String) -> Result<FileMetaView, UiError> {
        self.asset_rename(id, name)
    }

    pub fn asset_delete(&self, id: Uuid) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.delete_asset(id))?;
        self.emit_changed("assets");
        self.emit_changed("files");
        Ok(())
    }

    pub fn file_delete(&self, id: Uuid) -> Result<(), UiError> {
        self.asset_delete(id)
    }

    // ========================================================================
    // 7. Notes
    // ========================================================================

    pub fn notes_list(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<NoteMetaView>, UiError> {
        self.with_secwet(|v| v.list_notes(item_id, environment_id))
    }

    pub fn note_get(&self, id: Uuid) -> Result<NoteView, UiError> {
        self.with_secwet(|v| v.get_note(id))
    }

    pub fn note_create(&self, draft: NoteDraftDto) -> Result<NoteView, UiError> {
        let note = self.with_secwet_mut(|v| {
            v.create_note(draft.item_id, draft.environment_id, &draft.title, &draft.content)
        })?;
        self.emit_changed("notes");
        Ok(note)
    }

    pub fn note_update(&self, id: Uuid, draft: NoteUpdateDto) -> Result<NoteView, UiError> {
        let note = self.with_secwet_mut(|v| {
            v.update_note(id, draft.title.as_deref(), draft.content.as_deref())
        })?;
        self.emit_changed("notes");
        Ok(note)
    }

    pub fn note_delete(&self, id: Uuid) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.delete_note(id))?;
        self.emit_changed("notes");
        Ok(())
    }

    /// Copies a note as plain text through the auto-clearing clipboard.
    pub fn note_copy_plain<C: ClipboardPort + ?Sized>(
        &self,
        clipboard: Arc<C>,
        id: Uuid,
    ) -> Result<(), UiError> {
        let note = self.with_secwet(|v| v.get_note(id))?;
        let plain_text = extract_plain_text(&note.content);
        self.auto_clear(clipboard)
            .copy_secret(&plain_text)
            .map_err(UiError::internal)
    }

    /// Copies editor text (HTML or plain) through the auto-clearing clipboard.
    /// Requires an unlocked store.
    pub fn clipboard_copy_text<C: ClipboardPort + ?Sized>(
        &self,
        clipboard: Arc<C>,
        text: String,
    ) -> Result<(), UiError> {
        self.with_secwet(|_| Ok(()))?;
        let plain_text = extract_plain_text(&text);
        self.auto_clear(clipboard)
            .copy_secret(&plain_text)
            .map_err(UiError::internal)
    }

    pub(crate) fn auto_clear<C: ClipboardPort + ?Sized>(
        &self,
        clipboard: Arc<C>,
    ) -> AutoClearManager<C> {
        AutoClearManager::new(
            clipboard,
            Arc::clone(&self.clipboard_generation),
            self.clear_duration,
        )
    }

    // ========================================================================
    // 8. Overview & Dashboard
    // ========================================================================

    pub fn overview(&self) -> Result<Overview, UiError> {
        self.with_secwet(|v| v.overview())
    }

    pub fn dashboard_get(&self) -> Result<DashboardConfig, UiError> {
        self.with_secwet(|v| v.dashboard_config())
    }

    pub fn dashboard_set(&self, config: DashboardConfig) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.set_dashboard_config(&config))?;
        self.emit_changed("dashboard");
        Ok(())
    }

    // ========================================================================
    // 9. Settings
    // ========================================================================

    pub fn settings_get(&self) -> Result<Settings, UiError> {
        self.with_secwet(|v| {
            let mut s = v.settings()?;
            if s.device_name.trim().is_empty()
                || s.device_name == "desktop"
                || s.device_name == "default-device"
            {
                s.device_name = system_device_name();
            }
            Ok(s)
        })
    }

    pub fn settings_set(&self, settings: SettingsPatchDto) -> Result<Settings, UiError> {
        let updated = self.with_secwet_mut(|v| {
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
        self.emit_changed("settings");
        Ok(updated)
    }

    // ========================================================================
    // 10. Backward compatibility (projects)
    // ========================================================================

    pub fn projects_list(&self) -> Result<Vec<ProjectView>, UiError> {
        self.with_secwet(|v| v.list_projects())
    }

    pub fn project_create(
        &self,
        name: String,
        environments: Vec<String>,
    ) -> Result<ProjectView, UiError> {
        let project = self.with_secwet_mut(|v| v.create_project(&name, &environments))?;
        self.emit_changed("items");
        Ok(project)
    }

    pub fn project_rename(&self, id: Uuid, name: String) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.rename_project(id, &name))?;
        self.emit_changed("items");
        Ok(())
    }

    pub fn project_delete(&self, id: Uuid) -> Result<(), UiError> {
        self.with_secwet_mut(|v| v.delete_project(id))?;
        self.emit_changed("items");
        Ok(())
    }

    // ========================================================================
    // 11. Active sessions
    // ========================================================================

    pub fn active_sessions_list(&self) -> Result<Vec<ActiveSession>, UiError> {
        self.with_secwet(|v| v.list_active_sessions())
    }

    pub fn active_session_stop(&self, session_id: String) -> Result<(), UiError> {
        self.with_secwet(|v| v.stop_active_session(&session_id))?;
        self.emit_changed("sessions");
        Ok(())
    }

    // ========================================================================
    // 12. Recovery & backup
    // ========================================================================

    pub fn recovery_key_create(&self) -> Result<String, UiError> {
        let key = self.with_secwet_mut(|secwet| secwet.create_recovery_key(self.keystore.as_ref()))?;
        self.emit_changed("settings");
        Ok(key.expose_secret().to_string())
    }

    pub fn recovery_key_replace(&self) -> Result<String, UiError> {
        let key =
            self.with_secwet_mut(|secwet| secwet.replace_recovery_key(self.keystore.as_ref()))?;
        self.emit_changed("settings");
        Ok(key.expose_secret().to_string())
    }

    pub fn recovery_status(&self) -> Result<RecoveryStatusDto, UiError> {
        self.with_secwet(|secwet| {
            let status = secwet.recovery_status()?;
            Ok(RecoveryStatusDto {
                created: status.created,
                created_at: status.created_at,
            })
        })
    }

    /// Writes an encrypted export to `path`. Hosts with a file picker resolve
    /// the path first; without one the path is required.
    pub fn workspace_export(
        &self,
        path: Option<PathBuf>,
        recovery_key: String,
    ) -> Result<ExportSummaryDto, UiError> {
        let out_path = path.ok_or_else(|| {
            UiError::invalid("path", "Export path is required when running in headless mode")
        })?;

        let recovery_secret = SecretString::from(recovery_key);
        let summary =
            self.with_secwet(|secwet| secwet.export_encrypted(&recovery_secret, &out_path))?;

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

    /// Replaces this device's store with an encrypted export. Hosts with a
    /// file picker resolve the path first; without one the path is required.
    pub fn workspace_restore(
        &self,
        path: Option<PathBuf>,
        recovery_key: String,
        device_name: Option<String>,
    ) -> Result<SecwetStatusDto, UiError> {
        let in_path = path.ok_or_else(|| {
            UiError::invalid("path", "Restore path is required when running in headless mode")
        })?;

        // Close any open secwet instance before restoring to avoid file lock conflicts
        {
            let mut guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            if let Some(old) = guard.take() {
                old.lock();
            }
        }

        let dev_name = effective_device_name(device_name.as_deref());
        let recovery_secret = SecretString::from(recovery_key);
        let secwet = Secwet::restore_from_export(
            &self.data_dir,
            &in_path,
            &recovery_secret,
            &dev_name,
            self.keystore.as_ref(),
        )?;

        let secwet_id = secwet.secwet_id();
        {
            let mut guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            *guard = Some(secwet);
        }

        self.emit_changed("all");
        Ok(SecwetStatusDto::Unlocked { secwet_id })
    }

    // ========================================================================
    // 13. Relay & entitlements
    // ========================================================================

    /// Relay connection and plan. On Free this reports the cached plan and
    /// makes no network call; otherwise it checks the relay and caches
    /// the entitlement it returns.
    pub async fn relay_status(&self) -> Result<secwet_proto::RelayStatusDto, UiError> {
        let (relay_url, info, device_id, secwet_id, sign_key, active_devices, pending) = {
            let guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            let secwet = guard.as_ref().ok_or_else(UiError::locked)?;
            (
                secwet.relay_url().unwrap_or_default(),
                secwet.plan_info().map_err(UiError::from)?,
                secwet.device_id().to_string(),
                secwet.secwet_id(),
                secwet.device_sign_key().clone(),
                secwet.active_devices_count().unwrap_or(1),
                secwet.pending_outbox_count().unwrap_or(0) as u32,
            )
        };

        let offline = |info: &secwet_core::PlanInfo| secwet_proto::RelayStatusDto {
            connected: false,
            relay_url: relay_url.clone(),
            plan: info.plan().to_string(),
            device_limit: info.device_limit,
            active_devices,
            expires_at: info.expires_at.clone(),
            pending_outbox_count: pending,
        };
        if info.state == secwet_core::PlanState::Free || relay_url.trim().is_empty() {
            return Ok(offline(&info));
        }

        let client = secwet_core::RelayClient::new(&relay_url, &device_id);
        if client.health().await.is_err() {
            return Ok(offline(&info));
        }
        let mut info = info;
        if let Ok(ent) = client.get_entitlement(secwet_id, &sign_key).await {
            let mut guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            if let Some(secwet) = guard.as_mut() {
                if secwet.secwet_id() == secwet_id {
                    info = secwet.apply_entitlement(&ent).map_err(UiError::from)?;
                }
            }
        }
        Ok(secwet_proto::RelayStatusDto { connected: true, ..offline(&info) })
    }

    /// Registers the store with the relay. Free never contacts the relay;
    /// a Free store registers through `plan_activate` instead.
    pub async fn relay_register(&self) -> Result<secwet_proto::RegisterSecwetResponse, UiError> {
        let (relay_url, device_id, secwet_id, sign_pub, enc_pub, sign_key) = {
            let guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            let secwet = guard.as_ref().ok_or_else(UiError::locked)?;
            secwet.ensure_relay_allowed(secwet_core::RelayOp::Entitlement)?;
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

        // The plan comes from the relay entitlement, never from registering.
        if let Ok(ent) = client.get_entitlement(secwet_id, &sign_key).await {
            let mut guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            if let Some(secwet) = guard.as_mut() {
                if secwet.secwet_id() == secwet_id {
                    secwet.apply_entitlement(&ent).map_err(UiError::from)?;
                }
            }
        }
        self.emit_changed("plan");

        Ok(res)
    }

    pub fn relay_set_url(&self, url: String) -> Result<(), UiError> {
        let mut guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = guard.as_mut().ok_or_else(UiError::locked)?;
        secwet.set_relay_url(&url).map_err(UiError::from)
    }

    // ========================================================================
    // 14. Devices & pairing
    // ========================================================================

    pub fn devices_list(&self) -> Result<Vec<secwet_proto::DeviceDto>, UiError> {
        self.with_secwet(|s| s.devices_list())
    }

    pub async fn pairing_start(&self) -> Result<secwet_proto::PairingSessionInfo, UiError> {
        let (secwet_id, relay_url, sign_key, device_id) = {
            let guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            let secwet = guard.as_ref().ok_or_else(UiError::locked)?;
            // Pairing needs an active Pro plan; Free never calls the relay.
            secwet.ensure_relay_allowed(secwet_core::RelayOp::Sync)?;
            let relay_url = secwet
                .relay_url()
                .unwrap_or_else(|_| "http://127.0.0.1:8787".into());
            (
                secwet.secwet_id(),
                relay_url,
                secwet.device_sign_key().clone(),
                secwet.device_id().to_string(),
            )
        };

        let (a_eph_secret, a_eph_pub) = secwet_core::crypto::generate_ephemeral_x25519();
        // The relay authenticates requests by this device's id and signature.
        let client = secwet_core::RelayClient::new(&relay_url, &device_id);

        let (session_id, expires_at, qr_payload) = match client
            .create_pairing_session(secwet_id, a_eph_pub, &sign_key)
            .await
        {
            Ok(resp) => (resp.session_id, resp.expires_at, resp.qr_payload),
            // A session the relay does not know could never be joined, so the
            // relay's error is shown instead of a code that cannot work.
            Err(err) => return Err(err.into()),
        };

        let active_session = ActivePairingSession {
            session_id,
            a_eph_secret,
            a_eph_pub,
            expires_at: expires_at.clone(),
            qr_payload: qr_payload.clone(),
            cached_peer: None,
        };

        {
            let mut guard = self
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

    pub async fn pairing_poll(&self) -> Result<secwet_proto::PairingPollResponse, UiError> {
        let (session_id, a_eph_secret_bytes, a_eph_pub, relay_url, sign_key, device_id) = {
            let guard = self
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

            let s_guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            let secwet = s_guard.as_ref().ok_or_else(UiError::locked)?;
            secwet.ensure_relay_allowed(secwet_core::RelayOp::Sync)?;
            let relay_url = secwet
                .relay_url()
                .unwrap_or_else(|_| "http://127.0.0.1:8787".into());

            (
                session.session_id,
                session.a_eph_secret.to_bytes(),
                session.a_eph_pub,
                relay_url,
                secwet.device_sign_key().clone(),
                secwet.device_id().to_string(),
            )
        };

        let client = secwet_core::RelayClient::new(&relay_url, &device_id);
        let status_resp = match client.get_pairing_status(session_id, &sign_key).await {
            Ok(s) => s,
            Err(_) => return Ok(secwet_proto::PairingPollResponse::Waiting),
        };

        if status_resp.status == "joined" {
            if let Some(join_payload) = status_resp.join_payload {
                let secret = x25519_dalek::StaticSecret::from(a_eph_secret_bytes);
                let shared = secwet_core::crypto::compute_pairing_shared_secret(
                    &secret,
                    &join_payload.n_eph_pub,
                )
                .map_err(|_| UiError::internal("Failed to compute pairing shared secret"))?;

                let profile = secwet_core::crypto::open_pairing_profile(
                    &shared,
                    &join_payload.sealed_profile,
                )
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

                let fingerprint = secwet_core::crypto::compute_fingerprint(
                    &join_payload.sign_pub,
                    &join_payload.enc_pub,
                );
                let device_id = secwet_core::crypto::compute_device_id(&join_payload.sign_pub);

                let peer = ActivePairingPeer {
                    join_req: join_payload,
                    profile: profile.clone(),
                    sas: sas.clone(),
                    fingerprint: fingerprint.clone(),
                    device_id: device_id.clone(),
                };

                {
                    let mut guard = self
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

    pub async fn pairing_approve(&self) -> Result<secwet_proto::DeviceDto, UiError> {
        let (session_id, peer, secwet_id, relay_url, sign_key, master_keys) = {
            let mut guard = self
                .active_pairing
                .lock()
                .map_err(|_| UiError::internal("Active pairing mutex poisoned"))?;
            let session = guard
                .take()
                .ok_or_else(|| UiError::new("bad_request", None, "No active pairing session"))?;
            let peer = session.cached_peer.ok_or_else(|| {
                UiError::new("bad_request", None, "No device has joined pairing yet")
            })?;

            let s_guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            let secwet = s_guard.as_ref().ok_or_else(UiError::locked)?;
            secwet.ensure_relay_allowed(secwet_core::RelayOp::Sync)?;
            let relay_url = secwet
                .relay_url()
                .unwrap_or_else(|_| "http://127.0.0.1:8787".into());
            let secwet_id = secwet.secwet_id();
            let sign_key = secwet.device_sign_key().clone();

            // Every epoch must be wrapped: the relay refuses an approval that
            // leaves the new device without a key it needs.
            let mut master_keys = Vec::new();
            for ep in 1..=secwet.key_epoch() {
                let k_vec =
                    secwet_core::collab::load_master_key(self.keystore.as_ref(), &secwet_id, ep)
                        .map_err(UiError::from)?
                        .ok_or_else(|| {
                            UiError::new(
                                "keystore_error",
                                None,
                                "A key this device needs is missing from secure storage.",
                            )
                        })?;
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
        let device_label = self.with_secwet(|s| Ok(s.device_id().to_string()))?;
        let client = secwet_core::RelayClient::new(&relay_url, device_label);
        match client
            .approve_pairing(session_id, &approve_req, &sign_key)
            .await
        {
            Ok(_) | Err(secwet_core::Error::Offline) => {}
            Err(e) => return Err(UiError::from(e)),
        }

        // 4. Record new device in local store
        let device_dto = {
            let mut guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            let secwet = guard.as_mut().ok_or_else(UiError::locked)?;
            secwet
                .record_paired_device(
                    &peer.device_id,
                    &peer.profile.name,
                    &peer.profile.platform,
                    &peer.join_req.sign_pub,
                    &peer.join_req.enc_pub,
                )
                .map_err(UiError::from)?
        };

        self.emit_changed("devices");
        Ok(device_dto)
    }

    pub fn pairing_cancel(&self) -> Result<(), UiError> {
        let mut guard = self
            .active_pairing
            .lock()
            .map_err(|_| UiError::internal("Active pairing mutex poisoned"))?;
        *guard = None;
        Ok(())
    }

    // ========================================================================
    // Sync
    // ========================================================================

    /// Pushes and pulls one sync round; returns (pushed, pulled).
    pub async fn sync_now(&self) -> Result<(usize, usize), UiError> {
        self.sync_round().await
    }

    pub fn sync_status(&self) -> Result<SyncStatusDto, UiError> {
        self.with_secwet(|secwet| {
            let pending_outbox_count = secwet.pending_outbox_count().unwrap_or(0) as u32;
            let sync_cursor = secwet.sync_cursor().unwrap_or(0);
            Ok(SyncStatusDto {
                pending_outbox_count,
                sync_cursor,
            })
        })
    }
}
