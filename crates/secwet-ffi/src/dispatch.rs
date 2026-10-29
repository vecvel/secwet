//! JSON command routing: one request `{"cmd", "args"}` in, one response
//! `{"ok": value}` or `{"err": UiError}` out.
//!
//! Command names and argument names are the desktop's Tauri commands with
//! snake_case keys (`apps/desktop/src-tauri/src/commands.rs`), so both hosts
//! speak the same contract. Outputs serialize exactly as the desktop receives
//! them.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use secwet_app::collab::GrantInput;
use secwet_app::commands::{NoteDraftDto, NoteUpdateDto, SecretDraftDto, SettingsPatchDto};
use secwet_app::{runtime, AppState, BiometryKind, PresenceVerifier, UiError};
use secwet_core::model::DashboardConfig;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::platform::{platform_kind_name, NativeClipboard, NativePresence};

/// Prompt text for the unlock check (the OS shows it under its own title).
const UNLOCK_REASON: &str = "Unlock Secwet";
/// Prompt text when a new store's keys are first written on this phone.
const SETUP_REASON: &str = "Protect Secwet with your screen lock";

/// Everything a request needs: the app state and the native services.
pub struct Bridge {
    pub state: AppState,
    clipboard: Arc<NativeClipboard>,
    presence: Arc<NativePresence>,
    /// A successful system prompt authorized the secure storage; cleared on
    /// lock (also by the event sink in `bridge_for`).
    session: Arc<AtomicBool>,
    device_name: String,
}

impl Bridge {
    /// The phone's unlock policy lives here, not in the app layer's opt-in
    /// biometric flag: with a screen lock every unlock runs the system prompt
    /// (biometric, passcode as fallback); without one the recovery key is
    /// asked for, when the store has one.
    pub fn new(
        state: AppState,
        clipboard: Arc<NativeClipboard>,
        presence: Arc<NativePresence>,
        session: Arc<AtomicBool>,
        device_name: String,
    ) -> Self {
        Self {
            state,
            clipboard,
            presence,
            session,
            device_name,
        }
    }

    /// Runs the system prompt once per session on a phone with a screen
    /// lock; the native storage then serves the keys until [`end_session`].
    /// A phone with no screen lock is refused: the OS cannot guard the keys
    /// there, so Secwet never stores or opens them.
    fn open_session(&self, reason: &str) -> Result<(), UiError> {
        if !self.presence.device_lock() {
            return Err(screen_lock_required());
        }
        if self.session.load(Ordering::SeqCst) {
            return Ok(());
        }
        self.presence.verify(reason)?;
        self.session.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn end_session(&self) {
        self.session.store(false, Ordering::SeqCst);
        self.presence.end_session();
    }

    fn is_open(&self) -> Result<bool, UiError> {
        Ok(self
            .state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?
            .is_some())
    }

    fn unlock(&self) -> Result<Value, UiError> {
        if self.is_open()? {
            return Ok(Value::Null);
        }
        if self.presence.device_lock() {
            // A fresh prompt for every unlock, even if a session was left over.
            self.end_session();
            self.open_session(UNLOCK_REASON)?;
            return match self.state.secwet_unlock() {
                Ok(()) => Ok(Value::Null),
                Err(err) => {
                    self.end_session();
                    Err(err)
                }
            };
        }
        // No screen lock: refused. The recovery key is only for recovery.
        Err(screen_lock_required())
    }

    /// How this phone unlocks, for the lock screen and Settings.
    fn unlock_status(&self) -> Result<Value, UiError> {
        let device_lock = self.presence.device_lock();
        let code = if device_lock {
            self.presence.platform_kind()
        } else {
            0
        };
        let kind = if device_lock {
            self.presence.kind()
        } else {
            BiometryKind::None
        };
        Ok(json!({
            "available": kind.is_available(),
            "kind": kind,
            // Always on with a screen lock; there is no opt-out on phones.
            "enabled": device_lock,
            "platform_kind": platform_kind_name(code),
            "device_lock": device_lock,
        }))
    }

    /// Runs one JSON request and returns the JSON response. Every string and
    /// number in the parsed request and in the response value (secret values,
    /// recovery keys, note bodies, asset bytes) is overwritten once used, and
    /// the asset and note DTOs are wiped after serialization. The caller's
    /// own copies are its job: Dart strings, for one, cannot be wiped.
    pub fn handle(&self, request: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut parsed: Value = match serde_json::from_slice(request) {
            Ok(v) => v,
            Err(_) => return error_response(&UiError::invalid("request", "Malformed request.")),
        };
        let cmd = parsed
            .get("cmd")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let mut args = match parsed.get_mut("args").map(Value::take) {
            Some(Value::Object(map)) => map,
            Some(Value::Null) | None => Map::new(),
            Some(_) => {
                scrub(&mut parsed);
                return error_response(&UiError::invalid("args", "Arguments must be an object."));
            }
        };
        scrub(&mut parsed);

        let result = self.route(&cmd, &args);
        scrub_map(&mut args);
        match result {
            Ok(value) => {
                let mut envelope = Map::new();
                envelope.insert("ok".to_owned(), value);
                let mut envelope = Value::Object(envelope);
                let bytes = encode(&envelope);
                scrub(&mut envelope);
                bytes
            }
            Err(err) => error_response(&err),
        }
    }

    fn route(&self, cmd: &str, a: &Map<String, Value>) -> Result<Value, UiError> {
        let s = &self.state;
        let clip = || self.clipboard.clone();
        match cmd {
            // Lifecycle
            "secwet_status" => out(s.secwet_status()),
            "secwet_create" => {
                let name: Option<String> = opt(a, "device_name")?;
                self.open_session(SETUP_REASON)?;
                out(s.secwet_create(Some(name.unwrap_or_else(|| self.device_name.clone()))))
            }
            "secwet_unlock" => self.unlock(),
            "secwet_lock" => {
                let result = s.secwet_lock();
                self.end_session();
                out(result)
            }

            // Spaces
            "spaces_list" => out(s.spaces_list()),
            "space_create" => out(s.space_create(req(a, "name")?, opt(a, "icon")?)),
            "space_rename" => out(s.space_rename(req(a, "id")?, req(a, "name")?, opt(a, "icon")?)),
            "space_delete" => out(s.space_delete(req(a, "id")?)),
            "space_reorder" => out(s.space_reorder(req(a, "ids")?)),

            // Groups (labels)
            "labels_list" | "groups_list" => out(s.labels_list()),
            "label_create" | "group_create" => {
                out(s.label_create_in_space(req(a, "name")?, opt(a, "icon")?, opt(a, "space_id")?))
            }
            "label_rename" | "group_rename" => {
                out(s.label_rename(req(a, "id")?, req(a, "name")?, opt(a, "icon")?))
            }
            "label_delete" | "group_delete" => out(s.label_delete(req(a, "id")?)),
            "label_reorder" | "group_reorder" => out(s.label_reorder(req(a, "ids")?)),
            "label_move_to_space" | "group_move_to_space" => {
                out(s.label_move_to_space(req(a, "id")?, req(a, "space_id")?))
            }

            // Items
            "items_list" => out(s.items_list(opt(a, "label_id")?)),
            "item_create" => {
                out(s.item_create(req(a, "label_id")?, req(a, "name")?, opt(a, "description")?))
            }
            "item_rename" => {
                out(s.item_rename(req(a, "id")?, req(a, "name")?, opt(a, "description")?))
            }
            "item_delete" => out(s.item_delete(req(a, "id")?)),

            // Environments
            "environments_list" => out(s.environments_list(req(a, "item_id")?)),
            "environment_add" => out(s.environment_add(req(a, "item_id")?, req(a, "name")?)),
            "environment_rename" => out(s.environment_rename(req(a, "id")?, req(a, "name")?)),
            "environment_delete" => {
                out(s.environment_delete(req(a, "id")?, opt(a, "preserve_content")?))
            }

            // Secrets
            "secrets_list" => out(s.secrets_list(opt(a, "item_id")?, opt(a, "environment_id")?)),
            "secret_reveal" => secret(s.secret_reveal(req(a, "id")?)),
            "secret_copy" => out(s.secret_copy(clip(), req(a, "id")?)),
            "secret_create" => out(s.secret_create(req::<SecretDraftDto>(a, "draft")?)),
            "secret_update" => {
                out(s.secret_update(req(a, "id")?, req::<SecretDraftDto>(a, "draft")?))
            }
            "secret_delete" => out(s.secret_delete(req(a, "id")?)),
            "secret_copy_to_environment" => {
                out(s.secret_copy_to_environment(req(a, "id")?, opt(a, "target_environment_id")?))
            }

            // Assets, and their older file_* names
            "assets_list" => out(s.assets_list(req(a, "item_id")?, opt(a, "environment_id")?)),
            "files_list" => out(s.files_list(req(a, "item_id")?, opt(a, "environment_id")?)),
            "asset_upload" | "file_upload" => out(s.asset_upload(
                req(a, "item_id")?,
                opt(a, "environment_id")?,
                req(a, "name")?,
                opt(a, "mime")?,
                req(a, "bytes")?,
            )),
            "asset_download" | "file_download" => {
                out_wiped(s.asset_download(req(a, "id")?), |d| d.bytes.zeroize())
            }
            "asset_rename" | "file_rename" => out(s.asset_rename(req(a, "id")?, req(a, "name")?)),
            "asset_delete" | "file_delete" => out(s.asset_delete(req(a, "id")?)),

            // Notes
            "notes_list" => out(s.notes_list(req(a, "item_id")?, opt(a, "environment_id")?)),
            "note_get" => out_wiped(s.note_get(req(a, "id")?), wipe_note),
            "note_create" => out_wiped(s.note_create(req::<NoteDraftDto>(a, "draft")?), wipe_note),
            "note_update" => out_wiped(
                s.note_update(req(a, "id")?, req::<NoteUpdateDto>(a, "draft")?),
                wipe_note,
            ),
            "note_delete" => out(s.note_delete(req(a, "id")?)),
            "note_copy_plain" => out(s.note_copy_plain(clip(), req(a, "id")?)),
            "clipboard_copy_text" => out(s.clipboard_copy_text(clip(), req(a, "text")?)),

            // Overview and dashboard
            "overview" => out(s.overview()),
            "dashboard_get" => out(s.dashboard_get()),
            "dashboard_set" => out(s.dashboard_set(req::<DashboardConfig>(a, "config")?)),

            // Settings and biometrics
            "settings_get" => {
                // Unset, the app layer answers its generic "Phone"; this host
                // knows the real device name.
                let mut settings = s.settings_get()?;
                if settings.device_name == secwet_app::commands::system_device_name() {
                    settings.device_name = self.device_name.clone();
                }
                out(Ok(settings))
            }
            "settings_set" => out(s.settings_set(req::<SettingsPatchDto>(a, "settings")?)),
            "system_device_name" => out(Ok(self.device_name.clone())),
            "biometric_status" => self.unlock_status(),

            // Projects (compatibility)
            "projects_list" => out(s.projects_list()),
            "project_create" => out(s.project_create(req(a, "name")?, req(a, "environments")?)),
            "project_rename" => out(s.project_rename(req(a, "id")?, req(a, "name")?)),
            "project_delete" => out(s.project_delete(req(a, "id")?)),

            // CLI sessions
            "active_sessions_list" => out(s.active_sessions_list()),
            "active_session_stop" => out(s.active_session_stop(req(a, "session_id")?)),

            // Recovery and backup. Paths come from the platform document picker.
            "recovery_key_create" => secret(s.recovery_key_create()),
            "recovery_key_replace" => secret(s.recovery_key_replace()),
            "recovery_status" => out(s.recovery_status()),
            "workspace_export" => {
                out(s.workspace_export(Some(req::<PathBuf>(a, "path")?), req(a, "recovery_key")?))
            }
            "workspace_restore" => {
                let name: Option<String> = opt(a, "device_name")?;
                self.open_session(SETUP_REASON)?;
                out(s.workspace_restore(
                    Some(req::<PathBuf>(a, "path")?),
                    req(a, "recovery_key")?,
                    Some(name.unwrap_or_else(|| self.device_name.clone())),
                ))
            }

            // Relay
            "relay_status" => out(runtime::block_on(s.relay_status())),
            "relay_register" => out(runtime::block_on(s.relay_register())),
            "relay_set_url" => out(s.relay_set_url(req(a, "url")?)),

            // Devices and pairing
            "devices_list" => out(s.devices_list()),
            "pairing_start" => out(runtime::block_on(s.pairing_start())),
            "pairing_poll" => out(runtime::block_on(s.pairing_poll())),
            "pairing_approve" => out(runtime::block_on(s.pairing_approve())),
            "pairing_cancel" => out(s.pairing_cancel()),
            // This phone as the new device (QR scan or secwet://pair link).
            "pairing_join_start" => {
                let name: Option<String> = opt(a, "device_name")?;
                self.open_session(SETUP_REASON)?;
                out(runtime::block_on(s.pairing_join_start(
                    req(a, "link")?,
                    name.unwrap_or_else(|| self.device_name.clone()),
                    platform_name().to_owned(),
                )))
            }
            "pairing_join_poll" => out(runtime::block_on(s.pairing_join_poll())),
            "pairing_join_cancel" => out(s.pairing_join_cancel()),

            // Plan (F13). Free never contacts the relay except plan_activate.
            "plan_status" => out(s.plan_status()),
            "plan_refresh" => out(runtime::block_on(s.plan_refresh())),
            "plan_activate" => out(runtime::block_on(s.plan_activate())),

            // Sync
            "sync_now" => {
                let (pushed, pulled) = runtime::block_on(s.sync_now())?;
                Ok(json!({ "pushed": pushed, "pulled": pulled }))
            }
            "sync_status" => out(s.sync_status()),

            // M7: revocation and key rotation
            "device_revoke" => {
                let wipe: Option<bool> = opt(a, "wipe")?;
                out(runtime::block_on(
                    s.device_revoke(req(a, "device_id")?, wipe.unwrap_or(false)),
                ))
            }
            "key_status" => out(s.key_status()),
            "key_rotate" => out(runtime::block_on(s.key_rotate())),
            "link_status" => out(s.link_status()),

            // M8: collaboration
            "members_list" => out(runtime::block_on(s.members_list())),
            "member_invite" => out(runtime::block_on(
                s.member_invite(req(a, "email")?, req::<Vec<GrantInput>>(a, "grants")?),
            )),
            "member_set_grants" => out(runtime::block_on(
                s.member_set_grants(req(a, "member_id")?, req::<Vec<GrantInput>>(a, "grants")?),
            )),
            "member_remove" => {
                let wipe: Option<bool> = opt(a, "wipe")?;
                out(runtime::block_on(
                    s.member_remove(req(a, "member_id")?, wipe.unwrap_or(false)),
                ))
            }
            "invitation_revoke" => out(runtime::block_on(
                s.invitation_revoke(req(a, "invitation_id")?),
            )),
            "invitation_accept" => {
                let name: Option<String> = opt(a, "device_name")?;
                self.open_session(SETUP_REASON)?;
                out(runtime::block_on(s.invitation_accept(
                    req(a, "link")?,
                    req(a, "email")?,
                    name.unwrap_or_else(|| self.device_name.clone()),
                )))
            }
            "scope_nodes" => out(s.scope_nodes(req(a, "space_id")?)),
            "my_access" => out(s.my_access()),
            "invite_link_copy" => {
                let raw: String = req(a, "invitation_id")?;
                let id = Uuid::parse_str(&raw)
                    .map_err(|_| UiError::invalid("invitation", "Invalid id."))?;
                out(s.invite_link_copy(clip(), id))
            }

            _ => Err(UiError::new(
                "unknown_command",
                Some("cmd".to_owned()),
                format!("Unknown command: {cmd}"),
            )),
        }
    }
}

/// Platform name the approving device shows for this phone.
fn platform_name() -> &'static str {
    if cfg!(target_os = "ios") {
        "iOS"
    } else if cfg!(target_os = "android") {
        "Android"
    } else {
        std::env::consts::OS
    }
}

/// Required argument.
fn req<T: DeserializeOwned>(args: &Map<String, Value>, name: &str) -> Result<T, UiError> {
    match args.get(name) {
        None | Some(Value::Null) => Err(UiError::invalid(name, format!("Missing {name}."))),
        Some(v) => {
            T::deserialize(v).map_err(|_| UiError::invalid(name, format!("Invalid {name}.")))
        }
    }
}

/// Optional argument; missing and null both mean `None`.
fn opt<T: DeserializeOwned>(args: &Map<String, Value>, name: &str) -> Result<Option<T>, UiError> {
    match args.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => T::deserialize(v)
            .map(Some)
            .map_err(|_| UiError::invalid(name, format!("Invalid {name}."))),
    }
}

fn to_value<T: Serialize>(value: T) -> Result<Value, UiError> {
    serde_json::to_value(value).map_err(|_| UiError::internal("Could not encode the response."))
}

fn out<T: Serialize>(result: Result<T, UiError>) -> Result<Value, UiError> {
    to_value(result?)
}

/// [out] for DTOs holding plaintext: serializes from a reference, then wipes
/// the DTO with `wipe` before it is dropped. The response value itself is
/// scrubbed by `handle` once encoded.
fn out_wiped<T: Serialize>(
    result: Result<T, UiError>,
    wipe: impl FnOnce(&mut T),
) -> Result<Value, UiError> {
    let mut dto = result?;
    let value = to_value(&dto);
    wipe(&mut dto);
    value
}

fn wipe_note(note: &mut secwet_core::model::NoteView) {
    note.title.zeroize();
    note.content.zeroize();
}

/// Moves a secret string into the response without leaving a copy behind.
fn secret(result: Result<String, UiError>) -> Result<Value, UiError> {
    result.map(Value::String)
}

fn error_response(err: &UiError) -> Zeroizing<Vec<u8>> {
    encode(&json!({ "err": err }))
}

/// Serializes into a buffer of the exact size, so no partially filled copy
/// is left behind by a reallocation.
fn encode(value: &Value) -> Zeroizing<Vec<u8>> {
    struct Count(usize);
    impl std::io::Write for Count {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 += buf.len();
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut count = Count(0);
    if serde_json::to_writer(&mut count, value).is_err() {
        return Zeroizing::new(br#"{"err":{"code":"internal","field":null,"message":"Could not encode the response."}}"#.to_vec());
    }
    let mut buf = Zeroizing::new(Vec::with_capacity(count.0));
    let _ = serde_json::to_writer(&mut *buf, value);
    buf
}

/// Overwrites every string and number in `value` before it is dropped.
/// Numbers matter: asset bytes travel as arrays of them.
pub(crate) fn scrub(value: &mut Value) {
    match value {
        Value::String(s) => s.zeroize(),
        Value::Number(n) => *n = serde_json::Number::from(0u8),
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(map) => scrub_map(map),
        _ => {}
    }
}

fn scrub_map(map: &mut Map<String, Value>) {
    map.values_mut().for_each(scrub);
}

fn screen_lock_required() -> UiError {
    UiError::new(
        "screen_lock_required",
        None,
        "Set a screen lock to use Secwet.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrub_wipes_strings_and_byte_arrays() {
        let mut v = json!({ "value": "hunter2", "bytes": [45, 45, 45, 66], "nested": [{ "body": "note" }] });
        scrub(&mut v);
        // String::zeroize overwrites the buffer and leaves it empty.
        assert_eq!(v["value"], "");
        assert_eq!(v["bytes"], json!([0, 0, 0, 0]));
        assert_eq!(v["nested"][0]["body"], "");
    }
}
