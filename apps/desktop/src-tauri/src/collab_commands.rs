//! Tauri commands for revocation, key rotation (F16) and collaboration (F19).
//!
//! IPC contract: `docs/m7-m8-architecture.md` §10. The logic lives in
//! `secwet_app::collab`; these wrappers only adapt Tauri arguments.

use std::sync::Arc;

use secwet_core::collab::KeyRotationReport;
use tauri::{AppHandle, State};
use uuid::Uuid;

pub use secwet_app::collab::{
    AccessView, GrantInput, GrantView, InviteResultDto, KeyStatusDto, LinkStatusDto,
    MemberDeviceView, MemberView, RevokeResultDto, ScopeNodeView,
};

use crate::clipboard::TauriClipboard;
use crate::error::UiError;
use crate::state::{AppState, SecwetStatusDto};

// ============================================================================
// M7
// ============================================================================

#[tauri::command]
pub async fn device_revoke(
    state: State<'_, AppState>,
    device_id: String,
    wipe: Option<bool>,
) -> Result<RevokeResultDto, UiError> {
    state.device_revoke(device_id, wipe.unwrap_or(false)).await
}

#[tauri::command]
pub fn key_status(state: State<'_, AppState>) -> Result<KeyStatusDto, UiError> {
    state.key_status()
}

#[tauri::command]
pub async fn key_rotate(state: State<'_, AppState>) -> Result<KeyRotationReport, UiError> {
    state.key_rotate().await
}

#[tauri::command]
pub fn link_status(state: State<'_, AppState>) -> Result<LinkStatusDto, UiError> {
    state.link_status()
}

// ============================================================================
// M8
// ============================================================================

#[tauri::command]
pub async fn members_list(state: State<'_, AppState>) -> Result<Vec<MemberView>, UiError> {
    state.members_list().await
}

#[tauri::command]
pub async fn member_invite(
    state: State<'_, AppState>,
    email: String,
    grants: Vec<GrantInput>,
) -> Result<InviteResultDto, UiError> {
    state.member_invite(email, grants).await
}

#[tauri::command]
pub async fn member_set_grants(
    state: State<'_, AppState>,
    member_id: String,
    grants: Vec<GrantInput>,
) -> Result<MemberView, UiError> {
    state.member_set_grants(member_id, grants).await
}

#[tauri::command]
pub async fn member_remove(
    state: State<'_, AppState>,
    member_id: String,
    wipe: Option<bool>,
) -> Result<(), UiError> {
    state.member_remove(member_id, wipe.unwrap_or(false)).await
}

#[tauri::command]
pub async fn invitation_revoke(
    state: State<'_, AppState>,
    invitation_id: String,
) -> Result<(), UiError> {
    state.invitation_revoke(invitation_id).await
}

#[tauri::command]
pub async fn invitation_accept(
    state: State<'_, AppState>,
    link: String,
    email: String,
    device_name: String,
) -> Result<SecwetStatusDto, UiError> {
    state.invitation_accept(link, email, device_name).await
}

#[tauri::command]
pub fn scope_nodes(state: State<'_, AppState>, space_id: String) -> Result<Vec<ScopeNodeView>, UiError> {
    state.scope_nodes(space_id)
}

#[tauri::command]
pub fn my_access(state: State<'_, AppState>) -> Result<AccessView, UiError> {
    state.my_access()
}

#[tauri::command]
pub fn invite_link_copy(app: AppHandle, state: State<'_, AppState>, invitation_id: String) -> Result<(), UiError> {
    let id = Uuid::parse_str(&invitation_id)
        .map_err(|_| UiError::new("invalid", Some("invitation".to_string()), "Invalid id."))?;
    state.invite_link_copy(Arc::new(TauriClipboard::new(app)), id)
}
