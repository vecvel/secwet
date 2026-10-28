//! Tauri commands for revocation, key rotation (F16) and collaboration (F19).
//!
//! IPC contract: `docs/m7-m8-architecture.md` §10.

use secwet_core::collab::{KeyRotationReport, MemberInfo, RevocationOutcome, ScopeNode};
use secwet_core::{Error, RelayClient, Secwet};
use secwet_proto::{TreeNode, TreeRole};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter, State};
use uuid::Uuid;

use crate::error::UiError;
use crate::state::{AppState, SecwetStatusDto};

// ============================================================================
// DTOs
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantInput {
    pub kind: String,
    pub id: Option<String>,
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct GrantView {
    pub kind: String,
    pub id: Option<String>,
    pub role: String,
    pub label: String,
    pub space_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemberDeviceView {
    pub id: String,
    pub fingerprint: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemberView {
    pub member_id: String,
    pub email: Option<String>,
    pub status: String,
    pub grants: Vec<GrantView>,
    pub devices: Vec<MemberDeviceView>,
    pub invited_at: i64,
    pub invitation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct InviteResultDto {
    pub invitation_id: String,
    pub member_id: String,
    pub link: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScopeNodeView {
    pub kind: String,
    pub id: String,
    pub label: String,
    pub depth: u8,
    pub parent_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccessView {
    pub is_owner: bool,
    pub grants: Vec<GrantView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RevokeResultDto {
    pub device_id: String,
    pub wipe_requested: bool,
    pub rotation_recommended: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeyStatusDto {
    pub epoch: u32,
    pub rotated_at: Option<i64>,
    pub rotation_recommended: bool,
    pub pending_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LinkStatusDto {
    pub state: String,
    pub revoked_at: Option<i64>,
}

// ============================================================================
// Helpers
// ============================================================================

fn parse_grants(grants: &[GrantInput]) -> Result<Vec<(TreeNode, TreeRole)>, UiError> {
    let invalid = || UiError::new("invalid", Some("grants".into()), "Choose who gets access and their role.");
    grants
        .iter()
        .map(|g| {
            let id = match &g.id {
                Some(s) if !s.is_empty() => Some(Uuid::parse_str(s).map_err(|_| invalid())?),
                _ => None,
            };
            let node = TreeNode::from_parts(&g.kind, id).ok_or_else(invalid)?;
            let role = TreeRole::parse(&g.role).ok_or_else(invalid)?;
            Ok((node, role))
        })
        .collect()
}

fn grant_view(s: &Secwet, node: TreeNode, role: TreeRole) -> GrantView {
    GrantView {
        kind: node.kind_str().to_string(),
        id: node.id().map(|u| u.to_string()),
        role: role.as_str().to_string(),
        label: s.node_label(node),
        space_id: s.space_of_node(node).ok().flatten().map(|u| u.to_string()),
    }
}

fn member_view(s: &Secwet, m: MemberInfo) -> MemberView {
    MemberView {
        member_id: m.member_id.to_string(),
        email: m.email,
        status: m.status,
        grants: m.grants.iter().map(|g| grant_view(s, g.node, g.role)).collect(),
        devices: m
            .devices
            .into_iter()
            .map(|d| MemberDeviceView { id: d.id, fingerprint: d.fingerprint, revoked: d.revoked })
            .collect(),
        invited_at: m.invited_at,
        invitation_id: m.invitation_id.map(|i| i.to_string()),
    }
}

fn parse_uuid(s: &str, field: &str) -> Result<Uuid, UiError> {
    Uuid::parse_str(s).map_err(|_| UiError::new("invalid", Some(field.to_string()), "Invalid id."))
}

/// Marks a store taken out of state for a network call. Dropping it (also on
/// panic) ends the in-flight period.
struct Ticket {
    generation: u64,
    in_flight: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Takes the unlocked store out of state so it can be used across awaits.
fn take(state: &AppState) -> Result<(Secwet, RelayClient, Ticket), UiError> {
    use std::sync::atomic::Ordering;
    let mut guard = state
        .secwet
        .lock()
        .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
    let secwet = guard.take().ok_or_else(|| state.locked_or_busy())?;
    let relay_url = match secwet.relay_url() {
        Ok(u) => u,
        Err(_) => {
            *guard = Some(secwet);
            return Err(UiError::new(
                "relay_not_configured",
                None,
                "Sync isn't set up on this device.",
            ));
        }
    };
    state.in_flight.fetch_add(1, Ordering::SeqCst);
    let ticket = Ticket {
        generation: state.lock_generation.load(Ordering::SeqCst),
        in_flight: std::sync::Arc::clone(&state.in_flight),
    };
    let client = RelayClient::new(&relay_url, secwet.device_id().to_string());
    Ok((secwet, client, ticket))
}

/// Returns the store to state, unless the app was locked meanwhile: then the
/// store is locked (keys zeroized) instead of silently unlocking the app.
fn put(state: &AppState, secwet: Secwet, ticket: Ticket) -> Result<(), UiError> {
    let mut guard = state
        .secwet
        .lock()
        .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
    if ticket.generation != state.lock_generation.load(std::sync::atomic::Ordering::SeqCst) || guard.is_some() {
        secwet.lock();
    } else {
        *guard = Some(secwet);
    }
    drop(ticket);
    Ok(())
}

/// Returns the store to state, executing a verified revocation first when
/// the relay reported this device as revoked.
async fn finish<T>(
    app: Option<&AppHandle>,
    state: &AppState,
    client: &RelayClient,
    mut secwet: Secwet,
    ticket: Ticket,
    result: Result<T, Error>,
) -> Result<T, UiError> {
    match result {
        Err(Error::RevocationNotice(notice)) => {
            let _ = client;
            let outcome = secwet.handle_revocation_notice(&notice, state.keystore.as_ref());
            match outcome {
                Ok(RevocationOutcome::Wiped) => {
                    drop(secwet);
                    drop(ticket);
                    if let Some(a) = app {
                        let _ = a.emit("secwet://wiped", serde_json::json!({}));
                    }
                    Err(UiError::new("wiped", None, "This device was erased."))
                }
                Ok(RevocationOutcome::Archived) => {
                    put(state, secwet, ticket)?;
                    if let Some(a) = app {
                        let _ = a.emit("secwet://unlinked", serde_json::json!({}));
                    }
                    Err(UiError::new("revoked", None, "This device was unlinked from Secwet. Sync is disabled."))
                }
                Err(e) => {
                    put(state, secwet, ticket)?;
                    Err(UiError::from(e))
                }
            }
        }
        other => {
            put(state, secwet, ticket)?;
            other.map_err(UiError::from)
        }
    }
}

// ============================================================================
// M7
// ============================================================================

pub async fn device_revoke_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    device_id: String,
    wipe: bool,
) -> Result<RevokeResultDto, UiError> {
    let pro = state.with_secwet(|s| s.plan())? == "pro";
    if !pro {
        // Free plan: no relay; only the local record changes.
        state.with_secwet_mut(|s| s.device_revoke(&device_id))?;
    } else {
        let (mut secwet, client, ticket) = take(state)?;
        let res = secwet.device_revoke_remote(&client, &device_id, wipe).await.map(|_| ());
        finish(app, state, &client, secwet, ticket, res).await?;
    }
    let rotation_recommended = state.with_secwet(|s| s.key_status())?.rotation_recommended;
    if let Some(a) = app {
        let _ = a.emit("secwet://changed", serde_json::json!({ "scope": "devices" }));
    }
    Ok(RevokeResultDto { device_id, wipe_requested: wipe && pro, rotation_recommended })
}

#[tauri::command]
pub async fn device_revoke(
    app: AppHandle,
    state: State<'_, AppState>,
    device_id: String,
    wipe: Option<bool>,
) -> Result<RevokeResultDto, UiError> {
    device_revoke_impl(Some(&app), &state, device_id, wipe.unwrap_or(false)).await
}

#[tauri::command]
pub fn key_status(state: State<'_, AppState>) -> Result<KeyStatusDto, UiError> {
    let k = state.with_secwet(|s| s.key_status())?;
    Ok(KeyStatusDto {
        epoch: k.epoch,
        rotated_at: k.rotated_at,
        rotation_recommended: k.rotation_recommended,
        pending_reason: k.pending_reason,
    })
}

#[tauri::command]
pub async fn key_rotate(app: AppHandle, state: State<'_, AppState>) -> Result<KeyRotationReport, UiError> {
    let (mut secwet, client, ticket) = take(&state)?;
    let res = secwet.rotate_master_key(&client, state.keystore.as_ref()).await;
    let report = finish(Some(&app), &state, &client, secwet, ticket, res).await?;
    let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "all" }));
    Ok(report)
}

#[tauri::command]
pub fn link_status(state: State<'_, AppState>) -> Result<LinkStatusDto, UiError> {
    let at = state.with_secwet(|s| s.unlinked_at())?;
    Ok(LinkStatusDto {
        state: if at.is_some() { "unlinked" } else { "active" }.into(),
        revoked_at: at,
    })
}

/// Collaboration-aware sync round (keys, invitations, events).
pub async fn sync_round_impl(app: Option<&AppHandle>, state: &AppState) -> Result<(usize, usize), UiError> {
    let (mut secwet, client, ticket) = take(state)?;
    let res = secwet.sync_round(&client, state.keystore.as_ref()).await;
    let out = finish(app, state, &client, secwet, ticket, res).await?;
    if let Some(a) = app {
        let _ = a.emit("secwet://changed", serde_json::json!({ "scope": "all" }));
    }
    Ok(out)
}

// ============================================================================
// M8
// ============================================================================

#[tauri::command]
pub async fn members_list(state: State<'_, AppState>) -> Result<Vec<MemberView>, UiError> {
    let (mut secwet, client, ticket) = take(&state)?;
    let res = secwet.members_list(&client).await;
    let views = res.map(|ms| ms.into_iter().map(|m| member_view(&secwet, m)).collect::<Vec<_>>());
    finish(None, &state, &client, secwet, ticket, views).await
}

#[tauri::command]
pub async fn member_invite(
    state: State<'_, AppState>,
    email: String,
    grants: Vec<GrantInput>,
) -> Result<InviteResultDto, UiError> {
    let grants = parse_grants(&grants)?;
    let (mut secwet, client, ticket) = take(&state)?;
    let res = secwet.invite_member(&client, state.keystore.as_ref(), &email, &grants).await;
    let r = finish(None, &state, &client, secwet, ticket, res).await?;
    if let Ok(mut links) = state.invite_links.lock() {
        links.insert(r.invitation_id, secrecy::SecretString::from(r.link.clone()));
    }
    Ok(InviteResultDto {
        invitation_id: r.invitation_id.to_string(),
        member_id: r.member_id.to_string(),
        link: r.link,
        expires_at: r.expires_at,
    })
}

#[tauri::command]
pub async fn member_set_grants(
    state: State<'_, AppState>,
    member_id: String,
    grants: Vec<GrantInput>,
) -> Result<MemberView, UiError> {
    let member = parse_uuid(&member_id, "member")?;
    let grants = parse_grants(&grants)?;
    let (mut secwet, client, ticket) = take(&state)?;
    let res = async {
        secwet.set_member_grants(&client, state.keystore.as_ref(), member, &grants).await?;
        let list = secwet.members_list(&client).await?;
        list.into_iter().find(|m| m.member_id == member).ok_or(Error::NotFound)
    }
    .await;
    let view = res.map(|m| member_view(&secwet, m));
    finish(None, &state, &client, secwet, ticket, view).await
}

#[tauri::command]
pub async fn member_remove(state: State<'_, AppState>, member_id: String, wipe: Option<bool>) -> Result<(), UiError> {
    let member = parse_uuid(&member_id, "member")?;
    let (mut secwet, client, ticket) = take(&state)?;
    let res = secwet
        .remove_member(&client, state.keystore.as_ref(), member, wipe.unwrap_or(false))
        .await;
    finish(None, &state, &client, secwet, ticket, res).await
}

#[tauri::command]
pub async fn invitation_revoke(state: State<'_, AppState>, invitation_id: String) -> Result<(), UiError> {
    let inv = parse_uuid(&invitation_id, "invitation")?;
    let (mut secwet, client, ticket) = take(&state)?;
    let res = secwet.revoke_invitation(&client, inv).await;
    finish(None, &state, &client, secwet, ticket, res).await
}

pub async fn invitation_accept_impl(
    state: &AppState,
    link: String,
    email: String,
    device_name: String,
) -> Result<SecwetStatusDto, UiError> {
    {
        let guard = state
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        if guard.is_some() {
            return Err(UiError::already_initialized());
        }
    }
    let secwet = Secwet::accept_invitation(&state.data_dir, &link, &email, &device_name, state.keystore.as_ref()).await?;
    let status = SecwetStatusDto::from(secwet.current_status());
    let mut guard = state
        .secwet
        .lock()
        .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
    *guard = Some(secwet);
    Ok(status)
}

#[tauri::command]
pub async fn invitation_accept(
    state: State<'_, AppState>,
    link: String,
    email: String,
    device_name: String,
) -> Result<SecwetStatusDto, UiError> {
    invitation_accept_impl(&state, link, email, device_name).await
}

#[tauri::command]
pub fn scope_nodes(state: State<'_, AppState>, space_id: String) -> Result<Vec<ScopeNodeView>, UiError> {
    let space = parse_uuid(&space_id, "space")?;
    let nodes: Vec<ScopeNode> = state.with_secwet(|s| s.scope_nodes(space))?;
    Ok(nodes
        .into_iter()
        .filter_map(|n| {
            Some(ScopeNodeView {
                kind: n.node.kind_str().to_string(),
                id: n.node.id()?.to_string(),
                label: n.label,
                depth: n.depth,
                parent_id: n.parent.and_then(|p| p.id()).map(|u| u.to_string()),
            })
        })
        .collect())
}

#[tauri::command]
pub fn my_access(state: State<'_, AppState>) -> Result<AccessView, UiError> {
    state.with_secwet(|s| {
        Ok(AccessView {
            is_owner: s.is_owner(),
            grants: s.my_grants().iter().map(|g| grant_view(s, g.node, g.role)).collect(),
        })
    })
}

/// Copies an invite link created in this session through the auto-clearing
/// clipboard (30 s), like secret values.
pub fn invite_link_copy_impl<C: crate::clipboard::ClipboardPort>(
    clipboard: std::sync::Arc<C>,
    state: &AppState,
    invitation_id: Uuid,
) -> Result<(), UiError> {
    use secrecy::ExposeSecret;
    let link = {
        let links = state
            .invite_links
            .lock()
            .map_err(|_| UiError::internal("Invite link mutex poisoned"))?;
        links
            .get(&invitation_id)
            .map(|l| l.expose_secret().to_string())
            .ok_or_else(|| UiError::new("not_found", None, "This invite link is no longer available. Revoke it and invite again."))?
    };
    let manager = crate::clipboard::AutoClearManager::new(
        clipboard,
        std::sync::Arc::clone(&state.clipboard_generation),
        state.clear_duration,
    );
    manager.copy_secret(&link).map_err(UiError::internal)
}

#[tauri::command]
pub fn invite_link_copy(app: AppHandle, state: State<'_, AppState>, invitation_id: String) -> Result<(), UiError> {
    let id = parse_uuid(&invitation_id, "invitation")?;
    invite_link_copy_impl(std::sync::Arc::new(crate::clipboard::TauriClipboard::new(app)), &state, id)
}
