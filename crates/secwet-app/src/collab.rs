//! Revocation, key rotation (F16) and collaboration (F19) commands.
//!
//! IPC contract: `docs/m7-m8-architecture.md` §10.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use secwet_core::collab::{KeyRotationReport, MemberInfo, RevocationOutcome, ScopeNode};
use secwet_core::{Error, RelayClient, Secwet};
use secwet_proto::{TreeNode, TreeRole};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::clipboard::ClipboardPort;
use crate::error::UiError;
use crate::events::AppEvent;
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

pub(crate) fn parse_uuid(s: &str, field: &str) -> Result<Uuid, UiError> {
    Uuid::parse_str(s).map_err(|_| UiError::new("invalid", Some(field.to_string()), "Invalid id."))
}

/// Marks a store taken out of state for a network call. Dropping it (also on
/// panic) ends the in-flight period.
pub(crate) struct Ticket {
    generation: u64,
    in_flight: Arc<AtomicU64>,
}

impl Drop for Ticket {
    fn drop(&mut self) {
        self.in_flight.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Whether a network command reports a verified revocation to the UI as a
/// `wiped`/`unlinked` event, besides returning the error.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Notify {
    Yes,
    No,
}

impl AppState {
    /// Takes the unlocked store out of state so it can be used across awaits.
    /// Free stores never contact the relay (F13): they get `needs_pro` here,
    /// before any network call.
    pub(crate) fn take(&self) -> Result<(Secwet, RelayClient, Ticket), UiError> {
        self.take_inner(true)
    }

    /// `take` without the plan check, for the user's explicit "Check for Pro".
    pub(crate) fn take_unchecked(&self) -> Result<(Secwet, RelayClient, Ticket), UiError> {
        self.take_inner(false)
    }

    fn take_inner(&self, plan_check: bool) -> Result<(Secwet, RelayClient, Ticket), UiError> {
        let mut guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = guard.take().ok_or_else(|| self.locked_or_busy())?;
        if plan_check {
            if let Err(e) = secwet.ensure_relay_allowed(secwet_core::RelayOp::Entitlement) {
                *guard = Some(secwet);
                return Err(UiError::from(e));
            }
        }
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
        self.in_flight.fetch_add(1, Ordering::SeqCst);
        let ticket = Ticket {
            generation: self.lock_generation.load(Ordering::SeqCst),
            in_flight: Arc::clone(&self.in_flight),
        };
        let client = RelayClient::new(&relay_url, secwet.device_id().to_string());
        Ok((secwet, client, ticket))
    }

    /// Returns the store to state, unless the app was locked meanwhile: then the
    /// store is locked (keys zeroized) instead of silently unlocking the app.
    pub(crate) fn put(&self, secwet: Secwet, ticket: Ticket) -> Result<(), UiError> {
        let mut guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        if ticket.generation != self.lock_generation.load(Ordering::SeqCst) || guard.is_some() {
            secwet.lock();
        } else {
            *guard = Some(secwet);
        }
        drop(ticket);
        Ok(())
    }

    /// `finish` for plan checks: a verified revocation is reported to the UI.
    pub(crate) fn finish_plan<T>(
        &self,
        secwet: Secwet,
        ticket: Ticket,
        result: Result<T, Error>,
    ) -> Result<T, UiError> {
        self.finish(Notify::Yes, secwet, ticket, result)
    }

    /// Returns the store to state, executing a verified revocation first when
    /// the relay reported this device as revoked.
    fn finish<T>(
        &self,
        notify: Notify,
        mut secwet: Secwet,
        ticket: Ticket,
        result: Result<T, Error>,
    ) -> Result<T, UiError> {
        match result {
            Err(Error::RevocationNotice(notice)) => {
                let outcome = secwet.handle_revocation_notice(&notice, self.keystore.as_ref());
                match outcome {
                    Ok(RevocationOutcome::Wiped) => {
                        drop(secwet);
                        drop(ticket);
                        if notify == Notify::Yes {
                            self.emit(AppEvent::Wiped);
                        }
                        Err(UiError::new("wiped", None, "This device was erased."))
                    }
                    Ok(RevocationOutcome::Archived) => {
                        self.put(secwet, ticket)?;
                        if notify == Notify::Yes {
                            self.emit(AppEvent::Unlinked);
                        }
                        Err(UiError::new(
                            "revoked",
                            None,
                            "This device was unlinked from Secwet. Sync is disabled.",
                        ))
                    }
                    Err(e) => {
                        self.put(secwet, ticket)?;
                        Err(UiError::from(e))
                    }
                }
            }
            other => {
                self.put(secwet, ticket)?;
                other.map_err(UiError::from)
            }
        }
    }

    // ========================================================================
    // M7
    // ========================================================================

    /// Revokes one of this Secwet's devices. On the Pro plan the relay is told
    /// (and the device erased on its next contact when `wipe`); on Free only
    /// the local record changes.
    pub async fn device_revoke(
        &self,
        device_id: String,
        wipe: bool,
    ) -> Result<RevokeResultDto, UiError> {
        // Pro, and Pro that ended (revocation is never locked behind a plan),
        // tell the relay.
        let pro = self.with_secwet(|s| s.plan_state())? != secwet_core::PlanState::Free;
        if !pro {
            // Free plan: no relay; only the local record changes.
            self.with_secwet_mut(|s| s.device_revoke(&device_id))?;
        } else {
            let (mut secwet, client, ticket) = self.take()?;
            let res = secwet
                .device_revoke_remote(&client, &device_id, wipe)
                .await
                .map(|_| ());
            self.finish(Notify::Yes, secwet, ticket, res)?;
        }
        let rotation_recommended = self.with_secwet(|s| s.key_status())?.rotation_recommended;
        self.emit_changed("devices");
        Ok(RevokeResultDto {
            device_id,
            wipe_requested: wipe && pro,
            rotation_recommended,
        })
    }

    pub fn key_status(&self) -> Result<KeyStatusDto, UiError> {
        let k = self.with_secwet(|s| s.key_status())?;
        Ok(KeyStatusDto {
            epoch: k.epoch,
            rotated_at: k.rotated_at,
            rotation_recommended: k.rotation_recommended,
            pending_reason: k.pending_reason,
        })
    }

    pub async fn key_rotate(&self) -> Result<KeyRotationReport, UiError> {
        let (mut secwet, client, ticket) = self.take()?;
        let res = secwet.rotate_master_key(&client, self.keystore.as_ref()).await;
        let report = self.finish(Notify::Yes, secwet, ticket, res)?;
        self.emit_changed("all");
        Ok(report)
    }

    pub fn link_status(&self) -> Result<LinkStatusDto, UiError> {
        let at = self.with_secwet(|s| s.unlinked_at())?;
        Ok(LinkStatusDto {
            state: if at.is_some() { "unlinked" } else { "active" }.into(),
            revoked_at: at,
        })
    }

    /// Collaboration-aware sync round (keys, invitations, events); returns
    /// (pushed, pulled).
    pub async fn sync_round(&self) -> Result<(usize, usize), UiError> {
        let (mut secwet, client, ticket) = self.take()?;
        let res = secwet.sync_round(&client, self.keystore.as_ref()).await;
        let out = self.finish(Notify::Yes, secwet, ticket, res)?;
        self.emit_changed("all");
        Ok(out)
    }

    // ========================================================================
    // M8
    // ========================================================================

    pub async fn members_list(&self) -> Result<Vec<MemberView>, UiError> {
        let (mut secwet, client, ticket) = self.take()?;
        let res = secwet.members_list(&client).await;
        let views =
            res.map(|ms| ms.into_iter().map(|m| member_view(&secwet, m)).collect::<Vec<_>>());
        self.finish(Notify::No, secwet, ticket, views)
    }

    pub async fn member_invite(
        &self,
        email: String,
        grants: Vec<GrantInput>,
    ) -> Result<InviteResultDto, UiError> {
        let grants = parse_grants(&grants)?;
        let (mut secwet, client, ticket) = self.take()?;
        let res = secwet
            .invite_member(&client, self.keystore.as_ref(), &email, &grants)
            .await;
        let r = self.finish(Notify::No, secwet, ticket, res)?;
        if let Ok(mut links) = self.invite_links.lock() {
            links.insert(r.invitation_id, secrecy::SecretString::from(r.link.clone()));
        }
        Ok(InviteResultDto {
            invitation_id: r.invitation_id.to_string(),
            member_id: r.member_id.to_string(),
            link: r.link,
            expires_at: r.expires_at,
        })
    }

    pub async fn member_set_grants(
        &self,
        member_id: String,
        grants: Vec<GrantInput>,
    ) -> Result<MemberView, UiError> {
        let member = parse_uuid(&member_id, "member")?;
        let grants = parse_grants(&grants)?;
        let (mut secwet, client, ticket) = self.take()?;
        let res = async {
            secwet
                .set_member_grants(&client, self.keystore.as_ref(), member, &grants)
                .await?;
            let list = secwet.members_list(&client).await?;
            list.into_iter()
                .find(|m| m.member_id == member)
                .ok_or(Error::NotFound)
        }
        .await;
        let view = res.map(|m| member_view(&secwet, m));
        self.finish(Notify::No, secwet, ticket, view)
    }

    pub async fn member_remove(&self, member_id: String, wipe: bool) -> Result<(), UiError> {
        let member = parse_uuid(&member_id, "member")?;
        let (mut secwet, client, ticket) = self.take()?;
        let res = secwet
            .remove_member(&client, self.keystore.as_ref(), member, wipe)
            .await;
        self.finish(Notify::No, secwet, ticket, res)
    }

    pub async fn invitation_revoke(&self, invitation_id: String) -> Result<(), UiError> {
        let inv = parse_uuid(&invitation_id, "invitation")?;
        let (mut secwet, client, ticket) = self.take()?;
        let res = secwet.revoke_invitation(&client, inv).await;
        self.finish(Notify::No, secwet, ticket, res)
    }

    /// Joins a Secwet from an invite link on a device that has none yet.
    pub async fn invitation_accept(
        &self,
        link: String,
        email: String,
        device_name: String,
    ) -> Result<SecwetStatusDto, UiError> {
        {
            let guard = self
                .secwet
                .lock()
                .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
            if guard.is_some() {
                return Err(UiError::already_initialized());
            }
        }
        let secwet = Secwet::accept_invitation(
            &self.data_dir,
            &link,
            &email,
            &device_name,
            self.keystore.as_ref(),
        )
        .await?;
        let status = SecwetStatusDto::from(secwet.current_status());
        let mut guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        *guard = Some(secwet);
        Ok(status)
    }

    pub fn scope_nodes(&self, space_id: String) -> Result<Vec<ScopeNodeView>, UiError> {
        let space = parse_uuid(&space_id, "space")?;
        let nodes: Vec<ScopeNode> = self.with_secwet(|s| s.scope_nodes(space))?;
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

    pub fn my_access(&self) -> Result<AccessView, UiError> {
        self.with_secwet(|s| {
            Ok(AccessView {
                is_owner: s.is_owner(),
                grants: s
                    .my_grants()
                    .iter()
                    .map(|g| grant_view(s, g.node, g.role))
                    .collect(),
            })
        })
    }

    /// Copies an invite link created in this session through the auto-clearing
    /// clipboard (30 s), like secret values.
    pub fn invite_link_copy<C: ClipboardPort + ?Sized>(
        &self,
        clipboard: Arc<C>,
        invitation_id: Uuid,
    ) -> Result<(), UiError> {
        use secrecy::ExposeSecret;
        let link = {
            let links = self
                .invite_links
                .lock()
                .map_err(|_| UiError::internal("Invite link mutex poisoned"))?;
            links
                .get(&invitation_id)
                .map(|l| l.expose_secret().to_string())
                .ok_or_else(|| {
                    UiError::new(
                        "not_found",
                        None,
                        "This invite link is no longer available. Revoke it and invite again.",
                    )
                })?
        };
        self.auto_clear(clipboard)
            .copy_secret(&link)
            .map_err(UiError::internal)
    }
}
