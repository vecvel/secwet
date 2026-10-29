//! HTTP handlers for device revocation and master key rotation and for
//! collaboration: members, invitations, tree-wise grants and branch keys.
//!
//! Every decision
//! that destroys data or grants access is backed by an Ed25519 signature the
//! relay verifies here and the clients verify again.

use axum::{
    body::to_bytes,
    extract::{ConnectInfo, Extension, Path, Request, State},
    Json,
};
use chrono::{DateTime, TimeZone, Utc};
use secwet_core::crypto::{compute_device_id, verify_signature_strict_bytes};
use secwet_proto::{
    effective_role, granted_spaces, validate_grants, AcceptInvitationRequest,
    AcceptInvitationResponse, AccessResponse, DeviceCertificates, BranchKeysResponse, BranchScopeDto,
    DeviceListResponse, InvitationDto, InviteAcceptance, InviteCollaboratorRequest,
    KeyRotationRequest, KeyRotationResponse, MemberDto, MemberGrant, MemberStatus,
    MembersResponse, PublishBranchKeysRequest, RelayDeviceDto, RemoveMemberRequest,
    RevokeRequest, RevokeResponse, SignedBranchStatement, SignedGrantSet, SignedRevocation,
    SignedRotationStatement, TreeNode, TreeRole,
    UpdateMemberGrantsRequest, WrappedKeysResponse, INVITATION_TTL_MS, MAX_CLOCK_SKEW_MS,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use uuid::Uuid;

use crate::{
    auth::AuthenticatedDevice,
    collab_db::{self, MemberDeviceRevocation},
    db::DeviceRow,
    error::RelayApiError,
    handlers::AppState,
    sqlx::PgPool,
};

// ============================================================================
// Shared checks
// ============================================================================

fn require_workspace(device: &AuthenticatedDevice, secwet_id: Uuid) -> Result<(), RelayApiError> {
    if device.secwet_id != secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this workspace".into(),
        ));
    }
    Ok(())
}

fn verify_signed(
    sign_pub: &[u8; 32],
    message: Result<Vec<u8>, postcard::Error>,
    signature: &[u8; 64],
    what: &str,
) -> Result<(), RelayApiError> {
    let message = message
        .map_err(|e| RelayApiError::Internal(format!("Canonical encoding error: {e}")))?;
    verify_signature_strict_bytes(sign_pub, &message, signature)
        .map_err(|_| RelayApiError::BadSignature(format!("{what} signature is invalid")))
}

/// Constant-time equality for fixed-size secrets and hashes.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

fn within_clock_skew(issued_at_ms: i64) -> bool {
    (Utc::now().timestamp_millis() - issued_at_ms).abs() <= MAX_CLOCK_SKEW_MS
}

fn ms_to_datetime(ms: i64) -> Result<DateTime<Utc>, RelayApiError> {
    Utc.timestamp_millis_opt(ms)
        .single()
        .ok_or_else(|| RelayApiError::InvalidRequest("Timestamp out of range".into()))
}

/// What the calling device may administer.
struct CallerAccess {
    owner: bool,
    grants: Vec<MemberGrant>,
}

impl CallerAccess {
    /// Admin on `space` (`None` = the workspace node itself). Owner devices are
    /// admin everywhere.
    fn is_admin_of(&self, space: Option<Uuid>) -> bool {
        if self.owner {
            return true;
        }
        let role = match space {
            None => effective_role(&self.grants, &[TreeNode::Workspace]),
            Some(s) => effective_role(&self.grants, &[TreeNode::Workspace, TreeNode::Space(s)]),
        };
        role == TreeRole::Admin
    }

    /// Admin covering every space a grant list touches.
    fn is_admin_for_grants(&self, grants: &[MemberGrant]) -> bool {
        grants.iter().all(|g| self.is_admin_of(g.space_id))
    }
}

async fn caller_access(
    pool: &PgPool,
    device: &AuthenticatedDevice,
) -> Result<CallerAccess, RelayApiError> {
    let Some(member_id) = device.member_id else {
        return Ok(CallerAccess {
            owner: true,
            grants: Vec::new(),
        });
    };
    let member = collab_db::get_member(pool, device.secwet_id, member_id)
        .await?
        .ok_or_else(|| RelayApiError::Forbidden("Member record not found".into()))?;
    if member.status()? == MemberStatus::Removed {
        return Err(RelayApiError::Forbidden("Member was removed".into()));
    }
    let grants = collab_db::load_member_grants(pool, device.secwet_id, member_id).await?;
    Ok(CallerAccess {
        owner: false,
        grants,
    })
}

/// Grants of a member device, `None` for an owner device.
pub async fn member_grants_for(
    pool: &PgPool,
    device: &AuthenticatedDevice,
) -> Result<Option<Vec<MemberGrant>>, RelayApiError> {
    match device.member_id {
        None => Ok(None),
        Some(member_id) => {
            let member = collab_db::get_member(pool, device.secwet_id, member_id)
                .await?
                .ok_or_else(|| RelayApiError::Forbidden("Member record not found".into()))?;
            if member.status()? == MemberStatus::Removed {
                return Err(RelayApiError::Forbidden("Member was removed".into()));
            }
            Ok(Some(
                collab_db::load_member_grants(pool, device.secwet_id, member_id).await?,
            ))
        }
    }
}

/// Structural and signature checks of a grant set issued by the caller.
fn check_grant_set(
    signed: &SignedGrantSet,
    caller: &AuthenticatedDevice,
    secwet_id: Uuid,
    member_id: Uuid,
) -> Result<(), RelayApiError> {
    let set = &signed.set;
    validate_grants(&set.grants).map_err(|e| RelayApiError::InvalidRequest(e.to_string()))?;
    if set.secwet_id != secwet_id {
        return Err(RelayApiError::InvalidRequest(
            "Grant set names another workspace".into(),
        ));
    }
    if set.member_id != member_id {
        return Err(RelayApiError::InvalidRequest("Grant set names another member".into()));
    }
    if set.issuer_device_id != caller.device_id {
        return Err(RelayApiError::InvalidRequest(
            "Grant set must be issued by the calling device".into(),
        ));
    }
    verify_signed(&caller.sign_pub, set.signing_bytes(), &signed.signature, "Grant set")
}

/// Checks a revocation directive against the request and the issuing device.
fn check_directive(
    revocation: &SignedRevocation,
    caller: &AuthenticatedDevice,
    secwet_id: Uuid,
    target_device_id: &str,
) -> Result<(), RelayApiError> {
    let d = &revocation.directive;
    if d.secwet_id != secwet_id
        || d.target_device_id != target_device_id
        || d.issuer_device_id != caller.device_id
    {
        return Err(RelayApiError::BadSignature(
            "Revocation directive does not match the request".into(),
        ));
    }
    if !within_clock_skew(d.issued_at) {
        return Err(RelayApiError::BadSignature(
            "Revocation directive is outside the 60 s window".into(),
        ));
    }
    verify_signed(&caller.sign_pub, d.signing_bytes(), &revocation.signature, "Revocation")
}

fn notify_revoked(state: &AppState, device_id: &str) {
    let _ = state.revoke_tx.send(device_id.to_string());
}

fn devices_to_dtos(rows: &[DeviceRow]) -> Result<Vec<RelayDeviceDto>, RelayApiError> {
    rows.iter().map(collab_db::device_to_dto).collect()
}

async fn member_dto(
    pool: &PgPool,
    member: &collab_db::MemberRow,
) -> Result<MemberDto, RelayApiError> {
    let devices = collab_db::list_member_devices(pool, member.secwet_id, member.member_id).await?;
    member.to_dto(devices_to_dtos(&devices)?)
}

// ============================================================================
// Devices and revocation
// ============================================================================

/// GET /v1/secwets/{id}/devices
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    Extension(device): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
) -> Result<Json<DeviceListResponse>, RelayApiError> {
    require_workspace(&device, secwet_id)?;
    let current_epoch = collab_db::get_current_epoch(&state.pool, secwet_id).await?;
    let rows = collab_db::list_devices(&state.pool, secwet_id).await?;
    Ok(Json(DeviceListResponse {
        current_epoch,
        devices: devices_to_dtos(&rows)?,
    }))
}

/// POST /v1/secwets/{id}/devices/{device_id}/revoke
pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path((secwet_id, target_id)): Path<(Uuid, String)>,
    Json(req): Json<RevokeRequest>,
) -> Result<Json<RevokeResponse>, RelayApiError> {
    // 1. Caller is active (middleware) and belongs to the workspace.
    require_workspace(&caller, secwet_id)?;

    // 2. No self-revocation.
    if target_id == caller.device_id {
        return Err(RelayApiError::CannotRevokeSelf);
    }

    // 3. Target exists here and is still active.
    let target = collab_db::get_workspace_device(&state.pool, secwet_id, &target_id)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Device not found in this workspace".into()))?;
    if target.revoked_at.is_some() {
        return Err(RelayApiError::AlreadyRevoked(target_id));
    }

    // 4. Owner devices may revoke any device; a member device only its own member's.
    if let Some(member_id) = caller.member_id {
        if target.member_id != Some(member_id) {
            return Err(RelayApiError::Forbidden(
                "A member device may only revoke devices of the same member".into(),
            ));
        }
    }

    // 5. Directive matches the request and is signed by the caller.
    if req.revocation.directive.wipe != req.wipe {
        return Err(RelayApiError::BadSignature(
            "Revocation directive does not match the request".into(),
        ));
    }
    check_directive(&req.revocation, &caller, secwet_id, &target_id)?;

    let bytes = postcard::to_stdvec(&req.revocation)
        .map_err(|e| RelayApiError::Internal(format!("Directive encode error: {e}")))?;
    let revoked_at = collab_db::revoke_device_with_directive(
        &state.pool,
        secwet_id,
        &target_id,
        req.wipe,
        &bytes,
    )
    .await?
    .ok_or_else(|| RelayApiError::AlreadyRevoked(target_id.clone()))?;

    notify_revoked(&state, &target_id);

    Ok(Json(RevokeResponse {
        device_id: target_id,
        revoked_at: revoked_at.timestamp_millis(),
        wipe_requested: req.wipe,
    }))
}

// ============================================================================
// Master key rotation
// ============================================================================

/// POST /v1/secwets/{id}/keys
pub async fn rotate_keys(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
    Json(req): Json<KeyRotationRequest>,
) -> Result<Json<KeyRotationResponse>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    if !caller.is_owner() {
        return Err(RelayApiError::Forbidden(
            "Only the owner's devices hold the master key".into(),
        ));
    }

    let statement = &req.statement;
    if statement.secwet_id != secwet_id {
        return Err(RelayApiError::InvalidRequest(
            "Rotation statement names another workspace".into(),
        ));
    }
    if statement.issuer_device_id != caller.device_id {
        return Err(RelayApiError::InvalidRequest(
            "Rotation statement must be issued by the calling device".into(),
        ));
    }
    if statement.epoch < 2 {
        return Err(RelayApiError::EpochConflict(
            "Rotation must open an epoch after the first".into(),
        ));
    }
    if statement.key_commitment == [0u8; 32] {
        return Err(RelayApiError::InvalidRequest(
            "Rotation statement must commit to the new key".into(),
        ));
    }
    verify_signed(
        &caller.sign_pub,
        statement.signing_bytes(),
        &req.signature,
        "Rotation statement",
    )?;

    // Recipients: sorted ascending, unique, and exactly the wrapped keys.
    if statement.recipients.is_empty()
        || statement.recipients.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(RelayApiError::InvalidRequest(
            "Recipients must be non-empty, sorted and unique".into(),
        ));
    }
    let mut wrapped_ids: Vec<&str> = req.wrapped.iter().map(|w| w.device_id.as_str()).collect();
    wrapped_ids.sort_unstable();
    if wrapped_ids.len() != statement.recipients.len()
        || wrapped_ids
            .iter()
            .zip(statement.recipients.iter())
            .any(|(a, b)| *a != b.as_str())
    {
        return Err(RelayApiError::InvalidRequest(
            "Wrapped keys must match the recipients exactly".into(),
        ));
    }

    let signed = SignedRotationStatement {
        statement: statement.clone(),
        signature: req.signature,
    };
    collab_db::rotate_master_key(&state.pool, secwet_id, &signed, &req.wrapped).await?;

    Ok(Json(KeyRotationResponse {
        epoch: statement.epoch,
    }))
}

/// GET /v1/secwets/{id}/keys
pub async fn get_keys(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
) -> Result<Json<WrappedKeysResponse>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    let current_epoch = collab_db::get_current_epoch(&state.pool, secwet_id).await?;
    let keys =
        collab_db::get_wrapped_keys_for_device(&state.pool, secwet_id, &caller.device_id).await?;
    let statements = collab_db::get_rotation_statements(&state.pool, secwet_id).await?;
    Ok(Json(WrappedKeysResponse {
        current_epoch,
        keys,
        statements,
    }))
}

// ============================================================================
// Access, members, invitations
// ============================================================================

/// GET /v1/secwets/{id}/access
pub async fn get_access(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
) -> Result<Json<AccessResponse>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    let Some(member_id) = caller.member_id else {
        return Ok(Json(AccessResponse {
            member_id: None,
            grants: None,
        }));
    };
    let member = collab_db::get_member(&state.pool, secwet_id, member_id)
        .await?
        .ok_or_else(|| RelayApiError::Forbidden("Member record not found".into()))?;
    Ok(Json(AccessResponse {
        member_id: Some(member_id),
        grants: Some(member.signed_grants()?),
    }))
}

/// GET /v1/secwets/{id}/members
pub async fn list_members(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
) -> Result<Json<MembersResponse>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    // Owner devices and workspace admins see everyone. A space-level admin
    // sees the members (and invitations) whose grants touch only spaces it
    // administers.
    let access = caller_access(&state.pool, &caller).await?;
    let full = access.is_admin_of(None);
    if !full && !access.grants.iter().any(|g| access.is_admin_of(g.space_id) && g.space_id.is_some()) {
        return Err(RelayApiError::Forbidden(
            "Listing members requires admin on the workspace or a space".into(),
        ));
    }

    let mut visible = std::collections::HashSet::new();
    let mut members = Vec::new();
    for member in collab_db::list_members(&state.pool, secwet_id).await? {
        if !full {
            let grants =
                collab_db::load_member_grants(&state.pool, secwet_id, member.member_id).await?;
            if !access.is_admin_for_grants(&grants) {
                continue;
            }
        }
        visible.insert(member.member_id);
        members.push(member_dto(&state.pool, &member).await?);
    }
    let invitations = collab_db::list_invitations(&state.pool, secwet_id)
        .await?
        .iter()
        .filter(|inv| visible.contains(&inv.member_id))
        .map(|inv| inv.to_dto())
        .collect::<Result<Vec<InvitationDto>, RelayApiError>>()?;

    Ok(Json(MembersResponse {
        members,
        invitations,
    }))
}

/// POST /v1/secwets/{id}/invitations
pub async fn create_invitation(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
    Json(req): Json<InviteCollaboratorRequest>,
) -> Result<Json<InvitationDto>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    crate::db::require_active_pro(&state.pool, secwet_id).await?;
    check_grant_set(&req.grants, &caller, secwet_id, req.member_id)?;

    let now_ms = Utc::now().timestamp_millis();
    if req.expires_at <= now_ms || req.expires_at > now_ms + INVITATION_TTL_MS + MAX_CLOCK_SKEW_MS {
        return Err(RelayApiError::InvalidRequest(
            "Invitation expiry must be in the future and within seven days".into(),
        ));
    }
    let expires_at = ms_to_datetime(req.expires_at)?;

    let access = caller_access(&state.pool, &caller).await?;
    if !access.is_admin_for_grants(&req.grants.set.grants) {
        return Err(RelayApiError::Forbidden(
            "Inviting requires admin on every space the grants touch".into(),
        ));
    }

    let row =
        collab_db::create_invitation(&state.pool, secwet_id, &caller.device_id, expires_at, &req)
            .await?;
    Ok(Json(row.to_dto()?))
}

/// DELETE /v1/secwets/{id}/invitations/{invitation_id}
pub async fn delete_invitation(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path((secwet_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<InvitationDto>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    let inv = collab_db::get_invitation(&state.pool, invitation_id)
        .await?
        .filter(|inv| inv.secwet_id == secwet_id)
        .ok_or_else(|| RelayApiError::NotFound("Invitation not found".into()))?;

    let access = caller_access(&state.pool, &caller).await?;
    if inv.created_by != caller.device_id {
        let grants = collab_db::load_member_grants(&state.pool, secwet_id, inv.member_id).await?;
        if !access.is_admin_for_grants(&grants) {
            return Err(RelayApiError::Forbidden(
                "Withdrawing an invitation requires admin on its spaces".into(),
            ));
        }
    }

    let (row, revoked_device) =
        collab_db::revoke_invitation(&state.pool, secwet_id, invitation_id).await?;
    if let Some(device_id) = revoked_device {
        notify_revoked(&state, &device_id);
    }
    Ok(Json(row.to_dto()?))
}

/// POST /v1/secwets/{id}/invitations/{invitation_id}/activate
pub async fn activate_invitation(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path((secwet_id, invitation_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<InvitationDto>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    let inv = collab_db::get_invitation(&state.pool, invitation_id)
        .await?
        .filter(|inv| inv.secwet_id == secwet_id)
        .ok_or_else(|| RelayApiError::NotFound("Invitation not found".into()))?;
    if !caller.is_owner() && inv.created_by != caller.device_id {
        return Err(RelayApiError::Forbidden(
            "Only the inviter or an owner device may activate an invitation".into(),
        ));
    }
    let row = collab_db::activate_invitation(&state.pool, secwet_id, invitation_id).await?;
    Ok(Json(row.to_dto()?))
}

/// PUT /v1/secwets/{id}/members/{member_id}/grants
pub async fn update_member_grants(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path((secwet_id, member_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateMemberGrantsRequest>,
) -> Result<Json<MemberDto>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    check_grant_set(&req.grants, &caller, secwet_id, member_id)?;

    let member = collab_db::get_member(&state.pool, secwet_id, member_id)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Member not found".into()))?;
    if member.status()? == MemberStatus::Removed {
        return Err(RelayApiError::NotFound("Member was removed".into()));
    }

    // Admin over both what the member had and what it will have.
    let access = caller_access(&state.pool, &caller).await?;
    let old_grants = collab_db::load_member_grants(&state.pool, secwet_id, member_id).await?;
    if !access.is_admin_for_grants(&old_grants)
        || !access.is_admin_for_grants(&req.grants.set.grants)
    {
        return Err(RelayApiError::Forbidden(
            "Changing roles requires admin on every space involved".into(),
        ));
    }

    let updated =
        collab_db::update_member_grants(&state.pool, secwet_id, member_id, &req.grants).await?;
    Ok(Json(member_dto(&state.pool, &updated).await?))
}

/// POST /v1/secwets/{id}/members/{member_id}/remove
pub async fn remove_member(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path((secwet_id, member_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<RemoveMemberRequest>,
) -> Result<Json<MemberDto>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    if caller.member_id == Some(member_id) {
        return Err(RelayApiError::CannotRevokeSelf);
    }

    let member = collab_db::get_member(&state.pool, secwet_id, member_id)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Member not found".into()))?;
    if member.status()? == MemberStatus::Removed {
        return Err(RelayApiError::NotFound("Member was already removed".into()));
    }

    let access = caller_access(&state.pool, &caller).await?;
    let grants = collab_db::load_member_grants(&state.pool, secwet_id, member_id).await?;
    if !access.is_admin_for_grants(&grants) {
        return Err(RelayApiError::Forbidden(
            "Removing a member requires admin on every space it can access".into(),
        ));
    }

    let mut seen = BTreeSet::new();
    let mut revocations = Vec::with_capacity(req.revocations.len());
    for rev in &req.revocations {
        let target = rev.directive.target_device_id.clone();
        if !seen.insert(target.clone()) {
            return Err(RelayApiError::InvalidRequest(
                "Duplicate revocation for the same device".into(),
            ));
        }
        check_directive(rev, &caller, secwet_id, &target)?;
        revocations.push(MemberDeviceRevocation {
            device_id: target,
            wipe: rev.directive.wipe,
            revocation: postcard::to_stdvec(rev)
                .map_err(|e| RelayApiError::Internal(format!("Directive encode error: {e}")))?,
        });
    }

    let updated = collab_db::remove_member(&state.pool, secwet_id, member_id, &revocations).await?;
    for rev in &revocations {
        notify_revoked(&state, &rev.device_id);
    }
    Ok(Json(member_dto(&state.pool, &updated).await?))
}

/// POST /v1/invitations/{invitation_id}/accept (unauthenticated, IP rate-limited)
pub async fn accept_invitation(
    State(state): State<Arc<AppState>>,
    Path(invitation_id): Path<Uuid>,
    req: Request,
) -> Result<Json<AcceptInvitationResponse>, RelayApiError> {
    let ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    if !state.limiter.check_ip(ip) {
        return Err(RelayApiError::RateLimited);
    }

    let body = to_bytes(req.into_body(), 64 * 1024)
        .await
        .map_err(|e| RelayApiError::InvalidRequest(format!("Failed to read body: {e}")))?;
    let req: AcceptInvitationRequest = serde_json::from_slice(&body)
        .map_err(|e| RelayApiError::InvalidRequest(format!("Invalid JSON body: {e}")))?;

    let inv = collab_db::get_invitation(&state.pool, invitation_id)
        .await?
        .ok_or(RelayApiError::InvalidInvitation)?;
    if inv.secwet_id != req.secwet_id {
        return Err(RelayApiError::InvalidInvitation);
    }

    // The secrets are checked (constant time) before anything about the
    // invitation's state is revealed: an unknown id, a wrong token or email,
    // an expired or withdrawn invitation all answer `invalid_invitation`.
    // Only a caller holding the right token learns `already_joined`.
    let auth_hash: [u8; 32] = Sha256::digest(req.auth).into();
    let token_ok = ct_eq(&auth_hash, &inv.token_hash);
    let email_ok = ct_eq(&req.email_hash, &inv.email_hash);
    if !(token_ok & email_ok) {
        return Err(RelayApiError::InvalidInvitation);
    }
    if inv.expires_at <= Utc::now() {
        return Err(RelayApiError::InvalidInvitation);
    }
    match inv.status()? {
        secwet_proto::InvitationStatus::Pending => {}
        secwet_proto::InvitationStatus::Accepted | secwet_proto::InvitationStatus::Active => {
            return Err(RelayApiError::AlreadyJoined)
        }
        _ => return Err(RelayApiError::InvalidInvitation),
    }
    verify_signed(
        &req.sign_pub,
        AcceptInvitationRequest::signing_bytes(
            &invitation_id,
            &req.secwet_id,
            &req.sign_pub,
            &req.enc_pub,
            &req.binding,
        ),
        &req.proof,
        "Acceptance proof",
    )?;

    let device_id = compute_device_id(&req.sign_pub);
    let acceptance = InviteAcceptance {
        device_id: device_id.clone(),
        sign_pub: req.sign_pub,
        enc_pub: req.enc_pub,
        binding: req.binding,
        accepted_at: Utc::now().timestamp_millis(),
    };
    let (row, head_seq) =
        collab_db::accept_invitation(&state.pool, invitation_id, &acceptance).await?;

    Ok(Json(AcceptInvitationResponse {
        secwet_id: row.secwet_id,
        member_id: row.member_id,
        device_id,
        head_seq,
    }))
}

// ============================================================================
// Branch keys
// ============================================================================

/// POST /v1/secwets/{id}/spaces/{space_id}/keys
pub async fn publish_branch_keys(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path((secwet_id, space_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<PublishBranchKeysRequest>,
) -> Result<Json<BranchScopeDto>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    let statement = &req.statement;
    if statement.secwet_id != secwet_id || statement.space_id != space_id {
        return Err(RelayApiError::InvalidRequest(
            "Publish statement does not match the path".into(),
        ));
    }
    if statement.issuer_device_id != caller.device_id {
        return Err(RelayApiError::InvalidRequest(
            "Publish statement must be issued by the calling device".into(),
        ));
    }
    if statement.epoch == 0 {
        return Err(RelayApiError::InvalidRequest("Branch epochs start at 1".into()));
    }
    verify_signed(
        &caller.sign_pub,
        statement.signing_bytes(),
        &req.signature,
        "Publish statement",
    )?;

    // Digests: sorted by device id, unique, exactly the bundles' devices,
    // each equal to SHA-256 of that bundle's digest input.
    let digests = &statement.digests;
    if digests.is_empty() || digests.windows(2).any(|w| w[0].device_id >= w[1].device_id) {
        return Err(RelayApiError::InvalidRequest(
            "Digests must be non-empty, sorted by device id and unique".into(),
        ));
    }
    if req.keys.len() != digests.len() {
        return Err(RelayApiError::InvalidRequest(
            "Bundles must match the signed digests exactly".into(),
        ));
    }
    for key in &req.keys {
        if key.space_id != space_id || key.epoch != statement.epoch {
            return Err(RelayApiError::InvalidRequest(
                "Every bundle must name this space and epoch".into(),
            ));
        }
        let entry = digests
            .iter()
            .find(|d| d.device_id == key.device_id)
            .ok_or_else(|| {
                RelayApiError::InvalidRequest("Bundles must match the signed digests exactly".into())
            })?;
        let input = key
            .digest_input()
            .map_err(|e| RelayApiError::Internal(format!("Digest encoding error: {e}")))?;
        let digest: [u8; 32] = Sha256::digest(&input).into();
        if !ct_eq(&digest, &entry.digest) {
            return Err(RelayApiError::InvalidRequest(format!(
                "Bundle digest mismatch for {}",
                key.device_id
            )));
        }
    }
    // With equal lengths and every key matched, duplicate key device ids
    // would leave a digest unmatched.
    let distinct: BTreeSet<&str> = req.keys.iter().map(|k| k.device_id.as_str()).collect();
    if distinct.len() != req.keys.len() {
        return Err(RelayApiError::InvalidRequest("Duplicate bundle for one device".into()));
    }

    // Caller: owner device or admin of this space.
    let access = caller_access(&state.pool, &caller).await?;
    if !access.is_admin_of(Some(space_id)) {
        return Err(RelayApiError::Forbidden(
            "Publishing branch keys requires admin on the space".into(),
        ));
    }

    // Recipient eligibility is checked inside the publish transaction.
    let signed = SignedBranchStatement {
        statement: statement.clone(),
        signature: req.signature,
    };
    let mut keys = req.keys.clone();
    for key in &mut keys {
        key.statement = None;
    }
    let mut scope = collab_db::publish_branch_keys(&state.pool, secwet_id, &signed, &keys).await?;
    if !caller.is_owner() {
        scope.recipients.clear();
    }
    Ok(Json(scope))
}

/// GET /v1/secwets/{id}/branch-keys
pub async fn get_branch_keys(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
) -> Result<Json<BranchKeysResponse>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    let mut scopes =
        collab_db::list_branch_scopes(&state.pool, secwet_id, caller.is_owner()).await?;
    let mut keys =
        collab_db::get_branch_keys_for_device(&state.pool, secwet_id, &caller.device_id).await?;

    if let Some(grants) = member_grants_for(&state.pool, &caller).await? {
        if let Some(spaces) = granted_spaces(&grants) {
            scopes.retain(|s| spaces.contains(&s.space_id));
            keys.retain(|k| spaces.contains(&k.space_id));
        }
    }

    Ok(Json(BranchKeysResponse { scopes, keys }))
}

// ============================================================================
// Device certificates
// ============================================================================

/// Largest number of certificates accepted in one request.
const MAX_CERTIFICATES_PER_REQUEST: usize = 256;

/// POST /v1/secwets/{id}/certificates
pub async fn post_certificates(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
    Json(req): Json<DeviceCertificates>,
) -> Result<Json<serde_json::Value>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    if req.certificates.len() > MAX_CERTIFICATES_PER_REQUEST {
        return Err(RelayApiError::InvalidRequest("Too many certificates".into()));
    }
    for cert in &req.certificates {
        let c = &cert.certificate;
        if c.secwet_id != secwet_id {
            return Err(RelayApiError::InvalidRequest(
                "Certificate names another workspace".into(),
            ));
        }
        if c.certifier_device_id != caller.device_id {
            return Err(RelayApiError::InvalidRequest(
                "Certificates must be issued by the calling device".into(),
            ));
        }
        if c.device_id != compute_device_id(&c.sign_pub) {
            return Err(RelayApiError::InvalidRequest(
                "Certificate device id does not match its signing key".into(),
            ));
        }
        verify_signed(&caller.sign_pub, c.signing_bytes(), &cert.signature, "Certificate")?;
    }
    collab_db::store_certificates(&state.pool, secwet_id, &req.certificates).await?;
    Ok(Json(serde_json::json!({ "stored": req.certificates.len() })))
}

/// GET /v1/secwets/{id}/certificates
pub async fn get_certificates(
    State(state): State<Arc<AppState>>,
    Extension(caller): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
) -> Result<Json<DeviceCertificates>, RelayApiError> {
    require_workspace(&caller, secwet_id)?;
    Ok(Json(DeviceCertificates {
        certificates: collab_db::list_certificates(&state.pool, secwet_id).await?,
    }))
}
