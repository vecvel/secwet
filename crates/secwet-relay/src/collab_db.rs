//! PostgreSQL queries for device revocation and master key rotation and
//! for collaboration: members, invitations, grants and branch keys.
//!
//! Every value stored here is either an identifier, a hash, a public key, a
//! signed statement or client-side ciphertext. Nothing is plaintext.

use chrono::{DateTime, Utc};
use secwet_proto::{
    granted_spaces, BranchScopeDto, DeviceWrappedKey, InvitationDto, InvitationStatus,
    InviteAcceptance, InviteCollaboratorRequest, MemberDto, MemberGrant, MemberStatus,
    RelayDeviceDto, ScopedBranchKey, SignedBranchStatement, SignedGrantSet,
    SignedDeviceCertificate, SignedRotationStatement, TreeNode, TreeRole, WrappedEpochKey, WrappedKey,
};
use uuid::Uuid;

use crate::{
    db::{workspace_head_seq, DeviceRow, DEVICE_COLUMNS},
    error::RelayApiError,
    sqlx::{query, query_as, query_scalar, Error as SqlxError, FromRow, PgPool, PgRow, Postgres, Row},
};

type PgTx<'a> = sqlx_core::transaction::Transaction<'a, Postgres>;

/// True when `err` is a Postgres unique constraint violation.
pub fn is_unique_violation(err: &SqlxError) -> bool {
    match err {
        SqlxError::Database(db) => db.code().as_deref() == Some("23505"),
        _ => false,
    }
}

fn to_array_32(bytes: &[u8], what: &str) -> Result<[u8; 32], RelayApiError> {
    bytes
        .try_into()
        .map_err(|_| RelayApiError::Internal(format!("Stored {what} has an invalid length")))
}

// ============================================================================
// Devices
// ============================================================================

/// Public view of a registered device.
pub fn device_to_dto(row: &DeviceRow) -> Result<RelayDeviceDto, RelayApiError> {
    Ok(RelayDeviceDto {
        id: row.id.clone(),
        sign_pub: to_array_32(&row.sign_pub, "sign_pub")?,
        enc_pub: to_array_32(&row.enc_pub, "enc_pub")?,
        member_id: row.member_id,
        added_at: row.added_at.timestamp_millis(),
        revoked_at: row.revoked_at.map(|t| t.timestamp_millis()),
        wipe_requested: row.wipe_requested,
        revoked_seq: row.revoked_seq.map(|s| s.max(0) as u64),
    })
}

/// Every device of a workspace (owner and member devices, revoked included).
pub async fn list_devices(pool: &PgPool, secwet_id: Uuid) -> Result<Vec<DeviceRow>, SqlxError> {
    query_as::<_, DeviceRow>(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE secwet_id = $1 ORDER BY added_at ASC, id ASC"
    ))
    .bind(secwet_id)
    .fetch_all(pool)
    .await
}

/// Devices registered for one member (revoked included).
pub async fn list_member_devices(
    pool: &PgPool,
    secwet_id: Uuid,
    member_id: Uuid,
) -> Result<Vec<DeviceRow>, SqlxError> {
    query_as::<_, DeviceRow>(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE secwet_id = $1 AND member_id = $2 \
         ORDER BY added_at ASC, id ASC"
    ))
    .bind(secwet_id)
    .bind(member_id)
    .fetch_all(pool)
    .await
}

/// Device of a given workspace.
pub async fn get_workspace_device(
    pool: &PgPool,
    secwet_id: Uuid,
    device_id: &str,
) -> Result<Option<DeviceRow>, SqlxError> {
    query_as::<_, DeviceRow>(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE secwet_id = $1 AND id = $2"
    ))
    .bind(secwet_id)
    .bind(device_id)
    .fetch_optional(pool)
    .await
}

/// Current master key epoch of a workspace.
pub async fn get_current_epoch(pool: &PgPool, secwet_id: Uuid) -> Result<u32, RelayApiError> {
    let epoch = query_scalar::<_, i32>("SELECT current_epoch FROM secwets WHERE id = $1")
        .bind(secwet_id)
        .fetch_optional(pool)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Workspace not found".into()))?;
    Ok(epoch.max(0) as u32)
}

/// Marks a device revoked with its signed directive. Returns the revocation
/// time, or `None` when the device was already revoked (race or replay).
pub async fn revoke_device_with_directive(
    pool: &PgPool,
    secwet_id: Uuid,
    device_id: &str,
    wipe: bool,
    revocation: &[u8],
) -> Result<Option<DateTime<Utc>>, RelayApiError> {
    let mut tx = pool.begin().await?;
    lock_workspace(&mut tx, secwet_id).await?;
    let revoked_at = revoke_in_tx(&mut tx, secwet_id, device_id, wipe, Some(revocation)).await?;
    if revoked_at.is_some() {
        query("DELETE FROM branch_keys WHERE secwet_id = $1 AND device_id = $2")
            .bind(secwet_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(revoked_at)
}

/// Exclusive lock on the workspace row. Rotation, revocation, member removal
/// and pairing approval take it so they serialize with each other and with
/// event pushes (which take it shared). Lock order: secwets, then devices.
async fn lock_workspace(tx: &mut PgTx<'_>, secwet_id: Uuid) -> Result<i32, RelayApiError> {
    query_scalar::<_, i32>("SELECT current_epoch FROM secwets WHERE id = $1 FOR UPDATE")
        .bind(secwet_id)
        .fetch_optional(&mut **tx)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Workspace not found".into()))
}

/// Revokes one device inside a transaction holding the workspace lock and
/// records `revoked_seq` (the workspace head at revocation time).
async fn revoke_in_tx(
    tx: &mut PgTx<'_>,
    secwet_id: Uuid,
    device_id: &str,
    wipe: bool,
    revocation: Option<&[u8]>,
) -> Result<Option<DateTime<Utc>>, SqlxError> {
    let head = workspace_head_seq(&mut **tx, secwet_id).await?;
    query_scalar::<_, DateTime<Utc>>(
        r#"
        UPDATE devices
        SET revoked_at = now(), wipe_requested = $3, revocation = $4, revoked_seq = $5
        WHERE secwet_id = $1 AND id = $2 AND revoked_at IS NULL
        RETURNING revoked_at
        "#,
    )
    .bind(secwet_id)
    .bind(device_id)
    .bind(wipe)
    .bind(revocation)
    .bind(head)
    .fetch_optional(&mut **tx)
    .await
}

// ============================================================================
// Master key rotation
// ============================================================================

/// Opens master key epoch `epoch` atomically.
///
/// `recipients` must be sorted, unique and equal to the set of active owner
/// devices; `wrapped` must contain exactly one key per recipient (checked by
/// the caller). Fails with `epoch_conflict` when `epoch != current + 1`,
/// including when a concurrent rotation won the race.
pub async fn rotate_master_key(
    pool: &PgPool,
    secwet_id: Uuid,
    signed: &SignedRotationStatement,
    wrapped: &[DeviceWrappedKey],
) -> Result<(), RelayApiError> {
    let epoch = signed.statement.epoch;
    let recipients = signed.statement.recipients.as_slice();
    let statement_bytes = postcard::to_stdvec(signed)
        .map_err(|e| RelayApiError::Internal(format!("Statement encode error: {e}")))?;
    let mut tx = pool.begin().await?;

    let current = lock_workspace(&mut tx, secwet_id).await?;

    if i64::from(epoch) != i64::from(current) + 1 {
        return Err(RelayApiError::EpochConflict(format!(
            "Rotation must open epoch {}, got {}",
            i64::from(current) + 1,
            epoch
        )));
    }

    let mut active_owners = query_scalar::<_, String>(
        r#"
        SELECT id FROM devices
        WHERE secwet_id = $1 AND revoked_at IS NULL AND member_id IS NULL
        "#,
    )
    .bind(secwet_id)
    .fetch_all(&mut *tx)
    .await?;
    active_owners.sort();

    if active_owners.as_slice() != recipients {
        return Err(RelayApiError::InvalidRequest(
            "Rotation recipients must be exactly the active owner devices".into(),
        ));
    }

    let updated = query("UPDATE secwets SET current_epoch = $2 WHERE id = $1 AND current_epoch = $3")
        .bind(secwet_id)
        .bind(epoch as i32)
        .bind(epoch as i32 - 1)
        .execute(&mut *tx)
        .await?;
    if updated.rows_affected() == 0 {
        return Err(RelayApiError::EpochConflict(
            "Another rotation opened this epoch first".into(),
        ));
    }

    query("INSERT INTO rotation_statements (secwet_id, epoch, statement) VALUES ($1, $2, $3)")
        .bind(secwet_id)
        .bind(epoch as i32)
        .bind(&statement_bytes)
        .execute(&mut *tx)
        .await?;

    for key in wrapped {
        query(
            r#"
            INSERT INTO wrapped_keys (secwet_id, device_id, epoch, enc, ciphertext)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (secwet_id, device_id, epoch) DO UPDATE SET
                enc = EXCLUDED.enc,
                ciphertext = EXCLUDED.ciphertext
            "#,
        )
        .bind(secwet_id)
        .bind(&key.device_id)
        .bind(epoch as i32)
        .bind(&key.wrapped.enc[..])
        .bind(&key.wrapped.ciphertext)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

/// Signed rotation statements of every epoch opened by a rotation, ascending.
pub async fn get_rotation_statements(
    pool: &PgPool,
    secwet_id: Uuid,
) -> Result<Vec<SignedRotationStatement>, RelayApiError> {
    let rows = query_scalar::<_, Vec<u8>>(
        "SELECT statement FROM rotation_statements WHERE secwet_id = $1 AND epoch >= 2 ORDER BY epoch",
    )
    .bind(secwet_id)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|b| {
            postcard::from_bytes(b)
                .map_err(|_| RelayApiError::Internal("Stored rotation statement is corrupt".into()))
        })
        .collect()
}

/// Wrapped master keys addressed to one device, every epoch, ascending.
pub async fn get_wrapped_keys_for_device(
    pool: &PgPool,
    secwet_id: Uuid,
    device_id: &str,
) -> Result<Vec<WrappedEpochKey>, RelayApiError> {
    let rows = query(
        r#"
        SELECT epoch, enc, ciphertext FROM wrapped_keys
        WHERE secwet_id = $1 AND device_id = $2
        ORDER BY epoch ASC
        "#,
    )
    .bind(secwet_id)
    .bind(device_id)
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let epoch: i32 = row.try_get("epoch")?;
            let enc: Vec<u8> = row.try_get("enc")?;
            let ciphertext: Vec<u8> = row.try_get("ciphertext")?;
            Ok(WrappedEpochKey {
                epoch: epoch.max(0) as u32,
                wrapped: WrappedKey {
                    enc: to_array_32(&enc, "wrapped key enc")?,
                    ciphertext,
                },
            })
        })
        .collect()
}

// ============================================================================
// Members and grants
// ============================================================================

#[derive(Debug, Clone)]
pub struct MemberRow {
    pub secwet_id: Uuid,
    pub member_id: Uuid,
    pub email_hash: Vec<u8>,
    pub status: String,
    pub grants: Vec<u8>,
    pub grants_version: i64,
    pub created_at: DateTime<Utc>,
    pub removed_at: Option<DateTime<Utc>>,
}

impl<'r> FromRow<'r, PgRow> for MemberRow {
    fn from_row(row: &'r PgRow) -> Result<Self, SqlxError> {
        Ok(Self {
            secwet_id: row.try_get("secwet_id")?,
            member_id: row.try_get("member_id")?,
            email_hash: row.try_get("email_hash")?,
            status: row.try_get("status")?,
            grants: row.try_get("grants")?,
            grants_version: row.try_get("grants_version")?,
            created_at: row.try_get("created_at")?,
            removed_at: row.try_get("removed_at")?,
        })
    }
}

/// Grant sets are stored as the postcard `SignedGrantSet`. The signature
/// covers `MemberGrantSet::signing_bytes`, so clients re-verify what they read.
fn encode_grant_set(signed: &SignedGrantSet) -> Result<Vec<u8>, RelayApiError> {
    postcard::to_stdvec(signed)
        .map_err(|e| RelayApiError::Internal(format!("Grant set encode error: {e}")))
}

fn decode_grant_set(bytes: &[u8]) -> Result<SignedGrantSet, RelayApiError> {
    postcard::from_bytes(bytes)
        .map_err(|_| RelayApiError::Internal("Stored grant set is corrupt".into()))
}

const MEMBER_COLUMNS: &str =
    "secwet_id, member_id, email_hash, status, grants, grants_version, created_at, removed_at";

impl MemberRow {
    pub fn status(&self) -> Result<MemberStatus, RelayApiError> {
        MemberStatus::parse(&self.status)
            .ok_or_else(|| RelayApiError::Internal("Stored member status is invalid".into()))
    }

    pub fn signed_grants(&self) -> Result<SignedGrantSet, RelayApiError> {
        decode_grant_set(&self.grants)
    }

    pub fn to_dto(&self, devices: Vec<RelayDeviceDto>) -> Result<MemberDto, RelayApiError> {
        Ok(MemberDto {
            member_id: self.member_id,
            email_hash: to_array_32(&self.email_hash, "email_hash")?,
            status: self.status()?,
            grants: self.signed_grants()?,
            devices,
            created_at: self.created_at.timestamp_millis(),
            removed_at: self.removed_at.map(|t| t.timestamp_millis()),
        })
    }
}

pub async fn get_member(
    pool: &PgPool,
    secwet_id: Uuid,
    member_id: Uuid,
) -> Result<Option<MemberRow>, SqlxError> {
    query_as::<_, MemberRow>(&format!(
        "SELECT {MEMBER_COLUMNS} FROM workspace_members WHERE secwet_id = $1 AND member_id = $2"
    ))
    .bind(secwet_id)
    .bind(member_id)
    .fetch_optional(pool)
    .await
}

pub async fn list_members(pool: &PgPool, secwet_id: Uuid) -> Result<Vec<MemberRow>, SqlxError> {
    query_as::<_, MemberRow>(&format!(
        "SELECT {MEMBER_COLUMNS} FROM workspace_members WHERE secwet_id = $1 \
         ORDER BY created_at ASC, member_id ASC"
    ))
    .bind(secwet_id)
    .fetch_all(pool)
    .await
}

/// Enforcement grants of a member, read from the clear `member_grants` rows.
pub async fn load_member_grants(
    pool: &PgPool,
    secwet_id: Uuid,
    member_id: Uuid,
) -> Result<Vec<MemberGrant>, RelayApiError> {
    let rows = query(
        r#"
        SELECT node_kind, node_id, space_id, role FROM member_grants
        WHERE secwet_id = $1 AND member_id = $2
        "#,
    )
    .bind(secwet_id)
    .bind(member_id)
    .fetch_all(pool)
    .await?;

    rows.iter().map(grant_from_row).collect()
}

fn grant_from_row(row: &PgRow) -> Result<MemberGrant, RelayApiError> {
    let kind: String = row.try_get("node_kind")?;
    let node_id: Option<Uuid> = row.try_get("node_id")?;
    let space_id: Option<Uuid> = row.try_get("space_id")?;
    let role: String = row.try_get("role")?;
    let node = TreeNode::from_parts(&kind, node_id)
        .ok_or_else(|| RelayApiError::Internal("Stored grant node is invalid".into()))?;
    let role = TreeRole::parse(&role)
        .ok_or_else(|| RelayApiError::Internal("Stored grant role is invalid".into()))?;
    Ok(MemberGrant { node, space_id, role })
}

/// Rebuilds the clear enforcement rows from a (verified) signed grant set.
async fn replace_member_grants(
    tx: &mut PgTx<'_>,
    secwet_id: Uuid,
    member_id: Uuid,
    grants: &[MemberGrant],
) -> Result<(), SqlxError> {
    query("DELETE FROM member_grants WHERE secwet_id = $1 AND member_id = $2")
        .bind(secwet_id)
        .bind(member_id)
        .execute(&mut **tx)
        .await?;
    for grant in grants {
        query(
            r#"
            INSERT INTO member_grants (secwet_id, member_id, node_kind, node_id, space_id, role)
            VALUES ($1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(secwet_id)
        .bind(member_id)
        .bind(grant.node.kind_str())
        .bind(grant.node.id())
        .bind(grant.space_id)
        .bind(grant.role.as_str())
        .execute(&mut **tx)
        .await?;
    }
    Ok(())
}

/// Replaces a member's signed grant set. The version must strictly increase
/// (`epoch_conflict` otherwise) so a stale set cannot be replayed.
pub async fn update_member_grants(
    pool: &PgPool,
    secwet_id: Uuid,
    member_id: Uuid,
    signed: &SignedGrantSet,
) -> Result<MemberRow, RelayApiError> {
    let bytes = encode_grant_set(signed)?;
    let version = i64::try_from(signed.set.version)
        .map_err(|_| RelayApiError::InvalidRequest("Grant set version out of range".into()))?;

    let mut tx = pool.begin().await?;
    let member = query_as::<_, MemberRow>(&format!(
        "SELECT {MEMBER_COLUMNS} FROM workspace_members \
         WHERE secwet_id = $1 AND member_id = $2 FOR UPDATE"
    ))
    .bind(secwet_id)
    .bind(member_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| RelayApiError::NotFound("Member not found".into()))?;

    if member.status()? == MemberStatus::Removed {
        return Err(RelayApiError::NotFound("Member was removed".into()));
    }
    if version <= member.grants_version {
        return Err(RelayApiError::EpochConflict(format!(
            "Grant set version {} is not newer than stored version {}",
            version, member.grants_version
        )));
    }

    let updated = query_as::<_, MemberRow>(&format!(
        "UPDATE workspace_members SET grants = $3, grants_version = $4 \
         WHERE secwet_id = $1 AND member_id = $2 RETURNING {MEMBER_COLUMNS}"
    ))
    .bind(secwet_id)
    .bind(member_id)
    .bind(&bytes)
    .bind(version)
    .fetch_one(&mut *tx)
    .await?;

    replace_member_grants(&mut tx, secwet_id, member_id, &signed.set.grants).await?;
    tx.commit().await?;
    Ok(updated)
}

/// One verified revocation of a member device.
pub struct MemberDeviceRevocation {
    pub device_id: String,
    pub wipe: bool,
    pub revocation: Vec<u8>,
}

/// Removes a member: revokes every listed device (which must be exactly the
/// member's active devices), marks the member removed, withdraws its open
/// invitations and deletes its branch key rows. Returns the updated row.
pub async fn remove_member(
    pool: &PgPool,
    secwet_id: Uuid,
    member_id: Uuid,
    revocations: &[MemberDeviceRevocation],
) -> Result<MemberRow, RelayApiError> {
    let mut tx = pool.begin().await?;
    lock_workspace(&mut tx, secwet_id).await?;

    let member = query_as::<_, MemberRow>(&format!(
        "SELECT {MEMBER_COLUMNS} FROM workspace_members \
         WHERE secwet_id = $1 AND member_id = $2 FOR UPDATE"
    ))
    .bind(secwet_id)
    .bind(member_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| RelayApiError::NotFound("Member not found".into()))?;
    if member.status()? == MemberStatus::Removed {
        return Err(RelayApiError::NotFound("Member was already removed".into()));
    }

    let mut active = query_scalar::<_, String>(
        r#"
        SELECT id FROM devices
        WHERE secwet_id = $1 AND member_id = $2 AND revoked_at IS NULL
        FOR UPDATE
        "#,
    )
    .bind(secwet_id)
    .bind(member_id)
    .fetch_all(&mut *tx)
    .await?;
    active.sort();
    let mut targets: Vec<String> = revocations.iter().map(|r| r.device_id.clone()).collect();
    targets.sort();
    if active != targets {
        return Err(RelayApiError::InvalidRequest(
            "Removal must carry exactly one revocation per active device of the member".into(),
        ));
    }

    for rev in revocations {
        let revoked =
            revoke_in_tx(&mut tx, secwet_id, &rev.device_id, rev.wipe, Some(&rev.revocation)).await?;
        if revoked.is_none() {
            return Err(RelayApiError::AlreadyRevoked(rev.device_id.clone()));
        }
    }

    let updated = query_as::<_, MemberRow>(&format!(
        "UPDATE workspace_members SET status = 'removed', removed_at = now() \
         WHERE secwet_id = $1 AND member_id = $2 RETURNING {MEMBER_COLUMNS}"
    ))
    .bind(secwet_id)
    .bind(member_id)
    .fetch_one(&mut *tx)
    .await?;

    query(
        r#"
        DELETE FROM branch_keys
        WHERE secwet_id = $1
          AND device_id IN (SELECT id FROM devices WHERE secwet_id = $1 AND member_id = $2)
        "#,
    )
    .bind(secwet_id)
    .bind(member_id)
    .execute(&mut *tx)
    .await?;

    query(
        r#"
        UPDATE invitations SET status = 'revoked'
        WHERE secwet_id = $1 AND member_id = $2 AND status IN ('pending', 'accepted')
        "#,
    )
    .bind(secwet_id)
    .bind(member_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(updated)
}

// ============================================================================
// Invitations
// ============================================================================

#[derive(Debug, Clone)]
pub struct InvitationRow {
    pub id: Uuid,
    pub secwet_id: Uuid,
    pub member_id: Uuid,
    pub email_hash: Vec<u8>,
    pub token_hash: Vec<u8>,
    pub created_by: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub status: String,
    pub acceptance: Option<Vec<u8>>,
    pub accepted_device_id: Option<String>,
}

impl<'r> FromRow<'r, PgRow> for InvitationRow {
    fn from_row(row: &'r PgRow) -> Result<Self, SqlxError> {
        Ok(Self {
            id: row.try_get("id")?,
            secwet_id: row.try_get("secwet_id")?,
            member_id: row.try_get("member_id")?,
            email_hash: row.try_get("email_hash")?,
            token_hash: row.try_get("token_hash")?,
            created_by: row.try_get("created_by")?,
            created_at: row.try_get("created_at")?,
            expires_at: row.try_get("expires_at")?,
            status: row.try_get("status")?,
            acceptance: row.try_get("acceptance")?,
            accepted_device_id: row.try_get("accepted_device_id")?,
        })
    }
}

const INVITATION_COLUMNS: &str = "id, secwet_id, member_id, email_hash, token_hash, created_by, \
     created_at, expires_at, status, acceptance, accepted_device_id";

impl InvitationRow {
    pub fn status(&self) -> Result<InvitationStatus, RelayApiError> {
        InvitationStatus::parse(&self.status)
            .ok_or_else(|| RelayApiError::Internal("Stored invitation status is invalid".into()))
    }

    /// Status as reported to clients: a pending invitation past its expiry is `expired`.
    pub fn effective_status(&self, now: DateTime<Utc>) -> Result<InvitationStatus, RelayApiError> {
        let status = self.status()?;
        if status == InvitationStatus::Pending && self.expires_at <= now {
            return Ok(InvitationStatus::Expired);
        }
        Ok(status)
    }

    pub fn to_dto(&self) -> Result<InvitationDto, RelayApiError> {
        let acceptance = match &self.acceptance {
            Some(bytes) => Some(
                postcard::from_bytes::<InviteAcceptance>(bytes)
                    .map_err(|_| RelayApiError::Internal("Stored acceptance is corrupt".into()))?,
            ),
            None => None,
        };
        Ok(InvitationDto {
            invitation_id: self.id,
            member_id: self.member_id,
            email_hash: to_array_32(&self.email_hash, "email_hash")?,
            status: self.effective_status(Utc::now())?,
            created_by: self.created_by.clone(),
            created_at: self.created_at.timestamp_millis(),
            expires_at: self.expires_at.timestamp_millis(),
            acceptance,
        })
    }
}

pub async fn get_invitation(
    pool: &PgPool,
    invitation_id: Uuid,
) -> Result<Option<InvitationRow>, SqlxError> {
    query_as::<_, InvitationRow>(&format!(
        "SELECT {INVITATION_COLUMNS} FROM invitations WHERE id = $1"
    ))
    .bind(invitation_id)
    .fetch_optional(pool)
    .await
}

pub async fn list_invitations(
    pool: &PgPool,
    secwet_id: Uuid,
) -> Result<Vec<InvitationRow>, SqlxError> {
    query_as::<_, InvitationRow>(&format!(
        "SELECT {INVITATION_COLUMNS} FROM invitations WHERE secwet_id = $1 \
         ORDER BY created_at ASC, id ASC"
    ))
    .bind(secwet_id)
    .fetch_all(pool)
    .await
}

/// Creates an invitation, its (invited) member and the member's enforcement
/// grants in one transaction. Fails with `exists` when the invitation id or
/// member id is taken, or a pending invitation for the same email hash exists.
pub async fn create_invitation(
    pool: &PgPool,
    secwet_id: Uuid,
    created_by: &str,
    expires_at: DateTime<Utc>,
    req: &InviteCollaboratorRequest,
) -> Result<InvitationRow, RelayApiError> {
    let grants_bytes = encode_grant_set(&req.grants)?;
    let version = i64::try_from(req.grants.set.version)
        .map_err(|_| RelayApiError::InvalidRequest("Grant set version out of range".into()))?;

    let mut tx = pool.begin().await?;

    // Pending invitations past their expiry no longer block a new invitation.
    query(
        r#"
        UPDATE invitations SET status = 'expired'
        WHERE secwet_id = $1 AND status = 'pending' AND expires_at <= now()
        "#,
    )
    .bind(secwet_id)
    .execute(&mut *tx)
    .await?;

    let taken = query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(SELECT 1 FROM invitations WHERE id = $1)
            OR EXISTS(SELECT 1 FROM workspace_members WHERE secwet_id = $2 AND member_id = $3)
            OR EXISTS(SELECT 1 FROM invitations
                      WHERE secwet_id = $2 AND email_hash = $4 AND status = 'pending')
        "#,
    )
    .bind(req.invitation_id)
    .bind(secwet_id)
    .bind(req.member_id)
    .bind(&req.email_hash[..])
    .fetch_one(&mut *tx)
    .await?;
    if taken {
        return Err(RelayApiError::Exists(
            "An invitation for this member or email is already pending".into(),
        ));
    }

    let map_unique = |e: SqlxError| {
        if is_unique_violation(&e) {
            RelayApiError::Exists("An invitation for this member or email is already pending".into())
        } else {
            RelayApiError::Database(e)
        }
    };

    query(
        r#"
        INSERT INTO workspace_members (secwet_id, member_id, email_hash, status, grants, grants_version)
        VALUES ($1, $2, $3, 'invited', $4, $5)
        "#,
    )
    .bind(secwet_id)
    .bind(req.member_id)
    .bind(&req.email_hash[..])
    .bind(&grants_bytes)
    .bind(version)
    .execute(&mut *tx)
    .await
    .map_err(map_unique)?;

    replace_member_grants(&mut tx, secwet_id, req.member_id, &req.grants.set.grants).await?;

    let row = query_as::<_, InvitationRow>(&format!(
        r#"
        INSERT INTO invitations (id, secwet_id, member_id, email_hash, token_hash, created_by, expires_at, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending')
        RETURNING {INVITATION_COLUMNS}
        "#
    ))
    .bind(req.invitation_id)
    .bind(secwet_id)
    .bind(req.member_id)
    .bind(&req.email_hash[..])
    .bind(&req.token_hash[..])
    .bind(created_by)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await
    .map_err(map_unique)?;

    tx.commit().await?;
    Ok(row)
}

/// Withdraws a pending or accepted invitation. The member is marked removed
/// and a device registered through the invitation (it never received keys) is
/// revoked. Returns the updated row and the revoked device id, if any.
pub async fn revoke_invitation(
    pool: &PgPool,
    secwet_id: Uuid,
    invitation_id: Uuid,
) -> Result<(InvitationRow, Option<String>), RelayApiError> {
    let mut tx = pool.begin().await?;
    lock_workspace(&mut tx, secwet_id).await?;
    let inv = query_as::<_, InvitationRow>(&format!(
        "SELECT {INVITATION_COLUMNS} FROM invitations WHERE id = $1 AND secwet_id = $2 FOR UPDATE"
    ))
    .bind(invitation_id)
    .bind(secwet_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| RelayApiError::NotFound("Invitation not found".into()))?;

    match inv.status()? {
        InvitationStatus::Pending | InvitationStatus::Accepted => {}
        InvitationStatus::Active => {
            return Err(RelayApiError::InvalidRequest(
                "Invitation is active; remove the member instead".into(),
            ))
        }
        InvitationStatus::Revoked | InvitationStatus::Expired => {
            return Err(RelayApiError::NotFound("Invitation is no longer open".into()))
        }
    }

    let updated = query_as::<_, InvitationRow>(&format!(
        "UPDATE invitations SET status = 'revoked' WHERE id = $1 RETURNING {INVITATION_COLUMNS}"
    ))
    .bind(invitation_id)
    .fetch_one(&mut *tx)
    .await?;

    query(
        r#"
        UPDATE workspace_members SET status = 'removed', removed_at = now()
        WHERE secwet_id = $1 AND member_id = $2 AND status <> 'removed'
        "#,
    )
    .bind(secwet_id)
    .bind(inv.member_id)
    .execute(&mut *tx)
    .await?;

    let mut revoked_device = None;
    if let Some(device_id) = &inv.accepted_device_id {
        // The device registered through this invitation; it never received
        // keys, so it is revoked without a directive.
        let revoked = revoke_in_tx(&mut tx, secwet_id, device_id, false, None).await?;
        if revoked.is_some() {
            revoked_device = Some(device_id.clone());
        }
        query("DELETE FROM branch_keys WHERE secwet_id = $1 AND device_id = $2")
            .bind(secwet_id)
            .bind(device_id)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok((updated, revoked_device))
}

/// Marks an accepted invitation and its member active (keys delivered).
/// Idempotent for an already active invitation.
pub async fn activate_invitation(
    pool: &PgPool,
    secwet_id: Uuid,
    invitation_id: Uuid,
) -> Result<InvitationRow, RelayApiError> {
    let mut tx = pool.begin().await?;
    let inv = query_as::<_, InvitationRow>(&format!(
        "SELECT {INVITATION_COLUMNS} FROM invitations WHERE id = $1 AND secwet_id = $2 FOR UPDATE"
    ))
    .bind(invitation_id)
    .bind(secwet_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| RelayApiError::NotFound("Invitation not found".into()))?;

    match inv.status()? {
        InvitationStatus::Accepted => {}
        InvitationStatus::Active => {
            tx.commit().await?;
            return Ok(inv);
        }
        InvitationStatus::Pending => {
            return Err(RelayApiError::InvalidRequest(
                "Invitation has not been accepted yet".into(),
            ))
        }
        InvitationStatus::Revoked | InvitationStatus::Expired => {
            return Err(RelayApiError::NotFound("Invitation is no longer open".into()))
        }
    }

    let updated = query_as::<_, InvitationRow>(&format!(
        "UPDATE invitations SET status = 'active' WHERE id = $1 RETURNING {INVITATION_COLUMNS}"
    ))
    .bind(invitation_id)
    .fetch_one(&mut *tx)
    .await?;

    let member = query(
        r#"
        UPDATE workspace_members SET status = 'active'
        WHERE secwet_id = $1 AND member_id = $2 AND status = 'invited'
        "#,
    )
    .bind(secwet_id)
    .bind(inv.member_id)
    .execute(&mut *tx)
    .await?;
    if member.rows_affected() == 0 {
        let status = query_scalar::<_, String>(
            "SELECT status FROM workspace_members WHERE secwet_id = $1 AND member_id = $2",
        )
        .bind(secwet_id)
        .bind(inv.member_id)
        .fetch_optional(&mut *tx)
        .await?;
        if status.as_deref() != Some("active") {
            return Err(RelayApiError::NotFound("Member was removed".into()));
        }
    }

    tx.commit().await?;
    Ok(updated)
}

/// Registers the invitee's device and marks the invitation accepted. All
/// authorization checks happen in the handler; this re-checks the state
/// under a row lock so concurrent accepts cannot both succeed.
pub async fn accept_invitation(
    pool: &PgPool,
    invitation_id: Uuid,
    acceptance: &InviteAcceptance,
) -> Result<(InvitationRow, u64), RelayApiError> {
    let acceptance_bytes = postcard::to_stdvec(acceptance)
        .map_err(|e| RelayApiError::Internal(format!("Acceptance encode error: {e}")))?;

    let mut tx = pool.begin().await?;
    let inv = query_as::<_, InvitationRow>(&format!(
        "SELECT {INVITATION_COLUMNS} FROM invitations WHERE id = $1 FOR UPDATE"
    ))
    .bind(invitation_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(RelayApiError::InvalidInvitation)?;

    if inv.expires_at <= Utc::now() {
        return Err(RelayApiError::InvalidInvitation);
    }
    match inv.status()? {
        InvitationStatus::Pending => {}
        InvitationStatus::Accepted | InvitationStatus::Active => {
            return Err(RelayApiError::AlreadyJoined)
        }
        InvitationStatus::Revoked | InvitationStatus::Expired => {
            return Err(RelayApiError::InvalidInvitation)
        }
    }

    let member_status = query_scalar::<_, String>(
        "SELECT status FROM workspace_members WHERE secwet_id = $1 AND member_id = $2 FOR UPDATE",
    )
    .bind(inv.secwet_id)
    .bind(inv.member_id)
    .fetch_optional(&mut *tx)
    .await?;
    if member_status.as_deref() != Some("invited") {
        return Err(RelayApiError::InvalidInvitation);
    }

    let inserted = query(
        r#"
        INSERT INTO devices (id, secwet_id, sign_pub, enc_pub, added_at, member_id)
        VALUES ($1, $2, $3, $4, now(), $5)
        ON CONFLICT (id) DO NOTHING
        "#,
    )
    .bind(&acceptance.device_id)
    .bind(inv.secwet_id)
    .bind(&acceptance.sign_pub[..])
    .bind(&acceptance.enc_pub[..])
    .bind(inv.member_id)
    .execute(&mut *tx)
    .await?;
    if inserted.rows_affected() == 0 {
        return Err(RelayApiError::Exists("Device is already registered".into()));
    }

    let updated = query_as::<_, InvitationRow>(&format!(
        "UPDATE invitations SET status = 'accepted', acceptance = $2, accepted_device_id = $3 \
         WHERE id = $1 RETURNING {INVITATION_COLUMNS}"
    ))
    .bind(invitation_id)
    .bind(&acceptance_bytes)
    .bind(&acceptance.device_id)
    .fetch_one(&mut *tx)
    .await?;

    let head = workspace_head_seq(&mut *tx, inv.secwet_id).await?;
    tx.commit().await?;
    Ok((updated, head.max(0) as u64))
}

// ============================================================================
// Branch keys
// ============================================================================

/// Checks, inside the publish transaction, that a recipient is an active
/// device of this workspace that is an owner device or belongs to a
/// non-removed member whose grants touch `space_id`.
async fn check_branch_recipient(
    tx: &mut PgTx<'_>,
    secwet_id: Uuid,
    space_id: Uuid,
    device_id: &str,
) -> Result<(), RelayApiError> {
    let device = query_as::<_, DeviceRow>(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE secwet_id = $1 AND id = $2"
    ))
    .bind(secwet_id)
    .bind(device_id)
    .fetch_optional(&mut **tx)
    .await?
    .ok_or_else(|| RelayApiError::InvalidRequest(format!("Unknown recipient {device_id}")))?;
    if device.revoked_at.is_some() {
        return Err(RelayApiError::InvalidRequest(format!("Recipient {device_id} is revoked")));
    }
    let Some(member_id) = device.member_id else {
        return Ok(());
    };
    let status = query_scalar::<_, String>(
        "SELECT status FROM workspace_members WHERE secwet_id = $1 AND member_id = $2 FOR SHARE",
    )
    .bind(secwet_id)
    .bind(member_id)
    .fetch_optional(&mut **tx)
    .await?;
    match status.as_deref() {
        Some("invited") | Some("active") => {}
        _ => {
            return Err(RelayApiError::InvalidRequest(format!(
                "Recipient {device_id} belongs to a removed member"
            )))
        }
    }
    let rows = query("SELECT node_kind, node_id, space_id, role FROM member_grants WHERE secwet_id = $1 AND member_id = $2")
        .bind(secwet_id)
        .bind(member_id)
        .fetch_all(&mut **tx)
        .await?;
    let grants = rows
        .into_iter()
        .map(|row| grant_from_row(&row))
        .collect::<Result<Vec<MemberGrant>, RelayApiError>>()?;
    let touches = match granted_spaces(&grants) {
        None => true,
        Some(spaces) => spaces.contains(&space_id),
    };
    if !touches {
        return Err(RelayApiError::InvalidRequest(format!(
            "Recipient {device_id} has no grant in this space"
        )));
    }
    Ok(())
}

/// Stores a branch key publish for one space.
///
/// `rotate = true` opens `epoch`, which must be `current + 1` (or `1` when the
/// space has no scope yet); `rotate = false` adds or replaces bundles at the
/// current epoch. Both fail with `epoch_conflict` otherwise. Recipients are
/// validated inside the transaction, under the shared workspace lock that
/// revocation and member removal take exclusively.
pub async fn publish_branch_keys(
    pool: &PgPool,
    secwet_id: Uuid,
    signed: &SignedBranchStatement,
    keys: &[ScopedBranchKey],
) -> Result<BranchScopeDto, RelayApiError> {
    let statement = &signed.statement;
    let space_id = statement.space_id;
    let epoch = statement.epoch;
    let epoch_i32 = i32::try_from(epoch)
        .map_err(|_| RelayApiError::InvalidRequest("Branch epoch out of range".into()))?;
    let statement_bytes = postcard::to_stdvec(signed)
        .map_err(|e| RelayApiError::Internal(format!("Statement encode error: {e}")))?;

    let mut tx = pool.begin().await?;
    query("SELECT 1 FROM secwets WHERE id = $1 FOR SHARE")
        .bind(secwet_id)
        .execute(&mut *tx)
        .await?;
    let current = query_scalar::<_, i32>(
        "SELECT current_epoch FROM branch_scopes WHERE secwet_id = $1 AND space_id = $2 FOR UPDATE",
    )
    .bind(secwet_id)
    .bind(space_id)
    .fetch_optional(&mut *tx)
    .await?;

    if statement.rotate {
        let expected = current.map(|c| i64::from(c) + 1).unwrap_or(1);
        if i64::from(epoch) != expected {
            return Err(RelayApiError::EpochConflict(format!(
                "Branch rotation must open epoch {expected}, got {epoch}"
            )));
        }
    } else {
        match current {
            Some(c) if c == epoch_i32 => {}
            Some(c) => {
                return Err(RelayApiError::EpochConflict(format!(
                    "Branch publish targets epoch {epoch}, current is {c}"
                )))
            }
            None => {
                return Err(RelayApiError::EpochConflict(
                    "Space is not shared yet; publish with rotate = true".into(),
                ))
            }
        }
    }

    for key in keys {
        check_branch_recipient(&mut tx, secwet_id, space_id, &key.device_id).await?;
    }

    if statement.rotate {
        let changed = match current {
            None => query(
                r#"
                INSERT INTO branch_scopes (secwet_id, space_id, current_epoch)
                VALUES ($1, $2, $3)
                ON CONFLICT (secwet_id, space_id) DO NOTHING
                "#,
            )
            .bind(secwet_id)
            .bind(space_id)
            .bind(epoch_i32)
            .execute(&mut *tx)
            .await?
            .rows_affected(),
            Some(c) => query(
                r#"
                UPDATE branch_scopes SET current_epoch = $3
                WHERE secwet_id = $1 AND space_id = $2 AND current_epoch = $4
                "#,
            )
            .bind(secwet_id)
            .bind(space_id)
            .bind(epoch_i32)
            .bind(c)
            .execute(&mut *tx)
            .await?
            .rows_affected(),
        };
        if changed == 0 {
            return Err(RelayApiError::EpochConflict(
                "Another branch rotation opened this epoch first".into(),
            ));
        }
    }

    for key in keys {
        let wrapped = postcard::to_stdvec(&key.wrapped)
            .map_err(|e| RelayApiError::Internal(format!("Wrapped key encode error: {e}")))?;
        query(
            r#"
            INSERT INTO branch_keys (secwet_id, space_id, epoch, device_id, wrapped, sealed_bundle, statement)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (secwet_id, space_id, epoch, device_id) DO UPDATE SET
                wrapped = EXCLUDED.wrapped,
                sealed_bundle = EXCLUDED.sealed_bundle,
                statement = EXCLUDED.statement
            "#,
        )
        .bind(secwet_id)
        .bind(space_id)
        .bind(epoch_i32)
        .bind(&key.device_id)
        .bind(&wrapped)
        .bind(&key.sealed_bundle)
        .bind(&statement_bytes)
        .execute(&mut *tx)
        .await?;
    }

    let recipients = scope_recipients(&mut *tx, secwet_id, space_id, epoch_i32).await?;
    tx.commit().await?;
    Ok(BranchScopeDto {
        space_id,
        current_epoch: epoch,
        recipients,
    })
}

/// Device ids holding a bundle of `space_id` at `epoch`, sorted.
async fn scope_recipients<'e, E>(
    executor: E,
    secwet_id: Uuid,
    space_id: Uuid,
    epoch: i32,
) -> Result<Vec<String>, SqlxError>
where
    E: crate::sqlx::Executor<'e, Database = Postgres>,
{
    query_scalar::<_, String>(
        "SELECT device_id FROM branch_keys WHERE secwet_id = $1 AND space_id = $2 AND epoch = $3 \
         ORDER BY device_id",
    )
    .bind(secwet_id)
    .bind(space_id)
    .bind(epoch)
    .fetch_all(executor)
    .await
}

/// Every branch scope of a workspace. With `with_recipients`, each scope
/// lists the devices holding a bundle at its current epoch.
pub async fn list_branch_scopes(
    pool: &PgPool,
    secwet_id: Uuid,
    with_recipients: bool,
) -> Result<Vec<BranchScopeDto>, RelayApiError> {
    let rows = query(
        "SELECT space_id, current_epoch FROM branch_scopes WHERE secwet_id = $1 ORDER BY space_id",
    )
    .bind(secwet_id)
    .fetch_all(pool)
    .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let space_id: Uuid = row.try_get("space_id")?;
        let epoch: i32 = row.try_get("current_epoch")?;
        let recipients = if with_recipients {
            scope_recipients(pool, secwet_id, space_id, epoch).await?
        } else {
            Vec::new()
        };
        out.push(BranchScopeDto {
            space_id,
            current_epoch: epoch.max(0) as u32,
            recipients,
        });
    }
    Ok(out)
}

/// Branch key bundles addressed to one device, every space and epoch, each
/// with the signed publish statement it came from.
pub async fn get_branch_keys_for_device(
    pool: &PgPool,
    secwet_id: Uuid,
    device_id: &str,
) -> Result<Vec<ScopedBranchKey>, RelayApiError> {
    let rows = query(
        r#"
        SELECT space_id, epoch, wrapped, sealed_bundle, statement FROM branch_keys
        WHERE secwet_id = $1 AND device_id = $2
        ORDER BY space_id ASC, epoch ASC
        "#,
    )
    .bind(secwet_id)
    .bind(device_id)
    .fetch_all(pool)
    .await?;
    rows.into_iter()
        .map(|row| {
            let space_id: Uuid = row.try_get("space_id")?;
            let epoch: i32 = row.try_get("epoch")?;
            let wrapped: Vec<u8> = row.try_get("wrapped")?;
            let sealed_bundle: Vec<u8> = row.try_get("sealed_bundle")?;
            let statement: Option<Vec<u8>> = row.try_get("statement")?;
            let wrapped: WrappedKey = postcard::from_bytes(&wrapped)
                .map_err(|_| RelayApiError::Internal("Stored branch key is corrupt".into()))?;
            let statement = match statement {
                Some(bytes) => Some(postcard::from_bytes::<SignedBranchStatement>(&bytes).map_err(
                    |_| RelayApiError::Internal("Stored branch statement is corrupt".into()),
                )?),
                None => None,
            };
            Ok(ScopedBranchKey {
                space_id,
                epoch: epoch.max(0) as u32,
                device_id: device_id.to_string(),
                wrapped,
                sealed_bundle,
                statement,
            })
        })
        .collect()
}

// ============================================================================
// Device certificates
// ============================================================================

/// Stores verified certificates. One row per (workspace, device, certifier);
/// a newer certificate replaces an older one, an older one is ignored.
pub async fn store_certificates(
    pool: &PgPool,
    secwet_id: Uuid,
    certificates: &[SignedDeviceCertificate],
) -> Result<(), RelayApiError> {
    let mut tx = pool.begin().await?;
    for cert in certificates {
        let bytes = postcard::to_stdvec(cert)
            .map_err(|e| RelayApiError::Internal(format!("Certificate encode error: {e}")))?;
        query(
            r#"
            INSERT INTO device_certificates (secwet_id, device_id, certifier_device_id, issued_at, certificate)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (secwet_id, device_id, certifier_device_id) DO UPDATE SET
                issued_at = EXCLUDED.issued_at,
                certificate = EXCLUDED.certificate
            WHERE device_certificates.issued_at < EXCLUDED.issued_at
            "#,
        )
        .bind(secwet_id)
        .bind(&cert.certificate.device_id)
        .bind(&cert.certificate.certifier_device_id)
        .bind(cert.certificate.issued_at)
        .bind(&bytes)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Every certificate of a workspace.
pub async fn list_certificates(
    pool: &PgPool,
    secwet_id: Uuid,
) -> Result<Vec<SignedDeviceCertificate>, RelayApiError> {
    let rows = query_scalar::<_, Vec<u8>>(
        "SELECT certificate FROM device_certificates WHERE secwet_id = $1 \
         ORDER BY device_id, certifier_device_id",
    )
    .bind(secwet_id)
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|b| {
            postcard::from_bytes(b)
                .map_err(|_| RelayApiError::Internal("Stored certificate is corrupt".into()))
        })
        .collect()
}
