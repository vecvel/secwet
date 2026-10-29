//! PostgreSQL database queries, transaction management, and migrations.

use chrono::{DateTime, Utc};
use secwet_core::crypto::verify_signature_strict_bytes;
use secwet_proto::{
    EntitlementResponse, MemberGrant, RegisterSecwetResponse, SignedEvent, SnapshotResponse,
    StoredEventDto, WrappedEpochKey,
};
use uuid::Uuid;

use crate::{
    error::RelayApiError,
    sqlx::{
        postgres::PgPoolOptions, query, query_as, query_scalar, Error as SqlxError, Executor,
        FromRow, PgPool, PgRow, Row,
    },
};

pub const SCHEMA_MIGRATION_0001: &str = include_str!("../migrations/0001_relay_schema.sql");
pub const SCHEMA_MIGRATION_0002: &str = include_str!("../migrations/0002_collaboration.sql");
pub const SCHEMA_MIGRATION_0003: &str = include_str!("../migrations/0003_remediation.sql");
pub const SCHEMA_MIGRATION_0004: &str = include_str!("../migrations/0004_device_certificates.sql");

/// Advisory lock key serializing schema migrations across relay instances.
const MIGRATION_LOCK_KEY: i64 = 0x5EC3_E700_0002;

/// Column list matching [`DeviceRow`].
pub const DEVICE_COLUMNS: &str = "id, secwet_id, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, \
     ack_seq, member_id, wipe_requested, revocation, last_device_seq, revoked_seq";

#[derive(Debug, Clone)]
pub struct DeviceRow {
    pub id: String,
    pub secwet_id: Uuid,
    pub sign_pub: Vec<u8>,
    pub enc_pub: Vec<u8>,
    pub added_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub ack_seq: i64,
    pub member_id: Option<Uuid>,
    pub wipe_requested: bool,
    /// postcard `SignedRevocation`, set when revoked through the signed endpoint.
    pub revocation: Option<Vec<u8>>,
    pub last_device_seq: i64,
    /// Highest workspace server_seq when the device was revoked.
    pub revoked_seq: Option<i64>,
}

impl<'r> FromRow<'r, PgRow> for DeviceRow {
    fn from_row(row: &'r PgRow) -> Result<Self, SqlxError> {
        Ok(Self {
            id: row.try_get("id")?,
            secwet_id: row.try_get("secwet_id")?,
            sign_pub: row.try_get("sign_pub")?,
            enc_pub: row.try_get("enc_pub")?,
            added_at: row.try_get("added_at")?,
            revoked_at: row.try_get("revoked_at")?,
            last_seen_at: row.try_get("last_seen_at")?,
            ack_seq: row.try_get("ack_seq")?,
            member_id: row.try_get("member_id")?,
            wipe_requested: row.try_get("wipe_requested")?,
            revocation: row.try_get("revocation")?,
            last_device_seq: row.try_get("last_device_seq")?,
            revoked_seq: row.try_get("revoked_seq")?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct EntitlementRow {
    pub secwet_id: Uuid,
    pub plan: String,
    pub device_limit: i32,
    pub expires_at: Option<DateTime<Utc>>,
}

impl<'r> FromRow<'r, PgRow> for EntitlementRow {
    fn from_row(row: &'r PgRow) -> Result<Self, SqlxError> {
        Ok(Self {
            secwet_id: row.try_get("secwet_id")?,
            plan: row.try_get("plan")?,
            device_limit: row.try_get("device_limit")?,
            expires_at: row.try_get("expires_at")?,
        })
    }
}

/// Creates a connection pool for PostgreSQL.
pub async fn create_pool(database_url: &str) -> Result<PgPool, SqlxError> {
    PgPoolOptions::new()
        .max_connections(20)
        .connect(database_url)
        .await
}

/// Runs embedded schema migrations on startup, in order. Both migrations are
/// idempotent; a session-level advisory lock keeps concurrent relay instances
/// (or test binaries) from racing on DDL.
pub async fn run_migrations(pool: &PgPool) -> Result<(), SqlxError> {
    let mut conn = pool.acquire().await?;
    query("SELECT pg_advisory_lock($1)")
        .bind(MIGRATION_LOCK_KEY)
        .execute(&mut *conn)
        .await?;
    let result = async {
        (&mut *conn).execute(SCHEMA_MIGRATION_0001).await?;
        (&mut *conn).execute(SCHEMA_MIGRATION_0002).await?;
        (&mut *conn).execute(SCHEMA_MIGRATION_0003).await?;
        (&mut *conn).execute(SCHEMA_MIGRATION_0004).await?;
        Ok::<(), SqlxError>(())
    }
    .await;
    let unlock = query("SELECT pg_advisory_unlock($1)")
        .bind(MIGRATION_LOCK_KEY)
        .execute(&mut *conn)
        .await;
    result?;
    unlock?;
    Ok(())
}

/// Looks up a device by its ID.
pub async fn get_device(pool: &PgPool, device_id: &str) -> Result<Option<DeviceRow>, SqlxError> {
    query_as::<_, DeviceRow>(&format!("SELECT {DEVICE_COLUMNS} FROM devices WHERE id = $1"))
    .bind(device_id)
    .fetch_optional(pool)
    .await
}

/// Newest server_seq of a workspace, whether or not the event still exists
/// (retention may have pruned it).
pub async fn workspace_head_seq<'e, E>(executor: E, secwet_id: Uuid) -> Result<i64, SqlxError>
where
    E: Executor<'e, Database = crate::sqlx::Postgres>,
{
    query_scalar::<_, i64>(
        r#"
        SELECT GREATEST(
            COALESCE((SELECT MAX(server_seq) FROM events WHERE secwet_id = $1), 0),
            COALESCE((SELECT pruned_seq FROM secwets WHERE id = $1), 0)
        )
        "#,
    )
    .bind(secwet_id)
    .fetch_one(executor)
    .await
}

/// Updates last_seen_at for a device.
pub async fn update_device_last_seen(pool: &PgPool, device_id: &str) -> Result<(), SqlxError> {
    query(
        r#"
        UPDATE devices
        SET last_seen_at = now()
        WHERE id = $1
        "#,
    )
    .bind(device_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Tries to record a nonce.
/// Returns Ok(true) if the nonce was fresh and inserted.
/// Returns Ok(false) if the nonce was already present (replay attack).
pub async fn try_record_nonce(
    pool: &PgPool,
    device_id: &str,
    nonce: &[u8],
) -> Result<bool, SqlxError> {
    let result = query(
        r#"
        INSERT INTO seen_nonces (device_id, nonce, seen_at)
        VALUES ($1, $2, now())
        ON CONFLICT (device_id, nonce) DO NOTHING
        "#,
    )
    .bind(device_id)
    .bind(nonce)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Deletes seen nonces older than the retention threshold (e.g. 10 minutes).
pub async fn cleanup_old_nonces(pool: &PgPool, older_than_secs: i64) -> Result<u64, SqlxError> {
    let result = query(
        r#"
        DELETE FROM seen_nonces
        WHERE seen_at < now() - ($1 || ' seconds')::INTERVAL
        "#,
    )
    .bind(older_than_secs.to_string())
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Cleans up expired pairing sessions.
pub async fn cleanup_expired_pairing(pool: &PgPool) -> Result<u64, SqlxError> {
    let result = query(
        r#"
        DELETE FROM pairing_sessions
        WHERE expires_at < now()
        "#,
    )
    .execute(pool)
    .await?;

    Ok(result.rows_affected())
}

/// Registers a new workspace and its initial device.
pub async fn register_workspace_and_device(
    pool: &PgPool,
    secwet_id: Uuid,
    device_id: &str,
    sign_pub: &[u8; 32],
    enc_pub: &[u8; 32],
    plan: &str,
    device_limit: u32,
) -> Result<RegisterSecwetResponse, RelayApiError> {
    let mut tx = pool.begin().await?;

    // 1. A workspace exists once a device registered it. Registration is
    //    self-signed and proves nothing about who owns the id, so it never
    //    adopts an entitlement: grants need a registered workspace (see
    //    grant_entitlement), and an orphaned entitlement row left by an older
    //    relay also counts as taken until an operator ungrants it.
    let exists = query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(SELECT 1 FROM devices WHERE secwet_id = $1)
            OR EXISTS(SELECT 1 FROM entitlements WHERE secwet_id = $1)
        "#,
    )
    .bind(secwet_id)
    .fetch_one(&mut *tx)
    .await?;

    if exists {
        return Err(RelayApiError::Exists(secwet_id.to_string()));
    }

    // 2. Insert workspace (a bare row with no devices or entitlement holds
    //    nothing worth protecting and is reused)
    let created_at = query_scalar::<_, DateTime<Utc>>(
        r#"
        INSERT INTO secwets (id, created_at, current_epoch)
        VALUES ($1, now(), 1)
        ON CONFLICT (id) DO UPDATE SET id = EXCLUDED.id
        RETURNING created_at
        "#,
    )
    .bind(secwet_id)
    .fetch_one(&mut *tx)
    .await?;

    // 3. Insert device
    query(
        r#"
        INSERT INTO devices (id, secwet_id, sign_pub, enc_pub, added_at)
        VALUES ($1, $2, $3, $4, now())
        "#,
    )
    .bind(device_id)
    .bind(secwet_id)
    .bind(&sign_pub[..])
    .bind(&enc_pub[..])
    .execute(&mut *tx)
    .await?;

    // 4. Insert the default entitlement (step 1 ruled out an existing one)
    query(
        r#"
        INSERT INTO entitlements (secwet_id, plan, device_limit)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(secwet_id)
    .bind(plan)
    .bind(device_limit as i32)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;

    Ok(RegisterSecwetResponse {
        secwet_id,
        device_id: device_id.to_string(),
        created_at: created_at.to_rfc3339(),
        current_epoch: 1,
    })
}

/// Adds a subsequent device to an existing workspace, enforcing the active entitlement limit.
pub async fn add_device(
    pool: &PgPool,
    secwet_id: Uuid,
    device_id: &str,
    sign_pub: &[u8; 32],
    enc_pub: &[u8; 32],
) -> Result<(), RelayApiError> {
    let mut tx = pool.begin().await?;

    let ent = get_entitlement(pool, secwet_id).await?;
    let active_count = count_active_devices(pool, secwet_id).await?;

    if active_count >= ent.device_limit {
        return Err(RelayApiError::DeviceLimit(format!(
            "Device limit reached ({}/{})",
            active_count, ent.device_limit
        )));
    }

    query(
        r#"
        INSERT INTO devices (id, secwet_id, sign_pub, enc_pub, added_at)
        VALUES ($1, $2, $3, $4, now())
        "#,
    )
    .bind(device_id)
    .bind(secwet_id)
    .bind(&sign_pub[..])
    .bind(&enc_pub[..])
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}

/// Retrieves the entitlement for a given workspace.
pub async fn get_entitlement(
    pool: &PgPool,
    secwet_id: Uuid,
) -> Result<EntitlementResponse, RelayApiError> {
    let row = query_as::<_, EntitlementRow>(
        r#"
        SELECT secwet_id, plan, device_limit, expires_at
        FROM entitlements
        WHERE secwet_id = $1
        "#,
    )
    .bind(secwet_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => Ok(r.into_response()),
        None => Err(RelayApiError::NotFound(format!(
            "No entitlement for workspace {}",
            secwet_id
        ))),
    }
}

impl EntitlementRow {
    /// Pro whose end has not passed. Expiry is evaluated on every read, so an
    /// entitlement ends on time without a background job.
    pub fn is_active_pro(&self) -> bool {
        self.plan == "pro" && self.expires_at.is_none_or(|end| end > Utc::now())
    }

    /// The entitlement as clients see it: an ended Pro reads as `free` and
    /// keeps its `expires_at`, so the client can tell "Pro ended" from Free.
    pub fn into_response(self) -> EntitlementResponse {
        let plan = if self.plan == "pro" && !self.is_active_pro() {
            "free".to_string()
        } else {
            self.plan.clone()
        };
        EntitlementResponse {
            secwet_id: self.secwet_id,
            plan,
            device_limit: self.device_limit.max(0) as u32,
            expires_at: self.expires_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// Fails with `not_entitled` unless the workspace has an active Pro
/// entitlement. Guards pairing, sync and collaboration.
pub async fn require_active_pro<'e, E>(executor: E, secwet_id: Uuid) -> Result<(), RelayApiError>
where
    E: Executor<'e, Database = crate::sqlx::Postgres>,
{
    let active = query_scalar::<_, bool>(
        r#"
        SELECT plan = 'pro' AND (expires_at IS NULL OR expires_at > now())
        FROM entitlements
        WHERE secwet_id = $1
        "#,
    )
    .bind(secwet_id)
    .fetch_optional(executor)
    .await?
    .unwrap_or(false);
    if active {
        Ok(())
    } else {
        Err(RelayApiError::NotEntitled("This needs an active Pro plan".into()))
    }
}

/// Ends a workspace's entitlement now (admin `expire`). Sync pauses on every
/// device at its next contact; nothing is deleted.
pub async fn expire_entitlement(
    pool: &PgPool,
    secwet_id: Uuid,
) -> Result<EntitlementResponse, RelayApiError> {
    let row = query_as::<_, EntitlementRow>(
        r#"
        UPDATE entitlements SET expires_at = now()
        WHERE secwet_id = $1
        RETURNING secwet_id, plan, device_limit, expires_at
        "#,
    )
    .bind(secwet_id)
    .fetch_optional(pool)
    .await?
    .ok_or_else(|| RelayApiError::NotFound(format!("No entitlement for workspace {}", secwet_id)))?;
    Ok(row.into_response())
}

/// Grants or updates plan entitlements for a workspace (Admin operation).
pub async fn grant_entitlement(
    pool: &PgPool,
    secwet_id: Uuid,
    plan: &str,
    device_limit: u32,
    expires_at: Option<DateTime<Utc>>,
) -> Result<EntitlementResponse, RelayApiError> {
    let mut tx = pool.begin().await?;
    // Only a registered workspace can be granted. The id is shared with the
    // operator to get paid, and registration is self-signed, so a grant made
    // first would go to whichever device registered the id first. The owner
    // registers with "Check for Pro" (Settings > Plan), then pays.
    require_registered(&mut *tx, secwet_id).await?;
    let row = query_as::<_, EntitlementRow>(
        r#"
        INSERT INTO entitlements (secwet_id, plan, device_limit, expires_at)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (secwet_id) DO UPDATE SET
            plan = EXCLUDED.plan,
            device_limit = EXCLUDED.device_limit,
            expires_at = EXCLUDED.expires_at
        RETURNING secwet_id, plan, device_limit, expires_at
        "#,
    )
    .bind(secwet_id)
    .bind(plan)
    .bind(device_limit as i32)
    .bind(expires_at)
    .fetch_one(&mut *tx)
    .await?;
    tx.commit().await?;

    Ok(row.into_response())
}

async fn require_registered<'e, E>(executor: E, secwet_id: Uuid) -> Result<(), RelayApiError>
where
    E: Executor<'e, Database = crate::sqlx::Postgres>,
{
    let registered = query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM devices WHERE secwet_id = $1)")
        .bind(secwet_id)
        .fetch_one(executor)
        .await?;
    if registered {
        Ok(())
    } else {
        Err(RelayApiError::NotFound(format!(
            "Workspace {secwet_id} is not registered. The owner registers it with Check for Pro in Settings > Plan first."
        )))
    }
}

/// Moves a workspace to the Free plan (admin `ungrant`). For an id that never
/// registered it removes the entitlement left by a pre-registration grant
/// from an older relay, so the owner can register the id again.
pub async fn ungrant_entitlement(
    pool: &PgPool,
    secwet_id: Uuid,
) -> Result<EntitlementResponse, RelayApiError> {
    let mut tx = pool.begin().await?;
    let registered = query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM devices WHERE secwet_id = $1)")
        .bind(secwet_id)
        .fetch_one(&mut *tx)
        .await?;
    if !registered {
        query("DELETE FROM entitlements WHERE secwet_id = $1")
            .bind(secwet_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(EntitlementResponse {
            secwet_id,
            plan: "free".into(),
            device_limit: 1,
            expires_at: None,
        });
    }
    tx.commit().await?;
    grant_entitlement(pool, secwet_id, "free", 1, None).await
}

/// Revokes a device.
pub async fn revoke_device(
    pool: &PgPool,
    secwet_id: Uuid,
    device_id: &str,
) -> Result<bool, RelayApiError> {
    let result = query(
        r#"
        UPDATE devices
        SET revoked_at = now(),
            revoked_seq = GREATEST(
                COALESCE((SELECT MAX(server_seq) FROM events WHERE secwet_id = $1), 0),
                COALESCE((SELECT pruned_seq FROM secwets WHERE id = $1), 0))
        WHERE secwet_id = $1 AND id = $2 AND revoked_at IS NULL
        "#,
    )
    .bind(secwet_id)
    .bind(device_id)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Counts active (non-revoked) owner devices for a workspace. Collaborator
/// devices (`member_id IS NOT NULL`) do not count toward the device limit.
pub async fn count_active_devices(pool: &PgPool, secwet_id: Uuid) -> Result<u32, SqlxError> {
    let count: i64 = query_scalar(
        r#"
        SELECT count(*)
        FROM devices
        WHERE secwet_id = $1 AND revoked_at IS NULL AND member_id IS NULL
        "#,
    )
    .bind(secwet_id)
    .fetch_one(pool)
    .await?;

    Ok(count.max(0) as u32)
}

#[derive(Debug, Clone)]
pub struct PairingSessionRow {
    pub id: Uuid,
    pub secwet_id: Uuid,
    pub created_by: String,
    pub expires_at: DateTime<Utc>,
    pub a_eph_pub: Option<Vec<u8>>,
    pub join_payload: Option<Vec<u8>>,
    pub approved: bool,
    pub wrapped_keys: Option<Vec<u8>>,
    pub new_device_id: Option<String>,
}

impl<'r> FromRow<'r, PgRow> for PairingSessionRow {
    fn from_row(row: &'r PgRow) -> Result<Self, SqlxError> {
        Ok(Self {
            id: row.try_get("id")?,
            secwet_id: row.try_get("secwet_id")?,
            created_by: row.try_get("created_by")?,
            expires_at: row.try_get("expires_at")?,
            a_eph_pub: row.try_get("a_eph_pub")?,
            join_payload: row.try_get("join_payload")?,
            approved: row.try_get("approved")?,
            wrapped_keys: row.try_get("wrapped_keys")?,
            new_device_id: row.try_get("new_device_id")?,
        })
    }
}

/// Creates a new pairing session on the relay.
pub async fn create_pairing_session(
    pool: &PgPool,
    session_id: Uuid,
    secwet_id: Uuid,
    created_by: &str,
    a_eph_pub: &[u8; 32],
    expires_at: DateTime<Utc>,
) -> Result<(), SqlxError> {
    query(
        r#"
        INSERT INTO pairing_sessions (id, secwet_id, created_by, a_eph_pub, expires_at)
        VALUES ($1, $2, $3, $4, $5)
        "#,
    )
    .bind(session_id)
    .bind(secwet_id)
    .bind(created_by)
    .bind(&a_eph_pub[..])
    .bind(expires_at)
    .execute(pool)
    .await?;

    Ok(())
}

/// Fetches a pairing session by ID.
pub async fn get_pairing_session(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Option<PairingSessionRow>, SqlxError> {
    query_as::<_, PairingSessionRow>(
        r#"
        SELECT id, secwet_id, created_by, expires_at, a_eph_pub, join_payload, approved, wrapped_keys, new_device_id
        FROM pairing_sessions
        WHERE id = $1
        "#,
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await
}

/// Atomically submits the join payload for an active, unjoined pairing session.
pub async fn record_pairing_join(
    pool: &PgPool,
    session_id: Uuid,
    join_payload: &[u8],
) -> Result<bool, SqlxError> {
    let result = query(
        r#"
        UPDATE pairing_sessions
        SET join_payload = $2
        WHERE id = $1
          AND join_payload IS NULL
          AND expires_at > now()
          AND approved = false
        "#,
    )
    .bind(session_id)
    .bind(join_payload)
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}

/// Approves pairing session, enforces device quota, registers new device, and stores wrapped keys.
pub async fn approve_pairing_and_register_device(
    pool: &PgPool,
    session_id: Uuid,
    secwet_id: Uuid,
    new_device_id: &str,
    sign_pub: &[u8; 32],
    enc_pub: &[u8; 32],
    wrapped_keys: &[u8],
) -> Result<(), RelayApiError> {
    let mut tx = pool.begin().await?;

    // 1. Verify session is still valid and unapproved
    let session = query_as::<_, PairingSessionRow>(
        r#"
        SELECT id, secwet_id, created_by, expires_at, a_eph_pub, join_payload, approved, wrapped_keys, new_device_id
        FROM pairing_sessions
        WHERE id = $1 FOR UPDATE
        "#,
    )
    .bind(session_id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or_else(|| RelayApiError::NotFound("Pairing session not found".into()))?;

    if session.expires_at < Utc::now() {
        return Err(RelayApiError::Expired("Pairing session has expired".into()));
    }
    if session.approved {
        return Err(RelayApiError::InvalidRequest("Pairing session already approved".into()));
    }
    if session.join_payload.is_none() {
        return Err(RelayApiError::InvalidRequest("No device has joined this pairing session".into()));
    }

    // 2. Serialize with rotations and revocations, and require a wrapped
    //    master key for every epoch 1..=current so the new device can read
    //    all history and is never left behind by a concurrent rotation.
    let current_epoch = query_scalar::<_, i32>("SELECT current_epoch FROM secwets WHERE id = $1 FOR UPDATE")
        .bind(secwet_id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Workspace not found".into()))?;
    let keys: Vec<WrappedEpochKey> = postcard::from_bytes(wrapped_keys)
        .map_err(|_| RelayApiError::InvalidRequest("Invalid wrapped keys".into()))?;
    let covered: std::collections::BTreeSet<u32> = keys.iter().map(|k| k.epoch).collect();
    if (1..=current_epoch.max(1) as u32).any(|e| !covered.contains(&e))
        || keys.iter().any(|k| k.epoch == 0 || k.epoch as i64 > current_epoch as i64)
    {
        return Err(RelayApiError::EpochConflict(format!(
            "Approval must wrap the master key for every epoch 1..={current_epoch}"
        )));
    }

    // 3. Enforce device limit
    let active_count = query_scalar::<_, i64>(
        r#"
        SELECT count(*) FROM devices
        WHERE secwet_id = $1 AND revoked_at IS NULL AND member_id IS NULL
        "#,
    )
    .bind(secwet_id)
    .fetch_one(&mut *tx)
    .await?;

    let limit = query_scalar::<_, i32>(
        r#"
        SELECT device_limit FROM entitlements
        WHERE secwet_id = $1
        "#,
    )
    .bind(secwet_id)
    .fetch_optional(&mut *tx)
    .await?
    .unwrap_or(1);

    if active_count >= limit as i64 {
        return Err(RelayApiError::DeviceLimit(format!(
            "Device limit reached ({}/{})",
            active_count, limit
        )));
    }

    // 4. Register the new device
    query(
        r#"
        INSERT INTO devices (id, secwet_id, sign_pub, enc_pub, added_at)
        VALUES ($1, $2, $3, $4, now())
        ON CONFLICT (id) DO UPDATE SET
            revoked_at = NULL,
            revoked_seq = NULL,
            wipe_requested = false,
            revocation = NULL,
            last_seen_at = now()
        "#,
    )
    .bind(new_device_id)
    .bind(secwet_id)
    .bind(&sign_pub[..])
    .bind(&enc_pub[..])
    .execute(&mut *tx)
    .await?;

    // 5. Mark session approved and store wrapped keys
    query(
        r#"
        UPDATE pairing_sessions
        SET approved = true,
            wrapped_keys = $2,
            new_device_id = $3
        WHERE id = $1
        "#,
    )
    .bind(session_id)
    .bind(wrapped_keys)
    .bind(new_device_id)
    .execute(&mut *tx)
    .await?;

    // 6. Mirror the wrapped master keys into `wrapped_keys` so the new device
    //    can catch up later through `GET /v1/secwets/{id}/keys`.
    for key in keys {
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
        .bind(new_device_id)
        .bind(key.epoch as i32)
        .bind(&key.wrapped.enc[..])
        .bind(&key.wrapped.ciphertext)
        .execute(&mut *tx)
        .await?;
    }

    tx.commit().await?;
    Ok(())
}

// ============================================================================
// Sync Queries & Mutations
// ============================================================================

/// Result of [`append_events`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AppendOutcome {
    /// Events consumed (stored, deduplicated or rejected).
    pub accepted: usize,
    /// Events newly written to the log.
    pub stored: usize,
    /// Highest server_seq among stored or deduplicated events (0 if none).
    pub latest_server_seq: u64,
    /// Event ids consumed without storing because the author's role does not permit them.
    pub rejected: Vec<[u8; 16]>,
}

/// Which events a device may pull.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventVisibility {
    /// Owner devices: every event of the workspace.
    All,
    /// Member device with a workspace-level grant: every scoped event.
    AllScoped,
    /// Member device: scoped events of these spaces only.
    Spaces(Vec<Uuid>),
}

impl EventVisibility {
    /// Visibility for a member holding `grants` (`granted_spaces`).
    pub fn for_member(grants: &[MemberGrant]) -> Self {
        match secwet_proto::granted_spaces(grants) {
            None => EventVisibility::AllScoped,
            Some(spaces) => EventVisibility::Spaces(spaces),
        }
    }
}

/// Appends signed events to the workspace event stream.
///
/// `member_grants` is `None` for owner devices (unrestricted). For a member
/// device every event must carry a scope its grants permit; other events are
/// consumed (their `device_seq` advances) but not stored, and their ids are
/// returned in [`AppendOutcome::rejected`].
pub async fn append_events(
    pool: &PgPool,
    secwet_id: Uuid,
    device_id: &str,
    member_grants: Option<&[MemberGrant]>,
    events: &[SignedEvent],
) -> Result<AppendOutcome, RelayApiError> {
    if events.is_empty() {
        return Ok(AppendOutcome::default());
    }
    if events.len() > 500 {
        return Err(RelayApiError::InvalidRequest(
            "Exceeded max limit of 500 events per call".into(),
        ));
    }

    let mut tx = pool.begin().await?;

    // 0. Shared lock on the workspace row: a rotation or revocation (which
    //    take it exclusively) cannot interleave with this batch. Taken first
    //    to keep one lock order (secwets, devices, branch_scopes) everywhere.
    let current_epoch =
        query_scalar::<_, i32>("SELECT current_epoch FROM secwets WHERE id = $1 FOR SHARE")
            .bind(secwet_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or_else(|| RelayApiError::NotFound("Workspace not found".into()))?;

    // 1. Verify device exists, belongs to secwet, and is not revoked. The row
    //    lock serializes concurrent pushes from the same device.
    let device = query_as::<_, DeviceRow>(&format!(
        "SELECT {DEVICE_COLUMNS} FROM devices WHERE id = $1 AND secwet_id = $2 FOR UPDATE"
    ))
    .bind(device_id)
    .bind(secwet_id)
    .fetch_optional(&mut *tx)
    .await?;

    let device = match device {
        Some(d) => d,
        None => return Err(RelayApiError::DeviceNotFound),
    };

    if device.revoked_at.is_some() {
        return Err(RelayApiError::Revoked);
    }

    if device.sign_pub.len() != 32 {
        return Err(RelayApiError::BadSignature("Invalid device sign_pub length".into()));
    }
    let mut sign_pub_bytes = [0u8; 32];
    sign_pub_bytes.copy_from_slice(&device.sign_pub);

    // 2. Enforce an active (unexpired) Pro entitlement
    require_active_pro(&mut *tx, secwet_id).await?;

    // 3. Epoch enforcement for every new event of the batch: unscoped events
    //    must use the current master key epoch, scoped events the current
    //    branch epoch of their space. Any mismatch rejects the whole batch so
    //    the client refreshes its keys and re-encrypts its outbox.
    //
    //    Member devices: the role check comes first. An event the member's
    //    grants do not permit, or one in a space that is no longer shared, is
    //    consumed and rejected below and is not subject to the epoch check.
    let mut branch_epochs: std::collections::HashMap<Uuid, Option<i32>> =
        std::collections::HashMap::new();
    for signed_event in events {
        let envelope = &signed_event.envelope;
        let stored = query_scalar::<_, bool>("SELECT EXISTS(SELECT 1 FROM events WHERE event_id = $1)")
            .bind(&envelope.event_id[..])
            .fetch_one(&mut *tx)
            .await?;
        if stored {
            continue;
        }
        if let Some(grants) = member_grants {
            let permitted = envelope
                .scope
                .as_ref()
                .map(|scope| scope.permits(grants))
                .unwrap_or(false);
            if !permitted {
                continue;
            }
        }
        let expected = match &envelope.scope {
            None => Some(current_epoch),
            Some(scope) => match branch_epochs.get(&scope.space_id) {
                Some(epoch) => *epoch,
                None => {
                    let epoch = query_scalar::<_, i32>(
                        "SELECT current_epoch FROM branch_scopes \
                         WHERE secwet_id = $1 AND space_id = $2 FOR SHARE",
                    )
                    .bind(secwet_id)
                    .bind(scope.space_id)
                    .fetch_optional(&mut *tx)
                    .await?;
                    branch_epochs.insert(scope.space_id, epoch);
                    epoch
                }
            },
        };
        match expected {
            Some(epoch) if i64::from(epoch) == i64::from(envelope.key_epoch) => {}
            Some(epoch) => {
                return Err(RelayApiError::EpochConflict(format!(
                    "Event uses key epoch {}, current is {}",
                    envelope.key_epoch, epoch
                )))
            }
            // A member's event in a space that is not shared is consumed below.
            None if member_grants.is_some() => {}
            None => {
                return Err(RelayApiError::EpochConflict(
                    "Scoped event names a space that is not shared".into(),
                ))
            }
        }
    }

    // 4. Current device_seq: the persisted cursor, or the highest stored event
    //    for rows written before the cursor existed.
    let max_stored = query_scalar::<_, Option<i64>>(
        r#"
        SELECT MAX(device_seq) FROM events
        WHERE device_id = $1
        "#,
    )
    .bind(device_id)
    .fetch_one(&mut *tx)
    .await?
    .unwrap_or(0);
    let mut current_device_seq = device.last_device_seq.max(max_stored).max(0) as u64;
    let starting_device_seq = current_device_seq;

    let mut outcome = AppendOutcome::default();

    for signed_event in events {
        let envelope = &signed_event.envelope;
        // Enforce envelope constraints
        if envelope.device_id != device_id {
            return Err(RelayApiError::BadSignature(
                "Envelope device_id does not match authenticated device".into(),
            ));
        }
        if envelope.secwet_id != *secwet_id.as_bytes() {
            return Err(RelayApiError::InvalidRequest(
                "Envelope secwet_id does not match workspace".into(),
            ));
        }
        if envelope.ciphertext.len() > 256 * 1024 {
            return Err(RelayApiError::InvalidRequest(
                "Event ciphertext exceeds 256 KiB limit".into(),
            ));
        }

        // Deduplication check: if event_id already stored, skip insertion
        let existing = query(r#"SELECT server_seq, secwet_id FROM events WHERE event_id = $1"#)
            .bind(&envelope.event_id[..])
            .fetch_optional(&mut *tx)
            .await?;

        if let Some(row) = existing {
            let existing_secwet: Uuid = row.try_get("secwet_id")?;
            if existing_secwet != secwet_id {
                return Err(RelayApiError::InvalidRequest(
                    "Event id already used in another workspace".into(),
                ));
            }
            let existing_server_seq: i64 = row.try_get("server_seq")?;
            outcome.latest_server_seq = outcome.latest_server_seq.max(existing_server_seq as u64);
            continue;
        }

        // Cryptographic signature check over the canonical signing bytes
        // (legacy layout for unscoped events, full envelope for scoped ones).
        let signing_bytes = envelope
            .signing_bytes()
            .map_err(|e| RelayApiError::InvalidRequest(format!("Postcard encode error: {}", e)))?;
        verify_signature_strict_bytes(&sign_pub_bytes, &signing_bytes, &signed_event.signature)
            .map_err(|_| RelayApiError::BadSignature("Invalid event envelope signature".into()))?;

        // Member retry of an event that was consumed without being stored.
        if member_grants.is_some()
            && envelope.device_seq >= 1
            && envelope.device_seq <= current_device_seq
        {
            outcome.rejected.push(envelope.event_id);
            outcome.accepted += 1;
            continue;
        }

        // Strict monotonicity check (no sequence gaps)
        let expected_seq = current_device_seq + 1;
        if envelope.device_seq != expected_seq {
            return Err(RelayApiError::SeqGap(format!(
                "Sequence gap for device {}: expected {}, received {}",
                device_id, expected_seq, envelope.device_seq
            )));
        }

        // Role enforcement for collaborator devices.
        if let Some(grants) = member_grants {
            let permitted = envelope
                .scope
                .as_ref()
                .map(|scope| {
                    scope.permits(grants)
                        && matches!(branch_epochs.get(&scope.space_id), Some(Some(_)))
                })
                .unwrap_or(false);
            if !permitted {
                current_device_seq = envelope.device_seq;
                outcome.rejected.push(envelope.event_id);
                outcome.accepted += 1;
                continue;
            }
        }

        // Postcard-encode the entire SignedEvent
        let signed_event_bytes = postcard::to_stdvec(signed_event)
            .map_err(|e| RelayApiError::InvalidRequest(format!("Postcard encode error: {}", e)))?;
        let scope_space = envelope.scope.as_ref().map(|scope| scope.space_id);

        let server_seq = query_scalar::<_, i64>(
            r#"
            INSERT INTO events (secwet_id, event_id, device_id, device_seq, envelope, received_at, scope_space)
            VALUES ($1, $2, $3, $4, $5, now(), $6)
            RETURNING server_seq
            "#,
        )
        .bind(secwet_id)
        .bind(&envelope.event_id[..])
        .bind(device_id)
        .bind(envelope.device_seq as i64)
        .bind(&signed_event_bytes[..])
        .bind(scope_space)
        .fetch_one(&mut *tx)
        .await?;

        current_device_seq = envelope.device_seq;
        outcome.latest_server_seq = outcome.latest_server_seq.max(server_seq as u64);
        outcome.accepted += 1;
        outcome.stored += 1;
    }

    if current_device_seq != starting_device_seq || device.last_device_seq < max_stored {
        query("UPDATE devices SET last_device_seq = GREATEST(last_device_seq, $2) WHERE id = $1")
            .bind(device_id)
            .bind(current_device_seq as i64)
            .execute(&mut *tx)
            .await?;
    }

    tx.commit().await?;
    Ok(outcome)
}

/// Retrieves stored events after a given server sequence cursor, restricted
/// to what `visibility` allows the caller to see.
pub async fn get_events_after(
    pool: &PgPool,
    secwet_id: Uuid,
    after: i64,
    limit: i64,
    visibility: &EventVisibility,
) -> Result<(Vec<StoredEventDto>, bool, u64), RelayApiError> {
    let limit = limit.clamp(1, 500);

    // 1. Cursor expired when retention removed an event after it that the
    //    caller could see. Watermarks are tracked per workspace (owners) and
    //    per routing space (members) because server_seq is global: gaps
    //    between visible events are normal and are not pruning.
    let pruned_seq = match visibility {
        EventVisibility::All => {
            query_scalar::<_, i64>(r#"SELECT pruned_seq FROM secwets WHERE id = $1"#)
                .bind(secwet_id)
                .fetch_optional(pool)
                .await?
                .unwrap_or(0)
        }
        EventVisibility::AllScoped => query_scalar::<_, Option<i64>>(
            r#"SELECT MAX(pruned_seq) FROM scope_pruned WHERE secwet_id = $1"#,
        )
        .bind(secwet_id)
        .fetch_one(pool)
        .await?
        .unwrap_or(0),
        EventVisibility::Spaces(spaces) => query_scalar::<_, Option<i64>>(
            r#"SELECT MAX(pruned_seq) FROM scope_pruned WHERE secwet_id = $1 AND scope_space = ANY($2)"#,
        )
        .bind(secwet_id)
        .bind(spaces)
        .fetch_one(pool)
        .await?
        .unwrap_or(0),
    };

    if after < pruned_seq {
        return Err(RelayApiError::CursorExpired(format!(
            "Cursor {} is expired: visible events through {} were pruned",
            after, pruned_seq
        )));
    }

    // Head before the page, so a caller advancing to it never skips an
    // event committed after this read.
    let head_seq = workspace_head_seq(pool, secwet_id).await?.max(0) as u64;

    // 2. Fetch events after cursor, filtered in SQL so `limit` counts only
    //    events the caller may receive.
    let rows = match visibility {
        EventVisibility::All => {
            query(
                r#"
                SELECT server_seq, envelope, received_at
                FROM events
                WHERE secwet_id = $1 AND server_seq > $2
                ORDER BY server_seq ASC
                LIMIT $3
                "#,
            )
            .bind(secwet_id)
            .bind(after)
            .bind(limit + 1)
            .fetch_all(pool)
            .await?
        }
        EventVisibility::AllScoped => {
            query(
                r#"
                SELECT server_seq, envelope, received_at
                FROM events
                WHERE secwet_id = $1 AND server_seq > $2 AND scope_space IS NOT NULL
                ORDER BY server_seq ASC
                LIMIT $3
                "#,
            )
            .bind(secwet_id)
            .bind(after)
            .bind(limit + 1)
            .fetch_all(pool)
            .await?
        }
        EventVisibility::Spaces(spaces) => {
            if spaces.is_empty() {
                return Ok((Vec::new(), false, head_seq));
            }
            query(
                r#"
                SELECT server_seq, envelope, received_at
                FROM events
                WHERE secwet_id = $1 AND server_seq > $2 AND scope_space = ANY($4)
                ORDER BY server_seq ASC
                LIMIT $3
                "#,
            )
            .bind(secwet_id)
            .bind(after)
            .bind(limit + 1)
            .bind(spaces)
            .fetch_all(pool)
            .await?
        }
    };

    let has_more = rows.len() > limit as usize;
    let mut dtos = Vec::with_capacity(rows.len());

    for row in rows.into_iter().take(limit as usize) {
        let server_seq: i64 = row.try_get("server_seq")?;
        let envelope_bytes: Vec<u8> = row.try_get("envelope")?;
        let received_at: DateTime<Utc> = row.try_get("received_at")?;

        let event = SignedEvent::from_postcard_compat(&envelope_bytes).map_err(|e| {
            RelayApiError::Internal(format!("Failed to deserialize event envelope: {}", e))
        })?;

        dtos.push(StoredEventDto {
            server_seq: server_seq as u64,
            event,
            received_at: received_at.timestamp_millis(),
        });
    }

    Ok((dtos, has_more, head_seq))
}

/// Updates the acknowledged server_seq for a device.
pub async fn record_device_ack(
    pool: &PgPool,
    device_id: &str,
    server_seq: i64,
) -> Result<(), RelayApiError> {
    query(
        r#"
        UPDATE devices
        SET ack_seq = GREATEST(ack_seq, $2),
            last_seen_at = now()
        WHERE id = $1
        "#,
    )
    .bind(device_id)
    .bind(server_seq)
    .execute(pool)
    .await?;
    Ok(())
}

/// Saves an encrypted workspace snapshot.
pub async fn save_snapshot(
    pool: &PgPool,
    secwet_id: Uuid,
    server_seq: i64,
    key_epoch: i32,
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<(), RelayApiError> {
    query(
        r#"
        INSERT INTO snapshots (secwet_id, server_seq, key_epoch, nonce, ciphertext, updated_at)
        VALUES ($1, $2, $3, $4, $5, now())
        ON CONFLICT (secwet_id) DO UPDATE SET
            server_seq = $2,
            key_epoch = $3,
            nonce = $4,
            ciphertext = $5,
            updated_at = now()
        "#,
    )
    .bind(secwet_id)
    .bind(server_seq)
    .bind(key_epoch)
    .bind(nonce)
    .bind(ciphertext)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetches the newest encrypted snapshot for a workspace.
pub async fn get_snapshot(
    pool: &PgPool,
    secwet_id: Uuid,
) -> Result<Option<SnapshotResponse>, RelayApiError> {
    let row = query(
        r#"
        SELECT server_seq, key_epoch, nonce, ciphertext, updated_at
        FROM snapshots
        WHERE secwet_id = $1
        "#,
    )
    .bind(secwet_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some(r) => {
            let server_seq: i64 = r.try_get("server_seq")?;
            let key_epoch: i32 = r.try_get("key_epoch")?;
            let nonce_bytes: Vec<u8> = r.try_get("nonce")?;
            let ciphertext: Vec<u8> = r.try_get("ciphertext")?;
            let updated_at: DateTime<Utc> = r.try_get("updated_at")?;

            if nonce_bytes.len() != 24 {
                return Err(RelayApiError::Internal("Corrupted snapshot nonce".into()));
            }
            let mut nonce = [0u8; 24];
            nonce.copy_from_slice(&nonce_bytes);

            Ok(Some(SnapshotResponse {
                server_seq: server_seq as u64,
                key_epoch: key_epoch as u32,
                nonce,
                ciphertext,
                updated_at: updated_at.timestamp_millis(),
            }))
        }
        None => Ok(None),
    }
}

/// Deletes events that have been acknowledged by all active devices, or exceeded RETENTION_DAYS,
/// across every workspace.
pub async fn run_retention_job(
    pool: &PgPool,
    retention_days: i64,
) -> Result<u64, RelayApiError> {
    let mut total_deleted = 0u64;

    let secwet_ids = query_scalar::<_, Uuid>(
        r#"SELECT DISTINCT secwet_id FROM events"#
    )
    .fetch_all(pool)
    .await?;

    for secwet_id in secwet_ids {
        total_deleted += run_retention_for_secwet(pool, secwet_id, retention_days).await?;
    }

    Ok(total_deleted)
}

/// Retention for one workspace: deletes events acknowledged by every active
/// device (owner and member devices alike) or older than `retention_days`.
/// Unscoped events are never pruned past the latest snapshot, since that is
/// the only way an owner device can recover them. Pruning watermarks are
/// recorded per workspace and per routing space for cursor expiry.
pub async fn run_retention_for_secwet(
    pool: &PgPool,
    secwet_id: Uuid,
    retention_days: i64,
) -> Result<u64, RelayApiError> {
    let min_ack = query_scalar::<_, Option<i64>>(
        r#"
        SELECT MIN(ack_seq) FROM devices
        WHERE secwet_id = $1 AND revoked_at IS NULL
        "#,
    )
    .bind(secwet_id)
    .fetch_one(pool)
    .await?
    .unwrap_or(0);

    let mut tx = pool.begin().await?;
    let snapshot_seq = query_scalar::<_, i64>("SELECT server_seq FROM snapshots WHERE secwet_id = $1")
        .bind(secwet_id)
        .fetch_optional(&mut *tx)
        .await?;

    let deleted = query(
        r#"
        DELETE FROM events
        WHERE secwet_id = $1
          AND (server_seq <= $2 OR received_at < now() - ($3 * INTERVAL '1 day'))
          AND (scope_space IS NOT NULL OR $4::BIGINT IS NULL OR server_seq <= $4)
        RETURNING server_seq, scope_space
        "#,
    )
    .bind(secwet_id)
    .bind(min_ack)
    .bind(retention_days)
    .bind(snapshot_seq)
    .fetch_all(&mut *tx)
    .await?;

    let mut max_deleted: Option<i64> = None;
    let mut per_space: std::collections::HashMap<Uuid, i64> = std::collections::HashMap::new();
    for row in &deleted {
        let seq: i64 = row.try_get("server_seq")?;
        let space: Option<Uuid> = row.try_get("scope_space")?;
        max_deleted = Some(max_deleted.map_or(seq, |m| m.max(seq)));
        if let Some(space) = space {
            let entry = per_space.entry(space).or_insert(seq);
            *entry = (*entry).max(seq);
        }
    }

    if let Some(max_deleted) = max_deleted {
        query("UPDATE secwets SET pruned_seq = GREATEST(pruned_seq, $2) WHERE id = $1")
            .bind(secwet_id)
            .bind(max_deleted)
            .execute(&mut *tx)
            .await?;
    }
    for (space, seq) in per_space {
        query(
            r#"
            INSERT INTO scope_pruned (secwet_id, scope_space, pruned_seq)
            VALUES ($1, $2, $3)
            ON CONFLICT (secwet_id, scope_space) DO UPDATE SET
                pruned_seq = GREATEST(scope_pruned.pruned_seq, EXCLUDED.pruned_seq)
            "#,
        )
        .bind(secwet_id)
        .bind(space)
        .bind(seq)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    Ok(deleted.len() as u64)
}
