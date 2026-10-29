//! HTTP Request Handlers for Relay Endpoints.

use axum::{
    body::to_bytes,
    extract::{Extension, Path, Request, State},
    http::HeaderMap,
    Json,
};
use chrono::Utc;
use secwet_core::crypto::{compute_device_id, verify_signature_strict_bytes};
use secwet_proto::{
    canonical_registration_proof_bytes, canonical_request_bytes, AckEventsRequest,
    CreatePairingSessionRequest, CreatePairingSessionResponse, EntitlementResponse, HealthResponse,
    PairingApproveRequest, PairingJoinRequest, PairingResultResponse, PairingSessionStatusResponse,
    PullEventsResponse, PushEventsRequest, PushEventsResponse, RegisterSecwetRequest,
    RegisterSecwetResponse, SnapshotResponse, SnapshotUploadRequest, StreamEventMessage,
    WrappedEpochKey, HEADER_DEVICE, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIME, MAX_CLOCK_SKEW_MS,
};
use sha2::{Digest, Sha256};
use crate::sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    auth::{decode_base64url, AuthenticatedDevice},
    config::RelayConfig,
    db::{self, try_record_nonce},
    error::RelayApiError,
    rate_limit::RateLimitManager,
};

#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    pub config: RelayConfig,
    pub limiter: RateLimitManager,
    pub stream_tx: tokio::sync::broadcast::Sender<(Uuid, u64)>,
    /// Device ids revoked on this relay instance; open streams of those
    /// devices receive `{"type":"revoked"}` and are closed (F16).
    pub revoke_tx: tokio::sync::broadcast::Sender<String>,
}

impl AppState {
    pub fn new(pool: PgPool, config: RelayConfig, limiter: RateLimitManager) -> Self {
        let (stream_tx, _) = tokio::sync::broadcast::channel(1024);
        let (revoke_tx, _) = tokio::sync::broadcast::channel(256);
        Self {
            pool,
            config,
            limiter,
            stream_tx,
            revoke_tx,
        }
    }
}

/// Collaborator devices cannot pair new devices: a paired device would be
/// registered as an owner device.
fn require_owner_device(device: &AuthenticatedDevice) -> Result<(), RelayApiError> {
    if device.member_id.is_some() {
        return Err(RelayApiError::Forbidden(
            "Only the owner's devices may do this".into(),
        ));
    }
    Ok(())
}

/// GET /health
/// Unauthenticated health check.
pub async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
    })
}

/// POST /v1/secwets
/// Store and initial device registration with Ed25519 proof.
pub async fn register_secwet(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    req: Request,
) -> Result<Json<RegisterSecwetResponse>, RelayApiError> {
    // 1. Extract authentication headers
    let device_id = headers
        .get(HEADER_DEVICE)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            RelayApiError::BadSignature("Missing X-Secwet-Device header".into())
        })?
        .to_string();

    let time_str = headers
        .get(HEADER_TIME)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            RelayApiError::BadSignature("Missing X-Secwet-Time header".into())
        })?;

    let time_ms: i64 = time_str.parse().map_err(|_| {
        RelayApiError::InvalidRequest("Invalid X-Secwet-Time format".into())
    })?;

    let nonce_str = headers
        .get(HEADER_NONCE)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            RelayApiError::BadSignature("Missing X-Secwet-Nonce header".into())
        })?;

    let nonce_bytes = decode_base64url(nonce_str).map_err(|e| {
        RelayApiError::InvalidRequest(format!("Invalid X-Secwet-Nonce encoding: {}", e))
    })?;

    if nonce_bytes.len() != 16 {
        return Err(RelayApiError::InvalidRequest("Nonce must be 16 bytes".into()));
    }

    let signature_str = headers
        .get(HEADER_SIGNATURE)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            RelayApiError::BadSignature("Missing X-Secwet-Signature header".into())
        })?;

    let signature_bytes = decode_base64url(signature_str).map_err(|e| {
        RelayApiError::BadSignature(format!("Invalid X-Secwet-Signature encoding: {}", e))
    })?;

    if signature_bytes.len() != 64 {
        return Err(RelayApiError::BadSignature(
            "Signature must be 64 bytes".into(),
        ));
    }
    let mut sig_64 = [0u8; 64];
    sig_64.copy_from_slice(&signature_bytes);

    // 2. Rate limit check
    if !state.limiter.check_device(&device_id) {
        return Err(RelayApiError::RateLimited);
    }

    // 3. Timestamp skew check (60s)
    let now_ms = Utc::now().timestamp_millis();
    let skew = (now_ms - time_ms).abs();
    if skew > MAX_CLOCK_SKEW_MS {
        return Err(RelayApiError::ExpiredTimestamp(format!(
            "Timestamp skew {}ms exceeds {}ms limit",
            skew, MAX_CLOCK_SKEW_MS
        )));
    }

    // 4. Anti-replay check
    let fresh = try_record_nonce(&state.pool, &device_id, &nonce_bytes).await?;
    if !fresh {
        return Err(RelayApiError::ReusedNonce(
            "Nonce already seen for registration".into(),
        ));
    }

    // 5. Read and parse body
    let uri = req.uri().clone();
    let method = req.method().clone();

    let body_bytes = to_bytes(req.into_body(), 1024 * 1024)
        .await
        .map_err(|e| RelayApiError::InvalidRequest(format!("Failed to read body: {}", e)))?;

    let register_req: RegisterSecwetRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| RelayApiError::InvalidRequest(format!("Invalid JSON body: {}", e)))?;

    // 6. Verify device_id matches sign_pub
    let computed_device_id = compute_device_id(&register_req.sign_pub);
    if computed_device_id != device_id {
        return Err(RelayApiError::BadSignature(
            "Device ID header does not match public key in body".into(),
        ));
    }

    // 7. Verify registration proof signature over canonical payload
    let proof_canonical = canonical_registration_proof_bytes(
        &register_req.secwet_id,
        &register_req.sign_pub,
        &register_req.enc_pub,
    )
    .map_err(|e| RelayApiError::Internal(format!("Canonical proof error: {}", e)))?;

    verify_signature_strict_bytes(
        &register_req.sign_pub,
        &proof_canonical,
        &register_req.proof,
    )
    .map_err(|_| RelayApiError::BadSignature("Registration proof signature invalid".into()))?;

    // 8. Verify request signature over canonical request
    let body_sha256: [u8; 32] = Sha256::digest(&body_bytes).into();
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| uri.path());

    let canonical_req = canonical_request_bytes(
        method.as_str(),
        path_and_query,
        time_ms,
        &nonce_bytes,
        &body_sha256,
    )
    .map_err(|e| RelayApiError::Internal(format!("Canonical request error: {}", e)))?;

    verify_signature_strict_bytes(&register_req.sign_pub, &canonical_req, &sig_64).map_err(
        |_| RelayApiError::BadSignature("Request signature invalid".into()),
    )?;

    // 9. Register in PostgreSQL
    let res = db::register_workspace_and_device(
        &state.pool,
        register_req.secwet_id,
        &device_id,
        &register_req.sign_pub,
        &register_req.enc_pub,
        "free",
        state.config.default_device_limit,
    )
    .await?;

    Ok(Json(res))
}

/// GET /v1/secwets/{id}/entitlement
/// Authenticated query for workspace plan tier and device limits.
pub async fn get_entitlement(
    State(state): State<Arc<AppState>>,
    Extension(device): Extension<AuthenticatedDevice>,
    Path(secwet_id): Path<Uuid>,
) -> Result<Json<EntitlementResponse>, RelayApiError> {
    // Verify caller belongs to the requested workspace
    if device.secwet_id != secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to the requested workspace".into(),
        ));
    }

    let entitlement = db::get_entitlement(&state.pool, secwet_id).await?;
    Ok(Json(entitlement))
}

/// POST /v1/pairing
/// Starts a new pairing session for an authorized device.
pub async fn start_pairing(
    State(state): State<Arc<AppState>>,
    Extension(device): Extension<AuthenticatedDevice>,
    Json(req): Json<CreatePairingSessionRequest>,
) -> Result<Json<CreatePairingSessionResponse>, RelayApiError> {
    if device.secwet_id != req.secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to the requested workspace".into(),
        ));
    }
    require_owner_device(&device)?;
    db::require_active_pro(&state.pool, device.secwet_id).await?;

    // Check device limit / entitlement
    let entitlement = db::get_entitlement(&state.pool, device.secwet_id).await?;
    let active_count = db::count_active_devices(&state.pool, device.secwet_id).await?;
    if active_count >= entitlement.device_limit {
        return Err(RelayApiError::DeviceLimit(format!(
            "Device limit reached ({}/{})",
            active_count, entitlement.device_limit
        )));
    }

    let session_id = Uuid::now_v7();
    let expires_at = Utc::now() + chrono::Duration::minutes(5);

    let qr_payload = secwet_core::crypto::format_pairing_qr_payload(
        &session_id,
        &req.a_eph_pub,
        &state.config.public_url,
    );

    db::create_pairing_session(
        &state.pool,
        session_id,
        device.secwet_id,
        &device.device_id,
        &req.a_eph_pub,
        expires_at,
    )
    .await?;

    Ok(Json(CreatePairingSessionResponse {
        session_id,
        expires_at: expires_at.to_rfc3339(),
        qr_payload,
    }))
}

/// POST /v1/pairing/{id}/join
/// Unauthenticated endpoint for new device to submit its join payload.
pub async fn join_pairing(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
    Json(req): Json<PairingJoinRequest>,
) -> Result<Json<serde_json::Value>, RelayApiError> {
    let session = db::get_pairing_session(&state.pool, session_id)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Pairing session not found".into()))?;

    if session.expires_at < Utc::now() {
        return Err(RelayApiError::Expired("Pairing session has expired".into()));
    }
    if session.approved {
        return Err(RelayApiError::InvalidRequest("Pairing session already approved".into()));
    }
    if session.join_payload.is_some() {
        return Err(RelayApiError::AlreadyJoined);
    }

    let serialized = postcard::to_stdvec(&req)
        .map_err(|e| RelayApiError::InvalidRequest(format!("Invalid join payload: {}", e)))?;

    let recorded = db::record_pairing_join(&state.pool, session_id, &serialized).await?;
    if !recorded {
        return Err(RelayApiError::AlreadyJoined);
    }

    Ok(Json(serde_json::json!({ "status": "joined" })))
}

/// GET /v1/pairing/{id}
/// Authenticated query for creating device to inspect pairing session status and join payload.
pub async fn get_pairing_status(
    State(state): State<Arc<AppState>>,
    Extension(device): Extension<AuthenticatedDevice>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<PairingSessionStatusResponse>, RelayApiError> {
    let session = db::get_pairing_session(&state.pool, session_id)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Pairing session not found".into()))?;

    if session.secwet_id != device.secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this pairing session's workspace".into(),
        ));
    }

    if session.expires_at < Utc::now() {
        return Err(RelayApiError::Expired("Pairing session has expired".into()));
    }

    let (status, join_payload) = match (session.approved, session.join_payload) {
        (true, Some(bytes)) => {
            let join_req: PairingJoinRequest = postcard::from_bytes(&bytes)
                .map_err(|e| RelayApiError::Internal(format!("Corrupt join payload: {}", e)))?;
            ("approved".to_string(), Some(join_req))
        }
        (false, Some(bytes)) => {
            let join_req: PairingJoinRequest = postcard::from_bytes(&bytes)
                .map_err(|e| RelayApiError::Internal(format!("Corrupt join payload: {}", e)))?;
            ("joined".to_string(), Some(join_req))
        }
        (false, None) => ("waiting".to_string(), None),
        (true, None) => ("approved".to_string(), None),
    };

    Ok(Json(PairingSessionStatusResponse {
        session_id: session.id,
        secwet_id: session.secwet_id,
        created_by: session.created_by,
        expires_at: session.expires_at.to_rfc3339(),
        status,
        join_payload,
    }))
}

/// POST /v1/pairing/{id}/approve
/// Authenticated endpoint for creating device to approve pairing, register new device, and store wrapped keys.
pub async fn approve_pairing(
    State(state): State<Arc<AppState>>,
    Extension(device): Extension<AuthenticatedDevice>,
    Path(session_id): Path<Uuid>,
    Json(req): Json<PairingApproveRequest>,
) -> Result<Json<serde_json::Value>, RelayApiError> {
    let session = db::get_pairing_session(&state.pool, session_id)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Pairing session not found".into()))?;

    if session.secwet_id != device.secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this pairing session's workspace".into(),
        ));
    }
    require_owner_device(&device)?;
    db::require_active_pro(&state.pool, device.secwet_id).await?;

    if session.expires_at < Utc::now() {
        return Err(RelayApiError::Expired("Pairing session has expired".into()));
    }

    if req.approval.session_id != *session_id.as_bytes() {
        return Err(RelayApiError::BadSignature("Session ID mismatch in approval".into()));
    }

    // Verify approval signature using the approving device's sign_pub
    let mut caller_sign_pub = [0u8; 32];
    if device.sign_pub.len() != 32 {
        return Err(RelayApiError::Internal("Invalid signing key length".into()));
    }
    caller_sign_pub.copy_from_slice(&device.sign_pub);

    secwet_core::crypto::verify_pairing_approval(
        &req.approval,
        &req.signature,
        &caller_sign_pub,
    )
    .map_err(|_| RelayApiError::BadSignature("Approval signature invalid".into()))?;

    // Serialize wrapped keys
    let wrapped_keys_bytes = postcard::to_stdvec(&req.wrapped_keys)
        .map_err(|e| RelayApiError::Internal(format!("Failed to serialize wrapped keys: {}", e)))?;

    // Approve session, register device in DB, and enforce limit atomically
    db::approve_pairing_and_register_device(
        &state.pool,
        session_id,
        device.secwet_id,
        &req.approval.device_id,
        &req.approval.sign_pub,
        &req.approval.enc_pub,
        &wrapped_keys_bytes,
    )
    .await?;

    Ok(Json(serde_json::json!({ "status": "approved" })))
}

/// GET /v1/pairing/{id}/result
/// Unauthenticated endpoint for new device to poll for approval and retrieve wrapped keys.
pub async fn get_pairing_result(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<Json<PairingResultResponse>, RelayApiError> {
    let session = db::get_pairing_session(&state.pool, session_id)
        .await?
        .ok_or_else(|| RelayApiError::NotFound("Pairing session not found".into()))?;

    if session.expires_at < Utc::now() {
        return Err(RelayApiError::Expired("Pairing session has expired".into()));
    }

    if !session.approved {
        return Err(RelayApiError::Pending);
    }

    let wrapped_keys_bytes = session
        .wrapped_keys
        .ok_or_else(|| RelayApiError::Internal("Wrapped keys missing on approved session".into()))?;

    let wrapped_keys: Vec<WrappedEpochKey> = postcard::from_bytes(&wrapped_keys_bytes)
        .map_err(|e| RelayApiError::Internal(format!("Failed to deserialize wrapped keys: {}", e)))?;

    let device_id = session.new_device_id.unwrap_or_default();

    Ok(Json(PairingResultResponse {
        secwet_id: session.secwet_id,
        device_id,
        wrapped_keys,
    }))
}

// ============================================================================
// Sync Handlers (M6)
// ============================================================================

/// POST /v1/secwets/{id}/events
/// Append signed events to the workspace.
pub async fn push_events(
    State(state): State<Arc<AppState>>,
    Path(secwet_id): Path<Uuid>,
    Extension(auth_device): Extension<AuthenticatedDevice>,
    Json(req): Json<PushEventsRequest>,
) -> Result<Json<PushEventsResponse>, RelayApiError> {
    if auth_device.secwet_id != secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this workspace".into(),
        ));
    }

    let member_grants = crate::collab::member_grants_for(&state.pool, &auth_device).await?;
    let outcome = db::append_events(
        &state.pool,
        secwet_id,
        &auth_device.device_id,
        member_grants.as_deref(),
        &req.events,
    )
    .await?;

    if outcome.stored > 0 {
        let _ = state.stream_tx.send((secwet_id, outcome.latest_server_seq));
    }

    Ok(Json(PushEventsResponse {
        accepted: outcome.accepted,
        latest_server_seq: outcome.latest_server_seq,
        rejected: outcome.rejected,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct EventsQuery {
    pub after: Option<i64>,
    pub limit: Option<i64>,
}

/// GET /v1/secwets/{id}/events
/// Pull events after the specified cursor.
///
/// Pull, ack and snapshot download need only membership, so a paused
/// workspace (Pro ended) can still catch up on what was pushed while it was
/// Pro and receive revocations. Nothing new can land: push, snapshot upload
/// and the live stream need an active Pro plan, so a workspace that never had
/// Pro has nothing to pull.
pub async fn get_events(
    State(state): State<Arc<AppState>>,
    Path(secwet_id): Path<Uuid>,
    Extension(auth_device): Extension<AuthenticatedDevice>,
    axum::extract::Query(query): axum::extract::Query<EventsQuery>,
) -> Result<Json<PullEventsResponse>, RelayApiError> {
    if auth_device.secwet_id != secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this workspace".into(),
        ));
    }

    let after = query.after.unwrap_or(0);
    let limit = query.limit.unwrap_or(500);

    let visibility = match crate::collab::member_grants_for(&state.pool, &auth_device).await? {
        None => db::EventVisibility::All,
        Some(grants) => db::EventVisibility::for_member(&grants),
    };
    let (events, has_more, head_seq) =
        db::get_events_after(&state.pool, secwet_id, after, limit, &visibility).await?;

    Ok(Json(PullEventsResponse {
        events,
        has_more,
        head_seq,
    }))
}

/// POST /v1/secwets/{id}/ack
/// Record the device's acknowledged server_seq.
pub async fn ack_events(
    State(state): State<Arc<AppState>>,
    Path(secwet_id): Path<Uuid>,
    Extension(auth_device): Extension<AuthenticatedDevice>,
    Json(req): Json<AckEventsRequest>,
) -> Result<Json<serde_json::Value>, RelayApiError> {
    if auth_device.secwet_id != secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this workspace".into(),
        ));
    }

    db::record_device_ack(&state.pool, &auth_device.device_id, req.server_seq as i64).await?;
    Ok(Json(serde_json::json!({ "ok": true })))
}

/// The workspace snapshot is sealed under the master key, which member
/// devices never hold (F19 §6).
fn require_snapshot_access(device: &AuthenticatedDevice) -> Result<(), RelayApiError> {
    if device.member_id.is_some() {
        return Err(RelayApiError::Forbidden(
            "Member devices cannot access the workspace snapshot".into(),
        ));
    }
    Ok(())
}

/// PUT /v1/secwets/{id}/snapshot
/// Upload an encrypted workspace snapshot.
pub async fn upload_snapshot(
    State(state): State<Arc<AppState>>,
    Path(secwet_id): Path<Uuid>,
    Extension(auth_device): Extension<AuthenticatedDevice>,
    Json(req): Json<SnapshotUploadRequest>,
) -> Result<Json<serde_json::Value>, RelayApiError> {
    if auth_device.secwet_id != secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this workspace".into(),
        ));
    }
    require_snapshot_access(&auth_device)?;
    // Storing on the relay is Pro only (F13), like push.
    db::require_active_pro(&state.pool, secwet_id).await?;

    db::save_snapshot(
        &state.pool,
        secwet_id,
        req.server_seq as i64,
        req.key_epoch as i32,
        &req.nonce,
        &req.ciphertext,
    )
    .await?;

    Ok(Json(serde_json::json!({ "ok": true })))
}

/// GET /v1/secwets/{id}/snapshot
/// Download the newest encrypted workspace snapshot.
pub async fn get_snapshot(
    State(state): State<Arc<AppState>>,
    Path(secwet_id): Path<Uuid>,
    Extension(auth_device): Extension<AuthenticatedDevice>,
) -> Result<Json<SnapshotResponse>, RelayApiError> {
    if auth_device.secwet_id != secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this workspace".into(),
        ));
    }
    require_snapshot_access(&auth_device)?;

    let snap = db::get_snapshot(&state.pool, secwet_id).await?;
    match snap {
        Some(s) => Ok(Json(s)),
        None => Err(RelayApiError::NotFound("Snapshot not found".into())),
    }
}

/// GET /v1/secwets/{id}/stream
/// WebSocket push notification stream for new events.
pub async fn stream_events(
    ws: axum::extract::ws::WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
    Path(secwet_id): Path<Uuid>,
    Extension(auth_device): Extension<AuthenticatedDevice>,
) -> Result<axum::response::Response, RelayApiError> {
    if auth_device.secwet_id != secwet_id {
        return Err(RelayApiError::NotEntitled(
            "Device does not belong to this workspace".into(),
        ));
    }

    // Live sync is Pro only (F13); a paused workspace pulls on demand.
    db::require_active_pro(&state.pool, secwet_id).await?;

    // Subscribe before the final revocation check so a revocation landing in
    // between is still delivered to this stream.
    let mut rx = state.stream_tx.subscribe();
    let mut revoke_rx = state.revoke_tx.subscribe();
    let device_id = auth_device.device_id.clone();
    if let Some(dev) = db::get_device(&state.pool, &device_id).await? {
        if dev.revoked_at.is_some() {
            return Err(RelayApiError::Revoked);
        }
    }

    Ok(ws.on_upgrade(move |mut socket| async move {
        use axum::extract::ws::Message;
        use tokio::sync::broadcast::error::RecvError;

        enum Step {
            Notify(u64),
            Revoked,
            Skip,
            Close,
        }

        loop {
            let step = tokio::select! {
                ev = rx.recv() => match ev {
                    Ok((target, seq)) if target == secwet_id => Step::Notify(seq),
                    Ok(_) | Err(RecvError::Lagged(_)) => Step::Skip,
                    Err(RecvError::Closed) => Step::Close,
                },
                rev = revoke_rx.recv() => match rev {
                    Ok(id) if id == device_id => Step::Revoked,
                    Ok(_) | Err(RecvError::Lagged(_)) => Step::Skip,
                    Err(RecvError::Closed) => Step::Close,
                },
                incoming = socket.recv() => match incoming {
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => Step::Close,
                    Some(Ok(_)) => Step::Skip,
                },
            };

            match step {
                Step::Notify(server_seq) => {
                    let msg = StreamEventMessage {
                        r#type: "events".into(),
                        server_seq,
                    };
                    if let Ok(text) = serde_json::to_string(&msg) {
                        if socket.send(Message::Text(text.into())).await.is_err() {
                            break;
                        }
                    }
                }
                Step::Revoked => {
                    let msg = StreamEventMessage {
                        r#type: "revoked".into(),
                        server_seq: 0,
                    };
                    if let Ok(text) = serde_json::to_string(&msg) {
                        let _ = socket.send(Message::Text(text.into())).await;
                    }
                    let _ = socket.send(Message::Close(None)).await;
                    break;
                }
                Step::Skip => {}
                Step::Close => break,
            }
        }
    }))
}
