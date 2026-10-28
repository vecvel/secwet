//! Request authentication middleware verifying Ed25519 signatures,
//! 60-second timestamp windows, and anti-replay nonces.
//!
//! Section 8.2:
//! Canonical payload: postcard(("secwet-req-v1", method, path_and_query, time, nonce, SHA-256(body)))

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use data_encoding::{BASE64URL, BASE64URL_NOPAD};
use secwet_core::crypto::verify_signature_strict_bytes;
use secwet_proto::{
    canonical_request_bytes, SignedRevocation, HEADER_DEVICE, HEADER_NONCE, HEADER_SIGNATURE,
    HEADER_TIME, MAX_CLOCK_SKEW_MS,
};
use sha2::{Digest, Sha256};
use crate::sqlx::PgPool;
use uuid::Uuid;

use crate::{
    db::{get_device, try_record_nonce, update_device_last_seen},
    error::RelayApiError,
    rate_limit::RateLimitManager,
};

#[derive(Debug, Clone)]
pub struct AuthenticatedDevice {
    pub device_id: String,
    pub secwet_id: Uuid,
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    /// `None` for the workspace owner's devices, `Some` for a collaborator's device.
    pub member_id: Option<Uuid>,
}

impl AuthenticatedDevice {
    /// Owner devices (`member_id IS NULL`) are unrestricted inside their workspace.
    pub fn is_owner(&self) -> bool {
        self.member_id.is_none()
    }
}

/// Decodes base64url string with or without padding.
pub fn decode_base64url(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.trim_end_matches('=');
    BASE64URL_NOPAD
        .decode(trimmed.as_bytes())
        .or_else(|_| BASE64URL.decode(s.as_bytes()))
        .map_err(|e| format!("Base64url decode error: {}", e))
}

/// Encodes binary to unpadded base64url string.
pub fn encode_base64url(bytes: &[u8]) -> String {
    BASE64URL_NOPAD.encode(bytes)
}

/// Extracts and verifies signed request headers.
pub async fn verify_request_auth(
    pool: &PgPool,
    limiter: &RateLimitManager,
    req: Request,
    next: Next,
) -> Result<Response, RelayApiError> {
    let (parts, body) = req.into_parts();

    // 1. Extract required headers
    let device_id = parts
        .headers
        .get(HEADER_DEVICE)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            RelayApiError::BadSignature("Missing X-Secwet-Device header".into())
        })?
        .to_string();

    let (time_ms, nonce_bytes, sig_64) = match parse_signed_headers(&parts.headers) {
        Ok(v) => v,
        Err(err) => {
            // An unsigned or malformed request naming a revoked device gets the
            // plain `revoked` answer, never the directive (F16 §2.2).
            if limiter.check_device(&device_id) {
                if let Ok(Some(dev)) = get_device(pool, &device_id).await {
                    if dev.revoked_at.is_some() {
                        return Err(RelayApiError::Revoked);
                    }
                }
            }
            return Err(err);
        }
    };

    // 2. Check rate limit
    if !limiter.check_device(&device_id) {
        return Err(RelayApiError::RateLimited);
    }

    // 3. Check timestamp skew (60s window)
    let now_ms = Utc::now().timestamp_millis();
    let skew = (now_ms - time_ms).abs();
    if skew > MAX_CLOCK_SKEW_MS {
        return Err(RelayApiError::ExpiredTimestamp(format!(
            "Request time {}ms differs from server time {}ms by {}ms (> {}ms limit)",
            time_ms, now_ms, skew, MAX_CLOCK_SKEW_MS
        )));
    }

    // 4. Anti-replay verification: record nonce atomically
    let fresh = try_record_nonce(pool, &device_id, &nonce_bytes).await?;
    if !fresh {
        return Err(RelayApiError::ReusedNonce(format!(
            "Nonce has already been used by device {}",
            device_id
        )));
    }

    // 5. Look up device identity in database
    let device_row = get_device(pool, &device_id).await?;
    let device = device_row.ok_or(RelayApiError::DeviceNotFound)?;

    if device.sign_pub.len() != 32 {
        return Err(RelayApiError::Internal("Stored sign_pub invalid size".into()));
    }
    let mut sign_pub = [0u8; 32];
    sign_pub.copy_from_slice(&device.sign_pub);

    if device.enc_pub.len() != 32 {
        return Err(RelayApiError::Internal("Stored enc_pub invalid size".into()));
    }
    let mut enc_pub = [0u8; 32];
    enc_pub.copy_from_slice(&device.enc_pub);

    // 6. Buffer and hash request body (max 10 MiB)
    let body_bytes = to_bytes(body, 10 * 1024 * 1024)
        .await
        .map_err(|e| RelayApiError::InvalidRequest(format!("Failed to read body: {}", e)))?;

    let body_sha256: [u8; 32] = Sha256::digest(&body_bytes).into();

    // 7. Verify Ed25519 signature over canonical request
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or_else(|| parts.uri.path());

    let canonical = canonical_request_bytes(
        parts.method.as_str(),
        path_and_query,
        time_ms,
        &nonce_bytes,
        &body_sha256,
    )
    .map_err(|e| RelayApiError::Internal(format!("Canonical serialization error: {}", e)))?;

    let signature_valid = verify_signature_strict_bytes(&sign_pub, &canonical, &sig_64).is_ok();

    // Revoked devices: the signed directive is only disclosed to a request that
    // proves possession of the revoked device's key (F16 §2.2).
    if device.revoked_at.is_some() {
        if signature_valid {
            if let Some(bytes) = device.revocation.as_deref() {
                if let Ok(directive) = postcard::from_bytes::<SignedRevocation>(bytes) {
                    return Err(RelayApiError::RevokedWithDirective(Box::new(directive)));
                }
            }
        }
        return Err(RelayApiError::Revoked);
    }

    if !signature_valid {
        return Err(RelayApiError::BadSignature("Signature verification failed".into()));
    }

    // 8. Update device last_seen_at asynchronously (ignore minor failure)
    let _ = update_device_last_seen(pool, &device_id).await;

    // 9. Reconstruct request with AuthenticatedDevice extension
    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(AuthenticatedDevice {
        device_id,
        secwet_id: device.secwet_id,
        sign_pub,
        enc_pub,
        member_id: device.member_id,
    });

    Ok(next.run(req).await)
}

/// Parses `X-Secwet-Time`, `X-Secwet-Nonce` and `X-Secwet-Signature`.
fn parse_signed_headers(
    headers: &axum::http::HeaderMap,
) -> Result<(i64, Vec<u8>, [u8; 64]), RelayApiError> {
    let time_str = headers
        .get(HEADER_TIME)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            RelayApiError::BadSignature("Missing X-Secwet-Time header".into())
        })?;

    let time_ms: i64 = time_str.parse().map_err(|_| {
        RelayApiError::InvalidRequest("Invalid X-Secwet-Time header format".into())
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
        return Err(RelayApiError::InvalidRequest(format!(
            "Nonce must be exactly 16 bytes, got {}",
            nonce_bytes.len()
        )));
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
        return Err(RelayApiError::BadSignature(format!(
            "Signature must be exactly 64 bytes, got {}",
            signature_bytes.len()
        )));
    }

    let mut sig_64 = [0u8; 64];
    sig_64.copy_from_slice(&signature_bytes);

    Ok((time_ms, nonce_bytes, sig_64))
}
