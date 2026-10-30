//! Error types and Axum JSON response formatting for Relay API.

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use secwet_proto::{RelayError, RelayErrorCode, SignedRevocation};

#[derive(Debug, thiserror::Error)]
pub enum RelayApiError {
    #[error("Bad signature: {0}")]
    BadSignature(String),

    #[error("Timestamp expired or clock skew too large: {0}")]
    ExpiredTimestamp(String),

    #[error("Nonce already seen (replay detected): {0}")]
    ReusedNonce(String),

    #[error("Device is revoked")]
    Revoked,

    /// Revoked device whose request signature verified: the response carries
    /// the signed directive so the device can wipe or archive itself.
    #[error("Device is revoked")]
    RevokedWithDirective(Box<SignedRevocation>),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Device is already revoked: {0}")]
    AlreadyRevoked(String),

    #[error("A device cannot revoke itself")]
    CannotRevokeSelf,

    #[error("Invalid invitation")]
    InvalidInvitation,

    #[error("Device not found")]
    DeviceNotFound,

    #[error("Workspace already exists: {0}")]
    Exists(String),

    #[error("Not entitled to this resource: {0}")]
    NotEntitled(String),

    #[error("Device limit reached: {0}")]
    DeviceLimit(String),

    #[error("Session expired: {0}")]
    Expired(String),

    #[error("Pairing session has already been joined")]
    AlreadyJoined,

    #[error("Pairing approval is pending")]
    Pending,

    #[error("Resource not found: {0}")]
    NotFound(String),

    #[error("Rate limit exceeded")]
    RateLimited,

    #[error("Sequence gap detected: {0}")]
    SeqGap(String),

    #[error("Cursor expired: {0}")]
    CursorExpired(String),

    #[error("Key epoch conflict: {0}")]
    EpochConflict(String),

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx_core::Error),

    #[error("Internal server error: {0}")]
    Internal(String),
}

impl RelayApiError {
    pub fn error_code(&self) -> RelayErrorCode {
        match self {
            Self::BadSignature(_) => RelayErrorCode::BadSignature,
            Self::ExpiredTimestamp(_) => RelayErrorCode::ExpiredTimestamp,
            Self::ReusedNonce(_) => RelayErrorCode::ReusedNonce,
            Self::Revoked | Self::RevokedWithDirective(_) => RelayErrorCode::Revoked,
            Self::Forbidden(_) => RelayErrorCode::Forbidden,
            Self::AlreadyRevoked(_) => RelayErrorCode::AlreadyRevoked,
            Self::CannotRevokeSelf => RelayErrorCode::CannotRevokeSelf,
            Self::InvalidInvitation => RelayErrorCode::InvalidInvitation,
            Self::DeviceNotFound => RelayErrorCode::Unauthorized,
            Self::Exists(_) => RelayErrorCode::Exists,
            Self::NotEntitled(_) => RelayErrorCode::NotEntitled,
            Self::DeviceLimit(_) => RelayErrorCode::DeviceLimit,
            Self::Expired(_) => RelayErrorCode::Expired,
            Self::AlreadyJoined => RelayErrorCode::AlreadyJoined,
            Self::Pending => RelayErrorCode::Pending,
            Self::NotFound(_) => RelayErrorCode::NotFound,
            Self::RateLimited => RelayErrorCode::RateLimited,
            Self::SeqGap(_) => RelayErrorCode::SeqGap,
            Self::CursorExpired(_) => RelayErrorCode::CursorExpired,
            Self::EpochConflict(_) => RelayErrorCode::EpochConflict,
            Self::InvalidRequest(_) => RelayErrorCode::InvalidRequest,
            Self::Database(_) | Self::Internal(_) => RelayErrorCode::Internal,
        }
    }

    pub fn status_code(&self) -> StatusCode {
        let code = self.error_code();
        StatusCode::from_u16(code.http_status_code())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl IntoResponse for RelayApiError {
    fn into_response(self) -> Response {
        let status = self.status_code();
        let code = self.error_code();
        let message = match &self {
            // Never echo database internals to clients.
            Self::Database(err) => {
                tracing::error!(error = %err, "Relay database error");
                "Internal server error".to_string()
            }
            other => other.to_string(),
        };

        let mut body = RelayError::new(code, message);
        if let Self::RevokedWithDirective(directive) = self {
            body.revocation = Some(*directive);
        }
        (status, Json(body)).into_response()
    }
}
