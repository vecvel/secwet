//! Server setup, routing, and lifecycle management.

use axum::{
    extract::{Request, State},
    middleware::Next,
    response::Response,
    routing::{delete, get, post, put},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::{
    collab,
    error::RelayApiError,
    handlers::{self, AppState},
};

async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request,
    next: Next,
) -> Result<Response, RelayApiError> {
    crate::auth::verify_request_auth(&state.pool, &state.limiter, req, next).await
}

/// Creates the complete Axum Router.
pub fn create_router(state: Arc<AppState>) -> Router {
    let auth_routes = Router::new()
        .route("/v1/secwets/{id}/entitlement", get(handlers::get_entitlement))
        .route("/v1/secwets/{id}/events", post(handlers::push_events).get(handlers::get_events))
        .route("/v1/secwets/{id}/ack", post(handlers::ack_events))
        .route("/v1/secwets/{id}/snapshot", put(handlers::upload_snapshot).get(handlers::get_snapshot))
        .route("/v1/secwets/{id}/stream", get(handlers::stream_events))
        .route("/v1/pairing", post(handlers::start_pairing))
        .route("/v1/pairing/{id}", get(handlers::get_pairing_status))
        .route("/v1/pairing/{id}/approve", post(handlers::approve_pairing))
        // Devices, revocation, master key rotation
        .route("/v1/secwets/{id}/devices", get(collab::list_devices))
        .route("/v1/secwets/{id}/devices/{device_id}/revoke", post(collab::revoke_device))
        .route("/v1/secwets/{id}/keys", post(collab::rotate_keys).get(collab::get_keys))
        // Access, members, invitations, branch keys
        .route("/v1/secwets/{id}/access", get(collab::get_access))
        .route("/v1/secwets/{id}/members", get(collab::list_members))
        .route("/v1/secwets/{id}/invitations", post(collab::create_invitation))
        .route("/v1/secwets/{id}/invitations/{invitation_id}", delete(collab::delete_invitation))
        .route(
            "/v1/secwets/{id}/invitations/{invitation_id}/activate",
            post(collab::activate_invitation),
        )
        .route("/v1/secwets/{id}/members/{member_id}/grants", put(collab::update_member_grants))
        .route("/v1/secwets/{id}/members/{member_id}/remove", post(collab::remove_member))
        .route("/v1/secwets/{id}/spaces/{space_id}/keys", post(collab::publish_branch_keys))
        .route("/v1/secwets/{id}/branch-keys", get(collab::get_branch_keys))
        .route(
            "/v1/secwets/{id}/certificates",
            post(collab::post_certificates).get(collab::get_certificates),
        )
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware));

    Router::new()
        .route("/health", get(handlers::health))
        .route("/v1/secwets", post(handlers::register_secwet))
        .route("/v1/pairing/{id}/join", post(handlers::join_pairing))
        .route("/v1/pairing/{id}/result", get(handlers::get_pairing_result))
        .route("/v1/invitations/{invitation_id}/accept", post(collab::accept_invitation))
        .merge(auth_routes)
        // Redaction layer: trace headers/status only, never log bodies
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
