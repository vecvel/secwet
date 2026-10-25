//! Relay skeleton. Planned routes: device registration, signed auth
//! challenges, entitlement checks and a WebSocket for encrypted events.

use axum::{routing::get, Json, Router};
use serde_json::{json, Value};

async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

#[tokio::main]
async fn main() {
    let addr = std::env::var("SECWET_RELAY_ADDR").unwrap_or_else(|_| "127.0.0.1:8787".into());
    let app = Router::new().route("/health", get(health));
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind relay address");
    println!("secwet-relay listening on http://{addr}");
    axum::serve(listener, app).await.expect("relay server");
}
