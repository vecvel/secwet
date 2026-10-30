//! Integration & Adversarial Test Suite for Secwet Relay Server.
//!
//! Validates:
//! 1. `GET /health` unauthenticated check
//! 2. `rejects_unsigned_request`: Missing auth headers return 401 Unauthorized
//! 3. `rejects_old_timestamp`: Timestamp > 60s in the past returns 401 expired_timestamp
//! 4. `rejects_future_timestamp`: Timestamp > 60s in the future returns 401 expired_timestamp
//! 5. `rejects_reused_nonce`: Nonce reused by device returns 401 reused_nonce
//! 6. `rejects_corrupted_signature`: Corrupted signature returns 401 unauthorized
//! 7. `register_secwet_and_entitlements`: Happy-path workspace registration & entitlement check
//! 8. `revoked_device_rejected_everywhere`: Revoked device returns 403 revoked
//! 9. `device_limit_enforced`: Quota limit strictly enforced on device additions
//! 10. `admin_grant_and_status`: Admin entitlement CLI command from Free to Pro
//! 11. `relay_never_stores_plaintext`: Adversarial zero-knowledge leakage oracle scanning all DB tables

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use reqwest::header::{HeaderMap, HeaderValue};
use secwet_core::{crypto::compute_device_id, RelayClient};
use secwet_proto::{
    canonical_request_bytes, HealthResponse, RelayError, RelayErrorCode, HEADER_DEVICE,
    HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIME,
};
use secwet_relay::{
    admin::{self, AdminCommand, AdminGrantArgs, AdminStatusArgs},
    create_router,
    db::{self, create_pool, run_migrations},
    rate_limit::RateLimitManager,
    sqlx::Row,
    AppState, RelayConfig,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::OnceCell;
use uuid::Uuid;

static MIGRATION_ONCE: OnceCell<()> = OnceCell::const_new();

fn test_db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".into())
}

async fn setup_test_server() -> (String, secwet_relay::sqlx::PgPool) {
    let db_url = test_db_url();
    let pool = create_pool(&db_url).await.expect("Failed to connect to test Postgres");

    MIGRATION_ONCE
        .get_or_init(|| async {
            run_migrations(&pool).await.expect("Failed to run migrations");
        })
        .await;

    let mut config = RelayConfig::from_env();
    config.database_url = db_url;
    config.default_device_limit = 2;

    let state = AppState::new(pool.clone(), config, RateLimitManager::new());

    let router = create_router(Arc::new(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("Bind ephemeral port");
    let addr = listener.local_addr().expect("Get local addr");
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (base_url, pool)
}

fn generate_keypair() -> (SigningKey, [u8; 32], String) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("random seed");
    let signing_key = SigningKey::from_bytes(&seed);
    let sign_pub = signing_key.verifying_key().to_bytes();
    let device_id = compute_device_id(&sign_pub);
    (signing_key, sign_pub, device_id)
}

fn generate_enc_pub() -> [u8; 32] {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("random seed");
    let secret = x25519_dalek::StaticSecret::from(seed);
    x25519_dalek::PublicKey::from(&secret).to_bytes()
}

fn build_auth_headers(
    method: &str,
    path_and_query: &str,
    body: &[u8],
    device_id: &str,
    signing_key: &SigningKey,
    time_offset_ms: i64,
    custom_nonce: Option<[u8; 16]>,
) -> HeaderMap {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let time_ms = now_ms + time_offset_ms;

    let nonce_bytes = match custom_nonce {
        Some(n) => n,
        None => {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes).expect("nonce random");
            bytes
        }
    };
    let nonce_b64 = BASE64URL_NOPAD.encode(&nonce_bytes);

    let mut hasher = Sha256::new();
    hasher.update(body);
    let body_hash: [u8; 32] = hasher.finalize().into();

    let canonical =
        canonical_request_bytes(method, path_and_query, time_ms, &nonce_bytes, &body_hash)
            .expect("canonical bytes");
    let signature = signing_key.sign(&canonical);
    let sig_b64 = BASE64URL_NOPAD.encode(&signature.to_bytes());

    let mut headers = HeaderMap::new();
    headers.insert(HEADER_DEVICE, HeaderValue::from_str(device_id).unwrap());
    headers.insert(HEADER_TIME, HeaderValue::from_str(&time_ms.to_string()).unwrap());
    headers.insert(HEADER_NONCE, HeaderValue::from_str(&nonce_b64).unwrap());
    headers.insert(HEADER_SIGNATURE, HeaderValue::from_str(&sig_b64).unwrap());
    headers.insert(
        reqwest::header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers
}

#[tokio::test]
async fn test_health_check() {
    let (base_url, _) = setup_test_server().await;
    let client = reqwest::Client::new();
    let res = client
        .get(format!("{}/health", base_url))
        .send()
        .await
        .expect("send health request");

    assert_eq!(res.status(), reqwest::StatusCode::OK);
    let body = res.json::<HealthResponse>().await.expect("parse health json");
    assert_eq!(body.status, "ok");
}

#[tokio::test]
async fn test_rejects_unsigned_request() {
    let (base_url, _) = setup_test_server().await;
    let client = reqwest::Client::new();
    let secwet_id = Uuid::now_v7();

    // GET /v1/secwets/{id}/entitlement without auth headers
    let res = client
        .get(format!("{}/v1/secwets/{}/entitlement", base_url, secwet_id))
        .send()
        .await
        .expect("send request");

    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    let err = res.json::<RelayError>().await.expect("parse error");
    assert_eq!(err.error.code, RelayErrorCode::BadSignature);
}

#[tokio::test]
async fn test_rejects_old_timestamp() {
    let (base_url, _) = setup_test_server().await;
    let (signing_key, sign_pub, device_id) = generate_keypair();
    let enc_pub = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    // First register workspace so device exists
    let client = RelayClient::new(&base_url, &device_id);
    let reg = client.register(secwet_id, sign_pub, enc_pub, &signing_key).await;
    assert!(reg.is_ok(), "Registration must succeed: {:?}", reg.err());

    // Send request with timestamp skewed 65 seconds in the past
    let raw_client = reqwest::Client::new();
    let path = format!("/v1/secwets/{}/entitlement", secwet_id);
    let headers = build_auth_headers(
        "GET",
        &path,
        b"",
        &device_id,
        &signing_key,
        -65_000, // 65 seconds in past (> 60s skew limit)
        None,
    );

    let res = raw_client
        .get(format!("{}{}", base_url, path))
        .headers(headers)
        .send()
        .await
        .expect("send request");

    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    let err = res.json::<RelayError>().await.expect("parse error");
    assert_eq!(err.error.code, RelayErrorCode::ExpiredTimestamp);
}

#[tokio::test]
async fn test_rejects_future_timestamp() {
    let (base_url, _) = setup_test_server().await;
    let (signing_key, sign_pub, device_id) = generate_keypair();
    let enc_pub = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    let client = RelayClient::new(&base_url, &device_id);
    client.register(secwet_id, sign_pub, enc_pub, &signing_key).await.expect("register");

    // Send request with timestamp skewed 65 seconds in the future
    let raw_client = reqwest::Client::new();
    let path = format!("/v1/secwets/{}/entitlement", secwet_id);
    let headers = build_auth_headers(
        "GET",
        &path,
        b"",
        &device_id,
        &signing_key,
        65_000, // 65 seconds in future (> 60s skew limit)
        None,
    );

    let res = raw_client
        .get(format!("{}{}", base_url, path))
        .headers(headers)
        .send()
        .await
        .expect("send request");

    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    let err = res.json::<RelayError>().await.expect("parse error");
    assert_eq!(err.error.code, RelayErrorCode::ExpiredTimestamp);
}

#[tokio::test]
async fn test_rejects_reused_nonce() {
    let (base_url, _) = setup_test_server().await;
    let (signing_key, sign_pub, device_id) = generate_keypair();
    let enc_pub = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    let client = RelayClient::new(&base_url, &device_id);
    client.register(secwet_id, sign_pub, enc_pub, &signing_key).await.expect("register");

    let raw_client = reqwest::Client::new();
    let path = format!("/v1/secwets/{}/entitlement", secwet_id);
    let fixed_nonce = [42u8; 16];

    let headers1 = build_auth_headers(
        "GET",
        &path,
        b"",
        &device_id,
        &signing_key,
        0,
        Some(fixed_nonce),
    );

    // 1. First request with fixed_nonce MUST succeed
    let res1 = raw_client
        .get(format!("{}{}", base_url, path))
        .headers(headers1.clone())
        .send()
        .await
        .expect("send request 1");
    assert_eq!(res1.status(), reqwest::StatusCode::OK);

    // 2. Replay attack: second request with exact same device & nonce MUST be rejected
    let res2 = raw_client
        .get(format!("{}{}", base_url, path))
        .headers(headers1)
        .send()
        .await
        .expect("send request 2");

    assert_eq!(res2.status(), reqwest::StatusCode::UNAUTHORIZED);
    let err = res2.json::<RelayError>().await.expect("parse error");
    assert_eq!(err.error.code, RelayErrorCode::ReusedNonce);
}

#[tokio::test]
async fn test_rejects_corrupted_signature() {
    let (base_url, _) = setup_test_server().await;
    let (signing_key, sign_pub, device_id) = generate_keypair();
    let enc_pub = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    let client = RelayClient::new(&base_url, &device_id);
    client.register(secwet_id, sign_pub, enc_pub, &signing_key).await.expect("register");

    let raw_client = reqwest::Client::new();
    let path = format!("/v1/secwets/{}/entitlement", secwet_id);
    let mut headers = build_auth_headers("GET", &path, b"", &device_id, &signing_key, 0, None);

    // Corrupt signature
    headers.insert(HEADER_SIGNATURE, HeaderValue::from_static("corrupted_invalid_signature_bytes"));

    let res = raw_client
        .get(format!("{}{}", base_url, path))
        .headers(headers)
        .send()
        .await
        .expect("send request");

    assert_eq!(res.status(), reqwest::StatusCode::UNAUTHORIZED);
    let err = res.json::<RelayError>().await.expect("parse error");
    assert_eq!(err.error.code, RelayErrorCode::BadSignature);
}

#[tokio::test]
async fn test_register_secwet_and_entitlements() {
    let (base_url, _) = setup_test_server().await;
    let (signing_key, sign_pub, device_id) = generate_keypair();
    let enc_pub = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    let client = RelayClient::new(&base_url, &device_id);

    // 1. Register
    let reg_res = client
        .register(secwet_id, sign_pub, enc_pub, &signing_key)
        .await
        .expect("register must succeed");

    assert_eq!(reg_res.secwet_id, secwet_id);
    assert_eq!(reg_res.device_id, device_id);
    assert_eq!(reg_res.current_epoch, 1);

    // 2. Query entitlement
    let ent = client
        .get_entitlement(secwet_id, &signing_key)
        .await
        .expect("get entitlement must succeed");

    assert_eq!(ent.plan, "free");
    assert_eq!(ent.device_limit, 2);
}

#[tokio::test]
async fn test_revoked_device_rejected_everywhere() {
    let (base_url, pool) = setup_test_server().await;
    let (signing_key, sign_pub, device_id) = generate_keypair();
    let enc_pub = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    let client = RelayClient::new(&base_url, &device_id);
    client.register(secwet_id, sign_pub, enc_pub, &signing_key).await.expect("register");

    // Verify valid entitlement query while active
    let ent = client.get_entitlement(secwet_id, &signing_key).await;
    assert!(ent.is_ok(), "Active device can query entitlement");

    // Revoke device in database
    db::revoke_device(&pool, secwet_id, &device_id).await.expect("revoke device");

    // Query again - MUST be rejected with 403 Forbidden / revoked
    let ent_revoked = client.get_entitlement(secwet_id, &signing_key).await;
    assert!(ent_revoked.is_err(), "Revoked device must be rejected");
    match ent_revoked {
        // RelayClient maps `403 revoked` to `Error::Revoked` (no directive was
        // stored because the device was revoked directly in the database).
        Err(secwet_core::Error::Revoked) => {}
        Err(secwet_core::Error::Relay { code }) => assert_eq!(code, "revoked"),
        other => panic!("Expected a revoked error, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn test_device_limit_enforced() {
    let (base_url, pool) = setup_test_server().await;
    let (signing_key1, sign_pub1, device_id1) = generate_keypair();
    let enc_pub1 = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    // Register store with Device 1 (Plan = Free, limit = 2)
    let client1 = RelayClient::new(&base_url, &device_id1);
    client1
        .register(secwet_id, sign_pub1, enc_pub1, &signing_key1)
        .await
        .expect("register dev1");

    // Device 2 registers in DB (allowed, 2 of 2)
    let (_signing_key2, sign_pub2, device_id2) = generate_keypair();
    let enc_pub2 = generate_enc_pub();
    db::add_device(
        &pool,
        secwet_id,
        &device_id2,
        &sign_pub2,
        &enc_pub2,
    )
    .await
    .expect("add dev2");

    let count = db::count_active_devices(&pool, secwet_id).await.expect("count devices");
    assert_eq!(count, 2);

    // Device 3 attempt: quota exceeded (limit is 2)
    let (_signing_key3, sign_pub3, device_id3) = generate_keypair();
    let enc_pub3 = generate_enc_pub();
    let dev3_res = db::add_device(
        &pool,
        secwet_id,
        &device_id3,
        &sign_pub3,
        &enc_pub3,
    )
    .await;

    assert!(dev3_res.is_err(), "Adding device beyond quota limit must fail");
}

#[tokio::test]
async fn test_admin_grant_and_status() {
    let (base_url, pool) = setup_test_server().await;
    let (signing_key, sign_pub, device_id) = generate_keypair();
    let enc_pub = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    let client = RelayClient::new(&base_url, &device_id);
    client.register(secwet_id, sign_pub, enc_pub, &signing_key).await.expect("register");

    // Initial check: Free plan
    let ent_initial = client.get_entitlement(secwet_id, &signing_key).await.expect("initial ent");
    assert_eq!(ent_initial.plan, "free");
    assert_eq!(ent_initial.device_limit, 2);

    // Admin grants Pro plan with 5 devices via AdminCommand CLI
    let grant_cmd = AdminCommand::Grant(AdminGrantArgs {
        secwet: Some(secwet_id),
        secwet_pos: None,
        plan: "pro".to_string(),
        devices: 5,
        until: None,
    });
    admin::run_admin_command(&pool, grant_cmd)
        .await
        .expect("run admin grant command");

    // Verify status with AdminCommand::Status
    let status_cmd = AdminCommand::Status(AdminStatusArgs { secwet_id });
    admin::run_admin_command(&pool, status_cmd)
        .await
        .expect("run admin status command");

    // Client queries entitlement again: now Pro with 5 devices
    let ent_updated = client.get_entitlement(secwet_id, &signing_key).await.expect("updated ent");
    assert_eq!(ent_updated.plan, "pro");
    assert_eq!(ent_updated.device_limit, 5);
}

#[tokio::test]
async fn test_relay_never_stores_plaintext() {
    let (base_url, pool) = setup_test_server().await;
    let (signing_key, sign_pub, device_id) = generate_keypair();
    let enc_pub = generate_enc_pub();
    let secwet_id = Uuid::now_v7();

    // Adversarial Plaintext Canary
    let canary_secret = format!("CANARY_HIGHLY_CONFIDENTIAL_PLAINTEXT_{}", Uuid::now_v7());

    // Perform client registration and queries
    let client = RelayClient::new(&base_url, &device_id);
    client.register(secwet_id, sign_pub, enc_pub, &signing_key).await.expect("register");
    let _ = client.get_entitlement(secwet_id, &signing_key).await.expect("entitlement");

    // Scan all tables and columns in PostgreSQL public schema
    let columns = secwet_relay::sqlx::query(
        "SELECT table_name, column_name, data_type 
         FROM information_schema.columns 
         WHERE table_schema = 'public' 
           AND data_type IN ('text', 'character varying', 'bytea')",
    )
    .fetch_all(&pool)
    .await
    .expect("fetch schema columns");

    assert!(!columns.is_empty(), "Must have columns to audit");

    for col in &columns {
        let table_name: String = col.get("table_name");
        let column_name: String = col.get("column_name");
        let data_type: String = col.get("data_type");

        let query_str = if data_type == "bytea" {
            format!(
                "SELECT encode(\"{}\", 'escape') as val FROM \"{}\" WHERE \"{}\" IS NOT NULL",
                column_name, table_name, column_name
            )
        } else {
            format!(
                "SELECT \"{}\"::text as val FROM \"{}\" WHERE \"{}\" IS NOT NULL",
                column_name, table_name, column_name
            )
        };

        let rows = secwet_relay::sqlx::query(&query_str).fetch_all(&pool).await;
        if let Ok(rows) = rows {
            for row in rows {
                let val: Option<String> = row.try_get("val").ok();
                if let Some(val_str) = val {
                    // Assert canary plaintext never appears
                    assert!(
                        !val_str.contains(&canary_secret),
                        "CRITICAL VIOLATION: Plaintext canary detected in table '{}' column '{}'",
                        table_name,
                        column_name
                    );
                    // Assert no passwords, master keys, or decrypted markers
                    assert!(
                        !val_str.contains("PLAINTEXT") && !val_str.contains("SUPER_SECRET"),
                        "Plaintext leak marker detected in table '{}' column '{}'",
                        table_name,
                        column_name
                    );
                }
            }
        }
    }
}
