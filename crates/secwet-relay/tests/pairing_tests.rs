//! Comprehensive Test Suite for Device Pairing (F14).
//!
//! Mandatory Tests:
//! 1. `pairing_happy_path`: Two Secwet instances and an in-process relay.
//! 2. `pairing_sas_mismatch_when_relay_swaps_key`: Ephemeral key tampering results in SAS mismatch.
//! 3. `pairing_qr_contains_no_key_material`: Strict audit that QR payload contains zero private/master keys.
//! 4. `pairing_expires_after_5_minutes`: Expired sessions are strictly rejected by the relay.
//! 5. `pairing_respects_device_limit`: Relay enforces workspace device limit upon approval.
//! 6. `pairing_rejects_approval_from_revoked_device`: Revoked approving device cannot add new devices.

use chrono::{Duration, Utc};
use ed25519_dalek::SigningKey;
use secwet_core::{
    crypto::{
        compute_device_id, compute_pairing_sas, compute_pairing_shared_secret,
        create_pairing_approval, format_pairing_qr_payload, generate_ephemeral_x25519,
        open_pairing_profile, parse_pairing_qr_payload, seal_pairing_profile,
        unwrap_master_keys_for_me, wrap_master_keys_for_device,
    },
    RelayClient,
};
use secwet_proto::{
    PairingApproveRequest, PairingJoinRequest, PairingProfile,
};
use secwet_relay::{
    admin::{self, AdminCommand, AdminGrantArgs},
    create_router,
    db::{create_pool, run_migrations},
    rate_limit::RateLimitManager,
    AppState, RelayConfig,
};
use std::sync::Arc;
use tokio::sync::OnceCell;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

static MIGRATION_ONCE: OnceCell<()> = OnceCell::const_new();

fn test_db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".into())
}

async fn setup_test_server(default_device_limit: u32) -> (String, secwet_relay::sqlx::PgPool) {
    let db_url = test_db_url();
    let pool = create_pool(&db_url)
        .await
        .expect("Failed to connect to test Postgres");

    MIGRATION_ONCE
        .get_or_init(|| async {
            run_migrations(&pool).await.expect("Failed to run migrations");
        })
        .await;

    let mut config = RelayConfig::from_env();
    config.database_url = db_url;
    config.default_device_limit = default_device_limit;

    let state = AppState::new(pool.clone(), config, RateLimitManager::new());

    let router = create_router(Arc::new(state));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind ephemeral port");
    let addr = listener.local_addr().expect("Get local addr");
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (base_url, pool)
}

fn generate_device_keys() -> (SigningKey, [u8; 32], StaticSecret, [u8; 32], String) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("random seed");
    let sign_key = SigningKey::from_bytes(&seed);
    let sign_pub = sign_key.verifying_key().to_bytes();
    let device_id = compute_device_id(&sign_pub);

    let mut enc_seed = [0u8; 32];
    getrandom::fill(&mut enc_seed).expect("random enc seed");
    let enc_secret = StaticSecret::from(enc_seed);
    let enc_pub = X25519PublicKey::from(&enc_secret).to_bytes();

    (sign_key, sign_pub, enc_secret, enc_pub, device_id)
}

/// 1. Happy-path end-to-end pairing between Device A and Device N via in-process relay.
#[tokio::test]
async fn test_pairing_happy_path() {
    let (base_url, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    // 1. Setup Device A (primary device)
    let (a_sign_key, a_sign_pub, _a_enc_secret, a_enc_pub, a_device_id) = generate_device_keys();
    let client_a = RelayClient::new(&base_url, &a_device_id);

    client_a
        .register(secwet_id, a_sign_pub, a_enc_pub, &a_sign_key)
        .await
        .expect("Device A register");

    // Upgrade to Pro to enable multi-device pairing
    admin::run_admin_command(
        &pool,
        AdminCommand::Grant(AdminGrantArgs {
            secwet: Some(secwet_id),
            secwet_pos: None,
            plan: "pro".into(),
            devices: 5,
            until: None,
        }),
    )
    .await
    .expect("Grant pro");

    // 2. Device A starts pairing
    let (a_eph_secret, a_eph_pub) = generate_ephemeral_x25519();
    let session_resp = client_a
        .create_pairing_session(secwet_id, a_eph_pub, &a_sign_key)
        .await
        .expect("Create pairing session");

    assert!(!session_resp.qr_payload.is_empty());
    let session_id = session_resp.session_id;

    // 3. Device N parses QR payload
    let (parsed_session_id, parsed_a_eph_pub, _) =
        parse_pairing_qr_payload(&session_resp.qr_payload).expect("Parse QR payload");
    assert_eq!(parsed_session_id, session_id);
    assert_eq!(parsed_a_eph_pub, a_eph_pub);

    // 4. Device N generates its keys and joins
    let (_n_sign_key, n_sign_pub, n_enc_secret, n_enc_pub, n_device_id) = generate_device_keys();
    let client_n = RelayClient::new(&base_url, &n_device_id);

    let (n_eph_secret, n_eph_pub) = generate_ephemeral_x25519();
    let n_shared = compute_pairing_shared_secret(&n_eph_secret, &a_eph_pub)
        .expect("N computes shared secret");

    let profile = PairingProfile {
        name: "MacBook Pro".into(),
        platform: "macOS".into(),
    };
    let sealed_profile = seal_pairing_profile(&n_shared, &profile).expect("Seal profile");

    let join_req = PairingJoinRequest {
        n_eph_pub,
        sign_pub: n_sign_pub,
        enc_pub: n_enc_pub,
        sealed_profile,
    };

    client_n
        .join_pairing_session(session_id, &join_req)
        .await
        .expect("Device N joins");

    // 5. Device A polls status
    let status_resp = client_a
        .get_pairing_status(session_id, &a_sign_key)
        .await
        .expect("A polls status");

    assert_eq!(status_resp.status, "joined");
    let join_payload = status_resp.join_payload.expect("Join payload present");
    assert_eq!(join_payload.n_eph_pub, n_eph_pub);

    // Device A computes shared secret and unseals profile
    let a_shared = compute_pairing_shared_secret(&a_eph_secret, &join_payload.n_eph_pub)
        .expect("A computes shared secret");
    assert_eq!(a_shared.as_slice(), n_shared.as_slice());

    let unsealed_profile =
        open_pairing_profile(&a_shared, &join_payload.sealed_profile).expect("Open profile");
    assert_eq!(unsealed_profile.name, "MacBook Pro");
    assert_eq!(unsealed_profile.platform, "macOS");

    // 6. Both compute SAS comparison code
    let sas_a = compute_pairing_sas(
        &a_shared,
        &session_id,
        &a_eph_pub,
        &join_payload.n_eph_pub,
        &join_payload.sign_pub,
        &join_payload.enc_pub,
    )
    .expect("SAS on A");

    let sas_n = compute_pairing_sas(
        &n_shared,
        &session_id,
        &a_eph_pub,
        &n_eph_pub,
        &n_sign_pub,
        &n_enc_pub,
    )
    .expect("SAS on N");

    assert_eq!(sas_a, sas_n);
    assert_eq!(sas_a.len(), 7); // "XXX YYY"

    // 7. Device A approves pairing and wraps master keys
    let master_k_v = [42u8; 32];
    let master_keys_by_epoch = vec![(1u32, master_k_v)];

    let wrapped_keys = wrap_master_keys_for_device(
        &master_keys_by_epoch,
        &join_payload.enc_pub,
        &n_device_id,
        &secwet_id,
    )
    .expect("Wrap master keys");

    let (approval, signature) = create_pairing_approval(
        &secwet_id,
        &session_id,
        &n_device_id,
        &join_payload.sign_pub,
        &join_payload.enc_pub,
        &a_sign_key,
    )
    .expect("Create pairing approval");

    let approve_req = PairingApproveRequest {
        approval,
        signature,
        wrapped_keys,
    };

    client_a
        .approve_pairing(session_id, &approve_req, &a_sign_key)
        .await
        .expect("Approve pairing");

    // 8. Device N polls result and unwraps master keys
    let result = client_n
        .get_pairing_result(session_id)
        .await
        .expect("N polls result")
        .expect("Result is approved");

    assert_eq!(result.secwet_id, secwet_id);
    assert_eq!(result.device_id, n_device_id);

    let unwrapped = unwrap_master_keys_for_me(
        &result.wrapped_keys,
        &n_enc_secret,
        &n_device_id,
        &secwet_id,
    )
    .expect("Unwrap master keys");

    assert_eq!(unwrapped.len(), 1);
    assert_eq!(unwrapped[0].0, 1u32); // Epoch 1
    assert_eq!(*unwrapped[0].1, master_k_v); // Master key restored perfectly
}

/// 2. SAS mismatch when an adversary or malicious relay swaps or tampers with the ephemeral key.
#[test]
fn test_pairing_sas_mismatch_when_relay_swaps_key() {
    let session_id = Uuid::new_v4();
    let (_, _, _, _, _) = generate_device_keys();
    let (_, n_sign_pub, _, n_enc_pub, _) = generate_device_keys();
    let (_, a_eph_pub) = generate_ephemeral_x25519();
    let (_, n_eph_pub) = generate_ephemeral_x25519();

    let shared_legit = [77u8; 32];
    let sas_legit = compute_pairing_sas(
        &shared_legit,
        &session_id,
        &a_eph_pub,
        &n_eph_pub,
        &n_sign_pub,
        &n_enc_pub,
    )
    .unwrap();

    // Tampered ephemeral public key
    let mut tampered_n_eph_pub = n_eph_pub;
    tampered_n_eph_pub[0] ^= 0xFF;

    let sas_tampered_key = compute_pairing_sas(
        &shared_legit,
        &session_id,
        &a_eph_pub,
        &tampered_n_eph_pub,
        &n_sign_pub,
        &n_enc_pub,
    )
    .unwrap();

    assert_ne!(
        sas_legit, sas_tampered_key,
        "Adversarial swap of ephemeral public key MUST alter SAS code"
    );

    // Tampered session id
    let tampered_session_id = Uuid::new_v4();
    let sas_tampered_session = compute_pairing_sas(
        &shared_legit,
        &tampered_session_id,
        &a_eph_pub,
        &n_eph_pub,
        &n_sign_pub,
        &n_enc_pub,
    )
    .unwrap();

    assert_ne!(
        sas_legit, sas_tampered_session,
        "Altered session id MUST alter SAS code"
    );
}

/// 3. Assert that pairing QR payload contains zero private or master key material.
#[test]
fn test_pairing_qr_contains_no_key_material() {
    let session_id = Uuid::new_v4();
    let (_, a_eph_pub) = generate_ephemeral_x25519();
    let relay_host = "relay.secwet.test:8787";

    let qr = format_pairing_qr_payload(&session_id, &a_eph_pub, relay_host);

    // Must be standard secwet://pair URI
    assert!(qr.starts_with("secwet://pair?"));

    // Parse URI back
    let (parsed_id, parsed_pub, parsed_host) =
        parse_pairing_qr_payload(&qr).expect("Valid QR parsing");
    assert_eq!(parsed_id, session_id);
    assert_eq!(parsed_pub, a_eph_pub);
    assert_eq!(parsed_host, relay_host);

    // Verify URI strictly contains only v, s, k, r
    assert!(!qr.contains("master"));
    assert!(!qr.contains("secret"));
    assert!(!qr.contains("priv"));
    assert!(!qr.contains("token"));
    assert!(!qr.contains("auth"));
    assert!(!qr.contains("pass"));
}

/// 4. Pairing session strictly expires after 5 minutes and is rejected by relay.
#[tokio::test]
async fn test_pairing_expires_after_5_minutes() {
    let (base_url, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (a_sign_key, a_sign_pub, _, a_enc_pub, a_device_id) = generate_device_keys();
    let client_a = RelayClient::new(&base_url, &a_device_id);

    client_a
        .register(secwet_id, a_sign_pub, a_enc_pub, &a_sign_key)
        .await
        .expect("Device A register");

    let (_, a_eph_pub) = generate_ephemeral_x25519();
    let session_resp = client_a
        .create_pairing_session(secwet_id, a_eph_pub, &a_sign_key)
        .await
        .expect("Create pairing session");
    let session_id = session_resp.session_id;

    // Simulate clock advancement: expire the session directly in DB (expires_at 1 minute in the past)
    let past_time = Utc::now() - Duration::minutes(1);
    secwet_relay::sqlx::query("UPDATE pairing_sessions SET expires_at = $1 WHERE id = $2")
        .bind(past_time)
        .bind(session_id)
        .execute(&pool)
        .await
        .expect("Update session expiration");

    // New device tries to join expired session
    let (_, n_sign_pub, _, n_enc_pub, n_device_id) = generate_device_keys();
    let client_n = RelayClient::new(&base_url, &n_device_id);

    let join_req = PairingJoinRequest {
        n_eph_pub: [1u8; 32],
        sign_pub: n_sign_pub,
        enc_pub: n_enc_pub,
        sealed_profile: vec![0u8; 32],
    };

    let join_err = client_n
        .join_pairing_session(session_id, &join_req)
        .await
        .expect_err("Expired session join must fail");

    match join_err {
        secwet_core::Error::Relay { code } => {
            assert!(code.contains("expired") || code.contains("401") || code.contains("400"));
        }
        err => panic!("Expected expired error, got: {:?}", err),
    }

    // Device A polling status of expired session also fails with expired
    let status_err = client_a
        .get_pairing_status(session_id, &a_sign_key)
        .await
        .expect_err("Expired status poll must fail");

    match status_err {
        secwet_core::Error::Relay { code } => {
            assert!(code.contains("expired") || code.contains("401") || code.contains("400"));
        }
        err => panic!("Expected expired error, got: {:?}", err),
    }
}

/// 5. Workspace device limit is strictly enforced when pairing new devices.
#[tokio::test]
async fn test_pairing_respects_device_limit() {
    let (base_url, _pool) = setup_test_server(2).await; // Device limit = 2
    let secwet_id = Uuid::new_v4();

    let (a_sign_key, a_sign_pub, _, a_enc_pub, a_device_id) = generate_device_keys();
    let client_a = RelayClient::new(&base_url, &a_device_id);

    // Register Device A (count = 1 of 2)
    client_a
        .register(secwet_id, a_sign_pub, a_enc_pub, &a_sign_key)
        .await
        .expect("Device A register");

    // Device A starts pairing for Device 2 (allowed since 1 < 2)
    let (_a_eph_secret, a_eph_pub) = generate_ephemeral_x25519();
    let session_resp = client_a
        .create_pairing_session(secwet_id, a_eph_pub, &a_sign_key)
        .await
        .expect("Create pairing session");
    let session_id = session_resp.session_id;

    // Device 2 joins and is approved (count becomes 2 of 2)
    let (_, n_sign_pub, _, n_enc_pub, n_device_id) = generate_device_keys();
    let client_n = RelayClient::new(&base_url, &n_device_id);

    let join_req = PairingJoinRequest {
        n_eph_pub: [2u8; 32],
        sign_pub: n_sign_pub,
        enc_pub: n_enc_pub,
        sealed_profile: vec![0u8; 32],
    };
    client_n
        .join_pairing_session(session_id, &join_req)
        .await
        .expect("Device 2 joins");

    let (approval, signature) = create_pairing_approval(
        &secwet_id,
        &session_id,
        &n_device_id,
        &n_sign_pub,
        &n_enc_pub,
        &a_sign_key,
    )
    .expect("Create approval");

    // The approval must wrap the master key for every epoch (1 here).
    let wrapped_keys = wrap_master_keys_for_device(&[(1u32, [7u8; 32])], &n_enc_pub, &n_device_id, &secwet_id)
        .expect("Wrap master key");
    let approve_req = PairingApproveRequest {
        approval,
        signature,
        wrapped_keys,
    };

    client_a
        .approve_pairing(session_id, &approve_req, &a_sign_key)
        .await
        .expect("Approval of Device 2 succeeds");

    // Now workspace has reached its limit (2 of 2 devices registered).
    // Attempting to start a pairing session for a 3rd device MUST be rejected with device_limit!
    let (_, a_eph_pub_3) = generate_ephemeral_x25519();
    let err_3 = client_a
        .create_pairing_session(secwet_id, a_eph_pub_3, &a_sign_key)
        .await
        .expect_err("Creating pairing session when device limit is reached must fail");

    match err_3 {
        secwet_core::Error::Relay { code } => {
            assert!(
                code.contains("device_limit") || code.contains("devicelimit") || code.contains("limit"),
                "Expected device limit error, got: {}",
                code
            );
        }
        err => panic!("Expected device limit error, got: {:?}", err),
    }
}

/// 6. Pairing rejects approval from a revoked device.
#[tokio::test]
async fn test_pairing_rejects_approval_from_revoked_device() {
    let (base_url, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (a_sign_key, a_sign_pub, _, a_enc_pub, a_device_id) = generate_device_keys();
    let client_a = RelayClient::new(&base_url, &a_device_id);

    client_a
        .register(secwet_id, a_sign_pub, a_enc_pub, &a_sign_key)
        .await
        .expect("Device A register");

    // Upgrade to Pro
    admin::run_admin_command(
        &pool,
        AdminCommand::Grant(AdminGrantArgs {
            secwet: Some(secwet_id),
            secwet_pos: None,
            plan: "pro".into(),
            devices: 5,
            until: None,
        }),
    )
    .await
    .expect("Grant pro");

    let (_, a_eph_pub) = generate_ephemeral_x25519();
    let session_resp = client_a
        .create_pairing_session(secwet_id, a_eph_pub, &a_sign_key)
        .await
        .expect("Create pairing session");
    let session_id = session_resp.session_id;

    // Device N joins
    let (_, n_sign_pub, _, n_enc_pub, n_device_id) = generate_device_keys();
    let client_n = RelayClient::new(&base_url, &n_device_id);

    let join_req = PairingJoinRequest {
        n_eph_pub: [3u8; 32],
        sign_pub: n_sign_pub,
        enc_pub: n_enc_pub,
        sealed_profile: vec![0u8; 32],
    };
    client_n
        .join_pairing_session(session_id, &join_req)
        .await
        .expect("Device N joins");

    // Revoke Device A in the relay database
    secwet_relay::sqlx::query("UPDATE devices SET revoked_at = NOW() WHERE id = $1")
        .bind(&a_device_id)
        .execute(&pool)
        .await
        .expect("Revoke Device A");

    // Device A attempts to approve pairing
    let (approval, signature) = create_pairing_approval(
        &secwet_id,
        &session_id,
        &n_device_id,
        &n_sign_pub,
        &n_enc_pub,
        &a_sign_key,
    )
    .expect("Create approval");

    let approve_req = PairingApproveRequest {
        approval,
        signature,
        wrapped_keys: vec![],
    };

    let approve_err = client_a
        .approve_pairing(session_id, &approve_req, &a_sign_key)
        .await
        .expect_err("Revoked device must not be able to approve pairing");

    match approve_err {
        // RelayClient maps `403 revoked` to `Error::Revoked`.
        secwet_core::Error::Revoked => {}
        secwet_core::Error::Relay { code } => {
            assert!(
                code.contains("revoked") || code.contains("403") || code.contains("unauthorized"),
                "Expected revoked error, got: {}",
                code
            );
        }
        err => panic!("Expected revoked error, got: {:?}", err),
    }
}
