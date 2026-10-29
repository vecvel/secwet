//! Comprehensive Sync Engine Integration Test Suite for Secwet Relay Server.
//!
//! Validates:
//! 1. `test_sync_unentitled_free_tier_rejected`: Free workspace sync attempts are strictly rejected.
//! 2. `test_sync_push_events_monotonic_gap_rejected`: Relay rejects non-monotonic device sequence numbers.
//! 3. `test_sync_push_events_bad_signature_rejected`: Forged / corrupted event signatures are rejected.
//! 4. `test_sync_push_events_success_and_deduplication`: Valid events are assigned monotonic server sequences and duplicate event_ids are deduplicated.
//! 5. `test_sync_get_events_pagination`: Cursor-based event pulling with `after` and `limit`.
//! 6. `test_sync_ack_and_retention_pruning`: Device acks track min-ack across active devices and retention job purges acked events.
//! 7. `test_sync_cursor_expired_returns_410`: Pulling from an expired cursor returns HTTP 410 CursorExpired.
//! 8. `test_sync_snapshot_upload_and_download`: Encrypted snapshot upload, retrieval, and replacement.
//! 9. `test_sync_websocket_notification_stream`: Real-time WebSocket push notifications on new events.

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signer, SigningKey};
use secwet_core::{
    crypto::compute_device_id,
    RelayClient,
};
use secwet_proto::{
    canonical_request_bytes, EventEnvelope,
    SignedEvent, SnapshotUploadRequest, HEADER_DEVICE, HEADER_NONCE, HEADER_SIGNATURE,
    HEADER_TIME,
};
use secwet_relay::{
    admin::{self, AdminCommand, AdminGrantArgs},
    create_router,
    db::{create_pool, run_migrations, run_retention_for_secwet},
    rate_limit::RateLimitManager,
    AppState, RelayConfig,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::OnceCell;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

static MIGRATION_ONCE: OnceCell<()> = OnceCell::const_new();

fn test_db_url() -> String {
    std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".into())
}

async fn setup_test_server(default_device_limit: u32) -> (String, u16, secwet_relay::sqlx::PgPool) {
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
    let port = addr.port();
    let base_url = format!("http://{}", addr);

    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    (base_url, port, pool)
}

fn generate_device_keys() -> (SigningKey, [u8; 32], [u8; 32], String) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("random seed");
    let sign_key = SigningKey::from_bytes(&seed);
    let sign_pub = sign_key.verifying_key().to_bytes();
    let device_id = compute_device_id(&sign_pub);

    let mut enc_seed = [0u8; 32];
    getrandom::fill(&mut enc_seed).expect("random enc seed");
    let enc_secret = StaticSecret::from(enc_seed);
    let enc_pub = X25519PublicKey::from(&enc_secret).to_bytes();

    (sign_key, sign_pub, enc_pub, device_id)
}

fn create_test_signed_event(
    secwet_id: Uuid,
    device_id: &str,
    device_seq: u64,
    sign_key: &SigningKey,
) -> SignedEvent {
    let mut event_id = [0u8; 16];
    getrandom::fill(&mut event_id).expect("random event_id");
    let mut nonce = [0u8; 24];
    getrandom::fill(&mut nonce).expect("random nonce");

    let envelope = EventEnvelope {
        secwet_id: *secwet_id.as_bytes(),
        event_id,
        device_id: device_id.to_string(),
        device_seq,
        key_epoch: 1,
        nonce,
        ciphertext: vec![42; 64],
        scope: None,
    };

    let envelope_bytes = envelope.signing_bytes().expect("encode envelope");
    let signature = sign_key.sign(&envelope_bytes).to_bytes();

    SignedEvent {
        envelope,
        signature,
    }
}

/// 1. Free workspace sync attempts are strictly rejected with NotEntitled.
#[tokio::test]
async fn test_sync_unentitled_free_tier_rejected() {
    let (base_url, _port, _pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (sign_key, sign_pub, enc_pub, device_id) = generate_device_keys();
    let client = RelayClient::new(&base_url, &device_id);

    // Register (defaults to Free tier)
    client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .expect("Register free workspace");

    let event = create_test_signed_event(secwet_id, &device_id, 1, &sign_key);
    let err = client
        .push_events(secwet_id, vec![event], &sign_key)
        .await
        .unwrap_err();

    match err {
        secwet_core::Error::Relay { code } => {
            assert!(
                code.contains("notentitled") || code.contains("not_entitled"),
                "Expected notentitled error, got: {}",
                code
            );
        }
        other => panic!("Expected Error::Relay, got {:?}", other),
    }
}

/// 2. Relay rejects non-monotonic device sequence numbers (sequence gaps).
#[tokio::test]
async fn test_sync_push_events_monotonic_gap_rejected() {
    let (base_url, _port, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (sign_key, sign_pub, enc_pub, device_id) = generate_device_keys();
    let client = RelayClient::new(&base_url, &device_id);

    client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .expect("Register workspace");

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

    // Device starts at sequence 0. Attempting to push sequence 2 directly must fail.
    let event_gap = create_test_signed_event(secwet_id, &device_id, 2, &sign_key);
    let err = client
        .push_events(secwet_id, vec![event_gap], &sign_key)
        .await
        .unwrap_err();

    match err {
        secwet_core::Error::Relay { code } => {
            assert!(
                code.contains("seqgap") || code.contains("seq_gap"),
                "Expected seqgap error, got: {}",
                code
            );
        }
        other => panic!("Expected Error::Relay, got {:?}", other),
    }
}

/// 3. Forged / corrupted event signatures are strictly rejected.
#[tokio::test]
async fn test_sync_push_events_bad_signature_rejected() {
    let (base_url, _port, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (sign_key, sign_pub, enc_pub, device_id) = generate_device_keys();
    let client = RelayClient::new(&base_url, &device_id);

    client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .expect("Register workspace");

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

    // Create event signed by an unrelated key
    let (wrong_key, _, _, _) = generate_device_keys();
    let bad_event = create_test_signed_event(secwet_id, &device_id, 1, &wrong_key);

    let err = client
        .push_events(secwet_id, vec![bad_event], &sign_key)
        .await
        .unwrap_err();

    match err {
        secwet_core::Error::Relay { code } => {
            assert!(
                code.contains("badsignature") || code.contains("bad_signature"),
                "Expected badsignature error, got: {}",
                code
            );
        }
        other => panic!("Expected Error::Relay, got {:?}", other),
    }
}

/// 4. Valid events are accepted with monotonic server sequences, and duplicates are deduplicated.
#[tokio::test]
async fn test_sync_push_events_success_and_deduplication() {
    let (base_url, _port, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (sign_key, sign_pub, enc_pub, device_id) = generate_device_keys();
    let client = RelayClient::new(&base_url, &device_id);

    client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .expect("Register workspace");

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

    let ev1 = create_test_signed_event(secwet_id, &device_id, 1, &sign_key);
    let ev2 = create_test_signed_event(secwet_id, &device_id, 2, &sign_key);
    let ev3 = create_test_signed_event(secwet_id, &device_id, 3, &sign_key);

    let batch = vec![ev1.clone(), ev2.clone(), ev3.clone()];
    let res = client
        .push_events(secwet_id, batch.clone(), &sign_key)
        .await
        .expect("Push events 1..=3");

    assert_eq!(res.accepted, 3);
    let latest_server_seq = res.latest_server_seq;
    assert!(latest_server_seq >= 3);

    // Re-push identical events (retry/redelivery)
    let res_dedup = client
        .push_events(secwet_id, batch, &sign_key)
        .await
        .expect("Push duplicate events");

    assert_eq!(res_dedup.accepted, 0, "Duplicate events must not be re-accepted");
    assert_eq!(res_dedup.latest_server_seq, latest_server_seq);
}

/// 5. Cursor-based event pulling with `after` and `limit`.
#[tokio::test]
async fn test_sync_get_events_pagination() {
    let (base_url, _port, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (sign_key, sign_pub, enc_pub, device_id) = generate_device_keys();
    let client = RelayClient::new(&base_url, &device_id);

    client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .expect("Register workspace");

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

    // Push 5 events
    let mut events = Vec::new();
    for seq in 1..=5 {
        events.push(create_test_signed_event(secwet_id, &device_id, seq, &sign_key));
    }
    client
        .push_events(secwet_id, events, &sign_key)
        .await
        .expect("Push 5 events");

    // Page 1: after=0, limit=2
    let page1 = client
        .get_events(secwet_id, 0, 2, &sign_key)
        .await
        .expect("Get page 1");
    assert_eq!(page1.events.len(), 2);
    assert!(page1.has_more);
    let seq1 = page1.events[0].server_seq;
    let seq2 = page1.events[1].server_seq;
    assert!(seq1 < seq2);

    // Page 2: after=seq2, limit=2
    let page2 = client
        .get_events(secwet_id, seq2, 2, &sign_key)
        .await
        .expect("Get page 2");
    assert_eq!(page2.events.len(), 2);
    assert!(page2.has_more);
    let seq3 = page2.events[0].server_seq;
    let seq4 = page2.events[1].server_seq;
    assert!(seq2 < seq3);
    assert!(seq3 < seq4);

    // Page 3: after=seq4, limit=2
    let page3 = client
        .get_events(secwet_id, seq4, 2, &sign_key)
        .await
        .expect("Get page 3");
    assert_eq!(page3.events.len(), 1);
    assert!(!page3.has_more);
    let seq5 = page3.events[0].server_seq;
    assert!(seq4 < seq5);

    // Verify all 5 events were retrieved in exact sequence
    let all_seqs = [seq1, seq2, seq3, seq4, seq5];
    assert_eq!(all_seqs.len(), 5);
}

/// 6. Device acks track min-ack across active devices and retention job purges acked events.
#[tokio::test]
async fn test_sync_ack_and_retention_pruning() {
    let (base_url, _port, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    // Primary Device A
    let (a_sign_key, a_sign_pub, a_enc_pub, a_device_id) = generate_device_keys();
    let client_a = RelayClient::new(&base_url, &a_device_id);
    client_a
        .register(secwet_id, a_sign_pub, a_enc_pub, &a_sign_key)
        .await
        .expect("Register Device A");

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

    // Add Device B to workspace
    let (b_sign_key, b_sign_pub, b_enc_pub, b_device_id) = generate_device_keys();
    secwet_relay::db::add_device(&pool, secwet_id, &b_device_id, &b_sign_pub, &b_enc_pub)
        .await
        .expect("Add Device B");
    let client_b = RelayClient::new(&base_url, &b_device_id);

    // Device A pushes 4 events
    let mut events = Vec::new();
    for seq in 1..=4 {
        events.push(create_test_signed_event(secwet_id, &a_device_id, seq, &a_sign_key));
    }
    let push_res = client_a
        .push_events(secwet_id, events, &a_sign_key)
        .await
        .expect("Push 4 events");

    // server_seq is a global BIGSERIAL shared with concurrently running tests,
    // so this workspace's sequence numbers need not be contiguous: read them back.
    let pushed = client_a
        .get_events(secwet_id, 0, 10, &a_sign_key)
        .await
        .expect("Read back pushed events");
    let seqs: Vec<u64> = pushed.events.iter().map(|e| e.server_seq).collect();
    assert_eq!(seqs.len(), 4);
    let seq_4 = push_res.latest_server_seq;
    assert_eq!(seqs[3], seq_4);
    let seq_2 = seqs[1];

    // Device A acks up to seq_4
    client_a
        .ack_events(secwet_id, seq_4, &a_sign_key)
        .await
        .expect("Device A acks seq_4");

    // Device B acks up to seq_2
    client_b
        .ack_events(secwet_id, seq_2, &b_sign_key)
        .await
        .expect("Device B acks seq_2");

    // Run retention job: min_ack across active devices is seq_2
    let purged = run_retention_for_secwet(&pool, secwet_id, 30).await.expect("Retention job");
    assert_eq!(purged, 2, "Events 1 and 2 must be purged since both devices acked >= seq_2");

    // Verify events 3 and 4 remain
    let remaining = client_a
        .get_events(secwet_id, seq_2, 10, &a_sign_key)
        .await
        .expect("Get remaining events");
    assert_eq!(remaining.events.len(), 2);
    assert_eq!(remaining.events[0].server_seq, seqs[2]);
    assert_eq!(remaining.events[1].server_seq, seq_4);

    // Device B catches up and acks up to seq_4
    client_b
        .ack_events(secwet_id, seq_4, &b_sign_key)
        .await
        .expect("Device B acks seq_4");

    // Run retention job again: min_ack is seq_4
    let purged_more = run_retention_for_secwet(&pool, secwet_id, 30).await.expect("Retention job 2");
    assert_eq!(purged_more, 2, "Events 3 and 4 must now be purged");

    let count: i64 = secwet_relay::sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE secwet_id = $1")
        .bind(secwet_id)
        .fetch_one(&pool)
        .await
        .expect("Count events");
    assert_eq!(count, 0);
}

/// 7. Pulling from an expired cursor returns HTTP 410 CursorExpired.
#[tokio::test]
async fn test_sync_cursor_expired_returns_410() {
    let (base_url, _port, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (sign_key, sign_pub, enc_pub, device_id) = generate_device_keys();
    let client = RelayClient::new(&base_url, &device_id);

    client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .expect("Register workspace");

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

    // Push 3 events
    let mut events = Vec::new();
    for seq in 1..=3 {
        events.push(create_test_signed_event(secwet_id, &device_id, seq, &sign_key));
    }
    let push_res = client
        .push_events(secwet_id, events, &sign_key)
        .await
        .expect("Push 3 events");

    // server_seq is a global BIGSERIAL shared with concurrently running tests,
    // so this workspace's sequence numbers need not be contiguous: read them back.
    let pushed = client
        .get_events(secwet_id, 0, 10, &sign_key)
        .await
        .expect("Read back pushed events");
    let seqs: Vec<u64> = pushed.events.iter().map(|e| e.server_seq).collect();
    assert_eq!(seqs.len(), 3);
    let seq_3 = push_res.latest_server_seq;
    assert_eq!(seqs[2], seq_3);
    let seq_2 = seqs[1];

    // Upload snapshot at seq_2
    let snap_req = SnapshotUploadRequest {
        server_seq: seq_2,
        key_epoch: 1,
        nonce: [8u8; 24],
        ciphertext: vec![1, 2, 3],
    };
    client
        .upload_snapshot(secwet_id, &snap_req, &sign_key)
        .await
        .expect("Upload snapshot at seq_2");

    // Ack up to seq_2 and run retention job
    client.ack_events(secwet_id, seq_2, &sign_key).await.expect("Ack seq_2");
    let purged = run_retention_for_secwet(&pool, secwet_id, 30).await.expect("Retention job");
    assert_eq!(purged, 2, "Events up to seq_2 should be purged");

    // Minimum retained server_seq is now seq_3.
    // Querying after=0 is expired (0 < snap_seq and 0 < seq_3 - 1).
    let err = client
        .get_events(secwet_id, 0, 10, &sign_key)
        .await
        .unwrap_err();

    match err {
        secwet_core::Error::Relay { code } => {
            assert!(
                code.contains("cursor_expired") || code.contains("cursorexpired"),
                "Expected cursor_expired, got: {}",
                code
            );
        }
        other => panic!("Expected Error::Relay cursor_expired, got {:?}", other),
    }

    // Querying after=seq_2 (which is immediately before seq_3) succeeds!
    let valid = client
        .get_events(secwet_id, seq_2, 10, &sign_key)
        .await
        .expect("Get events after=seq_2");
    assert_eq!(valid.events.len(), 1);
    assert_eq!(valid.events[0].server_seq, seq_3);
}

/// 8. Encrypted snapshot upload, retrieval, and replacement.
#[tokio::test]
async fn test_sync_snapshot_upload_and_download() {
    let (base_url, _port, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (sign_key, sign_pub, enc_pub, device_id) = generate_device_keys();
    let client = RelayClient::new(&base_url, &device_id);

    client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .expect("Register workspace");

    // Relay-stored snapshots are Pro only.
    secwet_relay::db::grant_entitlement(&pool, secwet_id, "pro", 5, None)
        .await
        .expect("Grant pro");

    // Initially no snapshot exists -> 404 None
    let none_snap = client
        .get_snapshot(secwet_id, &sign_key)
        .await
        .expect("Get initial snapshot");
    assert!(none_snap.is_none());

    let nonce1 = [7u8; 24];
    let ciphertext1 = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let req1 = SnapshotUploadRequest {
        server_seq: 10,
        key_epoch: 1,
        nonce: nonce1,
        ciphertext: ciphertext1.clone(),
    };

    client
        .upload_snapshot(secwet_id, &req1, &sign_key)
        .await
        .expect("Upload snapshot 1");

    let snap1 = client
        .get_snapshot(secwet_id, &sign_key)
        .await
        .expect("Get snapshot 1")
        .expect("Snapshot exists");

    assert_eq!(snap1.server_seq, 10);
    assert_eq!(snap1.key_epoch, 1);
    assert_eq!(snap1.nonce, nonce1);
    assert_eq!(snap1.ciphertext, ciphertext1);

    // Overwrite snapshot with newer epoch & sequence
    let nonce2 = [9u8; 24];
    let ciphertext2 = vec![9, 8, 7, 6, 5, 4, 3, 2, 1];
    let req2 = SnapshotUploadRequest {
        server_seq: 25,
        key_epoch: 2,
        nonce: nonce2,
        ciphertext: ciphertext2.clone(),
    };

    client
        .upload_snapshot(secwet_id, &req2, &sign_key)
        .await
        .expect("Upload snapshot 2");

    let snap2 = client
        .get_snapshot(secwet_id, &sign_key)
        .await
        .expect("Get snapshot 2")
        .expect("Snapshot exists");

    assert_eq!(snap2.server_seq, 25);
    assert_eq!(snap2.key_epoch, 2);
    assert_eq!(snap2.nonce, nonce2);
    assert_eq!(snap2.ciphertext, ciphertext2);
}

/// 9. Real-time WebSocket push notifications on new events.
#[tokio::test]
async fn test_sync_websocket_notification_stream() {
    let (base_url, port, pool) = setup_test_server(5).await;
    let secwet_id = Uuid::new_v4();

    let (sign_key, sign_pub, enc_pub, device_id) = generate_device_keys();
    let client = RelayClient::new(&base_url, &device_id);

    client
        .register(secwet_id, sign_pub, enc_pub, &sign_key)
        .await
        .expect("Register workspace");

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

    // Establish WebSocket connection via TCP to test the streaming endpoint
    let path = format!("/v1/secwets/{}/stream", secwet_id);
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;

    let mut nonce_bytes = [0u8; 16];
    getrandom::fill(&mut nonce_bytes).expect("nonce");
    let nonce_b64 = BASE64URL_NOPAD.encode(&nonce_bytes);

    let empty_sha256: [u8; 32] = Sha256::digest(b"").into();
    let canonical = canonical_request_bytes("GET", &path, now_ms, &nonce_bytes, &empty_sha256)
        .expect("canonical bytes");
    let sig = sign_key.sign(&canonical);
    let sig_b64 = BASE64URL_NOPAD.encode(&sig.to_bytes());

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("Connect TCP");

    let handshake = format!(
        "GET {} HTTP/1.1\r\n\
        Host: 127.0.0.1:{}\r\n\
        Upgrade: websocket\r\n\
        Connection: Upgrade\r\n\
        Content-Length: 0\r\n\
        Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
        Sec-WebSocket-Version: 13\r\n\
        {}: {}\r\n\
        {}: {}\r\n\
        {}: {}\r\n\
        {}: {}\r\n\
        \r\n",
        path, port,
        HEADER_DEVICE, device_id,
        HEADER_TIME, now_ms,
        HEADER_NONCE, nonce_b64,
        HEADER_SIGNATURE, sig_b64,
    );

    stream.write_all(handshake.as_bytes()).await.expect("Send handshake");

    let mut response_buf = [0u8; 1024];
    let n = stream.read(&mut response_buf).await.expect("Read handshake response");
    let response_str = String::from_utf8_lossy(&response_buf[..n]);
    assert!(
        response_str.contains("101 Switching Protocols"),
        "Expected 101 Switching Protocols, got:\n{}",
        response_str
    );

    // Push an event from another client or background task
    let event = create_test_signed_event(secwet_id, &device_id, 1, &sign_key);
    tokio::spawn({
        let client = client.clone();
        async move {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            client.push_events(secwet_id, vec![event], &sign_key).await.expect("Push event");
        }
    });

    // Read the WebSocket text frame notification
    let mut ws_frame_buf = [0u8; 1024];
    let n = stream.read(&mut ws_frame_buf).await.expect("Read WS frame");
    assert!(n > 2, "WS frame must contain at least header and payload");
    // Opcode 0x81 = text frame
    assert_eq!(ws_frame_buf[0], 0x81, "Must be unmasked text frame");

    let payload = String::from_utf8_lossy(&ws_frame_buf[2..n]);
    assert!(
        payload.contains(r#""type":"events""#),
        "Payload must contain event notification: {}",
        payload
    );
    assert!(
        payload.contains(r#""server_seq":"#),
        "Payload must contain server_seq: {}",
        payload
    );
}
