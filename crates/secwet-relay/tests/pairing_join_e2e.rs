//! The new device's side of pairing end to end: a real owner store
//! approves, a fresh store is created from the scanned link with
//! `secwet_core::pairing_join::PairingJoin`, and the data arrives by sync.
//! Real relay router over HTTP, Postgres, Ed25519, HPKE and SQLite.

use secwet_core::crypto::{
    compute_device_id, compute_pairing_sas, compute_pairing_shared_secret, create_pairing_approval,
    generate_ephemeral_x25519, open_pairing_profile, wrap_master_keys_for_device,
};
use secwet_core::keys::KeyStore;
use secwet_core::pairing_join::PairingJoin;
use secwet_core::{MemoryStore, RelayClient, SecretDraft, SecretKind, Secwet};
use secwet_proto::PairingApproveRequest;
use secwet_relay::{
    create_router,
    db::{self, create_pool, run_migrations},
    rate_limit::RateLimitManager,
    sqlx::PgPool,
    AppState, RelayConfig,
};
use std::{net::SocketAddr, sync::Arc};
use tempfile::TempDir;
use tokio::sync::OnceCell;

static MIGRATION_ONCE: OnceCell<()> = OnceCell::const_new();

async fn start_relay() -> (String, PgPool) {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".into());
    let pool = create_pool(&db_url).await.expect("connect to test Postgres");
    MIGRATION_ONCE
        .get_or_init(|| async { run_migrations(&pool).await.expect("migrations") })
        .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let mut config = RelayConfig::from_env();
    config.database_url = db_url;
    config.default_device_limit = 5;
    // The QR carries the relay address; a bare host must resolve to http here.
    config.public_url = addr.to_string();
    let router = create_router(Arc::new(AppState::new(pool.clone(), config, RateLimitManager::new())));
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    (format!("http://{addr}"), pool)
}

fn secret_names(s: &Secwet) -> Vec<String> {
    let mut out = Vec::new();
    for l in s.list_labels().unwrap() {
        for i in s.list_items(l.id).unwrap() {
            out.extend(s.list_secrets(i.id, None).unwrap().into_iter().map(|x| x.name));
        }
    }
    out.sort();
    out
}

#[tokio::test]
async fn new_device_joins_by_pairing_link_and_receives_data() {
    let (relay, pool) = start_relay().await;

    // Owner with data, on key epoch 2 so the join must adopt more than one epoch.
    let a_dir = TempDir::new().unwrap();
    let a_ks = MemoryStore::new();
    let mut a = Secwet::create(a_dir.path(), "Owner Mac", &a_ks).unwrap();
    a.set_relay_url(&relay).unwrap();
    let ca = RelayClient::new(&relay, a.device_id().to_string());
    a.relay_register(&ca).await.expect("register");
    db::grant_entitlement(&pool, a.secwet_id(), "pro", 5, None).await.unwrap();
    a.set_plan("pro").unwrap();
    a.rotate_master_key(&ca, &a_ks).await.expect("rotate");
    let space = a.ensure_default_personal_space().unwrap().id;
    let label = a.create_label_in_space("Ops", None, Some(space)).unwrap();
    let item = a.create_item(label.id, "api", None).unwrap();
    a.create_secret(SecretDraft::new(item.id, None, "DATABASE_URL", SecretKind::Password, "postgres://x", None))
        .unwrap();
    a.sync_round(&ca, &a_ks).await.expect("owner sync");

    // Owner shows the code.
    let (a_eph_secret, a_eph_pub) = generate_ephemeral_x25519();
    let session = ca
        .create_pairing_session(a.secwet_id(), a_eph_pub, a.device_sign_key())
        .await
        .expect("pairing session");

    // New phone scans it.
    let join = PairingJoin::start(&session.qr_payload, "Pixel 9", "Android").await.expect("join");
    let poller = join.poller();
    assert!(poller.poll().await.unwrap().is_none(), "nothing before approval");

    // Owner sees the phone and the same code.
    let status = ca.get_pairing_status(session.session_id, a.device_sign_key()).await.unwrap();
    let peer = status.join_payload.expect("joined");
    let shared = compute_pairing_shared_secret(&a_eph_secret, &peer.n_eph_pub).unwrap();
    let profile = open_pairing_profile(&shared, &peer.sealed_profile).unwrap();
    assert_eq!((profile.name.as_str(), profile.platform.as_str()), ("Pixel 9", "Android"));
    let code = compute_pairing_sas(&shared, &session.session_id, &a_eph_pub, &peer.n_eph_pub, &peer.sign_pub, &peer.enc_pub)
        .unwrap();
    assert_eq!(code, join.code());

    // Owner approves with every key epoch.
    let device_id = compute_device_id(&peer.sign_pub);
    let mut keys = Vec::new();
    for epoch in 1..=a.key_epoch() {
        let k = secwet_core::collab::load_master_key(&a_ks, &a.secwet_id(), epoch).unwrap().unwrap();
        keys.push((epoch, <[u8; 32]>::try_from(k.as_slice()).unwrap()));
    }
    assert_eq!(keys.len(), 2);
    let wrapped_keys = wrap_master_keys_for_device(&keys, &peer.enc_pub, &device_id, &a.secwet_id()).unwrap();
    let (approval, signature) =
        create_pairing_approval(&a.secwet_id(), &session.session_id, &device_id, &peer.sign_pub, &peer.enc_pub, a.device_sign_key())
            .unwrap();
    ca.approve_pairing(session.session_id, &PairingApproveRequest { approval, signature, wrapped_keys }, a.device_sign_key())
        .await
        .expect("approve");
    a.record_paired_device(&device_id, &profile.name, &profile.platform, &peer.sign_pub, &peer.enc_pub)
        .unwrap();
    a.sync_round(&ca, &a_ks).await.expect("owner sync after approval");

    // The phone creates its store from the approval and pulls the data.
    let result = poller.poll().await.unwrap().expect("approved");
    let n_dir = TempDir::new().unwrap();
    let n_ks = MemoryStore::new();
    let mut n = join.finish(n_dir.path(), &result, &n_ks).expect("finish");
    assert_eq!(n.secwet_id(), a.secwet_id());
    assert_eq!(n.device_id().to_string(), device_id);
    assert_eq!(n.key_epoch(), 2);
    assert!(n_ks.get(&format!("secwet/{}/master-key/2", n.secwet_id())).unwrap().is_some());
    let cn = RelayClient::new(n.relay_url().unwrap(), n.device_id().to_string());
    n.sync_round(&cn, &n_ks).await.expect("phone sync");
    assert_eq!(secret_names(&n), vec!["DATABASE_URL".to_string()]);

    // A second scan of the same code is refused by the relay.
    assert!(PairingJoin::start(&session.qr_payload, "Other", "iOS").await.is_err());
}

#[tokio::test]
async fn invalid_pairing_links_are_rejected_before_any_network_call() {
    for link in ["", "secwet://invite?v=1", "secwet://pair?v=1&s=nope&k=x&r=127.0.0.1:1"] {
        let err = PairingJoin::start(link, "Phone", "iOS").await.unwrap_err();
        assert!(matches!(err, secwet_core::Error::Invalid { .. }), "{link}: {err:?}");
    }
}
