//! End-to-end revocation, key rotation and collaboration flows: real `Secwet`
//! stores (core) talking to the real relay router over HTTP, backed by
//! Postgres. No mocks: real Ed25519, HPKE, XChaCha20-Poly1305, SQLite and
//! keystore code paths.

use secrecy::ExposeSecret;
use secwet_core::collab::RevocationOutcome;
use secwet_core::keys::KeyStore;
use secwet_core::{Error, MemoryStore, RelayClient, SecretDraft, SecretKind, Secwet};
use secwet_proto::{TreeNode, TreeRole};
use secwet_relay::{
    create_router,
    db::{self, create_pool, run_migrations},
    rate_limit::RateLimitManager,
    sqlx::{PgPool, Row},
    AppState, RelayConfig,
};
use std::{net::SocketAddr, sync::Arc};
use tempfile::TempDir;
use tokio::sync::OnceCell;
use uuid::Uuid;

static MIGRATION_ONCE: OnceCell<()> = OnceCell::const_new();

async fn start_relay() -> (String, PgPool) {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".into());
    let pool = create_pool(&db_url).await.expect("connect to test Postgres");
    MIGRATION_ONCE
        .get_or_init(|| async { run_migrations(&pool).await.expect("migrations") })
        .await;
    let mut config = RelayConfig::from_env();
    config.database_url = db_url;
    config.default_device_limit = 5;
    let router = create_router(Arc::new(AppState::new(pool.clone(), config, RateLimitManager::new())));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    });
    (format!("http://{addr}"), pool)
}

struct Node {
    dir: TempDir,
    ks: MemoryStore,
    s: Secwet,
}

impl Node {
    fn client(&self) -> RelayClient {
        RelayClient::new(self.s.relay_url().unwrap(), self.s.device_id().to_string())
    }
    async fn sync(&mut self) -> Result<(usize, usize), Error> {
        let c = self.client();
        self.s.sync_round(&c, &self.ks).await
    }
}

async fn owner(relay: &str, pool: &PgPool) -> Node {
    let dir = TempDir::new().unwrap();
    let ks = MemoryStore::new();
    let mut s = Secwet::create(dir.path(), "Owner Mac", &ks).unwrap();
    s.set_relay_url(relay).unwrap();
    let c = RelayClient::new(relay, s.device_id().to_string());
    s.relay_register(&c).await.expect("register");
    db::grant_entitlement(pool, s.secwet_id(), "pro", 5, None).await.unwrap();
    s.set_plan("pro").unwrap();
    Node { dir, ks, s }
}

/// A second device of the owner, registered on the relay and recorded by
/// the approving device the way an approved pairing does.
async fn second_owner_device(a: &mut Node, relay: &str, pool: &PgPool, name: &str) -> Node {
    let id = a.s.secwet_id();
    let km = a.ks.get(&format!("secwet/{id}/master-key/1")).unwrap().unwrap();
    let mut k = [0u8; 32];
    k.copy_from_slice(km.as_slice());
    let dir = TempDir::new().unwrap();
    let ks = MemoryStore::new();
    let mut s = Secwet::create_paired(dir.path(), name, id, &k, &ks).unwrap();
    s.set_relay_url(relay).unwrap();
    db::add_device(pool, id, &s.device_id().to_string(), &s.device_sign_pub(), &s.test_enc_pub())
        .await
        .unwrap();
    a.s.record_paired_device(&s.device_id().to_string(), name, "macOS", &s.device_sign_pub(), &s.test_enc_pub())
        .unwrap();
    s.set_plan("pro").unwrap();
    Node { dir, ks, s }
}

fn secret(s: &mut Secwet, item: Uuid, env: Option<Uuid>, name: &str, value: &str) -> Uuid {
    s.create_secret(SecretDraft::new(item, env, name, SecretKind::Password, value, None))
        .unwrap()
        .id
}

fn all_secret_names(s: &Secwet) -> Vec<String> {
    let mut out = Vec::new();
    for l in s.list_labels().unwrap() {
        for i in s.list_items(l.id).unwrap() {
            out.extend(s.list_secrets(i.id, None).unwrap().into_iter().map(|x| x.name));
            for e in s.list_environments(i.id).unwrap() {
                out.extend(s.list_secrets(i.id, Some(e.id)).unwrap().into_iter().map(|x| x.name));
            }
        }
    }
    out.sort();
    out
}

// ============================================================================
// Revocation and key rotation
// ============================================================================

#[tokio::test]
async fn revoked_device_cannot_push_or_pull_and_wipes_itself() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let mut b = second_owner_device(&mut a, &relay, &pool, "Lost laptop").await;
    a.sync().await.unwrap();
    b.sync().await.unwrap();

    let bid = b.s.device_id().to_string();
    let ca = a.client();
    let resp = a.s.device_revoke_remote(&ca, &bid, true).await.unwrap();
    assert!(resp.wipe_requested);
    assert!(a.s.key_status().unwrap().rotation_recommended);

    // A replay (for example after a lost response) is idempotent.
    let replay = a.s.device_revoke_remote(&ca, &bid, true).await;
    assert!(replay.is_ok(), "{replay:?}");

    // B's next contact delivers the signed directive; B crypto-shreds.
    let secwet_id = b.s.secwet_id();
    let res = b.sync().await;
    assert!(matches!(res, Err(Error::RevocationNotice(_))), "{res:?}");
    assert!(b.ks.get(&format!("secwet/{secwet_id}/device-sign")).unwrap().is_none());
    assert!(b.ks.get(&format!("secwet/{secwet_id}/master-key/1")).unwrap().is_none());
    assert!(!b.dir.path().join("secwet").join(secwet_id.to_string()).exists());

    // Rotation excludes B; A keeps working on epoch 2.
    let report = a.s.rotate_master_key(&ca, &a.ks).await.unwrap();
    assert_eq!((report.previous_epoch, report.epoch, report.recipients), (1, 2, 1));
    assert!(!a.s.key_status().unwrap().rotation_recommended);
    let rows = sqlx_count(&pool, "SELECT COUNT(*) FROM wrapped_keys WHERE device_id = $1 AND epoch = 2", &bid).await;
    assert_eq!(rows, 0, "revoked device never receives epoch 2");
}

async fn sqlx_count(pool: &PgPool, sql: &str, arg: &str) -> i64 {
    secwet_relay::sqlx::query(sql)
        .bind(arg)
        .fetch_one(pool)
        .await
        .unwrap()
        .try_get::<i64, _>(0)
        .unwrap()
}

#[tokio::test]
async fn revoke_sync_only_keeps_read_only_archive() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Ops", None, Some(space)).unwrap();
    let item = a.s.create_item(label.id, "svc", None).unwrap();
    secret(&mut a.s, item.id, None, "API_KEY", "archived-value");
    let mut b = second_owner_device(&mut a, &relay, &pool, "Old laptop").await;
    a.sync().await.unwrap();
    b.sync().await.unwrap();
    assert!(all_secret_names(&b.s).contains(&"API_KEY".to_string()));

    let ca = a.client();
    a.s.device_revoke_remote(&ca, &b.s.device_id().to_string(), false).await.unwrap();
    let res = b.sync().await;
    assert!(matches!(res, Err(Error::RevocationNotice(_))));
    assert!(b.s.unlinked_at().unwrap().is_some());
    // Read-only archive: reads work, writes and sync do not.
    let id = b.s.list_secrets(item.id, None).unwrap()[0].id;
    assert_eq!(b.s.reveal_secret(id).unwrap().expose_secret(), "archived-value");
    assert!(matches!(b.s.delete_secret(id), Err(Error::Revoked)));
    assert!(matches!(b.sync().await, Err(Error::Revoked)));
}

#[tokio::test]
async fn concurrent_rotation_conflict() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let mut c = second_owner_device(&mut a, &relay, &pool, "Desktop").await;
    a.sync().await.unwrap();
    c.sync().await.unwrap();

    let (ca, cc) = (a.client(), c.client());
    let (ra, rc) = tokio::join!(
        a.s.rotate_master_key(&ca, &a.ks),
        c.s.rotate_master_key(&cc, &c.ks)
    );
    let (ra, rc) = (ra.unwrap(), rc.unwrap());
    assert_eq!(ra.epoch, 2);
    assert_eq!(rc.epoch, 2);
    assert!(ra.adopted_from_conflict ^ rc.adopted_from_conflict, "exactly one rotation wins");

    // Both devices hold the same epoch 2: a write on one reads on the other.
    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Shared", None, Some(space)).unwrap();
    let item = a.s.create_item(label.id, "app", None).unwrap();
    secret(&mut a.s, item.id, None, "AFTER_ROTATION", "v2");
    a.sync().await.unwrap();
    c.sync().await.unwrap();
    assert!(all_secret_names(&c.s).contains(&"AFTER_ROTATION".to_string()));
}

#[tokio::test]
async fn offline_device_catches_up_on_new_epoch() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let mut c = second_owner_device(&mut a, &relay, &pool, "Travel laptop").await;
    a.sync().await.unwrap();
    // C is offline while A rotates and writes.
    let ca = a.client();
    a.s.rotate_master_key(&ca, &a.ks).await.unwrap();
    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Infra", None, Some(space)).unwrap();
    let item = a.s.create_item(label.id, "db", None).unwrap();
    secret(&mut a.s, item.id, None, "WRITTEN_ON_EPOCH_2", "x");
    a.sync().await.unwrap();

    c.sync().await.unwrap();
    assert_eq!(c.s.key_epoch(), 2, "C adopted epoch 2 on reconnect");
    assert!(all_secret_names(&c.s).contains(&"WRITTEN_ON_EPOCH_2".to_string()));
}

// ============================================================================
// Collaboration
// ============================================================================

struct Tree {
    space: Uuid,
    item: Uuid,
    dev: Uuid,
    prod: Uuid,
}

fn build_tree(a: &mut Node) -> Tree {
    let space = a.s.create_space("Client Alpha", None).unwrap().id;
    let group = a.s.create_label_in_space("Backend", None, Some(space)).unwrap().id;
    let billing = a.s.create_label_in_space("Billing", None, Some(space)).unwrap().id;
    let item = a.s.create_item(group, "auth-service", None).unwrap().id;
    let dev = a.s.add_environment(item, "Development").unwrap().id;
    let prod = a.s.add_environment(item, "Production").unwrap().id;
    let pay = a.s.create_item(billing, "payments", None).unwrap().id;
    secret(&mut a.s, item, Some(dev), "DEV_DB", "e2e-dev-value");
    secret(&mut a.s, item, Some(prod), "PROD_DB", "e2e-prod-value-zk");
    secret(&mut a.s, item, None, "GENERAL_FLAG", "e2e-general-value");
    secret(&mut a.s, pay, None, "STRIPE_KEY", "e2e-stripe-value-zk");
    Tree { space, item, dev, prod }
}

async fn join(relay: &str, link: &str, email: &str) -> Node {
    let dir = TempDir::new().unwrap();
    let ks = MemoryStore::new();
    let s = Secwet::accept_invitation(dir.path(), link, email, "Contractor laptop", &ks)
        .await
        .expect("accept invitation");
    assert_eq!(s.relay_url().unwrap(), relay);
    Node { dir, ks, s }
}

#[tokio::test]
async fn invited_contractor_gets_only_development() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let t = build_tree(&mut a);
    a.sync().await.unwrap();

    let ca = a.client();
    let inv = a
        .s
        .invite_member(&ca, &a.ks, "Contractor@Example.com", &[(TreeNode::Environment(t.dev), TreeRole::Editor)])
        .await
        .unwrap();
    assert!(inv.link.starts_with("secwet://invite?v=1&"));

    // Wrong email is refused; the right one is accepted once.
    let bad_dir = TempDir::new().unwrap();
    let bad = Secwet::accept_invitation(bad_dir.path(), &inv.link, "someone@else.com", "x", &MemoryStore::new()).await;
    assert!(matches!(bad, Err(Error::Relay { ref code }) if code == "invalid_invitation"), "{bad:?}");
    let mut m = join(&relay, &inv.link, "contractor@example.com").await;
    let again_dir = TempDir::new().unwrap();
    let again = Secwet::accept_invitation(again_dir.path(), &inv.link, "contractor@example.com", "x", &MemoryStore::new()).await;
    assert!(again.is_err(), "an invite link works once");

    // Admin's sync verifies the key binding and delivers keys; member syncs.
    a.sync().await.unwrap();
    m.sync().await.unwrap();
    assert_eq!(all_secret_names(&m.s), vec!["DEV_DB".to_string()]);

    // The member writes in Development; the admin receives it.
    secret(&mut m.s, t.item, Some(t.dev), "CONTRACTOR_TOKEN", "c-value");
    m.sync().await.unwrap();
    a.sync().await.unwrap();
    assert!(all_secret_names(&a.s).contains(&"CONTRACTOR_TOKEN".to_string()));

    // Production and General are cryptographically out of reach.
    assert!(matches!(
        m.s.create_secret(SecretDraft::new(t.item, Some(t.prod), "X", SecretKind::Password, "v", None)),
        Err(Error::Forbidden) | Err(Error::NotFound)
    ));
    assert!(matches!(m.s.delete_secret(m.s.list_secrets(t.item, Some(t.dev)).unwrap()[0].id), Err(Error::Forbidden)));

    let members = a.s.members_list(&ca).await.unwrap();
    assert_eq!(members.len(), 1);
    assert_eq!(members[0].email.as_deref(), Some("contractor@example.com"));
    assert_eq!(members[0].status, "active");
    let _ = (&t.space, &m.dir);
}

#[tokio::test]
async fn member_removal_rotates_branch_and_blocks_new_data() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let t = build_tree(&mut a);
    a.sync().await.unwrap();
    let ca = a.client();
    let inv = a
        .s
        .invite_member(&ca, &a.ks, "dev@example.com", &[(TreeNode::Space(t.space), TreeRole::Viewer)])
        .await
        .unwrap();
    let mut m = join(&relay, &inv.link, "dev@example.com").await;
    a.sync().await.unwrap();
    m.sync().await.unwrap();
    assert!(all_secret_names(&m.s).contains(&"PROD_DB".to_string()));
    let mdev = m.s.device_id().to_string();

    a.s.remove_member(&ca, &a.ks, inv.member_id, false).await.unwrap();
    secret(&mut a.s, t.item, Some(t.prod), "AFTER_REMOVAL", "e2e-after-removal");
    a.sync().await.unwrap();

    // The removed member is unlinked and never received the new epoch.
    let res = m.sync().await;
    assert!(matches!(res, Err(Error::RevocationNotice(_))), "{res:?}");
    assert!(m.s.unlinked_at().unwrap().is_some());
    assert!(!all_secret_names(&m.s).contains(&"AFTER_REMOVAL".to_string()));
    let newest_for_member = sqlx_count(
        &pool,
        "SELECT COALESCE(MAX(epoch), 0)::BIGINT FROM branch_keys WHERE device_id = $1",
        &mdev,
    )
    .await;
    let newest = sqlx_count(
        &pool,
        "SELECT MAX(current_epoch)::BIGINT FROM branch_scopes WHERE space_id::text = $1",
        &t.space.to_string(),
    )
    .await;
    assert!(newest > newest_for_member, "branch rotated past the removed member's keys");
}

#[tokio::test]
async fn viewer_writes_are_rejected_by_relay_and_owner() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let t = build_tree(&mut a);
    a.sync().await.unwrap();
    let ca = a.client();
    let inv = a
        .s
        .invite_member(&ca, &a.ks, "viewer@example.com", &[(TreeNode::Item(t.item), TreeRole::Viewer)])
        .await
        .unwrap();
    let mut m = join(&relay, &inv.link, "viewer@example.com").await;
    a.sync().await.unwrap();
    m.sync().await.unwrap();
    let names = all_secret_names(&m.s);
    assert!(names.contains(&"PROD_DB".to_string()) && names.contains(&"GENERAL_FLAG".to_string()));
    assert!(!names.contains(&"STRIPE_KEY".to_string()));
    assert!(matches!(
        m.s.create_secret(SecretDraft::new(t.item, Some(t.dev), "NOPE", SecretKind::Password, "v", None)),
        Err(Error::Forbidden)
    ));
}

#[tokio::test]
async fn relay_never_stores_plaintext_across_m7_m8_flows() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let t = build_tree(&mut a);
    a.sync().await.unwrap();
    let ca = a.client();
    let inv = a
        .s
        .invite_member(&ca, &a.ks, "zk-audit@example.com", &[(TreeNode::Environment(t.dev), TreeRole::Editor)])
        .await
        .unwrap();
    let mut m = join(&relay, &inv.link, "zk-audit@example.com").await;
    a.sync().await.unwrap();
    m.sync().await.unwrap();
    a.s.rotate_master_key(&ca, &a.ks).await.unwrap();
    a.sync().await.unwrap();

    let markers: [&[u8]; 8] = [
        b"e2e-dev-value",
        b"e2e-prod-value-zk",
        b"e2e-stripe-value-zk",
        b"zk-audit@example.com",
        b"Client Alpha",
        b"auth-service",
        b"Production",
        b"STRIPE_KEY",
    ];
    let tables: Vec<String> = secwet_relay::sqlx::query(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public'",
    )
    .fetch_all(&pool)
    .await
    .unwrap()
    .iter()
    .map(|r| r.try_get::<String, _>(0).unwrap())
    .collect();
    for table in tables {
        let rows = secwet_relay::sqlx::query(&format!("SELECT row_to_json(t)::text FROM {table} t"))
            .fetch_all(&pool)
            .await
            .unwrap();
        for r in rows {
            let json: String = r.try_get(0).unwrap();
            // Byte columns appear hex-encoded in row_to_json; check both forms.
            for m in &markers {
                let hex: String = m.iter().map(|b| format!("{b:02x}")).collect();
                assert!(!json.as_bytes().windows(m.len()).any(|w| w == *m), "plaintext in {table}");
                assert!(!json.contains(&hex), "plaintext bytes in {table}");
            }
        }
    }
    let _ = (m.s.secwet_id(), RevocationOutcome::Archived);
}

// ============================================================================
// Regression: a malicious relay operator (database access, no device keys)
// ============================================================================

struct Ghost {
    sk: ed25519_dalek::SigningKey,
    sign_pub: [u8; 32],
    enc_pub: [u8; 32],
    id: String,
}

fn ghost() -> Ghost {
    let sk = ed25519_dalek::SigningKey::generate(&mut rand_core_os());
    let sign_pub = sk.verifying_key().to_bytes();
    let enc = x25519_dalek::StaticSecret::random_from_rng(&mut rand_core_os());
    let enc_pub = x25519_dalek::PublicKey::from(&enc).to_bytes();
    Ghost { id: secwet_core::crypto::compute_device_id(&sign_pub), sk, sign_pub, enc_pub }
}

fn rand_core_os() -> secwet_core::crypto::OsRng {
    secwet_core::crypto::OsRng
}

#[tokio::test]
async fn relay_injected_device_cannot_trigger_a_wipe() {
    use ed25519_dalek::Signer;
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let mut b = second_owner_device(&mut a, &relay, &pool, "Laptop").await;
    a.sync().await.unwrap();
    b.sync().await.unwrap();

    let g = ghost();
    let id = b.s.secwet_id();
    db::add_device(&pool, id, &g.id, &g.sign_pub, &g.enc_pub).await.unwrap();
    b.sync().await.unwrap(); // B now lists the ghost, but only as relay-known.

    let directive = secwet_proto::RevocationDirective {
        secwet_id: id,
        target_device_id: b.s.device_id().to_string(),
        issuer_device_id: g.id.clone(),
        wipe: true,
        issued_at: chrono::Utc::now().timestamp_millis(),
    };
    let signature = g.sk.sign(&directive.signing_bytes().unwrap()).to_bytes();
    let bytes = postcard::to_stdvec(&secwet_proto::SignedRevocation { directive, signature }).unwrap();
    secwet_relay::collab_db::revoke_device_with_directive(&pool, id, &b.s.device_id().to_string(), true, &bytes)
        .await
        .unwrap();

    let res = b.sync().await;
    assert!(res.is_err(), "B is revoked on the relay");
    assert!(b.ks.get(&format!("secwet/{id}/device-sign")).unwrap().is_some(), "forged wipe ignored");
    assert!(b.ks.get(&format!("secwet/{id}/master-key/1")).unwrap().is_some());
    assert!(b.s.list_spaces().is_ok());
}

#[tokio::test]
async fn relay_cannot_install_its_own_master_key() {
    use ed25519_dalek::Signer;
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    a.sync().await.unwrap();
    let id = a.s.secwet_id();
    let g = ghost();
    db::add_device(&pool, id, &g.id, &g.sign_pub, &g.enc_pub).await.unwrap();

    // The operator opens epoch 2 with a key it knows, "signed" by its ghost.
    let attacker_key = [7u8; 32];
    let mut recipients = vec![a.s.device_id().to_string(), g.id.clone()];
    recipients.sort();
    let statement = secwet_proto::KeyRotationStatement {
        secwet_id: id,
        epoch: 2,
        issuer_device_id: g.id.clone(),
        recipients: recipients.clone(),
        key_commitment: *secwet_core::crypto::derive_hkdf_sha256(&attacker_key, id.as_bytes(), b"secwet/v1/key-commit"),
    };
    let signature = g.sk.sign(&statement.signing_bytes().unwrap()).to_bytes();
    let wrap = |dev: &str, pk: &[u8; 32]| {
        let info = postcard::to_stdvec(&secwet_proto::KeyWrapInfo {
            purpose: "secwet/v1/master-key",
            secwet_id: id.as_bytes(),
            key_epoch: 2,
            recipient_device_id: dev,
        })
        .unwrap();
        secwet_proto::DeviceWrappedKey {
            device_id: dev.to_string(),
            wrapped: secwet_core::crypto::wrap_for_device(pk, &info, &attacker_key).unwrap(),
        }
    };
    let wrapped = vec![wrap(&a.s.device_id().to_string(), &a.s.test_enc_pub()), wrap(&g.id, &g.enc_pub)];
    secwet_relay::collab_db::rotate_master_key(
        &pool,
        id,
        &secwet_proto::SignedRotationStatement { statement, signature },
        &wrapped,
    )
    .await
    .unwrap();

    let _ = a.sync().await;
    assert_eq!(a.s.key_epoch(), 1, "an epoch signed by a relay-only device is never adopted");
}

#[tokio::test]
async fn relay_injected_device_never_receives_branch_keys() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let t = build_tree(&mut a);
    a.sync().await.unwrap();
    let g = ghost();
    db::add_device(&pool, a.s.secwet_id(), &g.id, &g.sign_pub, &g.enc_pub).await.unwrap();
    let ca = a.client();
    a.s.invite_member(&ca, &a.ks, "x@example.com", &[(TreeNode::Space(t.space), TreeRole::Viewer)])
        .await
        .unwrap();
    // A container change marks the space dirty; republishing must skip the ghost.
    a.s.add_environment(t.item, "Staging").unwrap();
    a.sync().await.unwrap();
    let rows = sqlx_count(&pool, "SELECT COUNT(*) FROM branch_keys WHERE device_id = $1", &g.id).await;
    assert_eq!(rows, 0);
}

#[tokio::test]
async fn member_that_syncs_before_the_admin_still_gets_the_tree() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let t = build_tree(&mut a);
    a.sync().await.unwrap();
    let ca = a.client();
    let inv = a
        .s
        .invite_member(&ca, &a.ks, "early@example.com", &[(TreeNode::Space(t.space), TreeRole::Viewer)])
        .await
        .unwrap();
    let mut m = join(&relay, &inv.link, "early@example.com").await;
    m.sync().await.unwrap(); // before the admin delivered any key
    a.sync().await.unwrap();
    m.sync().await.unwrap();
    let names = all_secret_names(&m.s);
    assert!(names.contains(&"PROD_DB".to_string()) && names.contains(&"DEV_DB".to_string()), "{names:?}");
    assert_eq!(m.s.deferred_count().unwrap(), 0);
}

#[tokio::test]
async fn owner_device_paired_after_sharing_sees_member_writes() {
    let (relay, pool) = start_relay().await;
    let mut a = owner(&relay, &pool).await;
    let t = build_tree(&mut a);
    a.sync().await.unwrap();
    let ca = a.client();
    let inv = a
        .s
        .invite_member(&ca, &a.ks, "ed@example.com", &[(TreeNode::Item(t.item), TreeRole::Editor)])
        .await
        .unwrap();
    let mut m = join(&relay, &inv.link, "ed@example.com").await;
    a.sync().await.unwrap();
    m.sync().await.unwrap();

    let mut c = second_owner_device(&mut a, &relay, &pool, "New desktop").await;
    a.sync().await.unwrap(); // certifies C to the other devices and covers it
    c.sync().await.unwrap();

    secret(&mut m.s, t.item, Some(t.dev), "FROM_MEMBER", "m-value");
    m.sync().await.unwrap();
    c.sync().await.unwrap();
    assert!(all_secret_names(&c.s).contains(&"FROM_MEMBER".to_string()));
}
