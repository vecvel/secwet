//! Plans and entitlements against the real relay router and Postgres:
//! admin grant (also before registration), expiry evaluated on every read,
//! admin expire/ungrant, and the client side of an ended Pro plan with real
//! `Secwet` stores. No mocks.

use chrono::{Duration, Utc};
use secrecy::ExposeSecret;
use secwet_core::{Error, MemoryStore, PlanState, RelayClient, SecretDraft, SecretKind, Secwet};
use secwet_relay::{
    admin::{self, AdminCommand, AdminGrantArgs, AdminTargetArgs},
    create_router,
    db::{self, create_pool, run_migrations},
    rate_limit::RateLimitManager,
    sqlx::PgPool,
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

async fn grant(pool: &PgPool, secwet_id: Uuid, plan: &str, devices: u32, until: Option<String>) {
    admin::run_admin_command(
        pool,
        AdminCommand::Grant(AdminGrantArgs {
            secwet: Some(secwet_id),
            secwet_pos: None,
            plan: plan.into(),
            devices,
            until,
        }),
    )
    .await
    .expect("admin grant");
}

fn target(secwet_id: Uuid) -> AdminTargetArgs {
    AdminTargetArgs { secwet: Some(secwet_id), secwet_pos: None }
}

struct Node {
    _dir: TempDir,
    ks: MemoryStore,
    s: Secwet,
}

impl Node {
    fn new(relay: &str) -> Node {
        let dir = TempDir::new().unwrap();
        let ks = MemoryStore::new();
        let mut s = Secwet::create(dir.path(), "Owner Mac", &ks).unwrap();
        s.set_relay_url(relay).unwrap();
        Node { _dir: dir, ks, s }
    }
    fn client(&self) -> RelayClient {
        RelayClient::new(self.s.relay_url().unwrap(), self.s.device_id().to_string())
    }
    async fn sync(&mut self) -> Result<(usize, usize), Error> {
        let c = self.client();
        self.s.sync_round(&c, &self.ks).await
    }
}

async fn count_events(pool: &PgPool, secwet_id: Uuid) -> i64 {
    secwet_relay::sqlx::query_scalar::<_, i64>("SELECT count(*) FROM events WHERE secwet_id = $1")
        .bind(secwet_id)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn new_secret(s: &mut Secwet, item: Uuid, name: &str, value: &str) -> Uuid {
    s.create_secret(SecretDraft::new(item, None, name, SecretKind::Password, value, None))
        .unwrap()
        .id
}

#[tokio::test]
async fn admin_grant_needs_a_registered_workspace() {
    let (relay, pool) = start_relay().await;
    let mut a = Node::new(&relay);
    let id = a.s.secwet_id();
    let until = (Utc::now() + Duration::days(400)).format("%Y-%m-%d").to_string();
    let early = admin::run_admin_command(
        &pool,
        AdminCommand::Grant(AdminGrantArgs {
            secwet: Some(id),
            secwet_pos: None,
            plan: "pro".into(),
            devices: 5,
            until: Some(until.clone()),
        }),
    )
    .await;
    assert!(early.is_err(), "an unregistered id cannot be granted");

    // "Check for Pro" registers the id on Free, the operator grants, and the
    // next check reads the grant.
    let c = a.client();
    assert_eq!(a.s.activate_plan(&c).await.expect("activate").state, PlanState::Free);
    grant(&pool, id, "pro", 5, Some(until)).await;
    let info = a.s.activate_plan(&c).await.expect("activate");
    assert_eq!(info.state, PlanState::Pro);
    assert_eq!(info.device_limit, 5);
    assert!(info.expires_at.is_some());

    // A second registration of the same workspace is still refused.
    let again = c
        .register(id, a.s.device_sign_pub(), a.s.device_enc_pub(), a.s.device_sign_key())
        .await;
    assert!(matches!(again, Err(Error::Relay { code }) if code == "exists"));
    // Activating again is idempotent.
    assert_eq!(a.s.activate_plan(&c).await.unwrap().state, PlanState::Pro);
}

#[tokio::test]
async fn shared_id_cannot_be_squatted_for_its_grant() {
    let (relay, pool) = start_relay().await;
    let victim = Node::new(&relay);
    let id = victim.s.secwet_id();

    // An entitlement row with no devices (left by an older relay that granted
    // before registration) keeps the id taken.
    secwet_relay::sqlx::query("INSERT INTO secwets (id) VALUES ($1)").bind(id).execute(&pool).await.unwrap();
    secwet_relay::sqlx::query("INSERT INTO entitlements (secwet_id, plan, device_limit) VALUES ($1, 'pro', 5)")
        .bind(id)
        .execute(&pool)
        .await
        .unwrap();
    let attacker = Node::new(&relay);
    let squat = attacker
        .client()
        .register(id, attacker.s.device_sign_pub(), attacker.s.device_enc_pub(), attacker.s.device_sign_key())
        .await;
    assert!(matches!(squat, Err(Error::Relay { ref code }) if code == "exists"), "{squat:?}");

    // The operator ungrants the orphan; the owner registers on Free and only
    // then can be granted.
    admin::run_admin_command(&pool, AdminCommand::Ungrant(target(id))).await.expect("ungrant");
    let mut victim = victim;
    let c = victim.client();
    assert_eq!(victim.s.activate_plan(&c).await.expect("activate").state, PlanState::Free);
    grant(&pool, id, "pro", 5, None).await;
    assert_eq!(victim.s.activate_plan(&c).await.unwrap().state, PlanState::Pro);
}

#[tokio::test]
async fn free_workspace_cannot_store_or_stream_on_the_relay() {
    let (relay, _pool) = start_relay().await;
    let mut a = Node::new(&relay);
    let c = a.client();
    assert_eq!(a.s.activate_plan(&c).await.unwrap().state, PlanState::Free);
    let req = secwet_proto::SnapshotUploadRequest {
        server_seq: 0,
        key_epoch: 1,
        nonce: [0u8; 24],
        ciphertext: vec![0u8; 4096],
    };
    let up = c.upload_snapshot(a.s.secwet_id(), &req, a.s.device_sign_key()).await;
    assert!(matches!(up, Err(Error::Relay { ref code }) if code.contains("entitled")), "{up:?}");
    assert!(c.get_snapshot(a.s.secwet_id(), a.s.device_sign_key()).await.unwrap().is_none());
}

#[tokio::test]
async fn activation_without_grant_stays_free() {
    let (relay, _pool) = start_relay().await;
    let mut a = Node::new(&relay);
    let c = a.client();
    let info = a.s.activate_plan(&c).await.expect("activate");
    assert_eq!(info.state, PlanState::Free);
    assert_eq!(info.device_limit, 1);
    // Still Free: sync is refused locally.
    assert!(matches!(a.sync().await, Err(Error::NeedsPro)));
}

#[tokio::test]
async fn expired_entitlement_reads_free_and_blocks_sync_and_pairing() {
    let (relay, pool) = start_relay().await;
    let mut a = Node::new(&relay);
    let id = a.s.secwet_id();
    let c = a.client();
    a.s.relay_register(&c).await.unwrap();

    let past = (Utc::now() - Duration::days(1)).to_rfc3339();
    grant(&pool, id, "pro", 5, Some(past)).await;
    let ent = c.get_entitlement(id, a.s.device_sign_key()).await.unwrap();
    assert_eq!(ent.plan, "free", "an ended Pro reads as free");
    assert!(ent.expires_at.is_some(), "and keeps its end so clients can show Paused");

    // Pairing and push are refused by the relay itself.
    let (_, eph) = secwet_core::crypto::generate_ephemeral_x25519();
    let pairing = c.create_pairing_session(id, eph, a.s.device_sign_key()).await;
    assert!(matches!(pairing, Err(Error::Relay { code }) if code == "not_entitled"));
    a.s.set_plan("pro").unwrap();
    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Ops", None, Some(space)).unwrap();
    a.s.create_item(label.id, "svc", None).unwrap();
    let events = a.s.peek_outbox(10).unwrap();
    assert!(!events.is_empty());
    let push = c.push_events(id, events, a.s.device_sign_key()).await;
    assert!(matches!(push, Err(Error::Relay { code }) if code == "not_entitled"));

    // A renewed grant works again; `expire` ends it now; `ungrant` goes Free.
    grant(&pool, id, "pro", 3, None).await;
    let ent = db::get_entitlement(&pool, id).await.unwrap();
    assert_eq!((ent.plan.as_str(), ent.device_limit, ent.expires_at.is_none()), ("pro", 3, true));
    admin::run_admin_command(&pool, AdminCommand::Expire(target(id))).await.unwrap();
    let ent = db::get_entitlement(&pool, id).await.unwrap();
    assert_eq!(ent.plan, "free");
    assert!(ent.expires_at.is_some());
    admin::run_admin_command(&pool, AdminCommand::Ungrant(target(id))).await.unwrap();
    let ent = db::get_entitlement(&pool, id).await.unwrap();
    assert_eq!((ent.plan.as_str(), ent.device_limit, ent.expires_at), ("free", 1, None));

    // Unknown plans and zero devices are rejected.
    let bad = admin::run_admin_command(
        &pool,
        AdminCommand::Grant(AdminGrantArgs {
            secwet: Some(id),
            secwet_pos: None,
            plan: "enterprise".into(),
            devices: 5,
            until: None,
        }),
    )
    .await;
    assert!(bad.is_err());
}

/// When Pro ends, sync stops and other devices show "Paused", but every
/// local read, write and export keeps working, nothing is deleted or locked,
/// and the changes made meanwhile go out once Pro is renewed.
#[tokio::test]
async fn expired_plan_pauses_sync_keeps_local_access() {
    let (relay, pool) = start_relay().await;
    let mut a = Node::new(&relay);
    let id = a.s.secwet_id();
    let c = a.client();
    a.s.activate_plan(&c).await.unwrap();
    grant(&pool, id, "pro", 5, None).await;
    assert_eq!(a.s.activate_plan(&c).await.unwrap().state, PlanState::Pro);

    let space = a.s.ensure_default_personal_space().unwrap().id;
    let label = a.s.create_label_in_space("Ops", None, Some(space)).unwrap();
    let item = a.s.create_item(label.id, "svc", None).unwrap().id;
    let before = new_secret(&mut a.s, item, "BEFORE", "v1");
    let (pushed, _) = a.sync().await.expect("sync while Pro");
    assert!(pushed > 0);
    let events_on_relay = count_events(&pool, id).await;

    // Pro ends on the relay.
    admin::run_admin_command(&pool, AdminCommand::Expire(target(id))).await.unwrap();

    let res = a.sync().await;
    assert!(matches!(res, Err(Error::SyncPaused)), "got {res:?}");
    let info = a.s.plan_info().unwrap();
    assert_eq!(info.state, PlanState::Paused);
    assert_eq!(a.s.plan().unwrap(), "paused");

    // Local data stays fully usable: read, write, delete, export.
    assert_eq!(a.s.reveal_secret(before).unwrap().expose_secret(), "v1");
    let during = new_secret(&mut a.s, item, "DURING", "v2");
    assert_eq!(a.s.reveal_secret(during).unwrap().expose_secret(), "v2");
    let scratch = new_secret(&mut a.s, item, "SCRATCH", "x");
    a.s.delete_secret(scratch).unwrap();
    let recovery = a.s.create_recovery_key(&a.ks).unwrap();
    let out = TempDir::new().unwrap();
    let path = out.path().join("backup.secwet");
    a.s.export_to_file(recovery.expose_secret(), &path).expect("export while paused");
    assert!(path.exists());

    // Nothing reached the relay while paused, and the changes wait in the outbox.
    assert_eq!(count_events(&pool, id).await, events_on_relay);
    assert!(a.s.pending_outbox_count().unwrap() > 0);
    assert!(matches!(a.s.push_outbox(&c).await, Err(Error::SyncPaused)));
    assert!(matches!(a.s.pull_and_apply_events(&c).await, Err(Error::SyncPaused)));

    // A store whose cached end passed reads as paused without a relay call.
    let mut b = Node::new(&relay);
    let ended = secwet_proto::EntitlementResponse {
        secwet_id: b.s.secwet_id(),
        plan: "pro".into(),
        device_limit: 5,
        expires_at: Some((Utc::now() + Duration::milliseconds(50)).to_rfc3339()),
    };
    assert_eq!(b.s.apply_entitlement(&ended).unwrap().state, PlanState::Pro);
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;
    assert_eq!(b.s.plan_state().unwrap(), PlanState::Paused);

    // Renewal resumes sync and sends what was written meanwhile.
    grant(&pool, id, "pro", 5, None).await;
    let (pushed, _) = a.sync().await.expect("sync after renewal");
    assert!(pushed > 0);
    assert_eq!(a.s.plan_state().unwrap(), PlanState::Pro);
    assert_eq!(a.s.pending_outbox_count().unwrap(), 0);
    assert!(count_events(&pool, id).await > events_on_relay);
}
