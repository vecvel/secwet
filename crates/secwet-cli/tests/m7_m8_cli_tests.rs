//! CLI coverage for `device revoke --wipe | --sync-only`, `key`, `member` and
//! `space share`, run as subprocesses against an in-process relay on Postgres.

use assert_cmd::Command;
use predicates::prelude::*;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::{RelayClient, Secwet};
use secwet_relay::{create_router, db, rate_limit::RateLimitManager, AppState, RelayConfig};
use std::{net::SocketAddr, path::Path, sync::Arc};
use tempfile::tempdir;

async fn start_relay() -> (String, secwet_relay::sqlx::PgPool) {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".into());
    let pool = db::create_pool(&db_url).await.expect("connect to test Postgres");
    db::run_migrations(&pool).await.expect("migrations");
    let mut config = RelayConfig::from_env();
    config.database_url = db_url;
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

fn secwet(dir: &Path) -> Command {
    let mut c = Command::cargo_bin("secwet").unwrap();
    c.env("SECWET_DATA_DIR", dir).env("SECWET_TEST_KEYSTORE", "file");
    c
}

#[test]
fn device_revoke_flags_are_exclusive() {
    let temp = tempdir().unwrap();
    let ks = FileKeyStore::new(temp.path().join(".test_keystore.json"));
    Secwet::create(temp.path(), "cli", &ks).unwrap().lock();
    secwet(temp.path())
        .args(["device", "revoke", "ABC", "--wipe", "--sync-only"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn member_invite_rejects_bad_grant_spec() {
    let temp = tempdir().unwrap();
    let ks = FileKeyStore::new(temp.path().join(".test_keystore.json"));
    let mut s = Secwet::create(temp.path(), "cli", &ks).unwrap();
    s.set_relay_url("http://127.0.0.1:9").unwrap();
    // On Free the plan check comes first (F13: no relay contact at all).
    s.set_plan("pro").unwrap();
    s.lock();
    secwet(temp.path())
        .args(["member", "invite", "a@b.com", "--grant", "space:not-a-uuid=admin"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("is not a grant"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cli_rotate_invite_join_and_sync() {
    let (relay, pool) = start_relay().await;

    // Owner store, registered with the relay on the Pro plan.
    let owner_dir = tempdir().unwrap();
    let ks = FileKeyStore::new(owner_dir.path().join(".test_keystore.json"));
    let mut s = Secwet::create(owner_dir.path(), "Owner CLI", &ks).unwrap();
    s.set_relay_url(&relay).unwrap();
    s.relay_register(&RelayClient::new(&relay, s.device_id().to_string())).await.unwrap();
    db::grant_entitlement(&pool, s.secwet_id(), "pro", 5, None).await.unwrap();
    s.set_plan("pro").unwrap();
    let space = s.create_space("Platform", None).unwrap().id;
    let group = s.create_label_in_space("Infra", None, Some(space)).unwrap().id;
    let item = s.create_item(group, "terraform", None).unwrap().id;
    s.create_secret(secwet_core::SecretDraft::new(item, None, "TF_TOKEN", secwet_core::SecretKind::ApiKey, "tf-cli-value", None))
        .unwrap();
    s.lock();
    let od = owner_dir.path().to_path_buf();

    let out = tokio::task::spawn_blocking(move || {
        secwet(&od).args(["key", "rotate", "--json"]).assert().success().get_output().stdout.clone()
    })
    .await
    .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(report["epoch"], 2);

    let od = owner_dir.path().to_path_buf();
    secwet(&od).args(["key", "status"]).assert().success().stdout(predicate::str::contains("Key version: 2"));

    let od2 = od.clone();
    let space_s = space.to_string();
    let out = tokio::task::spawn_blocking(move || {
        secwet(&od2)
            .args(["space", "share", &space_s, "--email", "ops@example.com", "--role", "viewer"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone()
    })
    .await
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let link = text.lines().find(|l| l.starts_with("secwet://invite")).expect("invite link").to_string();

    let member_dir = tempdir().unwrap();
    let md = member_dir.path().to_path_buf();
    let l2 = link.clone();
    tokio::task::spawn_blocking(move || {
        secwet(&md).args(["member", "join", &l2, "--email", "ops@example.com", "--name", "Ops CLI"]).assert().success();
    })
    .await
    .unwrap();

    let od3 = od.clone();
    tokio::task::spawn_blocking(move || secwet(&od3).args(["sync"]).assert().success()).await.unwrap();
    let md = member_dir.path().to_path_buf();
    let md2 = md.clone();
    tokio::task::spawn_blocking(move || secwet(&md2).args(["sync"]).assert().success()).await.unwrap();
    tokio::task::spawn_blocking(move || {
        secwet(&md)
            .args(["tree", "--json"])
            .assert()
            .success()
            .stdout(predicate::str::contains("TF_TOKEN"))
            .stdout(predicate::str::contains("tf-cli-value").not());
    })
    .await
    .unwrap();

    let od4 = od.clone();
    tokio::task::spawn_blocking(move || {
        secwet(&od4)
            .args(["member", "list"])
            .assert()
            .success()
            .stdout(predicate::str::contains("ops@example.com"))
            .stdout(predicate::str::contains("active"));
    })
    .await
    .unwrap();
}
