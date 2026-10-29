//! The phone's Settings and Members flows end to end through the mobile
//! command contract (`{cmd, args}` JSON into `Bridge::handle`, exactly what
//! Dart sends): pairing two stores, an invite join, and M7 remote wipe and
//! sync-only revoke. Real relay router over HTTP and the Docker Postgres
//! (`DATABASE_URL`, default postgres://secwet:secwet@localhost:5432/secwet_relay).

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secwet_ffi::{bridge_for, Bridge, SecwetPlatform};
use secwet_relay::{
    create_router, db, rate_limit::RateLimitManager, sqlx::PgPool, AppState, RelayConfig,
};
use serde_json::{json, Value};
use uuid::Uuid;

type Keys = Mutex<Option<HashMap<String, Vec<u8>>>>;

fn copy_out(value: &[u8], out: *mut u8, cap: usize) -> i64 {
    if value.len() > cap {
        return -2;
    }
    // SAFETY: the caller hands a writable buffer of `cap` bytes.
    unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len()) };
    value.len() as i64
}

fn entry(name: *const c_char) -> String {
    // SAFETY: Rust passes a NUL-terminated entry name.
    unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned()
}

fn ks_get(keys: &Keys, name: *const c_char, out: *mut u8, cap: usize) -> i64 {
    match keys
        .lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .get(&entry(name))
    {
        Some(v) => copy_out(v, out, cap),
        None => -1,
    }
}

fn ks_set(keys: &Keys, name: *const c_char, value: *const u8, len: usize) -> i32 {
    // SAFETY: `value` points to `len` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(value, len) }.to_vec();
    keys.lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(entry(name), bytes);
    0
}

fn ks_delete(keys: &Keys, name: *const c_char) -> i32 {
    keys.lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .remove(&entry(name));
    0
}

static CLIPBOARD: Mutex<Option<String>> = Mutex::new(None);

extern "C" fn clip_write(text: *const u8, len: usize) -> i32 {
    // SAFETY: `text` points to `len` readable bytes.
    let t = unsafe { std::slice::from_raw_parts(text, len) };
    *CLIPBOARD.lock().unwrap() = Some(String::from_utf8_lossy(t).into_owned());
    0
}

extern "C" fn clip_read(out: *mut u8, cap: usize) -> i64 {
    match CLIPBOARD.lock().unwrap().as_deref() {
        Some(t) => copy_out(t.as_bytes(), out, cap),
        None => -1,
    }
}

extern "C" fn clip_clear() -> i32 {
    *CLIPBOARD.lock().unwrap() = None;
    0
}

extern "C" fn bio_kind() -> i32 {
    0
}

/// The system prompt always succeeds on these test phones.
extern "C" fn bio_verify(_reason: *const u8, _len: usize) -> i32 {
    0
}

/// Phones must have a screen lock to run Secwet.
extern "C" fn device_lock() -> i32 {
    1
}

extern "C" fn end_session() {}

/// One phone's secure storage. Paired devices share a Secwet id, so each
/// phone needs its own keychain, like real devices.
macro_rules! phone {
    ($name:ident) => {
        mod $name {
            use super::*;
            pub static KEYS: Keys = Mutex::new(None);
            extern "C" fn get(n: *const c_char, out: *mut u8, cap: usize) -> i64 {
                ks_get(&KEYS, n, out, cap)
            }
            extern "C" fn set(n: *const c_char, v: *const u8, len: usize) -> i32 {
                ks_set(&KEYS, n, v, len)
            }
            extern "C" fn delete(n: *const c_char) -> i32 {
                ks_delete(&KEYS, n)
            }
            pub fn platform() -> SecwetPlatform {
                SecwetPlatform {
                    keystore_get: get,
                    keystore_set: set,
                    keystore_delete: delete,
                    clipboard_write: clip_write,
                    clipboard_read: clip_read,
                    clipboard_clear: clip_clear,
                    biometric_kind: bio_kind,
                    biometric_verify: bio_verify,
                    device_lock,
                    keystore_end_session: end_session,
                }
            }
        }
    };
}

phone!(owner_phone);
phone!(paired_phone);
phone!(member_phone);

/// The relay on its own runtime thread: `Bridge::handle` blocks on the app
/// layer's runtime, so the test itself stays synchronous like the Dart isolate.
fn start_relay() -> (String, PgPool, tokio::runtime::Runtime) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let (url, pool) = rt.block_on(async {
        let db_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".into());
        let pool = db::create_pool(&db_url)
            .await
            .expect("connect to the Docker Postgres");
        db::run_migrations(&pool).await.expect("migrations");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut config = RelayConfig::from_env();
        config.database_url = db_url;
        config.default_device_limit = 5;
        config.public_url = addr.to_string();
        let router = create_router(Arc::new(AppState::new(
            pool.clone(),
            config,
            RateLimitManager::new(),
        )));
        tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        (format!("http://{addr}"), pool)
    });
    (url, pool, rt)
}

fn call(b: &Bridge, cmd: &str, args: Value) -> Value {
    let req = serde_json::to_vec(&json!({ "cmd": cmd, "args": args })).unwrap();
    serde_json::from_slice(&b.handle(&req)).unwrap()
}

fn ok(b: &Bridge, cmd: &str, args: Value) -> Value {
    let res = call(b, cmd, args);
    assert!(res.get("err").is_none(), "{cmd} failed: {res}");
    res["ok"].clone()
}

/// Polls `cmd` until its `status` leaves "waiting" (the UI polls the same way).
fn poll(b: &Bridge, cmd: &str) -> Value {
    let end = Instant::now() + Duration::from_secs(20);
    loop {
        let v = ok(b, cmd, json!({}));
        if v["status"] != "waiting" {
            return v;
        }
        assert!(Instant::now() < end, "{cmd} still waiting");
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn secret_names(b: &Bridge) -> Vec<String> {
    let mut names = Vec::new();
    for item in ok(b, "items_list", json!({})).as_array().unwrap() {
        for s in ok(b, "secrets_list", json!({ "item_id": item["id"] }))
            .as_array()
            .unwrap()
        {
            names.push(s["name"].as_str().unwrap().to_owned());
        }
    }
    names.sort();
    names
}

/// A Pro owner phone registered with the relay, with one secret in a Work space.
fn owner(
    relay: &str,
    pool: &PgPool,
    rt: &tokio::runtime::Runtime,
    dir: &std::path::Path,
) -> (Bridge, Value) {
    let a = bridge_for(
        owner_phone::platform(),
        dir.to_path_buf(),
        "Owner iPhone".into(),
    );
    assert_eq!(ok(&a, "secwet_create", json!({}))["status"], "unlocked");
    // Settings > General shows the name this phone was set up with.
    assert_eq!(
        ok(&a, "settings_get", json!({}))["device_name"],
        "Owner iPhone"
    );
    for c in [
        "devices_list",
        "recovery_status",
        "key_status",
        "my_access",
        "plan_status",
        "dashboard_get",
        "settings_get",
    ] {
        eprintln!("DBG {c}: {}", ok(&a, c, json!({})));
    }
    ok(&a, "relay_set_url", json!({ "url": relay }));
    // Free never contacts the relay; "Check for Pro" registers instead.
    let refused = call(&a, "relay_register", json!({}));
    assert_eq!(refused["err"]["code"], "needs_pro", "{refused}");
    let id = Uuid::parse_str(
        ok(&a, "plan_status", json!({}))["secwet_id"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    // "Check for Pro" in Settings > Plan registers the id on Free; the
    // operator grants only a registered id, and the next check reads it.
    assert_eq!(ok(&a, "plan_activate", json!({}))["plan"], "free");
    rt.block_on(db::grant_entitlement(pool, id, "pro", 5, None))
        .unwrap();
    assert_eq!(ok(&a, "plan_activate", json!({}))["plan"], "pro");

    let space = ok(&a, "space_create", json!({ "name": "Work" }));
    let group = ok(
        &a,
        "group_create",
        json!({ "name": "Ops", "space_id": space["id"] }),
    );
    let item = ok(
        &a,
        "item_create",
        json!({ "label_id": group["id"], "name": "Deploy" }),
    );
    ok(
        &a,
        "secret_create",
        json!({ "draft": {
            "item_id": item["id"], "environment_id": null,
            "name": "DEPLOY_TOKEN", "kind": "api_key", "value": "tok-0a1b2c3d"
        }}),
    );
    ok(&a, "sync_now", json!({}));
    (a, space)
}

/// Settings > Devices > Pair a device on the owner, scan on the new phone.
fn pair(a: &Bridge, b: &Bridge) -> String {
    let session = ok(a, "pairing_start", json!({}));
    let link = session["qr_payload"].as_str().unwrap().to_owned();
    assert!(link.starts_with("secwet://pair"), "{link}");

    let join = ok(
        b,
        "pairing_join_start",
        json!({ "link": link, "device_name": "Second iPhone" }),
    );
    let found = poll(a, "pairing_poll");
    assert_eq!(found["status"], "found");
    assert_eq!(found["name"], "Second iPhone");
    // Both screens show the same 6-digit code.
    assert_eq!(found["code"], join["code"]);
    let digits = found["code"]
        .as_str()
        .unwrap()
        .chars()
        .filter(char::is_ascii_digit)
        .count();
    assert_eq!(digits, 6, "{found}");

    let device = ok(a, "pairing_approve", json!({}));
    let approved = poll(b, "pairing_join_poll");
    assert_eq!(approved["status"], "approved", "{approved}");
    device["id"].as_str().unwrap().to_owned()
}

#[test]
fn pairing_two_stores_then_remote_wipe_and_sync_only_revoke() {
    let (relay, pool, rt) = start_relay();
    let a_dir = tempfile::tempdir().unwrap();
    let (a, _) = owner(&relay, &pool, &rt, a_dir.path());

    // Pair a second phone: it gets the owner's data.
    let b_dir = tempfile::tempdir().unwrap();
    let b = bridge_for(
        paired_phone::platform(),
        b_dir.path().to_path_buf(),
        "Second iPhone".into(),
    );
    assert_eq!(
        ok(&b, "secwet_status", json!({}))["status"],
        "uninitialized"
    );
    let b_id = pair(&a, &b);
    assert_eq!(ok(&b, "secwet_status", json!({}))["status"], "unlocked");
    ok(&b, "sync_now", json!({}));
    assert_eq!(secret_names(&b), vec!["DEPLOY_TOKEN".to_owned()]);
    let devices = ok(&a, "devices_list", json!({}));
    assert_eq!(
        devices
            .as_array()
            .unwrap()
            .iter()
            .filter(|d| d["revoked_at"].is_null())
            .count(),
        2
    );
    assert_eq!(ok(&b, "my_access", json!({}))["is_owner"], true);

    // Sync-only revoke: the phone keeps a read-only copy (M7 archive mode).
    let r = ok(
        &a,
        "device_revoke",
        json!({ "device_id": b_id, "wipe": false }),
    );
    assert_eq!(r["wipe_requested"], false);
    assert_eq!(r["rotation_recommended"], true);
    let _ = call(&b, "sync_now", json!({}));
    assert_eq!(ok(&b, "link_status", json!({}))["state"], "unlinked");
    assert_eq!(secret_names(&b), vec!["DEPLOY_TOKEN".to_owned()]);

    // Pair a fresh phone and revoke it with remote wipe: it erases itself.
    let c_dir = tempfile::tempdir().unwrap();
    *paired_phone::KEYS.lock().unwrap() = None;
    drop(b);
    let c = bridge_for(
        paired_phone::platform(),
        c_dir.path().to_path_buf(),
        "Third iPhone".into(),
    );
    let c_id = pair(&a, &c);
    assert!(!paired_phone::KEYS
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .is_empty());
    let r = ok(
        &a,
        "device_revoke",
        json!({ "device_id": c_id, "wipe": true }),
    );
    assert_eq!(r["wipe_requested"], true);
    let _ = call(&c, "sync_now", json!({}));
    assert_eq!(
        ok(&c, "secwet_status", json!({}))["status"],
        "uninitialized"
    );
    // Crypto-shred: every key this phone held is gone from its keychain.
    assert!(paired_phone::KEYS
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .is_empty());

    // The owner rotates after the revokes.
    assert_eq!(
        ok(&a, "key_status", json!({}))["rotation_recommended"],
        true
    );
    let report = ok(&a, "key_rotate", json!({}));
    assert!(report["epoch"].as_u64().unwrap() > report["previous_epoch"].as_u64().unwrap());
}

#[test]
fn invite_join_through_the_link_and_remove_with_wipe() {
    let (relay, pool, rt) = start_relay();
    let a_dir = tempfile::tempdir().unwrap();
    let (a, space) = owner(&relay, &pool, &rt, a_dir.path());

    // Members > Invite: Viewer on the Work space, link copied through the
    // 30-second clipboard.
    let invite = ok(
        &a,
        "member_invite",
        json!({ "email": "ana@example.com", "grants": [{ "kind": "space", "id": space["id"], "role": "viewer" }] }),
    );
    let link = invite["link"].as_str().unwrap().to_owned();
    assert!(link.starts_with("secwet://invite"), "{link}");
    ok(
        &a,
        "invite_link_copy",
        json!({ "invitation_id": invite["invitation_id"] }),
    );
    assert_eq!(CLIPBOARD.lock().unwrap().as_deref(), Some(link.as_str()));
    let members = ok(&a, "members_list", json!({}));
    assert_eq!(members[0]["status"], "invited");

    // The member's phone opens secwet://invite and joins.
    let m_dir = tempfile::tempdir().unwrap();
    let m = bridge_for(
        member_phone::platform(),
        m_dir.path().to_path_buf(),
        "Ana's iPhone".into(),
    );
    assert_eq!(
        ok(
            &m,
            "invitation_accept",
            json!({ "link": link, "email": "ana@example.com" })
        )["status"],
        "unlocked"
    );
    // Owner admits on sync, the member pulls what was shared.
    ok(&a, "sync_now", json!({}));
    ok(&m, "sync_now", json!({}));
    assert_eq!(secret_names(&m), vec!["DEPLOY_TOKEN".to_owned()]);
    // Member mode: not the owner, so the phone hides pairing and device revoke.
    let access = ok(&m, "my_access", json!({}));
    assert_eq!(access["is_owner"], false);
    assert_eq!(access["grants"][0]["role"], "viewer");
    let members = ok(&a, "members_list", json!({}));
    assert_eq!(members[0]["status"], "active");

    // Remove with wipe: the member's phone erases the workspace on next sync.
    ok(
        &a,
        "member_remove",
        json!({ "member_id": members[0]["member_id"], "wipe": true }),
    );
    let _ = call(&m, "sync_now", json!({}));
    assert_eq!(
        ok(&m, "secwet_status", json!({}))["status"],
        "uninitialized"
    );

    // A revoked invitation stops working.
    let second = ok(
        &a,
        "member_invite",
        json!({ "email": "ben@example.com", "grants": [{ "kind": "space", "id": space["id"], "role": "editor" }] }),
    );
    ok(
        &a,
        "invitation_revoke",
        json!({ "invitation_id": second["invitation_id"] }),
    );
    let n_dir = tempfile::tempdir().unwrap();
    let n = bridge_for(
        member_phone::platform(),
        n_dir.path().to_path_buf(),
        "Ben's iPhone".into(),
    );
    let res = call(
        &n,
        "invitation_accept",
        json!({ "link": second["link"], "email": "ben@example.com" }),
    );
    assert!(
        res.get("err").is_some(),
        "revoked invite was accepted: {res}"
    );
}
