//! End-to-end tests of the C ABI and the JSON contract, with an in-process
//! platform standing in for the iOS / Android services.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

use secwet_ffi::{bridge_for, SecwetPlatform};
use serde_json::{json, Value};

// ---------------------------------------------------------------------------
// Test platform: process-wide maps behind plain C functions.
// ---------------------------------------------------------------------------

static KEYS: Mutex<Option<HashMap<String, Vec<u8>>>> = Mutex::new(None);
static CLIPBOARD: Mutex<Option<String>> = Mutex::new(None);
static BIO_KIND: AtomicI32 = AtomicI32::new(0);
static BIO_RESULT: AtomicI32 = AtomicI32::new(0);
static BIO_PROMPTS: AtomicUsize = AtomicUsize::new(0);
/// 1 when the simulated phone has a screen lock.
static DEVICE_LOCK: AtomicI32 = AtomicI32::new(0);
/// Like the native stores: with a screen lock, keys are readable only after
/// a successful prompt opened a session.
static KEY_SESSION: AtomicBool = AtomicBool::new(false);
static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
/// Tests share the statics above, so they run one at a time.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn copy_out(value: &[u8], out: *mut u8, cap: usize) -> i64 {
    if value.len() <= cap {
        // SAFETY: Rust passes a buffer of `cap` writable bytes.
        unsafe { std::ptr::copy_nonoverlapping(value.as_ptr(), out, value.len()) };
    }
    value.len() as i64
}

fn entry(name: *const c_char) -> String {
    // SAFETY: the platform contract passes NUL-terminated entry names.
    unsafe { CStr::from_ptr(name) }
        .to_string_lossy()
        .into_owned()
}

extern "C" fn ks_get(name: *const c_char, out: *mut u8, cap: usize) -> i64 {
    if DEVICE_LOCK.load(Ordering::SeqCst) == 1 && !KEY_SESSION.load(Ordering::SeqCst) {
        return -2;
    }
    let keys = KEYS.lock().unwrap();
    match keys.as_ref().and_then(|m| m.get(&entry(name))) {
        Some(v) => copy_out(v, out, cap),
        None => -1,
    }
}

extern "C" fn ks_set(name: *const c_char, value: *const u8, len: usize) -> i32 {
    // SAFETY: `value` points to `len` bytes per the contract.
    let bytes = unsafe { std::slice::from_raw_parts(value, len) }.to_vec();
    KEYS.lock()
        .unwrap()
        .get_or_insert_with(HashMap::new)
        .insert(entry(name), bytes);
    0
}

extern "C" fn ks_delete(name: *const c_char) -> i32 {
    if let Some(m) = KEYS.lock().unwrap().as_mut() {
        m.remove(&entry(name));
    }
    0
}

extern "C" fn clip_write(text: *const u8, len: usize) -> i32 {
    // SAFETY: `text` points to `len` UTF-8 bytes per the contract.
    let s = String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(text, len) }).into_owned();
    *CLIPBOARD.lock().unwrap() = Some(s);
    0
}

extern "C" fn clip_read(out: *mut u8, cap: usize) -> i64 {
    match CLIPBOARD.lock().unwrap().as_ref() {
        Some(s) => copy_out(s.as_bytes(), out, cap),
        None => -1,
    }
}

extern "C" fn clip_clear() -> i32 {
    *CLIPBOARD.lock().unwrap() = None;
    0
}

extern "C" fn bio_kind() -> i32 {
    BIO_KIND.load(Ordering::SeqCst)
}

extern "C" fn bio_verify(_reason: *const u8, _len: usize) -> i32 {
    BIO_PROMPTS.fetch_add(1, Ordering::SeqCst);
    let result = BIO_RESULT.load(Ordering::SeqCst);
    if result == 0 {
        KEY_SESSION.store(true, Ordering::SeqCst);
    }
    result
}

extern "C" fn device_lock() -> i32 {
    DEVICE_LOCK.load(Ordering::SeqCst)
}

extern "C" fn end_session() {
    KEY_SESSION.store(false, Ordering::SeqCst);
}

extern "C" fn on_event(ptr: *mut u8, len: usize) {
    // SAFETY: Rust hands over a buffer of `len` bytes that we must free.
    let text =
        String::from_utf8_lossy(unsafe { std::slice::from_raw_parts(ptr, len) }).into_owned();
    EVENTS.lock().unwrap().push(text);
    unsafe { secwet_ffi::secwet_ffi_free(ptr, len) };
}

fn platform() -> SecwetPlatform {
    SecwetPlatform {
        keystore_get: ks_get,
        keystore_set: ks_set,
        keystore_delete: ks_delete,
        clipboard_write: clip_write,
        clipboard_read: clip_read,
        clipboard_clear: clip_clear,
        biometric_kind: bio_kind,
        biometric_verify: bio_verify,
        device_lock,
        keystore_end_session: end_session,
    }
}

fn reset_platform() {
    *KEYS.lock().unwrap() = Some(HashMap::new());
    *CLIPBOARD.lock().unwrap() = None;
    BIO_KIND.store(0, Ordering::SeqCst);
    BIO_RESULT.store(0, Ordering::SeqCst);
    BIO_PROMPTS.store(0, Ordering::SeqCst);
    // Phones must have a screen lock; tests that need none clear it.
    DEVICE_LOCK.store(1, Ordering::SeqCst);
    KEY_SESSION.store(false, Ordering::SeqCst);
    EVENTS.lock().unwrap().clear();
}

fn call(bridge: &secwet_ffi::Bridge, cmd: &str, args: Value) -> Value {
    let req = serde_json::to_vec(&json!({ "cmd": cmd, "args": args })).unwrap();
    serde_json::from_slice(&bridge.handle(&req)).unwrap()
}

fn ok(bridge: &secwet_ffi::Bridge, cmd: &str, args: Value) -> Value {
    let res = call(bridge, cmd, args);
    assert!(res.get("err").is_none(), "{cmd} failed: {res}");
    res["ok"].clone()
}

fn err_code(bridge: &secwet_ffi::Bridge, cmd: &str, args: Value) -> String {
    let res = call(bridge, cmd, args);
    res["err"]["code"]
        .as_str()
        .unwrap_or_else(|| panic!("{cmd} should fail: {res}"))
        .to_owned()
}

// ---------------------------------------------------------------------------

#[test]
fn lifecycle_crud_and_secrets_through_json() {
    let _g = serial();
    reset_platform();
    let dir = tempfile::tempdir().unwrap();
    let b = bridge_for(platform(), dir.path().to_path_buf(), "Test Phone".into());

    assert_eq!(
        ok(&b, "secwet_status", json!({}))["status"],
        "uninitialized"
    );
    assert_eq!(ok(&b, "secwet_create", json!({}))["status"], "unlocked");
    assert_eq!(ok(&b, "system_device_name", json!({})), "Test Phone");
    assert_eq!(
        ok(&b, "settings_get", json!({}))["device_name"],
        "Test Phone"
    );
    // Keys went to the platform keystore, nothing else holds them.
    assert!(!KEYS.lock().unwrap().as_ref().unwrap().is_empty());

    let space = ok(&b, "space_create", json!({ "name": "Work" }));
    let group = ok(
        &b,
        "group_create",
        json!({ "name": "Projects", "space_id": space["id"] }),
    );
    let item = ok(
        &b,
        "item_create",
        json!({ "label_id": group["id"], "name": "Payments API" }),
    );
    let env = ok(
        &b,
        "environment_add",
        json!({ "item_id": item["id"], "name": "Production" }),
    );

    let secret = ok(
        &b,
        "secret_create",
        json!({ "draft": {
            "item_id": item["id"], "environment_id": env["id"],
            "name": "STRIPE_SECRET_KEY", "kind": "api_key", "value": "sk_live_123456789"
        }}),
    );
    assert_eq!(secret["value_tail"], "6789");
    assert!(secret.get("value").is_none());
    assert_eq!(
        ok(&b, "secret_reveal", json!({ "id": secret["id"] })),
        "sk_live_123456789"
    );

    ok(&b, "secret_copy", json!({ "id": secret["id"] }));
    assert_eq!(
        CLIPBOARD.lock().unwrap().as_deref(),
        Some("sk_live_123456789")
    );

    let list = ok(
        &b,
        "secrets_list",
        json!({ "item_id": item["id"], "environment_id": env["id"] }),
    );
    assert_eq!(list.as_array().unwrap().len(), 1);
    let overview = ok(&b, "overview", json!({}));
    assert_eq!(overview["secrets_count"], 1);

    ok(&b, "secwet_lock", json!({}));
    assert_eq!(err_code(&b, "labels_list", json!({})), "locked");
    ok(&b, "secwet_unlock", json!({}));
    assert!(!ok(&b, "labels_list", json!({}))
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn errors_are_structured() {
    let _g = serial();
    reset_platform();
    let dir = tempfile::tempdir().unwrap();
    let b = bridge_for(platform(), dir.path().to_path_buf(), "Phone".into());

    assert_eq!(
        err_code(&b, "no_such_command", json!({})),
        "unknown_command"
    );
    let res: Value = serde_json::from_slice(&b.handle(b"not json")).unwrap();
    assert_eq!(res["err"]["code"], "invalid");
    ok(&b, "secwet_create", json!({}));
    let res = call(
        &b,
        "space_rename",
        json!({ "id": "not-a-uuid", "name": "x" }),
    );
    assert_eq!(res["err"]["code"], "invalid");
    assert_eq!(res["err"]["field"], "id");
    let res = call(&b, "item_create", json!({ "name": "x" }));
    assert_eq!(res["err"]["field"], "label_id");
}

#[test]
fn screen_lock_prompt_guards_every_unlock() {
    let _g = serial();
    reset_platform();
    DEVICE_LOCK.store(1, Ordering::SeqCst);
    BIO_KIND.store(2, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let b = bridge_for(platform(), dir.path().to_path_buf(), "Phone".into());

    // Setting up writes and reads the keys, so it runs the prompt once.
    BIO_RESULT.store(1, Ordering::SeqCst);
    assert_eq!(
        err_code(&b, "secwet_create", json!({})),
        "biometric_cancelled"
    );
    BIO_RESULT.store(0, Ordering::SeqCst);
    ok(&b, "secwet_create", json!({}));
    assert_eq!(BIO_PROMPTS.load(Ordering::SeqCst), 2);

    // Always on with a screen lock; there is nothing to turn on.
    let status = ok(&b, "biometric_status", json!({}));
    assert_eq!(status["available"], true);
    assert_eq!(status["enabled"], true);
    assert_eq!(status["device_lock"], true);
    assert_eq!(status["platform_kind"], "face_id");
    assert_eq!(
        err_code(&b, "biometric_set_enabled", json!({ "enabled": false })),
        "unknown_command"
    );

    // Locking closes the key session: the native store refuses reads.
    ok(&b, "secwet_lock", json!({}));
    assert!(!KEY_SESSION.load(Ordering::SeqCst));
    BIO_RESULT.store(1, Ordering::SeqCst);
    assert_eq!(
        err_code(&b, "secwet_unlock", json!({})),
        "biometric_cancelled"
    );
    assert_eq!(err_code(&b, "labels_list", json!({})), "locked");
    BIO_RESULT.store(2, Ordering::SeqCst);
    assert_eq!(err_code(&b, "secwet_unlock", json!({})), "biometric_failed");
    BIO_RESULT.store(0, Ordering::SeqCst);
    ok(&b, "secwet_unlock", json!({}));
    assert_eq!(BIO_PROMPTS.load(Ordering::SeqCst), 5);
    ok(&b, "labels_list", json!({}));

    // Passcode only (no biometric enrolled): still prompted, the OS asks for the passcode.
    ok(&b, "secwet_lock", json!({}));
    BIO_KIND.store(0, Ordering::SeqCst);
    let status = ok(&b, "biometric_status", json!({}));
    assert_eq!(status["available"], false);
    assert_eq!(status["enabled"], true);
    ok(&b, "secwet_unlock", json!({}));
    assert_eq!(BIO_PROMPTS.load(Ordering::SeqCst), 6);
}

#[test]
fn no_screen_lock_is_refused() {
    let _g = serial();
    reset_platform();
    DEVICE_LOCK.store(0, Ordering::SeqCst);
    let dir = tempfile::tempdir().unwrap();
    let b = bridge_for(platform(), dir.path().to_path_buf(), "Phone".into());

    // Nothing is created or opened without a screen lock; the recovery key
    // is never a way in.
    assert_eq!(
        err_code(&b, "secwet_create", json!({})),
        "screen_lock_required"
    );
    let status = ok(&b, "biometric_status", json!({}));
    assert_eq!(status["device_lock"], false);
    assert!(status.get("recovery_required").is_none());
    assert_eq!(
        err_code(&b, "secwet_unlock", json!({})),
        "screen_lock_required"
    );
    assert_eq!(
        err_code(
            &b,
            "secwet_unlock",
            json!({ "recovery_key": "AAAAA-AAAAA-AAAAA-AAAAA-AAAAA" })
        ),
        "screen_lock_required"
    );
}

#[test]
fn c_abi_round_trip_events_and_free() {
    let _g = serial();
    reset_platform();
    let dir = tempfile::tempdir().unwrap();
    let p = platform();
    let dir_s = dir.path().to_str().unwrap().to_owned();
    let name = "Pixel 9";

    // SAFETY: valid platform and buffers.
    unsafe {
        assert_eq!(
            secwet_ffi::secwet_ffi_register_platform(
                std::ptr::null(),
                dir_s.as_ptr(),
                dir_s.len(),
                name.as_ptr(),
                name.len()
            ),
            -1
        );
        assert_eq!(
            secwet_ffi::secwet_ffi_register_platform(
                &p,
                dir_s.as_ptr(),
                dir_s.len(),
                name.as_ptr(),
                name.len()
            ),
            0
        );
        assert_eq!(
            secwet_ffi::secwet_ffi_register_platform(
                &p,
                dir_s.as_ptr(),
                dir_s.len(),
                name.as_ptr(),
                name.len()
            ),
            1
        );
    }
    secwet_ffi::secwet_ffi_set_event_callback(Some(on_event));

    let c = |cmd: &str, args: Value| -> Value {
        let req = serde_json::to_vec(&json!({ "cmd": cmd, "args": args })).unwrap();
        let mut len = 0usize;
        // SAFETY: valid request buffer and out pointer; the result is freed once.
        unsafe {
            let ptr = secwet_ffi::secwet_ffi_call(req.as_ptr(), req.len(), &mut len);
            let v: Value = serde_json::from_slice(std::slice::from_raw_parts(ptr, len)).unwrap();
            secwet_ffi::secwet_ffi_free(ptr, len);
            v
        }
    };

    assert_eq!(c("secwet_create", json!({}))["ok"]["status"], "unlocked");
    c("space_create", json!({ "name": "Personal 2" }));
    c("secwet_lock", json!({}));
    let events = EVENTS.lock().unwrap().clone();
    assert!(
        events
            .iter()
            .any(|e| e.contains("secwet://changed") && e.contains("\"spaces\"")),
        "{events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("secwet://locked")),
        "{events:?}"
    );
    secwet_ffi::secwet_ffi_set_event_callback(None);

    // Null request with a length is rejected without touching memory.
    let mut len = 0usize;
    // SAFETY: null request is handled; result freed once.
    unsafe {
        let ptr = secwet_ffi::secwet_ffi_call(std::ptr::null(), 4, &mut len);
        let v: Value = serde_json::from_slice(std::slice::from_raw_parts(ptr, len)).unwrap();
        assert_eq!(v["err"]["code"], "invalid");
        secwet_ffi::secwet_ffi_free(ptr, len);
        secwet_ffi::secwet_ffi_free(std::ptr::null_mut(), 0);
    }
}

#[test]
fn recovery_key_export_and_restore() {
    let _g = serial();
    reset_platform();
    let dir = tempfile::tempdir().unwrap();
    let b = bridge_for(platform(), dir.path().join("a"), "Phone A".into());
    ok(&b, "secwet_create", json!({}));
    ok(&b, "space_create", json!({ "name": "Carried over" }));
    let key = ok(&b, "recovery_key_create", json!({}));
    let key = key.as_str().unwrap().to_owned();
    let archive = dir.path().join("backup.secwet");
    let summary = ok(
        &b,
        "workspace_export",
        json!({ "path": archive, "recovery_key": key }),
    );
    assert!(summary["bytes_written"].as_u64().unwrap() > 0);

    let restored = bridge_for(platform(), dir.path().join("b"), "Phone B".into());
    let status = ok(
        &restored,
        "workspace_restore",
        json!({ "path": archive, "recovery_key": key }),
    );
    assert_eq!(status["status"], "unlocked");
    let spaces = ok(&restored, "spaces_list", json!({}));
    assert!(spaces
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["name"] == "Carried over"));
    assert_eq!(
        err_code(
            &restored,
            "workspace_restore",
            json!({ "recovery_key": key })
        ),
        "invalid"
    );
}

/// F13 through the phone's JSON contract: a Free store answers every relay
/// command with `needs_pro` and never opens a connection, even with a relay
/// address set. The relay is a listener that counts connections.
#[test]
fn free_plan_never_contacts_the_relay_from_the_phone() {
    let _g = serial();
    reset_platform();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let hits = std::sync::Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            counter.fetch_add(1, Ordering::SeqCst);
            drop(conn);
        }
    });

    let dir = tempfile::tempdir().unwrap();
    let b = bridge_for(platform(), dir.path().to_path_buf(), "Phone".into());
    ok(&b, "secwet_create", json!({}));
    ok(&b, "relay_set_url", json!({ "url": url }));

    let plan = ok(&b, "plan_status", json!({}));
    assert_eq!(plan["plan"], "free");
    assert_eq!(ok(&b, "plan_refresh", json!({}))["plan"], "free");
    assert_eq!(ok(&b, "relay_status", json!({}))["connected"], false);
    for cmd in ["sync_now", "pairing_start", "key_rotate", "members_list"] {
        assert_eq!(err_code(&b, cmd, json!({})), "needs_pro", "{cmd}");
    }
    assert_eq!(
        err_code(
            &b,
            "member_invite",
            json!({ "email": "a@example.com", "grants": [] })
        ),
        "needs_pro"
    );
    // Local data keeps working.
    ok(&b, "space_create", json!({ "name": "Work" }));
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "a Free phone contacted the relay"
    );
}
