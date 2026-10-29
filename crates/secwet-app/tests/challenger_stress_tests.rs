//! Empirical Challenger Stress & Invariant Test Suite for Milestone 3.
//!
//! Objectives:
//! 1. Verify rapid lock/unlock during active auto-clear timers.
//! 2. Verify foreign clipboard content is preserved across rapid lifecycle transitions.
//! 3. Verify concurrent burst copies with interleaved secwet locking and unlocking.
//! 4. Verify absolute zero secret leakage in all UiError variants, DTOs, and Debug representations.
//! 5. Verify rich-text note plain text clipboard extraction, isolation, and auto-clear.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use secwet_core::keys::MemoryStore;
use secwet_core::model::SecretKind;
use secwet_app::clipboard::{extract_plain_text, ClipboardPort};
use secwet_app::commands::{NoteDraftDto, SecretDraftDto};
use secwet_app::error::UiError;
use secwet_app::state::{AppState, SecwetStatusDto};
use tempfile::tempdir;

#[derive(Default)]
struct ChallengerMockClipboard {
    data: Mutex<Option<String>>,
    pub write_count: AtomicU64,
    pub clear_count: AtomicU64,
    pub read_count: AtomicU64,
}

impl ClipboardPort for ChallengerMockClipboard {
    fn write_secret(&self, text: &str) -> Result<(), String> {
        self.write_count.fetch_add(1, Ordering::SeqCst);
        *self.data.lock().unwrap() = Some(text.to_string());
        Ok(())
    }

    fn read_text(&self) -> Result<String, String> {
        self.read_count.fetch_add(1, Ordering::SeqCst);
        self.data
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "Empty".to_string())
    }

    fn clear(&self) -> Result<(), String> {
        self.clear_count.fetch_add(1, Ordering::SeqCst);
        *self.data.lock().unwrap() = None;
        Ok(())
    }
}

async fn wait_for_clear_or_timeout(
    cb: &ChallengerMockClipboard,
    timeout: Duration,
) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if cb.read_text().is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    cb.read_text().is_err()
}

// ============================================================================
// Test 1: Rapid Lock/Unlock During Active Auto-Clear
// ============================================================================

#[tokio::test]
async fn test_adversarial_rapid_lock_unlock_during_active_autoclear() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let mut state = AppState::new(dir.path().to_path_buf(), keystore);
    state.clear_duration = Duration::from_millis(60);
    let state = Arc::new(state);

    let cb = Arc::new(ChallengerMockClipboard::default());

    // Initialize secwet
    state.secwet_create(Some("ChallengerDevice".into())).unwrap();
    let label = state.label_create("Engineering".into(), None).unwrap();
    let item = state.item_create(label.id, "CoreAPI".into(), None).unwrap();

    let canary_secret = "CANARY_SECRET_AUTO_CLEAR_RACE_TEST_777";
    let draft = SecretDraftDto {
        item_id: Some(item.id),
        project_id: Some(item.id),
        environment_id: None,
        name: "DB_PASSWORD".into(),
        kind: SecretKind::Password,
        value: canary_secret.into(),
        note: None,
    };
    let meta = state.secret_create(draft).unwrap();

    // Copy secret: written to clipboard, 60ms timer starts
    state.secret_copy(Arc::clone(&cb), meta.id).unwrap();
    assert_eq!(cb.read_text().unwrap(), canary_secret);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);

    // Rapidly toggle lock and unlock 40 times while timer is actively ticking
    let s_clone = Arc::clone(&state);
    let lifecycle_handle = thread::spawn(move || {
        for _ in 0..40 {
            let _ = s_clone.secwet_lock();
            thread::yield_now();
            let _ = s_clone.secwet_unlock();
            thread::yield_now();
        }
        // End in locked state to test clearing even when secwet is locked
        let _ = s_clone.secwet_lock();
    });

    lifecycle_handle.join().unwrap();

    // Verify secwet is currently locked
    match state.secwet_status().unwrap() {
        SecwetStatusDto::Locked { .. } => {}
        status => panic!("Expected Locked status, got {:?}", status),
    }

    // Wait until timer elapses and clipboard is cleared
    let cleared = wait_for_clear_or_timeout(&cb, Duration::from_millis(500)).await;
    assert!(
        cleared,
        "Clipboard must be cleared after timeout even if secwet was locked during auto-clear"
    );
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);

    // Unlock and verify secwet state remains completely intact
    state.secwet_unlock().unwrap();
    let revealed = state.secret_reveal(meta.id).unwrap();
    assert_eq!(revealed, canary_secret);
}

// ============================================================================
// Test 2: Foreign Clipboard Overwrite Survives Rapid Lock/Unlock
// ============================================================================

#[tokio::test]
async fn test_adversarial_foreign_overwrite_survives_rapid_lock_unlock() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let mut state = AppState::new(dir.path().to_path_buf(), keystore);
    state.clear_duration = Duration::from_millis(60);
    let state = Arc::new(state);

    let cb = Arc::new(ChallengerMockClipboard::default());

    state.secwet_create(Some("DevHost".into())).unwrap();
    let label = state.label_create("Ops".into(), None).unwrap();
    let item = state.item_create(label.id, "Cluster".into(), None).unwrap();

    let secret_val = "SUPER_SECRET_TO_BE_OVERWRITTEN_EXTERNALLY";
    let draft = SecretDraftDto {
        item_id: Some(item.id),
        project_id: Some(item.id),
        environment_id: None,
        name: "SSH_KEY".into(),
        kind: SecretKind::SshKey,
        value: secret_val.into(),
        note: None,
    };
    let meta = state.secret_create(draft).unwrap();

    // Copy secret
    state.secret_copy(Arc::clone(&cb), meta.id).unwrap();
    assert_eq!(cb.read_text().unwrap(), secret_val);

    // External program overwrites clipboard at t=15ms
    tokio::time::sleep(Duration::from_millis(15)).await;
    let foreign_text = "https://internal-docs.company.net/rfc/4928?token=user123";
    *cb.data.lock().unwrap() = Some(foreign_text.to_string());

    // Concurrently trigger rapid lock/unlock cycles
    let s_clone = Arc::clone(&state);
    let lifecycle_handle = thread::spawn(move || {
        for _ in 0..30 {
            let _ = s_clone.secwet_lock();
            thread::yield_now();
            let _ = s_clone.secwet_unlock();
            thread::yield_now();
        }
    });

    lifecycle_handle.join().unwrap();

    // Wait past timer duration (total 150ms)
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Foreign text must NOT be cleared or tampered with
    assert_eq!(cb.read_text().unwrap(), foreign_text);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);
}

// ============================================================================
// Test 3: Burst Copies With Interleaved Secwet Locking and Unlocking
// ============================================================================

#[test]
fn test_adversarial_burst_copies_with_interleaved_locking() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let mut state = AppState::new(dir.path().to_path_buf(), keystore);
    state.clear_duration = Duration::from_millis(50);
    let state = Arc::new(state);

    let cb = Arc::new(ChallengerMockClipboard::default());

    state.secwet_create(Some("StressBench".into())).unwrap();
    let label = state.label_create("Services".into(), None).unwrap();
    let item = state.item_create(label.id, "AuthService".into(), None).unwrap();

    // Seed 10 secrets
    let mut secret_ids = Vec::new();
    for i in 0..10 {
        let draft = SecretDraftDto {
            item_id: Some(item.id),
            project_id: Some(item.id),
            environment_id: None,
            name: format!("BURST_SECRET_{}", i),
            kind: SecretKind::Password,
            value: format!("burst_val_{}", i),
            note: None,
        };
        let meta = state.secret_create(draft).unwrap();
        secret_ids.push(meta.id);
    }

    let secret_ids = Arc::new(secret_ids);
    let running = Arc::new(AtomicBool::new(true));
    let num_copiers = 8;
    let barrier = Arc::new(Barrier::new(num_copiers + 1));
    let mut handles = Vec::new();

    let successful_copies = Arc::new(AtomicUsize::new(0));
    let locked_rejections = Arc::new(AtomicUsize::new(0));

    // Spawn 8 copy workers
    for copier_id in 0..num_copiers {
        let s = Arc::clone(&state);
        let c = Arc::clone(&cb);
        let ids = Arc::clone(&secret_ids);
        let r = Arc::clone(&running);
        let b = Arc::clone(&barrier);
        let succ = Arc::clone(&successful_copies);
        let lock_rej = Arc::clone(&locked_rejections);

        handles.push(thread::spawn(move || {
            b.wait();
            let mut iter = 0;
            while r.load(Ordering::Relaxed) {
                let id = ids[iter % ids.len()];
                iter += 1;
                match s.secret_copy(Arc::clone(&c), id) {
                    Ok(()) => {
                        succ.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) if e.code == "locked" => {
                        lock_rej.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => {
                        panic!("Unexpected error in copier {}: {:?}", copier_id, e);
                    }
                }
                thread::yield_now();
            }
        }));
    }

    // Lifecycle controller: rapid lock/unlock
    let s_ctrl = Arc::clone(&state);
    let b_ctrl = Arc::clone(&barrier);
    let ctrl_handle = thread::spawn(move || {
        b_ctrl.wait();
        for _ in 0..50 {
            let _ = s_ctrl.secwet_lock();
            thread::sleep(Duration::from_millis(1));
            let _ = s_ctrl.secwet_unlock();
            thread::sleep(Duration::from_millis(1));
        }
    });

    ctrl_handle.join().unwrap();
    running.store(false, Ordering::SeqCst);

    for h in handles {
        h.join().unwrap();
    }

    let total_succ = successful_copies.load(Ordering::SeqCst);
    let total_rej = locked_rejections.load(Ordering::SeqCst);
    println!(
        "[Burst Copies Interleaved] successful_copies={}, locked_rejections={}",
        total_succ, total_rej
    );

    assert!(total_succ > 0, "Expected successful copies");
    assert!(total_rej > 0, "Expected locked rejections during locking phases");
}

// ============================================================================
// Test 4: Absolute Zero Secret Leakage in Error Display, DTOs & Debug
// ============================================================================

#[test]
fn test_adversarial_zero_secret_leakage_in_error_display_and_debug() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);
    let canary = "CANARY_SENSITIVE_CREDENTIAL_VALUE_DO_NOT_LEAK_123456789";

    // 1. Invariant check on UiError mappings
    let err_invalid = UiError::invalid("secret", "invalid secret format");
    assert!(!format!("{:?}", err_invalid).contains(canary));
    assert!(!format!("{}", err_invalid).contains(canary));

    // Verify all 17 secwet_core::Error variants format without sensitive leakage
    let errors: Vec<secwet_core::Error> = vec![
        secwet_core::Error::Locked,
        secwet_core::Error::NotInitialized,
        secwet_core::Error::AlreadyInitialized,
        secwet_core::Error::NotFound,
        secwet_core::Error::Invalid {
            field: "value",
            message: "Payload cannot exceed size limit".into(),
        },
        secwet_core::Error::Duplicate { field: "name" },
        secwet_core::Error::LastEnvironment,
        secwet_core::Error::NeedsPro,
        secwet_core::Error::DeviceLimit,
        secwet_core::Error::Revoked,
        secwet_core::Error::RecoveryFailed,
        secwet_core::Error::Offline,
        secwet_core::Error::Relay {
            code: "ERR_RATE_LIMITED".into(),
        },
        secwet_core::Error::KeyStore,
        secwet_core::Error::Storage,
        secwet_core::Error::Crypto,
        secwet_core::Error::Unimplemented("cloud_sync"),
    ];

    for core_err in errors {
        let ui_err = UiError::from(core_err);
        let debug_str = format!("{:?}", ui_err);
        let disp_str = format!("{}", ui_err);
        let json_str = serde_json::to_string(&ui_err).unwrap();

        assert!(!debug_str.contains(canary));
        assert!(!disp_str.contains(canary));
        assert!(!json_str.contains(canary));
        // Crypto errors must strictly say only generic message
        if ui_err.code == "crypto_error" {
            assert_eq!(ui_err.message, "This item could not be decrypted.");
        }
    }

    // 2. SecretMeta and Overview serialization must never contain the full canary
    state.secwet_create(Some("LeakTestNode".into())).unwrap();
    let label = state.label_create("SecwetGroup".into(), None).unwrap();
    let item = state.item_create(label.id, "ItemWithSecret".into(), None).unwrap();

    let meta = state.secret_create(SecretDraftDto {
            item_id: Some(item.id),
            project_id: Some(item.id),
            environment_id: None,
            name: "API_TOKEN".into(),
            kind: SecretKind::ApiKey,
            value: canary.into(),
            note: Some("Production key".into()),
        },
    )
    .unwrap();

    // Check meta Debug and JSON serialization
    let meta_debug = format!("{:?}", meta);
    let meta_json = serde_json::to_string(&meta).unwrap();
    assert!(
        !meta_debug.contains(canary),
        "SecretMeta debug leaked plaintext canary!"
    );
    assert!(
        !meta_json.contains(canary),
        "SecretMeta JSON leaked plaintext canary!"
    );
    assert_eq!(meta.value_tail, "6789");

    // Check overview
    let ov = state.overview().unwrap();
    let ov_json = serde_json::to_string(&ov).unwrap();
    assert!(!ov_json.contains(canary), "Overview JSON leaked canary!");

    // Check secrets_list
    let listed = state.secrets_list(Some(item.id), None).unwrap();
    let listed_json = serde_json::to_string(&listed).unwrap();
    assert!(
        !listed_json.contains(canary),
        "secrets_list JSON leaked canary!"
    );
}

// ============================================================================
// Test 5: Rich-Text Note Plain Text Extraction, Isolation & Auto-Clear
// ============================================================================

#[tokio::test]
async fn test_adversarial_note_copy_plain_and_clipboard_text_concurrency() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let mut state = AppState::new(dir.path().to_path_buf(), keystore);
    state.clear_duration = Duration::from_millis(60);
    let state = Arc::new(state);

    let cb = Arc::new(ChallengerMockClipboard::default());

    state.secwet_create(Some("NoteNode".into())).unwrap();
    let label = state.label_create("NotesLabel".into(), None).unwrap();
    let item = state.item_create(label.id, "NoteItem".into(), None).unwrap();

    // 1. Verify extract_plain_text strips adversarial HTML/scripts correctly
    let adversarial_html = "<h1>Confidential Architecture</h1><script>alert('pwned');</script><p>Key server: <b>10.0.0.5</b></p><div onclick=\"eval('bad')\">Password: <code>xyz999</code></div>";
    let extracted = extract_plain_text(adversarial_html);
    assert!(!extracted.contains("<script>"));
    assert!(!extracted.contains("alert('pwned')"));
    assert!(!extracted.contains("onclick"));
    assert!(extracted.contains("Confidential Architecture"));
    assert!(extracted.contains("Key server: 10.0.0.5"));
    assert!(extracted.contains("Password: xyz999"));

    // 2. Create note in secwet
    let note_meta = state.note_create(NoteDraftDto {
            item_id: item.id,
            environment_id: None,
            title: "Arch Note".into(),
            content: adversarial_html.into(),
        },
    )
    .unwrap();

    // 3. note_copy_plain: sets extracted plain text onto clipboard
    state.note_copy_plain(Arc::clone(&cb), note_meta.id).unwrap();
    let cb_content = cb.read_text().unwrap();
    assert!(cb_content.contains("Confidential Architecture"));
    assert!(!cb_content.contains("<script>"));

    // 4. Auto-clear timer clears note plain text after duration
    assert!(wait_for_clear_or_timeout(&cb, Duration::from_millis(500)).await);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);

    // 5. clipboard_copy_text: copies raw text and respects locked
    state.clipboard_copy_text(Arc::clone(&cb), "<p>Direct text copy</p>".into(),
    )
    .unwrap();
    assert_eq!(cb.read_text().unwrap(), "Direct text copy");

    // Lock secwet
    state.secwet_lock().unwrap();

    // Copying text while locked must fail with locked
    let lock_err = state.clipboard_copy_text(Arc::clone(&cb), "Should fail".into(),
    )
    .unwrap_err();
    assert_eq!(lock_err.code, "locked");
}
