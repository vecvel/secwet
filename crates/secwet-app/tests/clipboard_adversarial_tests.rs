//! Empirical Challenger Test Suite: Clipboard Auto-Clear & Secret Isolation.
//!
//! Validates:
//! 1. Expiration behavior across diverse payloads (empty, large, unicode, pre-cleared).
//! 2. Foreign content preservation against adversarial mutations (prefix, suffix, substring, off-by-one, case).
//! 3. Interleaved recopy and monotonic generation counter correctness under concurrency.
//! 4. Constant-time equality verification (subtle::ConstantTimeEq) and bypass resistance.
//! 5. Secret isolation: zero plaintext leakage in clipboard manager state or command APIs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use secwet_core::keys::MemoryStore;
use secwet_core::model::SecretKind;
use secwet_app::clipboard::{AutoClearManager, ClipboardPort};
use secwet_app::commands::SecretDraftDto;
use secwet_app::state::AppState;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tempfile::tempdir;

/// Thread-safe mock clipboard with invocation telemetry for empirical verification.
#[derive(Default)]
struct InstrumentedTestClipboard {
    data: Mutex<Option<String>>,
    pub write_count: AtomicU64,
    pub clear_count: AtomicU64,
    pub read_count: AtomicU64,
}

impl ClipboardPort for InstrumentedTestClipboard {
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

/// Helper that polls with timeout to handle threadpool scheduling jitter under high CPU load.
async fn wait_until_cleared(cb: &InstrumentedTestClipboard, timeout: Duration) -> bool {
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
// 1. Expiration Behavior Tests
// ============================================================================

#[tokio::test]
async fn test_expiration_standard_payload() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    manager.copy_secret("secwet_api_key_sample_12345").unwrap();
    assert_eq!(cb.read_text().unwrap(), "secwet_api_key_sample_12345");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);

    // Mid-interval check: secret still present at t=25ms
    tokio::time::sleep(Duration::from_millis(25)).await;
    assert_eq!(cb.read_text().unwrap(), "secwet_api_key_sample_12345");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);

    // Post-interval check: secret cleared after timer elapses
    assert!(wait_until_cleared(&cb, Duration::from_millis(500)).await);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_expiration_empty_string_secret() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(40));

    // Copying empty string should hash successfully without panic
    manager.copy_secret("").unwrap();
    assert_eq!(cb.read_text().unwrap(), "");

    // Cleared after expiration
    assert!(wait_until_cleared(&cb, Duration::from_millis(500)).await);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_expiration_large_multiline_payload() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    // 128 KiB secret payload with mixed characters and newlines
    let large_secret = "SECWET_CHUNK_0123456789_ABCDEF\n".repeat(4096);
    manager.copy_secret(&large_secret).unwrap();
    assert_eq!(cb.read_text().unwrap().len(), large_secret.len());

    assert!(wait_until_cleared(&cb, Duration::from_millis(500)).await);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_expiration_unicode_and_special_characters() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    // Multi-byte Unicode, emojis, null-escapes, zero-width joiners
    let unicode_secret = "🔐🔑 سِرِّي_جِداً \u{200B} \u{0000} \u{1F980} \t\r\n";
    manager.copy_secret(unicode_secret).unwrap();
    assert_eq!(cb.read_text().unwrap(), unicode_secret);

    assert!(wait_until_cleared(&cb, Duration::from_millis(500)).await);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_expiration_when_clipboard_already_empty() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    manager.copy_secret("token_to_manually_clear").unwrap();

    // User or third-party app clears clipboard at t=20ms
    tokio::time::sleep(Duration::from_millis(20)).await;
    cb.clear().unwrap();
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);

    // Timer expires at t=70ms; should gracefully handle read_text error and not re-clear
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1); // Remains 1, not 2
}

// ============================================================================
// 2. Foreign Content Preservation (Adversarial Mutations)
// ============================================================================

#[tokio::test]
async fn test_foreign_content_preservation_url() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    manager.copy_secret("secret_alpha").unwrap();

    // External copy at t=20ms
    tokio::time::sleep(Duration::from_millis(20)).await;
    *cb.data.lock().unwrap() = Some("https://github.com/secwet/secwet".to_string());

    // Timer fires at t=70ms; external URL MUST remain intact
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cb.read_text().unwrap(), "https://github.com/secwet/secwet");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_foreign_content_prefix_attack_preserved() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    let secret = "sk-live-999888777666555444333";
    manager.copy_secret(secret).unwrap();

    // User copies strict prefix of secret
    tokio::time::sleep(Duration::from_millis(20)).await;
    *cb.data.lock().unwrap() = Some("sk-live-999888777".to_string());

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cb.read_text().unwrap(), "sk-live-999888777");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_foreign_content_suffix_attack_preserved() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    let secret = "sk-live-999888777666555444333";
    manager.copy_secret(secret).unwrap();

    // User copies strict suffix of secret
    tokio::time::sleep(Duration::from_millis(20)).await;
    *cb.data.lock().unwrap() = Some("666555444333".to_string());

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cb.read_text().unwrap(), "666555444333");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_foreign_content_single_bit_flip_preserved() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    let secret = "SuperSecretPassword123!";
    manager.copy_secret(secret).unwrap();

    // Tamper single byte: '!' (0x21) -> '?' (0x3F)
    tokio::time::sleep(Duration::from_millis(20)).await;
    *cb.data.lock().unwrap() = Some("SuperSecretPassword123?".to_string());

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cb.read_text().unwrap(), "SuperSecretPassword123?");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_foreign_content_case_sensitivity_preserved() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    let secret = "ExactCaseKey_ABC";
    manager.copy_secret(secret).unwrap();

    // Changed case
    tokio::time::sleep(Duration::from_millis(20)).await;
    *cb.data.lock().unwrap() = Some("exactcasekey_abc".to_string());

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cb.read_text().unwrap(), "exactcasekey_abc");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn test_foreign_content_trailing_whitespace_preserved() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    let secret = "token123";
    manager.copy_secret(secret).unwrap();

    // Added trailing newline or space
    tokio::time::sleep(Duration::from_millis(20)).await;
    *cb.data.lock().unwrap() = Some("token123\n".to_string());

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(cb.read_text().unwrap(), "token123\n");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);
}

// ============================================================================
// 3. Interleaved Recopy & Concurrency Stress Tests
// ============================================================================

#[tokio::test]
async fn test_interleaved_recopy_timing_sequence() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    // 60ms timer
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(60));

    // t=0: Copy secret 1
    manager.copy_secret("secret_token_1").unwrap();
    assert_eq!(cb.read_text().unwrap(), "secret_token_1");

    // t=25ms: Copy secret 2
    tokio::time::sleep(Duration::from_millis(25)).await;
    manager.copy_secret("secret_token_2").unwrap();
    assert_eq!(cb.read_text().unwrap(), "secret_token_2");

    // t=70ms: Secret 1 timer (elapsed at t=60ms) fired, but secret 2 MUST NOT be cleared
    tokio::time::sleep(Duration::from_millis(45)).await;
    assert_eq!(cb.read_text().unwrap(), "secret_token_2");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);

    // Post-expiry: Secret 2 timer (fires at t=85ms) clears secret 2
    assert!(wait_until_cleared(&cb, Duration::from_millis(500)).await);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_recopy_same_secret_cancels_previous_timer() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(60));

    // t=0: Copy secret A
    manager.copy_secret("secret_same_value").unwrap();

    // t=30ms: Recopy exact same secret A
    tokio::time::sleep(Duration::from_millis(30)).await;
    manager.copy_secret("secret_same_value").unwrap();

    // t=70ms: Timer 1 has expired (at t=60ms), but token was incremented. Secret must remain!
    tokio::time::sleep(Duration::from_millis(40)).await;
    assert_eq!(cb.read_text().unwrap(), "secret_same_value");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);

    // Timer 2 expires (at t=90ms). Secret is cleared.
    assert!(wait_until_cleared(&cb, Duration::from_millis(500)).await);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_concurrent_rapid_burst_copies() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = Arc::new(AutoClearManager::new(
        Arc::clone(&cb),
        Arc::clone(&gen),
        Duration::from_millis(60),
    ));

    // Spawn 20 tasks concurrently copying distinct secrets
    let mut handles = Vec::new();
    for i in 0..20 {
        let mgr = Arc::clone(&manager);
        handles.push(tokio::spawn(async move {
            let secret = format!("burst_secret_{:02}", i);
            mgr.copy_secret(&secret).unwrap();
        }));
    }

    for h in handles {
        h.await.unwrap();
    }

    // Monotonic generation counter should have reached 20 exactly
    assert_eq!(gen.load(Ordering::SeqCst), 20);

    // Wait until all burst timers have passed
    assert!(wait_until_cleared(&cb, Duration::from_millis(500)).await);
    // Only the winning generation should have called clear()
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn test_sandwich_external_copy_between_secrets() {
    let cb = Arc::new(InstrumentedTestClipboard::default());
    let gen = Arc::new(AtomicU64::new(0));
    let manager = AutoClearManager::new(Arc::clone(&cb), gen, Duration::from_millis(50));

    // Copy secret 1
    manager.copy_secret("secret_one").unwrap();

    // User pastes foreign text at t=15ms
    tokio::time::sleep(Duration::from_millis(15)).await;
    *cb.data.lock().unwrap() = Some("foreign_intermediate".to_string());

    // Copy secret 2 at t=30ms
    tokio::time::sleep(Duration::from_millis(15)).await;
    manager.copy_secret("secret_two").unwrap();

    // User pastes foreign text again at t=45ms
    tokio::time::sleep(Duration::from_millis(15)).await;
    *cb.data.lock().unwrap() = Some("foreign_final".to_string());

    // Wait past all timers (t=110ms)
    tokio::time::sleep(Duration::from_millis(65)).await;

    // Foreign text must NOT be cleared by either timer
    assert_eq!(cb.read_text().unwrap(), "foreign_final");
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 0);
}

// ============================================================================
// 4. Constant-Time Equality & Subtle Fingerprint Tests
// ============================================================================

#[test]
fn test_constant_time_equality_full_exhaustive_bit_flips() {
    let secret = "ProductionMasterSecretPassword987!";
    let mut hasher = Sha256::new();
    hasher.update(secret.as_bytes());
    let expected_hash: [u8; 32] = hasher.finalize().into();

    // 1. Identical hash matches
    assert!(bool::from(expected_hash.ct_eq(&expected_hash)));

    // 2. Flip each of the 256 bits across all 32 bytes individually
    for byte_idx in 0..32 {
        for bit_idx in 0..8 {
            let mut tampered_hash = expected_hash;
            tampered_hash[byte_idx] ^= 1 << bit_idx;

            // Must evaluate to false
            let eq = bool::from(tampered_hash.ct_eq(&expected_hash));
            assert!(
                !eq,
                "Bypass detected: bit flip at byte {} bit {} unexpectedly matched",
                byte_idx, bit_idx
            );
        }
    }

    // 3. Inverted hash
    let inverted: [u8; 32] = expected_hash.map(|b| !b);
    assert!(!bool::from(inverted.ct_eq(&expected_hash)));

    // 4. All zeros vs expected
    let zeros = [0u8; 32];
    assert!(!bool::from(zeros.ct_eq(&expected_hash)));
}

#[test]
fn test_constant_time_comparison_timing_invariance() {
    let h1 = [0x55u8; 32];
    let h2_match = [0x55u8; 32];

    // Mismatches at different byte positions
    let mut h2_mismatch_first = [0x55u8; 32];
    h2_mismatch_first[0] = 0xAA;

    let mut h2_mismatch_middle = [0x55u8; 32];
    h2_mismatch_middle[16] = 0xAA;

    let mut h2_mismatch_last = [0x55u8; 32];
    h2_mismatch_last[31] = 0xAA;

    const ITERATIONS: usize = 100_000;

    // Warm-up
    let mut sink = 0u64;
    for _ in 0..1000 {
        sink += bool::from(h1.ct_eq(&h2_match)) as u64;
    }

    // Measure match
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        sink += bool::from(h1.ct_eq(&h2_match)) as u64;
    }
    let duration_match = start.elapsed();

    // Measure mismatch at first byte
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        sink += bool::from(h1.ct_eq(&h2_mismatch_first)) as u64;
    }
    let duration_first = start.elapsed();

    // Measure mismatch at middle byte
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        sink += bool::from(h1.ct_eq(&h2_mismatch_middle)) as u64;
    }
    let duration_middle = start.elapsed();

    // Measure mismatch at last byte
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        sink += bool::from(h1.ct_eq(&h2_mismatch_last)) as u64;
    }
    let duration_last = start.elapsed();

    assert!(sink > 0);

    // Verify executions completed without extreme variance (sanity check for constant-time subtle)
    let max_dur = duration_match
        .max(duration_first)
        .max(duration_middle)
        .max(duration_last);
    let min_dur = duration_match
        .min(duration_first)
        .min(duration_middle)
        .min(duration_last);

    // In constant-time operations, execution times across 100k iterations stay within reasonable variance
    let ratio = max_dur.as_nanos() as f64 / min_dur.as_nanos().max(1) as f64;
    assert!(
        ratio < 5.0,
        "Timing variance unexpectedly high: ratio={:.2} (min={:?}, max={:?})",
        ratio,
        min_dur,
        max_dur
    );
}

// ============================================================================
// 5. Secret Isolation & Zero Webview Plaintext Leakage
// ============================================================================

#[tokio::test]
async fn test_secret_copy_zero_webview_leakage_and_metadata_isolation() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let mut state = AppState::new(dir.path().to_path_buf(), keystore);
    state.clear_duration = Duration::from_millis(50);

    let cb = Arc::new(InstrumentedTestClipboard::default());

    // Initialize secwet
    state.secwet_create(Some("test-device".into())).unwrap();
    let proj =
        state.project_create("SecurityProj".into(), vec!["Prod".into()]).unwrap();
    let env_id = proj.environments[0].id;

    let secret_plain = "SUPER_SECRET_PAYLOAD_NEVER_LEAK_TO_WEBVIEW_OR_LOGS";
    let draft = SecretDraftDto {
        item_id: Some(proj.id),
        project_id: Some(proj.id),
        environment_id: Some(env_id),
        name: "API_SECRET".into(),
        kind: SecretKind::ApiKey,
        value: secret_plain.into(),
        note: Some("Confidential API Token".into()),
    };

    let meta = state.secret_create(draft).unwrap();

    // Invariant 1: `secret_create` returns SecretMeta with masked value_tail, NEVER full plaintext
    assert_ne!(meta.value_tail, secret_plain);
    assert_eq!(meta.value_tail, "LOGS"); // last 4 chars

    // Invariant 2: `secrets_list` returns only metadata with value_tail, NEVER plaintext
    let listed = state.secrets_list(None, Some(env_id)).unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].value_tail, "LOGS");

    // Invariant 3: `overview` contains counts and names, NEVER plaintext
    let ov = state.overview().unwrap();
    assert_eq!(ov.secrets_count, 1);
    for recent in &ov.recent {
        assert_ne!(recent.name, secret_plain);
    }

    // Invariant 4: `secret_copy` returns unit () to caller, NOT the plaintext
    let copy_result: () = state.secret_copy(Arc::clone(&cb), meta.id).unwrap();
    assert_eq!(copy_result, ());

    // Secret was written to OS clipboard
    assert_eq!(cb.read_text().unwrap(), secret_plain);

    // Invariant 5: `secret_reveal` exposes plaintext only when explicitly commanded
    let revealed = state.secret_reveal(meta.id).unwrap();
    assert_eq!(revealed, secret_plain);

    // After duration, clipboard auto-clears
    assert!(wait_until_cleared(&cb, Duration::from_millis(500)).await);
    assert_eq!(cb.clear_count.load(Ordering::SeqCst), 1);
}
