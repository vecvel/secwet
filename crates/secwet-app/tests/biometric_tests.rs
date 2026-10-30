//! Biometric unlock is enforced by the app layer, not the UI, is never
//! skipped while it is on, and leaves the recovery key as the way in when
//! the device has no check left.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use secwet_app::biometric::{BiometryKind, PresenceError, PresenceVerifier};
use secwet_app::AppState;
use secwet_core::keys::MemoryStore;
use tempfile::{tempdir, TempDir};

/// A scriptable stand-in for the OS prompt.
struct FakeVerifier {
    kind: Mutex<BiometryKind>,
    answer: Mutex<Result<(), PresenceError>>,
    prompts: AtomicUsize,
}

impl FakeVerifier {
    fn new(kind: BiometryKind) -> Arc<Self> {
        Arc::new(Self {
            kind: Mutex::new(kind),
            answer: Mutex::new(Ok(())),
            prompts: AtomicUsize::new(0),
        })
    }

    fn answer(&self, answer: Result<(), PresenceError>) {
        *self.answer.lock().unwrap() = answer;
    }

    fn set_kind(&self, kind: BiometryKind) {
        *self.kind.lock().unwrap() = kind;
    }

    fn prompts(&self) -> usize {
        self.prompts.load(Ordering::SeqCst)
    }
}

impl PresenceVerifier for FakeVerifier {
    fn kind(&self) -> BiometryKind {
        *self.kind.lock().unwrap()
    }

    fn verify(&self, _reason: &str) -> Result<(), PresenceError> {
        self.prompts.fetch_add(1, Ordering::SeqCst);
        self.answer.lock().unwrap().clone()
    }
}

fn setup(kind: BiometryKind) -> (TempDir, AppState, Arc<FakeVerifier>) {
    let dir = tempdir().unwrap();
    let state = AppState::new(dir.path().to_path_buf(), Arc::new(MemoryStore::new()));
    let verifier = FakeVerifier::new(kind);
    state.set_presence_verifier(verifier.clone());
    state.secwet_create(Some("Test Mac".into())).unwrap();
    (dir, state, verifier)
}

#[test]
fn test_status_reports_kind_and_starts_off() {
    let (_dir, state, _) = setup(BiometryKind::TouchId);
    let status = state.biometric_status().unwrap();
    assert!(status.available);
    assert_eq!(status.kind, BiometryKind::TouchId);
    assert!(!status.enabled);
    assert_eq!(
        serde_json::to_value(&status).unwrap(),
        serde_json::json!({ "available": true, "kind": "touch_id", "enabled": false })
    );
}

#[test]
fn test_no_biometrics_hides_the_feature_and_cannot_be_enabled() {
    let (_dir, state, verifier) = setup(BiometryKind::None);
    let status = state.biometric_status().unwrap();
    assert!(!status.available);
    assert!(!status.enabled);

    let err = state.biometric_set_enabled(true).unwrap_err();
    assert_eq!(err.code, "biometric_unavailable");
    assert_eq!(verifier.prompts(), 0);
}

#[test]
fn test_host_without_verifier_reports_none() {
    let dir = tempdir().unwrap();
    let state = AppState::new(dir.path().to_path_buf(), Arc::new(MemoryStore::new()));
    state.secwet_create(None).unwrap();
    let status = state.biometric_status().unwrap();
    assert_eq!(status.kind, BiometryKind::None);
    assert!(!status.available);
}

#[test]
fn test_enabling_requires_a_passing_check_and_an_open_store() {
    let (_dir, state, verifier) = setup(BiometryKind::WindowsHelloFingerprint);

    verifier.answer(Err(PresenceError::Cancelled));
    let err = state.biometric_set_enabled(true).unwrap_err();
    assert_eq!(err.code, "biometric_cancelled");
    assert!(!state.biometric_status().unwrap().enabled);

    verifier.answer(Ok(()));
    assert!(state.biometric_set_enabled(true).unwrap().enabled);

    state.secwet_lock().unwrap();
    // Locked: settings cannot be changed from the lock screen.
    assert_eq!(state.biometric_set_enabled(false).unwrap_err().code, "locked");
    // The flag is readable while locked, so the lock screen can name it.
    assert!(state.biometric_status().unwrap().enabled);
}

#[test]
fn test_unlock_is_refused_until_the_check_passes() {
    let (_dir, state, verifier) = setup(BiometryKind::TouchId);
    state.biometric_set_enabled(true).unwrap();
    state.secwet_lock().unwrap();
    let before = verifier.prompts();

    verifier.answer(Err(PresenceError::Cancelled));
    assert_eq!(state.secwet_unlock().unwrap_err().code, "biometric_cancelled");
    verifier.answer(Err(PresenceError::Failed));
    assert_eq!(state.secwet_unlock().unwrap_err().code, "biometric_failed");
    assert_eq!(state.items_list(None).unwrap_err().code, "locked");

    verifier.answer(Ok(()));
    state.secwet_unlock().unwrap();
    assert_eq!(verifier.prompts(), before + 3);

    // Already open: no second prompt.
    state.secwet_unlock().unwrap();
    assert_eq!(verifier.prompts(), before + 3);
}

#[test]
fn test_unlock_without_the_setting_never_prompts() {
    let (_dir, state, verifier) = setup(BiometryKind::TouchId);
    state.secwet_lock().unwrap();
    verifier.answer(Err(PresenceError::Failed));
    state.secwet_unlock().unwrap();
    assert_eq!(verifier.prompts(), 0);
}

#[test]
fn test_sensor_reading_as_missing_never_skips_the_check() {
    let (_dir, state, verifier) = setup(BiometryKind::TouchId);
    state.biometric_set_enabled(true).unwrap();
    state.secwet_lock().unwrap();

    // Lid closed or keyboard unplugged: the verifier still runs and offers
    // the OS owner check (here it fails, so unlock is refused).
    verifier.set_kind(BiometryKind::None);
    verifier.answer(Err(PresenceError::Failed));
    let prompts = verifier.prompts();
    assert_eq!(state.secwet_unlock().unwrap_err().code, "biometric_failed");
    assert_eq!(verifier.prompts(), prompts + 1);
    assert_eq!(state.items_list(None).unwrap_err().code, "locked");

    // Still shown as on, so the lock screen and Settings name it.
    assert!(state.biometric_status().unwrap().enabled);

    verifier.answer(Ok(()));
    state.secwet_unlock().unwrap();
}

#[test]
fn test_no_owner_check_left_needs_the_recovery_key() {
    let (_dir, state, verifier) = setup(BiometryKind::Fingerprint);
    let key = state.recovery_key_create().unwrap();
    state.biometric_set_enabled(true).unwrap();
    state.secwet_lock().unwrap();

    verifier.set_kind(BiometryKind::None);
    verifier.answer(Err(PresenceError::Unavailable));
    let err = state.secwet_unlock().unwrap_err();
    assert_eq!(err.code, "recovery_key_required");
    assert_eq!(err.field.as_deref(), Some("recovery_key"));
    assert_eq!(
        state
            .secwet_unlock_with(Some("AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"))
            .unwrap_err()
            .code,
        "recovery_key_invalid"
    );
    assert_eq!(state.items_list(None).unwrap_err().code, "locked");

    let prompts = verifier.prompts();
    state.secwet_unlock_with(Some(&key)).unwrap();
    // The recovery key is the owner check; no prompt for it.
    assert_eq!(verifier.prompts(), prompts);
    state.items_list(None).unwrap();
}

#[test]
fn test_no_owner_check_and_no_recovery_key_stays_locked() {
    let (_dir, state, verifier) = setup(BiometryKind::Fingerprint);
    state.biometric_set_enabled(true).unwrap();
    state.secwet_lock().unwrap();

    verifier.set_kind(BiometryKind::None);
    verifier.answer(Err(PresenceError::Unavailable));
    assert_eq!(state.secwet_unlock().unwrap_err().code, "biometric_unavailable");
    assert_eq!(
        state
            .secwet_unlock_with(Some("AAAAA-AAAAA-AAAAA-AAAAA-AAAAA"))
            .unwrap_err()
            .code,
        "biometric_unavailable"
    );

    // Sensor back: unlock works again.
    verifier.answer(Ok(()));
    state.secwet_unlock().unwrap();
}

#[test]
fn test_recovery_key_is_ignored_without_the_setting() {
    let (_dir, state, verifier) = setup(BiometryKind::TouchId);
    state.secwet_lock().unwrap();
    state.secwet_unlock_with(Some("anything")).unwrap();
    assert_eq!(verifier.prompts(), 0);
}

#[test]
fn test_disabling_restores_default_unlock() {
    let (_dir, state, verifier) = setup(BiometryKind::TouchId);
    state.biometric_set_enabled(true).unwrap();
    let off = state.biometric_set_enabled(false).unwrap();
    assert!(!off.enabled);
    let prompts = verifier.prompts();

    state.secwet_lock().unwrap();
    verifier.answer(Err(PresenceError::Failed));
    state.secwet_unlock().unwrap();
    assert_eq!(verifier.prompts(), prompts);
}

#[test]
fn test_flag_is_per_store() {
    let (_dir, state, _) = setup(BiometryKind::TouchId);
    state.biometric_set_enabled(true).unwrap();
    // Another store in another data dir, sharing the same keychain.
    let other_dir = tempdir().unwrap();
    let other = AppState::new(other_dir.path().to_path_buf(), Arc::clone(&state.keystore));
    other.set_presence_verifier(FakeVerifier::new(BiometryKind::TouchId));
    other.secwet_create(None).unwrap();
    assert!(!other.biometric_status().unwrap().enabled);
}
