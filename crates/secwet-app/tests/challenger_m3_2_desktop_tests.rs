//! Challenger Adversarial Integration Test Suite for Desktop Tauri IPC.
//!
//! Scope:
//! 1. Comprehensive verification that ALL recovery and export commands strictly reject calls
//!    when uninitialized (code == "locked").
//! 2. Verification that ALL recovery and export commands strictly reject calls when locked
//!    via `secwet_lock` (code == "locked").
//! 3. Re-unlocking permits commands to execute.
//! 4. Re-locking immediately re-enforces the "locked" barrier across all commands.
//! 5. Headless edge cases (path == None with app == None) reject with code == "invalid".
//! 6. Wrong and malformed recovery keys reject with code == "recovery_failed".
//! 7. Seamless active instance drop and lock during workspace_restore.

use std::sync::Arc;
use tempfile::tempdir;

use secwet_core::keys::MemoryStore;
use secwet_core::model::SecretKind;
use secwet_app::commands::SecretDraftDto;
use secwet_app::state::{AppState, SecwetStatusDto};

#[test]
fn test_adversarial_ipc_lifecycle_locked_uninitialized_and_relock_enforcement() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);

    let dummy_path = dir.path().join("dummy.secwet");
    let dummy_key = "00000-00000-00000-00000-00000".to_string();

    // =========================================================================
    // 1. Uninitialized State Enforcement
    // =========================================================================
    assert_eq!(
        state.recovery_status().unwrap_err().code,
        "locked",
        "recovery_status must reject when uninitialized"
    );
    assert_eq!(
        state.recovery_key_create().unwrap_err().code,
        "locked",
        "recovery_key_create must reject when uninitialized"
    );
    assert_eq!(
        state.recovery_key_replace().unwrap_err().code,
        "locked",
        "recovery_key_replace must reject when uninitialized"
    );
    assert_eq!(
        state.workspace_export(Some(dummy_path.clone()), dummy_key.clone())
            .unwrap_err()
            .code,
        "locked",
        "workspace_export must reject when uninitialized"
    );

    // =========================================================================
    // 2. Initialize Workspace, then Explicitly Lock
    // =========================================================================
    let init_status = state.secwet_create(Some("test-device".into())).unwrap();
    match init_status {
        SecwetStatusDto::Unlocked { .. } => {}
        _ => panic!("Expected Unlocked status after create"),
    }

    // Now explicitly lock the active instance
    state.secwet_lock().expect("secwet_lock must succeed");

    // All recovery & export commands must strictly reject with code "locked"
    assert_eq!(
        state.recovery_status().unwrap_err().code,
        "locked",
        "recovery_status must reject when locked"
    );
    assert_eq!(
        state.recovery_key_create().unwrap_err().code,
        "locked",
        "recovery_key_create must reject when locked"
    );
    assert_eq!(
        state.recovery_key_replace().unwrap_err().code,
        "locked",
        "recovery_key_replace must reject when locked"
    );
    assert_eq!(
        state.workspace_export(Some(dummy_path.clone()), dummy_key.clone())
            .unwrap_err()
            .code,
        "locked",
        "workspace_export must reject when locked"
    );

    // =========================================================================
    // 3. Re-unlock and Execute Lifecycle Commands
    // =========================================================================
    state.secwet_unlock().expect("secwet_unlock must succeed");

    // Status is now accessible
    let status_initial = state.recovery_status().unwrap();
    assert!(!status_initial.created);
    assert_eq!(status_initial.created_at, None);

    // Populate data
    let label = state.label_create("Backend".into(), None).unwrap();
    let item = state.item_create(label.id, "Auth".into(), None).unwrap();
    let env = state.environment_add(item.id, "Production".into()).unwrap();
    state.secret_create(SecretDraftDto {
            item_id: Some(item.id),
            project_id: None,
            environment_id: Some(env.id),
            name: "API_SECRET".into(),
            kind: SecretKind::Password,
            value: "super_secure_ipc_secret_12345".into(),
            note: None,
        },
    )
    .unwrap();

    // Create recovery key
    let key1 = state.recovery_key_create().unwrap();
    assert_eq!(key1.len(), 29);

    let status_after_create = state.recovery_status().unwrap();
    assert!(status_after_create.created);
    assert!(status_after_create.created_at.is_some());

    // Replace recovery key
    let key2 = state.recovery_key_replace().unwrap();
    assert_ne!(key1, key2);
    assert_eq!(key2.len(), 29);

    // Export with key1 must fail (old key invalidated)
    let export_archive = dir.path().join("test_export.secwet");
    let err_invalid_old_key = state.workspace_export(Some(export_archive.clone()), key1).unwrap_err();
    assert_eq!(err_invalid_old_key.code, "recovery_failed");

    // Headless mode without path must fail with invalid
    let err_headless = state.workspace_export(None, key2.clone()).unwrap_err();
    assert_eq!(err_headless.code, "invalid");
    assert!(err_headless.message.contains("headless"));

    // Export with key2 must succeed
    let summary = state.workspace_export(Some(export_archive.clone()), key2.clone()).unwrap();
    assert!(export_archive.exists());
    assert!(summary.bytes_written > 0);
    assert_eq!(summary.secrets_count, 1);

    // =========================================================================
    // 4. Re-lock Again and Verify Re-enforcement
    // =========================================================================
    state.secwet_lock().expect("re-lock must succeed");

    assert_eq!(state.recovery_status().unwrap_err().code, "locked");
    assert_eq!(state.recovery_key_create().unwrap_err().code, "locked");
    assert_eq!(state.recovery_key_replace().unwrap_err().code, "locked");
    assert_eq!(
        state.workspace_export(Some(export_archive.clone()), key2.clone())
            .unwrap_err()
            .code,
        "locked"
    );

    // =========================================================================
    // 5. Restore While an Active Workspace Exists (Lock Contention Defense)
    // =========================================================================
    // Re-unlock state
    state.secwet_unlock().expect("unlock must succeed");

    // Restore on top of active state must gracefully replace the active workspace
    let restore_status = state.workspace_restore(Some(export_archive.clone()),
        key2,
        Some("restored-desktop-device".into()),
    )
    .expect("workspace_restore must succeed on active state");

    match restore_status {
        SecwetStatusDto::Unlocked { .. } => {}
        _ => panic!("Expected Unlocked status after restore"),
    }

    // Verify restored data integrity
    let restored_secrets = state.secrets_list(Some(item.id), Some(env.id)).unwrap();
    assert_eq!(restored_secrets.len(), 1);
    assert_eq!(restored_secrets[0].name, "API_SECRET");

    let revealed = state.secret_reveal(restored_secrets[0].id).unwrap();
    assert_eq!(revealed, "super_secure_ipc_secret_12345");
}
