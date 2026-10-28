//! Challenger Adversarial Integration Test Suite for Milestone M3-2 Desktop Tauri IPC.
//!
//! Scope:
//! 1. Comprehensive verification that ALL recovery and export commands strictly reject calls
//!    when uninitialized (code == "locked").
//! 2. Verification that ALL recovery and export commands strictly reject calls when locked
//!    via `secwet_lock_impl` (code == "locked").
//! 3. Re-unlocking permits commands to execute.
//! 4. Re-locking immediately re-enforces the "locked" barrier across all commands.
//! 5. Headless edge cases (path == None with app == None) reject with code == "invalid".
//! 6. Wrong and malformed recovery keys reject with code == "recovery_failed".
//! 7. Seamless active instance drop and lock during workspace_restore_impl.

use std::sync::Arc;
use tempfile::tempdir;

use secwet_core::keys::MemoryStore;
use secwet_core::model::SecretKind;
use secwet_desktop_lib::commands::{
    environment_add_impl, item_create_impl, label_create_impl, recovery_key_create_impl,
    recovery_key_replace_impl, recovery_status_impl, secret_create_impl, secret_reveal_impl,
    secrets_list_impl, secwet_create_impl, secwet_lock_impl, secwet_unlock_impl,
    workspace_export_impl, workspace_restore_impl, SecretDraftDto,
};
use secwet_desktop_lib::state::{AppState, SecwetStatusDto};

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
        recovery_status_impl(&state).unwrap_err().code,
        "locked",
        "recovery_status must reject when uninitialized"
    );
    assert_eq!(
        recovery_key_create_impl(None, &state).unwrap_err().code,
        "locked",
        "recovery_key_create must reject when uninitialized"
    );
    assert_eq!(
        recovery_key_replace_impl(None, &state).unwrap_err().code,
        "locked",
        "recovery_key_replace must reject when uninitialized"
    );
    assert_eq!(
        workspace_export_impl(None, &state, Some(dummy_path.clone()), dummy_key.clone())
            .unwrap_err()
            .code,
        "locked",
        "workspace_export must reject when uninitialized"
    );

    // =========================================================================
    // 2. Initialize Workspace, then Explicitly Lock
    // =========================================================================
    let init_status = secwet_create_impl(None, &state, Some("test-device".into())).unwrap();
    match init_status {
        SecwetStatusDto::Unlocked { .. } => {}
        _ => panic!("Expected Unlocked status after create"),
    }

    // Now explicitly lock the active instance
    secwet_lock_impl(None, &state).expect("secwet_lock_impl must succeed");

    // All recovery & export commands must strictly reject with code "locked"
    assert_eq!(
        recovery_status_impl(&state).unwrap_err().code,
        "locked",
        "recovery_status must reject when locked"
    );
    assert_eq!(
        recovery_key_create_impl(None, &state).unwrap_err().code,
        "locked",
        "recovery_key_create must reject when locked"
    );
    assert_eq!(
        recovery_key_replace_impl(None, &state).unwrap_err().code,
        "locked",
        "recovery_key_replace must reject when locked"
    );
    assert_eq!(
        workspace_export_impl(None, &state, Some(dummy_path.clone()), dummy_key.clone())
            .unwrap_err()
            .code,
        "locked",
        "workspace_export must reject when locked"
    );

    // =========================================================================
    // 3. Re-unlock and Execute Lifecycle Commands
    // =========================================================================
    secwet_unlock_impl(None, &state).expect("secwet_unlock_impl must succeed");

    // Status is now accessible
    let status_initial = recovery_status_impl(&state).unwrap();
    assert!(!status_initial.created);
    assert_eq!(status_initial.created_at, None);

    // Populate data
    let label = label_create_impl(None, &state, "Backend".into(), None).unwrap();
    let item = item_create_impl(None, &state, label.id, "Auth".into(), None).unwrap();
    let env = environment_add_impl(None, &state, item.id, "Production".into()).unwrap();
    secret_create_impl(
        None,
        &state,
        SecretDraftDto {
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
    let key1 = recovery_key_create_impl(None, &state).unwrap();
    assert_eq!(key1.len(), 29);

    let status_after_create = recovery_status_impl(&state).unwrap();
    assert!(status_after_create.created);
    assert!(status_after_create.created_at.is_some());

    // Replace recovery key
    let key2 = recovery_key_replace_impl(None, &state).unwrap();
    assert_ne!(key1, key2);
    assert_eq!(key2.len(), 29);

    // Export with key1 must fail (old key invalidated)
    let export_archive = dir.path().join("test_export.secwet");
    let err_invalid_old_key = workspace_export_impl(None, &state, Some(export_archive.clone()), key1).unwrap_err();
    assert_eq!(err_invalid_old_key.code, "recovery_failed");

    // Headless mode without path must fail with invalid
    let err_headless = workspace_export_impl(None, &state, None, key2.clone()).unwrap_err();
    assert_eq!(err_headless.code, "invalid");
    assert!(err_headless.message.contains("headless"));

    // Export with key2 must succeed
    let summary = workspace_export_impl(None, &state, Some(export_archive.clone()), key2.clone()).unwrap();
    assert!(export_archive.exists());
    assert!(summary.bytes_written > 0);
    assert_eq!(summary.secrets_count, 1);

    // =========================================================================
    // 4. Re-lock Again and Verify Re-enforcement
    // =========================================================================
    secwet_lock_impl(None, &state).expect("re-lock must succeed");

    assert_eq!(recovery_status_impl(&state).unwrap_err().code, "locked");
    assert_eq!(recovery_key_create_impl(None, &state).unwrap_err().code, "locked");
    assert_eq!(recovery_key_replace_impl(None, &state).unwrap_err().code, "locked");
    assert_eq!(
        workspace_export_impl(None, &state, Some(export_archive.clone()), key2.clone())
            .unwrap_err()
            .code,
        "locked"
    );

    // =========================================================================
    // 5. Restore While an Active Workspace Exists (Lock Contention Defense)
    // =========================================================================
    // Re-unlock state
    secwet_unlock_impl(None, &state).expect("unlock must succeed");

    // Restore on top of active state must gracefully replace the active workspace
    let restore_status = workspace_restore_impl(
        None,
        &state,
        Some(export_archive.clone()),
        key2,
        Some("restored-desktop-device".into()),
    )
    .expect("workspace_restore_impl must succeed on active state");

    match restore_status {
        SecwetStatusDto::Unlocked { .. } => {}
        _ => panic!("Expected Unlocked status after restore"),
    }

    // Verify restored data integrity
    let restored_secrets = secrets_list_impl(&state, Some(item.id), Some(env.id)).unwrap();
    assert_eq!(restored_secrets.len(), 1);
    assert_eq!(restored_secrets[0].name, "API_SECRET");

    let revealed = secret_reveal_impl(&state, restored_secrets[0].id).unwrap();
    assert_eq!(revealed, "super_secure_ipc_secret_12345");
}
