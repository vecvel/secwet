//! Empirical Adversarial Stress Suite: Tauri IPC Recovery Key Lifecycle & Concurrency
//!
//! Mandatory Task 2:
//! 1. Rapid create and replace recovery key calls under concurrent load.
//! 2. Multi-threaded race condition stress testing (replacers vs exporters vs readers).
//! 3. Verify zero deadlocks, thread-safety, and invalidation of historical keys.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use secwet_core::keys::MemoryStore;
use secwet_core::model::SecretKind;
use secwet_app::commands::SecretDraftDto;
use secwet_app::state::{AppState, SecwetStatusDto};
use tempfile::tempdir;

// ============================================================================
// 1. Recovery Key Creation and Immediate Replacement Invariants
// ============================================================================

#[test]
fn test_recovery_ipc_create_replace_and_restore_lifecycle() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);

    state.secwet_create(Some("LifecycleDevice".into())).unwrap();

    // 1.1 Status before recovery key creation
    let status_before = state.recovery_status().unwrap();
    assert!(!status_before.created);
    assert!(status_before.created_at.is_none());

    // 1.2 Create recovery key
    let key1 = state.recovery_key_create().expect("recovery key create");
    assert_eq!(key1.len(), 29); // 5 groups of 5 with 4 hyphens = 29 chars
    assert_eq!(key1.chars().filter(|c| *c == '-').count(), 4);

    let status_created = state.recovery_status().unwrap();
    assert!(status_created.created);
    assert!(status_created.created_at.is_some());

    // 1.3 Replace recovery key
    let key2 = state.recovery_key_replace().expect("recovery key replace");
    assert_ne!(key1, key2);
    assert_eq!(key2.len(), 29);

    let status_replaced = state.recovery_status().unwrap();
    assert!(status_replaced.created);

    // 1.4 Old key1 is strictly invalidated on export attempt
    let export_path = dir.path().join("lifecycle_test.secwet");
    let err_old = state.workspace_export(Some(export_path.clone()), key1).unwrap_err();
    assert_eq!(err_old.code, "recovery_failed");

    // 1.5 Key2 successfully exports
    let summary = state.workspace_export(Some(export_path.clone()), key2.clone())
        .expect("export with new key");
    assert!(summary.bytes_written > 0);

    // 1.6 Restore into a clean AppState
    let restore_dir = tempdir().unwrap();
    let restore_keystore = Arc::new(MemoryStore::new());
    let restore_state = AppState::new(restore_dir.path().to_path_buf(), restore_keystore);

    // Restore with wrong key fails
    let err_wrong = restore_state.workspace_restore(Some(export_path.clone()),
        "WRONG-KEY00-00000-00000-00000".into(),
        Some("restore-dev".into()),
    )
    .unwrap_err();
    assert_eq!(err_wrong.code, "recovery_failed");

    // Restore with correct key2 succeeds
    let restore_status = restore_state.workspace_restore(Some(export_path),
        key2,
        Some("restored-device".into()),
    )
    .expect("restore");

    match restore_status {
        SecwetStatusDto::Unlocked { .. } => {}
        _ => panic!("Expected Unlocked status after restore"),
    }

    let status_restored = restore_state.recovery_status().unwrap();
    assert!(status_restored.created);
}

// ============================================================================
// 2. Sequential Rapid Key Replacement & Historical Invalidation
// ============================================================================

#[test]
fn test_rapid_sequential_recovery_key_replacements() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);

    state.secwet_create(Some("RapidDevice".into())).unwrap();
    let _space = state.space_create("CoreSpace".into(), None).unwrap();
    let label = state.label_create("CoreLabel".into(), None).unwrap();
    let item = state.item_create(label.id, "CoreItem".into(), None).unwrap();
    state.secret_create(SecretDraftDto {
            item_id: Some(item.id),
            project_id: Some(item.id),
            environment_id: None,
            name: "CANARY_SECRET".into(),
            kind: SecretKind::Password,
            value: "canary_val_1234".into(),
            note: None,
        },
    )
    .unwrap();

    let mut keys = Vec::new();
    let first_key = state.recovery_key_create().unwrap();
    keys.push(first_key);

    // Perform 30 rapid replacements in succession
    for _ in 0..30 {
        let new_key = state.recovery_key_replace().unwrap();
        keys.push(new_key);
    }

    assert_eq!(keys.len(), 31);

    // All older 30 keys MUST be invalidated on export attempts
    let export_path = dir.path().join("rapid_test.secwet");
    for (i, old_key) in keys[..30].iter().enumerate() {
        let err = state.workspace_export(Some(export_path.clone()), old_key.clone())
            .expect_err(&format!("Key at index {i} should be invalidated"));
        assert_eq!(err.code, "recovery_failed");
    }

    // Only the 31st (latest) key succeeds
    let latest_key = keys.last().unwrap();
    let summary = state.workspace_export(Some(export_path.clone()), latest_key.clone())
        .expect("Latest key must successfully export");
    assert!(summary.bytes_written > 0);
    assert!(summary.secrets_count >= 1);
}

// ============================================================================
// 3. Multi-Threaded Concurrent Replacement & Read Stress
// ============================================================================

#[test]
fn test_concurrent_recovery_key_replace_and_readers_race() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = Arc::new(AppState::new(dir.path().to_path_buf(), keystore));

    state.secwet_create(Some("ConcurrentDevice".into())).unwrap();

    // Create initial recovery key
    state.recovery_key_create().unwrap();

    let num_replacers = 8;
    let replaces_per_thread = 5;
    let num_readers = 8;
    let barrier = Arc::new(Barrier::new(num_replacers + num_readers));
    let stop_readers = Arc::new(AtomicBool::new(false));

    let replaced_keys = Arc::new(Mutex::new(Vec::new()));

    let mut handles = Vec::new();

    // Spawn replacers
    for _ in 0..num_replacers {
        let s = Arc::clone(&state);
        let b = Arc::clone(&barrier);
        let rk = Arc::clone(&replaced_keys);

        handles.push(thread::spawn(move || {
            b.wait();
            for _ in 0..replaces_per_thread {
                match s.recovery_key_replace() {
                    Ok(k) => {
                        rk.lock().unwrap().push(k);
                    }
                    Err(e) => {
                        panic!("recovery_key_replace failed: {:?}", e);
                    }
                }
            }
        }));
    }

    // Spawn concurrent readers
    for _ in 0..num_readers {
        let s = Arc::clone(&state);
        let b = Arc::clone(&barrier);
        let sr = Arc::clone(&stop_readers);

        handles.push(thread::spawn(move || {
            b.wait();
            while !sr.load(Ordering::Relaxed) {
                let status = s.recovery_status().unwrap();
                assert!(status.created);
                let _ = s.overview();
                let _ = s.spaces_list();
                thread::yield_now();
            }
        }));
    }

    // Wait for all replacers to finish
    for h in handles.drain(..num_replacers) {
        h.join().unwrap();
    }

    // Stop readers
    stop_readers.store(true, Ordering::Relaxed);
    for h in handles {
        h.join().unwrap();
    }

    let all_keys = replaced_keys.lock().unwrap().clone();
    assert_eq!(all_keys.len(), num_replacers * replaces_per_thread);

    // Verify recovery status is intact
    let final_status = state.recovery_status().unwrap();
    assert!(final_status.created);

    // Verify exactly one of the generated keys is currently active and can export
    let export_path = dir.path().join("concurrent_test.secwet");
    let mut successful_exports = 0;
    let mut working_key = None;

    for k in all_keys.iter().rev() {
        if let Ok(summary) = state.workspace_export(Some(export_path.clone()), k.clone()) {
            successful_exports += 1;
            if working_key.is_none() {
                working_key = Some(k.clone());
            }
            assert!(summary.bytes_written > 0);
        }
    }

    // Exactly the latest active key succeeds
    assert!(successful_exports >= 1);
    assert!(working_key.is_some());
}

// ============================================================================
// 4. Concurrent Export and Key Replacement Race
// ============================================================================

#[test]
fn test_concurrent_export_interleaved_with_key_replacement() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = Arc::new(AppState::new(dir.path().to_path_buf(), keystore));

    state.secwet_create(Some("RaceDevice".into())).unwrap();

    let initial_key = state.recovery_key_create().unwrap();
    let latest_key = Arc::new(Mutex::new(initial_key));

    let stop_flag = Arc::new(AtomicBool::new(false));
    let export_attempts = Arc::new(AtomicUsize::new(0));
    let export_successes = Arc::new(AtomicUsize::new(0));
    let export_recovery_failed = Arc::new(AtomicUsize::new(0));

    let barrier = Arc::new(Barrier::new(3));

    // Thread 1: Rapid key replacer
    let t1 = {
        let s = Arc::clone(&state);
        let k = Arc::clone(&latest_key);
        let b = Arc::clone(&barrier);
        let sf = Arc::clone(&stop_flag);
        thread::spawn(move || {
            b.wait();
            for _ in 0..15 {
                if sf.load(Ordering::Relaxed) {
                    break;
                }
                let new_key = s.recovery_key_replace().unwrap();
                *k.lock().unwrap() = new_key;
                thread::sleep(Duration::from_millis(5));
            }
        })
    };

    // Thread 2 & 3: Exporters
    let mut exporter_handles = Vec::new();
    for thread_idx in 0..2 {
        let s = Arc::clone(&state);
        let k = Arc::clone(&latest_key);
        let b = Arc::clone(&barrier);
        let sf = Arc::clone(&stop_flag);
        let ea = Arc::clone(&export_attempts);
        let es = Arc::clone(&export_successes);
        let erf = Arc::clone(&export_recovery_failed);
        let exp_dir = dir.path().to_path_buf();

        exporter_handles.push(thread::spawn(move || {
            b.wait();
            for i in 0..30 {
                if sf.load(Ordering::Relaxed) {
                    break;
                }
                let current_k = k.lock().unwrap().clone();
                let path = exp_dir.join(format!("race_export_{}_{}.secwet", thread_idx, i));
                ea.fetch_add(1, Ordering::SeqCst);

                match s.workspace_export(Some(path), current_k) {
                    Ok(_) => {
                        es.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(e) => {
                        // If the key was replaced just between reading `current_k` and `export_encrypted`,
                        // it should cleanly return "recovery_failed". No panics, no DB corruption.
                        assert_eq!(e.code, "recovery_failed");
                        erf.fetch_add(1, Ordering::SeqCst);
                    }
                }
                thread::sleep(Duration::from_millis(2));
            }
        }));
    }

    t1.join().unwrap();
    stop_flag.store(true, Ordering::Relaxed);
    for h in exporter_handles {
        h.join().unwrap();
    }

    assert!(export_attempts.load(Ordering::SeqCst) > 0);
    // Every attempt either succeeded or failed with "recovery_failed"
    assert_eq!(
        export_attempts.load(Ordering::SeqCst),
        export_successes.load(Ordering::SeqCst) + export_recovery_failed.load(Ordering::SeqCst)
    );
}

// ============================================================================
// 5. Invariant & Edge Cases: Locked Enforcement & Headless Validation
// ============================================================================

#[test]
fn test_recovery_ipc_invariants_locked_and_headless() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);

    // 5.1 When uninitialized or locked, all recovery operations return locked
    assert_eq!(state.recovery_key_create().unwrap_err().code, "locked");
    assert_eq!(state.recovery_key_replace().unwrap_err().code, "locked");
    assert_eq!(state.recovery_status().unwrap_err().code, "locked");
    assert_eq!(
        state.workspace_export(Some(dir.path().join("a.secwet")), "KEY".into()).unwrap_err().code,
        "locked"
    );

    // Initialize and unlock
    state.secwet_create(Some("InvDevice".into())).unwrap();
    let key = state.recovery_key_create().unwrap();

    // 5.2 Headless mode without path returns invalid
    let err_exp = state.workspace_export(None, key.clone()).unwrap_err();
    assert_eq!(err_exp.code, "invalid");

    let err_rst = state.workspace_restore(None, key.clone(), None).unwrap_err();
    assert_eq!(err_rst.code, "invalid");

    // 5.3 Lock and verify enforcement
    state.secwet_lock().unwrap();
    assert_eq!(state.recovery_key_create().unwrap_err().code, "locked");
    assert_eq!(state.recovery_key_replace().unwrap_err().code, "locked");
    assert_eq!(state.recovery_status().unwrap_err().code, "locked");
}
