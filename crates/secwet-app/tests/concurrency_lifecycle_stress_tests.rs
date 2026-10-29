//! Empirical stress tests for Secwet Tauri backend state and commands.
//!
//! Objectives:
//! 1. High concurrency: Multiple threads simultaneously reading projects, listing secrets, and adding secrets via AppState helpers.
//! 2. Lifecycle transitions: Uninitialized -> create -> unlock -> rapid lock/unlock cycles while concurrent reader/writer threads are active. Verify no deadlocks, panics, or SQLite locking errors occur.
//! 3. Invariant enforcement: Calling commands while locked returns `locked` without crashing.
//! 4. Uninitialized to create race condition: Multiple threads racing to create a secwet on a fresh directory.
//! 5. Multi-instance WAL concurrency: Multiple independent AppState instances accessing the same database concurrently.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::Duration;

use secwet_core::keys::{KeyStore, MemoryStore};
use secwet_core::model::SecretKind;
use secwet_app::clipboard::ClipboardPort;
use secwet_app::commands::{SecretDraftDto, SettingsPatchDto};
use secwet_app::state::{AppState, SecwetStatusDto};
use tempfile::tempdir;
use uuid::Uuid;

#[derive(Default)]
struct StressMockClipboard {
    data: Mutex<Option<String>>,
}

impl ClipboardPort for StressMockClipboard {
    fn write_secret(&self, text: &str) -> Result<(), String> {
        *self.data.lock().unwrap() = Some(text.to_string());
        Ok(())
    }
    fn read_text(&self) -> Result<String, String> {
        self.data
            .lock()
            .unwrap()
            .clone()
            .ok_or_else(|| "Empty".to_string())
    }
    fn clear(&self) -> Result<(), String> {
        *self.data.lock().unwrap() = None;
        Ok(())
    }
}

// ============================================================================
// Test 1: High Concurrency Readers and Writers
// ============================================================================

#[test]
fn test_stress_high_concurrency_readers_and_writers() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = Arc::new(AppState::new(dir.path().to_path_buf(), keystore));

    // Initialize secwet and base structure
    state.secwet_create(Some("StressBench-1".into())).unwrap();
    let proj1 = state.project_create("Backend Core".into(),
        vec!["Staging".into(), "Production".into()],
    )
    .unwrap();
    let proj2 = state.project_create("Mobile App".into(),
        vec!["Development".into(), "Release".into()],
    )
    .unwrap();

    let env1 = proj1.environments[0].id;
    let env2 = proj1.environments[1].id;
    let env3 = proj2.environments[0].id;

    // Seed initial secrets
    let mut initial_secret_ids = Vec::new();
    for i in 0..5 {
        let draft = SecretDraftDto {
            item_id: Some(proj1.id),
            project_id: Some(proj1.id),
            environment_id: Some(env1),
            name: format!("INITIAL_SECRET_{}", i),
            kind: SecretKind::ApiKey,
            value: format!("sk_test_initial_value_for_secret_{}", i),
            note: Some("Seed secret".into()),
        };
        let meta = state.secret_create(draft).unwrap();
        initial_secret_ids.push(meta.id);
    }

    let num_readers = 6;
    let num_secret_readers = 6;
    let num_writers = 6;
    let total_threads = num_readers + num_secret_readers + num_writers;

    let barrier = Arc::new(Barrier::new(total_threads));
    let mut handles = Vec::new();

    // Group 1: General readers (projects, overview, settings)
    for _ in 0..num_readers {
        let s = Arc::clone(&state);
        let b = Arc::clone(&barrier);
        handles.push(thread::spawn(move || {
            b.wait();
            for _ in 0..40 {
                let projs = s.projects_list().expect("projects_list failed under concurrency");
                assert!(projs.len() >= 2);

                let ov = s.overview().expect("overview failed under concurrency");
                assert!(ov.projects_count >= 2);
                assert!(ov.secrets_count >= 5);

                let st = s.settings_get().expect("settings_get failed under concurrency");
                assert_eq!(st.device_name, "StressBench-1");
            }
        }));
    }

    // Group 2: Secret readers (secrets_list, secret_reveal)
    let secret_ids_arc = Arc::new(initial_secret_ids);
    for _ in 0..num_secret_readers {
        let s = Arc::clone(&state);
        let b = Arc::clone(&barrier);
        let sec_ids = Arc::clone(&secret_ids_arc);
        handles.push(thread::spawn(move || {
            b.wait();
            for iter in 0..40 {
                let secs1 = s.secrets_list(None, Some(env1)).expect("secrets_list failed");
                assert!(!secs1.is_empty());
                // Invariant: list_secrets must NEVER expose values
                for s_meta in &secs1 {
                    assert!(!s_meta
                        .value_tail
                        .contains("sk_test_initial_value_for_secret"));
                }

                // Reveal seeded secret
                let target_id = sec_ids[iter % sec_ids.len()];
                let revealed = s.secret_reveal(target_id).expect("secret_reveal failed");
                assert!(revealed.starts_with("sk_test_initial_value_for_secret_"));
            }
        }));
    }

    // Group 3: Writers (secret_create, secret_update)
    let created_secrets_count = Arc::new(AtomicUsize::new(0));
    for writer_idx in 0..num_writers {
        let s = Arc::clone(&state);
        let b = Arc::clone(&barrier);
        let counter = Arc::clone(&created_secrets_count);
        let p_id = if writer_idx % 2 == 0 {
            proj1.id
        } else {
            proj2.id
        };
        let e_id = if writer_idx % 2 == 0 { env2 } else { env3 };

        handles.push(thread::spawn(move || {
            b.wait();
            for iter in 0..25 {
                let s_name = format!("CONC_SEC_W{}_I{}", writer_idx, iter);
                let draft = SecretDraftDto {
                    item_id: Some(p_id),
                    project_id: Some(p_id),
                    environment_id: Some(e_id),
                    name: s_name.clone(),
                    kind: SecretKind::Password,
                    value: format!("val_w{}_{}_secret_content", writer_idx, iter),
                    note: Some(format!("Created by writer {}", writer_idx)),
                };
                let created = s.secret_create(draft).expect("secret_create failed");
                counter.fetch_add(1, Ordering::Relaxed);

                // Immediately read back and reveal
                let revealed =
                    s.secret_reveal(created.id).expect("reveal immediately after create");
                assert_eq!(
                    revealed,
                    format!("val_w{}_{}_secret_content", writer_idx, iter)
                );
            }
        }));
    }

    // Join all threads and ensure no panics occurred
    for h in handles {
        h.join().expect("Worker thread panicked under concurrency!");
    }

    // Final integrity checks
    let total_created = created_secrets_count.load(Ordering::SeqCst);
    assert_eq!(total_created, num_writers * 25);

    let final_overview = state.overview().unwrap();
    assert_eq!(final_overview.secrets_count, 5 + num_writers * 25);

    let final_projs = state.projects_list().unwrap();
    assert_eq!(final_projs.len(), 2);
}

// ============================================================================
// Test 2: Lifecycle Transitions Under High Concurrent Load
// ============================================================================

#[test]
fn test_stress_lifecycle_rapid_lock_unlock_under_concurrent_readers_and_writers() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = Arc::new(AppState::new(dir.path().to_path_buf(), keystore));

    // 1. Initialize secwet and seed one secret
    let create_status = state.secwet_create(Some("LifecycleBench".into())).unwrap();
    let secwet_id = match create_status {
        SecwetStatusDto::Unlocked { secwet_id } => secwet_id,
        _ => panic!("Expected unlocked secwet"),
    };

    let proj =
        state.project_create("LifecycleProj".into(), vec!["Primary".into()]).unwrap();
    let env_id = proj.environments[0].id;
    let seed_secret = state.secret_create(SecretDraftDto {
            item_id: Some(proj.id),
            project_id: Some(proj.id),
            environment_id: Some(env_id),
            name: "SEED_LIFECYCLE".into(),
            kind: SecretKind::ApiKey,
            value: "super_secret_seed_value".into(),
            note: None,
        },
    )
    .unwrap();
    let seed_id = seed_secret.id;

    let running = Arc::new(AtomicBool::new(true));
    let locked_rejections = Arc::new(AtomicUsize::new(0));
    let unlocked_successes = Arc::new(AtomicUsize::new(0));
    let unexpected_errors = Arc::new(AtomicUsize::new(0));

    let num_workers = 10;
    let mut worker_handles = Vec::new();

    // Spawn 10 concurrent worker threads exercising various commands
    for worker_id in 0..num_workers {
        let s = Arc::clone(&state);
        let r = Arc::clone(&running);
        let locked_cnt = Arc::clone(&locked_rejections);
        let success_cnt = Arc::clone(&unlocked_successes);
        let err_cnt = Arc::clone(&unexpected_errors);

        worker_handles.push(thread::spawn(move || {
            let mut iter = 0usize;
            while r.load(Ordering::Relaxed) {
                iter += 1;
                thread::yield_now();
                // Alternate across various commands
                match worker_id % 7 {
                    0 => match s.projects_list() {
                        Ok(p) => {
                            assert!(!p.is_empty());
                            success_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) if e.code == "locked" => {
                            locked_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("Unexpected error in projects_list: {:?}", e);
                            err_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    1 => match s.secrets_list(None, Some(env_id)) {
                        Ok(secs) => {
                            assert!(!secs.is_empty());
                            success_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) if e.code == "locked" => {
                            locked_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("Unexpected error in secrets_list: {:?}", e);
                            err_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    2 => match s.secret_reveal(seed_id) {
                        Ok(val) => {
                            assert_eq!(val, "super_secret_seed_value");
                            success_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) if e.code == "locked" => {
                            locked_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("Unexpected error in secret_reveal: {:?}", e);
                            err_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    3 => match s.overview() {
                        Ok(ov) => {
                            assert!(ov.secrets_count >= 1);
                            success_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) if e.code == "locked" => {
                            locked_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("Unexpected error in overview: {:?}", e);
                            err_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    4 => match s.settings_get() {
                        Ok(settings) => {
                            assert_eq!(settings.device_name, "LifecycleBench");
                            success_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) if e.code == "locked" => {
                            locked_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("Unexpected error in settings_get: {:?}", e);
                            err_cnt.fetch_add(1, Ordering::Relaxed);
                        }
                    },
                    5 => {
                        // secwet_status must NEVER return locked; it returns Unlocked or Locked DTO
                        match s.secwet_status() {
                            Ok(SecwetStatusDto::Unlocked { secwet_id: id }) => {
                                assert_eq!(id, secwet_id);
                                success_cnt.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(SecwetStatusDto::Locked { secwet_id: id }) => {
                                assert_eq!(id, secwet_id);
                                locked_cnt.fetch_add(1, Ordering::Relaxed);
                            }
                            Ok(SecwetStatusDto::Uninitialized) => {
                                panic!("Secwet reported Uninitialized after being created!");
                            }
                            Err(e) => {
                                eprintln!("Unexpected error in secwet_status: {:?}", e);
                                err_cnt.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    _ => {
                        // Mutating writer: try to create a secret
                        let draft = SecretDraftDto {
                            item_id: Some(proj.id),
                            project_id: Some(proj.id),
                            environment_id: Some(env_id),
                            name: format!("DYN_W{}_I{}", worker_id, iter),
                            kind: SecretKind::Password,
                            value: "dyn_val".into(),
                            note: None,
                        };
                        match s.secret_create(draft) {
                            Ok(_) => {
                                success_cnt.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) if e.code == "locked" => {
                                locked_cnt.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => {
                                eprintln!("Unexpected error in secret_create: {:?}", e);
                                err_cnt.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                }
            }
        }));
    }

    // Controller: Rapidly lock and unlock the secwet 80 times
    let cycles = 80;
    for _ in 0..cycles {
        // Lock
        state.secwet_lock().expect("secwet_lock failed");
        thread::sleep(Duration::from_micros(300));

        // Unlock
        state.secwet_unlock().expect("secwet_unlock failed");
        thread::sleep(Duration::from_micros(300));
    }

    // Stop workers
    running.store(false, Ordering::SeqCst);

    for h in worker_handles {
        h.join()
            .expect("Worker thread panicked during rapid lifecycle cycling!");
    }

    let total_locked = locked_rejections.load(Ordering::SeqCst);
    let total_success = unlocked_successes.load(Ordering::SeqCst);
    let total_errors = unexpected_errors.load(Ordering::SeqCst);

    println!(
        "[Stress Lifecycle] Completed {} cycles: locked_rejections={}, unlocked_successes={}, unexpected_errors={}",
        cycles, total_locked, total_success, total_errors
    );

    assert_eq!(
        total_errors, 0,
        "Encountered unexpected errors during lifecycle stress testing!"
    );
    assert!(
        total_locked > 0,
        "Expected worker threads to encounter locked state rejections"
    );
    assert!(
        total_success > 0,
        "Expected worker threads to encounter unlocked successes"
    );

    // Final verification: ensure secwet is unlocked and fully functional
    let final_status = state.secwet_status().unwrap();
    assert_eq!(final_status, SecwetStatusDto::Unlocked { secwet_id });

    let final_revealed = state.secret_reveal(seed_id).unwrap();
    assert_eq!(final_revealed, "super_secret_seed_value");

    // Lock again to verify clean termination
    state.secwet_lock().unwrap();
    assert_eq!(
        state.secwet_status().unwrap(),
        SecwetStatusDto::Locked { secwet_id }
    );
}

// ============================================================================
// Test 3: Uninitialized to Create Race Condition
// ============================================================================

#[test]
fn test_stress_uninitialized_to_create_race_condition() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = Arc::new(AppState::new(dir.path().to_path_buf(), keystore));

    // Initial status must be Uninitialized
    assert_eq!(
        state.secwet_status().unwrap(),
        SecwetStatusDto::Uninitialized
    );

    let num_racers = 20;
    let barrier = Arc::new(Barrier::new(num_racers));
    let mut handles = Vec::new();

    let success_count = Arc::new(AtomicUsize::new(0));
    let already_init_count = Arc::new(AtomicUsize::new(0));
    let other_error_count = Arc::new(AtomicUsize::new(0));

    for i in 0..num_racers {
        let s = Arc::clone(&state);
        let b = Arc::clone(&barrier);
        let succ = Arc::clone(&success_count);
        let already = Arc::clone(&already_init_count);
        let other = Arc::clone(&other_error_count);

        handles.push(thread::spawn(move || {
            b.wait();
            match s.secwet_create(Some(format!("racer-{}", i))) {
                Ok(SecwetStatusDto::Unlocked { .. }) => {
                    succ.fetch_add(1, Ordering::SeqCst);
                }
                Ok(_) => {
                    other.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) if e.code == "already_initialized" => {
                    already.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) => {
                    eprintln!("Unexpected error in create race: {:?}", e);
                    other.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }

    for h in handles {
        h.join().expect("Racer thread panicked");
    }

    let successes = success_count.load(Ordering::SeqCst);
    let already_inits = already_init_count.load(Ordering::SeqCst);
    let others = other_error_count.load(Ordering::SeqCst);

    println!(
        "[Create Race] successes={}, already_initialized={}, other_errors={}",
        successes, already_inits, others
    );

    assert_eq!(
        successes, 1,
        "Exactly one thread must successfully create the secwet"
    );
    assert_eq!(
        already_inits,
        num_racers - 1,
        "All remaining threads must receive already_initialized"
    );
    assert_eq!(
        others, 0,
        "No unexpected errors permitted during create race"
    );

    // Status is now Unlocked
    match state.secwet_status().unwrap() {
        SecwetStatusDto::Unlocked { .. } => {}
        status => panic!("Expected Unlocked, got {:?}", status),
    }
}

// ============================================================================
// Test 4: Invariant Enforcement across all 20 commands while locked
// ============================================================================

#[test]
fn test_stress_invariant_all_commands_strictly_enforce_locked() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);
    let mock_cb = Arc::new(StressMockClipboard::default());
    let dummy_id = Uuid::new_v4();

    // PHASE 1: Fresh uninitialized state
    assert_eq!(
        state.secwet_status().unwrap(),
        SecwetStatusDto::Uninitialized
    );

    // Calling unlock on uninitialized secwet must fail cleanly with not_initialized
    let err_unlock = state.secwet_unlock().unwrap_err();
    assert_eq!(err_unlock.code, "not_initialized");

    // Calling lock on uninitialized secwet is idempotent
    state.secwet_lock().unwrap();

    // PHASE 2: Create secwet, then lock it
    let create_status = state.secwet_create(Some("DeviceA".into())).unwrap();
    let secwet_id = match create_status {
        SecwetStatusDto::Unlocked { secwet_id } => secwet_id,
        _ => panic!("Expected unlocked"),
    };

    // Lock the secwet
    state.secwet_lock().unwrap();

    // Verify status is Locked
    assert_eq!(
        state.secwet_status().unwrap(),
        SecwetStatusDto::Locked { secwet_id }
    );

    // Double locking is idempotent
    state.secwet_lock().unwrap();
    assert_eq!(
        state.secwet_status().unwrap(),
        SecwetStatusDto::Locked { secwet_id }
    );

    // Creating again when secwet is on disk but locked returns already_initialized
    let err_create = state.secwet_create(None).unwrap_err();
    assert_eq!(err_create.code, "already_initialized");

    // Exhaustive invariant check: Every single command MUST return locked
    let dummy_draft = SecretDraftDto {
        item_id: Some(dummy_id),
        project_id: Some(dummy_id),
        environment_id: Some(dummy_id),
        name: "VAR".into(),
        kind: SecretKind::Password,
        value: "val".into(),
        note: None,
    };
    let dummy_patch = SettingsPatchDto {
        theme: Some("light".into()),
        lock_timeout_minutes: Some(15),
        device_name: Some("test".into()),
    };

    assert_eq!(state.projects_list().unwrap_err().code, "locked");
    assert_eq!(
        state.project_create("P".into(), vec![])
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        state.project_rename(dummy_id, "P".into())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        state.project_delete(dummy_id)
            .unwrap_err()
            .code,
        "locked"
    );

    assert_eq!(
        state.environment_add(dummy_id, "E".into())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        state.environment_rename(dummy_id, "E".into())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        state.environment_delete(dummy_id, None)
            .unwrap_err()
            .code,
        "locked"
    );

    assert_eq!(
        state.secrets_list(None, Some(dummy_id)).unwrap_err().code,
        "locked"
    );
    assert_eq!(
        state.secret_reveal(dummy_id).unwrap_err().code,
        "locked"
    );
    assert_eq!(
        state.secret_copy(Arc::clone(&mock_cb), dummy_id)
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        state.secret_create(dummy_draft.clone())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        state.secret_update(dummy_id, dummy_draft)
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        state.secret_delete(dummy_id).unwrap_err().code,
        "locked"
    );
    assert_eq!(
        state.secret_copy_to_environment(dummy_id, Some(dummy_id))
            .unwrap_err()
            .code,
        "locked"
    );

    assert_eq!(state.overview().unwrap_err().code, "locked");
    assert_eq!(state.settings_get().unwrap_err().code, "locked");
    assert_eq!(
        state.settings_set(dummy_patch)
            .unwrap_err()
            .code,
        "locked"
    );

    // PHASE 3: Unlock again
    state.secwet_unlock().unwrap();
    assert_eq!(
        state.secwet_status().unwrap(),
        SecwetStatusDto::Unlocked { secwet_id }
    );

    // Double unlocking is idempotent
    state.secwet_unlock().unwrap();
    assert_eq!(
        state.secwet_status().unwrap(),
        SecwetStatusDto::Unlocked { secwet_id }
    );

    // Commands now work
    assert_eq!(state.projects_list().unwrap().len(), 0);
}

// ============================================================================
// Test 5: Multi-instance WAL Concurrency
// ============================================================================

#[test]
fn test_stress_multi_instance_wal_concurrency() {
    let dir = tempdir().unwrap();
    let keystore: Arc<dyn KeyStore> = Arc::new(MemoryStore::new());

    // Instance 1: Creates the secwet
    let state1 = Arc::new(AppState::new(
        dir.path().to_path_buf(),
        Arc::clone(&keystore),
    ));
    state1.secwet_create(Some("Node-1".into())).unwrap();
    let proj =
        state1.project_create("SharedProj".into(), vec!["Prod".into()]).unwrap();
    let env_id = proj.environments[0].id;

    // Instance 2: Connects to the same database directory and keystore
    let state2 = Arc::new(AppState::new(
        dir.path().to_path_buf(),
        Arc::clone(&keystore),
    ));
    state2.secwet_unlock().unwrap();

    let barrier = Arc::new(Barrier::new(2));
    let t1_barrier = Arc::clone(&barrier);
    let t2_barrier = Arc::clone(&barrier);

    let s1 = Arc::clone(&state1);
    let s2 = Arc::clone(&state2);

    let writer_handle = thread::spawn(move || {
        t1_barrier.wait();
        for i in 0..30 {
            let draft = SecretDraftDto {
                item_id: Some(proj.id),
                project_id: Some(proj.id),
                environment_id: Some(env_id),
                name: format!("MULTI_INST_SEC_{}", i),
                kind: SecretKind::ApiKey,
                value: format!("multi_inst_val_{}", i),
                note: None,
            };
            s1.secret_create(draft).expect("Writer failed in multi-instance WAL");
            thread::sleep(Duration::from_millis(1));
        }
    });

    let reader_handle = thread::spawn(move || {
        t2_barrier.wait();
        for _ in 0..30 {
            let list = s2.secrets_list(None, Some(env_id)).expect("Reader failed in multi-instance WAL");
            for meta in &list {
                let revealed =
                    s2.secret_reveal(meta.id).expect("Reveal failed in multi-instance WAL");
                assert!(!revealed.is_empty());
            }
            thread::sleep(Duration::from_millis(1));
        }
    });

    writer_handle.join().expect("Writer thread panicked");
    reader_handle.join().expect("Reader thread panicked");

    // Both instances see 30 secrets
    assert_eq!(state1.secrets_list(None, Some(env_id)).unwrap().len(), 30);
    assert_eq!(state2.secrets_list(None, Some(env_id)).unwrap().len(), 30);
}
