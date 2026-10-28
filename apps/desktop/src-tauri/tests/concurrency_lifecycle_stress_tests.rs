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
use secwet_desktop_lib::clipboard::ClipboardPort;
use secwet_desktop_lib::commands::{
    environment_add_impl, environment_delete_impl, environment_rename_impl, overview_impl,
    project_create_impl, project_delete_impl, project_rename_impl, projects_list_impl,
    secret_copy_impl, secret_copy_to_environment_impl, secret_create_impl, secret_delete_impl,
    secret_reveal_impl, secret_update_impl, secrets_list_impl, settings_get_impl,
    settings_set_impl, secwet_create_impl, secwet_lock_impl, secwet_status_impl, secwet_unlock_impl,
    SecretDraftDto, SettingsPatchDto,
};
use secwet_desktop_lib::state::{AppState, SecwetStatusDto};
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
    secwet_create_impl(None, &state, Some("StressBench-1".into())).unwrap();
    let proj1 = project_create_impl(
        None,
        &state,
        "Backend Core".into(),
        vec!["Staging".into(), "Production".into()],
    )
    .unwrap();
    let proj2 = project_create_impl(
        None,
        &state,
        "Mobile App".into(),
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
        let meta = secret_create_impl(None, &state, draft).unwrap();
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
                let projs = projects_list_impl(&s).expect("projects_list failed under concurrency");
                assert!(projs.len() >= 2);

                let ov = overview_impl(&s).expect("overview failed under concurrency");
                assert!(ov.projects_count >= 2);
                assert!(ov.secrets_count >= 5);

                let st = settings_get_impl(&s).expect("settings_get failed under concurrency");
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
                let secs1 = secrets_list_impl(&s, None, Some(env1)).expect("secrets_list failed");
                assert!(!secs1.is_empty());
                // Invariant: list_secrets must NEVER expose values
                for s_meta in &secs1 {
                    assert!(!s_meta
                        .value_tail
                        .contains("sk_test_initial_value_for_secret"));
                }

                // Reveal seeded secret
                let target_id = sec_ids[iter % sec_ids.len()];
                let revealed = secret_reveal_impl(&s, target_id).expect("secret_reveal failed");
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
                let created = secret_create_impl(None, &s, draft).expect("secret_create failed");
                counter.fetch_add(1, Ordering::Relaxed);

                // Immediately read back and reveal
                let revealed =
                    secret_reveal_impl(&s, created.id).expect("reveal immediately after create");
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

    let final_overview = overview_impl(&state).unwrap();
    assert_eq!(final_overview.secrets_count, 5 + num_writers * 25);

    let final_projs = projects_list_impl(&state).unwrap();
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
    let create_status = secwet_create_impl(None, &state, Some("LifecycleBench".into())).unwrap();
    let secwet_id = match create_status {
        SecwetStatusDto::Unlocked { secwet_id } => secwet_id,
        _ => panic!("Expected unlocked secwet"),
    };

    let proj =
        project_create_impl(None, &state, "LifecycleProj".into(), vec!["Primary".into()]).unwrap();
    let env_id = proj.environments[0].id;
    let seed_secret = secret_create_impl(
        None,
        &state,
        SecretDraftDto {
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
                    0 => match projects_list_impl(&s) {
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
                    1 => match secrets_list_impl(&s, None, Some(env_id)) {
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
                    2 => match secret_reveal_impl(&s, seed_id) {
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
                    3 => match overview_impl(&s) {
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
                    4 => match settings_get_impl(&s) {
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
                        match secwet_status_impl(&s) {
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
                        match secret_create_impl(None, &s, draft) {
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
        secwet_lock_impl(None, &state).expect("secwet_lock failed");
        thread::sleep(Duration::from_micros(300));

        // Unlock
        secwet_unlock_impl(None, &state).expect("secwet_unlock failed");
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
    let final_status = secwet_status_impl(&state).unwrap();
    assert_eq!(final_status, SecwetStatusDto::Unlocked { secwet_id });

    let final_revealed = secret_reveal_impl(&state, seed_id).unwrap();
    assert_eq!(final_revealed, "super_secret_seed_value");

    // Lock again to verify clean termination
    secwet_lock_impl(None, &state).unwrap();
    assert_eq!(
        secwet_status_impl(&state).unwrap(),
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
        secwet_status_impl(&state).unwrap(),
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
            match secwet_create_impl(None, &s, Some(format!("racer-{}", i))) {
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
    match secwet_status_impl(&state).unwrap() {
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
        secwet_status_impl(&state).unwrap(),
        SecwetStatusDto::Uninitialized
    );

    // Calling unlock on uninitialized secwet must fail cleanly with not_initialized
    let err_unlock = secwet_unlock_impl(None, &state).unwrap_err();
    assert_eq!(err_unlock.code, "not_initialized");

    // Calling lock on uninitialized secwet is idempotent
    secwet_lock_impl(None, &state).unwrap();

    // PHASE 2: Create secwet, then lock it
    let create_status = secwet_create_impl(None, &state, Some("DeviceA".into())).unwrap();
    let secwet_id = match create_status {
        SecwetStatusDto::Unlocked { secwet_id } => secwet_id,
        _ => panic!("Expected unlocked"),
    };

    // Lock the secwet
    secwet_lock_impl(None, &state).unwrap();

    // Verify status is Locked
    assert_eq!(
        secwet_status_impl(&state).unwrap(),
        SecwetStatusDto::Locked { secwet_id }
    );

    // Double locking is idempotent
    secwet_lock_impl(None, &state).unwrap();
    assert_eq!(
        secwet_status_impl(&state).unwrap(),
        SecwetStatusDto::Locked { secwet_id }
    );

    // Creating again when secwet is on disk but locked returns already_initialized
    let err_create = secwet_create_impl(None, &state, None).unwrap_err();
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

    assert_eq!(projects_list_impl(&state).unwrap_err().code, "locked");
    assert_eq!(
        project_create_impl(None, &state, "P".into(), vec![])
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        project_rename_impl(None, &state, dummy_id, "P".into())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        project_delete_impl(None, &state, dummy_id)
            .unwrap_err()
            .code,
        "locked"
    );

    assert_eq!(
        environment_add_impl(None, &state, dummy_id, "E".into())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        environment_rename_impl(None, &state, dummy_id, "E".into())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        environment_delete_impl(None, &state, dummy_id, None)
            .unwrap_err()
            .code,
        "locked"
    );

    assert_eq!(
        secrets_list_impl(&state, None, Some(dummy_id)).unwrap_err().code,
        "locked"
    );
    assert_eq!(
        secret_reveal_impl(&state, dummy_id).unwrap_err().code,
        "locked"
    );
    assert_eq!(
        secret_copy_impl(Arc::clone(&mock_cb), &state, dummy_id)
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        secret_create_impl(None, &state, dummy_draft.clone())
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        secret_update_impl(None, &state, dummy_id, dummy_draft)
            .unwrap_err()
            .code,
        "locked"
    );
    assert_eq!(
        secret_delete_impl(None, &state, dummy_id).unwrap_err().code,
        "locked"
    );
    assert_eq!(
        secret_copy_to_environment_impl(None, &state, dummy_id, Some(dummy_id))
            .unwrap_err()
            .code,
        "locked"
    );

    assert_eq!(overview_impl(&state).unwrap_err().code, "locked");
    assert_eq!(settings_get_impl(&state).unwrap_err().code, "locked");
    assert_eq!(
        settings_set_impl(None, &state, dummy_patch)
            .unwrap_err()
            .code,
        "locked"
    );

    // PHASE 3: Unlock again
    secwet_unlock_impl(None, &state).unwrap();
    assert_eq!(
        secwet_status_impl(&state).unwrap(),
        SecwetStatusDto::Unlocked { secwet_id }
    );

    // Double unlocking is idempotent
    secwet_unlock_impl(None, &state).unwrap();
    assert_eq!(
        secwet_status_impl(&state).unwrap(),
        SecwetStatusDto::Unlocked { secwet_id }
    );

    // Commands now work
    assert_eq!(projects_list_impl(&state).unwrap().len(), 0);
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
    secwet_create_impl(None, &state1, Some("Node-1".into())).unwrap();
    let proj =
        project_create_impl(None, &state1, "SharedProj".into(), vec!["Prod".into()]).unwrap();
    let env_id = proj.environments[0].id;

    // Instance 2: Connects to the same database directory and keystore
    let state2 = Arc::new(AppState::new(
        dir.path().to_path_buf(),
        Arc::clone(&keystore),
    ));
    secwet_unlock_impl(None, &state2).unwrap();

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
            secret_create_impl(None, &s1, draft).expect("Writer failed in multi-instance WAL");
            thread::sleep(Duration::from_millis(1));
        }
    });

    let reader_handle = thread::spawn(move || {
        t2_barrier.wait();
        for _ in 0..30 {
            let list = secrets_list_impl(&s2, None, Some(env_id)).expect("Reader failed in multi-instance WAL");
            for meta in &list {
                let revealed =
                    secret_reveal_impl(&s2, meta.id).expect("Reveal failed in multi-instance WAL");
                assert!(!revealed.is_empty());
            }
            thread::sleep(Duration::from_millis(1));
        }
    });

    writer_handle.join().expect("Writer thread panicked");
    reader_handle.join().expect("Reader thread panicked");

    // Both instances see 30 secrets
    assert_eq!(secrets_list_impl(&state1, None, Some(env_id)).unwrap().len(), 30);
    assert_eq!(secrets_list_impl(&state2, None, Some(env_id)).unwrap().len(), 30);
}
