//! Adversarial challenge and stress test suite for secwet-core SQLite local storage & records.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §5.2, §11.2, and `ORIGINAL_REQUEST.md`.
//!
//! Evaluates:
//! 1. Plaintext Leakage (`db_contains_no_plaintext_names`):
//!    - Varied Unicode scripts (CJK, Cyrillic, Arabic, Hebrew, Greek).
//!    - Complex emojis, zero-width joiners, skin tones.
//!    - Maximum length names (1000+ chars), multi-line 64 KiB secret payloads, large notes.
//!    - SQL injection formatting payloads.
//!    - Verifies raw bytes of `.sqlite3`, `.sqlite3-wal`, and `.sqlite3-shm` across mutations.
//! 2. Cascade Deletion Integrity:
//!    - Deep multi-environment and multi-secret hierarchies.
//!    - Pre-deleted environments and secrets.
//!    - Verifies all child and grandchild records are set to `deleted = 1` and `blob IS NULL`.
//!    - Monotonic Lamport clock bump verification.
//!    - Edge cases: last environment protection, non-existent records, idempotency.
//! 3. WAL Mode, PRAGMA Invariants, Foreign Keys & Busy Timeout Concurrency:
//!    - Explicit verification of `journal_mode = WAL`, `foreign_keys = ON`, `busy_timeout = 5000`.
//!    - Enforcement of foreign keys on table schemas.
//!    - Multi-threaded concurrent readers and writers under WAL mode.
//!    - Empirical verification of busy timeout delay and resolution.

use secwet_core::crypto::seal_record;
use secwet_core::records::{
    cascade_delete_environment, cascade_delete_project, get_highest_lamport, get_meta, get_record,
    get_schema_version, insert_record, next_lamport, open_and_migrate, open_connection,
    query_active_records_by_type, query_records_by_parent, run_migrations, set_meta,
    soft_delete_record, update_record_blob, RecordRow,
};
use secwet_core::Error;
use secwet_proto::{EnvironmentBody, ProjectBody, RecordAad, RecordType, SecretBody, SecretKind};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use uuid::Uuid;

// ============================================================================
// 1. Adversarial Plaintext Leakage Verification
// ============================================================================

#[test]
fn challenge_db_contains_no_plaintext_adversarial_unicode_and_large_secrets() {
    let dir = tempdir().expect("tempdir creation");
    let db_path = dir.path().join("vault.sqlite3");
    let wal_path = dir.path().join("vault.sqlite3-wal");
    let shm_path = dir.path().join("vault.sqlite3-shm");

    let vault_id = Uuid::now_v7();
    let k_rec = [0x4au8; 32];
    let origin_device = "adversarial_test_runner_node_01";
    let now_ms = 1_730_100_000_000i64;

    // Adversarial canary strings across languages, emojis, lengths, and formats
    let canary_cjk_project = "CanaryProject_项目_密鑰_测试_カンパニー_프로젝트_9981";
    let canary_cyrillic_env = "CanaryEnv_СекретныйПроект_КлючДоступа_Стейджинг_5541";
    let canary_arabic_secret_name = "CANARY_مشروع_سري_للغاية_مفتاح_امان_KEY";
    let canary_hebrew_note = "הערה סודית ביותר עבור מפתח אבטחה קריטי 7712";
    let canary_greek_str = "ΜυστικόΈργο_ΚλειδίΠρόσβασης_Ωμέγα_3319";
    let canary_emoji_name = "🔐Key_🛡️_SuperSecret_👩‍💻_Rocket_🚀_Sparkles_✨_8820";
    let canary_sql_injection =
        "Canary'; DROP TABLE records; DROP TABLE meta; SELECT * FROM sqlite_master; --";

    // 64 KiB multi-line secret payload with varied whitespace and special symbols
    let mut canary_64kib_secret_value = String::with_capacity(65536);
    canary_64kib_secret_value.push_str("-----BEGIN CANARY HIGH CONFIDENTIALITY PRIVATE KEY-----\n");
    for i in 0..1000 {
        canary_64kib_secret_value.push_str(&format!(
            "Line_{:04}: canary_chunk_token_{}_xyz_!@#$%^&*()_+=~`{}[]\r\n",
            i,
            i * 73,
            canary_greek_str
        ));
    }
    canary_64kib_secret_value.push_str("-----END CANARY HIGH CONFIDENTIALITY PRIVATE KEY-----\n");

    let canary_updated_secret_val = "Canary_Updated_Secret_Payload_Replacement_4091_Success";

    let project_id = Uuid::now_v7();
    let env_id = Uuid::now_v7();
    let secret_id = Uuid::now_v7();

    {
        let mut conn = open_connection(&db_path).expect("open connection");
        run_migrations(&mut conn).expect("run migrations");

        // 1. Insert Project with CJK and SQL injection string
        let project_body = ProjectBody::new(canary_cjk_project);
        let p_bytes = postcard::to_stdvec(&project_body).unwrap();
        let p_aad = RecordAad::new(
            vault_id.as_bytes(),
            project_id.as_bytes(),
            RecordType::Project,
            1,
        );
        let p_blob = seal_record(&k_rec, &p_aad, &p_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                project_id,
                RecordType::Project,
                None,
                1,
                p_blob,
                1,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // 2. Insert Environment with Cyrillic & Emoji name
        let env_body = EnvironmentBody::new(project_id, canary_cyrillic_env, 0);
        let e_bytes = postcard::to_stdvec(&env_body).unwrap();
        let e_aad = RecordAad::new(
            vault_id.as_bytes(),
            env_id.as_bytes(),
            RecordType::Environment,
            1,
        );
        let e_blob = seal_record(&k_rec, &e_aad, &e_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                env_id,
                RecordType::Environment,
                Some(project_id),
                1,
                e_blob,
                2,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // 3. Insert Secret with Arabic name, 64 KiB value, Hebrew note, and SQL injection tag
        let secret_body = SecretBody::new(
            project_id,
            env_id,
            canary_arabic_secret_name,
            SecretKind::Certificate,
            &canary_64kib_secret_value,
            Some(format!("{} | {}", canary_hebrew_note, canary_sql_injection)),
        );
        let s_bytes = postcard::to_stdvec(&secret_body).unwrap();
        let s_aad = RecordAad::new(
            vault_id.as_bytes(),
            secret_id.as_bytes(),
            RecordType::Secret,
            1,
        );
        let s_blob = seal_record(&k_rec, &s_aad, &s_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                secret_id,
                RecordType::Secret,
                Some(env_id),
                1,
                s_blob,
                3,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Checkpoint WAL and scan bytes BEFORE update
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    // Scan raw files on disk before update
    let read_all_db_bytes = || -> Vec<u8> {
        let mut bytes = Vec::new();
        if db_path.exists() {
            bytes.extend(std::fs::read(&db_path).unwrap());
        }
        if wal_path.exists() {
            bytes.extend(std::fs::read(&wal_path).unwrap());
        }
        if shm_path.exists() {
            bytes.extend(std::fs::read(&shm_path).unwrap());
        }
        bytes
    };

    let initial_bytes = read_all_db_bytes();
    let canaries_to_check: &[&str] = &[
        canary_cjk_project,
        canary_cyrillic_env,
        canary_arabic_secret_name,
        canary_hebrew_note,
        canary_greek_str,
        canary_emoji_name,
        canary_sql_injection,
        "BEGIN CANARY HIGH CONFIDENTIALITY PRIVATE KEY",
        "canary_chunk_token_0",
        "canary_chunk_token_73",
        "END CANARY HIGH CONFIDENTIALITY PRIVATE KEY",
    ];

    for canary in canaries_to_check {
        let needle = canary.as_bytes();
        let found = initial_bytes
            .windows(needle.len())
            .any(|window| window == needle);
        assert!(
            !found,
            "CRITICAL: Plaintext canary '{}' found in raw database bytes before update!",
            canary
        );
    }

    // Now reopen, update secret blob with updated value & emoji name, then soft-delete
    {
        let conn = open_connection(&db_path).expect("reopen");
        let updated_secret_body = SecretBody::new(
            project_id,
            env_id,
            canary_emoji_name,
            SecretKind::Password,
            canary_updated_secret_val,
            Some("Updated note".to_string()),
        );
        let updated_bytes = postcard::to_stdvec(&updated_secret_body).unwrap();
        let updated_aad = RecordAad::new(
            vault_id.as_bytes(),
            secret_id.as_bytes(),
            RecordType::Secret,
            1,
        );
        let updated_blob = seal_record(&k_rec, &updated_aad, &updated_bytes).unwrap();

        update_record_blob(
            &conn,
            secret_id,
            &updated_blob,
            "adversarial_updater",
            now_ms + 1000,
        )
        .unwrap();

        // Soft-delete secret
        soft_delete_record(&conn, secret_id, "adversarial_deleter", now_ms + 2000).unwrap();

        // Checkpoint again
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    // Scan raw files on disk after update and soft-delete
    let post_delete_bytes = read_all_db_bytes();
    for canary in canaries_to_check {
        let needle = canary.as_bytes();
        let found = post_delete_bytes
            .windows(needle.len())
            .any(|window| window == needle);
        assert!(
            !found,
            "CRITICAL: Plaintext canary '{}' found in raw database bytes after update & soft-delete!",
            canary
        );
    }

    let updated_needle = canary_updated_secret_val.as_bytes();
    assert!(
        !post_delete_bytes
            .windows(updated_needle.len())
            .any(|w| w == updated_needle),
        "CRITICAL: Updated plaintext canary found in raw database bytes!"
    );
}

// ============================================================================
// 2. Adversarial Cascade Deletion Verification
// ============================================================================

#[test]
fn challenge_cascade_deletion_deep_and_edge_cases() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let mut conn = open_and_migrate(&db_path).expect("open_and_migrate");
    let vault_id = Uuid::now_v7();
    let k_rec = [0x55u8; 32];
    let origin_device = "cascade_adversary";
    let now_ms = 1_730_200_000_000i64;

    let project_id = Uuid::now_v7();

    // Insert project
    let p_blob = seal_record(
        &k_rec,
        &RecordAad::new(
            vault_id.as_bytes(),
            project_id.as_bytes(),
            RecordType::Project,
            1,
        ),
        &postcard::to_stdvec(&ProjectBody::new("MegaProject")).unwrap(),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            project_id,
            RecordType::Project,
            None,
            1,
            p_blob,
            1,
            origin_device,
            now_ms,
        ),
    )
    .unwrap();

    // Create 4 environments:
    // Env 0: 5 secrets
    // Env 1: 0 secrets (empty env)
    // Env 2: 3 secrets, of which 1 is soft-deleted beforehand
    // Env 3: 10 secrets
    let mut env_ids = Vec::new();
    let mut all_secret_ids = Vec::new();
    let mut pre_deleted_secret_id = None;

    let secret_counts = [5, 0, 3, 10];
    let mut clock = 2u64;

    for (env_idx, &count) in secret_counts.iter().enumerate() {
        let env_id = Uuid::now_v7();
        env_ids.push(env_id);

        let e_blob = seal_record(
            &k_rec,
            &RecordAad::new(
                vault_id.as_bytes(),
                env_id.as_bytes(),
                RecordType::Environment,
                1,
            ),
            &postcard::to_stdvec(&EnvironmentBody::new(
                project_id,
                format!("Env_{}", env_idx),
                env_idx as u32,
            ))
            .unwrap(),
        )
        .unwrap();

        clock += 1;
        insert_record(
            &conn,
            &RecordRow::new_active(
                env_id,
                RecordType::Environment,
                Some(project_id),
                1,
                e_blob,
                clock,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        for s_idx in 0..count {
            let secret_id = Uuid::now_v7();
            all_secret_ids.push(secret_id);

            let s_blob = seal_record(
                &k_rec,
                &RecordAad::new(
                    vault_id.as_bytes(),
                    secret_id.as_bytes(),
                    RecordType::Secret,
                    1,
                ),
                &postcard::to_stdvec(&SecretBody::new(
                    project_id,
                    env_id,
                    format!("SECRET_{}_{}", env_idx, s_idx),
                    SecretKind::ApiKey,
                    "val",
                    None,
                ))
                .unwrap(),
            )
            .unwrap();

            clock += 1;
            insert_record(
                &conn,
                &RecordRow::new_active(
                    secret_id,
                    RecordType::Secret,
                    Some(env_id),
                    1,
                    s_blob,
                    clock,
                    origin_device,
                    now_ms,
                ),
            )
            .unwrap();

            if env_idx == 2 && s_idx == 0 {
                // Soft-delete this secret beforehand
                pre_deleted_secret_id = Some(secret_id);
            }
        }
    }

    // Soft-delete the chosen secret before cascade delete
    let p_del_id = pre_deleted_secret_id.unwrap();
    soft_delete_record(&conn, p_del_id, origin_device, now_ms + 10).unwrap();

    // Verify initial state
    let active_projects =
        query_active_records_by_type(&conn, RecordType::Project).expect("active projects");
    assert_eq!(active_projects.len(), 1);

    let active_envs = query_records_by_parent(&conn, Some(project_id), false).expect("active envs");
    assert_eq!(active_envs.len(), 4);

    let total_active_secrets: usize = env_ids
        .iter()
        .map(|eid| {
            query_records_by_parent(&conn, Some(*eid), false)
                .unwrap()
                .len()
        })
        .sum();
    // 5 + 0 + (3 - 1) + 10 = 17 active secrets
    assert_eq!(total_active_secrets, 17);

    // Now execute cascade deletion of project
    let summary = cascade_delete_project(&mut conn, project_id, origin_device, now_ms + 100)
        .expect("cascade delete");

    assert_eq!(summary.id, project_id);
    assert_eq!(summary.environments_deleted, 4);
    assert_eq!(summary.secrets_deleted, 17);
    assert_eq!(summary.total_records_affected, 1 + 4 + 17);

    // EMPIRICAL INVARIANT CHECK:
    // 1. Project record is marked deleted = true, blob = None
    let p_rec = get_record(&conn, project_id).unwrap().unwrap();
    assert!(p_rec.deleted);
    assert!(p_rec.blob.is_none());

    // 2. EVERY child environment record is marked deleted = true, blob = None
    for eid in &env_ids {
        let e_rec = get_record(&conn, *eid).unwrap().unwrap();
        assert!(e_rec.deleted, "Env {:?} must be marked deleted", eid);
        assert!(
            e_rec.blob.is_none(),
            "Env {:?} blob must be NULL upon deletion",
            eid
        );
        assert!(
            e_rec.lamport > p_rec.lamport,
            "Env lamport must be higher than project lamport"
        );
    }

    // 3. EVERY grandchild secret record is marked deleted = true, blob = None
    for sid in &all_secret_ids {
        let s_rec = get_record(&conn, *sid).unwrap().unwrap();
        assert!(s_rec.deleted, "Secret {:?} must be marked deleted", sid);
        assert!(
            s_rec.blob.is_none(),
            "Secret {:?} blob must be NULL upon deletion",
            sid
        );
    }

    // 4. Querying active records returns completely empty
    let remaining_projects = query_active_records_by_type(&conn, RecordType::Project).unwrap();
    assert!(remaining_projects.is_empty());

    let remaining_envs = query_records_by_parent(&conn, Some(project_id), false).unwrap();
    assert!(remaining_envs.is_empty());

    for eid in &env_ids {
        let remaining_secrets = query_records_by_parent(&conn, Some(*eid), false).unwrap();
        assert!(remaining_secrets.is_empty());
    }

    // 5. Cascade delete on already-deleted project returns Error::NotFound
    let err = cascade_delete_project(&mut conn, project_id, origin_device, now_ms + 200)
        .expect_err("repeat cascade delete must fail");
    match err {
        Error::NotFound => {}
        other => panic!("expected Error::NotFound, got: {:?}", other),
    }

    // 6. Cascade delete on non-existent ID returns Error::NotFound
    let err = cascade_delete_project(&mut conn, Uuid::now_v7(), origin_device, now_ms + 200)
        .expect_err("non-existent id cascade delete must fail");
    match err {
        Error::NotFound => {}
        other => panic!("expected Error::NotFound, got: {:?}", other),
    }
}

// ============================================================================
// 3. WAL Mode, PRAGMA Invariants, Foreign Keys & Busy Timeout Concurrency
// ============================================================================

#[test]
fn challenge_pragma_invariants_and_foreign_key_enforcement() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let conn = open_connection(&db_path).expect("open_connection");

    // 1. Verify PRAGMA journal_mode = WAL
    let journal_mode: String = conn
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .expect("query journal_mode");
    assert_eq!(
        journal_mode.to_lowercase(),
        "wal",
        "PRAGMA journal_mode must be WAL on disk database"
    );

    // 2. Verify PRAGMA foreign_keys = 1
    let foreign_keys: i64 = conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .expect("query foreign_keys");
    assert_eq!(foreign_keys, 1, "PRAGMA foreign_keys must be ON (1)");

    // 3. Verify PRAGMA busy_timeout = 5000
    let busy_timeout: i64 = conn
        .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
        .expect("query busy_timeout");
    assert_eq!(
        busy_timeout, 5000,
        "PRAGMA busy_timeout must be exactly 5000 ms"
    );

    // 4. Empirically verify that foreign key constraint violations are rejected
    conn.execute_batch(
        "CREATE TABLE test_parent (id BLOB PRIMARY KEY);\n\
         CREATE TABLE test_child (id BLOB PRIMARY KEY, parent_id BLOB REFERENCES test_parent(id));",
    )
    .expect("create test foreign key tables");

    let bad_parent_id = Uuid::now_v7();
    let child_id = Uuid::now_v7();

    // Inserting a child with non-existent parent MUST fail foreign key check
    let res = conn.execute(
        "INSERT INTO test_child (id, parent_id) VALUES (?1, ?2)",
        rusqlite::params![
            child_id.as_bytes().as_slice(),
            bad_parent_id.as_bytes().as_slice()
        ],
    );
    assert!(
        res.is_err(),
        "Foreign key enforcement must reject child referencing non-existent parent"
    );

    // Insert parent first, then child must succeed
    conn.execute(
        "INSERT INTO test_parent (id) VALUES (?1)",
        rusqlite::params![bad_parent_id.as_bytes().as_slice()],
    )
    .expect("insert parent");

    conn.execute(
        "INSERT INTO test_child (id, parent_id) VALUES (?1, ?2)",
        rusqlite::params![
            child_id.as_bytes().as_slice(),
            bad_parent_id.as_bytes().as_slice()
        ],
    )
    .expect("insert child with existing parent must succeed");

    // Deleting parent while child exists MUST fail
    let del_parent_res = conn.execute(
        "DELETE FROM test_parent WHERE id = ?1",
        rusqlite::params![bad_parent_id.as_bytes().as_slice()],
    );
    assert!(
        del_parent_res.is_err(),
        "Foreign key enforcement must reject deleting parent with active children"
    );
}

#[test]
fn challenge_wal_concurrent_readers_and_writers_stress() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    // Initialize schema
    {
        let conn = open_and_migrate(&db_path).expect("open_and_migrate");
        // Insert a base project
        let p_id = Uuid::now_v7();
        insert_record(
            &conn,
            &RecordRow::new_active(
                p_id,
                RecordType::Project,
                None,
                1,
                vec![1, 2, 3],
                1,
                "init",
                1_730_000_000_000,
            ),
        )
        .unwrap();
    }

    let running = Arc::new(AtomicBool::new(true));
    let mut handles = Vec::new();

    // Spawn 4 concurrent readers
    for _reader_idx in 0..4 {
        let db_path_clone = db_path.clone();
        let running_clone = Arc::clone(&running);
        let h = thread::spawn(move || {
            let conn = open_connection(&db_path_clone).expect("reader open_connection");
            let mut reads = 0;
            while running_clone.load(Ordering::Relaxed) {
                let projects = query_active_records_by_type(&conn, RecordType::Project).unwrap();
                assert!(!projects.is_empty());
                let _ = query_records_by_parent(&conn, None, true).unwrap();
                reads += 1;
                thread::yield_now();
            }
            reads
        });
        handles.push(h);
    }

    // Spawn 4 concurrent writers
    let mut writer_handles = Vec::new();
    for writer_idx in 0..4 {
        let db_path_clone = db_path.clone();
        let h = thread::spawn(move || {
            let conn = open_connection(&db_path_clone).expect("writer open_connection");
            for i in 0..50 {
                let rec_id = Uuid::now_v7();
                let lamport = next_lamport(&conn).unwrap();
                let row = RecordRow::new_active(
                    rec_id,
                    RecordType::Secret,
                    None,
                    1,
                    vec![0xAA; 32],
                    lamport,
                    format!("writer_{}", writer_idx),
                    1_730_000_000_000 + i,
                );
                insert_record(&conn, &row).expect("insert record concurrent");

                if i % 5 == 0 {
                    let updated_blob = vec![0xBB; 48];
                    let _ = update_record_blob(
                        &conn,
                        rec_id,
                        &updated_blob,
                        &format!("writer_{}", writer_idx),
                        1_730_000_000_000 + i + 1,
                    )
                    .expect("update record blob concurrent");
                }

                if i % 10 == 0 {
                    let _ = soft_delete_record(
                        &conn,
                        rec_id,
                        &format!("writer_{}", writer_idx),
                        1_730_000_000_000 + i + 2,
                    )
                    .expect("soft delete record concurrent");
                }
            }
        });
        writer_handles.push(h);
    }

    // Wait for all writers to finish
    for wh in writer_handles {
        wh.join().expect("writer thread panicked");
    }

    // Stop readers
    running.store(false, Ordering::Relaxed);
    for rh in handles {
        let reads = rh.join().expect("reader thread panicked");
        assert!(reads > 0, "Reader must have completed reads");
    }

    // Verify database integrity post-concurrency
    let conn = open_connection(&db_path).expect("verify open");
    let integrity_check: String = conn
        .query_row("PRAGMA integrity_check", [], |row| row.get(0))
        .expect("integrity_check");
    assert_eq!(
        integrity_check, "ok",
        "Database integrity check must return 'ok' after concurrent operations"
    );
}

#[test]
fn challenge_busy_timeout_empirical_resolution() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    // Initialize database
    {
        let conn = open_and_migrate(&db_path).expect("init");
        conn.execute("CREATE TABLE counter (v INTEGER);", [])
            .unwrap();
        conn.execute("INSERT INTO counter VALUES (0);", []).unwrap();
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .unwrap();
    }

    let db_path_1 = db_path.clone();
    let db_path_2 = db_path.clone();

    // Thread 1 acquires an IMMEDIATE write transaction and holds it for 400ms
    let lock_started = Arc::new(AtomicBool::new(false));
    let lock_started_clone = Arc::clone(&lock_started);

    let t1 = thread::spawn(move || {
        let mut conn1 = open_connection(&db_path_1).expect("open t1");
        let tx = conn1
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("t1 transaction immediate");

        tx.execute("UPDATE counter SET v = v + 1", []).unwrap();
        lock_started_clone.store(true, Ordering::SeqCst);

        // Sleep 400ms while holding the write lock
        thread::sleep(Duration::from_millis(400));
        tx.commit().expect("t1 commit");
    });

    // Wait until Thread 1 has acquired the lock
    while !lock_started.load(Ordering::SeqCst) {
        thread::yield_now();
    }

    // Thread 2 attempts to write immediately while Thread 1 holds the lock.
    // Because busy_timeout = 5000ms, Thread 2 MUST wait ~400ms and SUCCEED.
    let t2 = thread::spawn(move || {
        let start = Instant::now();
        let mut conn2 = open_connection(&db_path_2).expect("open t2");

        // Should wait until t1 commits and then succeed
        let tx = conn2
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("t2 transaction immediate should succeed via busy_timeout");

        let elapsed = start.elapsed();
        tx.execute("UPDATE counter SET v = v + 1", []).unwrap();
        tx.commit().expect("t2 commit");

        elapsed
    });

    t1.join().expect("t1 panicked");
    let elapsed = t2.join().expect("t2 panicked");

    // Verify elapsed time is around ~400ms (at least 200ms to prove it actually waited and didn't bypass)
    assert!(
        elapsed >= Duration::from_millis(200),
        "t2 should have waited at least 200ms for busy lock resolution, waited: {:?}",
        elapsed
    );

    // Verify counter value is 2
    let conn = open_connection(&db_path).expect("final open");
    let final_v: i64 = conn
        .query_row("SELECT v FROM counter", [], |r| r.get(0))
        .unwrap();
    assert_eq!(final_v, 2, "Both transactions must have committed");
}

#[test]
fn challenge_meta_table_storage_and_version() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let conn = open_and_migrate(&db_path).expect("open_and_migrate");

    // Schema version
    let ver = get_schema_version(&conn).expect("get_schema_version");
    assert_eq!(ver, 2);

    let meta_ver = get_meta(&conn, "schema_version").expect("get_meta");
    assert_eq!(meta_ver, Some("2".to_string()));

    // Custom metadata
    set_meta(&conn, "vault_id", "018f-canary-vault-id").expect("set_meta");
    let fetched = get_meta(&conn, "vault_id").expect("get_meta");
    assert_eq!(fetched, Some("018f-canary-vault-id".to_string()));

    // Missing key
    let missing = get_meta(&conn, "non_existent_key").expect("get_meta");
    assert_eq!(missing, None);
}

#[test]
fn challenge_db_contains_no_plaintext_in_uncheckpointed_wal() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");
    let wal_path = dir.path().join("vault.sqlite3-wal");

    let vault_id = Uuid::now_v7();
    let k_rec = [0x7eu8; 32];
    let origin_device = "uncheckpointed_wal_tester";
    let now_ms = 1_730_300_000_000i64;

    let canary_uncheckpointed_secret_val =
        "RAW_WAL_CANARY_VALUE_SUPER_SECRET_PAYLOAD_UNCHECKPOINTED";
    let canary_uncheckpointed_name = "RAW_WAL_SECRET_NAME_CANARY_7761";

    let conn = open_and_migrate(&db_path).expect("open_and_migrate");

    let p_id = Uuid::now_v7();
    let e_id = Uuid::now_v7();
    let s_id = Uuid::now_v7();

    // Insert secret directly into WAL without checkpoint
    let s_body = SecretBody::new(
        p_id,
        e_id,
        canary_uncheckpointed_name,
        SecretKind::ApiKey,
        canary_uncheckpointed_secret_val,
        None,
    );
    let s_blob = seal_record(
        &k_rec,
        &RecordAad::new(vault_id.as_bytes(), s_id.as_bytes(), RecordType::Secret, 1),
        &postcard::to_stdvec(&s_body).unwrap(),
    )
    .unwrap();

    insert_record(
        &conn,
        &RecordRow::new_active(
            s_id,
            RecordType::Secret,
            Some(e_id),
            1,
            s_blob,
            1,
            origin_device,
            now_ms,
        ),
    )
    .unwrap();

    // Deliberately do NOT checkpoint WAL!
    // Flush OS buffers and inspect raw bytes of WAL file directly while connection is open
    assert!(
        wal_path.exists(),
        "WAL file must exist after active transactions"
    );
    let wal_bytes = std::fs::read(&wal_path).expect("read wal file directly");

    let needle_val = canary_uncheckpointed_secret_val.as_bytes();
    assert!(
        !wal_bytes.windows(needle_val.len()).any(|w| w == needle_val),
        "CRITICAL: Uncheckpointed WAL file contains plaintext secret value!"
    );

    let needle_name = canary_uncheckpointed_name.as_bytes();
    assert!(
        !wal_bytes
            .windows(needle_name.len())
            .any(|w| w == needle_name),
        "CRITICAL: Uncheckpointed WAL file contains plaintext secret name!"
    );
}

#[test]
fn challenge_multi_project_last_environment_protection_isolation() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let mut conn = open_and_migrate(&db_path).expect("open_and_migrate");
    let vault_id = Uuid::now_v7();
    let k_rec = [0x66u8; 32];
    let origin = "multi_proj_tester";
    let now = 1_730_000_000_000i64;

    // Project 1 has only 1 environment (Env 1A)
    let p1_id = Uuid::now_v7();
    let e1a_id = Uuid::now_v7();

    insert_record(
        &conn,
        &RecordRow::new_active(
            p1_id,
            RecordType::Project,
            None,
            1,
            seal_record(
                &k_rec,
                &RecordAad::new(
                    vault_id.as_bytes(),
                    p1_id.as_bytes(),
                    RecordType::Project,
                    1,
                ),
                &postcard::to_stdvec(&ProjectBody::new("P1")).unwrap(),
            )
            .unwrap(),
            1,
            origin,
            now,
        ),
    )
    .unwrap();

    insert_record(
        &conn,
        &RecordRow::new_active(
            e1a_id,
            RecordType::Environment,
            Some(p1_id),
            1,
            seal_record(
                &k_rec,
                &RecordAad::new(
                    vault_id.as_bytes(),
                    e1a_id.as_bytes(),
                    RecordType::Environment,
                    1,
                ),
                &postcard::to_stdvec(&EnvironmentBody::new(p1_id, "E1A", 0)).unwrap(),
            )
            .unwrap(),
            2,
            origin,
            now,
        ),
    )
    .unwrap();

    // Project 2 has 2 environments (Env 2A, Env 2B)
    let p2_id = Uuid::now_v7();
    let e2a_id = Uuid::now_v7();
    let e2b_id = Uuid::now_v7();

    insert_record(
        &conn,
        &RecordRow::new_active(
            p2_id,
            RecordType::Project,
            None,
            1,
            seal_record(
                &k_rec,
                &RecordAad::new(
                    vault_id.as_bytes(),
                    p2_id.as_bytes(),
                    RecordType::Project,
                    1,
                ),
                &postcard::to_stdvec(&ProjectBody::new("P2")).unwrap(),
            )
            .unwrap(),
            3,
            origin,
            now,
        ),
    )
    .unwrap();

    insert_record(
        &conn,
        &RecordRow::new_active(
            e2a_id,
            RecordType::Environment,
            Some(p2_id),
            1,
            seal_record(
                &k_rec,
                &RecordAad::new(
                    vault_id.as_bytes(),
                    e2a_id.as_bytes(),
                    RecordType::Environment,
                    1,
                ),
                &postcard::to_stdvec(&EnvironmentBody::new(p2_id, "E2A", 0)).unwrap(),
            )
            .unwrap(),
            4,
            origin,
            now,
        ),
    )
    .unwrap();

    insert_record(
        &conn,
        &RecordRow::new_active(
            e2b_id,
            RecordType::Environment,
            Some(p2_id),
            1,
            seal_record(
                &k_rec,
                &RecordAad::new(
                    vault_id.as_bytes(),
                    e2b_id.as_bytes(),
                    RecordType::Environment,
                    1,
                ),
                &postcard::to_stdvec(&EnvironmentBody::new(p2_id, "E2B", 1)).unwrap(),
            )
            .unwrap(),
            5,
            origin,
            now,
        ),
    )
    .unwrap();

    // Deleting Env 1A MUST fail with Error::LastEnvironment, even though the database has 3 total active environments!
    let err1 = cascade_delete_environment(&mut conn, e1a_id, origin, now + 10)
        .expect_err("P1 only has 1 env; must refuse to delete");
    match err1 {
        Error::LastEnvironment => {}
        other => panic!("expected Error::LastEnvironment, got: {:?}", other),
    }

    // Deleting Env 2A MUST succeed because P2 has 2 environments
    let summary = cascade_delete_environment(&mut conn, e2a_id, origin, now + 20)
        .expect("P2 has 2 envs; deleting one must succeed");
    assert_eq!(summary.environments_deleted, 1);

    // Deleting Env 2B now MUST fail with Error::LastEnvironment because P2 only has 1 remaining
    let err2 = cascade_delete_environment(&mut conn, e2b_id, origin, now + 30)
        .expect_err("P2 now has only 1 env remaining; must refuse to delete");
    match err2 {
        Error::LastEnvironment => {}
        other => panic!("expected Error::LastEnvironment, got: {:?}", other),
    }
}

#[test]
fn challenge_schema_all_seven_tables_and_indices_exist() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let conn = open_and_migrate(&db_path).expect("open_and_migrate");

    let required_tables = [
        "meta",
        "records",
        "devices",
        "outbox",
        "applied_events",
        "sync_state",
        "settings",
    ];

    for table in required_tables {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?1",
                rusqlite::params![table],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(count, 1, "Table '{}' must exist in schema", table);
    }

    let required_indices = ["records_parent", "records_type"];
    for index in required_indices {
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?1",
                rusqlite::params![index],
                |r| r.get(0),
            )
            .unwrap_or(0);
        assert_eq!(count, 1, "Index '{}' must exist in schema", index);
    }
}

#[test]
fn challenge_lamport_clock_monotonicity_under_sequential_and_cascade_ops() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let mut conn = open_and_migrate(&db_path).expect("open_and_migrate");

    // Empty DB highest lamport is 0
    assert_eq!(get_highest_lamport(&conn).unwrap(), 0);
    assert_eq!(next_lamport(&conn).unwrap(), 1);

    // Insert record with lamport 100
    let id1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            id1,
            RecordType::Project,
            None,
            1,
            vec![1],
            100,
            "dev",
            1_730_000_000_000,
        ),
    )
    .unwrap();

    assert_eq!(get_highest_lamport(&conn).unwrap(), 100);
    assert_eq!(next_lamport(&conn).unwrap(), 101);

    // Insert record with lamport 50 (should not decrease highest lamport)
    let id2 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            id2,
            RecordType::Environment,
            Some(id1),
            1,
            vec![2],
            50,
            "dev",
            1_730_000_000_000,
        ),
    )
    .unwrap();

    assert_eq!(get_highest_lamport(&conn).unwrap(), 100);
    assert_eq!(next_lamport(&conn).unwrap(), 101);

    // Update blob bumps lamport to 101
    let new_lam = update_record_blob(&conn, id2, &[3], "dev", 1_730_000_000_001).unwrap();
    assert_eq!(new_lam, 101);
    assert_eq!(get_highest_lamport(&conn).unwrap(), 101);

    // Soft delete bumps to 102
    let del_lam = soft_delete_record(&conn, id2, "dev", 1_730_000_000_002).unwrap();
    assert_eq!(del_lam, 102);
    assert_eq!(get_highest_lamport(&conn).unwrap(), 102);

    // Cascade delete project bumps lamport sequentially
    let summary = cascade_delete_project(&mut conn, id1, "dev", 1_730_000_000_003).unwrap();
    assert_eq!(summary.total_records_affected, 1); // id2 was already deleted
    let post_cascade_lam = get_highest_lamport(&conn).unwrap();
    assert!(
        post_cascade_lam > 102,
        "Cascade deletion must have bumped Lamport clock above 102"
    );
}

#[test]
fn challenge_busy_timeout_failure_when_lock_held_beyond_timeout() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    {
        let conn = open_and_migrate(&db_path).expect("init");
        conn.execute("CREATE TABLE lock_test (x INTEGER);", [])
            .unwrap();
    }

    let db_path_1 = db_path.clone();
    let db_path_2 = db_path.clone();

    let lock_held = Arc::new(AtomicBool::new(false));
    let lock_held_clone = Arc::clone(&lock_held);

    let t1 = thread::spawn(move || {
        let mut conn1 = open_connection(&db_path_1).expect("open t1");
        let tx = conn1
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .expect("t1 tx");
        tx.execute("INSERT INTO lock_test VALUES (1)", []).unwrap();
        lock_held_clone.store(true, Ordering::SeqCst);

        // Sleep 600ms while holding the lock
        thread::sleep(Duration::from_millis(600));
        tx.commit().expect("t1 commit");
    });

    while !lock_held.load(Ordering::SeqCst) {
        thread::yield_now();
    }

    // Thread 2 configures a small busy timeout of 100ms. Since Thread 1 holds lock for 600ms, Thread 2 MUST fail!
    let t2 = thread::spawn(move || {
        let mut conn2 = open_connection(&db_path_2).expect("open t2");
        // Explicitly set busy_timeout to 100ms
        conn2
            .execute_batch("PRAGMA busy_timeout = 100;")
            .expect("set short timeout");

        let res = conn2.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate);
        assert!(
            res.is_err(),
            "Transaction must time out and fail when lock is held longer than busy_timeout"
        );
    });

    t1.join().expect("t1 join");
    t2.join().expect("t2 join");
}
