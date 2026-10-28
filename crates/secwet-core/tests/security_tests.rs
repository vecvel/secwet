//! Security and local storage acceptance test suite.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §5.2, §11.2, and `ORIGINAL_REQUEST.md`.

use secwet_core::crypto::{open_record, seal_record};
use secwet_core::records::{
    cascade_delete_environment, cascade_delete_project, get_record, insert_record,
    open_and_migrate, open_connection, query_active_records_by_type, query_records_by_parent,
    run_migrations, soft_delete_record, update_record_blob, RecordRow,
};
use secwet_core::Error;
use secwet_proto::{EnvironmentBody, ProjectBody, RecordAad, RecordType, SecretBody, SecretKind};
use tempfile::tempdir;
use uuid::Uuid;

/// Acceptance test mandated by `docs/IMPLEMENTATION.md` §11.2 and `ORIGINAL_REQUEST.md`:
/// `db_contains_no_plaintext_names`
///
/// Verifies:
/// 1. A real temporary SQLite database on disk with WAL mode enabled.
/// 2. Migrations run cleanly.
/// 3. Canary project, environment, and secret (with secret value and secret note) are sealed and inserted.
/// 4. `PRAGMA wal_checkpoint(TRUNCATE)` is executed to flush all pages to the database file.
/// 5. Database connection is closed.
/// 6. Raw bytes of `secwet.sqlite3`, `secwet.sqlite3-wal`, and `secwet.sqlite3-shm` are scanned.
/// 7. Zero occurrences of any plaintext canary strings are found in the files.
/// 8. Reopens database and verifies that cascade deletion marks child records `deleted = 1` with `blob = NULL`.
#[test]
fn db_contains_no_plaintext_names() {
    let dir = tempdir().expect("failed to create temp dir");
    let db_path = dir.path().join("secwet.sqlite3");
    let wal_path = dir.path().join("secwet.sqlite3-wal");
    let shm_path = dir.path().join("secwet.sqlite3-shm");

    let canary_project_name = "CanaryProject_Omega_9871";
    let canary_env_name = "CanaryEnv_Staging_5432";
    let canary_secret_name = "CANARY_STRIPE_LIVE_KEY_8192";
    let canary_secret_val = "sk_live_canary_super_secret_payload_value_99999";
    let canary_secret_note = "Confidential canary operational note 4401";

    let secwet_id = Uuid::now_v7();
    let k_rec = [0x5au8; 32];
    let origin_device = "device_test_runner";
    let now_ms = 1_730_000_000_000i64;

    let project_id = Uuid::now_v7();
    let env_id = Uuid::now_v7();
    let secret_id = Uuid::now_v7();

    {
        let mut conn = open_connection(&db_path).expect("failed to open connection");
        run_migrations(&mut conn).expect("failed to run migrations");

        // 1. Seal & insert Project
        let project_body = ProjectBody::new(canary_project_name);
        let project_bytes = postcard::to_stdvec(&project_body).expect("postcard serialization");
        let project_aad = RecordAad::new(
            secwet_id.as_bytes(),
            project_id.as_bytes(),
            RecordType::Project,
            1,
        );
        let project_blob = seal_record(&k_rec, &project_aad, &project_bytes).expect("seal_record");
        let project_row = RecordRow::new_active(
            project_id,
            RecordType::Project,
            None,
            1,
            project_blob,
            1,
            origin_device,
            now_ms,
        );
        insert_record(&conn, &project_row).expect("insert project");

        // 2. Seal & insert Environment
        let env_body = EnvironmentBody::new(project_id, canary_env_name, 0);
        let env_bytes = postcard::to_stdvec(&env_body).expect("postcard serialization");
        let env_aad = RecordAad::new(
            secwet_id.as_bytes(),
            env_id.as_bytes(),
            RecordType::Environment,
            1,
        );
        let env_blob = seal_record(&k_rec, &env_aad, &env_bytes).expect("seal_record");
        let env_row = RecordRow::new_active(
            env_id,
            RecordType::Environment,
            Some(project_id),
            1,
            env_blob,
            2,
            origin_device,
            now_ms,
        );
        insert_record(&conn, &env_row).expect("insert env");

        // 3. Seal & insert Secret
        let secret_body = SecretBody::new(
            project_id,
            env_id,
            canary_secret_name,
            SecretKind::ApiKey,
            canary_secret_val,
            Some(canary_secret_note.to_string()),
        );
        let secret_bytes = postcard::to_stdvec(&secret_body).expect("postcard serialization");
        let secret_aad = RecordAad::new(
            secwet_id.as_bytes(),
            secret_id.as_bytes(),
            RecordType::Secret,
            1,
        );
        let secret_blob = seal_record(&k_rec, &secret_aad, &secret_bytes).expect("seal_record");
        let secret_row = RecordRow::new_active(
            secret_id,
            RecordType::Secret,
            Some(env_id),
            1,
            secret_blob,
            3,
            origin_device,
            now_ms,
        );
        insert_record(&conn, &secret_row).expect("insert secret");

        // Checkpoint WAL completely into database file
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("wal_checkpoint");
        // Connection drops here and file handles close
    }

    // Read all bytes across the main SQLite file, WAL, and SHM files
    let mut all_bytes = Vec::new();
    assert!(db_path.exists(), "database file must exist on disk");
    all_bytes.extend(std::fs::read(&db_path).expect("read db file"));

    if wal_path.exists() {
        all_bytes.extend(std::fs::read(&wal_path).expect("read wal file"));
    }
    if shm_path.exists() {
        all_bytes.extend(std::fs::read(&shm_path).expect("read shm file"));
    }

    // Assert zero leakage of any sensitive plaintext canary string
    let canaries = [
        canary_project_name,
        canary_env_name,
        canary_secret_name,
        canary_secret_val,
        canary_secret_note,
    ];

    for canary in canaries {
        let needle = canary.as_bytes();
        let found = all_bytes
            .windows(needle.len())
            .any(|window| window == needle);
        assert!(
            !found,
            "CRITICAL SECURITY FAILURE: Plaintext canary '{}' was found in raw database file bytes!",
            canary
        );
    }

    // Now re-open connection and verify cascade deletion marks child records deleted=1 and blob=NULL
    {
        let mut conn = open_connection(&db_path).expect("reopen connection");

        // Verify active records before cascade deletion
        let active_projects = query_active_records_by_type(&conn, RecordType::Project)
            .expect("query active projects");
        assert_eq!(active_projects.len(), 1);

        let active_envs =
            query_records_by_parent(&conn, Some(project_id), false).expect("query active envs");
        assert_eq!(active_envs.len(), 1);

        let active_secrets =
            query_records_by_parent(&conn, Some(env_id), false).expect("query active secrets");
        assert_eq!(active_secrets.len(), 1);

        // Perform cascade deletion of project
        let summary = cascade_delete_project(&mut conn, project_id, origin_device, now_ms + 10_000)
            .expect("cascade_delete_project");
        assert_eq!(summary.environments_deleted, 1);
        assert_eq!(summary.secrets_deleted, 1);
        assert_eq!(summary.total_records_affected, 3);

        // Inspect records directly: deleted = 1 and blob is NULL
        let proj_rec = get_record(&conn, project_id)
            .expect("get_record")
            .expect("project row exists");
        assert!(proj_rec.deleted, "project record must be marked deleted");
        assert!(
            proj_rec.blob.is_none(),
            "project blob must be set to NULL upon deletion"
        );
        assert!(
            proj_rec.lamport > 3,
            "project lamport clock must be bumped upon deletion"
        );

        let env_rec = get_record(&conn, env_id)
            .expect("get_record")
            .expect("env row exists");
        assert!(env_rec.deleted, "environment record must be marked deleted");
        assert!(
            env_rec.blob.is_none(),
            "environment blob must be set to NULL upon deletion"
        );
        assert!(
            env_rec.lamport > proj_rec.lamport,
            "env lamport must be sequentially bumped"
        );

        let secret_rec = get_record(&conn, secret_id)
            .expect("get_record")
            .expect("secret row exists");
        assert!(secret_rec.deleted, "secret record must be marked deleted");
        assert!(
            secret_rec.blob.is_none(),
            "secret blob must be set to NULL upon deletion"
        );
        assert!(
            secret_rec.lamport > env_rec.lamport,
            "secret lamport must be sequentially bumped"
        );

        // Querying active records now returns empty
        let remaining_active_projects = query_active_records_by_type(&conn, RecordType::Project)
            .expect("query active projects");
        assert!(remaining_active_projects.is_empty());

        let remaining_active_envs =
            query_records_by_parent(&conn, Some(project_id), false).expect("query active envs");
        assert!(remaining_active_envs.is_empty());

        let remaining_active_secrets =
            query_records_by_parent(&conn, Some(env_id), false).expect("query active secrets");
        assert!(remaining_active_secrets.is_empty());

        // Checkpoint again and confirm no new leakage
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("wal_checkpoint");
    }
}

#[test]
fn test_cascade_delete_environment_and_last_environment_protection() {
    let dir = tempdir().expect("failed to create temp dir");
    let db_path = dir.path().join("secwet.sqlite3");

    let mut conn = open_and_migrate(&db_path).expect("open_and_migrate");
    let secwet_id = Uuid::now_v7();
    let k_rec = [0x77u8; 32];
    let origin_device = "dev_1";
    let now_ms = 1_730_000_000_000i64;

    let project_id = Uuid::now_v7();
    let env_1_id = Uuid::now_v7();
    let env_2_id = Uuid::now_v7();
    let secret_1_id = Uuid::now_v7();

    // 1. Create project
    let p_blob = seal_record(
        &k_rec,
        &RecordAad::new(
            secwet_id.as_bytes(),
            project_id.as_bytes(),
            RecordType::Project,
            1,
        ),
        &postcard::to_stdvec(&ProjectBody::new("App")).unwrap(),
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

    // 2. Create only 1 environment
    let e1_blob = seal_record(
        &k_rec,
        &RecordAad::new(
            secwet_id.as_bytes(),
            env_1_id.as_bytes(),
            RecordType::Environment,
            1,
        ),
        &postcard::to_stdvec(&EnvironmentBody::new(project_id, "Dev", 0)).unwrap(),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            env_1_id,
            RecordType::Environment,
            Some(project_id),
            1,
            e1_blob,
            2,
            origin_device,
            now_ms,
        ),
    )
    .unwrap();

    // 3. Attempting to delete the only environment fails with Error::LastEnvironment
    let err = cascade_delete_environment(&mut conn, env_1_id, origin_device, now_ms + 100)
        .expect_err("must refuse to delete last environment");
    match err {
        Error::LastEnvironment => {}
        other => panic!("expected Error::LastEnvironment, got: {:?}", other),
    }

    // 4. Add a second environment
    let e2_blob = seal_record(
        &k_rec,
        &RecordAad::new(
            secwet_id.as_bytes(),
            env_2_id.as_bytes(),
            RecordType::Environment,
            1,
        ),
        &postcard::to_stdvec(&EnvironmentBody::new(project_id, "Prod", 1)).unwrap(),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            env_2_id,
            RecordType::Environment,
            Some(project_id),
            1,
            e2_blob,
            3,
            origin_device,
            now_ms,
        ),
    )
    .unwrap();

    // Add a secret under env_2
    let s1_blob = seal_record(
        &k_rec,
        &RecordAad::new(
            secwet_id.as_bytes(),
            secret_1_id.as_bytes(),
            RecordType::Secret,
            1,
        ),
        &postcard::to_stdvec(&SecretBody::new(
            project_id,
            env_2_id,
            "API_KEY",
            SecretKind::ApiKey,
            "secret_val",
            None,
        ))
        .unwrap(),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            secret_1_id,
            RecordType::Secret,
            Some(env_2_id),
            1,
            s1_blob,
            4,
            origin_device,
            now_ms,
        ),
    )
    .unwrap();

    // 5. Deleting env_2 now succeeds because env_1 remains
    let summary = cascade_delete_environment(&mut conn, env_2_id, origin_device, now_ms + 200)
        .expect("should delete env_2");
    assert_eq!(summary.environments_deleted, 1);
    assert_eq!(summary.secrets_deleted, 1);

    // Verify env_2 and its secret are deleted with NULL blob
    let e2_rec = get_record(&conn, env_2_id).unwrap().unwrap();
    assert!(e2_rec.deleted);
    assert!(e2_rec.blob.is_none());

    let s1_rec = get_record(&conn, secret_1_id).unwrap().unwrap();
    assert!(s1_rec.deleted);
    assert!(s1_rec.blob.is_none());

    // 6. Attempting to delete env_1 now fails again with Error::LastEnvironment
    let err = cascade_delete_environment(&mut conn, env_1_id, origin_device, now_ms + 300)
        .expect_err("must refuse to delete last environment");
    match err {
        Error::LastEnvironment => {}
        other => panic!("expected Error::LastEnvironment, got: {:?}", other),
    }
}

#[test]
fn test_update_record_blob_and_soft_delete() {
    let dir = tempdir().expect("failed to create temp dir");
    let db_path = dir.path().join("secwet.sqlite3");

    let conn = open_and_migrate(&db_path).expect("open_and_migrate");
    let secwet_id = Uuid::now_v7();
    let k_rec = [0x88u8; 32];
    let origin_device = "dev_1";
    let now_ms = 1_730_000_000_000i64;

    let project_id = Uuid::now_v7();
    let initial_body = ProjectBody::new("InitialName");
    let initial_blob = seal_record(
        &k_rec,
        &RecordAad::new(
            secwet_id.as_bytes(),
            project_id.as_bytes(),
            RecordType::Project,
            1,
        ),
        &postcard::to_stdvec(&initial_body).unwrap(),
    )
    .unwrap();

    insert_record(
        &conn,
        &RecordRow::new_active(
            project_id,
            RecordType::Project,
            None,
            1,
            initial_blob,
            10,
            origin_device,
            now_ms,
        ),
    )
    .unwrap();

    // Update blob
    let updated_body = ProjectBody::new("UpdatedName");
    let updated_blob = seal_record(
        &k_rec,
        &RecordAad::new(
            secwet_id.as_bytes(),
            project_id.as_bytes(),
            RecordType::Project,
            1,
        ),
        &postcard::to_stdvec(&updated_body).unwrap(),
    )
    .unwrap();

    let new_lamport = update_record_blob(&conn, project_id, &updated_blob, "dev_2", now_ms + 500)
        .expect("update_record_blob");
    assert!(new_lamport > 10);

    let fetched = get_record(&conn, project_id).unwrap().unwrap();
    assert_eq!(fetched.lamport, new_lamport);
    assert_eq!(fetched.origin_device, "dev_2");
    assert_eq!(fetched.updated_at, now_ms + 500);

    // Verify decrypted content matches updated body
    let decrypted = open_record(
        &k_rec,
        &RecordAad::new(
            secwet_id.as_bytes(),
            project_id.as_bytes(),
            RecordType::Project,
            1,
        ),
        fetched.blob.as_ref().unwrap(),
    )
    .expect("open_record");
    let parsed: ProjectBody = postcard::from_bytes(&decrypted).unwrap();
    assert_eq!(parsed.name, "UpdatedName");

    // Soft delete
    let del_lamport =
        soft_delete_record(&conn, project_id, "dev_2", now_ms + 1000).expect("soft_delete_record");
    assert!(del_lamport > new_lamport);

    let deleted_rec = get_record(&conn, project_id).unwrap().unwrap();
    assert!(deleted_rec.deleted);
    assert!(deleted_rec.blob.is_none());

    // Non-existent ID returns NotFound
    let missing_id = Uuid::now_v7();
    let err = update_record_blob(&conn, missing_id, &updated_blob, "dev_2", now_ms)
        .expect_err("should return NotFound");
    match err {
        Error::NotFound => {}
        other => panic!("expected NotFound, got {:?}", other),
    }

    let err =
        soft_delete_record(&conn, missing_id, "dev_2", now_ms).expect_err("should return NotFound");
    match err {
        Error::NotFound => {}
        other => panic!("expected NotFound, got {:?}", other),
    }
}

/// Acceptance test mandated by `docs/IMPLEMENTATION.md` §11.2 and `ORIGINAL_REQUEST.md`:
/// `lock_zeroizes_keys`
///
/// Verifies:
/// 1. Create and unlock a secwet with `MemoryStore`.
/// 2. Retain a witness hook to internal key buffers (k_rec and k_evt).
/// 3. Assert before lock that the key buffers are non-zero.
/// 4. Call `secwet.lock()`.
/// 5. Assert after lock that key buffers are overwritten with zeros (`0x00`).
/// 6. Assert that `Secwet::status(data_dir)` now returns `SecwetStatus::Locked { secwet_id }`.
#[test]
fn lock_zeroizes_keys() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = secwet_core::MemoryStore::new();

    let secwet = secwet_core::Secwet::create(dir.path(), "test-device", &keystore)
        .expect("Secwet::create should succeed");
    let secwet_id = secwet.secwet_id();

    let k_rec_witness = secwet.test_k_rec_witness();
    let k_evt_witness = secwet.test_k_evt_witness();

    // Verify keys in memory are non-zero before lock
    assert_ne!(
        *k_rec_witness.lock().unwrap(),
        [0u8; 32],
        "k_rec buffer must be non-zero while unlocked"
    );
    assert_ne!(
        *k_evt_witness.lock().unwrap(),
        [0u8; 32],
        "k_evt buffer must be non-zero while unlocked"
    );

    // Call lock consuming the secwet
    secwet.lock();

    // Assert that in-memory key buffers are zeroized
    assert_eq!(
        *k_rec_witness.lock().unwrap(),
        [0u8; 32],
        "k_rec buffer must be zeroized to 0x00 after lock()"
    );
    assert_eq!(
        *k_evt_witness.lock().unwrap(),
        [0u8; 32],
        "k_evt buffer must be zeroized to 0x00 after lock()"
    );

    // Verify status returns Locked
    let status = secwet_core::Secwet::status(dir.path()).expect("Secwet::status");
    assert_eq!(
        status,
        secwet_core::SecwetStatus::Locked { secwet_id },
        "Secwet status must be Locked after calling lock()"
    );
}
