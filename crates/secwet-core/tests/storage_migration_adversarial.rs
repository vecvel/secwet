//! Empirical adversarial tests for secwet-core storage and migration (Milestone 1).
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §5.1, §5.2, §11.2, and `ORIGINAL_REQUEST.md`.
//!
//! Evaluates:
//! 1. Migration `0002_flexible_organization.sql` on a database with existing v1 schema and records:
//!    - Verifies migration succeeds cleanly, user_version is bumped to 2, schema_version is '2'.
//!    - Verifies indexes are created (`idx_labels_position`, `records_parent`, `records_type`).
//!    - Verifies existing v1 records, devices, and settings are preserved intact.
//!    - Verifies migration idempotency.
//! 2. `LabelRow` CRUD operations under edge cases:
//!    - Duplicate positions sorting determinism (`position ASC, created_at ASC`).
//!    - Extreme positions (`position = 0`, `position = 100`, gaps).
//!    - `next_label_position` calculation on empty, populated, gapped, and soft-deleted records.
//!    - `reorder_labels` edge cases: empty list, non-existent UUID rollback, soft-deleted UUID rollback, duplicate UUIDs.
//!    - Soft deletion filtering: `query_active_labels` excludes deleted, `update_label_name` and `soft_delete_label` return `NotFound` on deleted.
//! 3. Hierarchical `parent_id` queries and counting:
//!    - Linking: Label -> Items -> Environments -> Content (Secrets, Files, Notes).
//!    - Verification of `query_items_by_label`, `query_environments_by_item`, `query_content_records`.
//!    - Verification of `query_all_item_content_records` across item-level and environment-level content.
//!    - Verification of `count_active_items_for_label`, `count_active_records_by_parent_and_type`, `count_item_content_recursive`.
//!    - Isolation: items under different labels, environments under different items, deleted records filtering.
//! 4. Cascade deletions and atomic transactions:
//!    - `cascade_delete_item`: verifies soft-deletion of item, all child environments, and all child secrets/files/notes with monotonic Lamport bumping and zero active orphans.
//!    - `delete_environment_records` with `preserve_content = false`: tombstones environment and all its child content.
//!    - `delete_environment_records` with `preserve_content = true`: tombstones environment and reparents child content to the item.
//!    - Atomicity & Rollback verification on invalid inputs.
//!    - `cascade_delete_label`: cascades to items, environments, and content.

use rusqlite::params;
use secrecy::ExposeSecret;
use secwet_core::crypto::{derive_keys, seal_record};
use secwet_core::keys::{KeyStore, MemoryStore};
use secwet_core::records::{
    cascade_delete_item, cascade_delete_label, count_active_items_for_label,
    count_active_records_by_parent_and_type, count_item_content_recursive,
    delete_environment_records, get_highest_lamport, get_label, get_meta, get_record,
    get_schema_version, insert_label, insert_record, next_label_position, open_connection,
    query_active_labels, query_all_item_content_records, query_content_records,
    query_environments_by_item, query_items_by_label, reorder_labels, run_migrations,
    soft_delete_label, update_label_name, LabelRow, RecordRow, INITIAL_SCHEMA_SQL,
};
use secwet_core::{Error, SecretDraft, Vault, VaultStatus};
use secwet_proto::{EnvironmentBody, ProjectBody, RecordAad, RecordType, SecretBody, SecretKind};
use tempfile::tempdir;
use uuid::Uuid;

// ============================================================================
// 1. Migration 0002 on Populated v1 Schema Database
// ============================================================================

#[test]
fn challenge_migration_0002_on_populated_v1_database() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("v1_populated_vault.sqlite3");

    let vault_id = Uuid::now_v7();
    let origin_device = "migration_tester_node";
    let now_ms = 1_730_200_000_000i64;

    let p1_id = Uuid::now_v7();
    let p2_id = Uuid::now_v7();
    let e1_id = Uuid::now_v7();
    let e2_id = Uuid::now_v7();
    let s1_id = Uuid::now_v7();
    let s2_id = Uuid::now_v7();
    let s_deleted_id = Uuid::now_v7();

    // 1. Manually establish a pure v1 schema database with user_version = 1
    {
        let conn = open_connection(&db_path).expect("open connection");
        conn.execute_batch(INITIAL_SCHEMA_SQL)
            .expect("v1 schema DDL");
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('vault_id', ?1)",
            params![vault_id.to_string()],
        )
        .expect("insert meta v1");
        conn.execute("PRAGMA user_version = 1", [])
            .expect("set user_version 1");

        // Verify baseline version is 1
        let v = get_schema_version(&conn).expect("version check");
        assert_eq!(v, 1, "Baseline database must be at version 1");

        // Populate legacy records: Project (1), Environment (2), Secret (3)
        // Insert Project 1
        insert_record(
            &conn,
            &RecordRow::new_active(
                p1_id,
                RecordType::Project,
                None,
                1,
                b"sealed_legacy_project_1_blob".to_vec(),
                1,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Insert Project 2
        insert_record(
            &conn,
            &RecordRow::new_active(
                p2_id,
                RecordType::Project,
                None,
                1,
                b"sealed_legacy_project_2_blob".to_vec(),
                2,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Insert Environment E1 under P1
        insert_record(
            &conn,
            &RecordRow::new_active(
                e1_id,
                RecordType::Environment,
                Some(p1_id),
                1,
                b"sealed_legacy_env_1_blob".to_vec(),
                3,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Insert Environment E2 under P2
        insert_record(
            &conn,
            &RecordRow::new_active(
                e2_id,
                RecordType::Environment,
                Some(p2_id),
                1,
                b"sealed_legacy_env_2_blob".to_vec(),
                4,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Insert Secret S1 under E1
        insert_record(
            &conn,
            &RecordRow::new_active(
                s1_id,
                RecordType::Secret,
                Some(e1_id),
                1,
                b"sealed_legacy_secret_1_blob".to_vec(),
                5,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Insert Secret S2 under E2
        insert_record(
            &conn,
            &RecordRow::new_active(
                s2_id,
                RecordType::Secret,
                Some(e2_id),
                1,
                b"sealed_legacy_secret_2_blob".to_vec(),
                6,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Insert a soft-deleted legacy secret
        insert_record(
            &conn,
            &RecordRow::new_deleted(
                s_deleted_id,
                RecordType::Secret,
                Some(e1_id),
                1,
                7,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Insert a device row
        conn.execute(
            "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                origin_device,
                b"device_name_blob".to_vec(),
                vec![0x11u8; 32],
                vec![0x22u8; 32],
                now_ms,
            ],
        )
        .unwrap();

        // Insert settings
        conn.execute(
            "INSERT INTO settings (key, value) VALUES ('lock_minutes', '15'), ('theme', 'system')",
            [],
        )
        .unwrap();
    }

    // 2. Execute run_migrations to apply Migration 0002
    {
        let mut conn = open_connection(&db_path).expect("reopen connection");
        run_migrations(&mut conn).expect("execute migration 0002");

        // Verify schema version is bumped to 2
        let v = get_schema_version(&conn).expect("get_schema_version");
        assert_eq!(v, 2, "user_version must be bumped to 2 after migration");

        let meta_ver = get_meta(&conn, "schema_version").expect("get_meta");
        assert_eq!(
            meta_ver,
            Some("2".to_string()),
            "meta.schema_version must be '2'"
        );

        // Verify meta vault_id is preserved
        let meta_vault = get_meta(&conn, "vault_id").expect("get_meta vault_id");
        assert_eq!(meta_vault, Some(vault_id.to_string()));

        // 3. Verify tables and indexes
        // labels table must exist with required columns
        let table_exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'labels'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(table_exists, 1, "labels table must exist");

        // Check columns in labels table
        {
            let mut col_stmt = conn.prepare("PRAGMA table_info(labels)").unwrap();
            let mut col_rows = col_stmt.query([]).unwrap();
            let mut columns = Vec::new();
            while let Some(row) = col_rows.next().unwrap() {
                let col_name: String = row.get(1).unwrap();
                columns.push(col_name);
            }
            assert!(columns.contains(&"id".to_string()));
            assert!(columns.contains(&"name_blob".to_string()));
            assert!(columns.contains(&"position".to_string()));
            assert!(columns.contains(&"created_at".to_string()));
            assert!(columns.contains(&"updated_at".to_string()));
            assert!(columns.contains(&"deleted".to_string()));
        }

        // Check index on labels position exists
        let label_idx_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND tbl_name = 'labels' AND (name = 'idx_labels_position' OR name = 'labels_position')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(label_idx_count >= 1, "Index on labels position must exist");

        // 4. Verify all existing v1 records remain intact and unchanged
        let p1 = get_record(&conn, p1_id).unwrap().expect("p1 must exist");
        assert_eq!(p1.blob, Some(b"sealed_legacy_project_1_blob".to_vec()));
        assert_eq!(p1.lamport, 1);
        assert!(!p1.deleted);

        let p2 = get_record(&conn, p2_id).unwrap().expect("p2 must exist");
        assert_eq!(p2.blob, Some(b"sealed_legacy_project_2_blob".to_vec()));
        assert_eq!(p2.lamport, 2);

        let e1 = get_record(&conn, e1_id).unwrap().expect("e1 must exist");
        assert_eq!(e1.parent_id, Some(p1_id));
        assert_eq!(e1.blob, Some(b"sealed_legacy_env_1_blob".to_vec()));

        let s1 = get_record(&conn, s1_id).unwrap().expect("s1 must exist");
        assert_eq!(s1.parent_id, Some(e1_id));
        assert_eq!(s1.blob, Some(b"sealed_legacy_secret_1_blob".to_vec()));

        let s_del = get_record(&conn, s_deleted_id)
            .unwrap()
            .expect("s_deleted must exist");
        assert!(s_del.deleted);
        assert!(s_del.blob.is_none());

        // Verify device and settings rows intact
        let dev_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE device_id = ?1",
                params![origin_device],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(dev_count, 1);

        let lock_min: String = conn
            .query_row(
                "SELECT value FROM settings WHERE key = 'lock_minutes'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(lock_min, "15");

        // 5. Test Migration Idempotency: run_migrations again must succeed as a no-op
        run_migrations(&mut conn).expect("re-running migrations must succeed cleanly");
        assert_eq!(get_schema_version(&conn).unwrap(), 2);
    }
}

// ============================================================================
// 2. LabelRow CRUD & Edge Cases
// ============================================================================

#[test]
fn challenge_label_crud_positions_and_sorting() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("label_crud.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let now = 1_730_000_000_000i64;

    // 1. Verify next_label_position on empty table
    assert_eq!(
        next_label_position(&conn).unwrap(),
        0,
        "next_label_position on empty table must be 0"
    );

    // 2. Insert label with position 0
    let l1_id = Uuid::now_v7();
    let l1 = LabelRow::new_active(l1_id, b"label_1".to_vec(), 0, now);
    insert_label(&conn, &l1).unwrap();

    assert_eq!(
        next_label_position(&conn).unwrap(),
        1,
        "next_label_position after position 0 must be 1"
    );

    // 3. Insert duplicate position (position 0) with later timestamp
    let l2_id = Uuid::now_v7();
    let l2 = LabelRow::new_active(l2_id, b"label_2".to_vec(), 0, now + 100);
    insert_label(&conn, &l2).unwrap();

    // 4. Insert label with higher position (position 5)
    let l3_id = Uuid::now_v7();
    let l3 = LabelRow::new_active(l3_id, b"label_3".to_vec(), 5, now + 200);
    insert_label(&conn, &l3).unwrap();

    assert_eq!(
        next_label_position(&conn).unwrap(),
        6,
        "next_label_position after max(5) must be 6"
    );

    // 5. Query active labels: verify deterministic ordering by `position ASC, created_at ASC`
    let active = query_active_labels(&conn).unwrap();
    assert_eq!(active.len(), 3);
    assert_eq!(
        active[0].id, l1_id,
        "l1 has position 0 and earlier created_at"
    );
    assert_eq!(
        active[1].id, l2_id,
        "l2 has position 0 and later created_at"
    );
    assert_eq!(active[2].id, l3_id, "l3 has position 5");

    // 6. Test next_label_position ignoring soft-deleted label with higher position
    let l_del_id = Uuid::now_v7();
    let l_del = LabelRow::new_deleted(l_del_id, 999, now, now + 300);
    insert_label(&conn, &l_del).unwrap();

    // next_label_position filters `WHERE deleted = 0`, so it must still return 6 (max active 5 + 1)
    assert_eq!(
        next_label_position(&conn).unwrap(),
        6,
        "next_label_position must ignore soft-deleted labels"
    );
}

#[test]
fn challenge_label_reordering_edge_cases() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("label_reorder.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let now = 1_730_000_000_000i64;
    let l1_id = Uuid::now_v7();
    let l2_id = Uuid::now_v7();
    let l3_id = Uuid::now_v7();

    insert_label(&conn, &LabelRow::new_active(l1_id, b"L1".to_vec(), 0, now)).unwrap();
    insert_label(&conn, &LabelRow::new_active(l2_id, b"L2".to_vec(), 1, now)).unwrap();
    insert_label(&conn, &LabelRow::new_active(l3_id, b"L3".to_vec(), 2, now)).unwrap();

    // 1. Reordering empty list `&[]`: must succeed as a clean no-op
    reorder_labels(&mut conn, &[], now + 10).expect("empty reorder list must succeed");
    let active = query_active_labels(&conn).unwrap();
    assert_eq!(active[0].position, 0);
    assert_eq!(active[1].position, 1);
    assert_eq!(active[2].position, 2);

    // 2. Reordering reversed: `[l3, l2, l1]`
    reorder_labels(&mut conn, &[l3_id, l2_id, l1_id], now + 20).unwrap();
    let active2 = query_active_labels(&conn).unwrap();
    assert_eq!(active2[0].id, l3_id);
    assert_eq!(active2[0].position, 0);
    assert_eq!(active2[1].id, l2_id);
    assert_eq!(active2[1].position, 1);
    assert_eq!(active2[2].id, l1_id);
    assert_eq!(active2[2].position, 2);

    // 3. Reordering with non-existent UUID: must fail with Error::NotFound AND rollback transaction
    let fake_id = Uuid::now_v7();
    let res = reorder_labels(&mut conn, &[l1_id, fake_id, l2_id], now + 30);
    match res {
        Err(Error::NotFound) => {}
        other => panic!(
            "expected Error::NotFound on non-existent UUID, got: {:?}",
            other
        ),
    }

    // Verify rollback: l3 is still 0, l2 is still 1, l1 is still 2!
    let active3 = query_active_labels(&conn).unwrap();
    assert_eq!(active3[0].id, l3_id);
    assert_eq!(active3[0].position, 0);
    assert_eq!(active3[1].id, l2_id);
    assert_eq!(active3[1].position, 1);
    assert_eq!(active3[2].id, l1_id);
    assert_eq!(active3[2].position, 2);

    // 4. Soft-delete l2, then attempt to reorder including l2
    soft_delete_label(&conn, l2_id, now + 40).unwrap();
    let res_deleted = reorder_labels(&mut conn, &[l1_id, l2_id, l3_id], now + 50);
    match res_deleted {
        Err(Error::NotFound) => {}
        other => panic!(
            "expected Error::NotFound for deleted UUID in reorder, got: {:?}",
            other
        ),
    }

    // 5. Reorder remaining active labels: `[l1, l3]`
    reorder_labels(&mut conn, &[l1_id, l3_id], now + 60).unwrap();
    let active4 = query_active_labels(&conn).unwrap();
    assert_eq!(active4.len(), 2);
    assert_eq!(active4[0].id, l1_id);
    assert_eq!(active4[0].position, 0);
    assert_eq!(active4[1].id, l3_id);
    assert_eq!(active4[1].position, 1);
}

#[test]
fn challenge_label_soft_delete_and_name_update_invariants() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("label_ops.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let now = 1_730_000_000_000i64;
    let l_id = Uuid::now_v7();
    insert_label(
        &conn,
        &LabelRow::new_active(l_id, b"original_name".to_vec(), 0, now),
    )
    .unwrap();

    // 1. Update name succeeds on active label
    update_label_name(&conn, l_id, b"renamed_name", now + 10).unwrap();
    let label = get_label(&conn, l_id).unwrap().expect("label exists");
    assert_eq!(label.name_blob, b"renamed_name".to_vec());
    assert_eq!(label.updated_at, now + 10);

    // 2. Update name on non-existent label returns Error::NotFound
    let fake_id = Uuid::now_v7();
    let res_fake = update_label_name(&conn, fake_id, b"ghost", now + 20);
    assert!(matches!(res_fake, Err(Error::NotFound)));

    // 3. Soft-delete label
    soft_delete_label(&conn, l_id, now + 30).unwrap();

    // get_label returns row with deleted = true
    let deleted_label = get_label(&conn, l_id).unwrap().expect("label still in DB");
    assert!(deleted_label.deleted);
    assert_eq!(deleted_label.updated_at, now + 30);

    // query_active_labels excludes it
    let active = query_active_labels(&conn).unwrap();
    assert!(
        active.is_empty(),
        "Soft-deleted label must be excluded from active queries"
    );

    // 4. Double soft-delete returns Error::NotFound
    let res_double = soft_delete_label(&conn, l_id, now + 40);
    assert!(
        matches!(res_double, Err(Error::NotFound)),
        "Calling soft_delete_label on an already deleted label must return Error::NotFound"
    );

    // 5. Update name on soft-deleted label returns Error::NotFound
    let res_update_del = update_label_name(&conn, l_id, b"attempt_on_deleted", now + 50);
    assert!(
        matches!(res_update_del, Err(Error::NotFound)),
        "Updating name on a deleted label must return Error::NotFound"
    );
}

// ============================================================================
// 3. Hierarchical parent_id Queries and Counting
// ============================================================================

#[test]
fn challenge_hierarchical_queries_isolation_and_counting() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("hierarchy.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "hierarchy_tester";
    let now = 1_730_000_000_000i64;

    // Build hierarchy:
    // Label 1
    //  ├─ Item 1A
    //  │   ├─ Item-level Secret 1A_S1
    //  │   ├─ Item-level Secret 1A_S2
    //  │   ├─ Item-level File 1A_F1
    //  │   ├─ Item-level Note 1A_N1
    //  │   ├─ Env 1A_E1
    //  │   │   ├─ Env-level Secret 1A_E1_S1
    //  │   │   ├─ Env-level File 1A_E1_F1
    //  │   │   └─ Env-level Note 1A_E1_N1
    //  │   └─ Env 1A_E2
    //  │       ├─ Env-level Secret 1A_E2_S1
    //  │       └─ Pre-deleted Secret 1A_E2_S_DEL (deleted = 1)
    //  ├─ Item 1B
    //  │   └─ Item-level Secret 1B_S1
    //  └─ Soft-deleted Item 1C (deleted = 1)
    // Label 2
    //  └─ Item 2A
    //      └─ Env 2A_E1
    //          └─ Env-level Secret 2A_E1_S1

    let l1_id = Uuid::now_v7();
    let l2_id = Uuid::now_v7();
    insert_label(
        &conn,
        &LabelRow::new_active(l1_id, b"Label1".to_vec(), 0, now),
    )
    .unwrap();
    insert_label(
        &conn,
        &LabelRow::new_active(l2_id, b"Label2".to_vec(), 1, now),
    )
    .unwrap();

    let item_1a_id = Uuid::now_v7();
    let item_1b_id = Uuid::now_v7();
    let item_1c_id = Uuid::now_v7();
    let item_2a_id = Uuid::now_v7();

    insert_record(
        &conn,
        &RecordRow::new_active(
            item_1a_id,
            RecordType::Item,
            Some(l1_id),
            1,
            vec![1],
            1,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            item_1b_id,
            RecordType::Item,
            Some(l1_id),
            1,
            vec![2],
            2,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_deleted(item_1c_id, RecordType::Item, Some(l1_id), 1, 3, origin, now),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            item_2a_id,
            RecordType::Item,
            Some(l2_id),
            1,
            vec![4],
            4,
            origin,
            now,
        ),
    )
    .unwrap();

    // Verify query_items_by_label & count_active_items_for_label
    let l1_items = query_items_by_label(&conn, l1_id).unwrap();
    assert_eq!(
        l1_items.len(),
        2,
        "Must return active items 1A and 1B; 1C is deleted"
    );
    assert!(l1_items.iter().any(|i| i.id == item_1a_id));
    assert!(l1_items.iter().any(|i| i.id == item_1b_id));
    assert_eq!(count_active_items_for_label(&conn, l1_id).unwrap(), 2);

    let l2_items = query_items_by_label(&conn, l2_id).unwrap();
    assert_eq!(l2_items.len(), 1);
    assert_eq!(l2_items[0].id, item_2a_id);
    assert_eq!(count_active_items_for_label(&conn, l2_id).unwrap(), 1);

    // Add Item 1A content
    let s_1a_1 = Uuid::now_v7();
    let s_1a_2 = Uuid::now_v7();
    let f_1a_1 = Uuid::now_v7();
    let n_1a_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_1a_1,
            RecordType::Secret,
            Some(item_1a_id),
            1,
            vec![10],
            5,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_1a_2,
            RecordType::Secret,
            Some(item_1a_id),
            1,
            vec![11],
            6,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            f_1a_1,
            RecordType::File,
            Some(item_1a_id),
            1,
            vec![12],
            7,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            n_1a_1,
            RecordType::Note,
            Some(item_1a_id),
            1,
            vec![13],
            8,
            origin,
            now,
        ),
    )
    .unwrap();

    // Add Item 1A environments
    let env_1a_e1 = Uuid::now_v7();
    let env_1a_e2 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            env_1a_e1,
            RecordType::Environment,
            Some(item_1a_id),
            1,
            vec![20],
            9,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            env_1a_e2,
            RecordType::Environment,
            Some(item_1a_id),
            1,
            vec![21],
            10,
            origin,
            now,
        ),
    )
    .unwrap();

    // Env 1A_E1 content
    let s_e1_1 = Uuid::now_v7();
    let f_e1_1 = Uuid::now_v7();
    let n_e1_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e1_1,
            RecordType::Secret,
            Some(env_1a_e1),
            1,
            vec![30],
            11,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            f_e1_1,
            RecordType::File,
            Some(env_1a_e1),
            1,
            vec![31],
            12,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            n_e1_1,
            RecordType::Note,
            Some(env_1a_e1),
            1,
            vec![32],
            13,
            origin,
            now,
        ),
    )
    .unwrap();

    // Env 1A_E2 content
    let s_e2_1 = Uuid::now_v7();
    let s_e2_del = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e2_1,
            RecordType::Secret,
            Some(env_1a_e2),
            1,
            vec![40],
            14,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_deleted(
            s_e2_del,
            RecordType::Secret,
            Some(env_1a_e2),
            1,
            15,
            origin,
            now,
        ),
    )
    .unwrap();

    // Item 1B content
    let s_1b_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_1b_1,
            RecordType::Secret,
            Some(item_1b_id),
            1,
            vec![50],
            16,
            origin,
            now,
        ),
    )
    .unwrap();

    // Item 2A environment and content
    let env_2a_e1 = Uuid::now_v7();
    let s_2a_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            env_2a_e1,
            RecordType::Environment,
            Some(item_2a_id),
            1,
            vec![60],
            17,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_2a_1,
            RecordType::Secret,
            Some(env_2a_e1),
            1,
            vec![61],
            18,
            origin,
            now,
        ),
    )
    .unwrap();

    // 1. Verify query_environments_by_item
    let envs_1a = query_environments_by_item(&conn, item_1a_id).unwrap();
    assert_eq!(envs_1a.len(), 2);
    assert_eq!(
        count_active_records_by_parent_and_type(&conn, item_1a_id, RecordType::Environment)
            .unwrap(),
        2
    );

    let envs_1b = query_environments_by_item(&conn, item_1b_id).unwrap();
    assert!(envs_1b.is_empty(), "Item 1B has no environments");

    let envs_2a = query_environments_by_item(&conn, item_2a_id).unwrap();
    assert_eq!(envs_2a.len(), 1);

    // 2. Verify query_content_records for direct container queries
    // Item-level secrets for Item 1A
    let item_secrets = query_content_records(&conn, item_1a_id, None, RecordType::Secret).unwrap();
    assert_eq!(item_secrets.len(), 2);
    assert!(item_secrets.iter().all(|s| s.parent_id == Some(item_1a_id)));

    // Item-level files and notes
    let item_files = query_content_records(&conn, item_1a_id, None, RecordType::File).unwrap();
    assert_eq!(item_files.len(), 1);
    assert_eq!(item_files[0].id, f_1a_1);

    let item_notes = query_content_records(&conn, item_1a_id, None, RecordType::Note).unwrap();
    assert_eq!(item_notes.len(), 1);
    assert_eq!(item_notes[0].id, n_1a_1);

    // Environment-level queries for E1
    let e1_secrets =
        query_content_records(&conn, item_1a_id, Some(env_1a_e1), RecordType::Secret).unwrap();
    assert_eq!(e1_secrets.len(), 1);
    assert_eq!(e1_secrets[0].id, s_e1_1);

    let e1_files =
        query_content_records(&conn, item_1a_id, Some(env_1a_e1), RecordType::File).unwrap();
    assert_eq!(e1_files.len(), 1);
    assert_eq!(e1_files[0].id, f_e1_1);

    // Environment-level queries for E2 (excludes s_e2_del)
    let e2_secrets =
        query_content_records(&conn, item_1a_id, Some(env_1a_e2), RecordType::Secret).unwrap();
    assert_eq!(e2_secrets.len(), 1);
    assert_eq!(e2_secrets[0].id, s_e2_1);

    // 3. Verify query_all_item_content_records & count_item_content_recursive
    // Item 1A all secrets = 2 (item) + 1 (E1) + 1 (E2) = 4 active secrets
    let all_1a_secrets =
        query_all_item_content_records(&conn, item_1a_id, RecordType::Secret).unwrap();
    assert_eq!(
        all_1a_secrets.len(),
        4,
        "Must aggregate item-level and environment-level secrets"
    );
    assert_eq!(
        count_item_content_recursive(&conn, item_1a_id, RecordType::Secret).unwrap(),
        4
    );

    // Must NOT contain Item 1B secrets or Item 2A secrets
    assert!(!all_1a_secrets.iter().any(|s| s.id == s_1b_1));
    assert!(!all_1a_secrets.iter().any(|s| s.id == s_2a_1));
    // Must NOT contain deleted secret
    assert!(!all_1a_secrets.iter().any(|s| s.id == s_e2_del));

    // Item 1A all files = 1 (item) + 1 (E1) = 2 active files
    let all_1a_files = query_all_item_content_records(&conn, item_1a_id, RecordType::File).unwrap();
    assert_eq!(all_1a_files.len(), 2);
    assert_eq!(
        count_item_content_recursive(&conn, item_1a_id, RecordType::File).unwrap(),
        2
    );

    // Item 1A all notes = 1 (item) + 1 (E1) = 2 active notes
    let all_1a_notes = query_all_item_content_records(&conn, item_1a_id, RecordType::Note).unwrap();
    assert_eq!(all_1a_notes.len(), 2);
    assert_eq!(
        count_item_content_recursive(&conn, item_1a_id, RecordType::Note).unwrap(),
        2
    );

    // Item 1B all secrets = 1
    assert_eq!(
        count_item_content_recursive(&conn, item_1b_id, RecordType::Secret).unwrap(),
        1
    );
    // Item 2A all secrets = 1
    assert_eq!(
        count_item_content_recursive(&conn, item_2a_id, RecordType::Secret).unwrap(),
        1
    );
}

// ============================================================================
// 4. Cascade Deletion Operations & Transaction Atomicity
// ============================================================================

#[test]
fn challenge_cascade_delete_item_integrity_and_isolation() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("cascade_item.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "cascade_item_tester";
    let now = 1_730_000_000_000i64;

    let label_id = Uuid::now_v7();
    insert_label(
        &conn,
        &LabelRow::new_active(label_id, b"Projects".to_vec(), 0, now),
    )
    .unwrap();

    let target_item = Uuid::now_v7();
    let sibling_item = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            target_item,
            RecordType::Item,
            Some(label_id),
            1,
            vec![1],
            1,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            sibling_item,
            RecordType::Item,
            Some(label_id),
            1,
            vec![2],
            2,
            origin,
            now,
        ),
    )
    .unwrap();

    // Populate target item: 2 environments, 2 item secrets, 1 file, 1 note
    let e1 = Uuid::now_v7();
    let e2 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            e1,
            RecordType::Environment,
            Some(target_item),
            1,
            vec![10],
            3,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            e2,
            RecordType::Environment,
            Some(target_item),
            1,
            vec![11],
            4,
            origin,
            now,
        ),
    )
    .unwrap();

    let s_item_1 = Uuid::now_v7();
    let s_item_2 = Uuid::now_v7();
    let f_item_1 = Uuid::now_v7();
    let n_item_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_item_1,
            RecordType::Secret,
            Some(target_item),
            1,
            vec![20],
            5,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_item_2,
            RecordType::Secret,
            Some(target_item),
            1,
            vec![21],
            6,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            f_item_1,
            RecordType::File,
            Some(target_item),
            1,
            vec![22],
            7,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            n_item_1,
            RecordType::Note,
            Some(target_item),
            1,
            vec![23],
            8,
            origin,
            now,
        ),
    )
    .unwrap();

    // E1 content: 2 secrets, 1 file
    let s_e1_1 = Uuid::now_v7();
    let s_e1_2 = Uuid::now_v7();
    let f_e1_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e1_1,
            RecordType::Secret,
            Some(e1),
            1,
            vec![30],
            9,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e1_2,
            RecordType::Secret,
            Some(e1),
            1,
            vec![31],
            10,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            f_e1_1,
            RecordType::File,
            Some(e1),
            1,
            vec![32],
            11,
            origin,
            now,
        ),
    )
    .unwrap();

    // E2 content: 1 secret, 1 note, 1 pre-deleted secret
    let s_e2_1 = Uuid::now_v7();
    let n_e2_1 = Uuid::now_v7();
    let s_e2_pre_del = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e2_1,
            RecordType::Secret,
            Some(e2),
            1,
            vec![40],
            12,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            n_e2_1,
            RecordType::Note,
            Some(e2),
            1,
            vec![41],
            13,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_deleted(
            s_e2_pre_del,
            RecordType::Secret,
            Some(e2),
            1,
            14,
            origin,
            now,
        ),
    )
    .unwrap();

    // Sibling item content: 1 env, 1 secret
    let sib_env = Uuid::now_v7();
    let sib_sec = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            sib_env,
            RecordType::Environment,
            Some(sibling_item),
            1,
            vec![50],
            15,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            sib_sec,
            RecordType::Secret,
            Some(sib_env),
            1,
            vec![51],
            16,
            origin,
            now,
        ),
    )
    .unwrap();

    let initial_lamport = get_highest_lamport(&conn).unwrap();

    // Execute cascade_delete_item on target_item
    let summary = cascade_delete_item(&mut conn, target_item, origin, now + 1000)
        .expect("cascade delete item");

    // Total affected: 1 (item) + 2 (envs) + 5 (secrets: 2 item + 2 e1 + 1 e2) + 2 (files: 1 item + 1 e1) + 2 (notes: 1 item + 1 e2) = 12 records
    assert_eq!(summary.item_id, target_item);
    assert_eq!(summary.environments_deleted, 2);
    assert_eq!(summary.secrets_deleted, 5);
    assert_eq!(summary.files_deleted, 2);
    assert_eq!(summary.notes_deleted, 2);
    assert_eq!(summary.total_records_affected, 12);

    // Verify target item is soft-deleted and blob is NULL
    let item_row = get_record(&conn, target_item)
        .unwrap()
        .expect("item row exists");
    assert!(item_row.deleted);
    assert!(item_row.blob.is_none());

    // Verify all child environments and content are soft-deleted and blob is NULL
    for child_id in [
        e1, e2, s_item_1, s_item_2, f_item_1, n_item_1, s_e1_1, s_e1_2, f_e1_1, s_e2_1, n_e2_1,
    ] {
        let r = get_record(&conn, child_id)
            .unwrap()
            .expect("child row exists");
        assert!(r.deleted, "Record {:?} must be deleted", child_id);
        assert!(
            r.blob.is_none(),
            "Record {:?} blob must be cleared to NULL",
            child_id
        );
    }

    // Verify zero active child records exist under target_item or its environments
    let active_envs = query_environments_by_item(&conn, target_item).unwrap();
    assert!(
        active_envs.is_empty(),
        "Zero active environments must remain"
    );

    let active_secrets =
        query_all_item_content_records(&conn, target_item, RecordType::Secret).unwrap();
    assert!(active_secrets.is_empty(), "Zero active secrets must remain");

    let active_files =
        query_all_item_content_records(&conn, target_item, RecordType::File).unwrap();
    assert!(active_files.is_empty(), "Zero active files must remain");

    let active_notes =
        query_all_item_content_records(&conn, target_item, RecordType::Note).unwrap();
    assert!(active_notes.is_empty(), "Zero active notes must remain");

    // Sibling item isolation: Sibling item and its children MUST be 100% active and untouched
    let sib_row = get_record(&conn, sibling_item)
        .unwrap()
        .expect("sibling exists");
    assert!(!sib_row.deleted);
    assert!(sib_row.blob.is_some());

    let sib_env_row = get_record(&conn, sib_env)
        .unwrap()
        .expect("sibling env exists");
    assert!(!sib_env_row.deleted);

    let sib_sec_row = get_record(&conn, sib_sec)
        .unwrap()
        .expect("sibling secret exists");
    assert!(!sib_sec_row.deleted);

    // Verify Lamport clock bumped monotonically
    let post_lamport = get_highest_lamport(&conn).unwrap();
    assert_eq!(
        post_lamport,
        initial_lamport + 12,
        "Lamport clock must be bumped by exactly 12 for all affected records"
    );

    // Calling cascade_delete_item a second time must return Error::NotFound (cannot delete already deleted item)
    let res_second = cascade_delete_item(&mut conn, target_item, origin, now + 2000);
    assert!(matches!(res_second, Err(Error::NotFound)));

    // Non-existent item returns Error::NotFound
    let res_fake = cascade_delete_item(&mut conn, Uuid::now_v7(), origin, now + 3000);
    assert!(matches!(res_fake, Err(Error::NotFound)));
}

#[test]
fn challenge_delete_environment_preserve_content_true() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("env_preserve_true.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "preserve_tester";
    let now = 1_730_000_000_000i64;

    let item_id = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(item_id, RecordType::Item, None, 1, vec![1], 1, origin, now),
    )
    .unwrap();

    let e1 = Uuid::now_v7();
    let e2 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            e1,
            RecordType::Environment,
            Some(item_id),
            1,
            vec![10],
            2,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            e2,
            RecordType::Environment,
            Some(item_id),
            1,
            vec![11],
            3,
            origin,
            now,
        ),
    )
    .unwrap();

    // 1 item-level secret
    let s_orig_item = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_orig_item,
            RecordType::Secret,
            Some(item_id),
            1,
            vec![20],
            4,
            origin,
            now,
        ),
    )
    .unwrap();

    // Environment E1 content: 2 secrets, 1 file, 1 note
    let s_e1_1 = Uuid::now_v7();
    let s_e1_2 = Uuid::now_v7();
    let f_e1_1 = Uuid::now_v7();
    let n_e1_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e1_1,
            RecordType::Secret,
            Some(e1),
            1,
            vec![30],
            5,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e1_2,
            RecordType::Secret,
            Some(e1),
            1,
            vec![31],
            6,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            f_e1_1,
            RecordType::File,
            Some(e1),
            1,
            vec![32],
            7,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            n_e1_1,
            RecordType::Note,
            Some(e1),
            1,
            vec![33],
            8,
            origin,
            now,
        ),
    )
    .unwrap();

    // Environment E2 content: 1 secret
    let s_e2_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e2_1,
            RecordType::Secret,
            Some(e2),
            1,
            vec![40],
            9,
            origin,
            now,
        ),
    )
    .unwrap();

    // Execute delete_environment_records with preserve_content = true
    let affected = delete_environment_records(&mut conn, e1, true, origin, now + 1000)
        .expect("delete e1 with preserve");
    assert_eq!(
        affected, 4,
        "Must affect 4 child records (2 secrets, 1 file, 1 note)"
    );

    // 1. E1 must be soft-deleted with blob = NULL
    let e1_row = get_record(&conn, e1).unwrap().expect("e1 exists");
    assert!(e1_row.deleted);
    assert!(e1_row.blob.is_none());

    // 2. E2 must remain active and untouched
    let e2_row = get_record(&conn, e2).unwrap().expect("e2 exists");
    assert!(!e2_row.deleted);

    // 3. Child records of E1 must now have parent_id = item_id, deleted = false, and blob intact!
    for child_id in [s_e1_1, s_e1_2, f_e1_1, n_e1_1] {
        let r = get_record(&conn, child_id).unwrap().expect("child exists");
        assert!(
            !r.deleted,
            "Child {:?} must NOT be deleted when preserved",
            child_id
        );
        assert!(
            r.blob.is_some(),
            "Child {:?} blob must remain intact",
            child_id
        );
        assert_eq!(
            r.parent_id,
            Some(item_id),
            "Child {:?} must be reparented to parent item_id",
            child_id
        );
    }

    // 4. Query item-level secrets: now returns 3 (1 original + 2 reparented)
    let item_secrets = query_content_records(&conn, item_id, None, RecordType::Secret).unwrap();
    assert_eq!(item_secrets.len(), 3);
    assert!(item_secrets.iter().any(|s| s.id == s_orig_item));
    assert!(item_secrets.iter().any(|s| s.id == s_e1_1));
    assert!(item_secrets.iter().any(|s| s.id == s_e1_2));

    // 5. Query E1 content: returns empty
    let e1_secrets = query_content_records(&conn, item_id, Some(e1), RecordType::Secret).unwrap();
    assert!(e1_secrets.is_empty(), "E1 has no records remaining");

    // 6. Query all item secrets: still returns all 4 active secrets (3 item-level + 1 in E2)
    let all_secrets = query_all_item_content_records(&conn, item_id, RecordType::Secret).unwrap();
    assert_eq!(all_secrets.len(), 4);
}

#[test]
fn challenge_delete_environment_preserve_content_false() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("env_preserve_false.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "no_preserve_tester";
    let now = 1_730_000_000_000i64;

    let item_id = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(item_id, RecordType::Item, None, 1, vec![1], 1, origin, now),
    )
    .unwrap();

    let e1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            e1,
            RecordType::Environment,
            Some(item_id),
            1,
            vec![10],
            2,
            origin,
            now,
        ),
    )
    .unwrap();

    // 1 item-level secret
    let s_orig_item = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_orig_item,
            RecordType::Secret,
            Some(item_id),
            1,
            vec![20],
            3,
            origin,
            now,
        ),
    )
    .unwrap();

    // E1 content: 2 secrets, 1 file
    let s_e1_1 = Uuid::now_v7();
    let s_e1_2 = Uuid::now_v7();
    let f_e1_1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e1_1,
            RecordType::Secret,
            Some(e1),
            1,
            vec![30],
            4,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_e1_2,
            RecordType::Secret,
            Some(e1),
            1,
            vec![31],
            5,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            f_e1_1,
            RecordType::File,
            Some(e1),
            1,
            vec![32],
            6,
            origin,
            now,
        ),
    )
    .unwrap();

    // Execute delete_environment_records with preserve_content = false
    let affected = delete_environment_records(&mut conn, e1, false, origin, now + 1000)
        .expect("delete e1 without preserve");
    assert_eq!(affected, 3, "Must tombstone 3 child records");

    // E1 is soft-deleted
    let e1_row = get_record(&conn, e1).unwrap().expect("e1 exists");
    assert!(e1_row.deleted);
    assert!(e1_row.blob.is_none());

    // Children are soft-deleted with blob = NULL
    for child_id in [s_e1_1, s_e1_2, f_e1_1] {
        let r = get_record(&conn, child_id).unwrap().expect("child exists");
        assert!(r.deleted, "Child {:?} must be deleted", child_id);
        assert!(
            r.blob.is_none(),
            "Child {:?} blob must be cleared",
            child_id
        );
    }

    // Item-level secret is completely unaffected
    let orig = get_record(&conn, s_orig_item)
        .unwrap()
        .expect("item secret exists");
    assert!(!orig.deleted);
    assert!(orig.blob.is_some());

    // Query item-level secrets: only original secret
    let item_secrets = query_content_records(&conn, item_id, None, RecordType::Secret).unwrap();
    assert_eq!(item_secrets.len(), 1);
    assert_eq!(item_secrets[0].id, s_orig_item);

    // Query all item secrets: only original secret
    let all_secrets = query_all_item_content_records(&conn, item_id, RecordType::Secret).unwrap();
    assert_eq!(all_secrets.len(), 1);
    assert_eq!(all_secrets[0].id, s_orig_item);

    // Calling delete_environment_records again on E1 must return Error::NotFound
    let res_repeat = delete_environment_records(&mut conn, e1, false, origin, now + 2000);
    assert!(matches!(res_repeat, Err(Error::NotFound)));
}

#[test]
fn challenge_cascade_delete_label_full_tree() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("cascade_label.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "label_cascade_tester";
    let now = 1_730_000_000_000i64;

    let label_id = Uuid::now_v7();
    insert_label(
        &conn,
        &LabelRow::new_active(label_id, b"DeleteMeLabel".to_vec(), 0, now),
    )
    .unwrap();

    // Item 1 under Label: 1 env, 2 secrets
    let item1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            item1,
            RecordType::Item,
            Some(label_id),
            1,
            vec![1],
            1,
            origin,
            now,
        ),
    )
    .unwrap();
    let env1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            env1,
            RecordType::Environment,
            Some(item1),
            1,
            vec![10],
            2,
            origin,
            now,
        ),
    )
    .unwrap();
    let sec1 = Uuid::now_v7();
    let sec2 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            sec1,
            RecordType::Secret,
            Some(env1),
            1,
            vec![20],
            3,
            origin,
            now,
        ),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_active(
            sec2,
            RecordType::Secret,
            Some(item1),
            1,
            vec![21],
            4,
            origin,
            now,
        ),
    )
    .unwrap();

    // Item 2 under Label: 1 env, 1 note
    let item2 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            item2,
            RecordType::Item,
            Some(label_id),
            1,
            vec![2],
            5,
            origin,
            now,
        ),
    )
    .unwrap();
    let env2 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            env2,
            RecordType::Environment,
            Some(item2),
            1,
            vec![11],
            6,
            origin,
            now,
        ),
    )
    .unwrap();
    let note1 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            note1,
            RecordType::Note,
            Some(env2),
            1,
            vec![30],
            7,
            origin,
            now,
        ),
    )
    .unwrap();

    // Execute cascade_delete_label
    let summary = cascade_delete_label(&mut conn, label_id, origin, now + 1000)
        .expect("cascade delete label");

    assert_eq!(summary.label_id, label_id);
    assert_eq!(summary.items_deleted, 2);
    assert_eq!(summary.environments_deleted, 2);
    assert_eq!(summary.secrets_deleted, 2);
    assert_eq!(summary.notes_deleted, 1);
    assert_eq!(summary.files_deleted, 0);

    // Verify label is soft-deleted
    let lbl = get_label(&conn, label_id).unwrap().expect("label exists");
    assert!(lbl.deleted);

    // Verify active labels does not include it
    assert!(query_active_labels(&conn).unwrap().is_empty());

    // Verify all items, environments, secrets, notes are soft-deleted
    for id in [item1, item2, env1, env2, sec1, sec2, note1] {
        let r = get_record(&conn, id).unwrap().expect("record exists");
        assert!(r.deleted);
        assert!(r.blob.is_none());
    }

    // Calling cascade_delete_label again returns Error::NotFound
    let res_again = cascade_delete_label(&mut conn, label_id, origin, now + 2000);
    assert!(matches!(res_again, Err(Error::NotFound)));
}

// ============================================================================
// 5. Additional Adversarial Edge Cases & Stress Harnesses
// ============================================================================

#[test]
fn challenge_cascade_delete_item_minimal_no_children() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("cascade_minimal.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "minimal_tester";
    let now = 1_730_000_000_000i64;

    let item_id = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(item_id, RecordType::Item, None, 1, vec![1], 1, origin, now),
    )
    .unwrap();

    let summary = cascade_delete_item(&mut conn, item_id, origin, now + 10).unwrap();
    assert_eq!(summary.item_id, item_id);
    assert_eq!(summary.environments_deleted, 0);
    assert_eq!(summary.secrets_deleted, 0);
    assert_eq!(summary.files_deleted, 0);
    assert_eq!(summary.notes_deleted, 0);
    assert_eq!(summary.total_records_affected, 1);

    let row = get_record(&conn, item_id).unwrap().expect("row exists");
    assert!(row.deleted);
    assert!(row.blob.is_none());
}

#[test]
fn challenge_delete_environment_empty_and_pre_deleted_children() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("env_empty_del.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "empty_env_tester";
    let now = 1_730_000_000_000i64;

    let item_id = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(item_id, RecordType::Item, None, 1, vec![1], 1, origin, now),
    )
    .unwrap();

    let env_id = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            env_id,
            RecordType::Environment,
            Some(item_id),
            1,
            vec![2],
            2,
            origin,
            now,
        ),
    )
    .unwrap();

    // Insert 2 pre-deleted secrets under env_id
    let s_del_1 = Uuid::now_v7();
    let s_del_2 = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_deleted(s_del_1, RecordType::Secret, Some(env_id), 1, 3, origin, now),
    )
    .unwrap();
    insert_record(
        &conn,
        &RecordRow::new_deleted(s_del_2, RecordType::Secret, Some(env_id), 1, 4, origin, now),
    )
    .unwrap();

    // delete_environment_records with preserve_content = true:
    // Only active children should be reparented; pre-deleted children must NOT be reparented!
    let affected = delete_environment_records(&mut conn, env_id, true, origin, now + 10).unwrap();
    assert_eq!(affected, 0, "No active children were present");

    let env_row = get_record(&conn, env_id).unwrap().unwrap();
    assert!(env_row.deleted);

    let r1 = get_record(&conn, s_del_1).unwrap().unwrap();
    assert!(r1.deleted);
    assert_eq!(
        r1.parent_id,
        Some(env_id),
        "Pre-deleted child parent_id must not be altered"
    );

    let r2 = get_record(&conn, s_del_2).unwrap().unwrap();
    assert!(r2.deleted);
    assert_eq!(r2.parent_id, Some(env_id));
}

#[test]
fn challenge_query_all_item_content_excludes_deleted_environment_content() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("query_deleted_env.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "deleted_env_tester";
    let now = 1_730_000_000_000i64;

    let item_id = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(item_id, RecordType::Item, None, 1, vec![1], 1, origin, now),
    )
    .unwrap();

    let e_active = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            e_active,
            RecordType::Environment,
            Some(item_id),
            1,
            vec![10],
            2,
            origin,
            now,
        ),
    )
    .unwrap();

    let e_deleted = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_deleted(
            e_deleted,
            RecordType::Environment,
            Some(item_id),
            1,
            3,
            origin,
            now,
        ),
    )
    .unwrap();

    // Secret under active environment
    let s_active = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_active,
            RecordType::Secret,
            Some(e_active),
            1,
            vec![20],
            4,
            origin,
            now,
        ),
    )
    .unwrap();

    // Secret under deleted environment (even if secret record itself has deleted=0)
    let s_in_deleted_env = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(
            s_in_deleted_env,
            RecordType::Secret,
            Some(e_deleted),
            1,
            vec![21],
            5,
            origin,
            now,
        ),
    )
    .unwrap();

    // query_all_item_content_records must ONLY return secret under the active environment!
    let results = query_all_item_content_records(&conn, item_id, RecordType::Secret).unwrap();
    assert_eq!(
        results.len(),
        1,
        "Must exclude content belonging to soft-deleted environment"
    );
    assert_eq!(results[0].id, s_active);

    assert_eq!(
        count_item_content_recursive(&conn, item_id, RecordType::Secret).unwrap(),
        1
    );
}

#[test]
fn challenge_cascade_delete_item_large_scale_stress() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("cascade_large.sqlite3");
    let mut conn = open_connection(&db_path).expect("open connection");
    run_migrations(&mut conn).expect("run migrations");

    let origin = "large_scale_tester";
    let now = 1_730_000_000_000i64;

    let item_id = Uuid::now_v7();
    insert_record(
        &conn,
        &RecordRow::new_active(item_id, RecordType::Item, None, 1, vec![1], 1, origin, now),
    )
    .unwrap();

    // Create 10 environments, each with 5 secrets, 2 files, 2 notes = 9 content items per env = 90 items + 10 envs = 100 children
    let mut expected_envs = 0;
    let mut expected_secrets = 0;
    let mut expected_files = 0;
    let mut expected_notes = 0;

    let mut all_child_ids = Vec::new();

    for i in 0..10 {
        let env_id = Uuid::now_v7();
        insert_record(
            &conn,
            &RecordRow::new_active(
                env_id,
                RecordType::Environment,
                Some(item_id),
                1,
                vec![i as u8],
                (i + 2) as u64,
                origin,
                now,
            ),
        )
        .unwrap();
        expected_envs += 1;
        all_child_ids.push(env_id);

        for j in 0..5 {
            let s_id = Uuid::now_v7();
            insert_record(
                &conn,
                &RecordRow::new_active(
                    s_id,
                    RecordType::Secret,
                    Some(env_id),
                    1,
                    vec![j as u8],
                    100,
                    origin,
                    now,
                ),
            )
            .unwrap();
            expected_secrets += 1;
            all_child_ids.push(s_id);
        }

        for j in 0..2 {
            let f_id = Uuid::now_v7();
            insert_record(
                &conn,
                &RecordRow::new_active(
                    f_id,
                    RecordType::File,
                    Some(env_id),
                    1,
                    vec![j as u8],
                    200,
                    origin,
                    now,
                ),
            )
            .unwrap();
            expected_files += 1;
            all_child_ids.push(f_id);
        }

        for j in 0..2 {
            let n_id = Uuid::now_v7();
            insert_record(
                &conn,
                &RecordRow::new_active(
                    n_id,
                    RecordType::Note,
                    Some(env_id),
                    1,
                    vec![j as u8],
                    300,
                    origin,
                    now,
                ),
            )
            .unwrap();
            expected_notes += 1;
            all_child_ids.push(n_id);
        }
    }

    let summary = cascade_delete_item(&mut conn, item_id, origin, now + 100).unwrap();
    assert_eq!(summary.item_id, item_id);
    assert_eq!(summary.environments_deleted, expected_envs);
    assert_eq!(summary.secrets_deleted, expected_secrets);
    assert_eq!(summary.files_deleted, expected_files);
    assert_eq!(summary.notes_deleted, expected_notes);
    assert_eq!(summary.total_records_affected, 1 + all_child_ids.len());

    // Verify all records are deleted with blob = NULL
    let item_row = get_record(&conn, item_id).unwrap().unwrap();
    assert!(item_row.deleted);
    assert!(item_row.blob.is_none());

    for cid in all_child_ids {
        let r = get_record(&conn, cid).unwrap().unwrap();
        assert!(r.deleted);
        assert!(r.blob.is_none());
    }
}

// ============================================================================
// 5. Phase 2 Non-Destructive Storage Migration End-to-End
// ============================================================================

#[test]
fn challenge_phase2_storage_migration_end_to_end() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let vault_id = Uuid::now_v7();
    let origin_device = "migration_challenger_node";
    let now_ms = 1_730_200_000_000i64;

    // Master key k_v and keystore
    let k_v = [42u8; 32];
    let (k_rec, _k_evt) = derive_keys(&k_v, &vault_id);
    let keystore = MemoryStore::new();
    keystore
        .set(&format!("secwet/{vault_id}/vault-key/1"), &k_v)
        .expect("set key in keystore");

    let p1_id = Uuid::now_v7();
    let p2_id = Uuid::now_v7();
    let e1_id = Uuid::now_v7();
    let e2_id = Uuid::now_v7();
    let s1_id = Uuid::now_v7();
    let s2_id = Uuid::now_v7();

    // 1. Establish a v1 schema database with user_version = 1
    {
        let conn = open_connection(&db_path).expect("open connection");
        conn.execute_batch(INITIAL_SCHEMA_SQL)
            .expect("v1 schema DDL");
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('vault_id', ?1), ('device_id', ?2), ('current_key_epoch', '1')",
            params![vault_id.to_string(), origin_device],
        )
        .expect("insert meta v1");
        conn.execute("PRAGMA user_version = 1", [])
            .expect("set user_version 1");

        // Insert legacy Project 1 (record_type = 1, parent_id = None)
        let p1_body = ProjectBody::new("Production Web App");
        let p1_bytes = postcard::to_stdvec(&p1_body).unwrap();
        let p1_aad = RecordAad::from_raw_type(vault_id.as_bytes(), p1_id.as_bytes(), 1, 1);
        let p1_blob = seal_record(&k_rec, &p1_aad, &p1_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                p1_id,
                RecordType::Label, /* raw 1 */
                None,
                1,
                p1_blob,
                1,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Insert legacy Project 2 (record_type = 1, parent_id = None)
        let p2_body = ProjectBody::new("Internal Tools");
        let p2_bytes = postcard::to_stdvec(&p2_body).unwrap();
        let p2_aad = RecordAad::from_raw_type(vault_id.as_bytes(), p2_id.as_bytes(), 1, 1);
        let p2_blob = seal_record(&k_rec, &p2_aad, &p2_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                p2_id,
                RecordType::Label, /* raw 1 */
                None,
                1,
                p2_blob,
                2,
                origin_device,
                now_ms + 10,
            ),
        )
        .unwrap();

        // Insert legacy Environment 1 under P1 (record_type = 2, parent_id = Some(p1_id))
        let e1_body = EnvironmentBody::new(p1_id, "production", 0);
        let e1_bytes = postcard::to_stdvec(&e1_body).unwrap();
        let e1_aad = RecordAad::from_raw_type(vault_id.as_bytes(), e1_id.as_bytes(), 2, 1);
        let e1_blob = seal_record(&k_rec, &e1_aad, &e1_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                e1_id,
                RecordType::Item, /* raw 2 */
                Some(p1_id),
                1,
                e1_blob,
                3,
                origin_device,
                now_ms + 20,
            ),
        )
        .unwrap();

        // Insert legacy Environment 2 under P1 (record_type = 2, parent_id = Some(p1_id))
        let e2_body = EnvironmentBody::new(p1_id, "staging", 1);
        let e2_bytes = postcard::to_stdvec(&e2_body).unwrap();
        let e2_aad = RecordAad::from_raw_type(vault_id.as_bytes(), e2_id.as_bytes(), 2, 1);
        let e2_blob = seal_record(&k_rec, &e2_aad, &e2_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                e2_id,
                RecordType::Item, /* raw 2 */
                Some(p1_id),
                1,
                e2_blob,
                4,
                origin_device,
                now_ms + 30,
            ),
        )
        .unwrap();

        // Insert legacy Secret 1 under E1 (record_type = 3, parent_id = Some(e1_id))
        let s1_body = SecretBody::new(
            p1_id,
            Some(e1_id),
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://prod:sec@db/app",
            None,
        );
        let s1_bytes = postcard::to_stdvec(&s1_body).unwrap();
        let s1_aad = RecordAad::from_raw_type(vault_id.as_bytes(), s1_id.as_bytes(), 3, 1);
        let s1_blob = seal_record(&k_rec, &s1_aad, &s1_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                s1_id,
                RecordType::Environment, /* raw 3 */
                Some(e1_id),
                1,
                s1_blob,
                5,
                origin_device,
                now_ms + 40,
            ),
        )
        .unwrap();

        // Insert legacy Secret 2 under E2 (record_type = 3, parent_id = Some(e2_id))
        let s2_body = SecretBody::new(
            p1_id,
            Some(e2_id),
            "API_KEY",
            SecretKind::ApiKey,
            "test_api_key_value_123",
            Some("staging key".to_string()),
        );
        let s2_bytes = postcard::to_stdvec(&s2_body).unwrap();
        let s2_aad = RecordAad::from_raw_type(vault_id.as_bytes(), s2_id.as_bytes(), 3, 1);
        let s2_blob = seal_record(&k_rec, &s2_aad, &s2_bytes).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                s2_id,
                RecordType::Environment, /* raw 3 */
                Some(e2_id),
                1,
                s2_blob,
                6,
                origin_device,
                now_ms + 50,
            ),
        )
        .unwrap();
    }

    // Verify status is Locked
    let status = Vault::status(dir.path()).expect("vault status");
    assert_eq!(status, VaultStatus::Locked { vault_id });

    // 2. Unlock the vault - executes run_migrations (0002) and migrate_phase2_flexible_org
    let vault = Vault::unlock(dir.path(), &keystore).expect("unlock migrated vault");
    assert!(
        vault.is_flexible_migrated(),
        "vault must be marked flexible migrated"
    );

    // 3. Verify public flexible org APIs:
    // Labels: default "Projects" label seeded at position 0
    let labels = vault.list_labels().expect("list labels");
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].name, "Projects");
    assert_eq!(labels[0].position, 0);
    let projects_label_id = labels[0].id;

    // Items: both legacy projects migrated into items under the "Projects" label
    let items = vault.list_items(projects_label_id).expect("list items");
    assert_eq!(items.len(), 2);
    let item1 = items.iter().find(|i| i.id == p1_id).expect("P1 migrated");
    let item2 = items.iter().find(|i| i.id == p2_id).expect("P2 migrated");
    assert_eq!(item1.name, "Production Web App");
    assert_eq!(item1.label_id, projects_label_id);
    assert_eq!(item2.name, "Internal Tools");
    assert_eq!(item2.label_id, projects_label_id);

    // Environments: e1 and e2 migrated under item1 (p1_id)
    let envs = vault.list_environments(p1_id).expect("list environments");
    assert_eq!(envs.len(), 2);
    let env_prod = envs.iter().find(|e| e.id == e1_id).expect("e1 migrated");
    let env_stag = envs.iter().find(|e| e.id == e2_id).expect("e2 migrated");
    assert_eq!(env_prod.name, "production");
    assert_eq!(env_prod.item_id, p1_id);
    assert_eq!(env_stag.name, "staging");
    assert_eq!(env_stag.item_id, p1_id);

    // Secrets: s1 and s2 migrated under respective environments
    let secrets_e1 = vault
        .list_secrets(p1_id, Some(e1_id))
        .expect("list secrets e1");
    assert_eq!(secrets_e1.len(), 1);
    assert_eq!(secrets_e1[0].name, "DATABASE_URL");
    assert_eq!(secrets_e1[0].kind, SecretKind::EnvVar);

    let secrets_e2 = vault
        .list_secrets(p1_id, Some(e2_id))
        .expect("list secrets e2");
    assert_eq!(secrets_e2.len(), 1);
    assert_eq!(secrets_e2[0].name, "API_KEY");
    assert_eq!(secrets_e2[0].kind, SecretKind::ApiKey);

    // Decryption of secret values
    let s1_revealed = vault.reveal_secret(s1_id).expect("reveal s1");
    assert_eq!(s1_revealed.expose_secret(), "postgres://prod:sec@db/app");

    let s2_revealed = vault.reveal_secret(s2_id).expect("reveal s2");
    assert_eq!(s2_revealed.expose_secret(), "test_api_key_value_123");

    // Overview counts
    let ov = vault.overview().expect("overview");
    assert_eq!(ov.items_count, 2);
    assert_eq!(ov.labels_count, 1);
    assert_eq!(ov.environments_count, 2);
    assert_eq!(ov.secrets_count, 2);
    assert_eq!(ov.files_count, 0);
    assert_eq!(ov.notes_count, 0);

    // Backwards compatibility APIs continue to work
    let legacy_projects = vault.list_projects().expect("list projects");
    assert_eq!(legacy_projects.len(), 2);

    vault.lock();

    // 4. Verify low-level SQLite database state directly
    {
        let conn = open_connection(&db_path).expect("open connection verification");
        let v = get_schema_version(&conn).expect("schema version");
        assert_eq!(v, 2);

        let mig = get_meta(&conn, "flexible_org_migrated").expect("meta mig");
        assert_eq!(mig.as_deref(), Some("1"));

        // Verify record types:
        // Type 1 (Label): none in records table (labels live in labels table!)
        let count_type_1: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count_type_1, 0,
            "No records of legacy type 1 remain in records table"
        );

        // Type 2 (Item): 2 items
        let count_type_2: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count_type_2, 2, "Exactly 2 items (migrated projects)");

        // Type 3 (Environment): 2 environments
        let count_type_3: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            count_type_3, 2,
            "Exactly 2 environments (migrated from type 2)"
        );

        // Type 4 (Secret): 2 secrets
        let count_type_4: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 4",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(count_type_4, 2, "Exactly 2 secrets (migrated from type 3)");

        // Labels table: exactly 1 label
        let count_labels: i64 = conn
            .query_row("SELECT COUNT(*) FROM labels WHERE deleted = 0", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(count_labels, 1, "Exactly 1 active label");
    }

    // 5. Test idempotency: unlock a second time
    let vault2 = Vault::unlock(dir.path(), &keystore).expect("unlock second time");
    assert!(vault2.is_flexible_migrated());
    let items2 = vault2
        .list_items(projects_label_id)
        .expect("list items second time");
    assert_eq!(items2.len(), 2);
    vault2.lock();
}

// ============================================================================
// 6. Milestone 2 Challenger 2: Adversarial Legacy v1 Migration & Zeroization
// ============================================================================

#[derive(serde::Serialize)]
struct AdversarialLegacyV1SecretBody {
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub name: String,
    pub kind: secwet_proto::SecretKind,
    pub value: String,
    pub note: Option<String>,
}

#[test]
fn challenge_phase2_migration_complex_adversarial_v1_vault() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let vault_id = Uuid::now_v7();
    let origin_device = "challenger_migration_node_m2";
    let now_ms = 1_730_300_000_000i64;

    let k_v = [137u8; 32];
    let (k_rec, _k_evt) = derive_keys(&k_v, &vault_id);
    let keystore = MemoryStore::new();
    keystore
        .set(&format!("secwet/{vault_id}/vault-key/1"), &k_v)
        .expect("set key in keystore");

    let p1_id = Uuid::now_v7();
    let p2_id = Uuid::now_v7();
    let p3_id = Uuid::now_v7();
    let p4_id = Uuid::now_v7(); // deleted project
    let p5_id = Uuid::now_v7();

    let e1_prod = Uuid::now_v7();
    let e1_stag = Uuid::now_v7();
    let e1_dev = Uuid::now_v7();
    let e1_canary = Uuid::now_v7();

    let e2_useast = Uuid::now_v7();
    let e2_eucentral = Uuid::now_v7();
    let e2_email = Uuid::now_v7();

    let e3_default = Uuid::now_v7();
    let e4_deleted = Uuid::now_v7(); // deleted environment

    let e5_batch = Uuid::now_v7();
    let e5_stream = Uuid::now_v7();
    let e5_infer = Uuid::now_v7();

    let s1_multiline = Uuid::now_v7();
    let s1_cert = Uuid::now_v7();
    let s1_apikey = Uuid::now_v7();
    let s1_del = Uuid::now_v7(); // soft-deleted secret
    let s2_emoji = Uuid::now_v7();
    let s2_special_name = Uuid::now_v7();
    let s2_legacy_format = Uuid::now_v7();
    let s2_ssh = Uuid::now_v7();
    let s4_del = Uuid::now_v7(); // soft-deleted secret in soft-deleted env
    let s5_json = Uuid::now_v7();
    let s5_large = Uuid::now_v7();
    let s5_dotenv = Uuid::now_v7();

    // 1. Build v1 legacy database
    {
        let conn = open_connection(&db_path).expect("open connection");
        conn.execute_batch(INITIAL_SCHEMA_SQL)
            .expect("v1 schema DDL");
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('vault_id', ?1), ('device_id', ?2), ('current_key_epoch', '1')",
            params![vault_id.to_string(), origin_device],
        )
        .expect("insert meta v1");
        conn.execute("PRAGMA user_version = 1", [])
            .expect("set user_version 1");

        let mut lamport = 1u64;

        let seal_and_insert = |conn: &rusqlite::Connection,
                               id: Uuid,
                               rec_type: u8,
                               parent_id: Option<Uuid>,
                               payload_bytes: &[u8],
                               clock: u64| {
            let aad = RecordAad::from_raw_type(vault_id.as_bytes(), id.as_bytes(), rec_type, 1);
            let blob = seal_record(&k_rec, &aad, payload_bytes).unwrap();
            let r_type = match rec_type {
                1 => RecordType::Label,
                2 => RecordType::Item,
                3 => RecordType::Environment,
                _ => panic!("unsupported raw rec_type"),
            };
            insert_record(
                conn,
                &RecordRow::new_active(
                    id,
                    r_type,
                    parent_id,
                    1,
                    blob,
                    clock,
                    origin_device,
                    now_ms + clock as i64,
                ),
            )
            .unwrap();
        };

        // Projects (raw type 1)
        let p1_body = ProjectBody::new("Production Web Cluster");
        seal_and_insert(
            &conn,
            p1_id,
            1,
            None,
            &postcard::to_stdvec(&p1_body).unwrap(),
            lamport,
        );
        lamport += 1;

        let p2_body = ProjectBody::new("Edge Gateway 🚀 / (Special & Complex 0.1.0)");
        seal_and_insert(
            &conn,
            p2_id,
            1,
            None,
            &postcard::to_stdvec(&p2_body).unwrap(),
            lamport,
        );
        lamport += 1;

        let p3_body = ProjectBody::new("Empty Project (Zero Secrets)");
        seal_and_insert(
            &conn,
            p3_id,
            1,
            None,
            &postcard::to_stdvec(&p3_body).unwrap(),
            lamport,
        );
        lamport += 1;

        insert_record(
            &conn,
            &RecordRow {
                id: p4_id,
                record_type: RecordType::Label, // raw 1
                parent_id: None,
                key_epoch: 1,
                blob: None,
                lamport,
                origin_device: origin_device.to_string(),
                updated_at: now_ms + 10,
                deleted: true,
            },
        )
        .unwrap();
        lamport += 1;

        let p5_body = ProjectBody::new("ML Infrastructure");
        seal_and_insert(
            &conn,
            p5_id,
            1,
            None,
            &postcard::to_stdvec(&p5_body).unwrap(),
            lamport,
        );
        lamport += 1;

        // Environments (raw type 2)
        seal_and_insert(
            &conn,
            e1_prod,
            2,
            Some(p1_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p1_id, "production", 0)).unwrap(),
            lamport,
        );
        lamport += 1;
        seal_and_insert(
            &conn,
            e1_stag,
            2,
            Some(p1_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p1_id, "staging", 1)).unwrap(),
            lamport,
        );
        lamport += 1;
        seal_and_insert(
            &conn,
            e1_dev,
            2,
            Some(p1_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p1_id, "dev", 2)).unwrap(),
            lamport,
        );
        lamport += 1;
        seal_and_insert(
            &conn,
            e1_canary,
            2,
            Some(p1_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p1_id, "qa-canary", 3)).unwrap(),
            lamport,
        );
        lamport += 1;

        seal_and_insert(
            &conn,
            e2_useast,
            2,
            Some(p2_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p2_id, "prod-us-east-1", 0)).unwrap(),
            lamport,
        );
        lamport += 1;
        seal_and_insert(
            &conn,
            e2_eucentral,
            2,
            Some(p2_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p2_id, "prod-eu-central-1", 1)).unwrap(),
            lamport,
        );
        lamport += 1;
        seal_and_insert(
            &conn,
            e2_email,
            2,
            Some(p2_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p2_id, "admin@secwet.test", 2)).unwrap(),
            lamport,
        );
        lamport += 1;

        seal_and_insert(
            &conn,
            e3_default,
            2,
            Some(p3_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p3_id, "default", 0)).unwrap(),
            lamport,
        );
        lamport += 1;

        insert_record(
            &conn,
            &RecordRow {
                id: e4_deleted,
                record_type: RecordType::Item, // raw 2
                parent_id: Some(p4_id),
                key_epoch: 1,
                blob: None,
                lamport,
                origin_device: origin_device.to_string(),
                updated_at: now_ms + 20,
                deleted: true,
            },
        )
        .unwrap();
        lamport += 1;

        seal_and_insert(
            &conn,
            e5_batch,
            2,
            Some(p5_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p5_id, "batch", 0)).unwrap(),
            lamport,
        );
        lamport += 1;
        seal_and_insert(
            &conn,
            e5_stream,
            2,
            Some(p5_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p5_id, "streaming", 1)).unwrap(),
            lamport,
        );
        lamport += 1;
        seal_and_insert(
            &conn,
            e5_infer,
            2,
            Some(p5_id),
            &postcard::to_stdvec(&EnvironmentBody::new(p5_id, "inference", 2)).unwrap(),
            lamport,
        );
        lamport += 1;

        // Secrets (raw type 3)
        let s1_body = SecretBody::new(
            p1_id,
            Some(e1_prod),
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://prod_admin:p%40ssw0rd!@db-cluster.internal:5432/main_db?sslmode=verify-full\r\n# Connection pool configs\nPOOL_MAX=50\nTIMEOUT=30s\n",
            Some("Primary DB URI with CRLF and special chars".to_string()),
        );
        seal_and_insert(
            &conn,
            s1_multiline,
            3,
            Some(e1_prod),
            &postcard::to_stdvec(&s1_body).unwrap(),
            lamport,
        );
        lamport += 1;

        let s1_cert_body = SecretBody::new(
            p1_id,
            Some(e1_prod),
            "TLS_CERTIFICATE",
            SecretKind::Certificate,
            "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJALe1...==\n-----END CERTIFICATE-----\n",
            None,
        );
        seal_and_insert(
            &conn,
            s1_cert,
            3,
            Some(e1_prod),
            &postcard::to_stdvec(&s1_cert_body).unwrap(),
            lamport,
        );
        lamport += 1;

        let s1_apikey_body = SecretBody::new(
            p1_id,
            Some(e1_stag),
            "STRIPE_SECRET_KEY",
            SecretKind::ApiKey,
            "sk_test_51Mz...xyz789",
            Some("Stripe staging key".to_string()),
        );
        seal_and_insert(
            &conn,
            s1_apikey,
            3,
            Some(e1_stag),
            &postcard::to_stdvec(&s1_apikey_body).unwrap(),
            lamport,
        );
        lamport += 1;

        insert_record(
            &conn,
            &RecordRow {
                id: s1_del,
                record_type: RecordType::Environment, // raw 3
                parent_id: Some(e1_dev),
                key_epoch: 1,
                blob: None,
                lamport,
                origin_device: origin_device.to_string(),
                updated_at: now_ms + 30,
                deleted: true,
            },
        )
        .unwrap();
        lamport += 1;

        let s2_emoji_body = SecretBody::new(
            p2_id,
            Some(e2_useast),
            "API_TOKEN_EMOJI",
            SecretKind::ApiKey,
            "token_🚀_🔥_🔒_secret_value_✨_123",
            Some("Unicode emoji note 🌟".to_string()),
        );
        seal_and_insert(
            &conn,
            s2_emoji,
            3,
            Some(e2_useast),
            &postcard::to_stdvec(&s2_emoji_body).unwrap(),
            lamport,
        );
        lamport += 1;

        let s2_special_body = SecretBody::new(
            p2_id,
            Some(e2_useast),
            "__SPECIAL_ENV_VAR__",
            SecretKind::EnvVar,
            "special_value_with_quotes_\"'and_backslashes\\",
            None,
        );
        seal_and_insert(
            &conn,
            s2_special_name,
            3,
            Some(e2_useast),
            &postcard::to_stdvec(&s2_special_body).unwrap(),
            lamport,
        );
        lamport += 1;

        let s2_leg = AdversarialLegacyV1SecretBody {
            project_id: p2_id,
            environment_id: e2_eucentral,
            name: "LEGACY_FORMAT_SECRET".to_string(),
            kind: SecretKind::Password,
            value: "v1_legacy_serialized_password_secret_val".to_string(),
            note: Some("Serialized with v1 format".to_string()),
        };
        seal_and_insert(
            &conn,
            s2_legacy_format,
            3,
            Some(e2_eucentral),
            &postcard::to_stdvec(&s2_leg).unwrap(),
            lamport,
        );
        lamport += 1;

        let s2_ssh_body = SecretBody::new(
            p2_id,
            Some(e2_email),
            "ID_RSA",
            SecretKind::SshKey,
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAA...\n-----END OPENSSH PRIVATE KEY-----",
            None,
        );
        seal_and_insert(
            &conn,
            s2_ssh,
            3,
            Some(e2_email),
            &postcard::to_stdvec(&s2_ssh_body).unwrap(),
            lamport,
        );
        lamport += 1;

        insert_record(
            &conn,
            &RecordRow {
                id: s4_del,
                record_type: RecordType::Environment, // raw 3
                parent_id: Some(e4_deleted),
                key_epoch: 1,
                blob: None,
                lamport,
                origin_device: origin_device.to_string(),
                updated_at: now_ms + 40,
                deleted: true,
            },
        )
        .unwrap();
        lamport += 1;

        let s5_json_body = SecretBody::new(
            p5_id,
            Some(e5_batch),
            "CONFIG_JSON",
            SecretKind::AccessToken,
            "{\"batch_size\": 1024, \"enabled\": true, \"null_field\": null, \"nested\": {\"ratio\": 0.95}}",
            Some("JSON configuration blob".to_string()),
        );
        seal_and_insert(
            &conn,
            s5_json,
            3,
            Some(e5_batch),
            &postcard::to_stdvec(&s5_json_body).unwrap(),
            lamport,
        );
        lamport += 1;

        let large_val = "A".repeat(60_000);
        let s5_large_body = SecretBody::new(
            p5_id,
            Some(e5_stream),
            "LARGE_SECRET_64KB",
            SecretKind::Password,
            &large_val,
            Some("60KB payload".to_string()),
        );
        seal_and_insert(
            &conn,
            s5_large,
            3,
            Some(e5_stream),
            &postcard::to_stdvec(&s5_large_body).unwrap(),
            lamport,
        );
        lamport += 1;

        let s5_dotenv_body = SecretBody::new(
            p5_id,
            Some(e5_infer),
            "DOTENV_EXPORT",
            SecretKind::EnvVar,
            "FOO=bar\nBAZ=\"qux with spaces\"\nEMPTY=\nSPECIAL=\"!@#$%^&*()_+\"",
            None,
        );
        seal_and_insert(
            &conn,
            s5_dotenv,
            3,
            Some(e5_infer),
            &postcard::to_stdvec(&s5_dotenv_body).unwrap(),
            lamport,
        );
    }

    // 2. Initial state verification: vault is Locked
    let status = Vault::status(dir.path()).expect("vault status");
    assert_eq!(status, VaultStatus::Locked { vault_id });

    // 3. Unlock vault -> automatically runs Phase 2 migration
    let vault = Vault::unlock(dir.path(), &keystore).expect("unlock legacy vault");
    assert!(
        vault.is_flexible_migrated(),
        "vault must report flexible_org_migrated"
    );

    // 4. Verify Labels: exactly 1 label ("Projects")
    let labels = vault.list_labels().expect("list labels");
    assert_eq!(labels.len(), 1, "Only default 'Projects' label must exist");
    assert_eq!(labels[0].name, "Projects");
    let projects_label_id = labels[0].id;

    // 5. Verify Items: exactly 4 active items (P1, P2, P3, P5). P4 (deleted) is filtered out!
    let items = vault.list_items(projects_label_id).expect("list items");
    assert_eq!(
        items.len(),
        4,
        "Exactly 4 active projects migrated to items"
    );
    let item_ids: Vec<Uuid> = items.iter().map(|i| i.id).collect();
    assert!(item_ids.contains(&p1_id));
    assert!(item_ids.contains(&p2_id));
    assert!(item_ids.contains(&p3_id));
    assert!(item_ids.contains(&p5_id));
    assert!(
        !item_ids.contains(&p4_id),
        "Soft-deleted project must NOT be returned"
    );

    let p2_item = items.iter().find(|i| i.id == p2_id).unwrap();
    assert_eq!(p2_item.name, "Edge Gateway 🚀 / (Special & Complex 0.1.0)");

    // 6. Verify Environments under each item:
    let envs_p1 = vault.list_environments(p1_id).expect("list envs p1");
    assert_eq!(envs_p1.len(), 4);
    let env_names_p1: Vec<&str> = envs_p1.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        env_names_p1,
        vec!["production", "staging", "dev", "qa-canary"]
    );

    let envs_p2 = vault.list_environments(p2_id).expect("list envs p2");
    assert_eq!(envs_p2.len(), 3);
    let env_names_p2: Vec<&str> = envs_p2.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(
        env_names_p2,
        vec!["prod-us-east-1", "prod-eu-central-1", "admin@secwet.test"]
    );

    let envs_p3 = vault.list_environments(p3_id).expect("list envs p3");
    assert_eq!(envs_p3.len(), 1);
    assert_eq!(envs_p3[0].name, "default");

    let envs_p5 = vault.list_environments(p5_id).expect("list envs p5");
    assert_eq!(envs_p5.len(), 3);
    let env_names_p5: Vec<&str> = envs_p5.iter().map(|e| e.name.as_str()).collect();
    assert_eq!(env_names_p5, vec!["batch", "streaming", "inference"]);

    // 7. Verify Secrets and Decryption (reveal_secret):
    let s_e1_prod = vault
        .list_secrets(p1_id, Some(e1_prod))
        .expect("list secrets e1_prod");
    assert_eq!(s_e1_prod.len(), 2);
    let s_multiline_meta = s_e1_prod.iter().find(|s| s.id == s1_multiline).unwrap();
    assert_eq!(s_multiline_meta.name, "DATABASE_URL");
    assert_eq!(s_multiline_meta.kind, SecretKind::EnvVar);
    let s_multiline_rev = vault
        .reveal_secret(s1_multiline)
        .expect("reveal s1_multiline");
    assert_eq!(
        s_multiline_rev.expose_secret(),
        "postgres://prod_admin:p%40ssw0rd!@db-cluster.internal:5432/main_db?sslmode=verify-full\r\n# Connection pool configs\nPOOL_MAX=50\nTIMEOUT=30s\n"
    );

    let s_cert_rev = vault.reveal_secret(s1_cert).expect("reveal s1_cert");
    assert_eq!(
        s_cert_rev.expose_secret(),
        "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJALe1...==\n-----END CERTIFICATE-----\n"
    );

    // e1_dev secrets: soft-deleted secret must NOT be listed
    let s_e1_dev = vault
        .list_secrets(p1_id, Some(e1_dev))
        .expect("list secrets e1_dev");
    assert_eq!(
        s_e1_dev.len(),
        0,
        "Soft-deleted secret must be filtered out"
    );
    assert!(matches!(vault.reveal_secret(s1_del), Err(Error::NotFound)));

    let s_emoji_rev = vault.reveal_secret(s2_emoji).expect("reveal s2_emoji");
    assert_eq!(
        s_emoji_rev.expose_secret(),
        "token_🚀_🔥_🔒_secret_value_✨_123"
    );

    let s_special_rev = vault
        .reveal_secret(s2_special_name)
        .expect("reveal s2_special");
    assert_eq!(
        s_special_rev.expose_secret(),
        "special_value_with_quotes_\"'and_backslashes\\"
    );

    let s_leg_meta = vault
        .list_secrets(p2_id, Some(e2_eucentral))
        .expect("list s2_leg");
    assert_eq!(s_leg_meta.len(), 1);
    assert_eq!(s_leg_meta[0].name, "LEGACY_FORMAT_SECRET");
    let s_leg_rev = vault
        .reveal_secret(s2_legacy_format)
        .expect("reveal s2_legacy_format");
    assert_eq!(
        s_leg_rev.expose_secret(),
        "v1_legacy_serialized_password_secret_val"
    );

    let s_ssh_rev = vault.reveal_secret(s2_ssh).expect("reveal s2_ssh");
    assert!(s_ssh_rev
        .expose_secret()
        .starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));

    let s_json_rev = vault.reveal_secret(s5_json).expect("reveal s5_json");
    assert_eq!(s_json_rev.expose_secret(), "{\"batch_size\": 1024, \"enabled\": true, \"null_field\": null, \"nested\": {\"ratio\": 0.95}}");

    let s_large_rev = vault.reveal_secret(s5_large).expect("reveal s5_large");
    assert_eq!(s_large_rev.expose_secret().len(), 60_000);

    let s_dotenv_rev = vault.reveal_secret(s5_dotenv).expect("reveal s5_dotenv");
    assert_eq!(
        s_dotenv_rev.expose_secret(),
        "FOO=bar\nBAZ=\"qux with spaces\"\nEMPTY=\nSPECIAL=\"!@#$%^&*()_+\""
    );

    // 8. Overview aggregation metrics
    let ov = vault.overview().expect("overview");
    assert_eq!(ov.labels_count, 1);
    assert_eq!(ov.items_count, 4);
    assert_eq!(ov.environments_count, 11);
    assert_eq!(ov.secrets_count, 10);
    assert_eq!(ov.files_count, 0);
    assert_eq!(ov.notes_count, 0);

    // 9. Backwards compatibility legacy projects
    let legacy_projs = vault.list_projects().expect("list_projects");
    assert_eq!(legacy_projs.len(), 4);

    vault.lock();

    // 10. Low-level database row audit
    {
        let conn = open_connection(&db_path).expect("open connection");
        assert_eq!(get_schema_version(&conn).unwrap(), 2);
        assert_eq!(
            get_meta(&conn, "flexible_org_migrated").unwrap().as_deref(),
            Some("1")
        );

        let c1: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(c1, 0, "No records of legacy type 1 remain");

        let c2: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 2",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(c2, 5, "5 items total (4 active + 1 tombstoned)");

        let c3: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 3",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(c3, 12, "12 environments total (11 active + 1 tombstoned)");

        let c4: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 4",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(c4, 12, "12 secrets total (10 active + 2 tombstoned)");

        let c_del_blobs: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM records WHERE deleted = 1 AND blob IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            c_del_blobs, 0,
            "All soft-deleted records must have NULL blobs"
        );
    }
}

#[test]
fn challenge_phase2_migration_adversarial_postcard_discriminator_fallback() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let vault_id = Uuid::now_v7();
    let origin_device = "challenger_discriminator_node";
    let now_ms = 1_730_300_100_000i64;

    let k_v = [200u8; 32];
    let (k_rec, _k_evt) = derive_keys(&k_v, &vault_id);
    let keystore = MemoryStore::new();
    keystore
        .set(&format!("secwet/{vault_id}/vault-key/1"), &k_v)
        .expect("set key in keystore");

    let p_id = Uuid::now_v7();

    // Adversarial environment UUIDs with distinct first bytes
    let env_00 = Uuid::from_bytes([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0x01,
    ]);
    let env_01 = Uuid::from_bytes([
        0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0x02,
    ]);
    let env_ff = Uuid::from_bytes([
        0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0x03,
    ]);

    let s_00_id = Uuid::now_v7();
    let s_01_id = Uuid::now_v7();
    let s_ff_id = Uuid::now_v7();

    {
        let conn = open_connection(&db_path).expect("open connection");
        conn.execute_batch(INITIAL_SCHEMA_SQL)
            .expect("v1 schema DDL");
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('vault_id', ?1), ('device_id', ?2), ('current_key_epoch', '1')",
            params![vault_id.to_string(), origin_device],
        ).unwrap();
        conn.execute("PRAGMA user_version = 1", []).unwrap();

        // Project
        let p_body = ProjectBody::new("Discriminator Stress App");
        let p_aad = RecordAad::from_raw_type(vault_id.as_bytes(), p_id.as_bytes(), 1, 1);
        let p_blob = seal_record(&k_rec, &p_aad, &postcard::to_stdvec(&p_body).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                p_id,
                RecordType::Label,
                None,
                1,
                p_blob,
                1,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        // Environments
        for (idx, (eid, ename)) in [
            (env_00, "env_byte_00"),
            (env_01, "env_byte_01"),
            (env_ff, "env_byte_ff"),
        ]
        .iter()
        .enumerate()
        {
            let e_body = EnvironmentBody::new(p_id, *ename, idx as u32);
            let e_aad = RecordAad::from_raw_type(vault_id.as_bytes(), eid.as_bytes(), 2, 1);
            let e_blob =
                seal_record(&k_rec, &e_aad, &postcard::to_stdvec(&e_body).unwrap()).unwrap();
            insert_record(
                &conn,
                &RecordRow::new_active(
                    *eid,
                    RecordType::Item,
                    Some(p_id),
                    1,
                    e_blob,
                    2 + idx as u64,
                    origin_device,
                    now_ms + idx as i64,
                ),
            )
            .unwrap();
        }

        // Secrets serialized using legacy format (AdversarialLegacyV1SecretBody)
        let s_00 = AdversarialLegacyV1SecretBody {
            project_id: p_id,
            environment_id: env_00,
            name: "SECRET_ENV_BYTE_00".to_string(),
            kind: SecretKind::Password,
            value: "value_env_byte_00".to_string(),
            note: None,
        };
        let s_00_aad = RecordAad::from_raw_type(vault_id.as_bytes(), s_00_id.as_bytes(), 3, 1);
        let s_00_blob =
            seal_record(&k_rec, &s_00_aad, &postcard::to_stdvec(&s_00).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                s_00_id,
                RecordType::Environment,
                Some(env_00),
                1,
                s_00_blob,
                10,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        let s_01 = AdversarialLegacyV1SecretBody {
            project_id: p_id,
            environment_id: env_01,
            name: "SECRET_ENV_BYTE_01".to_string(),
            kind: SecretKind::Password,
            value: "value_env_byte_01".to_string(),
            note: None,
        };
        let s_01_aad = RecordAad::from_raw_type(vault_id.as_bytes(), s_01_id.as_bytes(), 3, 1);
        let s_01_blob =
            seal_record(&k_rec, &s_01_aad, &postcard::to_stdvec(&s_01).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                s_01_id,
                RecordType::Environment,
                Some(env_01),
                1,
                s_01_blob,
                11,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        let s_ff = AdversarialLegacyV1SecretBody {
            project_id: p_id,
            environment_id: env_ff,
            name: "SECRET_ENV_BYTE_FF".to_string(),
            kind: SecretKind::Password,
            value: "value_env_byte_ff".to_string(),
            note: None,
        };
        let s_ff_aad = RecordAad::from_raw_type(vault_id.as_bytes(), s_ff_id.as_bytes(), 3, 1);
        let s_ff_blob =
            seal_record(&k_rec, &s_ff_aad, &postcard::to_stdvec(&s_ff).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                s_ff_id,
                RecordType::Environment,
                Some(env_ff),
                1,
                s_ff_blob,
                12,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();
    }

    let vault = Vault::unlock(dir.path(), &keystore).expect("unlock migrated vault");
    assert!(vault.is_flexible_migrated());

    // Verify all 3 secrets decrypted correctly
    let rev_00 = vault.reveal_secret(s_00_id).expect("reveal s_00");
    assert_eq!(rev_00.expose_secret(), "value_env_byte_00");

    let rev_01 = vault.reveal_secret(s_01_id).expect("reveal s_01");
    assert_eq!(rev_01.expose_secret(), "value_env_byte_01");

    let rev_ff = vault.reveal_secret(s_ff_id).expect("reveal s_ff");
    assert_eq!(rev_ff.expose_secret(), "value_env_byte_ff");

    // Verify secret listings under each environment
    let s_00_list = vault.list_secrets(p_id, Some(env_00)).expect("list s_00");
    assert_eq!(s_00_list.len(), 1);
    assert_eq!(s_00_list[0].name, "SECRET_ENV_BYTE_00");

    let s_01_list = vault.list_secrets(p_id, Some(env_01)).expect("list s_01");
    assert_eq!(s_01_list.len(), 1);
    assert_eq!(s_01_list[0].name, "SECRET_ENV_BYTE_01");

    let s_ff_list = vault.list_secrets(p_id, Some(env_ff)).expect("list s_ff");
    assert_eq!(s_ff_list.len(), 1);
    assert_eq!(s_ff_list[0].name, "SECRET_ENV_BYTE_FF");

    vault.lock();
}

#[test]
fn challenge_phase2_migration_multi_unlock_idempotency_stress() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let vault_id = Uuid::now_v7();
    let origin_device = "challenger_idempotency_node";
    let now_ms = 1_730_300_200_000i64;

    let k_v = [77u8; 32];
    let (k_rec, _k_evt) = derive_keys(&k_v, &vault_id);
    let keystore = MemoryStore::new();
    keystore
        .set(&format!("secwet/{vault_id}/vault-key/1"), &k_v)
        .expect("set key in keystore");

    let p_id = Uuid::now_v7();
    let e_id = Uuid::now_v7();
    let s_id = Uuid::now_v7();

    {
        let conn = open_connection(&db_path).expect("open connection");
        conn.execute_batch(INITIAL_SCHEMA_SQL)
            .expect("v1 schema DDL");
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('vault_id', ?1), ('device_id', ?2), ('current_key_epoch', '1')",
            params![vault_id.to_string(), origin_device],
        ).unwrap();
        conn.execute("PRAGMA user_version = 1", []).unwrap();

        let p_body = ProjectBody::new("Idempotency Base Project");
        let p_aad = RecordAad::from_raw_type(vault_id.as_bytes(), p_id.as_bytes(), 1, 1);
        let p_blob = seal_record(&k_rec, &p_aad, &postcard::to_stdvec(&p_body).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                p_id,
                RecordType::Label,
                None,
                1,
                p_blob,
                1,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        let e_body = EnvironmentBody::new(p_id, "production", 0);
        let e_aad = RecordAad::from_raw_type(vault_id.as_bytes(), e_id.as_bytes(), 2, 1);
        let e_blob = seal_record(&k_rec, &e_aad, &postcard::to_stdvec(&e_body).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                e_id,
                RecordType::Item,
                Some(p_id),
                1,
                e_blob,
                2,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        let s_body = SecretBody::new(
            p_id,
            Some(e_id),
            "BASE_SECRET",
            SecretKind::EnvVar,
            "base_val_123",
            None,
        );
        let s_aad = RecordAad::from_raw_type(vault_id.as_bytes(), s_id.as_bytes(), 3, 1);
        let s_blob = seal_record(&k_rec, &s_aad, &postcard::to_stdvec(&s_body).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                s_id,
                RecordType::Environment,
                Some(e_id),
                1,
                s_blob,
                3,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();
    }

    // First unlock: triggers Phase 2 migration
    let mut vault = Vault::unlock(dir.path(), &keystore).expect("unlock 1");
    assert!(vault.is_flexible_migrated());

    let labels = vault.list_labels().expect("labels");
    let proj_label_id = labels[0].id;

    // Mutate in v2: add a second item, an environment, a secret, a file, and a note
    let v2_item = vault
        .create_item(proj_label_id, "V2 Added Item", None)
        .expect("create item");
    let v2_env = vault
        .add_environment(v2_item.id, "v2-staging")
        .expect("add env");
    vault
        .create_secret(SecretDraft::new(
            v2_item.id,
            Some(v2_env.id),
            "NEW_V2_SECRET",
            SecretKind::ApiKey,
            "sk_live_v2_123456",
            None,
        ))
        .expect("create secret");
    vault
        .upload_file(
            v2_item.id,
            Some(v2_env.id),
            "document.pdf",
            b"test pdf binary stream",
            Some("application/pdf"),
        )
        .expect("upload file");
    vault
        .create_note(
            v2_item.id,
            Some(v2_env.id),
            "Sprint Notes",
            "<p>Meeting notes content</p>",
        )
        .expect("create note");

    let ov1 = vault.overview().expect("ov1");
    assert_eq!(ov1.labels_count, 1);
    assert_eq!(ov1.items_count, 2);
    assert_eq!(ov1.environments_count, 2);
    assert_eq!(ov1.secrets_count, 2);
    assert_eq!(ov1.files_count, 1);
    assert_eq!(ov1.notes_count, 1);

    vault.lock();

    // Unlock 10 times consecutively and assert state invariants
    for cycle in 2..=11 {
        let v = Vault::unlock(dir.path(), &keystore)
            .unwrap_or_else(|e| panic!("unlock failed on cycle {cycle}: {e:?}"));
        assert!(
            v.is_flexible_migrated(),
            "must remain migrated on cycle {cycle}"
        );

        let ov = v.overview().expect("overview");
        assert_eq!(
            ov.labels_count, 1,
            "labels_count corrupted on cycle {cycle}"
        );
        assert_eq!(ov.items_count, 2, "items_count corrupted on cycle {cycle}");
        assert_eq!(
            ov.environments_count, 2,
            "environments_count corrupted on cycle {cycle}"
        );
        assert_eq!(
            ov.secrets_count, 2,
            "secrets_count corrupted on cycle {cycle}"
        );
        assert_eq!(ov.files_count, 1, "files_count corrupted on cycle {cycle}");
        assert_eq!(ov.notes_count, 1, "notes_count corrupted on cycle {cycle}");

        let items = v.list_items(proj_label_id).expect("list items");
        assert_eq!(
            items.len(),
            2,
            "items list length corrupted on cycle {cycle}"
        );

        let rev_base = v.reveal_secret(s_id).expect("reveal base");
        assert_eq!(rev_base.expose_secret(), "base_val_123");

        v.lock();
    }

    // Direct SQLite check
    let conn = open_connection(&db_path).expect("open connection");
    let c_mig = get_meta(&conn, "flexible_org_migrated")
        .expect("meta")
        .unwrap();
    assert_eq!(c_mig, "1");

    let label_count: i64 = conn
        .query_row("SELECT COUNT(*) FROM labels WHERE deleted = 0", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(label_count, 1, "Exactly 1 active label must exist");
}

#[test]
fn challenge_phase2_migration_raw_disk_strings_inspection_zero_leakage() {
    let dir = tempdir().expect("tempdir");
    let db_path = dir.path().join("vault.sqlite3");

    let vault_id = Uuid::now_v7();
    let origin_device = "challenger_leakage_node";
    let now_ms = 1_730_300_300_000i64;

    let k_v = [99u8; 32];
    let (k_rec, _k_evt) = derive_keys(&k_v, &vault_id);
    let keystore = MemoryStore::new();
    keystore
        .set(&format!("secwet/{vault_id}/vault-key/1"), &k_v)
        .expect("set key in keystore");

    let p_id = Uuid::now_v7();
    let e_id = Uuid::now_v7();
    let s_id = Uuid::now_v7();

    // Canary sensitive plaintext tokens
    let canary_secret_name = "CANARY_NAME_EMPIRICAL_SECRET_XYZ99";
    let canary_secret_value = "CANARY_VALUE_SUPER_CONFIDENTIAL_PLAINTEXT_TOKEN_ABC123456789";
    let canary_note_title = "CANARY_NOTE_CONFIDENTIAL_TITLE_99";
    let canary_note_content = "CANARY_NOTE_CONTENT_BODY_TOP_SECRET_REPORT_FOR_EYES_ONLY";
    let canary_file_name = "CANARY_FILE_FINANCIAL_AUDIT_2026.TXT";
    let canary_file_data = b"CANARY_RAW_FILE_BINARY_BYTES_SUPER_SENSITIVE_PAYLOAD_DEADBEEF";

    // 1. Establish legacy database containing canary secret
    {
        let conn = open_connection(&db_path).expect("open connection");
        conn.execute_batch(INITIAL_SCHEMA_SQL)
            .expect("v1 schema DDL");
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('schema_version', '1'), ('vault_id', ?1), ('device_id', ?2), ('current_key_epoch', '1')",
            params![vault_id.to_string(), origin_device],
        ).unwrap();
        conn.execute("PRAGMA user_version = 1", []).unwrap();

        let p_body = ProjectBody::new("Canary Inspection Project");
        let p_aad = RecordAad::from_raw_type(vault_id.as_bytes(), p_id.as_bytes(), 1, 1);
        let p_blob = seal_record(&k_rec, &p_aad, &postcard::to_stdvec(&p_body).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                p_id,
                RecordType::Label,
                None,
                1,
                p_blob,
                1,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        let e_body = EnvironmentBody::new(p_id, "production", 0);
        let e_aad = RecordAad::from_raw_type(vault_id.as_bytes(), e_id.as_bytes(), 2, 1);
        let e_blob = seal_record(&k_rec, &e_aad, &postcard::to_stdvec(&e_body).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                e_id,
                RecordType::Item,
                Some(p_id),
                1,
                e_blob,
                2,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();

        let s_body = SecretBody::new(
            p_id,
            Some(e_id),
            canary_secret_name,
            SecretKind::ApiKey,
            canary_secret_value,
            Some("canary secret note".to_string()),
        );
        let s_aad = RecordAad::from_raw_type(vault_id.as_bytes(), s_id.as_bytes(), 3, 1);
        let s_blob = seal_record(&k_rec, &s_aad, &postcard::to_stdvec(&s_body).unwrap()).unwrap();
        insert_record(
            &conn,
            &RecordRow::new_active(
                s_id,
                RecordType::Environment,
                Some(e_id),
                1,
                s_blob,
                3,
                origin_device,
                now_ms,
            ),
        )
        .unwrap();
    }

    // 2. Unlock vault (executes Phase 2 migration)
    let mut vault = Vault::unlock(dir.path(), &keystore).expect("unlock vault");
    assert!(vault.is_flexible_migrated());

    // 3. Add canary file and note in v2
    let file_view = vault
        .upload_file(
            p_id,
            Some(e_id),
            canary_file_name,
            canary_file_data,
            Some("text/plain"),
        )
        .expect("upload file");
    assert_eq!(file_view.name, canary_file_name);

    let note_view = vault
        .create_note(p_id, Some(e_id), canary_note_title, canary_note_content)
        .expect("create note");
    assert_eq!(note_view.title, canary_note_title);

    // Lock vault to ensure zero active lock held
    vault.lock();

    // 4. Force a WAL checkpoint TRUNCATE to flush all pages to disk
    {
        let conn = open_connection(&db_path).expect("open for checkpoint");
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .expect("wal checkpoint");
    }

    // 5. Raw Disk Inspection: read disk files
    let mut disk_data = std::fs::read(&db_path).expect("read vault.sqlite3");

    let wal_path = dir.path().join("vault.sqlite3-wal");
    if wal_path.exists() {
        let wal_bytes = std::fs::read(&wal_path).expect("read wal");
        disk_data.extend_from_slice(&wal_bytes);
    }

    let shm_path = dir.path().join("vault.sqlite3-shm");
    if shm_path.exists() {
        let shm_bytes = std::fs::read(&shm_path).expect("read shm");
        disk_data.extend_from_slice(&shm_bytes);
    }

    // Check for canary sensitive tokens
    assert!(
        !find_subsequence(&disk_data, canary_secret_name.as_bytes()),
        "LEAK DETECTED: Secret name '{canary_secret_name}' found in raw disk bytes!"
    );

    assert!(
        !find_subsequence(&disk_data, canary_secret_value.as_bytes()),
        "LEAK DETECTED: Secret value '{canary_secret_value}' found in raw disk bytes!"
    );

    assert!(
        !find_subsequence(&disk_data, canary_note_content.as_bytes()),
        "LEAK DETECTED: Note content '{canary_note_content}' found in raw disk bytes!"
    );

    assert!(
        !find_subsequence(&disk_data, canary_file_data),
        "LEAK DETECTED: Raw file payload found in raw disk bytes!"
    );

    // Verify strings simulation (any ASCII substring >= 6 chars matching canary)
    let extracted_strings = extract_ascii_strings(&disk_data, 6);
    for s in extracted_strings {
        assert!(
            !s.contains(canary_secret_name),
            "Extracted string leaked secret name: {s}"
        );
        assert!(
            !s.contains(canary_secret_value),
            "Extracted string leaked secret value: {s}"
        );
        assert!(
            !s.contains(canary_note_content),
            "Extracted string leaked note content: {s}"
        );
    }
}

#[test]
fn challenge_phase2_zeroization_witness_and_memory_safety_comprehensive() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    // 1. Create vault
    let vault = Vault::create(dir.path(), "device-zeroize-test", &keystore).expect("create");
    let rec_w = vault.test_k_rec_witness();
    let evt_w = vault.test_k_evt_witness();

    {
        let r = rec_w.lock().unwrap();
        let e = evt_w.lock().unwrap();
        assert_ne!(*r, [0u8; 32], "k_rec must be non-zero while unlocked");
        assert_ne!(*e, [0u8; 32], "k_evt must be non-zero while unlocked");
    }

    // Lock vault
    vault.lock();

    {
        let r = rec_w.lock().unwrap();
        let e = evt_w.lock().unwrap();
        assert_eq!(*r, [0u8; 32], "k_rec must be zeroized upon lock()");
        assert_eq!(*e, [0u8; 32], "k_evt must be zeroized upon lock()");
    }

    // 2. Unlock vault
    let unlocked = Vault::unlock(dir.path(), &keystore).expect("unlock");
    let rec_w2 = unlocked.test_k_rec_witness();
    let evt_w2 = unlocked.test_k_evt_witness();

    {
        let r = rec_w2.lock().unwrap();
        let e = evt_w2.lock().unwrap();
        assert_ne!(*r, [0u8; 32], "k_rec must be non-zero while unlocked");
        assert_ne!(*e, [0u8; 32], "k_evt must be non-zero while unlocked");
    }

    // Drop unlocked vault without calling lock()
    drop(unlocked);

    {
        let r = rec_w2.lock().unwrap();
        let e = evt_w2.lock().unwrap();
        assert_eq!(*r, [0u8; 32], "k_rec must be zeroized upon drop");
        assert_eq!(*e, [0u8; 32], "k_evt must be zeroized upon drop");
    }
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn extract_ascii_strings(data: &[u8], min_len: usize) -> Vec<String> {
    let mut strings = Vec::new();
    let mut current = Vec::new();

    for &b in data {
        if (32..=126).contains(&b) {
            current.push(b);
        } else {
            if current.len() >= min_len {
                if let Ok(s) = String::from_utf8(current.clone()) {
                    strings.push(s);
                }
            }
            current.clear();
        }
    }

    if current.len() >= min_len {
        if let Ok(s) = String::from_utf8(current) {
            strings.push(s);
        }
    }

    strings
}
