//! Projects CRUD and invariants acceptance tests.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §6, §7 (F3), §11.2, and `ORIGINAL_REQUEST.md`.

use secwet_core::keys::MemoryStore;
use secwet_core::records::get_record;
use secwet_core::{Error, SecretDraft, SecretKind, Vault};
use tempfile::tempdir;

/// Acceptance test: `project_name_unique_case_insensitive`
///
/// Verifies:
/// 1. Create project "payments-api".
/// 2. Attempt to create "Payments-API" or "PAYMENTS-API": fails with `Error::Duplicate { field: "name" }`.
/// 3. Rename of another project to "payments-api" fails with `Error::Duplicate { field: "name" }`.
#[test]
fn project_name_unique_case_insensitive() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut vault = Vault::create(dir.path(), "device-1", &keystore).unwrap();

    // 1. Create initial project
    let p1 = vault.create_project("payments-api", &[]).unwrap();
    assert_eq!(p1.name, "payments-api");

    // 2. Attempt duplicate creation with mixed casing
    let err_mixed = vault.create_project("Payments-API", &[]);
    match err_mixed {
        Err(Error::Duplicate { field: "name" }) => {}
        other => panic!(
            "Expected Error::Duplicate {{ field: \"name\" }}, got: {:?}",
            other
        ),
    }

    let err_upper = vault.create_project("PAYMENTS-API", &[]);
    match err_upper {
        Err(Error::Duplicate { field: "name" }) => {}
        other => panic!(
            "Expected Error::Duplicate {{ field: \"name\" }}, got: {:?}",
            other
        ),
    }

    // 3. Create a second distinct project
    let p2 = vault.create_project("web-dashboard", &[]).unwrap();

    // 4. Attempt to rename p2 to "payments-api" (case-insensitive collision)
    let rename_err = vault.rename_project(p2.id, "Payments-API");
    match rename_err {
        Err(Error::Duplicate { field: "name" }) => {}
        other => panic!(
            "Expected Error::Duplicate {{ field: \"name\" }}, got: {:?}",
            other
        ),
    }

    // Renaming p2 to its own name or changing its own casing is permitted
    vault
        .rename_project(p2.id, "Web-Dashboard")
        .expect("Self-rename or casing change should succeed");

    vault.lock();
}

/// Acceptance test: `delete_project_cascades`
///
/// Verifies:
/// 1. Create project with 3 environments and 6 secrets.
/// 2. Call `Vault::delete_project(project_id)`.
/// 3. In SQLite `records` table, project, all 3 environments, and all 6 secrets have `deleted = 1` and `blob = NULL`.
/// 4. `list_projects` no longer lists the deleted project.
#[test]
fn delete_project_cascades() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut vault = Vault::create(dir.path(), "device-1", &keystore).unwrap();

    // 1. Create project with 3 environments (default: Dev, Staging, Prod)
    let p = vault.create_project("FullCascadeApp", &[]).unwrap();
    assert_eq!(p.environments.len(), 3);

    let env_1 = p.environments[0].id;
    let env_2 = p.environments[1].id;
    let env_3 = p.environments[2].id;

    // Add 2 secrets to each environment (total 6 secrets)
    let mut secret_ids = Vec::new();
    for (i, env_id) in [env_1, env_2, env_3].iter().enumerate() {
        for s_idx in 1..=2 {
            let meta = vault
                .create_secret(SecretDraft::new(
                    p.id,
                    *env_id,
                    format!("SECRET_{i}_{s_idx}"),
                    SecretKind::ApiKey,
                    format!("secret_payload_{i}_{s_idx}"),
                    Some("Note".to_string()),
                ))
                .unwrap();
            secret_ids.push(meta.id);
        }
    }
    assert_eq!(secret_ids.len(), 6);

    // 2. Cascade delete the project
    vault
        .delete_project(p.id)
        .expect("delete_project should succeed");

    // 3. Verify list_projects is now empty
    let remaining_projects = vault.list_projects().unwrap();
    assert!(
        remaining_projects.is_empty(),
        "Deleted project must not appear in list_projects"
    );

    // 4. Verify raw SQLite rows: deleted = 1 and blob is NULL
    let p_rec = get_record(vault.db_connection(), p.id).unwrap().unwrap();
    assert!(p_rec.deleted, "Project record must be deleted = 1");
    assert!(p_rec.blob.is_none(), "Project blob must be NULL");

    for env_id in [env_1, env_2, env_3] {
        let e_rec = get_record(vault.db_connection(), env_id).unwrap().unwrap();
        assert!(e_rec.deleted, "Environment record must be deleted = 1");
        assert!(e_rec.blob.is_none(), "Environment blob must be NULL");
    }

    for s_id in secret_ids {
        let s_rec = get_record(vault.db_connection(), s_id).unwrap().unwrap();
        assert!(s_rec.deleted, "Secret record must be deleted = 1");
        assert!(s_rec.blob.is_none(), "Secret blob must be NULL");
    }

    vault.lock();
}

#[test]
fn create_project_with_default_environments() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut vault = Vault::create(dir.path(), "device-1", &keystore).unwrap();

    let p = vault.create_project("MyProject", &[]).unwrap();
    assert_eq!(p.environments.len(), 3);
    assert_eq!(p.environments[0].name, "Development");
    assert_eq!(p.environments[0].position, 0);
    assert_eq!(p.environments[1].name, "Staging");
    assert_eq!(p.environments[1].position, 1);
    assert_eq!(p.environments[2].name, "Production");
    assert_eq!(p.environments[2].position, 2);

    vault.lock();
}

#[test]
fn project_name_validation_and_limits() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut vault = Vault::create(dir.path(), "device-1", &keystore).unwrap();

    // Empty name rejected
    assert!(matches!(
        vault.create_project("   ", &[]),
        Err(Error::Invalid { field: "name", .. })
    ));

    // > 64 chars rejected
    let long_name = "x".repeat(65);
    assert!(matches!(
        vault.create_project(&long_name, &[]),
        Err(Error::Invalid { field: "name", .. })
    ));

    // More than 12 environments rejected
    let thirteen_envs: Vec<String> = (1..=13).map(|i| format!("env_{i}")).collect();
    assert!(matches!(
        vault.create_project("ValidName", &thirteen_envs),
        Err(Error::Invalid {
            field: "environments",
            ..
        })
    ));

    vault.lock();
}
