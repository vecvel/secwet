//! Environments CRUD and invariants acceptance tests.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §6, §7 (F4), §11.2, and `ORIGINAL_REQUEST.md`.

use secwet_core::keys::MemoryStore;
use secwet_core::records::get_record;
use secwet_core::{Error, SecretDraft, SecretKind, Vault};
use tempfile::tempdir;

/// Acceptance test: `cannot_delete_last_environment`
///
/// Verifies:
/// 1. Create project with default environments.
/// 2. Delete two environments so only one remains.
/// 3. Call `Vault::delete_environment` on the final environment.
/// 4. Call fails with `Err(Error::LastEnvironment)`.
/// 5. The environment and its secrets remain intact.
#[test]
fn cannot_delete_last_environment() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut vault = Vault::create(dir.path(), "device-1", &keystore).unwrap();

    // 1. Create project with 3 default environments: Development, Staging, Production
    let p = vault.create_project("SingleEnvProject", &[]).unwrap();
    assert_eq!(p.environments.len(), 3);

    let dev_id = p.environments[0].id;
    let stg_id = p.environments[1].id;
    let prod_id = p.environments[2].id;

    // Add a secret under dev_id
    let s_meta = vault
        .create_secret(SecretDraft::new(
            p.id,
            dev_id,
            "DEV_PORT",
            SecretKind::EnvVar,
            "3000",
            None,
        ))
        .unwrap();

    // 2. Delete Staging and Production
    vault
        .delete_environment(stg_id)
        .expect("Delete Staging should succeed");
    vault
        .delete_environment(prod_id)
        .expect("Delete Production should succeed");

    // Verify only Development remains
    let updated_projects = vault.list_projects().unwrap();
    let current_proj = updated_projects.iter().find(|pr| pr.id == p.id).unwrap();
    assert_eq!(current_proj.environments.len(), 1);
    assert_eq!(current_proj.environments[0].id, dev_id);

    // 3. Attempt to delete the last remaining environment
    let last_err = vault.delete_environment(dev_id);
    match last_err {
        Err(Error::LastEnvironment) => {}
        other => panic!("Expected Error::LastEnvironment, got: {:?}", other),
    }

    // 4. Verify Development and its secret are still intact
    let dev_rec = get_record(vault.db_connection(), dev_id).unwrap().unwrap();
    assert!(
        !dev_rec.deleted,
        "Last environment must NOT be marked deleted"
    );
    assert!(
        dev_rec.blob.is_some(),
        "Last environment blob must still be present"
    );

    let s_rec = get_record(vault.db_connection(), s_meta.id)
        .unwrap()
        .unwrap();
    assert!(
        !s_rec.deleted,
        "Secret under last environment must NOT be marked deleted"
    );
    assert!(s_rec.blob.is_some(), "Secret blob must still be present");

    vault.lock();
}

#[test]
fn environment_name_unique_per_project() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut vault = Vault::create(dir.path(), "device-1", &keystore).unwrap();

    let p1 = vault.create_project("ProjectAlpha", &[]).unwrap();
    let p2 = vault.create_project("ProjectBeta", &[]).unwrap();

    // In ProjectAlpha, "Development" exists. Attempting to add "development" or "DEVELOPMENT" fails
    assert!(matches!(
        vault.add_environment(p1.id, "development"),
        Err(Error::Duplicate { field: "name" })
    ));

    // Adding "development" to ProjectBeta (different project) is permitted
    // Note: ProjectBeta already has "Development" by default, so let's add a custom name
    let alpha_qa = vault.add_environment(p1.id, "QA-Env").unwrap();
    assert_eq!(alpha_qa.name, "QA-Env");

    // QA-Env in ProjectBeta is completely allowed because environments are scoped per project
    let beta_qa = vault.add_environment(p2.id, "QA-Env").unwrap();
    assert_eq!(beta_qa.name, "QA-Env");

    // Renaming alpha_qa to "Development" fails due to collision within ProjectAlpha
    assert!(matches!(
        vault.rename_environment(alpha_qa.id, "development"),
        Err(Error::Duplicate { field: "name" })
    ));

    // Renaming alpha_qa to "QA-Staging" succeeds
    vault.rename_environment(alpha_qa.id, "QA-Staging").unwrap();

    vault.lock();
}

#[test]
fn delete_environment_deletes_its_secrets() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut vault = Vault::create(dir.path(), "device-1", &keystore).unwrap();

    let p = vault.create_project("App", &[]).unwrap();
    let env_to_delete = p.environments[0].id; // Development
    let remaining_env = p.environments[1].id; // Staging

    let s1 = vault
        .create_secret(SecretDraft::new(
            p.id,
            env_to_delete,
            "DEV_KEY",
            SecretKind::ApiKey,
            "dev_key_val",
            None,
        ))
        .unwrap();

    let s2 = vault
        .create_secret(SecretDraft::new(
            p.id,
            remaining_env,
            "STG_KEY",
            SecretKind::ApiKey,
            "stg_key_val",
            None,
        ))
        .unwrap();

    // Delete Development
    vault.delete_environment(env_to_delete).unwrap();

    // Verify s1 is deleted with blob = NULL
    let s1_rec = get_record(vault.db_connection(), s1.id).unwrap().unwrap();
    assert!(s1_rec.deleted);
    assert!(s1_rec.blob.is_none());

    // Verify s2 is intact
    let s2_rec = get_record(vault.db_connection(), s2.id).unwrap().unwrap();
    assert!(!s2_rec.deleted);
    assert!(s2_rec.blob.is_some());

    vault.lock();
}
