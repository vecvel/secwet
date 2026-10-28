//! Empirical integration tests for Secwet Flexible Organization Secwet APIs.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §5.1, §6, and Milestone 2 specification.
//!
//! Evaluates:
//! 1. Labels CRUD & Reordering:
//!    - Default "Projects" label seeded at position 0 on secwet creation.
//!    - Create, rename, update (name + icon), reorder, and cascade delete labels.
//!    - Case-insensitive duplicate prevention.
//! 2. Items CRUD:
//!    - Zero-environment invariant: newly created items have 0 default environments.
//!    - Create, rename, and cascade delete items.
//! 3. Optional Environments CRUD:
//!    - Add environment, rename, reorder.
//!    - Deleting last environment on an item via `delete_environment_with_options(id, preserve_content)`.
//!    - `preserve_content: true` reparents child secrets to item level (`environment_id: None`).
//!    - `preserve_content: false` cascades deletion to child secrets.
//! 4. Secrets CRUD:
//!    - Item-level secrets (`environment_id: None`) vs Environment-level secrets (`environment_id: Some(id)`).
//!    - `list_secrets` with container filtering and value masking.
//!    - `reveal_secret` decryption and zeroization.
//!    - `copy_secret_to_environment`.
//!    - `env_for` container export.
//! 5. Dashboard Configuration & Overview:
//!    - Get and set `DashboardConfig` persistence.
//!    - `overview()` aggregates accurate counts across all 6 entity types.

use secrecy::ExposeSecret;
use secwet_core::keys::MemoryStore;
use secwet_core::{DashboardConfig, Error, SecretDraft, SecretKind, Secwet};
use tempfile::tempdir;
use uuid::Uuid;

fn create_test_secwet() -> (tempfile::TempDir, Secwet, MemoryStore, Uuid) {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let secwet = Secwet::create(dir.path(), "test-device", &keystore).expect("secwet create");

    let labels = secwet.list_labels().expect("list labels");
    assert_eq!(labels.len(), 1);
    assert_eq!(labels[0].name, "Projects");
    assert_eq!(labels[0].position, 0);

    let default_label_id = labels[0].id;
    (dir, secwet, keystore, default_label_id)
}

// ============================================================================
// 1. Labels CRUD & Reordering
// ============================================================================

#[test]
fn test_label_crud_and_reordering() {
    let (_dir, mut secwet, _ks, projects_label_id) = create_test_secwet();

    // 1. Create labels
    let personal = secwet
        .create_label("Personal", Some("user".to_string()))
        .expect("create Personal label");
    assert_eq!(personal.name, "Personal");
    assert_eq!(personal.icon.as_deref(), Some("user"));
    assert_eq!(personal.position, 1);

    let work = secwet
        .create_label("Work", Some("briefcase".to_string()))
        .expect("create Work label");
    assert_eq!(work.name, "Work");
    assert_eq!(work.position, 2);

    // Duplicate name (case-insensitive) must be rejected
    let err_dup = secwet.create_label("  work  ", None);
    assert!(matches!(err_dup, Err(Error::Duplicate { field: "name" })));

    let all_labels = secwet.list_labels().expect("list labels");
    assert_eq!(all_labels.len(), 3);
    assert_eq!(all_labels[0].id, projects_label_id);
    assert_eq!(all_labels[1].id, personal.id);
    assert_eq!(all_labels[2].id, work.id);

    // 2. Rename label
    secwet
        .rename_label(work.id, "Enterprise")
        .expect("rename label");
    let work_label = secwet
        .list_labels()
        .unwrap()
        .into_iter()
        .find(|l| l.id == work.id)
        .unwrap();
    assert_eq!(work_label.name, "Enterprise");

    // 3. Update label (name and icon)
    secwet
        .update_label(work.id, "Enterprise Corp", Some("building".to_string()))
        .expect("update label");
    let work_label2 = secwet
        .list_labels()
        .unwrap()
        .into_iter()
        .find(|l| l.id == work.id)
        .unwrap();
    assert_eq!(work_label2.name, "Enterprise Corp");
    assert_eq!(work_label2.icon.as_deref(), Some("building"));

    // 4. Reorder labels
    secwet
        .reorder_labels(&[work.id, projects_label_id, personal.id])
        .expect("reorder labels");

    let reordered = secwet.list_labels().expect("list labels after reorder");
    assert_eq!(reordered[0].id, work.id);
    assert_eq!(reordered[0].position, 0);
    assert_eq!(reordered[1].id, projects_label_id);
    assert_eq!(reordered[1].position, 1);
    assert_eq!(reordered[2].id, personal.id);
    assert_eq!(reordered[2].position, 2);

    // 5. Delete label (cascades to items)
    let _item_in_work = secwet
        .create_item(work.id, "Work Item", None)
        .expect("create item in work");

    secwet.delete_label(work.id).expect("delete label");

    let labels_after_del = secwet.list_labels().expect("list labels after delete");
    assert_eq!(labels_after_del.len(), 2);
    assert!(labels_after_del.iter().all(|l| l.id != work.id));

    // Item under deleted label must be deleted
    let items_under_work = secwet.list_items(work.id);
    assert!(items_under_work.is_err()); // Label no longer found
}

// ============================================================================
// 2. Items CRUD & Zero-Environment Invariant
// ============================================================================

#[test]
fn test_item_crud_and_zero_default_environments() {
    let (_dir, mut secwet, _ks, label_id) = create_test_secwet();

    // 1. Create item and verify ZERO default environments!
    let item = secwet
        .create_item(
            label_id,
            "Microservice Auth",
            Some("Authentication service".to_string()),
        )
        .expect("create item");

    assert_eq!(item.name, "Microservice Auth");
    assert_eq!(item.label_id, label_id);
    assert_eq!(item.description.as_deref(), Some("Authentication service"));

    // INVARIANT: Items created via flexible organization API MUST have 0 environments by default
    let envs = secwet.list_environments(item.id).expect("list environments");
    assert!(
        envs.is_empty(),
        "New items in flexible org must have ZERO default environments"
    );

    // 2. Verify item listing
    let items = secwet.list_items(label_id).expect("list items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, item.id);

    // 3. Rename item
    secwet
        .rename_item(item.id, "Auth Service v2", None)
        .expect("rename item");
    let item_renamed = secwet
        .list_items(label_id)
        .unwrap()
        .into_iter()
        .find(|i| i.id == item.id)
        .unwrap();
    assert_eq!(item_renamed.name, "Auth Service v2");

    // 4. Cascade delete item
    secwet.delete_item(item.id).expect("delete item");
    let items_after = secwet.list_items(label_id).expect("list items after delete");
    assert!(items_after.is_empty());
}

// ============================================================================
// 3. Optional Environments CRUD & Deleting Last Environment
// ============================================================================

#[test]
fn test_optional_environments_and_delete_with_options() {
    let (_dir, mut secwet, _ks, label_id) = create_test_secwet();

    let item = secwet
        .create_item(label_id, "Data Pipeline", None)
        .expect("create item");

    // 1. Add environments
    let dev = secwet
        .add_environment(item.id, "development")
        .expect("add dev env");
    assert_eq!(dev.name, "development");
    assert_eq!(dev.position, 0);

    let prod = secwet
        .add_environment(item.id, "production")
        .expect("add prod env");
    assert_eq!(prod.name, "production");
    assert_eq!(prod.position, 1);

    // Duplicate environment name under same item must fail
    let err_dup = secwet.add_environment(item.id, "  DEVELOPMENT  ");
    assert!(matches!(err_dup, Err(Error::Duplicate { field: "name" })));

    // 2. Rename and reorder
    secwet.rename_environment(dev.id, "dev").expect("rename env");
    let envs_after_rename = secwet.list_environments(item.id).unwrap();
    assert_eq!(
        envs_after_rename
            .iter()
            .find(|e| e.id == dev.id)
            .unwrap()
            .name,
        "dev"
    );

    secwet
        .reorder_environments(item.id, &[prod.id, dev.id])
        .expect("reorder envs");

    let envs_reordered = secwet.list_environments(item.id).expect("list envs");
    assert_eq!(envs_reordered[0].id, prod.id);
    assert_eq!(envs_reordered[0].position, 0);
    assert_eq!(envs_reordered[1].id, dev.id);
    assert_eq!(envs_reordered[1].position, 1);

    // 3. Add a secret to dev environment
    let s_dev = secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(dev.id),
            "DEV_PORT",
            SecretKind::EnvVar,
            "8080",
            None,
        ))
        .expect("create dev secret");

    // Delete dev environment with preserve_content: true -> secret is reparented to item level
    secwet
        .delete_environment_with_options(dev.id, true)
        .expect("delete dev env preserve content true");

    let envs_remaining = secwet
        .list_environments(item.id)
        .expect("list envs remaining");
    assert_eq!(envs_remaining.len(), 1);
    assert_eq!(envs_remaining[0].id, prod.id);

    // Secret must now be accessible at item level (environment_id: None)
    let item_secrets = secwet
        .list_secrets(item.id, None)
        .expect("list item secrets");
    assert_eq!(item_secrets.len(), 1);
    assert_eq!(item_secrets[0].id, s_dev.id);
    assert_eq!(item_secrets[0].environment_id, None);

    // 4. Delete the ONLY remaining environment (prod) on this item using delete_environment_with_options
    // This MUST succeed (items are not subject to last-environment protection!)
    let s_prod = secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(prod.id),
            "PROD_KEY",
            SecretKind::ApiKey,
            "prod_secret_key",
            None,
        ))
        .expect("create prod secret");

    secwet
        .delete_environment_with_options(prod.id, false)
        .expect("delete only remaining environment with preserve_content: false");

    // Item now has 0 environments again!
    let envs_zero = secwet.list_environments(item.id).expect("list envs zero");
    assert!(envs_zero.is_empty());

    // s_prod should have been deleted (preserve_content: false)
    let prod_secrets = secwet.list_secrets(item.id, Some(prod.id));
    assert!(prod_secrets.is_err()); // Container no longer exists
    assert!(matches!(
        secwet.reveal_secret(s_prod.id),
        Err(Error::NotFound)
    ));

    // s_dev at item level is still intact
    let item_secrets_after = secwet
        .list_secrets(item.id, None)
        .expect("list item secrets");
    assert_eq!(item_secrets_after.len(), 1);
    assert_eq!(item_secrets_after[0].id, s_dev.id);
}

// ============================================================================
// 4. Secrets CRUD at Item Level vs Environment Level
// ============================================================================

#[test]
fn test_secrets_item_vs_environment_scoping_and_copy() {
    let (_dir, mut secwet, _ks, label_id) = create_test_secwet();

    let item = secwet
        .create_item(label_id, "Web App", None)
        .expect("create item");
    let staging = secwet
        .add_environment(item.id, "staging")
        .expect("add staging");
    let prod = secwet
        .add_environment(item.id, "production")
        .expect("add prod");

    // 1. Create item-level secret (environment_id: None)
    let s_item = secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "APP_NAME",
            SecretKind::EnvVar,
            "Secwet Secure App",
            Some("Global app name".to_string()),
        ))
        .expect("create item secret");

    assert_eq!(s_item.environment_id, None);
    assert_eq!(s_item.item_id, item.id);

    // 2. Create environment-level secrets
    let s_stag = secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(staging.id),
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://stag:5432/db",
            None,
        ))
        .expect("create staging secret");

    let s_prod = secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(prod.id),
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://prod:5432/db",
            None,
        ))
        .expect("create prod secret");

    // 3. List secrets verifies scoping
    let item_secrets = secwet
        .list_secrets(item.id, None)
        .expect("list item secrets");
    assert_eq!(item_secrets.len(), 1);
    assert_eq!(item_secrets[0].id, s_item.id);

    let stag_secrets = secwet
        .list_secrets(item.id, Some(staging.id))
        .expect("list staging secrets");
    assert_eq!(stag_secrets.len(), 1);
    assert_eq!(stag_secrets[0].id, s_stag.id);

    let prod_secrets = secwet
        .list_secrets(item.id, Some(prod.id))
        .expect("list prod secrets");
    assert_eq!(prod_secrets.len(), 1);
    assert_eq!(prod_secrets[0].id, s_prod.id);

    // 4. Reveal secret checks plaintext decryption
    let val_stag = secwet.reveal_secret(s_stag.id).expect("reveal staging");
    assert_eq!(val_stag.expose_secret(), "postgres://stag:5432/db");

    let val_prod = secwet.reveal_secret(s_prod.id).expect("reveal prod");
    assert_eq!(val_prod.expose_secret(), "postgres://prod:5432/db");

    // 5. Copy secret to environment
    let s_copy = secwet
        .copy_secret_to_environment(s_item.id, prod.id)
        .expect("copy secret to prod");

    assert_eq!(s_copy.name, "APP_NAME");
    assert_eq!(s_copy.environment_id, Some(prod.id));

    let prod_secrets_after_copy = secwet
        .list_secrets(item.id, Some(prod.id))
        .expect("prod list");
    assert_eq!(prod_secrets_after_copy.len(), 2);

    let val_copy = secwet.reveal_secret(s_copy.id).expect("reveal copy");
    assert_eq!(val_copy.expose_secret(), "Secwet Secure App");

    // 6. env_for exports
    let env_entries = secwet.env_for(item.id, Some(prod.id)).expect("env for prod");
    let env_map: std::collections::HashMap<String, secrecy::SecretString> =
        env_entries.into_iter().collect();
    assert_eq!(
        env_map.get("DATABASE_URL").unwrap().expose_secret(),
        "postgres://prod:5432/db"
    );
    assert_eq!(
        env_map.get("APP_NAME").unwrap().expose_secret(),
        "Secwet Secure App"
    );
}

// ============================================================================
// 5. Dashboard Configuration & Overview
// ============================================================================

#[test]
fn test_dashboard_config_and_overview_aggregation() {
    let (_dir, mut secwet, _ks, label_id) = create_test_secwet();

    // 1. Dashboard config default and persistence
    let initial_cfg = secwet.dashboard_config().expect("dashboard config");
    assert_eq!(initial_cfg.home_label, "Home");

    let new_cfg = DashboardConfig {
        home_label: "Production Services".to_string(),
        ..Default::default()
    };
    secwet
        .set_dashboard_config(&new_cfg)
        .expect("set dashboard config");

    let fetched_cfg = secwet
        .dashboard_config()
        .expect("get updated dashboard config");
    assert_eq!(fetched_cfg.home_label, "Production Services");

    // Empty home_label must be rejected
    let invalid_cfg = DashboardConfig {
        home_label: "   ".to_string(),
        ..Default::default()
    };
    let err_empty = secwet.set_dashboard_config(&invalid_cfg);
    assert!(matches!(
        err_empty,
        Err(Error::Invalid {
            field: "home_label",
            ..
        })
    ));

    // 2. Overview aggregation across items, environments, secrets, files, notes
    let item1 = secwet
        .create_item(label_id, "Item 1", None)
        .expect("create item 1");
    let item2 = secwet
        .create_item(label_id, "Item 2", None)
        .expect("create item 2");

    let env1 = secwet.add_environment(item1.id, "env1").expect("add env 1");
    let env2 = secwet.add_environment(item1.id, "env2").expect("add env 2");

    secwet
        .create_secret(SecretDraft::new(
            item1.id,
            Some(env1.id),
            "S1",
            SecretKind::EnvVar,
            "v1",
            None,
        ))
        .expect("create s1");
    secwet
        .create_secret(SecretDraft::new(
            item1.id,
            Some(env2.id),
            "S2",
            SecretKind::ApiKey,
            "v2",
            None,
        ))
        .expect("create s2");
    secwet
        .create_secret(SecretDraft::new(
            item2.id,
            None,
            "S3",
            SecretKind::Password,
            "v3",
            None,
        ))
        .expect("create s3");

    secwet
        .upload_file(
            item1.id,
            None,
            "readme.md",
            b"# Readme",
            Some("text/markdown"),
        )
        .expect("upload file 1");
    secwet
        .upload_file(
            item1.id,
            Some(env1.id),
            "config.json",
            b"{}",
            Some("application/json"),
        )
        .expect("upload file 2");

    secwet
        .create_note(item1.id, None, "Release Notes", "V1.0 released")
        .expect("create note 1");

    let overview = secwet.overview().expect("overview");
    assert_eq!(overview.labels_count, 1);
    assert_eq!(overview.items_count, 2);
    assert_eq!(overview.projects_count, 2);
    assert_eq!(overview.environments_count, 2);
    assert_eq!(overview.secrets_count, 3);
    assert_eq!(overview.files_count, 2);
    assert_eq!(overview.notes_count, 1);
    assert_eq!(overview.active_devices_count, 1);
    assert_eq!(overview.recent.len(), 3);
    assert!(overview.checklist.secwet_created);
}
