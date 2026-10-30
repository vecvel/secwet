//! Integration test suite for Secwet Tauri backend commands.
//!
//! Validates:
//! 1. All commands enforce `locked` when locked.
//! 2. Full lifecycle (status, create, unlock, lock).
//! 3. Labels CRUD and reordering.
//! 4. Items CRUD with 0 default environments.
//! 5. Environments CRUD with preserve_content options.
//! 6. Secrets CRUD (item-level and environment-level), list_secrets isolation, reveal on demand.
//! 7. Encrypted files upload, download, rename, list, and delete.
//! 8. Rich-text notes CRUD, note_copy_plain with plain text extraction, and clipboard_copy_text.
//! 9. Dashboard configuration get/set.
//! 10. Settings get/set roundtrip.
//! 11. Backward compatibility projects commands.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use secwet_core::keys::MemoryStore;
use secwet_core::model::{DashboardConfig, SecretKind};
use secwet_app::clipboard::ClipboardPort;
use secwet_app::commands::{ExportSummaryDto, NoteDraftDto, NoteUpdateDto, RecoveryStatusDto, SecretDraftDto, SettingsPatchDto};
use secwet_app::state::{AppState, SecwetStatusDto};
use tempfile::tempdir;
use uuid::Uuid;

#[derive(Default)]
struct TestMockClipboard {
    data: Mutex<Option<String>>,
}

impl ClipboardPort for TestMockClipboard {
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

#[test]
fn test_commands_enforce_locked_when_not_unlocked() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);
    let mock_cb = Arc::new(TestMockClipboard::default());
    let dummy_id = Uuid::new_v4();

    // 1. Status is Uninitialized, not locked yet
    let status = state.secwet_status().unwrap();
    assert_eq!(status, SecwetStatusDto::Uninitialized);

    // 2. All data commands return locked
    // Labels
    assert_eq!(state.labels_list().unwrap_err().code, "locked");
    assert_eq!(state.label_create("L".into(), None).unwrap_err().code, "locked");
    assert_eq!(state.label_rename(dummy_id, "L".into(), None).unwrap_err().code, "locked");
    assert_eq!(state.label_delete(dummy_id).unwrap_err().code, "locked");
    assert_eq!(state.label_reorder(vec![dummy_id]).unwrap_err().code, "locked");

    // Items
    assert_eq!(state.items_list(None).unwrap_err().code, "locked");
    assert_eq!(state.item_create(dummy_id, "I".into(), None).unwrap_err().code, "locked");
    assert_eq!(state.item_rename(dummy_id, "I".into(), None).unwrap_err().code, "locked");
    assert_eq!(state.item_delete(dummy_id).unwrap_err().code, "locked");

    // Environments
    assert_eq!(state.environments_list(dummy_id).unwrap_err().code, "locked");
    assert_eq!(state.environment_add(dummy_id, "E".into()).unwrap_err().code, "locked");
    assert_eq!(state.environment_rename(dummy_id, "E".into()).unwrap_err().code, "locked");
    assert_eq!(state.environment_delete(dummy_id, None).unwrap_err().code, "locked");

    // Secrets
    assert_eq!(state.secrets_list(Some(dummy_id), None).unwrap_err().code, "locked");
    assert_eq!(state.secret_reveal(dummy_id).unwrap_err().code, "locked");
    assert_eq!(state.secret_copy(Arc::clone(&mock_cb), dummy_id).unwrap_err().code, "locked");

    let draft = SecretDraftDto {
        item_id: Some(dummy_id),
        project_id: None,
        environment_id: None,
        name: "TEST".into(),
        kind: SecretKind::ApiKey,
        value: "secret".into(),
        note: None,
    };
    assert_eq!(state.secret_create(draft.clone()).unwrap_err().code, "locked");
    assert_eq!(state.secret_update(dummy_id, draft).unwrap_err().code, "locked");
    assert_eq!(state.secret_delete(dummy_id).unwrap_err().code, "locked");
    assert_eq!(state.secret_copy_to_environment(dummy_id, Some(dummy_id)).unwrap_err().code, "locked");

    // Files
    assert_eq!(state.files_list(dummy_id, None).unwrap_err().code, "locked");
    assert_eq!(state.file_upload(dummy_id, None, "f.txt".into(), None, vec![1, 2]).unwrap_err().code, "locked");
    assert_eq!(state.file_download(dummy_id).unwrap_err().code, "locked");
    assert_eq!(state.file_rename(dummy_id, "g.txt".into()).unwrap_err().code, "locked");
    assert_eq!(state.file_delete(dummy_id).unwrap_err().code, "locked");

    // Notes
    assert_eq!(state.notes_list(dummy_id, None).unwrap_err().code, "locked");
    assert_eq!(state.note_get(dummy_id).unwrap_err().code, "locked");
    let note_draft = NoteDraftDto {
        item_id: dummy_id,
        environment_id: None,
        title: "T".into(),
        content: "<p>body</p>".into(),
    };
    assert_eq!(state.note_create(note_draft).unwrap_err().code, "locked");
    assert_eq!(state.note_update(dummy_id, NoteUpdateDto { title: None, content: None }).unwrap_err().code, "locked");
    assert_eq!(state.note_delete(dummy_id).unwrap_err().code, "locked");
    assert_eq!(state.note_copy_plain(Arc::clone(&mock_cb), dummy_id).unwrap_err().code, "locked");
    assert_eq!(state.clipboard_copy_text(Arc::clone(&mock_cb), "some text".into()).unwrap_err().code, "locked");

    // Dashboard & Overview
    assert_eq!(state.overview().unwrap_err().code, "locked");
    assert_eq!(state.dashboard_get().unwrap_err().code, "locked");
    assert_eq!(state.dashboard_set(DashboardConfig::default()).unwrap_err().code, "locked");

    // Settings
    assert_eq!(state.settings_get().unwrap_err().code, "locked");
    let patch = SettingsPatchDto {
        theme: Some("dark".into()),
        lock_timeout_minutes: Some(30),
        device_name: Some("dev".into()),
    };
    assert_eq!(state.settings_set(patch).unwrap_err().code, "locked");

    // Compatibility (Projects)
    assert_eq!(state.projects_list().unwrap_err().code, "locked");
    assert_eq!(state.project_create("P".into(), vec![]).unwrap_err().code, "locked");
    assert_eq!(state.project_rename(dummy_id, "P".into()).unwrap_err().code, "locked");
    assert_eq!(state.project_delete(dummy_id).unwrap_err().code, "locked");
}

#[tokio::test]
async fn test_full_lifecycle_and_crud_workflow() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);
    let mock_cb = Arc::new(TestMockClipboard::default());

    // 1. Initial status
    assert_eq!(state.secwet_status().unwrap(), SecwetStatusDto::Uninitialized);

    // 2. Create secwet
    let status = state.secwet_create(Some("MacBook-Dev".into())).unwrap();
    let secwet_id = match status {
        SecwetStatusDto::Unlocked { secwet_id } => secwet_id,
        _ => panic!("Expected Unlocked status after create"),
    };

    // Double create fails cleanly
    let dup_err = state.secwet_create(None).unwrap_err();
    assert_eq!(dup_err.code, "already_initialized");

    // Status is unlocked
    assert_eq!(state.secwet_status().unwrap(), SecwetStatusDto::Unlocked { secwet_id });

    // 3. Labels CRUD and reordering
    let label1 = state.label_create("Infrastructure".into(), Some("server".into())).unwrap();
    assert_eq!(label1.name, "Infrastructure");
    assert_eq!(label1.icon.as_deref(), Some("server"));

    let label2 = state.label_create("Mobile Apps".into(), None).unwrap();
    assert_eq!(label2.name, "Mobile Apps");

    state.label_rename(label1.id, "Cloud Infra".into(), Some("cloud".into())).unwrap();
    let labels = state.labels_list().unwrap();
    assert!(labels.iter().any(|l| l.name == "Cloud Infra" && l.icon.as_deref() == Some("cloud")));
    let default_label_id = labels.iter().find(|l| l.id != label1.id && l.id != label2.id).unwrap().id;

    state.label_reorder(vec![label2.id, label1.id, default_label_id]).unwrap();
    let reordered = state.labels_list().unwrap();
    assert_eq!(reordered[0].id, label2.id);
    assert_eq!(reordered[1].id, label1.id);

    // 4. Items CRUD (zero default environments)
    let item1 = state.item_create(label1.id, "payments-service".into(), Some("Backend API".into())).unwrap();
    assert_eq!(item1.name, "payments-service");
    assert_eq!(item1.description.as_deref(), Some("Backend API"));

    let envs0 = state.environments_list(item1.id).unwrap();
    assert_eq!(envs0.len(), 0, "Item must be created with 0 default environments");

    let items = state.items_list(Some(label1.id)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, item1.id);

    state.item_rename(item1.id, "payments-api".into(), Some("Updated API".into())).unwrap();

    // 5. Item-Level Secrets CRUD (no environments needed)
    let item_secret_draft = SecretDraftDto {
        item_id: Some(item1.id),
        project_id: None,
        environment_id: None,
        name: "GLOBAL_API_KEY".into(),
        kind: SecretKind::ApiKey,
        value: "sk_live_item_level_secret_value".into(),
        note: Some("Item level secret".into()),
    };
    let created_item_sec = state.secret_create(item_secret_draft).unwrap();
    assert_eq!(created_item_sec.name, "GLOBAL_API_KEY");
    assert_eq!(created_item_sec.value_tail, "alue");

    let item_secrets = state.secrets_list(Some(item1.id), None).unwrap();
    assert_eq!(item_secrets.len(), 1);
    assert_eq!(item_secrets[0].id, created_item_sec.id);

    // Reveal item-level secret
    let revealed = state.secret_reveal(created_item_sec.id).unwrap();
    assert_eq!(revealed, "sk_live_item_level_secret_value");

    // 6. Environments within Item
    let prod_env = state.environment_add(item1.id, "Production".into()).unwrap();
    assert_eq!(prod_env.name, "Production");

    let dev_env = state.environment_add(item1.id, "Development".into()).unwrap();
    assert_eq!(dev_env.name, "Development");

    state.environment_rename(dev_env.id, "Dev".into()).unwrap();

    // Environment-scoped secret
    let env_draft = SecretDraftDto {
        item_id: Some(item1.id),
        project_id: None,
        environment_id: Some(prod_env.id),
        name: "DATABASE_URL".into(),
        kind: SecretKind::EnvVar,
        value: "postgres://user:pw@prod.db:5432/main".into(),
        note: None,
    };
    let created_env_sec = state.secret_create(env_draft).unwrap();
    assert_eq!(created_env_sec.name, "DATABASE_URL");

    // Copy secret to environment
    let copied_sec = state.secret_copy_to_environment(created_env_sec.id, Some(dev_env.id)).unwrap();
    assert_eq!(copied_sec.name, "DATABASE_URL");
    let dev_secrets = state.secrets_list(Some(item1.id), Some(dev_env.id)).unwrap();
    assert_eq!(dev_secrets.len(), 1);

    // 7. Encrypted Files CRUD
    let test_bytes = b"Hello, encrypted file storage in Tauri!".to_vec();
    let file_meta = state.file_upload(item1.id,
        Some(prod_env.id),
        "readme.txt".into(),
        Some("text/plain".into()),
        test_bytes.clone(),
    )
    .unwrap();
    assert_eq!(file_meta.name, "readme.txt");
    assert_eq!(file_meta.size_bytes, test_bytes.len() as u64);

    let files = state.files_list(item1.id, Some(prod_env.id)).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].id, file_meta.id);

    let downloaded = state.file_download(file_meta.id).unwrap();
    assert_eq!(downloaded.bytes, test_bytes);
    assert_eq!(downloaded.meta.name, "readme.txt");

    let renamed_file = state.file_rename(file_meta.id, "README.md".into()).unwrap();
    assert_eq!(renamed_file.name, "README.md");

    state.file_delete(file_meta.id).unwrap();
    assert_eq!(state.files_list(item1.id, Some(prod_env.id)).unwrap().len(), 0);

    // 8. Rich-Text Notes CRUD & Plain Text Copying
    let note_draft = NoteDraftDto {
        item_id: item1.id,
        environment_id: None,
        title: "Deployment Runbook".into(),
        content: "<h2>Steps</h2><p>Run <b>deploy.sh</b></p><ul><li>Step 1</li><li>Step 2</li></ul>".into(),
    };
    let note = state.note_create(note_draft).unwrap();
    assert_eq!(note.title, "Deployment Runbook");

    let notes = state.notes_list(item1.id, None).unwrap();
    assert_eq!(notes.len(), 1);

    let fetched_note = state.note_get(note.id).unwrap();
    assert_eq!(fetched_note.title, "Deployment Runbook");

    // Copy note plain text
    state.note_copy_plain(Arc::clone(&mock_cb), note.id).unwrap();
    let copied_note_text = mock_cb.read_text().unwrap();
    assert!(copied_note_text.contains("Steps"));
    assert!(copied_note_text.contains("Run deploy.sh"));
    assert!(copied_note_text.contains("• Step 1"));

    // Copy unsaved text directly
    state.clipboard_copy_text(Arc::clone(&mock_cb), "<p>Unsaved <b>snippet</b></p>".into()).unwrap();
    assert_eq!(mock_cb.read_text().unwrap(), "Unsaved snippet");

    let updated_note = state.note_update(note.id,
        NoteUpdateDto {
            title: Some("Updated Runbook".into()),
            content: Some("<p>Single paragraph</p>".into()),
        },
    )
    .unwrap();
    assert_eq!(updated_note.title, "Updated Runbook");

    state.note_delete(note.id).unwrap();
    assert_eq!(state.notes_list(item1.id, None).unwrap().len(), 0);

    // 9. Dashboard Configuration Get / Set
    let dash = state.dashboard_get().unwrap();
    assert_eq!(dash.home_label, "Overview");

    let custom_dash = DashboardConfig {
        home_label: "Executive Dashboard".into(),
        ..DashboardConfig::default()
    };
    state.dashboard_set(custom_dash).unwrap();
    let updated_dash = state.dashboard_get().unwrap();
    assert_eq!(updated_dash.home_label, "Executive Dashboard");

    // 10. Settings Get / Set
    let initial_settings = state.settings_get().unwrap();
    assert_eq!(initial_settings.theme, "system");

    let patch = SettingsPatchDto {
        theme: Some("dark".into()),
        lock_timeout_minutes: Some(30),
        device_name: Some("Workstation-Linux".into()),
    };
    let updated_settings = state.settings_set(patch).unwrap();
    assert_eq!(updated_settings.theme, "dark");
    assert_eq!(updated_settings.device_name, "Workstation-Linux");

    // 11. Backward Compatibility (Projects)
    let projects = state.projects_list().unwrap();
    assert!(!projects.is_empty());

    let legacy_proj = state.project_create("Legacy Service".into(), vec!["prod".into()]).unwrap();
    assert_eq!(legacy_proj.name, "Legacy Service");

    state.project_rename(legacy_proj.id, "Legacy Renamed".into()).unwrap();
    state.project_delete(legacy_proj.id).unwrap();

    // 12. Delete Environment with Options
    // Delete dev_env
    state.environment_delete(dev_env.id, Some(false)).unwrap();

    // 13. Lock / Unlock cycle
    state.secwet_lock().unwrap();
    assert_eq!(state.secwet_status().unwrap(), SecwetStatusDto::Locked { secwet_id });

    state.secwet_unlock().unwrap();
    assert_eq!(state.secwet_status().unwrap(), SecwetStatusDto::Unlocked { secwet_id });

    // Verify settings and dashboard persist after unlock
    let restored_dash = state.dashboard_get().unwrap();
    assert_eq!(restored_dash.home_label, "Executive Dashboard");

    state.secwet_lock().unwrap();
}

#[tokio::test]
async fn test_clipboard_copy_auto_clear_timing_and_foreign_content() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let mut state = AppState::new(dir.path().to_path_buf(), keystore);
    state.clear_duration = Duration::from_millis(50);

    let mock_cb = Arc::new(TestMockClipboard::default());

    // Create secwet and secret
    state.secwet_create(Some("test".into())).unwrap();
    let label = state.label_create("TestLabel".into(), None).unwrap();
    let item = state.item_create(label.id, "TestItem".into(), None).unwrap();

    let secret = state.secret_create(SecretDraftDto {
            item_id: Some(item.id),
            project_id: None,
            environment_id: None,
            name: "TOKEN".into(),
            kind: SecretKind::AccessToken,
            value: "ghp_VERY_SECRET_TOKEN_999".into(),
            note: None,
        },
    )
    .unwrap();

    // Test 1: Copy and auto-clear
    state.secret_copy(Arc::clone(&mock_cb), secret.id).unwrap();
    assert_eq!(mock_cb.read_text().unwrap(), "ghp_VERY_SECRET_TOKEN_999");

    // Wait for timer to expire (50ms duration)
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(mock_cb.read_text().is_err());

    // Test 2: Foreign content preservation
    state.secret_copy(Arc::clone(&mock_cb), secret.id).unwrap();
    assert_eq!(mock_cb.read_text().unwrap(), "ghp_VERY_SECRET_TOKEN_999");

    // User copies unrelated text at t=20ms
    tokio::time::sleep(Duration::from_millis(20)).await;
    *mock_cb.data.lock().unwrap() = Some("https://example.com".to_string());

    // At t=70ms (timer fired), foreign content must remain
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(mock_cb.read_text().unwrap(), "https://example.com");
}

#[tokio::test]
async fn test_error_mappings_and_edge_cases() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);
    let mock_cb = Arc::new(TestMockClipboard::default());

    state.secwet_create(Some("test-device".into())).unwrap();
    let label = state.label_create("General".into(), None).unwrap();
    let item = state.item_create(label.id, "Web".into(), None).unwrap();

    // 1. Duplicate item name
    let dup_err = state.item_create(label.id, "web".into(), None).unwrap_err();
    assert_eq!(dup_err.code, "duplicate");
    assert_eq!(dup_err.field.as_deref(), Some("name"));

    // 2. Invalid secret name
    let inv_err = state.secret_create(SecretDraftDto {
            item_id: Some(item.id),
            project_id: None,
            environment_id: None,
            name: "123_bad_start".into(),
            kind: SecretKind::Password,
            value: "secret".into(),
            note: None,
        },
    )
    .unwrap_err();
    assert_eq!(inv_err.code, "invalid");
    assert_eq!(inv_err.field.as_deref(), Some("name"));

    // 3. Not found on reveal, copy, delete
    let fake_id = Uuid::new_v4();
    let not_found_rev = state.secret_reveal(fake_id).unwrap_err();
    assert_eq!(not_found_rev.code, "not_found");

    let not_found_copy = state.secret_copy(mock_cb, fake_id).unwrap_err();
    assert_eq!(not_found_copy.code, "not_found");

    let not_found_del = state.secret_delete(fake_id).unwrap_err();
    assert_eq!(not_found_del.code, "not_found");

    // 4. Settings invalid inputs
    let err_theme = state.settings_set(SettingsPatchDto {
            theme: Some("hacker-green".into()),
            lock_timeout_minutes: None,
            device_name: None,
        },
    )
    .unwrap_err();
    assert_eq!(err_theme.code, "invalid");
    assert_eq!(err_theme.field.as_deref(), Some("theme"));

    let err_timeout = state.settings_set(SettingsPatchDto {
            theme: None,
            lock_timeout_minutes: Some(42),
            device_name: None,
        },
    )
    .unwrap_err();
    assert_eq!(err_timeout.code, "invalid");
    assert_eq!(err_timeout.field.as_deref(), Some("lock_timeout_minutes"));

    let err_name = state.settings_set(SettingsPatchDto {
            theme: None,
            lock_timeout_minutes: None,
            device_name: Some("   ".into()),
        },
    )
    .unwrap_err();
    assert_eq!(err_name.code, "invalid");
    assert_eq!(err_name.field.as_deref(), Some("device_name"));
}

#[tokio::test]
async fn test_secret_deserialization_general_secret_variations() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);

    state.secwet_create(Some("TestDevice".into())).unwrap();
    let label = state.label_create("General".into(), None).unwrap();
    let item = state.item_create(label.id, "MyApp".into(), None).unwrap();

    // 1. JSON with environment_id: null
    let json_null = format!(
        r#"{{"item_id": "{}", "environment_id": null, "name": "API_NULL", "kind": "env_var", "value": "val_null"}}"#,
        item.id
    );
    let dto_null: SecretDraftDto = serde_json::from_str(&json_null).expect("Failed to deserialize null env");
    assert_eq!(dto_null.environment_id, None);
    let sec_null = state.secret_create(dto_null).expect("Failed to create secret with null env");
    assert_eq!(sec_null.environment_id, None);
    assert_eq!(sec_null.name, "API_NULL");

    // 2. JSON with environment_id: "" (empty string - previously rejected by serde UUID)
    let json_empty = format!(
        r#"{{"item_id": "{}", "environment_id": "", "name": "API_EMPTY", "kind": "env_var", "value": "val_empty"}}"#,
        item.id
    );
    let dto_empty: SecretDraftDto = serde_json::from_str(&json_empty).expect("Failed to deserialize empty string env");
    assert_eq!(dto_empty.environment_id, None);
    let sec_empty = state.secret_create(dto_empty).expect("Failed to create secret with empty string env");
    assert_eq!(sec_empty.environment_id, None);
    assert_eq!(sec_empty.name, "API_EMPTY");

    // 3. JSON with omitted environment_id
    let json_omitted = format!(
        r#"{{"item_id": "{}", "name": "API_OMITTED", "kind": "api_key", "value": "val_omitted"}}"#,
        item.id
    );
    let dto_omitted: SecretDraftDto = serde_json::from_str(&json_omitted).expect("Failed to deserialize omitted env");
    assert_eq!(dto_omitted.environment_id, None);
    let sec_omitted = state.secret_create(dto_omitted).expect("Failed to create secret with omitted env");
    assert_eq!(sec_omitted.environment_id, None);
    assert_eq!(sec_omitted.name, "API_OMITTED");

    // 4. JSON with legacy project_id and environment_id: ""
    let json_legacy = format!(
        r#"{{"project_id": "{}", "environment_id": "", "name": "API_LEGACY", "kind": "access_token", "value": "val_legacy"}}"#,
        item.id
    );
    let dto_legacy: SecretDraftDto = serde_json::from_str(&json_legacy).expect("Failed to deserialize legacy project_id");
    assert_eq!(dto_legacy.environment_id, None);
    assert_eq!(dto_legacy.item_id, Some(item.id));
    let sec_legacy = state.secret_create(dto_legacy).expect("Failed to create secret with legacy project_id");
    assert_eq!(sec_legacy.environment_id, None);
    assert_eq!(sec_legacy.name, "API_LEGACY");

    // 5. Verify list_secrets returns all 4 General secrets
    let secrets = state.secrets_list(Some(item.id), None).expect("list_secrets");
    assert_eq!(secrets.len(), 4);

    // 6. Verify reveal for each
    assert_eq!(state.secret_reveal(sec_null.id).unwrap(), "val_null");
    assert_eq!(state.secret_reveal(sec_empty.id).unwrap(), "val_empty");
    assert_eq!(state.secret_reveal(sec_omitted.id).unwrap(), "val_omitted");
    assert_eq!(state.secret_reveal(sec_legacy.id).unwrap(), "val_legacy");

    // 7. Verify SQLite persistence across lock/unlock
    state.secwet_lock().unwrap();
    state.secwet_unlock().unwrap();
    let secrets_reopened = state.secrets_list(Some(item.id), None).expect("list_secrets after reopen");
    assert_eq!(secrets_reopened.len(), 4);
    assert_eq!(state.secret_reveal(sec_empty.id).unwrap(), "val_empty");
}

#[test]
fn test_recovery_and_workspace_export_restore_lifecycle_roundtrip() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);

    // 1. Locked / uninitialized state checks
    assert_eq!(state.recovery_status().unwrap_err().code, "locked");
    assert_eq!(state.recovery_key_create().unwrap_err().code, "locked");
    assert_eq!(state.recovery_key_replace().unwrap_err().code, "locked");
    assert_eq!(
        state.workspace_export(Some(dir.path().join("out.secwet")), "KEY".into())
            .unwrap_err()
            .code,
        "locked"
    );

    // 2. Initialize workspace
    state.secwet_create(Some("test-device".into())).unwrap();

    // Recovery status initially false
    let initial_status: RecoveryStatusDto = state.recovery_status().unwrap();
    assert!(!initial_status.created);
    assert_eq!(initial_status.created_at, None);

    // 3. Populate workspace with spaces, labels, items, environments, secrets, notes, and files
    let space = state.space_create("Backend Space".into(), Some("server".into()))
        .unwrap();
    assert_eq!(space.name, "Backend Space");
    let label = state.label_create("Core Service".into(), Some("tag".into()))
        .unwrap();
    let item = state.item_create(label.id, "Auth Service".into(), None)
        .unwrap();
    let env = state.environment_add(item.id, "Production".into())
        .unwrap();

    let secret_draft = SecretDraftDto {
        item_id: Some(item.id),
        project_id: None,
        environment_id: Some(env.id),
        name: "JWT_SECRET".into(),
        kind: SecretKind::Password,
        value: "super-secret-jwt-signing-key".into(),
        note: Some("Production JWT key".into()),
    };
    state.secret_create(secret_draft).unwrap();

    let note_draft = NoteDraftDto {
        item_id: item.id,
        environment_id: Some(env.id),
        title: "Deployment Notes".into(),
        content: "<p>Important runbook steps</p>".into(),
    };
    state.note_create(note_draft).unwrap();

    let file_content = b"TLS CERTIFICATE CONTENT PAYLOAD 12345";
    state.file_upload(item.id,
        Some(env.id),
        "cert.pem".into(),
        Some("application/x-pem-file".into()),
        file_content.to_vec(),
    )
    .unwrap();

    // 4. Create recovery key
    let key1 = state.recovery_key_create().unwrap();
    assert_eq!(key1.len(), 29); // 25 chars + 4 hyphens
    assert_eq!(key1.matches('-').count(), 4);

    let status1 = state.recovery_status().unwrap();
    assert!(status1.created);
    assert!(status1.created_at.is_some());

    // 5. Replace recovery key
    let key2 = state.recovery_key_replace().unwrap();
    assert_ne!(key1, key2);
    assert_eq!(key2.len(), 29);

    let status2 = state.recovery_status().unwrap();
    assert!(status2.created);

    // 6. Export with invalidated old key fails
    let export_path = dir.path().join("workspace_export.secwet");
    let err_old_key = state.workspace_export(Some(export_path.clone()), key1).unwrap_err();
    assert_eq!(err_old_key.code, "recovery_failed");

    // 7. Headless mode without path fails with invalid error
    let err_headless = state.workspace_export(None, key2.clone()).unwrap_err();
    assert_eq!(err_headless.code, "invalid");

    // 8. Export with valid key2 succeeds
    let export_summary: ExportSummaryDto = state.workspace_export(Some(export_path.clone()), key2.clone())
        .unwrap();
    assert!(export_path.exists());
    assert!(export_summary.bytes_written > 0);
    assert!(export_summary.spaces_count >= 1);
    assert!(export_summary.items_count >= 1);
    assert!(export_summary.secrets_count >= 1);
    assert!(export_summary.notes_count >= 1);
    assert!(export_summary.files_count >= 1);

    // 9. Restore on a fresh device / state
    let restore_dir = tempdir().unwrap();
    let restore_keystore = Arc::new(MemoryStore::new());
    let restore_state = AppState::new(restore_dir.path().to_path_buf(), restore_keystore);

    // Wrong key fails
    let err_restore_bad = restore_state.workspace_restore(Some(export_path.clone()),
        "WRONG-KEY00-00000-00000-00000".into(),
        Some("restore-dev".into()),
    )
    .unwrap_err();
    assert_eq!(err_restore_bad.code, "recovery_failed");

    // Headless mode without path fails with invalid error
    let err_restore_headless = restore_state.workspace_restore(None,
        key2.clone(),
        Some("restore-dev".into()),
    )
    .unwrap_err();
    assert_eq!(err_restore_headless.code, "invalid");

    // Restore with correct key2 succeeds
    let restore_status = restore_state.workspace_restore(Some(export_path),
        key2,
        Some("restored-desktop".into()),
    )
    .unwrap();

    match restore_status {
        SecwetStatusDto::Unlocked { secwet_id } => {
            assert_ne!(secwet_id, Uuid::nil());
        }
        _ => panic!("Expected Unlocked status after restore"),
    }

    // 10. Verify 100% data fidelity on restored instance
    let restored_status = restore_state.recovery_status().unwrap();
    assert!(restored_status.created);

    let restored_items = restore_state.items_list(Some(label.id)).unwrap();
    assert_eq!(restored_items.len(), 1);
    assert_eq!(restored_items[0].name, "Auth Service");

    let restored_secrets = restore_state.secrets_list(Some(item.id), Some(env.id)).unwrap();
    assert_eq!(restored_secrets.len(), 1);
    assert_eq!(restored_secrets[0].name, "JWT_SECRET");

    let revealed = restore_state.secret_reveal(restored_secrets[0].id).unwrap();
    assert_eq!(revealed, "super-secret-jwt-signing-key");

    let restored_notes = restore_state.notes_list(item.id, Some(env.id)).unwrap();
    assert_eq!(restored_notes.len(), 1);
    let note = restore_state.note_get(restored_notes[0].id).unwrap();
    assert_eq!(note.title, "Deployment Notes");
    assert_eq!(note.content, "<p>Important runbook steps</p>");

    let restored_files = restore_state.files_list(item.id, Some(env.id)).unwrap();
    assert_eq!(restored_files.len(), 1);
    assert_eq!(restored_files[0].name, "cert.pem");
    let downloaded = restore_state.file_download(restored_files[0].id).unwrap();
    assert_eq!(downloaded.bytes, file_content);
}



