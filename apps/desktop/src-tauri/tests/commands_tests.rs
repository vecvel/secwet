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
use secwet_desktop_lib::clipboard::ClipboardPort;
use secwet_desktop_lib::commands::{
    clipboard_copy_text_impl, dashboard_get_impl, dashboard_set_impl, environment_add_impl,
    environment_delete_impl, environment_rename_impl, environments_list_impl, file_delete_impl,
    file_download_impl, file_rename_impl, file_upload_impl, files_list_impl, item_create_impl,
    item_delete_impl, item_rename_impl, items_list_impl, label_create_impl, label_delete_impl,
    label_rename_impl, label_reorder_impl, labels_list_impl, note_copy_plain_impl, note_create_impl,
    note_delete_impl, note_get_impl, note_update_impl, notes_list_impl, overview_impl,
    project_create_impl, project_delete_impl, project_rename_impl, projects_list_impl,
    recovery_key_create_impl, recovery_key_replace_impl, recovery_status_impl,
    secret_copy_impl, secret_copy_to_environment_impl, secret_create_impl, secret_delete_impl,
    secret_reveal_impl, secret_update_impl, secrets_list_impl, settings_get_impl,
    settings_set_impl, space_create_impl, secwet_create_impl, secwet_lock_impl, secwet_status_impl,
    secwet_unlock_impl, workspace_export_impl, workspace_restore_impl,
    ExportSummaryDto, NoteDraftDto, NoteUpdateDto, RecoveryStatusDto, SecretDraftDto,
    SettingsPatchDto,
};
use secwet_desktop_lib::state::{AppState, SecwetStatusDto};
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
    let status = secwet_status_impl(&state).unwrap();
    assert_eq!(status, SecwetStatusDto::Uninitialized);

    // 2. All data commands return locked
    // Labels
    assert_eq!(labels_list_impl(&state).unwrap_err().code, "locked");
    assert_eq!(label_create_impl(None, &state, "L".into(), None).unwrap_err().code, "locked");
    assert_eq!(label_rename_impl(None, &state, dummy_id, "L".into(), None).unwrap_err().code, "locked");
    assert_eq!(label_delete_impl(None, &state, dummy_id).unwrap_err().code, "locked");
    assert_eq!(label_reorder_impl(None, &state, vec![dummy_id]).unwrap_err().code, "locked");

    // Items
    assert_eq!(items_list_impl(&state, None).unwrap_err().code, "locked");
    assert_eq!(item_create_impl(None, &state, dummy_id, "I".into(), None).unwrap_err().code, "locked");
    assert_eq!(item_rename_impl(None, &state, dummy_id, "I".into(), None).unwrap_err().code, "locked");
    assert_eq!(item_delete_impl(None, &state, dummy_id).unwrap_err().code, "locked");

    // Environments
    assert_eq!(environments_list_impl(&state, dummy_id).unwrap_err().code, "locked");
    assert_eq!(environment_add_impl(None, &state, dummy_id, "E".into()).unwrap_err().code, "locked");
    assert_eq!(environment_rename_impl(None, &state, dummy_id, "E".into()).unwrap_err().code, "locked");
    assert_eq!(environment_delete_impl(None, &state, dummy_id, None).unwrap_err().code, "locked");

    // Secrets
    assert_eq!(secrets_list_impl(&state, Some(dummy_id), None).unwrap_err().code, "locked");
    assert_eq!(secret_reveal_impl(&state, dummy_id).unwrap_err().code, "locked");
    assert_eq!(secret_copy_impl(Arc::clone(&mock_cb), &state, dummy_id).unwrap_err().code, "locked");

    let draft = SecretDraftDto {
        item_id: Some(dummy_id),
        project_id: None,
        environment_id: None,
        name: "TEST".into(),
        kind: SecretKind::ApiKey,
        value: "secret".into(),
        note: None,
    };
    assert_eq!(secret_create_impl(None, &state, draft.clone()).unwrap_err().code, "locked");
    assert_eq!(secret_update_impl(None, &state, dummy_id, draft).unwrap_err().code, "locked");
    assert_eq!(secret_delete_impl(None, &state, dummy_id).unwrap_err().code, "locked");
    assert_eq!(secret_copy_to_environment_impl(None, &state, dummy_id, Some(dummy_id)).unwrap_err().code, "locked");

    // Files
    assert_eq!(files_list_impl(&state, dummy_id, None).unwrap_err().code, "locked");
    assert_eq!(file_upload_impl(None, &state, dummy_id, None, "f.txt".into(), None, vec![1, 2]).unwrap_err().code, "locked");
    assert_eq!(file_download_impl(&state, dummy_id).unwrap_err().code, "locked");
    assert_eq!(file_rename_impl(None, &state, dummy_id, "g.txt".into()).unwrap_err().code, "locked");
    assert_eq!(file_delete_impl(None, &state, dummy_id).unwrap_err().code, "locked");

    // Notes
    assert_eq!(notes_list_impl(&state, dummy_id, None).unwrap_err().code, "locked");
    assert_eq!(note_get_impl(&state, dummy_id).unwrap_err().code, "locked");
    let note_draft = NoteDraftDto {
        item_id: dummy_id,
        environment_id: None,
        title: "T".into(),
        content: "<p>body</p>".into(),
    };
    assert_eq!(note_create_impl(None, &state, note_draft).unwrap_err().code, "locked");
    assert_eq!(note_update_impl(None, &state, dummy_id, NoteUpdateDto { title: None, content: None }).unwrap_err().code, "locked");
    assert_eq!(note_delete_impl(None, &state, dummy_id).unwrap_err().code, "locked");
    assert_eq!(note_copy_plain_impl(Arc::clone(&mock_cb), &state, dummy_id).unwrap_err().code, "locked");
    assert_eq!(clipboard_copy_text_impl(Arc::clone(&mock_cb), &state, "some text".into()).unwrap_err().code, "locked");

    // Dashboard & Overview
    assert_eq!(overview_impl(&state).unwrap_err().code, "locked");
    assert_eq!(dashboard_get_impl(&state).unwrap_err().code, "locked");
    assert_eq!(dashboard_set_impl(None, &state, DashboardConfig::default()).unwrap_err().code, "locked");

    // Settings
    assert_eq!(settings_get_impl(&state).unwrap_err().code, "locked");
    let patch = SettingsPatchDto {
        theme: Some("dark".into()),
        lock_timeout_minutes: Some(30),
        device_name: Some("dev".into()),
    };
    assert_eq!(settings_set_impl(None, &state, patch).unwrap_err().code, "locked");

    // Compatibility (Projects)
    assert_eq!(projects_list_impl(&state).unwrap_err().code, "locked");
    assert_eq!(project_create_impl(None, &state, "P".into(), vec![]).unwrap_err().code, "locked");
    assert_eq!(project_rename_impl(None, &state, dummy_id, "P".into()).unwrap_err().code, "locked");
    assert_eq!(project_delete_impl(None, &state, dummy_id).unwrap_err().code, "locked");
}

#[tokio::test]
async fn test_full_lifecycle_and_crud_workflow() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);
    let mock_cb = Arc::new(TestMockClipboard::default());

    // 1. Initial status
    assert_eq!(secwet_status_impl(&state).unwrap(), SecwetStatusDto::Uninitialized);

    // 2. Create secwet
    let status = secwet_create_impl(None, &state, Some("MacBook-Dev".into())).unwrap();
    let secwet_id = match status {
        SecwetStatusDto::Unlocked { secwet_id } => secwet_id,
        _ => panic!("Expected Unlocked status after create"),
    };

    // Double create fails cleanly
    let dup_err = secwet_create_impl(None, &state, None).unwrap_err();
    assert_eq!(dup_err.code, "already_initialized");

    // Status is unlocked
    assert_eq!(secwet_status_impl(&state).unwrap(), SecwetStatusDto::Unlocked { secwet_id });

    // 3. Labels CRUD and reordering
    let label1 = label_create_impl(None, &state, "Infrastructure".into(), Some("server".into())).unwrap();
    assert_eq!(label1.name, "Infrastructure");
    assert_eq!(label1.icon.as_deref(), Some("server"));

    let label2 = label_create_impl(None, &state, "Mobile Apps".into(), None).unwrap();
    assert_eq!(label2.name, "Mobile Apps");

    label_rename_impl(None, &state, label1.id, "Cloud Infra".into(), Some("cloud".into())).unwrap();
    let labels = labels_list_impl(&state).unwrap();
    assert!(labels.iter().any(|l| l.name == "Cloud Infra" && l.icon.as_deref() == Some("cloud")));
    let default_label_id = labels.iter().find(|l| l.id != label1.id && l.id != label2.id).unwrap().id;

    label_reorder_impl(None, &state, vec![label2.id, label1.id, default_label_id]).unwrap();
    let reordered = labels_list_impl(&state).unwrap();
    assert_eq!(reordered[0].id, label2.id);
    assert_eq!(reordered[1].id, label1.id);

    // 4. Items CRUD (zero default environments)
    let item1 = item_create_impl(None, &state, label1.id, "payments-service".into(), Some("Backend API".into())).unwrap();
    assert_eq!(item1.name, "payments-service");
    assert_eq!(item1.description.as_deref(), Some("Backend API"));

    let envs0 = environments_list_impl(&state, item1.id).unwrap();
    assert_eq!(envs0.len(), 0, "Item must be created with 0 default environments");

    let items = items_list_impl(&state, Some(label1.id)).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, item1.id);

    item_rename_impl(None, &state, item1.id, "payments-api".into(), Some("Updated API".into())).unwrap();

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
    let created_item_sec = secret_create_impl(None, &state, item_secret_draft).unwrap();
    assert_eq!(created_item_sec.name, "GLOBAL_API_KEY");
    assert_eq!(created_item_sec.value_tail, "alue");

    let item_secrets = secrets_list_impl(&state, Some(item1.id), None).unwrap();
    assert_eq!(item_secrets.len(), 1);
    assert_eq!(item_secrets[0].id, created_item_sec.id);

    // Reveal item-level secret
    let revealed = secret_reveal_impl(&state, created_item_sec.id).unwrap();
    assert_eq!(revealed, "sk_live_item_level_secret_value");

    // 6. Environments within Item
    let prod_env = environment_add_impl(None, &state, item1.id, "Production".into()).unwrap();
    assert_eq!(prod_env.name, "Production");

    let dev_env = environment_add_impl(None, &state, item1.id, "Development".into()).unwrap();
    assert_eq!(dev_env.name, "Development");

    environment_rename_impl(None, &state, dev_env.id, "Dev".into()).unwrap();

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
    let created_env_sec = secret_create_impl(None, &state, env_draft).unwrap();
    assert_eq!(created_env_sec.name, "DATABASE_URL");

    // Copy secret to environment
    let copied_sec = secret_copy_to_environment_impl(None, &state, created_env_sec.id, Some(dev_env.id)).unwrap();
    assert_eq!(copied_sec.name, "DATABASE_URL");
    let dev_secrets = secrets_list_impl(&state, Some(item1.id), Some(dev_env.id)).unwrap();
    assert_eq!(dev_secrets.len(), 1);

    // 7. Encrypted Files CRUD
    let test_bytes = b"Hello, encrypted file storage in Tauri!".to_vec();
    let file_meta = file_upload_impl(
        None,
        &state,
        item1.id,
        Some(prod_env.id),
        "readme.txt".into(),
        Some("text/plain".into()),
        test_bytes.clone(),
    )
    .unwrap();
    assert_eq!(file_meta.name, "readme.txt");
    assert_eq!(file_meta.size_bytes, test_bytes.len() as u64);

    let files = files_list_impl(&state, item1.id, Some(prod_env.id)).unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].id, file_meta.id);

    let downloaded = file_download_impl(&state, file_meta.id).unwrap();
    assert_eq!(downloaded.bytes, test_bytes);
    assert_eq!(downloaded.meta.name, "readme.txt");

    let renamed_file = file_rename_impl(None, &state, file_meta.id, "README.md".into()).unwrap();
    assert_eq!(renamed_file.name, "README.md");

    file_delete_impl(None, &state, file_meta.id).unwrap();
    assert_eq!(files_list_impl(&state, item1.id, Some(prod_env.id)).unwrap().len(), 0);

    // 8. Rich-Text Notes CRUD & Plain Text Copying
    let note_draft = NoteDraftDto {
        item_id: item1.id,
        environment_id: None,
        title: "Deployment Runbook".into(),
        content: "<h2>Steps</h2><p>Run <b>deploy.sh</b></p><ul><li>Step 1</li><li>Step 2</li></ul>".into(),
    };
    let note = note_create_impl(None, &state, note_draft).unwrap();
    assert_eq!(note.title, "Deployment Runbook");

    let notes = notes_list_impl(&state, item1.id, None).unwrap();
    assert_eq!(notes.len(), 1);

    let fetched_note = note_get_impl(&state, note.id).unwrap();
    assert_eq!(fetched_note.title, "Deployment Runbook");

    // Copy note plain text
    note_copy_plain_impl(Arc::clone(&mock_cb), &state, note.id).unwrap();
    let copied_note_text = mock_cb.read_text().unwrap();
    assert!(copied_note_text.contains("Steps"));
    assert!(copied_note_text.contains("Run deploy.sh"));
    assert!(copied_note_text.contains("• Step 1"));

    // Copy unsaved text directly
    clipboard_copy_text_impl(Arc::clone(&mock_cb), &state, "<p>Unsaved <b>snippet</b></p>".into()).unwrap();
    assert_eq!(mock_cb.read_text().unwrap(), "Unsaved snippet");

    let updated_note = note_update_impl(
        None,
        &state,
        note.id,
        NoteUpdateDto {
            title: Some("Updated Runbook".into()),
            content: Some("<p>Single paragraph</p>".into()),
        },
    )
    .unwrap();
    assert_eq!(updated_note.title, "Updated Runbook");

    note_delete_impl(None, &state, note.id).unwrap();
    assert_eq!(notes_list_impl(&state, item1.id, None).unwrap().len(), 0);

    // 9. Dashboard Configuration Get / Set
    let dash = dashboard_get_impl(&state).unwrap();
    assert_eq!(dash.home_label, "Home");

    let custom_dash = DashboardConfig {
        home_label: "Executive Dashboard".into(),
        ..DashboardConfig::default()
    };
    dashboard_set_impl(None, &state, custom_dash).unwrap();
    let updated_dash = dashboard_get_impl(&state).unwrap();
    assert_eq!(updated_dash.home_label, "Executive Dashboard");

    // 10. Settings Get / Set
    let initial_settings = settings_get_impl(&state).unwrap();
    assert_eq!(initial_settings.theme, "system");

    let patch = SettingsPatchDto {
        theme: Some("dark".into()),
        lock_timeout_minutes: Some(30),
        device_name: Some("Workstation-Linux".into()),
    };
    let updated_settings = settings_set_impl(None, &state, patch).unwrap();
    assert_eq!(updated_settings.theme, "dark");
    assert_eq!(updated_settings.device_name, "Workstation-Linux");

    // 11. Backward Compatibility (Projects)
    let projects = projects_list_impl(&state).unwrap();
    assert!(!projects.is_empty());

    let legacy_proj = project_create_impl(None, &state, "Legacy Service".into(), vec!["prod".into()]).unwrap();
    assert_eq!(legacy_proj.name, "Legacy Service");

    project_rename_impl(None, &state, legacy_proj.id, "Legacy Renamed".into()).unwrap();
    project_delete_impl(None, &state, legacy_proj.id).unwrap();

    // 12. Delete Environment with Options
    // Delete dev_env
    environment_delete_impl(None, &state, dev_env.id, Some(false)).unwrap();

    // 13. Lock / Unlock cycle
    secwet_lock_impl(None, &state).unwrap();
    assert_eq!(secwet_status_impl(&state).unwrap(), SecwetStatusDto::Locked { secwet_id });

    secwet_unlock_impl(None, &state).unwrap();
    assert_eq!(secwet_status_impl(&state).unwrap(), SecwetStatusDto::Unlocked { secwet_id });

    // Verify settings and dashboard persist after unlock
    let restored_dash = dashboard_get_impl(&state).unwrap();
    assert_eq!(restored_dash.home_label, "Executive Dashboard");

    secwet_lock_impl(None, &state).unwrap();
}

#[tokio::test]
async fn test_clipboard_copy_auto_clear_timing_and_foreign_content() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let mut state = AppState::new(dir.path().to_path_buf(), keystore);
    state.clear_duration = Duration::from_millis(50);

    let mock_cb = Arc::new(TestMockClipboard::default());

    // Create secwet and secret
    secwet_create_impl(None, &state, Some("test".into())).unwrap();
    let label = label_create_impl(None, &state, "TestLabel".into(), None).unwrap();
    let item = item_create_impl(None, &state, label.id, "TestItem".into(), None).unwrap();

    let secret = secret_create_impl(
        None,
        &state,
        SecretDraftDto {
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
    secret_copy_impl(Arc::clone(&mock_cb), &state, secret.id).unwrap();
    assert_eq!(mock_cb.read_text().unwrap(), "ghp_VERY_SECRET_TOKEN_999");

    // Wait for timer to expire (50ms duration)
    tokio::time::sleep(Duration::from_millis(70)).await;
    assert!(mock_cb.read_text().is_err());

    // Test 2: Foreign content preservation
    secret_copy_impl(Arc::clone(&mock_cb), &state, secret.id).unwrap();
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

    secwet_create_impl(None, &state, Some("test-device".into())).unwrap();
    let label = label_create_impl(None, &state, "General".into(), None).unwrap();
    let item = item_create_impl(None, &state, label.id, "Web".into(), None).unwrap();

    // 1. Duplicate item name
    let dup_err = item_create_impl(None, &state, label.id, "web".into(), None).unwrap_err();
    assert_eq!(dup_err.code, "duplicate");
    assert_eq!(dup_err.field.as_deref(), Some("name"));

    // 2. Invalid secret name
    let inv_err = secret_create_impl(
        None,
        &state,
        SecretDraftDto {
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
    let not_found_rev = secret_reveal_impl(&state, fake_id).unwrap_err();
    assert_eq!(not_found_rev.code, "not_found");

    let not_found_copy = secret_copy_impl(mock_cb, &state, fake_id).unwrap_err();
    assert_eq!(not_found_copy.code, "not_found");

    let not_found_del = secret_delete_impl(None, &state, fake_id).unwrap_err();
    assert_eq!(not_found_del.code, "not_found");

    // 4. Settings invalid inputs
    let err_theme = settings_set_impl(
        None,
        &state,
        SettingsPatchDto {
            theme: Some("hacker-green".into()),
            lock_timeout_minutes: None,
            device_name: None,
        },
    )
    .unwrap_err();
    assert_eq!(err_theme.code, "invalid");
    assert_eq!(err_theme.field.as_deref(), Some("theme"));

    let err_timeout = settings_set_impl(
        None,
        &state,
        SettingsPatchDto {
            theme: None,
            lock_timeout_minutes: Some(42),
            device_name: None,
        },
    )
    .unwrap_err();
    assert_eq!(err_timeout.code, "invalid");
    assert_eq!(err_timeout.field.as_deref(), Some("lock_timeout_minutes"));

    let err_name = settings_set_impl(
        None,
        &state,
        SettingsPatchDto {
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

    secwet_create_impl(None, &state, Some("TestDevice".into())).unwrap();
    let label = label_create_impl(None, &state, "General".into(), None).unwrap();
    let item = item_create_impl(None, &state, label.id, "MyApp".into(), None).unwrap();

    // 1. JSON with environment_id: null
    let json_null = format!(
        r#"{{"item_id": "{}", "environment_id": null, "name": "API_NULL", "kind": "env_var", "value": "val_null"}}"#,
        item.id
    );
    let dto_null: SecretDraftDto = serde_json::from_str(&json_null).expect("Failed to deserialize null env");
    assert_eq!(dto_null.environment_id, None);
    let sec_null = secret_create_impl(None, &state, dto_null).expect("Failed to create secret with null env");
    assert_eq!(sec_null.environment_id, None);
    assert_eq!(sec_null.name, "API_NULL");

    // 2. JSON with environment_id: "" (empty string - previously rejected by serde UUID)
    let json_empty = format!(
        r#"{{"item_id": "{}", "environment_id": "", "name": "API_EMPTY", "kind": "env_var", "value": "val_empty"}}"#,
        item.id
    );
    let dto_empty: SecretDraftDto = serde_json::from_str(&json_empty).expect("Failed to deserialize empty string env");
    assert_eq!(dto_empty.environment_id, None);
    let sec_empty = secret_create_impl(None, &state, dto_empty).expect("Failed to create secret with empty string env");
    assert_eq!(sec_empty.environment_id, None);
    assert_eq!(sec_empty.name, "API_EMPTY");

    // 3. JSON with omitted environment_id
    let json_omitted = format!(
        r#"{{"item_id": "{}", "name": "API_OMITTED", "kind": "api_key", "value": "val_omitted"}}"#,
        item.id
    );
    let dto_omitted: SecretDraftDto = serde_json::from_str(&json_omitted).expect("Failed to deserialize omitted env");
    assert_eq!(dto_omitted.environment_id, None);
    let sec_omitted = secret_create_impl(None, &state, dto_omitted).expect("Failed to create secret with omitted env");
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
    let sec_legacy = secret_create_impl(None, &state, dto_legacy).expect("Failed to create secret with legacy project_id");
    assert_eq!(sec_legacy.environment_id, None);
    assert_eq!(sec_legacy.name, "API_LEGACY");

    // 5. Verify list_secrets returns all 4 General secrets
    let secrets = secrets_list_impl(&state, Some(item.id), None).expect("list_secrets");
    assert_eq!(secrets.len(), 4);

    // 6. Verify reveal for each
    assert_eq!(secret_reveal_impl(&state, sec_null.id).unwrap(), "val_null");
    assert_eq!(secret_reveal_impl(&state, sec_empty.id).unwrap(), "val_empty");
    assert_eq!(secret_reveal_impl(&state, sec_omitted.id).unwrap(), "val_omitted");
    assert_eq!(secret_reveal_impl(&state, sec_legacy.id).unwrap(), "val_legacy");

    // 7. Verify SQLite persistence across lock/unlock
    secwet_lock_impl(None, &state).unwrap();
    secwet_unlock_impl(None, &state).unwrap();
    let secrets_reopened = secrets_list_impl(&state, Some(item.id), None).expect("list_secrets after reopen");
    assert_eq!(secrets_reopened.len(), 4);
    assert_eq!(secret_reveal_impl(&state, sec_empty.id).unwrap(), "val_empty");
}

#[test]
fn test_recovery_and_workspace_export_restore_lifecycle_roundtrip() {
    let dir = tempdir().unwrap();
    let keystore = Arc::new(MemoryStore::new());
    let state = AppState::new(dir.path().to_path_buf(), keystore);

    // 1. Locked / uninitialized state checks
    assert_eq!(recovery_status_impl(&state).unwrap_err().code, "locked");
    assert_eq!(recovery_key_create_impl(None, &state).unwrap_err().code, "locked");
    assert_eq!(recovery_key_replace_impl(None, &state).unwrap_err().code, "locked");
    assert_eq!(
        workspace_export_impl(None, &state, Some(dir.path().join("out.secwet")), "KEY".into())
            .unwrap_err()
            .code,
        "locked"
    );

    // 2. Initialize workspace
    secwet_create_impl(None, &state, Some("test-device".into())).unwrap();

    // Recovery status initially false
    let initial_status: RecoveryStatusDto = recovery_status_impl(&state).unwrap();
    assert!(!initial_status.created);
    assert_eq!(initial_status.created_at, None);

    // 3. Populate workspace with spaces, labels, items, environments, secrets, notes, and files
    let space = space_create_impl(None, &state, "Backend Space".into(), Some("server".into()))
        .unwrap();
    assert_eq!(space.name, "Backend Space");
    let label = label_create_impl(None, &state, "Core Service".into(), Some("tag".into()))
        .unwrap();
    let item = item_create_impl(None, &state, label.id, "Auth Service".into(), None)
        .unwrap();
    let env = environment_add_impl(None, &state, item.id, "Production".into())
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
    secret_create_impl(None, &state, secret_draft).unwrap();

    let note_draft = NoteDraftDto {
        item_id: item.id,
        environment_id: Some(env.id),
        title: "Deployment Notes".into(),
        content: "<p>Important runbook steps</p>".into(),
    };
    note_create_impl(None, &state, note_draft).unwrap();

    let file_content = b"TLS CERTIFICATE CONTENT PAYLOAD 12345";
    file_upload_impl(
        None,
        &state,
        item.id,
        Some(env.id),
        "cert.pem".into(),
        Some("application/x-pem-file".into()),
        file_content.to_vec(),
    )
    .unwrap();

    // 4. Create recovery key
    let key1 = recovery_key_create_impl(None, &state).unwrap();
    assert_eq!(key1.len(), 29); // 25 chars + 4 hyphens
    assert_eq!(key1.matches('-').count(), 4);

    let status1 = recovery_status_impl(&state).unwrap();
    assert!(status1.created);
    assert!(status1.created_at.is_some());

    // 5. Replace recovery key
    let key2 = recovery_key_replace_impl(None, &state).unwrap();
    assert_ne!(key1, key2);
    assert_eq!(key2.len(), 29);

    let status2 = recovery_status_impl(&state).unwrap();
    assert!(status2.created);

    // 6. Export with invalidated old key fails
    let export_path = dir.path().join("workspace_export.secwet");
    let err_old_key = workspace_export_impl(None, &state, Some(export_path.clone()), key1).unwrap_err();
    assert_eq!(err_old_key.code, "recovery_failed");

    // 7. Headless mode without path fails with invalid error
    let err_headless = workspace_export_impl(None, &state, None, key2.clone()).unwrap_err();
    assert_eq!(err_headless.code, "invalid");

    // 8. Export with valid key2 succeeds
    let export_summary: ExportSummaryDto = workspace_export_impl(None, &state, Some(export_path.clone()), key2.clone())
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
    let err_restore_bad = workspace_restore_impl(
        None,
        &restore_state,
        Some(export_path.clone()),
        "WRONG-KEY00-00000-00000-00000".into(),
        Some("restore-dev".into()),
    )
    .unwrap_err();
    assert_eq!(err_restore_bad.code, "recovery_failed");

    // Headless mode without path fails with invalid error
    let err_restore_headless = workspace_restore_impl(
        None,
        &restore_state,
        None,
        key2.clone(),
        Some("restore-dev".into()),
    )
    .unwrap_err();
    assert_eq!(err_restore_headless.code, "invalid");

    // Restore with correct key2 succeeds
    let restore_status = workspace_restore_impl(
        None,
        &restore_state,
        Some(export_path),
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
    let restored_status = recovery_status_impl(&restore_state).unwrap();
    assert!(restored_status.created);

    let restored_items = items_list_impl(&restore_state, Some(label.id)).unwrap();
    assert_eq!(restored_items.len(), 1);
    assert_eq!(restored_items[0].name, "Auth Service");

    let restored_secrets = secrets_list_impl(&restore_state, Some(item.id), Some(env.id)).unwrap();
    assert_eq!(restored_secrets.len(), 1);
    assert_eq!(restored_secrets[0].name, "JWT_SECRET");

    let revealed = secret_reveal_impl(&restore_state, restored_secrets[0].id).unwrap();
    assert_eq!(revealed, "super-secret-jwt-signing-key");

    let restored_notes = notes_list_impl(&restore_state, item.id, Some(env.id)).unwrap();
    assert_eq!(restored_notes.len(), 1);
    let note = note_get_impl(&restore_state, restored_notes[0].id).unwrap();
    assert_eq!(note.title, "Deployment Notes");
    assert_eq!(note.content, "<p>Important runbook steps</p>");

    let restored_files = files_list_impl(&restore_state, item.id, Some(env.id)).unwrap();
    assert_eq!(restored_files.len(), 1);
    assert_eq!(restored_files[0].name, "cert.pem");
    let downloaded = file_download_impl(&restore_state, restored_files[0].id).unwrap();
    assert_eq!(downloaded.bytes, file_content);
}



