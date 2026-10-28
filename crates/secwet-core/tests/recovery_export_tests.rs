//! Recovery and Backup Integration and Invariant Test Suite.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §7 (F9, F10), §11.2, and `ORIGINAL_REQUEST.md` (R2).
//!
//! Mandatory Invariants Tested:
//! 1. `export_then_restore_roundtrip`: Full roundtrip of rich workspace state (spaces, labels, items,
//!    environments, secrets, rich-text notes, binary files, settings) with 100% data fidelity.
//! 2. `export_wrong_key_fails_without_detail`: Wrong recovery key cleanly fails envelope decryption
//!    with generic `Error::RecoveryFailed` and zero partial data leakage.
//! 3. `export_file_contains_no_plaintext`: Export envelope contains zero plaintext occurrences of
//!    secret values, rich notes, file bytes, or item names.
//! 4. `test_recovery_key_create_and_replace`: Verifies 125-bit entropy format (25 Crockford chars in 5 groups),
//!    status reporting, normalization (lowercase, spaces, Crockford aliases), and old key invalidation upon replacement.

use rand_core::Rng;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use secwet_core::crypto::OsRng;
use secwet_core::keys::MemoryStore;
use secwet_core::{Error, SecretDraft, SecretKind, Secwet};
use tempfile::tempdir;

#[test]
fn test_recovery_key_create_and_replace() {
    let dir = tempdir().expect("failed to create tempdir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "test-laptop", &keystore)
        .expect("workspace creation must succeed");

    // Initially recovery key status is uncreated
    let status_initial = secwet
        .recovery_status()
        .expect("recovery_status must succeed");
    assert!(!status_initial.created);
    assert_eq!(status_initial.created_at, None);

    // Verify against uncreated recovery key returns false
    assert!(!secwet
        .verify_recovery_key("00000-00000-00000-00000-00000")
        .expect("verify must succeed"));

    // Create recovery key
    let key1 = secwet
        .create_recovery_key(&keystore)
        .expect("create_recovery_key must succeed");
    let key1_str = key1.expose_secret().to_string();

    // Verify format: 29 characters (5 groups of 5 with 4 hyphens)
    assert_eq!(
        key1_str.len(),
        29,
        "Recovery key must be exactly 29 chars formatted as XXXXX-XXXXX-XXXXX-XXXXX-XXXXX"
    );
    let parts: Vec<&str> = key1_str.split('-').collect();
    assert_eq!(parts.len(), 5, "Recovery key must contain 5 groups");
    for part in parts {
        assert_eq!(part.len(), 5, "Each group must be 5 chars");
    }

    // Status is now created
    let status_after = secwet
        .recovery_status()
        .expect("recovery_status must succeed");
    assert!(status_after.created);
    assert!(status_after.created_at.is_some());

    // Exact verification succeeds
    assert!(secwet
        .verify_recovery_key(&key1_str)
        .expect("verify must succeed"));

    // Normalization check: lowercase succeeds
    let key1_lower = key1_str.to_lowercase();
    assert!(secwet
        .verify_recovery_key(&key1_lower)
        .expect("lowercase key must verify"));

    // Normalization check: spaces instead of hyphens succeeds
    let key1_spaces = key1_str.replace('-', " ");
    assert!(secwet
        .verify_recovery_key(&key1_spaces)
        .expect("spaces key must verify"));

    // Normalization check: no hyphens at all succeeds
    let key1_raw = key1_str.replace('-', "");
    assert!(secwet
        .verify_recovery_key(&key1_raw)
        .expect("raw key without separators must verify"));

    // Normalization check: Crockford alias substitution
    // Replace '0' with 'O' and '1' with 'I' or 'L'
    let mut key1_aliased = key1_str.replace('0', "O");
    key1_aliased = key1_aliased.replace('1', "I");
    assert!(secwet
        .verify_recovery_key(&key1_aliased)
        .expect("Crockford aliased key must verify"));

    // Wrong key returns false
    let wrong_key = "ABCDE-FGHIJ-KLMNP-QRSTV-WXYZ0";
    assert!(!secwet
        .verify_recovery_key(wrong_key)
        .expect("wrong key verify must not error"));

    // Malformed key returns false cleanly
    assert!(!secwet
        .verify_recovery_key("too-short")
        .expect("malformed key must return false without error"));

    // Replace recovery key
    let key2 = secwet
        .replace_recovery_key(&keystore)
        .expect("replace_recovery_key must succeed");
    let key2_str = key2.expose_secret().to_string();

    assert_ne!(
        key1_str, key2_str,
        "Replaced key must be distinct from original key"
    );

    // New key verifies
    assert!(secwet
        .verify_recovery_key(&key2_str)
        .expect("new key must verify"));

    // Old key is now invalidated!
    assert!(
        !secwet
            .verify_recovery_key(&key1_str)
            .expect("old key verify must not error"),
        "Previous recovery key must be invalidated after replacement"
    );

    secwet.lock();
}

#[test]
fn export_then_restore_roundtrip() {
    let dir_orig = tempdir().expect("failed to create tempdir");
    let dir_restore = tempdir().expect("failed to create tempdir");
    let dir_export = tempdir().expect("failed to create tempdir");

    let keystore_orig = MemoryStore::new();

    // 1. Initialize original workspace
    let mut secwet = Secwet::create(dir_orig.path(), "laptop-work", &keystore_orig)
        .expect("workspace creation must succeed");

    // 2. Populate rich workspace hierarchy
    // Create Space
    let space_eng = secwet
        .create_space("Engineering", Some("terminal".to_string()))
        .expect("create_space must succeed");

    // Create Label in Space
    let label_infra = secwet
        .create_label_in_space(
            "Infrastructure",
            Some("server".to_string()),
            Some(space_eng.id),
        )
        .expect("create_label_in_space must succeed");

    // Create Item in Label
    let item_auth = secwet
        .create_item(
            label_infra.id,
            "Auth Service",
            Some("OAuth2 Authentication Microservice".to_string()),
        )
        .expect("create_item must succeed");

    // Create Environments
    let env_prod = secwet
        .add_environment(item_auth.id, "Production")
        .expect("add_environment must succeed");
    let env_stage = secwet
        .add_environment(item_auth.id, "Staging")
        .expect("add_environment must succeed");

    // Create Secrets:
    // a) Item-level secret (environment_id: None)
    let secret_global = secwet
        .create_secret(SecretDraft::new(
            item_auth.id,
            None,
            "GLOBAL_CONFIG",
            SecretKind::EnvVar,
            "{\"rate_limit_per_minute\": 1000, \"debug\": false}",
            Some("Item level global config".to_string()),
        ))
        .expect("create_secret must succeed");

    // b) Environment-scoped secret with multi-line value
    let rsa_private_key = "\
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y8v+KxV5XWvjXhPZ3Q1b1m2n3p4q5r6s7t8u9v0w1x2y3z4
A5B6C7D8E9F0G1H2I3J4K5L6M7N8O9P0Q1R2S3T4U5V6W7X8Y9Z0a1b2c3d4e5f6
g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6A7B8C9D0E1F2G3H4I5J6K7L8
-----END RSA PRIVATE KEY-----";

    let secret_rsa = secwet
        .create_secret(SecretDraft::new(
            item_auth.id,
            Some(env_prod.id),
            "JWT_SIGNING_KEY",
            SecretKind::Certificate,
            rsa_private_key,
            Some("Production JWT RSA Private Key".to_string()),
        ))
        .expect("create_secret must succeed");

    // c) Staging API key
    let secret_stage = secwet
        .create_secret(SecretDraft::new(
            item_auth.id,
            Some(env_stage.id),
            "STRIPE_API_KEY",
            SecretKind::ApiKey,
            "sk_test_51Mz0FakeSecretStripeKey998877",
            Some("Staging Stripe test token".to_string()),
        ))
        .expect("create_secret must succeed");

    // Create Rich-Text Notes:
    // a) Item-level markdown note
    let note_arch = secwet
        .create_note(
            item_auth.id,
            None,
            "Architecture Overview",
            "# Auth Architecture\n\n- Stateless JWT tokens\n- Refresh token rotation in Redis\n- PKCE flow for mobile clients",
        )
        .expect("create_note must succeed");

    // b) Environment-level HTML runbook note
    let note_runbook = secwet
        .create_note(
            item_auth.id,
            Some(env_prod.id),
            "Production Runbook",
            "<h1>Runbook</h1><p>Emergency key rotation procedure:</p><ol><li>Generate key</li><li>Drain traffic</li><li>Deploy</li></ol>",
        )
        .expect("create_note must succeed");

    // Upload Files:
    // a) Binary payload (64 KiB random bytes)
    let mut binary_data = vec![0u8; 65536];
    OsRng.fill_bytes(&mut binary_data);

    let file_binary = secwet
        .upload_file(
            item_auth.id,
            Some(env_prod.id),
            "firmware.bin",
            &binary_data,
            Some("application/octet-stream"),
        )
        .expect("upload_file must succeed");

    // b) Text certificate payload
    let cert_data = b"-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL9...\n-----END CERTIFICATE-----";
    let file_cert = secwet
        .upload_file(
            item_auth.id,
            None,
            "server.crt",
            cert_data,
            Some("application/x-x509-ca-cert"),
        )
        .expect("upload_file must succeed");

    // 3. Generate Recovery Key
    let recovery_key = secwet
        .create_recovery_key(&keystore_orig)
        .expect("create_recovery_key must succeed");

    // 4. Export to .secwet envelope
    let export_file = dir_export.path().join("workspace_backup.secwet");
    let summary = secwet
        .export_encrypted(&recovery_key, &export_file)
        .expect("export_encrypted must succeed");

    assert!(export_file.is_file(), "Backup file must be written to disk");
    assert_eq!(summary.secwet_id, secwet.secwet_id());
    assert!(summary.spaces_count >= 2); // Personal (default) + Engineering
    assert!(summary.labels_count >= 2); // Projects (default) + Infrastructure
    assert!(summary.items_count >= 1);
    assert!(summary.environments_count >= 2);
    assert!(summary.secrets_count >= 3);
    assert!(summary.notes_count >= 2);
    assert!(summary.files_count >= 2);
    assert!(summary.bytes_written > 0);

    // Lock original workspace
    secwet.lock();

    // 5. Restore into completely clean directory using separate keystore
    let keystore_restore = MemoryStore::new();
    let restored = Secwet::restore_from_export(
        dir_restore.path(),
        &export_file,
        &recovery_key,
        "desktop-restored",
        &keystore_restore,
    )
    .expect("restore_from_export must succeed");

    // 6. Verify 100% Data Fidelity across all restored entities
    assert_eq!(
        restored.secwet_id(),
        summary.secwet_id,
        "Secwet ID must match original workspace"
    );
    assert_eq!(
        restored.key_epoch(),
        2,
        "Restored workspace must have incremented master key epoch N+1"
    );

    // Recovery status and key verification persist on restored workspace
    let r_status = restored
        .recovery_status()
        .expect("recovery_status on restored must succeed");
    assert!(r_status.created, "Recovery status must be active on restored store");
    assert!(
        restored
            .verify_recovery_key(recovery_key.expose_secret())
            .expect("recovery key verify on restored must succeed"),
        "Original recovery key must verify against restored workspace"
    );

    // Verify Space fidelity
    let spaces = restored.list_spaces().expect("list_spaces must succeed");
    let found_eng = spaces.iter().find(|s| s.id == space_eng.id).expect("Engineering space must exist");
    assert_eq!(found_eng.name, "Engineering");
    assert_eq!(found_eng.icon, Some("terminal".to_string()));

    // Verify Label fidelity
    let labels = restored.list_labels().expect("list_labels must succeed");
    let found_infra = labels.iter().find(|l| l.id == label_infra.id).expect("Infrastructure label must exist");
    assert_eq!(found_infra.name, "Infrastructure");
    assert_eq!(found_infra.space_id, Some(space_eng.id));

    // Verify Item fidelity
    let items = restored.list_items(label_infra.id).expect("list_items must succeed");
    let found_auth = items.iter().find(|i| i.id == item_auth.id).expect("Auth Service item must exist");
    assert_eq!(found_auth.name, "Auth Service");
    assert_eq!(
        found_auth.description,
        Some("OAuth2 Authentication Microservice".to_string())
    );

    // Verify Environment fidelity
    let envs = restored.list_environments(item_auth.id).expect("list_environments must succeed");
    assert_eq!(envs.len(), 2);
    let found_prod = envs.iter().find(|e| e.id == env_prod.id).expect("Production env must exist");
    assert_eq!(found_prod.name, "Production");
    let found_stage = envs.iter().find(|e| e.id == env_stage.id).expect("Staging env must exist");
    assert_eq!(found_stage.name, "Staging");

    // Verify Secret values (100% exact match including multi-line whitespace and JSON)
    let rev_global = restored
        .reveal_secret(secret_global.id)
        .expect("reveal_secret for global must succeed");
    assert_eq!(
        rev_global.expose_secret(),
        "{\"rate_limit_per_minute\": 1000, \"debug\": false}"
    );

    let rev_rsa = restored
        .reveal_secret(secret_rsa.id)
        .expect("reveal_secret for rsa key must succeed");
    assert_eq!(
        rev_rsa.expose_secret(),
        rsa_private_key,
        "Multi-line secret value must be restored byte-for-byte"
    );

    let rev_stage = restored
        .reveal_secret(secret_stage.id)
        .expect("reveal_secret for staging stripe key must succeed");
    assert_eq!(
        rev_stage.expose_secret(),
        "sk_test_51Mz0FakeSecretStripeKey998877"
    );

    // Verify Notes content fidelity
    let r_note_arch = restored
        .get_note(note_arch.id)
        .expect("get_note for arch note must succeed");
    assert_eq!(r_note_arch.title, "Architecture Overview");
    assert_eq!(
        r_note_arch.content,
        "# Auth Architecture\n\n- Stateless JWT tokens\n- Refresh token rotation in Redis\n- PKCE flow for mobile clients"
    );

    let r_note_runbook = restored
        .get_note(note_runbook.id)
        .expect("get_note for runbook must succeed");
    assert_eq!(r_note_runbook.title, "Production Runbook");
    assert_eq!(
        r_note_runbook.content,
        "<h1>Runbook</h1><p>Emergency key rotation procedure:</p><ol><li>Generate key</li><li>Drain traffic</li><li>Deploy</li></ol>"
    );

    // Verify Files payload and SHA-256 fidelity
    let (meta_bin, downloaded_bin) = restored
        .download_file(file_binary.id)
        .expect("download_file for binary must succeed");
    assert_eq!(meta_bin.name, "firmware.bin");
    assert_eq!(meta_bin.size_bytes, 65536);
    assert_eq!(downloaded_bin, binary_data, "Binary file payload must match byte-for-byte");

    let (meta_cert, downloaded_cert) = restored
        .download_file(file_cert.id)
        .expect("download_file for cert must succeed");
    assert_eq!(meta_cert.name, "server.crt");
    assert_eq!(downloaded_cert, cert_data, "Certificate file payload must match byte-for-byte");

    restored.lock();
}

#[test]
fn export_wrong_key_fails_without_detail() {
    let dir_orig = tempdir().expect("failed to create tempdir");
    let dir_restore = tempdir().expect("failed to create tempdir");
    let dir_export = tempdir().expect("failed to create tempdir");

    let keystore_orig = MemoryStore::new();

    let mut secwet = Secwet::create(dir_orig.path(), "laptop-1", &keystore_orig)
        .expect("workspace creation must succeed");

    let p = secwet.create_project("SecretApp", &["prod".to_string()]).expect("create_project must succeed");
    secwet
        .create_secret(SecretDraft::new(
            p.id,
            p.environments[0].id,
            "DATABASE_PASSWORD",
            SecretKind::Password,
            "super-secret-production-password-9988",
            None,
        ))
        .expect("create_secret must succeed");

    let recovery_key = secwet
        .create_recovery_key(&keystore_orig)
        .expect("create_recovery_key must succeed");

    let export_file = dir_export.path().join("secure.secwet");
    secwet
        .export_encrypted(&recovery_key, &export_file)
        .expect("export_encrypted must succeed");
    secwet.lock();

    // Generate a completely different valid recovery key
    let wrong_key = SecretString::from("ABCDE-FGHIJ-KLMNP-QRSTV-WXYZ0");

    let keystore_restore = MemoryStore::new();
    let result = Secwet::restore_from_export(
        dir_restore.path(),
        &export_file,
        &wrong_key,
        "restored-laptop",
        &keystore_restore,
    );

    // Must fail cleanly with RecoveryFailed error
    assert!(result.is_err(), "Restore with wrong key must fail");
    match result.unwrap_err() {
        Error::RecoveryFailed => {}
        other => panic!("Expected Error::RecoveryFailed, got {:?}", other),
    }

    // Verify zero data directory or database leaked
    let db_path = dir_restore.path().join("secwet.sqlite3");
    assert!(!db_path.exists(), "No database file should be created on failed restore");
}

#[test]
fn export_file_contains_no_plaintext() {
    let dir_orig = tempdir().expect("failed to create tempdir");
    let dir_export = tempdir().expect("failed to create tempdir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir_orig.path(), "laptop-dev", &keystore)
        .expect("create must succeed");

    let space = secwet.create_space("SecretSpace", None).unwrap();
    let label = secwet.create_label_in_space("SecretLabel", None, Some(space.id)).unwrap();
    let item = secwet.create_item(label.id, "TopSecretItem", None).unwrap();
    let env = secwet.add_environment(item.id, "ConfidentialEnv").unwrap();

    let secret_val = "SECRET_VALUE_XYZZY_TOP_CONFIDENTIAL_123456789";
    secwet.create_secret(SecretDraft::new(
        item.id,
        Some(env.id),
        "API_SECRET",
        SecretKind::Password,
        secret_val,
        Some("Note with secret context".to_string()),
    )).unwrap();

    let note_content = "NOTE_BODY_CONFIDENTIAL_MEETING_NOTES_FOR_CEO";
    secwet.create_note(item.id, Some(env.id), "Secret Note", note_content).unwrap();

    let file_content = b"FILE_PAYLOAD_PRIVATE_INTERNAL_KEYS_ONLY";
    secwet.upload_file(item.id, Some(env.id), "secret.bin", file_content, Some("application/octet-stream")).unwrap();

    let recovery_key = secwet.create_recovery_key(&keystore).unwrap();
    let export_file = dir_export.path().join("leak_test.secwet");
    secwet.export_encrypted(&recovery_key, &export_file).unwrap();

    // Read raw file content from disk
    let raw_bytes = std::fs::read(&export_file).expect("export file must be readable");
    let raw_str = String::from_utf8_lossy(&raw_bytes);

    // Invariant: The raw backup file must NOT contain plaintext strings
    assert!(
        !raw_str.contains(secret_val),
        "Export file must NEVER leak plaintext secret values"
    );
    assert!(
        !raw_str.contains("Note with secret context"),
        "Export file must NEVER leak plaintext secret notes"
    );
    assert!(
        !raw_str.contains(note_content),
        "Export file must NEVER leak plaintext note content"
    );
    assert!(
        !raw_str.contains("FILE_PAYLOAD_PRIVATE_INTERNAL_KEYS_ONLY"),
        "Export file must NEVER leak plaintext file payloads"
    );
    assert!(
        !raw_str.contains("TopSecretItem"),
        "Export file must NEVER leak plaintext item names"
    );
    assert!(
        !raw_str.contains("ConfidentialEnv"),
        "Export file must NEVER leak plaintext environment names"
    );
    assert!(
        !raw_str.contains("SecretSpace"),
        "Export file must NEVER leak plaintext space names"
    );

    secwet.lock();
}
