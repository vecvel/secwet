//! Challenger Adversarial Integration Test Suite.
//!
//! Verifies:
//! 1. `secwet export` strictly rejects unencrypted `dotenv` export without `--plaintext`
//! 2. `secwet export` strictly rejects unencrypted `json` export without `--plaintext`
//! 3. `secwet export` to `.secwet` with empty recovery key rejects with code 1
//! 4. `secwet export` to `.secwet` with wrong recovery key rejects with code 1
//! 5. `secwet export` to `.secwet` with invalid Crockford characters rejects with code 1
//! 6. `secwet export` to `.secwet` with valid recovery key succeeds with zero plaintext leakage
//! 7. Restoring from corrupted `.secwet` archives (tampered MAC, truncated file, invalid JSON, wrong key) strictly fails

use assert_cmd::Command;
use predicates::prelude::*;
use secrecy::ExposeSecret;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::{Error, SecretDraft, SecretKind, Secwet};
use std::path::Path;
use tempfile::tempdir;

fn setup_secwet_with_item(data_dir: &Path, item_name: &str, secret_key: &str, secret_val: &str) -> (Secwet, String) {
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "challenger-cli-device", &keystore).expect("create secwet");
    let recovery_key = secwet.create_recovery_key(&keystore).expect("create recovery key");
    let recovery_key_str = recovery_key.expose_secret().to_string();

    let label = secwet.create_label("Security", None).expect("create label");
    let item = secwet.create_item(label.id, item_name, None).expect("create item");
    let env = secwet.add_environment(item.id, "production").expect("add env");

    secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(env.id),
            secret_key,
            SecretKind::Password,
            secret_val,
            None,
        ))
        .expect("create secret");

    (secwet, recovery_key_str)
}

#[test]
fn test_adversarial_dotenv_export_without_plaintext_flag_strictly_rejected() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let (secwet, _) = setup_secwet_with_item(data_dir, "api-gateway", "GATEWAY_TOKEN", "super-secret-jwt-token-999");
    secwet.lock();

    let out_file = data_dir.join("export.env");

    // Scenario A: Export to file path without --plaintext
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "--item",
            "api-gateway",
            "--env",
            "production",
            "--format",
            "dotenv",
            "--out",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error: exporting plaintext secrets requires the explicit --plaintext flag"));

    assert!(!out_file.exists(), "Output file must not be created on failure");

    // Scenario B: Export to stdout without --plaintext
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "--item",
            "api-gateway",
            "--env",
            "production",
            "--format",
            "dotenv",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error: exporting plaintext secrets requires the explicit --plaintext flag"))
        .stdout(predicate::str::contains("super-secret-jwt-token-999").not());

    // Scenario C: Export with explicit --plaintext succeeds with warning
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "--item",
            "api-gateway",
            "--env",
            "production",
            "--format",
            "dotenv",
            "--plaintext",
            "--out",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("warning: exporting unencrypted plaintext secrets"));

    assert!(out_file.exists());
    let content = std::fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("GATEWAY_TOKEN=\"super-secret-jwt-token-999\""));
}

#[test]
fn test_adversarial_json_export_without_plaintext_flag_strictly_rejected() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let (secwet, _) = setup_secwet_with_item(data_dir, "billing-service", "STRIPE_KEY", "sk_live_adversarial_secret_123");
    secwet.lock();

    let out_file = data_dir.join("export.json");

    // Scenario A: Export json to file without --plaintext
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "--item",
            "billing-service",
            "--env",
            "production",
            "--format",
            "json",
            "--out",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error: exporting plaintext secrets requires the explicit --plaintext flag"));

    assert!(!out_file.exists(), "Output json file must not be created on failure");

    // Scenario B: Export json to stdout without --plaintext
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "--item",
            "billing-service",
            "--env",
            "production",
            "--format",
            "json",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error: exporting plaintext secrets requires the explicit --plaintext flag"))
        .stdout(predicate::str::contains("sk_live_adversarial_secret_123").not());

    // Scenario C: Export json with --plaintext succeeds with warning
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "--item",
            "billing-service",
            "--env",
            "production",
            "--format",
            "json",
            "--plaintext",
            "--out",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("warning: exporting unencrypted plaintext secrets"));

    assert!(out_file.exists());
    let content = std::fs::read_to_string(&out_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("valid json output");
    assert!(parsed.is_object());
    assert_eq!(parsed["STRIPE_KEY"], "sk_live_adversarial_secret_123");
}

#[test]
fn test_adversarial_secwet_export_empty_recovery_key_rejected() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let (secwet, _) = setup_secwet_with_item(data_dir, "auth-hub", "SECRET_KEY", "val");
    secwet.lock();

    let backup_file = data_dir.join("backup.secwet");

    // Provide empty input via stdin
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", backup_file.to_str().unwrap()])
        .write_stdin("\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error: recovery key cannot be empty"));

    assert!(!backup_file.exists());

    // Provide whitespace-only input via stdin
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", backup_file.to_str().unwrap()])
        .write_stdin("   \t  \r\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error: recovery key cannot be empty"));

    assert!(!backup_file.exists());
}

#[test]
fn test_adversarial_secwet_export_wrong_and_corrupted_key_rejected() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let (secwet, _valid_key) = setup_secwet_with_item(data_dir, "auth-hub", "KEY_X", "secret_x");
    secwet.lock();

    let backup_file = data_dir.join("backup.secwet");

    // Scenario A: Syntactically valid Crockford key, but WRONG key for this workspace
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", backup_file.to_str().unwrap()])
        .write_stdin("00000-00000-00000-00000-00000\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error:"));

    assert!(!backup_file.exists());

    // Scenario B: Invalid Crockford characters ('U' is illegal in Crockford Base32)
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", backup_file.to_str().unwrap()])
        .write_stdin("UUUUU-UUUUU-UUUUU-UUUUU-UUUUU\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error:"));

    assert!(!backup_file.exists());

    // Scenario C: Malformed symbols / punctuation
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", backup_file.to_str().unwrap()])
        .write_stdin("!@#$%^&*()_+{}[]|\n")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error:"));

    assert!(!backup_file.exists());
}

#[test]
fn test_adversarial_secwet_export_and_restore_roundtrip_with_tamper_defense() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let secret_payload = "HIGHLY_CONFIDENTIAL_PLAINTEXT_SECRET_STRING_42";
    let (secwet, valid_key) = setup_secwet_with_item(data_dir, "prod-db", "DB_PASS", secret_payload);
    secwet.lock();

    let backup_file = data_dir.join("clean_archive.secwet");

    // 1. Export with valid recovery key
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", backup_file.to_str().unwrap()])
        .write_stdin(format!("{}\n", valid_key))
        .assert()
        .success()
        .stderr(predicate::str::contains("Exported"));

    assert!(backup_file.exists());

    // 2. Invariant: Export archive contains ZERO plaintext secrets
    let file_bytes = std::fs::read(&backup_file).unwrap();
    let file_str = String::from_utf8_lossy(&file_bytes);
    assert!(!file_str.contains(secret_payload));
    assert!(!file_str.contains("DB_PASS"));

    // 3. Test Restore with wrong recovery key fails strictly with RecoveryFailed
    let restore_temp = tempdir().unwrap();
    let restore_keystore = FileKeyStore::new(restore_temp.path().join(".test_keystore.json"));
    let err = Secwet::restore_from_export(
        restore_temp.path(),
        &backup_file,
        &secrecy::SecretString::from("00000-00000-00000-00000-00000".to_string()),
        "tamper-device",
        &restore_keystore,
    )
    .unwrap_err();
    assert!(matches!(err, Error::RecoveryFailed));

    // 4. Test Restore with tampered ciphertext (bit flip) fails strictly with RecoveryFailed
    let mut envelope: serde_json::Value = serde_json::from_str(&file_str).unwrap();
    let mut raw_ct = data_encoding::BASE64.decode(envelope["ciphertext"].as_str().unwrap().as_bytes()).unwrap();
    raw_ct[10] ^= 0x01; // flip 1 bit
    envelope["ciphertext"] = serde_json::Value::String(data_encoding::BASE64.encode(&raw_ct));
    let tampered_file = restore_temp.path().join("tampered_ct.secwet");
    std::fs::write(&tampered_file, serde_json::to_string(&envelope).unwrap()).unwrap();

    let err_ct = Secwet::restore_from_export(
        restore_temp.path(),
        &tampered_file,
        &secrecy::SecretString::from(valid_key.clone()),
        "tamper-device",
        &restore_keystore,
    )
    .unwrap_err();
    assert!(matches!(err_ct, Error::RecoveryFailed));

    // 5. Test Restore with truncated 0-byte file fails strictly with RecoveryFailed
    let empty_file = restore_temp.path().join("empty.secwet");
    std::fs::write(&empty_file, b"").unwrap();
    let err_empty = Secwet::restore_from_export(
        restore_temp.path(),
        &empty_file,
        &secrecy::SecretString::from(valid_key.clone()),
        "tamper-device",
        &restore_keystore,
    )
    .unwrap_err();
    assert!(matches!(err_empty, Error::RecoveryFailed));

    // 6. Test Restore with valid key succeeds with 100% data fidelity
    let clean_restore_temp = tempdir().unwrap();
    let clean_keystore = FileKeyStore::new(clean_restore_temp.path().join(".test_keystore.json"));
    let restored = Secwet::restore_from_export(
        clean_restore_temp.path(),
        &backup_file,
        &secrecy::SecretString::from(valid_key),
        "clean-restored-device",
        &clean_keystore,
    )
    .expect("restore must succeed");

    let labels = restored.list_labels().unwrap();
    let sec_label = labels.iter().find(|l| l.name == "Security").expect("Security label exists");

    let items = restored.list_items(sec_label.id).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].name, "prod-db");

    let envs = restored.list_environments(items[0].id).unwrap();
    assert_eq!(envs.len(), 1);
    assert_eq!(envs[0].name, "production");

    let secrets = restored.list_secrets(items[0].id, Some(envs[0].id)).unwrap();
    assert_eq!(secrets.len(), 1);
    assert_eq!(secrets[0].name, "DB_PASS");

    let revealed = restored.reveal_secret(secrets[0].id).unwrap();
    assert_eq!(revealed.expose_secret(), secret_payload);
}
