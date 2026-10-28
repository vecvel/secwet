//! Empirical Stress Test: CLI .secwet Export Roundtrip & Data Fidelity
//!
//! Mandatory Task 1:
//! 1. End-to-end CLI `.secwet` export roundtrip:
//!    - Create workspace with spaces, secrets, files, notes via CLI.
//!    - Export using `secwet export --out <file.secwet>`.
//!    - Restore to clean state and verify 100% data fidelity.
//! 2. Plaintext export flag enforcement:
//!    - `secwet export --env <name> --format dotenv --out .env` requires `--plaintext`.

use assert_cmd::Command;
use predicates::prelude::*;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::model::SecretKind;
use secwet_core::Secwet;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn init_empty_secwet(data_dir: &Path) -> Secwet {
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    Secwet::create(data_dir, "challenger-cli-device", &keystore).expect("create secwet")
}

#[test]
fn test_cli_secwet_export_roundtrip_100_percent_fidelity() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    // Step 1: Initialize workspace and create recovery key
    let mut initial_secwet = init_empty_secwet(data_dir);
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let recovery_key = initial_secwet
        .create_recovery_key(&keystore)
        .expect("create recovery key");
    let recovery_key_str = secrecy::ExposeSecret::expose_secret(&recovery_key).to_string();
    initial_secwet.lock();

    // Step 2: Populate workspace using CLI commands ONLY
    // 2.1 Spaces
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["space", "create", "Platform Infrastructure", "--icon", "server"])
        .assert()
        .success();

    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["space", "create", "Financial Operations", "--icon", "dollar-sign"])
        .assert()
        .success();

    // 2.2 Groups in Spaces
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "create", "Cloud Services", "--space", "Platform Infrastructure"])
        .assert()
        .success();

    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "create", "Billing Engine", "--space", "Financial Operations"])
        .assert()
        .success();

    // 2.3 Items in Groups
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["item", "create", "auth-gateway", "--group", "Cloud Services"])
        .assert()
        .success();

    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["item", "create", "payment-service", "--group", "Billing Engine"])
        .assert()
        .success();

    // 2.4 Environments
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["env", "create", "staging", "-i", "auth-gateway"])
        .assert()
        .success();

    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["env", "create", "production", "-i", "auth-gateway"])
        .assert()
        .success();

    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["env", "create", "production", "-i", "payment-service"])
        .assert()
        .success();

    // 2.5 Secrets with different kinds and notes
    // Secret 1: Password
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "secret", "set", "DB_PASSWORD",
            "-i", "auth-gateway",
            "-e", "production",
            "--kind", "password",
            "--value", "P@ssw0rd_Super_Secret_999!",
            "--note", "Primary Aurora Cluster Password",
        ])
        .assert()
        .success();

    // Secret 2: ApiKey
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "secret", "set", "STRIPE_SECRET_KEY",
            "-i", "payment-service",
            "-e", "production",
            "--kind", "api_key",
            "--value", "sk_live_stripe_key_00112233445566778899",
            "--note", "Production Stripe API Token",
        ])
        .assert()
        .success();

    // Secret 3: EnvVar with multiline JSON payload
    let multiline_payload = "{\"client_id\":\"secwet-oauth\",\"grant_types\":[\"authorization_code\",\"refresh_token\"]}";
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "secret", "set", "OAUTH_CONFIG_JSON",
            "-i", "auth-gateway",
            "-e", "staging",
            "--kind", "env_var",
            "--value", multiline_payload,
        ])
        .assert()
        .success();

    // 2.6 Binary File Asset Upload
    let binary_file_path = data_dir.join("tls_ca_cert.bin");
    let mut binary_bytes = Vec::with_capacity(4096);
    for i in 0..4096 {
        binary_bytes.push((i % 256) as u8);
    }
    fs::write(&binary_file_path, &binary_bytes).unwrap();

    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "file", "upload",
            binary_file_path.to_str().unwrap(),
            "-i", "auth-gateway",
            "-e", "production",
            "--name", "ca-certificate.bin",
        ])
        .assert()
        .success();

    // 2.7 Rich Markdown Note
    let note_content = "# Disaster Recovery Protocol\n\n1. Verify HSM status.\n2. Restore `.secwet` snapshot.\n3. Re-issue TLS certs.";
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "note", "create", "Disaster Recovery SOP",
            "-i", "auth-gateway",
            "-e", "production",
            "--content", note_content,
        ])
        .assert()
        .success();

    let export_target = data_dir.join("enterprise_backup.secwet");

    // Step 3: Adversarial test - export with wrong key must fail
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", export_target.to_str().unwrap()])
        .write_stdin("00000-00000-00000-00000-00000\n")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error:"));

    assert!(!export_target.exists());

    // Step 4: Export with normalized Crockford recovery key (aliases, spaces, dashes)
    // Crockford substitutions: 1 -> I, 0 -> O
    let mut aliased_key = recovery_key_str.replace('1', "I").replace('0', "O").to_lowercase();
    aliased_key.insert(4, ' ');
    aliased_key.insert(12, ' ');

    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", export_target.to_str().unwrap()])
        .write_stdin(format!("{}\n", aliased_key))
        .assert()
        .success()
        .stderr(predicate::str::contains("Exported"));

    assert!(export_target.exists());

    // Step 5: Invariant - Export file contains zero plaintext
    let raw_envelope_bytes = fs::read(&export_target).unwrap();
    let envelope_str = String::from_utf8_lossy(&raw_envelope_bytes);
    assert!(!envelope_str.contains("P@ssw0rd_Super_Secret_999!"));
    assert!(!envelope_str.contains("sk_live_stripe_key_00112233445566778899"));
    assert!(!envelope_str.contains("Disaster Recovery Protocol"));
    assert!(!envelope_str.contains("Primary Aurora Cluster Password"));

    // Step 6: Restore onto clean workspace and verify 100% data fidelity
    let clean_temp = tempdir().unwrap();
    let clean_dir = clean_temp.path();
    let clean_keystore = FileKeyStore::new(clean_dir.join(".test_keystore.json"));

    // 6.1 Wrong key restore fails
    let bad_restore = Secwet::restore_from_export(
        clean_dir,
        &export_target,
        &secrecy::SecretString::from("ABCDE-FGHIJ-KLMNO-PQRST-UVWXY".to_string()),
        "restored-challenger-device",
        &clean_keystore,
    );
    assert!(bad_restore.is_err());

    // 6.2 Valid key restore succeeds
    let restored_secwet = Secwet::restore_from_export(
        clean_dir,
        &export_target,
        &secrecy::SecretString::from(recovery_key_str.clone()),
        "restored-challenger-device",
        &clean_keystore,
    )
    .expect("restore from export must succeed");

    // Step 7: Verify 100% Data Fidelity on Restored Instance
    // 7.1 Verify spaces
    let spaces = restored_secwet.list_spaces().expect("list spaces");
    let plat_space = spaces.iter().find(|s| s.name == "Platform Infrastructure").expect("Platform Infrastructure space exists");
    assert_eq!(plat_space.icon.as_deref(), Some("server"));
    let fin_space = spaces.iter().find(|s| s.name == "Financial Operations").expect("Financial Operations space exists");
    assert_eq!(fin_space.icon.as_deref(), Some("dollar-sign"));

    // 7.2 Verify groups
    let groups = restored_secwet.list_labels().expect("list labels/groups");
    let cloud_grp = groups.iter().find(|g| g.name == "Cloud Services").expect("Cloud Services group exists");
    assert_eq!(cloud_grp.space_id, Some(plat_space.id));
    let bill_grp = groups.iter().find(|g| g.name == "Billing Engine").expect("Billing Engine group exists");
    assert_eq!(bill_grp.space_id, Some(fin_space.id));

    // 7.3 Verify items
    let auth_item = restored_secwet.list_items(cloud_grp.id).expect("list items").remove(0);
    assert_eq!(auth_item.name, "auth-gateway");
    let payment_item = restored_secwet.list_items(bill_grp.id).expect("list items").remove(0);
    assert_eq!(payment_item.name, "payment-service");

    // 7.4 Verify environments
    let auth_envs = restored_secwet.list_environments(auth_item.id).expect("list environments");
    assert_eq!(auth_envs.len(), 2);
    let prod_env = auth_envs.iter().find(|e| e.name == "production").unwrap();
    let stag_env = auth_envs.iter().find(|e| e.name == "staging").unwrap();

    let pay_envs = restored_secwet.list_environments(payment_item.id).expect("list environments");
    let pay_prod_env = pay_envs.iter().find(|e| e.name == "production").unwrap();

    // 7.5 Verify secrets
    let prod_secrets = restored_secwet.list_secrets(auth_item.id, Some(prod_env.id)).expect("list secrets");
    assert_eq!(prod_secrets.len(), 1);
    let db_sec = &prod_secrets[0];
    assert_eq!(db_sec.name, "DB_PASSWORD");
    assert_eq!(db_sec.kind, SecretKind::Password);
    let db_val = restored_secwet.reveal_secret(db_sec.id).expect("reveal secret");
    assert_eq!(secrecy::ExposeSecret::expose_secret(&db_val), "P@ssw0rd_Super_Secret_999!");

    let pay_secrets = restored_secwet.list_secrets(payment_item.id, Some(pay_prod_env.id)).expect("list secrets");
    assert_eq!(pay_secrets.len(), 1);
    let stripe_sec = &pay_secrets[0];
    assert_eq!(stripe_sec.name, "STRIPE_SECRET_KEY");
    assert_eq!(stripe_sec.kind, SecretKind::ApiKey);
    let stripe_val = restored_secwet.reveal_secret(stripe_sec.id).expect("reveal secret");
    assert_eq!(secrecy::ExposeSecret::expose_secret(&stripe_val), "sk_live_stripe_key_00112233445566778899");

    let stag_secrets = restored_secwet.list_secrets(auth_item.id, Some(stag_env.id)).expect("list secrets");
    assert_eq!(stag_secrets.len(), 1);
    let oauth_sec = &stag_secrets[0];
    assert_eq!(oauth_sec.name, "OAUTH_CONFIG_JSON");
    assert_eq!(oauth_sec.kind, SecretKind::EnvVar);
    let oauth_val = restored_secwet.reveal_secret(oauth_sec.id).expect("reveal secret");
    assert_eq!(secrecy::ExposeSecret::expose_secret(&oauth_val), multiline_payload);

    // 7.6 Verify binary file asset byte-for-byte fidelity
    let files = restored_secwet.list_files(auth_item.id, Some(prod_env.id)).expect("list files");
    assert_eq!(files.len(), 1);
    let file_meta = &files[0];
    assert_eq!(file_meta.name, "ca-certificate.bin");
    assert_eq!(file_meta.size_bytes, 4096);
    let (_meta, downloaded_bytes) = restored_secwet.download_file(file_meta.id).expect("download file");
    assert_eq!(downloaded_bytes, binary_bytes);

    // 7.7 Verify rich markdown note
    let notes = restored_secwet.list_notes(auth_item.id, Some(prod_env.id)).expect("list notes");
    assert_eq!(notes.len(), 1);
    let note_view = restored_secwet.get_note(notes[0].id).expect("get note");
    assert_eq!(note_view.title, "Disaster Recovery SOP");
    assert_eq!(note_view.content, note_content);

    // 7.8 Verify recovery status remains set
    let rec_status = restored_secwet.recovery_status().expect("recovery status");
    assert!(rec_status.created);
}

#[test]
fn test_cli_export_plaintext_flag_protections() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = init_empty_secwet(data_dir);
    let label = secwet.create_label("General", None).unwrap();
    let item = secwet.create_item(label.id, "api-server", None).unwrap();
    let env = secwet.add_environment(item.id, "production").unwrap();
    secwet
        .create_secret(secwet_core::model::SecretDraft::new(
            item.id,
            Some(env.id),
            "API_KEY",
            SecretKind::ApiKey,
            "secret_value_12345",
            None,
        ))
        .unwrap();
    secwet.lock();

    let out_dotenv = data_dir.join("exported.env");
    let out_json = data_dir.join("exported.json");

    // 1. Dotenv export without --plaintext flag must fail with exit code 1
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-i", "api-server",
            "-e", "production",
            "--format", "dotenv",
            "--out", out_dotenv.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "error: exporting plaintext secrets requires the explicit --plaintext flag",
        ));

    assert!(!out_dotenv.exists());

    // 2. JSON export without --plaintext flag must fail with exit code 1
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-i", "api-server",
            "-e", "production",
            "--format", "json",
            "--out", out_json.to_str().unwrap(),
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "error: exporting plaintext secrets requires the explicit --plaintext flag",
        ));

    assert!(!out_json.exists());

    // 3. Dotenv export WITH --plaintext flag succeeds and prints warning to stderr
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-i", "api-server",
            "-e", "production",
            "--format", "dotenv",
            "--plaintext",
            "--out", out_dotenv.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "warning: exporting unencrypted plaintext secrets",
        ));

    assert!(out_dotenv.exists());
    let dotenv_content = fs::read_to_string(&out_dotenv).unwrap();
    assert!(dotenv_content.contains("API_KEY=\"secret_value_12345\""));

    // 4. JSON export WITH --plaintext flag succeeds and prints warning to stderr
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-i", "api-server",
            "-e", "production",
            "--format", "json",
            "--plaintext",
            "--out", out_json.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "warning: exporting unencrypted plaintext secrets",
        ));

    assert!(out_json.exists());
    let json_content = fs::read_to_string(&out_json).unwrap();
    assert!(json_content.contains("secret_value_12345"));
}
