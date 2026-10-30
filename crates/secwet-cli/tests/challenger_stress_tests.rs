use assert_cmd::Command;
use predicates::prelude::*;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::{SecretDraft, SecretKind, Secwet};
use std::path::Path;
use tempfile::tempdir;

fn setup_secwet(data_dir: &Path) -> Secwet {
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    Secwet::create(data_dir, "challenger-device", &keystore).expect("create secwet")
}

// =========================================================================
// 1. Exit Code 1 on Missing Item or Environment Errors
// =========================================================================

#[test]
fn test_exit_code_1_missing_item_across_all_commands() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let secwet = setup_secwet(data_dir);
    secwet.lock();

    let missing_item = "completely-nonexistent-item";

    // 1. List
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "-i", missing_item])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: item not found"));

    // 2. Get
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "SOME_KEY", "-i", missing_item])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: item not found"));

    // 3. Run
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["run", "-i", missing_item, "--", "echo", "hello"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: item not found"));

    // 4. Set
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "SOME_KEY", "-i", missing_item])
        .write_stdin("value")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: item not found"));

    // 5. Import
    let dummy_env = data_dir.join("dummy.env");
    std::fs::write(&dummy_env, "FOO=BAR\n").unwrap();
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["import", dummy_env.to_str().unwrap(), "-i", missing_item])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: item not found"));

    // 6. Export
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "-i", missing_item])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: item not found"));
}

#[test]
fn test_exit_code_1_missing_environment_across_all_commands() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_secwet(data_dir);
    let label = secwet.create_label("General", None).unwrap();
    let item = secwet.create_item(label.id, "my-service", None).unwrap();
    secwet.add_environment(item.id, "development").unwrap();
    secwet.lock();

    let missing_env = "nonexistent-env";

    // 1. List
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "-i", "my-service", "-e", missing_env])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: environment not found in item 'my-service'"));

    // 2. Get
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "SOME_KEY", "-i", "my-service", "-e", missing_env])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: environment not found in item 'my-service'"));

    // 3. Run
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["run", "-i", "my-service", "-e", missing_env, "--", "echo", "test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: environment not found in item 'my-service'"));

    // 4. Set
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "SOME_KEY", "-i", "my-service", "-e", missing_env])
        .write_stdin("val")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: environment not found in item 'my-service'"));

    // 5. Import
    let dummy_env = data_dir.join("dummy.env");
    std::fs::write(&dummy_env, "FOO=BAR\n").unwrap();
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["import", dummy_env.to_str().unwrap(), "-i", "my-service", "-e", missing_env])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: environment not found in item 'my-service'"));

    // 6. Export
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "-i", "my-service", "-e", missing_env])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: environment not found in item 'my-service'"));
}

#[test]
fn test_exit_code_1_zero_env_item_with_env_flag_across_all_commands() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_secwet(data_dir);
    let label = secwet.create_label("General", None).unwrap();
    let _item = secwet.create_item(label.id, "zero-env-svc", None).unwrap();
    secwet.lock();

    let err_msg = "error: item 'zero-env-svc' has no environments";

    // 1. List
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "-i", "zero-env-svc", "-e", "prod"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(err_msg));

    // 2. Get
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "SOME_KEY", "-i", "zero-env-svc", "-e", "prod"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(err_msg));

    // 3. Run
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["run", "-i", "zero-env-svc", "-e", "prod", "--", "echo", "test"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(err_msg));

    // 4. Set
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "SOME_KEY", "-i", "zero-env-svc", "-e", "prod"])
        .write_stdin("val")
        .assert()
        .code(1)
        .stderr(predicate::str::contains(err_msg));

    // 5. Import
    let dummy_env = data_dir.join("dummy.env");
    std::fs::write(&dummy_env, "FOO=BAR\n").unwrap();
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["import", dummy_env.to_str().unwrap(), "-i", "zero-env-svc", "-e", "prod"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(err_msg));

    // 6. Export
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "-i", "zero-env-svc", "-e", "prod"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(err_msg));
}

// =========================================================================
// 2. Exit Code 64 on Invalid Config TOML Syntax
// =========================================================================

#[test]
fn test_exit_code_64_invalid_secwet_toml_syntax() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    let toml_file = root.join(".secwet.toml");
    std::fs::write(&toml_file, "this is definitely not valid toml = [[[]]").unwrap();

    let deep_dir = root.join("src").join("pkg");
    std::fs::create_dir_all(&deep_dir).unwrap();

    // Any command executed here must fail with exit code 64
    Command::cargo_bin("secwet")
        .unwrap()
        .current_dir(&deep_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .arg("status")
        .assert()
        .code(64)
        .stderr(predicate::str::contains("error: configuration error: failed to parse"));

    Command::cargo_bin("secwet")
        .unwrap()
        .current_dir(&deep_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .arg("list")
        .assert()
        .code(64)
        .stderr(predicate::str::contains("error: configuration error: failed to parse"));
}

// =========================================================================
// 3. Parity Between --item, -i, --project, -p Across Subcommands
// =========================================================================

#[test]
fn test_cli_flags_item_project_aliases_complete_parity() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_secwet(data_dir);
    let label = secwet.create_label("General", None).unwrap();
    let item = secwet.create_item(label.id, "alias-target", None).unwrap();
    let draft = SecretDraft::new(item.id, None, "CANARY_FLAG", SecretKind::EnvVar, "flag_value_xyz", None);
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    let flag_combos = [
        vec!["-i", "alias-target"],
        vec!["--item", "alias-target"],
        vec!["-p", "alias-target"],
        vec!["--project", "alias-target"],
    ];

    for combo in &flag_combos {
        // 1. Get
        let mut get_args = vec!["get", "CANARY_FLAG"];
        get_args.extend_from_slice(combo);
        let out = Command::cargo_bin("secwet")
            .unwrap()
            .env("SECWET_DATA_DIR", data_dir)
            .env("SECWET_TEST_KEYSTORE", "memory")
            .args(&get_args)
            .assert()
            .success();
        assert_eq!(out.get_output().stdout, b"flag_value_xyz");

        // 2. List
        let mut list_args = vec!["list"];
        list_args.extend_from_slice(combo);
        Command::cargo_bin("secwet")
            .unwrap()
            .env("SECWET_DATA_DIR", data_dir)
            .env("SECWET_TEST_KEYSTORE", "memory")
            .args(&list_args)
            .assert()
            .success()
            .stdout(predicate::str::contains("CANARY_FLAG"));

        // 3. Run
        let mut run_args = vec!["run"];
        run_args.extend_from_slice(combo);
        run_args.extend_from_slice(&["--", "sh", "-c", "printf %s \"$CANARY_FLAG\""]);
        Command::cargo_bin("secwet")
            .unwrap()
            .env("SECWET_DATA_DIR", data_dir)
            .env("SECWET_TEST_KEYSTORE", "memory")
            .args(&run_args)
            .assert()
            .success()
            .stdout("flag_value_xyz");

        // 4. Export
        let mut exp_args = vec!["export", "-f", "json", "--plaintext"];
        exp_args.extend_from_slice(combo);
        let exp_out = Command::cargo_bin("secwet")
            .unwrap()
            .env("SECWET_DATA_DIR", data_dir)
            .env("SECWET_TEST_KEYSTORE", "memory")
            .args(&exp_args)
            .assert()
            .success();
        assert!(String::from_utf8_lossy(&exp_out.get_output().stdout).contains("\"CANARY_FLAG\": \"flag_value_xyz\""));
    }
}

// =========================================================================
// 4. Secret Inheritance & Shadowing Stress Test
// =========================================================================

#[test]
fn test_secret_inheritance_and_shadowing_deep_verification() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_secwet(data_dir);
    let label = secwet.create_label("General", None).unwrap();
    let item = secwet.create_item(label.id, "tiered-service", None).unwrap();
    let env_staging = secwet.add_environment(item.id, "staging").unwrap();
    let env_prod = secwet.add_environment(item.id, "production").unwrap();

    // 1. Secrets at item level (base)
    // BASE_SHARED: inherited by both staging and prod
    // DB_HOST: overridden in staging and prod
    // PROD_ONLY_BASE: overridden only in prod
    let d1 = SecretDraft::new(item.id, None, "BASE_SHARED", SecretKind::EnvVar, "shared_base_123", None);
    let d2 = SecretDraft::new(item.id, None, "DB_HOST", SecretKind::EnvVar, "db.base.local", None);
    let d3 = SecretDraft::new(item.id, None, "OVERRIDDEN_IN_PROD", SecretKind::EnvVar, "base_val", None);
    secwet.create_secret(d1).unwrap();
    secwet.create_secret(d2).unwrap();
    secwet.create_secret(d3).unwrap();

    // 2. Secrets in staging environment
    let s1 = SecretDraft::new(item.id, Some(env_staging.id), "DB_HOST", SecretKind::EnvVar, "db.staging.cloud", None);
    let s2 = SecretDraft::new(item.id, Some(env_staging.id), "STAGING_SPECIAL", SecretKind::EnvVar, "stage_only", None);
    secwet.create_secret(s1).unwrap();
    secwet.create_secret(s2).unwrap();

    // 3. Secrets in production environment
    let p1 = SecretDraft::new(item.id, Some(env_prod.id), "DB_HOST", SecretKind::EnvVar, "db.prod.cloud", None);
    let p2 = SecretDraft::new(item.id, Some(env_prod.id), "OVERRIDDEN_IN_PROD", SecretKind::EnvVar, "prod_override_val", None);
    let p3 = SecretDraft::new(item.id, Some(env_prod.id), "PROD_SECRET", SecretKind::ApiKey, "sk_live_prod_999", None);
    secwet.create_secret(p1).unwrap();
    secwet.create_secret(p2).unwrap();
    secwet.create_secret(p3).unwrap();
    secwet.lock();

    // A. Check Item with environments when no env specified:
    // Falls back to first environment (staging) in the absence of "development"
    let get_item_default_env = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "DB_HOST", "-i", "tiered-service"])
        .assert()
        .success();
    assert_eq!(get_item_default_env.get_output().stdout, b"db.staging.cloud");

    // Staging secret IS visible because it defaulted to staging environment
    let get_item_stg_special = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "STAGING_SPECIAL", "-i", "tiered-service"])
        .assert()
        .success();
    assert_eq!(get_item_stg_special.get_output().stdout, b"stage_only");

    // B. Check Staging environment:
    // - BASE_SHARED inherited from item
    let get_stg_shared = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "BASE_SHARED", "-i", "tiered-service", "-e", "staging"])
        .assert()
        .success();
    assert_eq!(get_stg_shared.get_output().stdout, b"shared_base_123");

    // - DB_HOST overridden by staging
    let get_stg_db = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "DB_HOST", "-i", "tiered-service", "-e", "staging"])
        .assert()
        .success();
    assert_eq!(get_stg_db.get_output().stdout, b"db.staging.cloud");

    // - OVERRIDDEN_IN_PROD falls back to item base in staging
    let get_stg_base_fallback = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "OVERRIDDEN_IN_PROD", "-i", "tiered-service", "-e", "staging"])
        .assert()
        .success();
    assert_eq!(get_stg_base_fallback.get_output().stdout, b"base_val");

    // C. Check Production environment:
    // - DB_HOST overridden by prod
    let get_prod_db = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "DB_HOST", "-i", "tiered-service", "-e", "production"])
        .assert()
        .success();
    assert_eq!(get_prod_db.get_output().stdout, b"db.prod.cloud");

    // - OVERRIDDEN_IN_PROD overridden by prod
    let get_prod_override = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "OVERRIDDEN_IN_PROD", "-i", "tiered-service", "-e", "production"])
        .assert()
        .success();
    assert_eq!(get_prod_override.get_output().stdout, b"prod_override_val");

    // D. Injected run command in staging:
    // Verify all 4 effective variables are present in subprocess environment
    Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "run",
            "-i",
            "tiered-service",
            "-e",
            "staging",
            "--",
            "sh",
            "-c",
            "test \"$BASE_SHARED\" = 'shared_base_123' && \
             test \"$DB_HOST\" = 'db.staging.cloud' && \
             test \"$OVERRIDDEN_IN_PROD\" = 'base_val' && \
             test \"$STAGING_SPECIAL\" = 'stage_only' && \
             test -z \"$PROD_SECRET\" && \
             exit 0 || exit 22",
        ])
        .assert()
        .success();
}

// =========================================================================
// 5. Signal Termination & Exit Code Preservation
// =========================================================================

#[cfg(unix)]
#[test]
fn test_child_signal_termination_preservation() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_secwet(data_dir);
    let label = secwet.create_label("General", None).unwrap();
    let _item = secwet.create_item(label.id, "signal-svc", None).unwrap();
    secwet.lock();

    // Signal 9 (SIGKILL) -> 128 + 9 = 137
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["run", "-i", "signal-svc", "--", "sh", "-c", "kill -9 $$"])
        .assert()
        .code(137);

    // Signal 2 (SIGINT) -> 128 + 2 = 130
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["run", "-i", "signal-svc", "--", "sh", "-c", "kill -2 $$"])
        .assert()
        .code(130);

    // Signal 15 (SIGTERM) -> 128 + 15 = 143
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["run", "-i", "signal-svc", "--", "sh", "-c", "kill -15 $$"])
        .assert()
        .code(143);
}

// =========================================================================
// 6. Config File Discovery and Precedence Rules
// =========================================================================

#[test]
fn test_secwet_toml_item_project_precedence_and_cli_override() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let mut secwet = setup_secwet(root);
    let label = secwet.create_label("General", None).unwrap();
    let item_toml = secwet.create_item(label.id, "item-from-toml", None).unwrap();
    let item_cli = secwet.create_item(label.id, "item-from-cli", None).unwrap();

    let d_toml = SecretDraft::new(item_toml.id, None, "ORIGIN", SecretKind::EnvVar, "from_toml", None);
    let d_cli = SecretDraft::new(item_cli.id, None, "ORIGIN", SecretKind::EnvVar, "from_cli", None);
    secwet.create_secret(d_toml).unwrap();
    secwet.create_secret(d_cli).unwrap();
    secwet.lock();

    let toml_file = root.join(".secwet.toml");

    // Case 1: toml defines `item`
    std::fs::write(&toml_file, format!("item = \"item-from-toml\"\ndata_dir = '{}'\n", root.display())).unwrap();

    let out1 = Command::cargo_bin("secwet")
        .unwrap()
        .current_dir(root)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "ORIGIN"])
        .assert()
        .success();
    assert_eq!(out1.get_output().stdout, b"from_toml");

    // Case 2: CLI `--item` flag overrides toml `item`
    let out2 = Command::cargo_bin("secwet")
        .unwrap()
        .current_dir(root)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "ORIGIN", "--item", "item-from-cli"])
        .assert()
        .success();
    assert_eq!(out2.get_output().stdout, b"from_cli");

    let keystore = FileKeyStore::new(root.join(".test_keystore.json"));
    let mut v = Secwet::unlock(root, &keystore).unwrap();
    let item_legacy = v.create_item(label.id, "item-legacy", None).unwrap();
    let d_legacy = SecretDraft::new(item_legacy.id, None, "ORIGIN", SecretKind::EnvVar, "from_legacy", None);
    v.create_secret(d_legacy).unwrap();
    v.lock();

    std::fs::write(
        &toml_file,
        format!("item = \"item-from-toml\"\nproject = \"item-legacy\"\ndata_dir = '{}'\n", root.display())
    ).unwrap();

    let out3 = Command::cargo_bin("secwet")
        .unwrap()
        .current_dir(root)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "ORIGIN"])
        .assert()
        .success();
    assert_eq!(out3.get_output().stdout, b"from_toml");
}
