use assert_cmd::Command;
use predicates::prelude::*;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::{SecretDraft, SecretKind, Secwet};
use std::path::Path;
use tempfile::tempdir;

fn setup_secwet_with_project(data_dir: &Path, project_name: &str, envs: &[&str]) -> Secwet {
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "test-device-1", &keystore).expect("create secwet");
    let env_strings: Vec<String> = envs.iter().map(|s| s.to_string()).collect();
    secwet
        .create_project(project_name, &env_strings)
        .expect("create project");
    secwet
}

#[test]
fn cli_list_hides_values() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let draft = SecretDraft::new(
        project.id,
        env.id,
        "API_KEY",
        SecretKind::ApiKey,
        "SECRET_VALUE_DO_NOT_LEAK_12345",
        None,
    );
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "-p", "backend", "-e", "development"])
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("api_key"))
        .stdout(predicate::str::contains("SECRET_VALUE_DO_NOT_LEAK_12345").not())
        .stderr(predicate::str::contains("SECRET_VALUE_DO_NOT_LEAK_12345").not());
}

#[test]
fn cli_run_injects_env_and_forwards_exit_code() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let draft = SecretDraft::new(
        project.id,
        env.id,
        "MY_TEST_VAR",
        SecretKind::EnvVar,
        "injected_payload_xyz",
        None,
    );
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "run",
            "-p",
            "backend",
            "-e",
            "development",
            "--",
            "sh",
            "-c",
            "if [ \"$MY_TEST_VAR\" = \"injected_payload_xyz\" ]; then exit 3; else exit 1; fi",
        ])
        .assert()
        .code(3)
        .stdout(predicate::str::contains("injected_payload_xyz").not())
        .stderr(predicate::str::contains("injected_payload_xyz").not());
}

#[test]
fn cli_reads_project_from_secwet_toml() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    let config_path = root.join(".secwet.toml");
    std::fs::write(
        &config_path,
        format!(
            "project = \"payments-api\"\nenv = \"staging\"\ndata_dir = \"{}\"\n",
            root.display()
        ),
    )
    .unwrap();

    let mut secwet = setup_secwet_with_project(root, "payments-api", &["staging"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let draft = SecretDraft::new(
        project.id,
        env.id,
        "DB_HOST",
        SecretKind::EnvVar,
        "postgres.internal",
        None,
    );
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    let deep_dir = root.join("services").join("web");
    std::fs::create_dir_all(&deep_dir).unwrap();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.current_dir(&deep_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("DB_HOST"));
}

#[test]
fn cli_import_dotenv_parses_quotes_and_comments() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_secwet_with_project(data_dir, "payments", &["production"]);
    secwet.lock();

    let env_file = data_dir.join("test.env");
    let env_content = r#"
# Comment line
PORT=8080
DATABASE_URL="postgres://user:pass@localhost/db?ssl=true"
SINGLE_QUOTED='raw value with spaces'
export API_TOKEN=xyz123
ESCAPED_NEWLINE="line1\nline2"
"#;
    std::fs::write(&env_file, env_content).unwrap();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "import",
            env_file.to_str().unwrap(),
            "-p",
            "payments",
            "-e",
            "production",
        ])
        .assert()
        .success();

    // Verify DATABASE_URL
    let mut get_db = Command::cargo_bin("secwet").unwrap();
    let output = get_db
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "DATABASE_URL", "-p", "payments", "-e", "production"])
        .assert()
        .success();
    assert_eq!(
        output.get_output().stdout,
        b"postgres://user:pass@localhost/db?ssl=true"
    );

    // Verify SINGLE_QUOTED
    let mut get_single = Command::cargo_bin("secwet").unwrap();
    let output = get_single
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "SINGLE_QUOTED", "-p", "payments", "-e", "production"])
        .assert()
        .success();
    assert_eq!(output.get_output().stdout, b"raw value with spaces");

    // Verify API_TOKEN
    let mut get_token = Command::cargo_bin("secwet").unwrap();
    let output = get_token
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "API_TOKEN", "-p", "payments", "-e", "production"])
        .assert()
        .success();
    assert_eq!(output.get_output().stdout, b"xyz123");

    // Verify ESCAPED_NEWLINE
    let mut get_escaped = Command::cargo_bin("secwet").unwrap();
    let output = get_escaped
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "get",
            "ESCAPED_NEWLINE",
            "-p",
            "payments",
            "-e",
            "production",
        ])
        .assert()
        .success();
    assert_eq!(output.get_output().stdout, b"line1\nline2");
}

#[test]
fn cli_import_dotenv_from_stdin_with_dash() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_secwet_with_project(data_dir, "piped-item", &["staging"]);
    secwet.lock();

    let env_content = "PIPED_KEY=piped_secret_val\nOTHER_KEY=\"hello from stdin\"";

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["import", "-", "-i", "piped-item", "-e", "staging"])
        .write_stdin(env_content)
        .assert()
        .success();

    let mut get_cmd = Command::cargo_bin("secwet").unwrap();
    let output = get_cmd
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "PIPED_KEY", "-i", "piped-item", "-e", "staging"])
        .assert()
        .success();
    assert_eq!(output.get_output().stdout, b"piped_secret_val");
}

#[test]
fn cli_get_outputs_without_newline_when_piped() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let draft = SecretDraft::new(
        project.id,
        env.id,
        "SECRET_RAW",
        SecretKind::AccessToken,
        "clean_token_no_newline",
        None,
    );
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    let output = cmd
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "SECRET_RAW", "-p", "backend", "-e", "development"])
        .assert()
        .success();

    // assert_cmd captures stdout via pipe -> !is_terminal() -> NO trailing newline!
    assert_eq!(output.get_output().stdout, b"clean_token_no_newline");
}

#[test]
fn cli_status_displays_details() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    let secwet_id = secwet.secwet_id().to_string();
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .arg("status")
        .assert()
        .success()
        .stdout(predicate::str::contains(&secwet_id))
        .stdout(predicate::str::contains("test-device-1"))
        .stdout(predicate::str::contains("Free"))
        .stdout(predicate::str::contains("Local only"));

    let mut cmd_json = Command::cargo_bin("secwet").unwrap();
    cmd_json
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["status", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains(&secwet_id))
        .stdout(predicate::str::contains("\"free\""))
        .stdout(predicate::str::contains("\"offline\""));
}

#[test]
fn cli_set_creates_and_updates_secret() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    secwet.lock();

    // Create via set with stdin pipe
    let mut cmd_create = Command::cargo_bin("secwet").unwrap();
    cmd_create
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "NEW_VAR", "-p", "backend", "-e", "development"])
        .write_stdin("initial_value")
        .assert()
        .success();

    let mut cmd_get1 = Command::cargo_bin("secwet").unwrap();
    let out1 = cmd_get1
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "NEW_VAR", "-p", "backend", "-e", "development"])
        .assert()
        .success();
    assert_eq!(out1.get_output().stdout, b"initial_value");

    // Update via set with stdin pipe
    let mut cmd_update = Command::cargo_bin("secwet").unwrap();
    cmd_update
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "NEW_VAR", "-p", "backend", "-e", "development"])
        .write_stdin("updated_value")
        .assert()
        .success();

    let mut cmd_get2 = Command::cargo_bin("secwet").unwrap();
    let out2 = cmd_get2
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "NEW_VAR", "-p", "backend", "-e", "development"])
        .assert()
        .success();
    assert_eq!(out2.get_output().stdout, b"updated_value");
}

#[test]
fn cli_locked_or_missing_secwet_exits_code_2() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("nonexistent_secwet");

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", &data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .arg("list")
        .assert()
        .code(2)
        .stderr(predicate::str::contains("secwet not initialized on this device"));
}

#[test]
fn cli_usage_error_exits_code_64() {
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.arg("--nonexistent-flag-xyz").assert().code(64);
}

#[test]
fn cli_run_conflicting_env_var_wins() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let draft = SecretDraft::new(
        project.id,
        env.id,
        "TEST_CONFLICT",
        SecretKind::EnvVar,
        "secwet_wins",
        None,
    );
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .env("TEST_CONFLICT", "parent_loses")
        .args([
            "run",
            "-p",
            "backend",
            "-e",
            "development",
            "--",
            "sh",
            "-c",
            "printf %s \"$TEST_CONFLICT\"",
        ])
        .assert()
        .success()
        .stdout("secwet_wins");
}

#[test]
fn cli_get_not_found_exits_code_1() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "NON_EXISTENT", "-p", "backend", "-e", "development"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("secret 'NON_EXISTENT' not found"));
}

#[test]
fn cli_set_invalid_secret_name_exits_code_1() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "INVALID NAME!", "-p", "backend", "-e", "development"])
        .write_stdin("val")
        .assert()
        .code(1)
        .stderr(predicate::str::contains("invalid secret name"));
}

#[test]
fn cli_set_value_exceeding_64k_exits_code_1() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_secwet_with_project(data_dir, "backend", &["development"]);
    secwet.lock();

    let huge_val = "x".repeat(65_537);

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "HUGE_SECRET", "-p", "backend", "-e", "development"])
        .write_stdin(huge_val)
        .assert()
        .code(1)
        .stderr(predicate::str::contains("exceeded max length"));
}

#[test]
fn cli_export_dotenv_and_json_roundtrip() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_secwet_with_project(data_dir, "export-test", &["production"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let d1 = SecretDraft::new(
        project.id,
        Some(env.id),
        "API_KEY",
        SecretKind::ApiKey,
        "sk_live_12345",
        None,
    );
    let d2 = SecretDraft::new(
        project.id,
        Some(env.id),
        "DB_PASS",
        SecretKind::Password,
        "p@ss\"word\nmultiline",
        None,
    );
    secwet.create_secret(d1).unwrap();
    secwet.create_secret(d2).unwrap();
    secwet.lock();

    // 1. Export dotenv to stdout
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-p",
            "export-test",
            "-e",
            "production",
            "-f",
            "dotenv",
            "--plaintext",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY=\"sk_live_12345\"\n"))
        .stdout(predicate::str::contains("DB_PASS=\"p@ss\\\"word\\nmultiline\"\n"));

    // 2. Export json to file
    let json_file = data_dir.join("exported.json");
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-p",
            "export-test",
            "-e",
            "production",
            "-f",
            "json",
            "--plaintext",
            "-o",
            json_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    let file_content = std::fs::read_to_string(&json_file).unwrap();
    assert!(file_content.contains("\"API_KEY\": \"sk_live_12345\""));
    assert!(file_content.contains("\"DB_PASS\": \"p@ss\\\"word\\nmultiline\""));
}

#[test]
fn cli_concurrency_with_open_secwet() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "test-device-1", &keystore).unwrap();
    let project = secwet.create_project("concurrency-test", &["staging".to_string()])
        .unwrap();

    let draft = SecretDraft::new(
        project.id,
        project.environments[0].id,
        "CONCURRENT_KEY",
        SecretKind::EnvVar,
        "concurrent_val",
        None,
    );
    secwet.create_secret(draft).unwrap();

    // While secwet is still open and held in this process, invoke CLI command
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "-p", "concurrency-test", "-e", "staging"])
        .assert()
        .success()
        .stdout(predicate::str::contains("CONCURRENT_KEY"));

    // And also perform a set while the test secwet is open
    let mut cmd_set = Command::cargo_bin("secwet").unwrap();
    cmd_set
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "set",
            "ANOTHER_KEY",
            "-p",
            "concurrency-test",
            "-e",
            "staging",
        ])
        .write_stdin("another_val")
        .assert()
        .success();

    secwet.lock();
}

// =========================================================================
// Item and Zero-Environment Integration Tests
// =========================================================================

#[test]
fn cli_item_without_environments_crud_roundtrip() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "test-device-1", &keystore).unwrap();
    let label = secwet.create_label("General", None).unwrap();
    let _item = secwet.create_item(label.id, "standalone-item", None).unwrap();
    secwet.lock();

    // 1. Set secret on item with 0 environments (stdin pipe)
    let mut cmd_set = Command::cargo_bin("secwet").unwrap();
    cmd_set
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "ROOT_SECRET", "--item", "standalone-item"])
        .write_stdin("item_level_secret_value")
        .assert()
        .success()
        .stderr(predicate::str::contains("Created secret 'ROOT_SECRET' in standalone-item"));

    // 2. List secrets on item with 0 environments (hides values)
    let mut cmd_list = Command::cargo_bin("secwet").unwrap();
    cmd_list
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "--item", "standalone-item"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ROOT_SECRET"))
        .stdout(predicate::str::contains("item_level_secret_value").not());

    // 3. Get secret value without newline when piped
    let mut cmd_get = Command::cargo_bin("secwet").unwrap();
    let get_out = cmd_get
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "ROOT_SECRET", "--item", "standalone-item"])
        .assert()
        .success();
    assert_eq!(get_out.get_output().stdout, b"item_level_secret_value");

    // 4. Run command with injected item-level secret
    let mut cmd_run = Command::cargo_bin("secwet").unwrap();
    cmd_run
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "run",
            "--item",
            "standalone-item",
            "--",
            "sh",
            "-c",
            "printf %s \"$ROOT_SECRET\"",
        ])
        .assert()
        .success()
        .stdout("item_level_secret_value");
}

#[test]
fn cli_item_without_environments_errors_when_env_explicitly_passed() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "test-device-1", &keystore).unwrap();
    let label = secwet.create_label("General", None).unwrap();
    let _item = secwet.create_item(label.id, "no-env-item", None).unwrap();
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "--item", "no-env-item", "-e", "production"])
        .assert()
        .code(1)
        .stderr(predicate::str::contains("error: item 'no-env-item' has no environments"));
}

#[test]
fn cli_item_flag_aliases_parity() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "test-device-1", &keystore).unwrap();
    let label = secwet.create_label("Dev", None).unwrap();
    let item = secwet.create_item(label.id, "my-service", None).unwrap();
    let draft = SecretDraft::new(item.id, None, "TOKEN", SecretKind::ApiKey, "abc", None);
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    // Verify --item
    Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "--item", "my-service"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN"));

    // Verify -i
    Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "-i", "my-service"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN"));

    // Verify legacy --project
    Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "--project", "my-service"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN"));

    // Verify legacy -p
    Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "-p", "my-service"])
        .assert()
        .success()
        .stdout(predicate::str::contains("TOKEN"));
}

#[test]
fn cli_secwet_toml_item_and_project_key_support() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    let keystore = FileKeyStore::new(root.join(".test_keystore.json"));
    let mut secwet = Secwet::create(root, "test-device-1", &keystore).unwrap();
    let label = secwet.create_label("Work", None).unwrap();
    let item = secwet.create_item(label.id, "billing-service", None).unwrap();
    let draft = SecretDraft::new(item.id, None, "STRIPE_KEY", SecretKind::ApiKey, "sk_123", None);
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    // Test with item = "billing-service"
    let toml_path = root.join(".secwet.toml");
    std::fs::write(&toml_path, format!("item = \"billing-service\"\ndata_dir = \"{}\"\n", root.display())).unwrap();

    Command::cargo_bin("secwet").unwrap()
        .current_dir(root)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("STRIPE_KEY"));

    // Test with legacy project = "billing-service"
    std::fs::write(&toml_path, format!("project = \"billing-service\"\ndata_dir = \"{}\"\n", root.display())).unwrap();

    Command::cargo_bin("secwet").unwrap()
        .current_dir(root)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("STRIPE_KEY"));
}

#[test]
fn cli_environment_overlay_and_inheritance() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "test-device-1", &keystore).unwrap();
    let label = secwet.create_label("Work", None).unwrap();
    let item = secwet.create_item(label.id, "multi-env-item", None).unwrap();
    let env_dev = secwet.add_environment(item.id, "development").unwrap();

    // 1. Item-level base secret (inherited by environments)
    let d1 = SecretDraft::new(item.id, None, "BASE_URL", SecretKind::EnvVar, "https://api.base.com", None);
    secwet.create_secret(d1).unwrap();

    // 2. Secret defined in both: env should override item
    let d2_base = SecretDraft::new(item.id, None, "DB_HOST", SecretKind::EnvVar, "base-db", None);
    secwet.create_secret(d2_base).unwrap();
    let d2_dev = SecretDraft::new(item.id, Some(env_dev.id), "DB_HOST", SecretKind::EnvVar, "dev-db", None);
    secwet.create_secret(d2_dev).unwrap();
    secwet.lock();

    // Verification: get BASE_URL while targeting development environment finds it via inheritance
    let out_base = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "BASE_URL", "--item", "multi-env-item", "-e", "development"])
        .assert()
        .success();
    assert_eq!(out_base.get_output().stdout, b"https://api.base.com");

    // Verification: get DB_HOST while targeting development environment returns the overridden dev value
    let out_db = Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "DB_HOST", "--item", "multi-env-item", "-e", "development"])
        .assert()
        .success();
    assert_eq!(out_db.get_output().stdout, b"dev-db");
}

#[test]
fn cli_set_codes_kind_and_default_general_environment() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "test-device-1", &keystore).unwrap();
    let label = secwet.create_label("Security", None).unwrap();
    let item = secwet.create_item(label.id, "vault-service", None).unwrap();
    let _env = secwet.add_environment(item.id, "development").unwrap();
    secwet.lock();

    // 1. Set BACKUP_CODES without --env => defaults to General (env_id: None) with -k codes
    Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "BACKUP_CODES", "--item", "vault-service", "-k", "codes"])
        .write_stdin("code1,code2,code3")
        .assert()
        .success();

    // 2. Set RECOVERY_KEY with explicit --env general and alias -k code
    Command::cargo_bin("secwet").unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["set", "RECOVERY_KEY", "--item", "vault-service", "-k", "code", "--env", "general"])
        .write_stdin("rec-987654")
        .assert()
        .success();

    // 3. Verify in database: both secrets exist in General (env_id == None) and kind == SecretKind::Codes
    let secwet = Secwet::unlock(data_dir, &keystore).unwrap();
    let general_secrets = secwet.list_secrets(item.id, None).unwrap();
    assert_eq!(general_secrets.len(), 2);

    let backup_sec = general_secrets.iter().find(|s| s.name == "BACKUP_CODES").unwrap();
    assert_eq!(backup_sec.kind, SecretKind::Codes);

    let recovery_sec = general_secrets.iter().find(|s| s.name == "RECOVERY_KEY").unwrap();
    assert_eq!(recovery_sec.kind, SecretKind::Codes);
}

#[test]
fn dotenv_export_requires_plaintext_flag() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_secwet_with_project(data_dir, "auth-svc", &["production"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    secwet
        .create_secret(SecretDraft::new(
            project.id,
            Some(env.id),
            "DATABASE_PASSWORD",
            SecretKind::Password,
            "super-secret-db-pass",
            None,
        ))
        .unwrap();
    secwet.lock();

    let out_file = data_dir.join(".env");

    // 1. Export without --plaintext must abort immediately with exit code 1
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "--env",
            "production",
            "--format",
            "dotenv",
            "--out",
            out_file.to_str().unwrap(),
            "-p",
            "auth-svc",
        ])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("error: exporting plaintext secrets requires the explicit --plaintext flag"));

    assert!(!out_file.exists());

    // 2. Export with --plaintext must succeed and print warning to stderr
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "--env",
            "production",
            "--format",
            "dotenv",
            "--plaintext",
            "--out",
            out_file.to_str().unwrap(),
            "-p",
            "auth-svc",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("warning: exporting unencrypted plaintext secrets"));

    assert!(out_file.exists());
    let content = std::fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("DATABASE_PASSWORD=\"super-secret-db-pass\""));
}

#[test]
fn cli_export_secwet_envelope_roundtrip() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "cli-test-device", &keystore).expect("create secwet");
    let recovery_key = secwet.create_recovery_key(&keystore).expect("create recovery key");
    let recovery_key_str = secrecy::ExposeSecret::expose_secret(&recovery_key).to_string();

    let _space = secwet.create_space("Engineering", Some("gear".to_string())).expect("create space");
    let label = secwet.create_label("Infra", Some("cloud".to_string())).expect("create label");
    let item = secwet.create_item(label.id, "database-cluster", None).expect("create item");
    let env = secwet.add_environment(item.id, "production").expect("add env");

    secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(env.id),
            "CLUSTER_ADMIN_KEY",
            SecretKind::ApiKey,
            "secret_adm_999888777",
            None,
        ))
        .expect("create secret");
    secwet.lock();

    let backup_file = data_dir.join("cluster_backup.secwet");

    // 1. Export workspace to .secwet providing recovery key via stdin
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "--out", backup_file.to_str().unwrap()])
        .write_stdin(format!("{}\n", recovery_key_str))
        .assert()
        .success()
        .stderr(predicate::str::contains("Exported"));

    assert!(backup_file.exists());

    // 2. Invariant: exported file contains no plaintext secrets
    let file_bytes = std::fs::read(&backup_file).unwrap();
    let file_str = String::from_utf8_lossy(&file_bytes);
    assert!(!file_str.contains("secret_adm_999888777"));

    // 3. Restore the export into a clean target directory
    let restore_temp = tempdir().unwrap();
    let restore_data_dir = restore_temp.path();
    let restore_keystore = FileKeyStore::new(restore_data_dir.join(".test_keystore.json"));

    let restored_secwet = Secwet::restore_from_export(
        restore_data_dir,
        &backup_file,
        &secrecy::SecretString::from(recovery_key_str.clone()),
        "restored-cli-device",
        &restore_keystore,
    )
    .expect("restore from export");

    let restored_secrets = restored_secwet
        .list_secrets(item.id, Some(env.id))
        .expect("list secrets");
    assert_eq!(restored_secrets.len(), 1);
    assert_eq!(restored_secrets[0].name, "CLUSTER_ADMIN_KEY");

    let revealed = restored_secwet
        .reveal_secret(restored_secrets[0].id)
        .expect("reveal secret");
    assert_eq!(
        secrecy::ExposeSecret::expose_secret(&revealed),
        "secret_adm_999888777"
    );
}

