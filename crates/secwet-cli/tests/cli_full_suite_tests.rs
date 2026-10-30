use assert_cmd::Command;
use predicates::prelude::*;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::Secwet;
use std::path::Path;
use tempfile::tempdir;

fn setup_secwet(data_dir: &Path) -> Secwet {
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    Secwet::create(data_dir, "test-device-cli", &keystore).expect("create secwet")
}

#[test]
fn test_cli_group_crud_and_json() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let secwet = setup_secwet(data_dir);
    secwet.lock();

    // 1. Create group
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "create", "Infrastructure", "--icon", "server", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Infrastructure\""))
        .stdout(predicate::str::contains("\"icon\": \"server\""));

    // 2. List groups
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Infrastructure"));

    // 3. Rename group
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "rename", "Infrastructure", "Infra & Cloud", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Infra & Cloud"))
        .stdout(predicate::str::contains("renamed"));

    // 4. Delete group
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "delete", "Infra & Cloud", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("deleted"));
}

#[test]
fn test_cli_item_and_env_crud_and_tree() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_secwet(data_dir);
    let _group = secwet.create_label("Backend", Some("server".into())).unwrap();
    secwet.lock();

    // 1. Create item
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["item", "create", "Payment Service", "-g", "Backend", "-d", "Handles charges", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Payment Service\""));

    // 2. List items
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["item", "list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Payment Service"));

    // 3. Create environment
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["env", "create", "staging", "-i", "Payment Service", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"staging\""));

    // 4. Secret set, get, list
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "secret", "set", "STRIPE_KEY",
            "-i", "Payment Service",
            "-e", "staging",
            "-k", "api_key",
            "--value", "sk_test_1234567890",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"STRIPE_KEY\""));

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["secret", "get", "STRIPE_KEY", "-i", "Payment Service", "-e", "staging"])
        .assert()
        .success()
        .stdout(predicate::str::contains("sk_test_1234567890"));

    // 5. Tree command (ASCII and JSON)
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["tree"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Group: Backend"))
        .stdout(predicate::str::contains("Item: Payment Service"))
        .stdout(predicate::str::contains("STRIPE_KEY"));

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["tree", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Backend\""))
        .stdout(predicate::str::contains("\"name\": \"Payment Service\""))
        .stdout(predicate::str::contains("\"name\": \"STRIPE_KEY\""));
}

#[test]
fn test_cli_notes_and_files_crud() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_secwet(data_dir);
    let group = secwet.create_label("General", None).unwrap();
    let _item = secwet.create_item(group.id, "Docs App", None).unwrap();
    secwet.lock();

    // 1. Create Note
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "note", "create", "Runbook",
            "-i", "Docs App",
            "--content", "Step 1: Deploy\nStep 2: Verify",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"title\": \"Runbook\""));

    // 2. Get Note
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["note", "get", "Runbook", "-i", "Docs App", "--raw"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Step 1: Deploy"));

    // 3. Upload File
    let test_file = temp.path().join("sample.txt");
    std::fs::write(&test_file, b"sample file payload bytes").unwrap();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "file", "upload",
            test_file.to_str().unwrap(),
            "-i", "Docs App",
            "--name", "config.txt",
            "--json",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"config.txt\""));

    // 4. Download File
    let downloaded_file = temp.path().join("downloaded.txt");
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "file", "download", "config.txt",
            "-i", "Docs App",
            "-o", downloaded_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    let downloaded_bytes = std::fs::read(downloaded_file).unwrap();
    assert_eq!(downloaded_bytes, b"sample file payload bytes");
}

#[test]
fn test_cli_session_and_init() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let mut secwet = setup_secwet(&data_dir);
    let group = secwet.create_label("General", None).unwrap();
    let _item = secwet.create_item(group.id, "Web App", None).unwrap();
    secwet.lock();

    // 1. Session list (initially empty)
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", &data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["session", "list", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[]"));

    // 2. Init command creates .secwet.toml
    let project_dir = temp.path().join("repo");
    std::fs::create_dir_all(&project_dir).unwrap();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.current_dir(&project_dir)
        .env("SECWET_DATA_DIR", &data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["init", "-i", "Web App", "-e", "production"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Initialized .secwet.toml"));

    let config_content = std::fs::read_to_string(project_dir.join(".secwet.toml")).unwrap();
    assert!(config_content.contains("item = \"Web App\""));
    assert!(config_content.contains("environment = \"production\""));
}
