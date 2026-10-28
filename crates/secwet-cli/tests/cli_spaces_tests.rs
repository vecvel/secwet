use assert_cmd::Command;
use predicates::prelude::*;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::Secwet;
use std::path::Path;
use tempfile::tempdir;

fn setup_secwet(data_dir: &Path) -> Secwet {
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    Secwet::create(data_dir, "test-device-cli-spaces", &keystore).expect("create secwet")
}

#[test]
fn test_cli_spaces_crud_and_parity() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let secwet = setup_secwet(data_dir);
    secwet.lock();

    // 1. Initial list should show the default Personal space
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["space", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Personal"))
        .stdout(predicate::str::contains("yes")); // default: yes

    // 2. Create a new space: Work
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["space", "create", "Work", "--icon", "briefcase", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Work\""))
        .stdout(predicate::str::contains("\"icon\": \"briefcase\""))
        .stdout(predicate::str::contains("\"is_default\": false"));

    // 3. Create group under Work space
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "create", "Enterprise APIs", "--space", "Work", "--icon", "server", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Enterprise APIs\""));

    // 4. Create group under Personal space (default when --space omitted)
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "create", "Home Lab", "--icon", "folder", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Home Lab\""));

    // 5. List groups filtered by --space Work
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "list", "--space", "Work", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Enterprise APIs"))
        .stdout(predicate::str::contains("Home Lab").not());

    // 6. List groups filtered by --space Personal
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "list", "--space", "Personal", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Home Lab"))
        .stdout(predicate::str::contains("Enterprise APIs").not());

    // 7. Move "Home Lab" from Personal to Work
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "move", "Home Lab", "--to", "Work", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("moved"))
        .stdout(predicate::str::contains("Work"));

    // 8. Rename space Work -> Corporate
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["space", "rename", "Work", "Corporate", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Corporate\""));

    // 9. Inspect tree (ASCII)
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["tree"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Space: Personal [default]"))
        .stdout(predicate::str::contains("Space: Corporate"))
        .stdout(predicate::str::contains("Group: Enterprise APIs"))
        .stdout(predicate::str::contains("Group: Home Lab"));

    // 10. Inspect tree filtered by --space Corporate (--json)
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["tree", "--space", "Corporate", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"name\": \"Corporate\""))
        .stdout(predicate::str::contains("\"name\": \"Personal\"").not());

    // 11. Delete space Corporate: groups should be safely reassigned to Personal
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["space", "delete", "Corporate", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"deleted\""));

    // 12. Groups now belong to Personal
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["group", "list", "--space", "Personal", "--json"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Enterprise APIs"))
        .stdout(predicate::str::contains("Home Lab"));
}
