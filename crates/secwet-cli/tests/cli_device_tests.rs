//! CLI integration tests for device management and pairing commands.

use assert_cmd::Command;
use predicates::prelude::*;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::Secwet;
use tempfile::tempdir;

#[test]
fn test_cli_device_list_and_json() {
    let dir = tempdir().unwrap();
    let keystore = FileKeyStore::new(dir.path().join(".test_keystore.json"));

    // Initialize secwet
    let secwet = Secwet::create(dir.path(), "Primary Machine", &keystore).unwrap();
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", dir.path())
        .env("SECWET_TEST_KEYSTORE", "file")
        .arg("device")
        .arg("list");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("DEVICE ID"))
        .stdout(predicate::str::contains("Primary Machine"))
        .stdout(predicate::str::contains("Active (this)"));

    // JSON format
    let mut cmd_json = Command::cargo_bin("secwet").unwrap();
    cmd_json
        .env("SECWET_DATA_DIR", dir.path())
        .env("SECWET_TEST_KEYSTORE", "file")
        .arg("device")
        .arg("list")
        .arg("--json");

    let assert = cmd_json.assert().success();
    let stdout = String::from_utf8(assert.get_output().stdout.clone()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert!(parsed.is_array());
    assert_eq!(parsed.as_array().unwrap().len(), 1);
    assert_eq!(
        parsed[0]["name"].as_str().unwrap(),
        "Primary Machine"
    );
}

#[test]
fn test_cli_pair_help_displays_subcommands() {
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.arg("pair").arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("start"))
        .stdout(predicate::str::contains("join"));
}

