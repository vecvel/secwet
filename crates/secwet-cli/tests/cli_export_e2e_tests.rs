//! End-to-end integration tests for CLI export commands and flags.
//!
//! Authoritative source: `ORIGINAL_REQUEST.md` (R5) and `docs/IMPLEMENTATION.md` (F10, F11).

use assert_cmd::Command;
use predicates::prelude::*;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::{SecretDraft, SecretKind, Secwet};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn setup_cli_test_secwet(data_dir: &Path, project_name: &str, envs: &[&str]) -> Secwet {
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(data_dir, "cli-test-device", &keystore).expect("create secwet");
    let env_strings: Vec<String> = envs.iter().map(|s| s.to_string()).collect();
    secwet
        .create_project(project_name, &env_strings)
        .expect("create project");
    secwet
}

#[test]
fn test_cli_export_empty_workspace_fails() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let secwet = Secwet::create(data_dir, "cli-test-device", &keystore).expect("create secwet");
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export"])
        .assert()
        .failure();
}

#[test]
fn test_cli_export_invalid_format_fails() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let secwet = setup_cli_test_secwet(data_dir, "service-b", &["production"]);
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "-p", "service-b", "-e", "production", "-f", "xml"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported export format").or(predicate::str::contains("error")));
}

#[test]
fn test_cli_export_nonexistent_project_fails() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let secwet = setup_cli_test_secwet(data_dir, "existing-service", &["production"]);
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "-p", "does-not-exist", "-e", "production"])
        .assert()
        .failure();
}

#[test]
fn test_cli_export_nonexistent_environment_fails() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let secwet = setup_cli_test_secwet(data_dir, "service-c", &["production"]);
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["export", "-p", "service-c", "-e", "nonexistent-env"])
        .assert()
        .failure();
}

#[test]
fn test_cli_export_to_file_path_creates_exact_content() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_cli_test_secwet(data_dir, "service-d", &["staging"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    secwet
        .create_secret(SecretDraft::new(
            project.id,
            Some(env.id),
            "REDIS_HOST",
            SecretKind::EnvVar,
            "redis.internal:6379",
            None,
        ))
        .unwrap();
    secwet.lock();

    let out_file = data_dir.join("staging.env");
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-p",
            "service-d",
            "-e",
            "staging",
            "-f",
            "dotenv",
            "--plaintext",
            "-o",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    assert!(out_file.exists());
    let content = fs::read_to_string(&out_file).unwrap();
    assert!(content.contains("REDIS_HOST=\"redis.internal:6379\""));
}

#[test]
fn test_cli_export_empty_item_produces_empty_dotenv() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let secwet = setup_cli_test_secwet(data_dir, "empty-service", &["production"]);
    secwet.lock();

    let out_file = data_dir.join("empty.env");
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-p",
            "empty-service",
            "-e",
            "production",
            "-f",
            "dotenv",
            "--plaintext",
            "-o",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = fs::read_to_string(&out_file).unwrap();
    assert_eq!(content.trim(), "");
}

#[test]
fn test_cli_export_json_format_produces_valid_json() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();
    let mut secwet = setup_cli_test_secwet(data_dir, "service-json", &["production"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    secwet
        .create_secret(SecretDraft::new(
            project.id,
            Some(env.id),
            "SERVER_PORT",
            SecretKind::EnvVar,
            "8080",
            None,
        ))
        .unwrap();
    secwet.lock();

    let out_file = data_dir.join("prod.json");
    Command::cargo_bin("secwet")
        .unwrap()
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "export",
            "-p",
            "service-json",
            "-e",
            "production",
            "-f",
            "json",
            "--plaintext",
            "-o",
            out_file.to_str().unwrap(),
        ])
        .assert()
        .success();

    let content = fs::read_to_string(&out_file).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&content).expect("must be valid JSON");
    assert_eq!(parsed["SERVER_PORT"], "8080");
}
