use assert_cmd::Command;
use predicates::prelude::*;
use secrecy::ExposeSecret;
use secwet_cli::dotenv::parse_dotenv;
use secwet_cli::keystore::FileKeyStore;
use secwet_core::{SecretDraft, SecretKind, Secwet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

fn setup_test_secwet(data_dir: &Path, project_name: &str, envs: &[&str]) -> Secwet {
    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet =
        Secwet::create(data_dir, "adversarial-test-device", &keystore).expect("create secwet");
    let env_strings: Vec<String> = envs.iter().map(|s| s.to_string()).collect();
    secwet
        .create_project(project_name, &env_strings)
        .expect("create project");
    secwet
}

// =========================================================================
// 1. Subprocess Exit Code Forwarding
// =========================================================================

#[test]
fn test_adversarial_exit_code_forwarding_all_codes() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_test_secwet(data_dir, "runner-proj", &["dev"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let draft = SecretDraft::new(
        project.id,
        env.id,
        "DUMMY_VAR",
        SecretKind::EnvVar,
        "dummy_val",
        None,
    );
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    let test_codes = [0, 7, 42, 127, 255];

    for &code in &test_codes {
        let mut cmd = Command::cargo_bin("secwet").unwrap();
        let cmd_str = format!("exit {code}");
        cmd.env("SECWET_DATA_DIR", data_dir)
            .env("SECWET_TEST_KEYSTORE", "memory")
            .args([
                "run",
                "-p",
                "runner-proj",
                "-e",
                "dev",
                "--",
                "sh",
                "-c",
                &cmd_str,
            ])
            .assert()
            .code(code);
    }
}

#[cfg(unix)]
#[test]
fn test_adversarial_exit_code_forwarding_signals() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_test_secwet(data_dir, "runner-proj", &["dev"]);
    secwet.lock();

    // SIGKILL (signal 9) -> expected exit code 128 + 9 = 137
    let mut cmd_kill = Command::cargo_bin("secwet").unwrap();
    cmd_kill
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "run",
            "-p",
            "runner-proj",
            "-e",
            "dev",
            "--",
            "sh",
            "-c",
            "kill -9 $$",
        ])
        .assert()
        .code(137);

    // SIGTERM (signal 15) -> expected exit code 128 + 15 = 143
    let mut cmd_term = Command::cargo_bin("secwet").unwrap();
    cmd_term
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "run",
            "-p",
            "runner-proj",
            "-e",
            "dev",
            "--",
            "sh",
            "-c",
            "kill -15 $$",
        ])
        .assert()
        .code(143);
}

#[test]
fn test_adversarial_run_nonexistent_binary_returns_code_1() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_test_secwet(data_dir, "runner-proj", &["dev"]);
    secwet.lock();

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    cmd.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "run",
            "-p",
            "runner-proj",
            "-e",
            "dev",
            "--",
            "/nonexistent_executable_path_12345",
        ])
        .assert()
        .code(1)
        .stderr(predicate::str::contains(
            "failed to execute '/nonexistent_executable_path_12345'",
        ));
}

// =========================================================================
// 2. Secret Injection Security (Zero Secret Bytes Leaked)
// =========================================================================

#[test]
fn test_adversarial_secret_injection_and_zero_leakage() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_test_secwet(data_dir, "crypto-proj", &["production"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let canary_secrets = [
        ("SECRET_CANARY_ALPHA", "CLASSIFIED_PAYLOAD_9999_ALPHA"),
        ("SECRET_CANARY_BETA", "CLASSIFIED_PAYLOAD_8888_BETA"),
        ("SECRET_CANARY_GAMMA", "SPECIAL_SYMBOLS_!@#$%^&*()_+~`"),
    ];

    for (name, val) in &canary_secrets {
        let draft = SecretDraft::new(project.id, env.id, *name, SecretKind::EnvVar, *val, None);
        secwet.create_secret(draft).unwrap();
    }
    secwet.lock();

    let file_alpha = data_dir.join("child_alpha.txt");
    let file_beta = data_dir.join("child_beta.txt");
    let file_gamma = data_dir.join("child_gamma.txt");

    // Child writes environment variable values directly to isolated files.
    // Notice: The command line passed to sh does NOT contain the secret values at all,
    // so any secret leaking into stdout/stderr would have to come from secwet run itself.
    let child_script = format!(
        r#"
printf '%s' "$SECRET_CANARY_ALPHA" > "{}"
printf '%s' "$SECRET_CANARY_BETA" > "{}"
printf '%s' "$SECRET_CANARY_GAMMA" > "{}"
echo "CHILD_STATUS_OK"
exit 0
"#,
        file_alpha.display(),
        file_beta.display(),
        file_gamma.display(),
    );

    let mut cmd = Command::cargo_bin("secwet").unwrap();
    let assert = cmd
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "run",
            "-p",
            "crypto-proj",
            "-e",
            "production",
            "--",
            "sh",
            "-c",
            &child_script,
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("CHILD_STATUS_OK"));

    // Verify child indeed received all secrets exactly as injected
    assert_eq!(
        std::fs::read_to_string(&file_alpha).expect("read alpha"),
        "CLASSIFIED_PAYLOAD_9999_ALPHA"
    );
    assert_eq!(
        std::fs::read_to_string(&file_beta).expect("read beta"),
        "CLASSIFIED_PAYLOAD_8888_BETA"
    );
    assert_eq!(
        std::fs::read_to_string(&file_gamma).expect("read gamma"),
        "SPECIAL_SYMBOLS_!@#$%^&*()_+~`"
    );

    // Scrutinize secwet run output: ZERO secret bytes must appear in stdout or stderr
    let output = assert.get_output();
    for (_, secret_val) in &canary_secrets {
        let secret_bytes = secret_val.as_bytes();
        assert!(
            !output
                .stdout
                .windows(secret_bytes.len())
                .any(|w| w == secret_bytes),
            "SECURITY LEAK: Secret value '{secret_val}' was found in secwet run stdout!"
        );
        assert!(
            !output
                .stderr
                .windows(secret_bytes.len())
                .any(|w| w == secret_bytes),
            "SECURITY LEAK: Secret value '{secret_val}' was found in secwet run stderr!"
        );
    }

    // Also verify secwet list contains ZERO secret bytes
    let mut list_cmd = Command::cargo_bin("secwet").unwrap();
    let list_assert = list_cmd
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["list", "-p", "crypto-proj", "-e", "production"])
        .assert()
        .success();

    let list_output = list_assert.get_output();
    for (_, secret_val) in &canary_secrets {
        let secret_bytes = secret_val.as_bytes();
        assert!(
            !list_output
                .stdout
                .windows(secret_bytes.len())
                .any(|w| w == secret_bytes),
            "SECURITY LEAK: Secret value '{secret_val}' was found in secwet list stdout!"
        );
    }
}

#[test]
fn test_adversarial_zero_leakage_on_child_error() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_test_secwet(data_dir, "error-proj", &["dev"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let secret_payload = "SUPER_SECRET_TOKEN_NEVER_LEAK_ON_CRASH_9999";
    let draft = SecretDraft::new(
        project.id,
        env.id,
        "SECRET_CRASH_TEST",
        SecretKind::EnvVar,
        secret_payload,
        None,
    );
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    // Child writes an error message and exits 42
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    let assert = cmd
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "run",
            "-p",
            "error-proj",
            "-e",
            "dev",
            "--",
            "sh",
            "-c",
            "echo 'child generic crash' >&2; exit 42",
        ])
        .assert()
        .code(42)
        .stderr(predicate::str::contains("child generic crash"));

    let output = assert.get_output();
    let secret_bytes = secret_payload.as_bytes();
    assert!(
        !output
            .stdout
            .windows(secret_bytes.len())
            .any(|w| w == secret_bytes),
        "SECURITY LEAK: Secret found in stdout on child crash!"
    );
    assert!(
        !output
            .stderr
            .windows(secret_bytes.len())
            .any(|w| w == secret_bytes),
        "SECURITY LEAK: Secret found in stderr on child crash!"
    );
}

// =========================================================================
// 3. Piping for `secwet get`: Byte-Exact Output With No Trailing Newline
// =========================================================================

#[test]
fn test_adversarial_get_piping_byte_exact_no_newline() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let mut secwet = setup_test_secwet(data_dir, "piping-proj", &["dev"]);
    let project = secwet.list_projects().unwrap().remove(0);
    let env = &project.environments[0];

    let max_64k = "A".repeat(65_536);

    let test_cases: Vec<(&str, String)> = vec![
        ("SINGLE_CHAR", "x".to_string()),
        (
            "NO_NEWLINE",
            "pure_token_without_trailing_newline_12345".to_string(),
        ),
        (
            "WITH_NEWLINE",
            "payload_with_single_trailing_newline\n".to_string(),
        ),
        ("WITH_CRLF", "line1\r\nline2\r\n".to_string()),
        (
            "MULTILINE_PEM",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
                .to_string(),
        ),
        (
            "UNICODE_SPECIAL",
            "🔐_s3cr3t_🦀_123_€_¥_£_日本語_русский".to_string(),
        ),
        ("MAX_64K_VAL", max_64k.clone()),
    ];

    for (name, val) in &test_cases {
        let draft = SecretDraft::new(
            project.id,
            env.id,
            *name,
            SecretKind::EnvVar,
            val.as_str(),
            None,
        );
        secwet.create_secret(draft).unwrap();
    }
    secwet.lock();

    for (name, expected_val) in &test_cases {
        let mut cmd = Command::cargo_bin("secwet").unwrap();
        let output = cmd
            .env("SECWET_DATA_DIR", data_dir)
            .env("SECWET_TEST_KEYSTORE", "memory")
            .args(["get", name, "-p", "piping-proj", "-e", "dev"])
            .assert()
            .success();

        let stdout = output.get_output().stdout.clone();
        assert_eq!(
            stdout,
            expected_val.as_bytes(),
            "Byte mismatch for secret '{name}': Expected exact {} bytes, got {} bytes",
            expected_val.len(),
            stdout.len()
        );
    }
}

// =========================================================================
// 4. `.secwet.toml` Discovery and Hierarchy Override
// =========================================================================

#[test]
fn test_adversarial_secwet_toml_deep_discovery_and_cli_flag_overrides() {
    let temp = tempdir().unwrap();
    let root = temp.path();
    let secwet_dir = root.join("secwet_data");
    std::fs::create_dir_all(&secwet_dir).unwrap();

    let mut secwet = setup_test_secwet(&secwet_dir, "core-banking", &["production", "staging"]);
    let core_proj = secwet.list_projects().unwrap().remove(0);
    let prod_env = core_proj
        .environments
        .iter()
        .find(|e| e.name == "production")
        .unwrap();
    let staging_env = core_proj
        .environments
        .iter()
        .find(|e| e.name == "staging")
        .unwrap();

    // Secret in core-banking / production
    let draft1 = SecretDraft::new(
        core_proj.id,
        prod_env.id,
        "DISCOVERY_SECRET",
        SecretKind::EnvVar,
        "resolved_from_parent_toml_prod",
        None,
    );
    secwet.create_secret(draft1).unwrap();

    // Secret in core-banking / staging
    let draft2 = SecretDraft::new(
        core_proj.id,
        staging_env.id,
        "STAGE_SECRET",
        SecretKind::EnvVar,
        "resolved_with_env_flag_override",
        None,
    );
    secwet.create_secret(draft2).unwrap();

    // Create a 2nd project: payments-service / development
    secwet.create_project("payments-service", &["development".to_string()])
        .unwrap();
    let pay_proj = secwet.list_projects()
        .unwrap()
        .into_iter()
        .find(|p| p.name == "payments-service")
        .unwrap();
    let pay_dev_env = &pay_proj.environments[0];

    let draft3 = SecretDraft::new(
        pay_proj.id,
        pay_dev_env.id,
        "PAYMENTS_SECRET",
        SecretKind::EnvVar,
        "resolved_with_full_cli_override",
        None,
    );
    secwet.create_secret(draft3).unwrap();
    secwet.lock();

    // Write .secwet.toml at root
    let toml_path = root.join(".secwet.toml");
    let toml_content = format!(
        r#"
project = "core-banking"
env = "production"
data_dir = "{}"
"#,
        secwet_dir.display()
    );
    std::fs::write(&toml_path, toml_content).unwrap();

    // Create a deeply nested directory (4 levels deep)
    let deep_dir = root
        .join("services")
        .join("gateway")
        .join("src")
        .join("internal");
    std::fs::create_dir_all(&deep_dir).unwrap();

    // Case A: Run from deep subdirectory with NO flags.
    // Must find .secwet.toml in root and use core-banking / production.
    let mut cmd_a = Command::cargo_bin("secwet").unwrap();
    let out_a = cmd_a
        .current_dir(&deep_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "DISCOVERY_SECRET"])
        .assert()
        .success();
    assert_eq!(out_a.get_output().stdout, b"resolved_from_parent_toml_prod");

    // Case B: Run from deep subdirectory with CLI `--env staging` flag.
    // Must override env from .secwet.toml while keeping project = core-banking.
    let mut cmd_b = Command::cargo_bin("secwet").unwrap();
    let out_b = cmd_b
        .current_dir(&deep_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "STAGE_SECRET", "-e", "staging"])
        .assert()
        .success();
    assert_eq!(
        out_b.get_output().stdout,
        b"resolved_with_env_flag_override"
    );

    // Case C: Run from deep subdirectory with full CLI override `-p payments-service -e development`.
    // Must override both project and env.
    let mut cmd_c = Command::cargo_bin("secwet").unwrap();
    let out_c = cmd_c
        .current_dir(&deep_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "get",
            "PAYMENTS_SECRET",
            "-p",
            "payments-service",
            "-e",
            "development",
        ])
        .assert()
        .success();
    assert_eq!(
        out_c.get_output().stdout,
        b"resolved_with_full_cli_override"
    );

    // Case D: Corrupted .secwet.toml returns exit code 64
    std::fs::write(&toml_path, "MALFORMED [[[ TOML").unwrap();
    let mut cmd_d = Command::cargo_bin("secwet").unwrap();
    cmd_d
        .current_dir(&deep_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "DISCOVERY_SECRET"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("configuration error"));
}

#[test]
fn test_adversarial_secwet_toml_default_env_fallback() {
    let temp = tempdir().unwrap();
    let root = temp.path();

    // Secwet has project "service-a" with environments "Development" and "production"
    let mut secwet = setup_test_secwet(root, "service-a", &["production", "Development"]);
    let proj = secwet.list_projects().unwrap().remove(0);
    let dev_env = proj
        .environments
        .iter()
        .find(|e| e.name == "Development")
        .unwrap();

    let draft = SecretDraft::new(
        proj.id,
        dev_env.id,
        "DEV_FALLBACK_VAR",
        SecretKind::EnvVar,
        "default_dev_val",
        None,
    );
    secwet.create_secret(draft).unwrap();
    secwet.lock();

    // Write .secwet.toml specifying project and data_dir, but NO env
    let toml_path = root.join(".secwet.toml");
    std::fs::write(
        &toml_path,
        format!("project = \"service-a\"\ndata_dir = \"{}\"\n", root.display()),
    )
    .unwrap();

    // Invoking get without --env should automatically resolve to "Development"
    let mut cmd = Command::cargo_bin("secwet").unwrap();
    let output = cmd
        .current_dir(root)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "DEV_FALLBACK_VAR"])
        .assert()
        .success();
    assert_eq!(output.get_output().stdout, b"default_dev_val");
}

// =========================================================================
// 5. Dotenv Edge Cases: Comments, Quotes, Whitespace, Special Characters
// =========================================================================

#[test]
fn test_adversarial_dotenv_parser_edge_cases() {
    let dotenv_data = r#"
# ====================================================
# Comprehensive Adversarial Dotenv Test File
# ====================================================

    # Indented full line comment with spaces
	# Indented full line comment with tabs

# Empty lines below:


# 1. Standard unquoted and inline comment
STANDARD_KEY=standard_value # inline comment after spaces
HEX_COLOR_HASH=#00FF99
URL_WITH_HASH=https://example.com/api#section_anchor

# 2. Whitespace handling
  SPACED_KEY_1   =   spaced_value_unquoted   
SPACED_KEY_2="  preserved_spaces_quoted  "
EMPTY_VALUE=""
EMPTY_UNQUOTED=

# 3. Double quotes and escapes
DOUBLE_QUOTES="hello \"world\" \n \t \r \\ escaped"
MULTILINE_DOUBLE="line1
line2
line3"

# 4. Single quotes (literal semantics, no escape expansion)
SINGLE_QUOTES='hello\nworld\ttab$NO_EXPAND'
SINGLE_WITH_HASH='literal#hash # not a comment'

# 5. Export prefixes
export EXPORTED_VAR=exported_val
export	EXPORTED_TAB=exported_tab_val
export EXPORTED_QUOTED="exported double"

# 6. Symbols and special characters
EQUALS_IN_VALUE="a=1&b=2&c=3"
SQL_CONNECTION="Server=127.0.0.1;Port=5432;Database=mydb;User=secwet;Password=p@$$w0rd!#%^&*();"
UNICODE_VALUES="Hello 🌍 🦀 日本語"

# End of file comment without trailing newline
# Final comment"#;

    let parsed = parse_dotenv(dotenv_data).expect("dotenv parse must succeed");
    let map: std::collections::HashMap<String, String> = parsed.into_iter().collect();

    assert_eq!(map.get("STANDARD_KEY").unwrap(), "standard_value");
    assert_eq!(map.get("HEX_COLOR_HASH").unwrap(), "#00FF99");
    assert_eq!(
        map.get("URL_WITH_HASH").unwrap(),
        "https://example.com/api#section_anchor"
    );

    assert_eq!(map.get("SPACED_KEY_1").unwrap(), "spaced_value_unquoted");
    assert_eq!(
        map.get("SPACED_KEY_2").unwrap(),
        "  preserved_spaces_quoted  "
    );
    assert_eq!(map.get("EMPTY_VALUE").unwrap(), "");
    assert_eq!(map.get("EMPTY_UNQUOTED").unwrap(), "");

    assert_eq!(
        map.get("DOUBLE_QUOTES").unwrap(),
        "hello \"world\" \n \t \r \\ escaped"
    );
    assert_eq!(map.get("MULTILINE_DOUBLE").unwrap(), "line1\nline2\nline3");

    assert_eq!(
        map.get("SINGLE_QUOTES").unwrap(),
        "hello\\nworld\\ttab$NO_EXPAND"
    );
    assert_eq!(
        map.get("SINGLE_WITH_HASH").unwrap(),
        "literal#hash # not a comment"
    );

    assert_eq!(map.get("EXPORTED_VAR").unwrap(), "exported_val");
    assert_eq!(map.get("EXPORTED_TAB").unwrap(), "exported_tab_val");
    assert_eq!(map.get("EXPORTED_QUOTED").unwrap(), "exported double");

    assert_eq!(map.get("EQUALS_IN_VALUE").unwrap(), "a=1&b=2&c=3");
    assert_eq!(
        map.get("SQL_CONNECTION").unwrap(),
        "Server=127.0.0.1;Port=5432;Database=mydb;User=secwet;Password=p@$$w0rd!#%^&*();"
    );
    assert_eq!(map.get("UNICODE_VALUES").unwrap(), "Hello 🌍 🦀 日本語");
}

#[test]
fn test_adversarial_dotenv_invalid_inputs_fail_gracefully() {
    // 1. Unclosed double quote
    assert!(parse_dotenv("BAD=\"unclosed quote\n").is_err());

    // 2. Unclosed single quote
    assert!(parse_dotenv("BAD='unclosed quote\n").is_err());

    // 3. Line without '='
    assert!(parse_dotenv("JUST_A_BARE_KEY\n").is_err());

    // 4. Invalid secret name (starts with digit)
    assert!(parse_dotenv("123INVALID=value\n").is_err());

    // 5. Invalid secret name (contains space)
    assert!(parse_dotenv("INVALID NAME=value\n").is_err());

    // 6. Invalid secret name (non-ASCII characters)
    assert!(parse_dotenv("КЛЮЧ=value\n").is_err());
    assert!(parse_dotenv("API_SECRET_🦀=value\n").is_err());

    // 7. Invalid secret name (contains forbidden symbols like '$', ':')
    assert!(parse_dotenv("SECRET$NAME=value\n").is_err());
    assert!(parse_dotenv("SECRET:NAME=value\n").is_err());

    // 8. Secret value exceeding 64 KiB
    let huge_val = "x".repeat(65_537);
    let huge_input = format!("HUGE_VAL=\"{huge_val}\"\n");
    assert!(parse_dotenv(&huge_input).is_err());
}

#[test]
fn test_adversarial_cli_import_and_update_roundtrip() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path();

    let secwet = setup_test_secwet(data_dir, "import-proj", &["development"]);
    secwet.lock();

    // Initial import
    let env_file_1 = data_dir.join("v1.env");
    let content_1 = r#"
# Initial values
INITIAL_VAR=v1_val
UPDATE_ME=original_val
"#;
    std::fs::write(&env_file_1, content_1).unwrap();

    let mut cmd1 = Command::cargo_bin("secwet").unwrap();
    cmd1.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "import",
            env_file_1.to_str().unwrap(),
            "-p",
            "import-proj",
            "-e",
            "development",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Imported 2 secret(s) (2 created, 0 updated)",
        ));

    // Second import: updates UPDATE_ME, keeps INITIAL_VAR untouched, adds NEW_VAR
    let env_file_2 = data_dir.join("v2.env");
    let content_2 = r#"
UPDATE_ME=updated_v2_val
NEW_VAR=newly_added_val
"#;
    std::fs::write(&env_file_2, content_2).unwrap();

    let mut cmd2 = Command::cargo_bin("secwet").unwrap();
    cmd2.env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "import",
            env_file_2.to_str().unwrap(),
            "-p",
            "import-proj",
            "-e",
            "development",
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains(
            "Imported 2 secret(s) (1 created, 1 updated)",
        ));

    // Verify values via secwet get
    let mut get1 = Command::cargo_bin("secwet").unwrap();
    let out1 = get1
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args([
            "get",
            "INITIAL_VAR",
            "-p",
            "import-proj",
            "-e",
            "development",
        ])
        .assert()
        .success();
    assert_eq!(out1.get_output().stdout, b"v1_val");

    let mut get2 = Command::cargo_bin("secwet").unwrap();
    let out2 = get2
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "UPDATE_ME", "-p", "import-proj", "-e", "development"])
        .assert()
        .success();
    assert_eq!(out2.get_output().stdout, b"updated_v2_val");

    let mut get3 = Command::cargo_bin("secwet").unwrap();
    let out3 = get3
        .env("SECWET_DATA_DIR", data_dir)
        .env("SECWET_TEST_KEYSTORE", "memory")
        .args(["get", "NEW_VAR", "-p", "import-proj", "-e", "development"])
        .assert()
        .success();
    assert_eq!(out3.get_output().stdout, b"newly_added_val");
}

// =========================================================================
// 6. SQLite WAL Concurrency: CLI and Open Secwet Simultaneous Access
// =========================================================================

#[test]
fn test_adversarial_concurrency_cli_and_open_secwet_wal() {
    let temp = tempdir().unwrap();
    let data_dir = temp.path().to_path_buf();

    let keystore = FileKeyStore::new(data_dir.join(".test_keystore.json"));
    let mut secwet = Secwet::create(&data_dir, "concurrency-adversary", &keystore).unwrap();
    let project = secwet.create_project("wal-stress", &["production".to_string()])
        .unwrap();
    let env_id = project.environments[0].id;

    // Seed with initial secrets
    for i in 0..5 {
        let name = format!("SEED_SECRET_{i}");
        let val = format!("seed_value_{i}");
        let draft = SecretDraft::new(project.id, env_id, &name, SecretKind::EnvVar, &val, None);
        secwet.create_secret(draft).unwrap();
    }

    let running = Arc::new(AtomicBool::new(true));

    // Spawn 4 concurrent worker threads running CLI commands (list, get, set, status)
    let mut handles = Vec::new();

    // Worker 1: repeatedly runs `secwet list`
    let data_dir_1 = data_dir.clone();
    let running_1 = Arc::clone(&running);
    handles.push(std::thread::spawn(move || {
        let mut count = 0;
        while running_1.load(Ordering::Relaxed) && count < 15 {
            let mut cmd = Command::cargo_bin("secwet").unwrap();
            cmd.env("SECWET_DATA_DIR", &data_dir_1)
                .env("SECWET_TEST_KEYSTORE", "memory")
                .args(["list", "-p", "wal-stress", "-e", "production"])
                .assert()
                .success();
            count += 1;
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        count
    }));

    // Worker 2: repeatedly runs `secwet get SEED_SECRET_0`
    let data_dir_2 = data_dir.clone();
    let running_2 = Arc::clone(&running);
    handles.push(std::thread::spawn(move || {
        let mut count = 0;
        while running_2.load(Ordering::Relaxed) && count < 15 {
            let mut cmd = Command::cargo_bin("secwet").unwrap();
            let output = cmd
                .env("SECWET_DATA_DIR", &data_dir_2)
                .env("SECWET_TEST_KEYSTORE", "memory")
                .args([
                    "get",
                    "SEED_SECRET_0",
                    "-p",
                    "wal-stress",
                    "-e",
                    "production",
                ])
                .assert()
                .success();
            assert_eq!(output.get_output().stdout, b"seed_value_0");
            count += 1;
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        count
    }));

    // Worker 3: repeatedly runs `secwet set` with stdin pipes
    let data_dir_3 = data_dir.clone();
    let running_3 = Arc::clone(&running);
    handles.push(std::thread::spawn(move || {
        let mut count = 0;
        while running_3.load(Ordering::Relaxed) && count < 10 {
            let secret_name = format!("CLI_WRITTEN_{count}");
            let secret_val = format!("cli_val_{count}");
            let mut cmd = Command::cargo_bin("secwet").unwrap();
            cmd.env("SECWET_DATA_DIR", &data_dir_3)
                .env("SECWET_TEST_KEYSTORE", "memory")
                .args(["set", &secret_name, "-p", "wal-stress", "-e", "production"])
                .write_stdin(secret_val)
                .assert()
                .success();
            count += 1;
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        count
    }));

    // Worker 4: repeatedly runs `secwet status --json`
    let data_dir_4 = data_dir.clone();
    let running_4 = Arc::clone(&running);
    handles.push(std::thread::spawn(move || {
        let mut count = 0;
        while running_4.load(Ordering::Relaxed) && count < 15 {
            let mut cmd = Command::cargo_bin("secwet").unwrap();
            cmd.env("SECWET_DATA_DIR", &data_dir_4)
                .env("SECWET_TEST_KEYSTORE", "memory")
                .args(["status", "--json"])
                .assert()
                .success();
            count += 1;
            std::thread::sleep(std::time::Duration::from_millis(15));
        }
        count
    }));

    // Worker 5: repeatedly runs `secwet run` with secrets injected
    let data_dir_5 = data_dir.clone();
    let running_5 = Arc::clone(&running);
    handles.push(std::thread::spawn(move || {
        let mut count = 0;
        while running_5.load(Ordering::Relaxed) && count < 10 {
            let mut cmd = Command::cargo_bin("secwet").unwrap();
            cmd.env("SECWET_DATA_DIR", &data_dir_5)
                .env("SECWET_TEST_KEYSTORE", "memory")
                .args([
                    "run",
                    "-p",
                    "wal-stress",
                    "-e",
                    "production",
                    "--",
                    "sh",
                    "-c",
                    "test -n \"$SEED_SECRET_0\" && exit 0 || exit 1",
                ])
                .assert()
                .success();
            count += 1;
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        count
    }));

    // Meanwhile, in THIS thread, perform concurrent in-process Secwet mutations and reads
    for i in 0..15 {
        let name = format!("HOST_WRITTEN_{i}");
        let val = format!("host_val_{i}");
        let draft = SecretDraft::new(project.id, env_id, &name, SecretKind::EnvVar, &val, None);
        let meta = secwet.create_secret(draft)
            .expect("host secwet create_secret must succeed under concurrent CLI access");

        // Reveal the secret we just created
        let revealed = secwet.reveal_secret(meta.id)
            .expect("host secwet reveal_secret must succeed");
        assert_eq!(revealed.expose_secret(), val.as_str());

        // Update the secret
        let updated_val = format!("host_updated_{i}");
        let update_draft = SecretDraft::new(
            project.id,
            env_id,
            &name,
            SecretKind::EnvVar,
            &updated_val,
            None,
        );
        secwet.update_secret(meta.id, update_draft)
            .expect("host secwet update_secret must succeed");

        std::thread::sleep(std::time::Duration::from_millis(10));
    }

    running.store(false, Ordering::Relaxed);

    // Join all workers
    for h in handles {
        let op_count = h.join().expect("worker thread joined cleanly");
        assert!(op_count > 0, "worker performed at least one operation");
    }

    // Verify database consistency: both host and CLI secrets exist
    let all_secrets = secwet.list_environment_secrets(env_id)
        .expect("list secrets at end");
    assert!(
        all_secrets.iter().any(|s| s.name == "SEED_SECRET_0"),
        "seed secret must be present"
    );
    assert!(
        all_secrets.iter().any(|s| s.name == "HOST_WRITTEN_0"),
        "host-written secret must be present"
    );
    assert!(
        all_secrets
            .iter()
            .any(|s| s.name.starts_with("CLI_WRITTEN_")),
        "CLI-written secret must be present"
    );

    secwet.lock();
}
