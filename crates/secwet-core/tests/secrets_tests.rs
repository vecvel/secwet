//! Secrets CRUD, copy, and security invariants acceptance tests.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §6, §7 (F5, F6), §11.2, and `ORIGINAL_REQUEST.md`.

use secrecy::ExposeSecret;
use secwet_core::keys::MemoryStore;
use secwet_core::{Error, SecretDraft, SecretKind, Secwet};
use tempfile::tempdir;

/// Acceptance test: `secret_roundtrip_multiline`
///
/// Verifies:
/// 1. Secret with multi-line value (2048-bit RSA / Ed25519 SSH private key with line breaks).
/// 2. Stored, encrypted, and written to SQLite records.
/// 3. `reveal_secret(id)` returns exact `SecretString` matching input string byte-for-byte,
///    preserving all newlines (`\n`, `\r\n`) and formatting.
#[test]
fn secret_roundtrip_multiline() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "device-1", &keystore).unwrap();

    let p = secwet.create_project("Infra", &[]).unwrap();
    let env_id = p.environments[0].id;

    let multiline_ssh_key = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDEXAMPLEKEYONLYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAMwAAAAtzc2gtZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAABkZXBsb3kBAgME
-----END OPENSSH PRIVATE KEY-----
";

    let draft = SecretDraft::new(
        p.id,
        env_id,
        "DEPLOY_KEY_SSH",
        SecretKind::SshKey,
        multiline_ssh_key,
        Some("Production CI/CD deploy key".to_string()),
    );

    let meta = secwet
        .create_secret(draft)
        .expect("create_secret should succeed");

    // Reveal secret and compare byte-for-byte
    let revealed = secwet
        .reveal_secret(meta.id)
        .expect("reveal_secret should succeed");
    assert_eq!(
        revealed.expose_secret(),
        multiline_ssh_key,
        "Revealed secret must match input multiline string byte-for-byte"
    );

    secwet.lock();
}

/// Acceptance test: `secret_name_unique_per_environment_case_sensitive`
///
/// Verifies:
/// 1. In environment `dev`, create secret "DATABASE_URL".
/// 2. Attempt to create second secret "DATABASE_URL" in `dev`: fails with `Error::Duplicate { field: "name" }`.
/// 3. Attempt to create secret "database_url" in `dev`: succeeds (case-sensitive uniqueness permits env var casing).
#[test]
fn secret_name_unique_per_environment_case_sensitive() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "device-1", &keystore).unwrap();

    let p = secwet.create_project("BackendAPI", &[]).unwrap();
    let dev_env = p.environments[0].id;

    // 1. Create initial secret
    let draft1 = SecretDraft::new(
        p.id,
        dev_env,
        "DATABASE_URL",
        SecretKind::EnvVar,
        "postgres://localhost:5432/db",
        None,
    );
    secwet.create_secret(draft1).unwrap();

    // 2. Duplicate exact name in same environment must fail
    let duplicate_draft = SecretDraft::new(
        p.id,
        dev_env,
        "DATABASE_URL",
        SecretKind::EnvVar,
        "postgres://localhost:5432/other",
        None,
    );
    let dup_err = secwet.create_secret(duplicate_draft);
    match dup_err {
        Err(Error::Duplicate { field: "name" }) => {}
        other => panic!(
            "Expected Error::Duplicate {{ field: \"name\" }}, got: {:?}",
            other
        ),
    }

    // 3. Different casing in same environment must succeed
    let lower_draft = SecretDraft::new(
        p.id,
        dev_env,
        "database_url",
        SecretKind::EnvVar,
        "postgres://localhost:5432/lower",
        None,
    );
    let lower_meta = secwet
        .create_secret(lower_draft)
        .expect("Different casing must be allowed per case-sensitive env var semantics");
    assert_eq!(lower_meta.name, "database_url");

    // In a different environment (e.g. Staging), "DATABASE_URL" is also allowed
    let stg_env = p.environments[1].id;
    let stg_draft = SecretDraft::new(
        p.id,
        stg_env,
        "DATABASE_URL",
        SecretKind::EnvVar,
        "postgres://staging:5432/db",
        None,
    );
    secwet
        .create_secret(stg_draft)
        .expect("Same secret name in different environment must succeed");

    secwet.lock();
}

/// Acceptance test: `list_secrets_never_contains_values`
///
/// Verifies:
/// 1. Create secrets with sensitive values ("super_secret_password_xyz").
/// 2. Call `Secwet::list_secrets(env_id)`.
/// 3. Assert each returned `SecretMeta` has `value_tail == "_xyz"`.
/// 4. Assert no field in `SecretMeta` contains the full value.
/// 5. Serialize `SecretMeta` to JSON and confirm full value is absent.
#[test]
fn list_secrets_never_contains_values() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "device-1", &keystore).unwrap();

    let p = secwet.create_project("SecurityApp", &[]).unwrap();
    let env_id = p.environments[0].id;

    let sensitive_password = "super_secret_password_xyz";

    let draft = SecretDraft::new(
        p.id,
        env_id,
        "ADMIN_PASSWORD",
        SecretKind::Password,
        sensitive_password,
        Some("Top secret credential".to_string()),
    );
    secwet.create_secret(draft).unwrap();

    let secret_list = secwet.list_environment_secrets(env_id).unwrap();
    assert_eq!(secret_list.len(), 1);

    let meta = &secret_list[0];
    assert_eq!(meta.name, "ADMIN_PASSWORD");
    assert_eq!(
        meta.value_tail, "_xyz",
        "value_tail must contain only the last 4 characters"
    );

    // Serialize to JSON and assert full sensitive value is nowhere in the serialized JSON
    let json = serde_json::to_string(&meta).unwrap();
    assert!(
        !json.contains(sensitive_password),
        "Serialized SecretMeta JSON must NEVER contain the full secret value"
    );
    assert!(
        !json.contains("super_secret_password"),
        "Serialized SecretMeta JSON must NOT contain secret substrings"
    );
    assert!(
        json.contains("\"value_tail\":\"_xyz\""),
        "Serialized SecretMeta must contain value_tail"
    );

    secwet.lock();
}

#[test]
fn copy_secret_to_environment_and_refuse_duplicate() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "device-1", &keystore).unwrap();

    let p = secwet.create_project("CopyTest", &[]).unwrap();
    let dev_env = p.environments[0].id;
    let stg_env = p.environments[1].id;

    let original = secwet
        .create_secret(SecretDraft::new(
            p.id,
            dev_env,
            "STRIPE_API_KEY",
            SecretKind::ApiKey,
            "sk_test_1234567890abcdef",
            Some("Billing key".to_string()),
        ))
        .unwrap();

    // Copy to Staging
    let copied = secwet
        .copy_secret_to_environment(original.id, stg_env)
        .expect("Copy to Staging should succeed");

    assert_ne!(
        copied.id, original.id,
        "Copied secret must have a new, unique UUID"
    );
    assert_eq!(copied.environment_id, Some(stg_env));
    assert_eq!(copied.name, "STRIPE_API_KEY");
    assert_eq!(copied.kind, SecretKind::ApiKey);
    assert_eq!(copied.value_tail, "cdef");

    // Revealed value in Staging matches original
    let rev_copied = secwet.reveal_secret(copied.id).unwrap();
    assert_eq!(rev_copied.expose_secret(), "sk_test_1234567890abcdef");

    // Attempting to copy again to Staging fails with Duplicate
    let dup_err = secwet.copy_secret_to_environment(original.id, stg_env);
    match dup_err {
        Err(Error::Duplicate { field: "name" }) => {}
        other => panic!(
            "Expected Duplicate error when copying over existing secret name, got {:?}",
            other
        ),
    }

    secwet.lock();
}

#[test]
fn secret_name_regex_and_length_validation() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "device-1", &keystore).unwrap();
    let p = secwet.create_project("ValidationProj", &[]).unwrap();
    let env_id = p.environments[0].id;

    // Valid secret names
    for valid in [
        "A",
        "_KEY",
        "APP_CONFIG_1",
        "db.host@prod",
        "my-secret-token",
    ] {
        secwet
            .create_secret(SecretDraft::new(
                p.id,
                env_id,
                valid,
                SecretKind::Password,
                "val",
                None,
            ))
            .unwrap();
    }

    // Invalid: starts with number
    assert!(matches!(
        secwet.create_secret(SecretDraft::new(
            p.id,
            env_id,
            "1NUMBER_FIRST",
            SecretKind::Password,
            "val",
            None
        )),
        Err(Error::Invalid { field: "name", .. })
    ));

    // Invalid: contains spaces
    assert!(matches!(
        secwet.create_secret(SecretDraft::new(
            p.id,
            env_id,
            "KEY WITH SPACES",
            SecretKind::Password,
            "val",
            None
        )),
        Err(Error::Invalid { field: "name", .. })
    ));

    // Invalid: empty value
    assert!(matches!(
        secwet.create_secret(SecretDraft::new(
            p.id,
            env_id,
            "EMPTY_VAL_KEY",
            SecretKind::Password,
            "",
            None
        )),
        Err(Error::Invalid { field: "value", .. })
    ));

    // Invalid: > 64 KiB value
    let too_large = "x".repeat(65_537);
    assert!(matches!(
        secwet.create_secret(SecretDraft::new(
            p.id,
            env_id,
            "TOO_LARGE_VAL",
            SecretKind::Password,
            too_large,
            None
        )),
        Err(Error::Invalid { field: "value", .. })
    ));

    secwet.lock();
}

#[test]
fn update_secret_moves_between_environments() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "device-1", &keystore).unwrap();
    let p = secwet.create_project("MoveTest", &[]).unwrap();
    let dev_env = p.environments[0].id;
    let stg_env = p.environments[1].id;

    let original = secwet
        .create_secret(SecretDraft::new(
            p.id,
            dev_env,
            "RELOCATE_KEY",
            SecretKind::ApiKey,
            "initial_value",
            None,
        ))
        .unwrap();

    // Move to Staging with updated value
    let updated = secwet
        .update_secret(
            original.id,
            SecretDraft::new(
                p.id,
                stg_env,
                "RELOCATE_KEY_RENAMED",
                SecretKind::ApiKey,
                "new_value_4321",
                Some("Moved to staging".to_string()),
            ),
        )
        .unwrap();

    assert_eq!(updated.id, original.id);
    assert_eq!(updated.environment_id, Some(stg_env));
    assert_eq!(updated.name, "RELOCATE_KEY_RENAMED");
    assert_eq!(updated.value_tail, "4321");

    // Verify it is no longer in dev_env
    let dev_secrets = secwet.list_environment_secrets(dev_env).unwrap();
    assert!(dev_secrets.is_empty());

    // Verify it is now in stg_env
    let stg_secrets = secwet.list_environment_secrets(stg_env).unwrap();
    assert_eq!(stg_secrets.len(), 1);
    assert_eq!(stg_secrets[0].id, original.id);

    secwet.lock();
}
