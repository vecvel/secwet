//! Secwet lifecycle acceptance tests.

use secwet_core::keys::{KeyStore, MemoryStore, SecretVec};
use secwet_core::secwet::Settings;
use secwet_core::{Error, Result, SecretDraft, SecretKind, Secwet, SecwetStatus};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

/// KeyStore spy that checks no database files or directories exist on disk when keys are written.
struct SpyKeyStore {
    inner: MemoryStore,
    data_dir: PathBuf,
    keys_written_before_db: Arc<AtomicBool>,
    key_count: Arc<std::sync::atomic::AtomicUsize>,
}

impl SpyKeyStore {
    fn new(data_dir: &Path) -> Self {
        Self {
            inner: MemoryStore::new(),
            data_dir: data_dir.to_path_buf(),
            keys_written_before_db: Arc::new(AtomicBool::new(true)),
            key_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }
}

impl KeyStore for SpyKeyStore {
    fn get(&self, entry: &str) -> Result<Option<SecretVec<u8>>> {
        self.inner.get(entry)
    }

    fn set(&self, entry: &str, value: &[u8]) -> Result<()> {
        // Assert that neither secwet.sqlite3 nor the secwets/ subdirectory exists at the time of key writing
        let direct_db = self.data_dir.join("secwet.sqlite3");
        let secwet_dir = self.data_dir.join("secwet");

        if direct_db.exists() || secwet_dir.exists() {
            self.keys_written_before_db.store(false, Ordering::SeqCst);
        }

        self.key_count.fetch_add(1, Ordering::SeqCst);
        self.inner.set(entry, value)
    }

    fn delete(&self, entry: &str) -> Result<()> {
        self.inner.delete(entry)
    }
}

/// KeyStore that fails on every `set` operation.
struct FailingKeyStore;

impl KeyStore for FailingKeyStore {
    fn get(&self, _entry: &str) -> Result<Option<SecretVec<u8>>> {
        Ok(None)
    }

    fn set(&self, _entry: &str, _value: &[u8]) -> Result<()> {
        Err(Error::KeyStore)
    }

    fn delete(&self, _entry: &str) -> Result<()> {
        Ok(())
    }
}

/// Acceptance test: `create_writes_keys_before_db`
///
/// Verifies:
/// 1. `KeyStore::set` is called for device keys and epoch 1 secwet key BEFORE database creation.
/// 2. Database files and directories do not exist on disk when `set` executes.
#[test]
fn create_writes_keys_before_db() {
    let dir = tempdir().expect("failed to create temp dir");
    let spy = SpyKeyStore::new(dir.path());
    let keys_before_flag = spy.keys_written_before_db.clone();
    let count_atomic = spy.key_count.clone();

    let secwet =
        Secwet::create(dir.path(), "test-laptop", &spy).expect("Secwet::create should succeed");

    assert!(
        keys_before_flag.load(Ordering::SeqCst),
        "KeyStore writes must occur BEFORE any database file or directory is created on disk"
    );
    assert_eq!(
        count_atomic.load(Ordering::SeqCst),
        3,
        "Exactly 3 keys (device-sign, device-enc, master-key/1) must be written during creation"
    );

    // Verify database file exists after creation
    let secwet_db = dir
        .path()
        .join("secwet")
        .join(secwet.secwet_id().to_string())
        .join("secwet.sqlite3");
    assert!(
        secwet_db.is_file(),
        "Database file must exist on disk after successful create"
    );

    secwet.lock();
}

/// Acceptance test: `create_fails_cleanly_when_keystore_fails`
///
/// Verifies:
/// 1. `Secwet::create` aborts cleanly if `KeyStore::set` returns `Error::KeyStore`.
/// 2. No database files, lock files, or temporary directories remain in `data_dir`.
#[test]
fn create_fails_cleanly_when_keystore_fails() {
    let dir = tempdir().expect("failed to create temp dir");
    let failing_store = FailingKeyStore;

    let res = Secwet::create(dir.path(), "broken-keystore-device", &failing_store);

    assert!(
        matches!(res, Err(Error::KeyStore)),
        "Expected Error::KeyStore when keystore fails"
    );

    // Verify data_dir is completely clean
    let entry_count = std::fs::read_dir(dir.path()).expect("read_dir").count();
    assert_eq!(
        entry_count, 0,
        "No database file, lock file, or temporary directories may remain in data_dir on keystore failure"
    );
}

/// Acceptance test: `status_uninitialized_then_unlocked`
///
/// Verifies:
/// 1. Status is `Uninitialized` before creation.
/// 2. `Secwet::create` yields an active, unlocked secwet.
/// 3. Status reflects `Unlocked` while open.
/// 4. Calling `secwet.lock()` transitions status to `Locked`.
/// 5. Calling `Secwet::unlock` transitions status back to `Unlocked`.
#[test]
fn status_uninitialized_then_unlocked() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    // 1. Before creation
    let status = Secwet::status(dir.path()).expect("Secwet::status");
    assert_eq!(
        status,
        SecwetStatus::Uninitialized,
        "Status must be Uninitialized before creation"
    );

    // 2. Create secwet
    let secwet =
        Secwet::create(dir.path(), "test-device", &keystore).expect("Secwet::create should succeed");
    let secwet_id = secwet.secwet_id();

    // 3. Status while unlocked
    let status_unlocked = Secwet::status(dir.path()).expect("Secwet::status");
    assert_eq!(
        status_unlocked,
        SecwetStatus::Unlocked { secwet_id },
        "Status must reflect Unlocked while secwet is active"
    );

    // 4. Lock secwet
    secwet.lock();
    let status_locked = Secwet::status(dir.path()).expect("Secwet::status");
    assert_eq!(
        status_locked,
        SecwetStatus::Locked { secwet_id },
        "Status must reflect Locked after lock()"
    );

    // 5. Unlock secwet
    let unlocked_secwet = Secwet::unlock(dir.path(), &keystore).expect("Secwet::unlock");
    assert_eq!(unlocked_secwet.secwet_id(), secwet_id);

    let status_reunlocked = Secwet::status(dir.path()).expect("Secwet::status");
    assert_eq!(
        status_reunlocked,
        SecwetStatus::Unlocked { secwet_id },
        "Status must reflect Unlocked after unlock()"
    );

    unlocked_secwet.lock();
}

#[test]
fn unlock_fails_cleanly_when_keystore_missing_keys() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let secwet = Secwet::create(dir.path(), "test-device", &keystore).unwrap();
    let _secwet_id = secwet.secwet_id();
    secwet.lock();

    // Wipe keystore
    keystore.clear().unwrap();

    // Attempt unlock
    let err = Secwet::unlock(dir.path(), &keystore).expect_err("unlock should fail without keys");
    assert!(
        matches!(err, Error::KeyStore),
        "Expected Error::KeyStore when keystore is missing keys"
    );
}

#[test]
fn overview_aggregates_counts_and_recent() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "MacBook Pro", &keystore).unwrap();

    // Initially 0 projects, 0 environments, 0 secrets, 1 active device
    let ov1 = secwet.overview().unwrap();
    assert_eq!(ov1.projects_count, 0);
    assert_eq!(ov1.environments_count, 0);
    assert_eq!(ov1.secrets_count, 0);
    assert_eq!(ov1.active_devices_count, 1);
    assert!(ov1.checklist.secwet_created);
    assert!(!ov1.checklist.recovery_key_created);
    assert!(!ov1.checklist.cli_connected);

    // Create a project with default 3 environments
    let proj = secwet.create_project("Backend", &[]).unwrap();
    let dev_env = proj.environments[0].id;

    // Create 6 secrets in dev_env
    for i in 1..=6 {
        secwet
            .create_secret(SecretDraft::new(
                proj.id,
                dev_env,
                format!("KEY_{i}"),
                SecretKind::ApiKey,
                format!("val_{i}"),
                None,
            ))
            .unwrap();
    }

    let ov2 = secwet.overview().unwrap();
    assert_eq!(ov2.projects_count, 1);
    assert_eq!(ov2.environments_count, 3);
    assert_eq!(ov2.secrets_count, 6);
    assert_eq!(
        ov2.recent.len(),
        5,
        "overview.recent must contain at most 5 items"
    );

    // Check that recent secrets are metadata only (names and timestamps)
    assert_eq!(ov2.recent[0].project_name, "Backend");
    assert_eq!(ov2.recent[0].environment_name, "Development");

    secwet.lock();
}

#[test]
fn env_for_returns_all_secrets() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "dev", &keystore).unwrap();
    let p = secwet.create_project("app", &[]).unwrap();
    let env_id = p.environments[0].id;

    secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_id,
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://localhost:5432/db",
            None,
        ))
        .unwrap();

    secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_id,
            "PORT",
            SecretKind::EnvVar,
            "8080",
            None,
        ))
        .unwrap();

    let env_vars = secwet.env_for_environment(env_id).unwrap();
    assert_eq!(env_vars.len(), 2);

    use secrecy::ExposeSecret;
    let map: std::collections::HashMap<String, String> = env_vars
        .into_iter()
        .map(|(k, v)| (k, v.expose_secret().to_string()))
        .collect();

    assert_eq!(
        map.get("DATABASE_URL").unwrap(),
        "postgres://localhost:5432/db"
    );
    assert_eq!(map.get("PORT").unwrap(), "8080");

    secwet.lock();
}

#[test]
fn settings_defaults_and_roundtrip() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    // 1. Create secwet with initial device name
    let mut secwet = Secwet::create(dir.path(), "MacBook Pro M3", &keystore).unwrap();

    // 2. Verify defaults
    let initial_settings = secwet.settings().expect("settings() should succeed");
    assert_eq!(initial_settings.theme, "system");
    assert_eq!(initial_settings.lock_timeout_minutes, 15);
    assert_eq!(initial_settings.device_name, "MacBook Pro M3");

    // 3. Update settings
    let updated = Settings {
        theme: "dark".to_string(),
        lock_timeout_minutes: 60,
        device_name: "Office Workstation".to_string(),
    };
    secwet
        .set_settings(updated.clone())
        .expect("set_settings() should succeed");

    // Verify immediate reflection
    let read_back = secwet.settings().unwrap();
    assert_eq!(read_back, updated);

    // 4. Verify persistence across lock/unlock cycle
    secwet.lock();
    let unlocked = Secwet::unlock(dir.path(), &keystore).expect("unlock");
    let persisted = unlocked.settings().expect("settings after restart");
    assert_eq!(persisted, updated);

    unlocked.lock();
}

#[test]
fn settings_validation_enforces_allowed_values() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();
    let mut secwet = Secwet::create(dir.path(), "dev-device", &keystore).unwrap();

    // Invalid theme
    let err_theme = secwet
        .set_settings(Settings {
            theme: "neon-blue".to_string(),
            lock_timeout_minutes: 15,
            device_name: "dev-device".to_string(),
        })
        .unwrap_err();
    assert!(matches!(err_theme, Error::Invalid { field: "theme", .. }));

    // Invalid lock timeout
    let err_timeout = secwet
        .set_settings(Settings {
            theme: "light".to_string(),
            lock_timeout_minutes: 45, // not in 5, 15, 30, 60
            device_name: "dev-device".to_string(),
        })
        .unwrap_err();
    assert!(matches!(
        err_timeout,
        Error::Invalid {
            field: "lock_timeout_minutes",
            ..
        }
    ));

    // Empty device name
    let err_empty_name = secwet
        .set_settings(Settings {
            theme: "light".to_string(),
            lock_timeout_minutes: 30,
            device_name: "   ".to_string(),
        })
        .unwrap_err();
    assert!(matches!(
        err_empty_name,
        Error::Invalid {
            field: "device_name",
            ..
        }
    ));

    // Too long device name (> 64 chars)
    let err_long_name = secwet
        .set_settings(Settings {
            theme: "light".to_string(),
            lock_timeout_minutes: 30,
            device_name: "x".repeat(65),
        })
        .unwrap_err();
    assert!(matches!(
        err_long_name,
        Error::Invalid {
            field: "device_name",
            ..
        }
    ));

    secwet.lock();
}

#[test]
fn settings_device_name_is_never_stored_in_plaintext() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();
    let super_secret_device_name = "SuperSecretUniqDeviceLabel999";

    let mut secwet = Secwet::create(dir.path(), super_secret_device_name, &keystore).unwrap();
    let secwet_id = secwet.secwet_id();

    let updated_name = "AnotherVerySecretDeviceNameXYZ";
    secwet
        .set_settings(Settings {
            theme: "dark".to_string(),
            lock_timeout_minutes: 30,
            device_name: updated_name.to_string(),
        })
        .unwrap();

    secwet.lock();

    // Check disk bytes
    let db_path = dir
        .path()
        .join("secwet")
        .join(secwet_id.to_string())
        .join("secwet.sqlite3");
    let raw_bytes = std::fs::read(&db_path).expect("read db file");

    let needle1 = super_secret_device_name.as_bytes();
    let needle2 = updated_name.as_bytes();

    let found1 = raw_bytes.windows(needle1.len()).any(|w| w == needle1);
    let found2 = raw_bytes.windows(needle2.len()).any(|w| w == needle2);

    assert!(
        !found1,
        "Initial device name must never be found in plaintext in database bytes"
    );
    assert!(
        !found2,
        "Updated device name must never be found in plaintext in database bytes"
    );
}

#[test]
fn concurrent_secwet_readers_and_writers_wal() {
    let dir = tempdir().expect("failed to create temp dir");
    let keystore = MemoryStore::new();

    // Secwet created by "Desktop"
    let mut desktop_secwet = Secwet::create(dir.path(), "desktop", &keystore).unwrap();
    let p = desktop_secwet.create_project("Shared Project", &[]).unwrap();
    let env_id = p.environments[0].id;

    // "CLI" opens the secwet concurrently
    let mut cli_secwet = Secwet::unlock(dir.path(), &keystore).unwrap();

    // CLI creates a secret
    let meta = cli_secwet
        .create_secret(SecretDraft::new(
            p.id,
            env_id,
            "CLI_SECRET",
            SecretKind::Password,
            "super-secret-pass",
            None,
        ))
        .unwrap();

    // Desktop immediately sees the secret written by CLI
    let secrets_desktop = desktop_secwet.list_environment_secrets(env_id).unwrap();
    assert_eq!(secrets_desktop.len(), 1);
    assert_eq!(secrets_desktop[0].id, meta.id);

    // Desktop updates settings
    desktop_secwet
        .set_settings(Settings {
            theme: "dark".to_string(),
            lock_timeout_minutes: 30,
            device_name: "desktop".to_string(),
        })
        .unwrap();

    // CLI immediately reads the updated settings
    let cli_settings = cli_secwet.settings().unwrap();
    assert_eq!(cli_settings.theme, "dark");
    assert_eq!(cli_settings.lock_timeout_minutes, 30);

    desktop_secwet.lock();
    cli_secwet.lock();
}
