//! Persistent application state and access helpers for the Tauri host.

use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use secwet_core::keys::{KeyStore, KeyringStore, MemoryStore};
use secwet_core::{Vault, VaultStatus};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::UiError;

/// Discriminated status DTO for frontend consumption matching §9.1 and §13.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum VaultStatusDto {
    Uninitialized,
    Locked { vault_id: Uuid },
    Unlocked { vault_id: Uuid },
}

impl From<VaultStatus> for VaultStatusDto {
    fn from(s: VaultStatus) -> Self {
        match s {
            VaultStatus::Uninitialized => VaultStatusDto::Uninitialized,
            VaultStatus::Locked { vault_id } => VaultStatusDto::Locked { vault_id },
            VaultStatus::Unlocked { vault_id } => VaultStatusDto::Unlocked { vault_id },
        }
    }
}

/// Persistent shared state held and managed by Tauri.
pub struct AppState {
    pub vault: Mutex<Option<Vault>>,
    pub data_dir: PathBuf,
    pub keystore: Arc<dyn KeyStore>,
    pub clipboard_generation: Arc<AtomicU64>,
    pub clear_duration: Duration,
}

impl AppState {
    pub fn new(data_dir: PathBuf, keystore: Arc<dyn KeyStore>) -> Self {
        let clear_duration = std::env::var("SECWET_TEST_CLIPBOARD_CLEAR_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(30));

        Self {
            vault: Mutex::new(None),
            data_dir,
            keystore,
            clipboard_generation: Arc::new(AtomicU64::new(0)),
            clear_duration,
        }
    }

    /// Automatically discovers standard platform data_dir and keystore.
    pub fn default_state() -> Self {
        let data_dir = Self::resolve_data_dir();
        let keystore = Self::resolve_keystore();
        Self::new(data_dir, keystore)
    }

    /// Discovers data_dir: SECWET_DATA_DIR env override -> ProjectDirs -> .secwet fallback.
    pub fn resolve_data_dir() -> PathBuf {
        std::env::var_os("SECWET_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                directories::ProjectDirs::from("app", "secwet", "Secwet")
                    .map(|dirs| dirs.data_dir().to_path_buf())
                    .unwrap_or_else(|| PathBuf::from(".secwet"))
            })
    }

    /// Discovers keystore: MemoryStore if SECWET_TEST_KEYSTORE=memory; otherwise KeyringStore.
    pub fn resolve_keystore() -> Arc<dyn KeyStore> {
        if std::env::var("SECWET_TEST_KEYSTORE").as_deref() == Ok("memory") {
            return Arc::new(MemoryStore::new());
        }
        Arc::new(KeyringStore::new())
    }

    /// Executes a read-only closure with the unlocked vault.
    pub fn with_vault<T, F>(&self, f: F) -> Result<T, UiError>
    where
        F: FnOnce(&Vault) -> Result<T, secwet_core::Error>,
    {
        let guard = self
            .vault
            .lock()
            .map_err(|_| UiError::internal("Vault mutex poisoned"))?;
        let vault = guard.as_ref().ok_or_else(UiError::vault_locked)?;
        f(vault).map_err(UiError::from)
    }

    /// Executes a mutating closure with the unlocked vault.
    pub fn with_vault_mut<T, F>(&self, f: F) -> Result<T, UiError>
    where
        F: FnOnce(&mut Vault) -> Result<T, secwet_core::Error>,
    {
        let mut guard = self
            .vault
            .lock()
            .map_err(|_| UiError::internal("Vault mutex poisoned"))?;
        let vault = guard.as_mut().ok_or_else(UiError::vault_locked)?;
        f(vault).map_err(UiError::from)
    }
}
