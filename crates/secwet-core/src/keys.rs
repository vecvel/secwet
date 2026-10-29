//! Key storage boundaries and platform secure enclave implementations.

use crate::{Error, Result};
use secrecy::{ExposeSecret, ExposeSecretMut};
#[cfg(any(test, feature = "test-util"))]
use std::sync::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Secure vector wrapper that zeroizes memory on drop and redacts in Debug.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct SecretVec<T: Zeroize + Clone = u8> {
    inner: Vec<T>,
}

impl<T: Zeroize + Clone> SecretVec<T> {
    pub fn new(vec: Vec<T>) -> Self {
        Self { inner: vec }
    }

    pub fn as_slice(&self) -> &[T] {
        &self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<T: Zeroize + Clone> ExposeSecret<[T]> for SecretVec<T> {
    fn expose_secret(&self) -> &[T] {
        &self.inner
    }
}

impl<T: Zeroize + Clone> ExposeSecretMut<[T]> for SecretVec<T> {
    fn expose_secret_mut(&mut self) -> &mut [T] {
        &mut self.inner
    }
}

impl<T: Zeroize + Clone> std::ops::Deref for SecretVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<T: Zeroize + Clone> From<Vec<T>> for SecretVec<T> {
    fn from(vec: Vec<T>) -> Self {
        Self::new(vec)
    }
}

impl<T: Zeroize + Clone> Zeroize for SecretVec<T> {
    fn zeroize(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize + Clone> Drop for SecretVec<T> {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl<T: Zeroize + Clone> ZeroizeOnDrop for SecretVec<T> {}

impl<T: Zeroize + Clone> std::fmt::Debug for SecretVec<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretVec([REDACTED])")
    }
}

/// Abstract interface for secure credential persistence across platforms.
pub trait KeyStore: Send + Sync {
    /// Retrieve raw secret bytes from secure storage.
    fn get(&self, entry: &str) -> Result<Option<SecretVec<u8>>>;

    /// Persist raw secret bytes to secure storage.
    fn set(&self, entry: &str, value: &[u8]) -> Result<()>;

    /// Remove an entry from secure storage.
    fn delete(&self, entry: &str) -> Result<()>;
}

/// Production OS Keychain/Credential Manager backend using the `keyring` crate.
#[cfg(feature = "os-keyring")]
#[derive(Debug, Default, Clone)]
pub struct KeyringStore {
    service: String,
}

#[cfg(feature = "os-keyring")]
impl KeyringStore {
    pub const DEFAULT_SERVICE: &'static str = "secwet";

    pub fn new() -> Self {
        Self {
            service: Self::DEFAULT_SERVICE.to_string(),
        }
    }

    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn user_for_entry<'a>(&self, entry: &'a str) -> &'a str {
        entry.strip_prefix("secwet/").unwrap_or(entry)
    }
}

#[cfg(feature = "os-keyring")]
impl KeyStore for KeyringStore {
    fn get(&self, entry: &str) -> Result<Option<SecretVec<u8>>> {
        let user = self.user_for_entry(entry);
        let keyring_entry =
            keyring::Entry::new(&self.service, user).map_err(|_| Error::KeyStore)?;
        match keyring_entry.get_password() {
            Ok(pw) => {
                let bytes = data_encoding::HEXLOWER
                    .decode(pw.as_bytes())
                    .map_err(|_| Error::KeyStore)?;
                Ok(Some(SecretVec::new(bytes)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(_) => Err(Error::KeyStore),
        }
    }

    fn set(&self, entry: &str, value: &[u8]) -> Result<()> {
        let user = self.user_for_entry(entry);
        let keyring_entry =
            keyring::Entry::new(&self.service, user).map_err(|_| Error::KeyStore)?;
        let encoded = data_encoding::HEXLOWER.encode(value);
        keyring_entry
            .set_password(&encoded)
            .map_err(|_| Error::KeyStore)?;
        Ok(())
    }

    fn delete(&self, entry: &str) -> Result<()> {
        let user = self.user_for_entry(entry);
        let keyring_entry =
            keyring::Entry::new(&self.service, user).map_err(|_| Error::KeyStore)?;
        match keyring_entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(Error::KeyStore),
        }
    }
}

/// Thread-safe in-memory store for testing and mock environments.
#[cfg(any(test, feature = "test-util"))]
#[derive(Default, Debug)]
pub struct MemoryStore {
    storage: RwLock<std::collections::HashMap<String, Vec<u8>>>,
}

#[cfg(any(test, feature = "test-util"))]
impl MemoryStore {
    pub fn new() -> Self {
        Self {
            storage: RwLock::new(std::collections::HashMap::new()),
        }
    }

    pub fn clear(&self) -> Result<()> {
        let mut map = self.storage.write().map_err(|_| Error::KeyStore)?;
        map.clear();
        Ok(())
    }
}

#[cfg(any(test, feature = "test-util"))]
impl KeyStore for MemoryStore {
    fn get(&self, entry: &str) -> Result<Option<SecretVec<u8>>> {
        let map = self.storage.read().map_err(|_| Error::KeyStore)?;
        Ok(map.get(entry).cloned().map(SecretVec::new))
    }

    fn set(&self, entry: &str, value: &[u8]) -> Result<()> {
        let mut map = self.storage.write().map_err(|_| Error::KeyStore)?;
        map.insert(entry.to_string(), value.to_vec());
        Ok(())
    }

    fn delete(&self, entry: &str) -> Result<()> {
        let mut map = self.storage.write().map_err(|_| Error::KeyStore)?;
        map.remove(entry);
        Ok(())
    }
}
