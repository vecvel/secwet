//! Keystore backend selection and test persistence for secwet-cli.

use secwet_core::keys::{KeyStore, KeyringStore, SecretVec};
use secwet_core::{Error, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// File-backed keystore for integration testing across independent subprocesses.
#[derive(Debug, Clone)]
pub struct FileKeyStore {
    path: PathBuf,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn read_map(&self) -> HashMap<String, String> {
        if let Ok(bytes) = std::fs::read(&self.path) {
            serde_json::from_slice(&bytes).unwrap_or_default()
        } else {
            HashMap::new()
        }
    }

    fn write_map(&self, map: &HashMap<String, String>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let data = serde_json::to_vec(map).map_err(|_| Error::KeyStore)?;
        std::fs::write(&self.path, data).map_err(|_| Error::KeyStore)?;
        Ok(())
    }
}

impl KeyStore for FileKeyStore {
    fn get(&self, entry: &str) -> Result<Option<SecretVec<u8>>> {
        let map = self.read_map();
        if let Some(hex_val) = map.get(entry) {
            let bytes = data_encoding::HEXLOWER
                .decode(hex_val.as_bytes())
                .map_err(|_| Error::KeyStore)?;
            Ok(Some(SecretVec::new(bytes)))
        } else {
            Ok(None)
        }
    }

    fn set(&self, entry: &str, value: &[u8]) -> Result<()> {
        let mut map = self.read_map();
        map.insert(entry.to_string(), data_encoding::HEXLOWER.encode(value));
        self.write_map(&map)
    }

    fn delete(&self, entry: &str) -> Result<()> {
        let mut map = self.read_map();
        map.remove(entry);
        self.write_map(&map)
    }
}

/// Resolves the KeyStore implementation based on environment variables and secwet state.
pub fn resolve_keystore(data_dir: &Path) -> Box<dyn KeyStore> {
    if let Ok(val) = std::env::var("SECWET_TEST_KEYSTORE") {
        if val == "memory" || val == "file" || val == "1" || val == "true" {
            let file_path = data_dir.join(".test_keystore.json");
            return Box::new(FileKeyStore::new(file_path));
        } else if !val.is_empty() {
            return Box::new(FileKeyStore::new(PathBuf::from(val)));
        }
    }

    let test_file = data_dir.join(".test_keystore.json");
    if test_file.is_file() {
        return Box::new(FileKeyStore::new(test_file));
    }

    Box::new(KeyringStore::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_file_keystore_roundtrip() {
        let temp = tempdir().unwrap();
        let store_file = temp.path().join("keys.json");
        let store = FileKeyStore::new(&store_file);

        assert!(store.get("test/entry").unwrap().is_none());

        let payload = b"secret_encryption_key_1234567890";
        store.set("test/entry", payload).unwrap();

        let fetched = store.get("test/entry").unwrap().expect("must exist");
        assert_eq!(fetched.as_slice(), payload);

        store.delete("test/entry").unwrap();
        assert!(store.get("test/entry").unwrap().is_none());
    }
}
