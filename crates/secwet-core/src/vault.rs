//! Public Vault API Engine.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §6, §7 (F1-F6, F8).
//!
//! Invariants:
//! - All cryptographic keys are zeroized upon `lock()`.
//! - KeyStore writes occur before database creation.
//! - Names, values, and notes exist only inside encrypted blobs.
//! - Secret values are never exposed in lists, logs, or error messages.
//! - Files <= 50 MiB encrypted with XChaCha20Poly1305 and verified with SHA-256.
//! - Rich-text notes encrypted with XChaCha20Poly1305 and previews use stripped snippets.
//! - Phase 2 non-destructive storage migration executes authenticated reverse-order re-sealing.

use crate::crypto::{self, derive_keys, encode_record_blob, open_record, seal_record, OsRng};
use crate::keys::KeyStore;
use crate::model::{ChecklistState, DeviceId, Overview, RecentSecret, SecretDraft};
use crate::records::{
    self, cascade_delete_environment, cascade_delete_item, cascade_delete_label,
    cascade_delete_project, count_active_items_for_label, count_active_records_by_parent_and_type,
    count_item_content_recursive, delete_environment_records, get_label, get_meta, get_record,
    insert_label, insert_record, next_label_position, next_lamport, open_and_migrate,
    open_connection, query_active_labels, query_content_records, query_environments_by_item,
    query_items_by_label, query_records_by_parent, set_meta, soft_delete_record, update_label_name,
    update_record_blob, LabelRow, RecordRow,
};
use crate::{Error, Result};
use rand_core::Rng;
use rusqlite::{params, Connection};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
pub use secwet_proto::Settings;
use secwet_proto::{
    AssetMetaBody, AssetMetaView, AssetPayload, DashboardConfig, EnvironmentBody, EnvironmentView,
    FileMetaView, ItemBody, ItemView, LabelBody, LabelView, NoteBody, NoteMetaView, NoteView,
    ProjectBody, ProjectView, RecordAad, RecordType, SecretBody, SecretMeta, VaultStatus,
};
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;
use uuid::Uuid;
use zeroize::Zeroize;

static ACTIVE_VAULTS: LazyLock<Mutex<HashSet<Uuid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn same_name_case_insensitive(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

fn seal_device_name(k_rec: &[u8; 32], device_id: &str, device_name: &str) -> Result<Vec<u8>> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(k_rec.into());
    let ciphertext = cipher
        .encrypt(
            &XNonce::from(nonce),
            Payload {
                msg: device_name.as_bytes(),
                aad: device_id.as_bytes(),
            },
        )
        .map_err(|_| Error::Crypto)?;
    Ok(encode_record_blob(&nonce, &ciphertext))
}

fn unseal_device_name(k_rec: &[u8; 32], device_id: &str, blob: &[u8]) -> Result<String> {
    use chacha20poly1305::{
        aead::{Aead, KeyInit, Payload},
        XChaCha20Poly1305, XNonce,
    };
    let (nonce, ciphertext) = crypto::decode_record_blob(blob).map_err(|_| Error::Crypto)?;
    let cipher = XChaCha20Poly1305::new(k_rec.into());
    let plaintext = cipher
        .decrypt(
            &XNonce::from(nonce),
            Payload {
                msg: ciphertext,
                aad: device_id.as_bytes(),
            },
        )
        .map_err(|_| Error::Crypto)?;
    String::from_utf8(plaintext).map_err(|_| Error::Crypto)
}

/// Resolves an existing vault database file within `data_dir`.
/// Checks `<data_dir>/vaults/<vault_id>/vault.sqlite3` and `<data_dir>/vault.sqlite3`.
fn find_vault_db(data_dir: &Path) -> Option<(PathBuf, Uuid)> {
    let direct_db = data_dir.join("vault.sqlite3");
    if direct_db.is_file() {
        if let Ok(conn) = open_connection(&direct_db) {
            if let Ok(Some(vid_str)) = get_meta(&conn, "vault_id") {
                if let Ok(vid) = Uuid::parse_str(&vid_str) {
                    return Some((direct_db, vid));
                }
            }
        }
    }

    let vaults_dir = data_dir.join("vaults");
    if vaults_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&vaults_dir) {
            for entry in entries.flatten() {
                let db_path = entry.path().join("vault.sqlite3");
                if db_path.is_file() {
                    if let Ok(conn) = open_connection(&db_path) {
                        if let Ok(Some(vid_str)) = get_meta(&conn, "vault_id") {
                            if let Ok(vid) = Uuid::parse_str(&vid_str) {
                                return Some((db_path, vid));
                            }
                        }
                    }
                }
            }
        }
    }

    None
}

/// Fallback struct for legacy v1 secret bodies where environment_id was non-optional.
#[derive(serde::Deserialize)]
struct LegacyV1SecretBody {
    pub project_id: Uuid,
    pub environment_id: Uuid,
    pub name: String,
    pub kind: secwet_proto::SecretKind,
    pub value: String,
    pub note: Option<String>,
}

/// Executes Phase 2 Non-Destructive Data Migration inside an atomic SQLite transaction.
///
/// Invariant: Authenticated re-sealing in reverse order:
/// 1. Secrets (record_type = 3 -> 4)
/// 2. Environments (record_type = 2 -> 3)
/// 3. Projects (record_type = 1 -> 2, reparented under default "Projects" label)
///
/// All plaintext buffers are explicitly zeroized before dropping.
pub(crate) fn migrate_phase2_flexible_org(
    conn: &mut Connection,
    vault_id: &Uuid,
    epoch: u32,
    k_rec: &[u8; 32],
    _device_id: &str,
) -> Result<()> {
    let tx = conn.transaction().map_err(|_| Error::Storage)?;

    // 1. Ensure default "Projects" label exists in labels table
    let mut projects_label_id: Option<Uuid> = None;
    let label_rows = query_active_labels(&tx)?;
    for l_row in label_rows {
        let aad = RecordAad::new(
            vault_id.as_bytes(),
            l_row.id.as_bytes(),
            RecordType::Label,
            epoch,
        );
        if let Ok(bytes) = open_record(k_rec, &aad, &l_row.name_blob) {
            if let Ok(body) = postcard::from_bytes::<LabelBody>(&bytes) {
                if body.name.trim().eq_ignore_ascii_case("projects") {
                    projects_label_id = Some(l_row.id);
                    break;
                }
            }
        }
    }

    let target_label_id = match projects_label_id {
        Some(id) => id,
        None => {
            let new_label_id = Uuid::now_v7();
            let label_body = LabelBody::new("Projects", 0, Some("folder".to_string()));
            let body_bytes = postcard::to_stdvec(&label_body).map_err(|_| Error::Storage)?;
            let aad = RecordAad::new(
                vault_id.as_bytes(),
                new_label_id.as_bytes(),
                RecordType::Label,
                epoch,
            );
            let name_blob = seal_record(k_rec, &aad, &body_bytes)?;
            let now_ms = current_time_ms();
            let label_row = LabelRow::new_active(new_label_id, name_blob, 0, now_ms);
            insert_label(&tx, &label_row)?;
            new_label_id
        }
    };

    // 2. Step 1: Re-seal Legacy Secrets (record_type = 3 -> 4)
    {
        let mut stmt = tx
            .prepare("SELECT id, parent_id, key_epoch, blob FROM records WHERE record_type = 3 AND blob IS NOT NULL")
            .map_err(|_| Error::Storage)?;
        let rows = stmt
            .query_map([], |row| {
                let id_bytes: Vec<u8> = row.get(0)?;
                let id = Uuid::from_slice(&id_bytes).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;
                let key_epoch: u32 = row.get(2)?;
                let blob: Vec<u8> = row.get(3)?;
                Ok((id, key_epoch, blob))
            })
            .map_err(|_| Error::Storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Storage)?;

        for (id, row_epoch, blob) in rows {
            let old_aad =
                RecordAad::from_raw_type(vault_id.as_bytes(), id.as_bytes(), 3, row_epoch);
            let mut plaintext = open_record(k_rec, &old_aad, &blob)?;

            let secret_body = match postcard::from_bytes::<SecretBody>(&plaintext) {
                Ok(b) => b,
                Err(_) => {
                    let leg: LegacyV1SecretBody =
                        postcard::from_bytes(&plaintext).map_err(|_| Error::Storage)?;
                    SecretBody::new(
                        leg.project_id,
                        Some(leg.environment_id),
                        leg.name,
                        leg.kind,
                        leg.value,
                        leg.note,
                    )
                }
            };
            plaintext.zeroize();

            let mut body_bytes = postcard::to_stdvec(&secret_body).map_err(|_| Error::Storage)?;
            let new_aad = RecordAad::new(
                vault_id.as_bytes(),
                id.as_bytes(),
                RecordType::Secret,
                row_epoch,
            );
            let new_blob = seal_record(k_rec, &new_aad, &body_bytes)?;
            body_bytes.zeroize();

            tx.execute(
                "UPDATE records SET record_type = 4, blob = ?1 WHERE id = ?2",
                params![new_blob, id.as_bytes().as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        }

        // Soft-deleted secrets
        tx.execute(
            "UPDATE records SET record_type = 4 WHERE record_type = 3 AND blob IS NULL",
            [],
        )
        .map_err(|_| Error::Storage)?;
    }

    // 3. Step 2: Re-seal Legacy Environments (record_type = 2 -> 3)
    {
        let mut stmt = tx
            .prepare("SELECT id, parent_id, key_epoch, blob FROM records WHERE record_type = 2 AND blob IS NOT NULL")
            .map_err(|_| Error::Storage)?;
        let rows = stmt
            .query_map([], |row| {
                let id_bytes: Vec<u8> = row.get(0)?;
                let id = Uuid::from_slice(&id_bytes).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;
                let key_epoch: u32 = row.get(2)?;
                let blob: Vec<u8> = row.get(3)?;
                Ok((id, key_epoch, blob))
            })
            .map_err(|_| Error::Storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Storage)?;

        for (id, row_epoch, blob) in rows {
            let old_aad =
                RecordAad::from_raw_type(vault_id.as_bytes(), id.as_bytes(), 2, row_epoch);
            let plaintext = open_record(k_rec, &old_aad, &blob)?;
            let env_body: EnvironmentBody =
                postcard::from_bytes(&plaintext).map_err(|_| Error::Storage)?;

            let body_bytes = postcard::to_stdvec(&env_body).map_err(|_| Error::Storage)?;
            let new_aad = RecordAad::new(
                vault_id.as_bytes(),
                id.as_bytes(),
                RecordType::Environment,
                row_epoch,
            );
            let new_blob = seal_record(k_rec, &new_aad, &body_bytes)?;

            tx.execute(
                "UPDATE records SET record_type = 3, blob = ?1 WHERE id = ?2",
                params![new_blob, id.as_bytes().as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        }

        // Soft-deleted environments
        tx.execute(
            "UPDATE records SET record_type = 3 WHERE record_type = 2 AND blob IS NULL",
            [],
        )
        .map_err(|_| Error::Storage)?;
    }

    // 4. Step 3: Re-seal Legacy Projects (record_type = 1 -> 2, reparented to target_label_id)
    {
        let mut stmt = tx
            .prepare("SELECT id, parent_id, key_epoch, blob FROM records WHERE record_type = 1 AND blob IS NOT NULL ORDER BY updated_at ASC")
            .map_err(|_| Error::Storage)?;
        let rows = stmt
            .query_map([], |row| {
                let id_bytes: Vec<u8> = row.get(0)?;
                let id = Uuid::from_slice(&id_bytes).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;
                let key_epoch: u32 = row.get(2)?;
                let blob: Vec<u8> = row.get(3)?;
                Ok((id, key_epoch, blob))
            })
            .map_err(|_| Error::Storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Storage)?;

        for (idx, (id, row_epoch, blob)) in rows.into_iter().enumerate() {
            let old_aad =
                RecordAad::from_raw_type(vault_id.as_bytes(), id.as_bytes(), 1, row_epoch);
            let plaintext = open_record(k_rec, &old_aad, &blob)?;
            let p_body: ProjectBody =
                postcard::from_bytes(&plaintext).map_err(|_| Error::Storage)?;

            let item_body = ItemBody::new(target_label_id, &p_body.name, None, idx as u32);
            let body_bytes = postcard::to_stdvec(&item_body).map_err(|_| Error::Storage)?;
            let new_aad = RecordAad::new(
                vault_id.as_bytes(),
                id.as_bytes(),
                RecordType::Item,
                row_epoch,
            );
            let new_blob = seal_record(k_rec, &new_aad, &body_bytes)?;

            tx.execute(
                "UPDATE records SET record_type = 2, parent_id = ?1, blob = ?2 WHERE id = ?3",
                params![
                    target_label_id.as_bytes().as_slice(),
                    new_blob,
                    id.as_bytes().as_slice()
                ],
            )
            .map_err(|_| Error::Storage)?;
        }

        // Soft-deleted projects
        tx.execute(
            "UPDATE records SET record_type = 2, parent_id = ?1 WHERE record_type = 1 AND blob IS NULL",
            params![target_label_id.as_bytes().as_slice()],
        )
        .map_err(|_| Error::Storage)?;
    }

    // 5. Mark Phase 2 migration as complete
    set_meta(&tx, "flexible_org_migrated", "1")?;

    tx.commit().map_err(|_| Error::Storage)?;
    Ok(())
}

/// The unified entry point for all Secwet vault operations.
pub struct Vault {
    db: Connection,
    vault_id: Uuid,
    device_id: String,
    key_epoch: u32,
    k_rec: SecretBox<[u8; 32]>,
    k_evt: SecretBox<[u8; 32]>,
    #[cfg(any(test, feature = "test-util"))]
    test_k_rec_witness: std::sync::Arc<std::sync::Mutex<[u8; 32]>>,
    #[cfg(any(test, feature = "test-util"))]
    test_k_evt_witness: std::sync::Arc<std::sync::Mutex<[u8; 32]>>,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("vault_id", &self.vault_id)
            .field("device_id", &self.device_id)
            .field("key_epoch", &self.key_epoch)
            .field("k_rec", &"[REDACTED]")
            .field("k_evt", &"[REDACTED]")
            .finish()
    }
}

impl Vault {
    // ========================================================================
    // Lifecycle (F1, F2)
    // ========================================================================

    /// Inspects the data directory for an existing vault database and status.
    pub fn status(data_dir: &Path) -> Result<VaultStatus> {
        if !data_dir.exists() {
            return Ok(VaultStatus::Uninitialized);
        }

        if let Some((_, vault_id)) = find_vault_db(data_dir) {
            let active = {
                let guard = ACTIVE_VAULTS.lock().unwrap();
                guard.contains(&vault_id)
            };
            if active {
                Ok(VaultStatus::Unlocked { vault_id })
            } else {
                Ok(VaultStatus::Locked { vault_id })
            }
        } else {
            // Check if database files exist but are unreadable/corrupted
            if data_dir.join("vault.sqlite3").is_file() {
                return Err(Error::Storage);
            }
            if let Ok(entries) = std::fs::read_dir(data_dir.join("vaults")) {
                for entry in entries.flatten() {
                    if entry.path().join("vault.sqlite3").is_file() {
                        return Err(Error::Storage);
                    }
                }
            }
            Ok(VaultStatus::Uninitialized)
        }
    }

    /// Creates a new vault.
    ///
    /// Invariants:
    /// - KeyStore writes for device keys and epoch 1 vault key occur BEFORE database creation.
    /// - Database is created and schema migrations 0001 and 0002 are executed.
    /// - Default "Projects" label seeded in `labels` table.
    /// - `meta.flexible_org_migrated = '1'`.
    pub fn create(data_dir: &Path, device_name: &str, keystore: &dyn KeyStore) -> Result<Vault> {
        if find_vault_db(data_dir).is_some() {
            return Err(Error::AlreadyInitialized);
        }

        let trimmed_name = device_name.trim();
        let dev_name = if trimmed_name.is_empty() {
            "default-device"
        } else {
            trimmed_name
        };

        let vault_id = Uuid::new_v4();

        // 1. Generate keys
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let sign_pub = signing_key.verifying_key().to_bytes();
        let sign_priv = signing_key.to_bytes();
        let device_id = crypto::compute_device_id(&sign_pub);

        let enc_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let enc_pub = x25519_dalek::PublicKey::from(&enc_secret).to_bytes();
        let enc_priv = enc_secret.to_bytes();

        let mut k_v = [0u8; 32];
        OsRng.fill_bytes(&mut k_v);

        // 2. Persist keys to KeyStore BEFORE any filesystem writes
        keystore.set(&format!("secwet/{vault_id}/device-sign"), &sign_priv)?;
        keystore.set(&format!("secwet/{vault_id}/device-enc"), &enc_priv)?;
        keystore.set(&format!("secwet/{vault_id}/vault-key/1"), &k_v)?;

        // 3. Derive runtime symmetric keys
        let (k_rec_bytes, k_evt_bytes) = derive_keys(&k_v, &vault_id);
        k_v.zeroize();

        // 4. Create database on disk
        let db_dir = data_dir.join("vaults").join(vault_id.to_string());
        std::fs::create_dir_all(&db_dir).map_err(|_| Error::Storage)?;
        let db_path = db_dir.join("vault.sqlite3");
        let conn = open_and_migrate(&db_path)?;

        let now_ms = current_time_ms();
        set_meta(&conn, "schema_version", "2")?;
        set_meta(&conn, "vault_id", &vault_id.to_string())?;
        set_meta(&conn, "created_at", &now_ms.to_string())?;
        set_meta(&conn, "current_key_epoch", "1")?;
        set_meta(&conn, "device_id", &device_id)?;
        set_meta(&conn, "plan", "free")?;
        set_meta(&conn, "relay_url", "")?;
        set_meta(&conn, "flexible_org_migrated", "1")?;

        // 5. Seed default "Projects" label in labels table
        let default_label_id = Uuid::now_v7();
        let label_body = LabelBody::new("Projects", 0, Some("folder".to_string()));
        let label_bytes = postcard::to_stdvec(&label_body).map_err(|_| Error::Storage)?;
        let label_aad = RecordAad::new(
            vault_id.as_bytes(),
            default_label_id.as_bytes(),
            RecordType::Label,
            1,
        );
        let label_blob = seal_record(&k_rec_bytes, &label_aad, &label_bytes)?;
        let label_row = LabelRow::new_active(default_label_id, label_blob, 0, now_ms);
        insert_label(&conn, &label_row)?;

        // 6. Seal device name and insert into devices table
        let name_blob = seal_device_name(&k_rec_bytes, &device_id, dev_name)?;
        conn.execute(
            "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5)",
            params![
                device_id,
                name_blob,
                sign_pub.as_slice(),
                enc_pub.as_slice(),
                now_ms,
            ],
        )
        .map_err(|_| Error::Storage)?;

        // 7. Register active status
        ACTIVE_VAULTS.lock().unwrap().insert(vault_id);

        let k_rec = SecretBox::new(Box::new(*k_rec_bytes));
        let k_evt = SecretBox::new(Box::new(*k_evt_bytes));

        #[cfg(any(test, feature = "test-util"))]
        let test_k_rec_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_rec_bytes));
        #[cfg(any(test, feature = "test-util"))]
        let test_k_evt_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_evt_bytes));

        Ok(Vault {
            db: conn,
            vault_id,
            device_id,
            key_epoch: 1,
            k_rec,
            k_evt,
            #[cfg(any(test, feature = "test-util"))]
            test_k_rec_witness,
            #[cfg(any(test, feature = "test-util"))]
            test_k_evt_witness,
        })
    }

    /// Unlocks an existing vault from storage using keys from `keystore`.
    ///
    /// Runs Phase 1 schema migration (`run_migrations`) and executes Phase 2
    /// non-destructive authenticated data migration if not yet migrated.
    pub fn unlock(data_dir: &Path, keystore: &dyn KeyStore) -> Result<Vault> {
        let (db_path, vault_id) = find_vault_db(data_dir).ok_or(Error::NoVault)?;
        let mut conn = open_connection(&db_path)?;

        // Run DDL migrations up to version 2
        records::run_migrations(&mut conn)?;

        let epoch_str = get_meta(&conn, "current_key_epoch")?.unwrap_or_else(|| "1".to_string());
        let epoch: u32 = epoch_str.parse().unwrap_or(1);
        let device_id = get_meta(&conn, "device_id")?.ok_or(Error::Storage)?;

        let key_opt = keystore.get(&format!("secwet/{vault_id}/vault-key/{epoch}"))?;
        let key_vec = key_opt.ok_or(Error::KeyStore)?;
        if key_vec.len() != 32 {
            return Err(Error::KeyStore);
        }
        let mut k_v = [0u8; 32];
        k_v.copy_from_slice(key_vec.as_slice());

        let (k_rec_bytes, k_evt_bytes) = derive_keys(&k_v, &vault_id);
        k_v.zeroize();

        // Check Phase 2 non-destructive storage migration
        let flexible_migrated = get_meta(&conn, "flexible_org_migrated")?
            .as_deref()
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

        if !flexible_migrated {
            migrate_phase2_flexible_org(&mut conn, &vault_id, epoch, &k_rec_bytes, &device_id)?;
        }

        ACTIVE_VAULTS.lock().unwrap().insert(vault_id);

        let k_rec = SecretBox::new(Box::new(*k_rec_bytes));
        let k_evt = SecretBox::new(Box::new(*k_evt_bytes));

        #[cfg(any(test, feature = "test-util"))]
        let test_k_rec_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_rec_bytes));
        #[cfg(any(test, feature = "test-util"))]
        let test_k_evt_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_evt_bytes));

        Ok(Vault {
            db: conn,
            vault_id,
            device_id,
            key_epoch: epoch,
            k_rec,
            k_evt,
            #[cfg(any(test, feature = "test-util"))]
            test_k_rec_witness,
            #[cfg(any(test, feature = "test-util"))]
            test_k_evt_witness,
        })
    }

    /// Locks the vault, consuming `self` and zeroizing all in-memory keys.
    pub fn lock(mut self) {
        self.zeroize_keys_internal();
        ACTIVE_VAULTS.lock().unwrap().remove(&self.vault_id);
    }

    fn zeroize_keys_internal(&mut self) {
        self.k_rec.expose_secret_mut().zeroize();
        self.k_evt.expose_secret_mut().zeroize();
        #[cfg(any(test, feature = "test-util"))]
        {
            if let Ok(mut w) = self.test_k_rec_witness.lock() {
                w.zeroize();
            }
            if let Ok(mut w) = self.test_k_evt_witness.lock() {
                w.zeroize();
            }
        }
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId(self.device_id.clone())
    }

    pub fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    pub fn current_status(&self) -> VaultStatus {
        VaultStatus::Unlocked {
            vault_id: self.vault_id,
        }
    }

    pub fn is_flexible_migrated(&self) -> bool {
        get_meta(&self.db, "flexible_org_migrated")
            .unwrap_or(None)
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false)
    }

    /// Validates that an item and optional child environment exist and are active.
    fn validate_container(&self, item_id: Uuid, environment_id: Option<Uuid>) -> Result<()> {
        let item_row = get_record(&self.db, item_id)?.ok_or(Error::NotFound)?;
        if item_row.deleted
            || (item_row.record_type != RecordType::Item
                && item_row.record_type != RecordType::Project)
        {
            return Err(Error::NotFound);
        }
        if let Some(env_id) = environment_id {
            let env_row = get_record(&self.db, env_id)?.ok_or(Error::NotFound)?;
            if env_row.deleted
                || (env_row.record_type != RecordType::Environment
                    && env_row.record_type != RecordType::Item/* legacy 2 */)
                || env_row.parent_id != Some(item_id)
            {
                return Err(Error::NotFound);
            }
        }
        Ok(())
    }

    // ========================================================================
    // Labels CRUD & Reorder (F3)
    // ========================================================================

    /// Lists all active organizational labels ordered by position ASC.
    pub fn list_labels(&self) -> Result<Vec<LabelView>> {
        let label_rows = query_active_labels(&self.db)?;
        let mut views = Vec::with_capacity(label_rows.len());

        for row in label_rows {
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Label,
                self.key_epoch,
            );
            let bytes = open_record(self.k_rec.expose_secret(), &aad, &row.name_blob)?;
            let body: LabelBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

            let items_count = count_active_items_for_label(&self.db, row.id)?;

            views.push(LabelView::new(
                row.id,
                body.name,
                row.position,
                body.icon,
                items_count,
            ));
        }

        Ok(views)
    }

    /// Creates a new organizational label.
    pub fn create_label(&mut self, name: &str, icon: Option<String>) -> Result<LabelView> {
        let clean_name = secwet_proto::validate_label_name(name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter a label name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "name",
                message: "Keep the name under 64 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid label name.".to_string(),
            },
        })?;

        // Case-insensitive uniqueness check
        let existing = self.list_labels()?;
        if existing
            .iter()
            .any(|l| same_name_case_insensitive(&l.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let position = next_label_position(&self.db)?;
        let label_id = Uuid::now_v7();
        let now_ms = current_time_ms();

        let body = LabelBody::new(&clean_name, position, icon.clone());
        let bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            label_id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &bytes)?;

        let row = LabelRow::new_active(label_id, blob, position, now_ms);
        insert_label(&self.db, &row)?;

        Ok(LabelView::new(label_id, clean_name, position, icon, 0))
    }

    /// Renames an active label while preserving its icon and position.
    pub fn rename_label(&mut self, id: Uuid, name: &str) -> Result<()> {
        let label_row = get_label(&self.db, id)?.ok_or(Error::NotFound)?;
        if label_row.deleted {
            return Err(Error::NotFound);
        }

        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let bytes = open_record(self.k_rec.expose_secret(), &aad, &label_row.name_blob)?;
        let body: LabelBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        self.update_label(id, name, body.icon)
    }

    /// Updates both the name and icon of an active label.
    pub fn update_label(&mut self, id: Uuid, name: &str, icon: Option<String>) -> Result<()> {
        let clean_name = secwet_proto::validate_label_name(name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter a label name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "name",
                message: "Keep the name under 64 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid label name.".to_string(),
            },
        })?;

        let label_row = get_label(&self.db, id)?.ok_or(Error::NotFound)?;
        if label_row.deleted {
            return Err(Error::NotFound);
        }

        // Check case-insensitive uniqueness against other labels
        let existing = self.list_labels()?;
        if existing
            .iter()
            .any(|l| l.id != id && same_name_case_insensitive(&l.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let body = LabelBody::new(&clean_name, label_row.position, icon);
        let bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &bytes)?;

        update_label_name(&self.db, id, &blob, current_time_ms())?;
        Ok(())
    }

    /// Reorders active labels according to the provided ordered slice of UUIDs.
    pub fn reorder_labels(&mut self, ids: &[Uuid]) -> Result<()> {
        for id in ids {
            let label = get_label(&self.db, *id)?.ok_or(Error::NotFound)?;
            if label.deleted {
                return Err(Error::NotFound);
            }
        }
        records::reorder_labels(&mut self.db, ids, current_time_ms())
    }

    /// Cascades soft deletion of a label and all its child items, environments,
    /// secrets, files, and notes in a single atomic SQLite transaction.
    pub fn delete_label(&mut self, id: Uuid) -> Result<()> {
        cascade_delete_label(&mut self.db, id, &self.device_id, current_time_ms())?;
        Ok(())
    }

    // ========================================================================
    // Items CRUD (F3)
    // ========================================================================

    /// Lists all active items under a label.
    pub fn list_items(&self, label_id: Uuid) -> Result<Vec<ItemView>> {
        let label = get_label(&self.db, label_id)?.ok_or(Error::NotFound)?;
        if label.deleted {
            return Err(Error::NotFound);
        }

        let item_rows = query_items_by_label(&self.db, label_id)?;
        let mut views = Vec::with_capacity(item_rows.len());

        for row in item_rows {
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Item,
                row.key_epoch,
            );
            let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
            let body: ItemBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

            let environments_count =
                count_active_records_by_parent_and_type(&self.db, row.id, RecordType::Environment)?;
            let secrets_count = count_item_content_recursive(&self.db, row.id, RecordType::Secret)?;
            let files_count = count_item_content_recursive(&self.db, row.id, RecordType::File)?;
            let notes_count = count_item_content_recursive(&self.db, row.id, RecordType::Note)?;

            views.push(ItemView::new(
                row.id,
                label_id,
                body.name,
                body.description,
                body.position,
                environments_count,
                secrets_count,
                files_count,
                notes_count,
            ));
        }

        views.sort_by_key(|i| (i.position, i.id));
        Ok(views)
    }

    /// Creates a new item under a specified label.
    ///
    /// Invariant: Creates NO default environments. Items function 100% without environments.
    pub fn create_item(
        &mut self,
        label_id: Uuid,
        name: &str,
        description: Option<String>,
    ) -> Result<ItemView> {
        let label = get_label(&self.db, label_id)?.ok_or(Error::NotFound)?;
        if label.deleted {
            return Err(Error::NotFound);
        }

        let clean_name = secwet_proto::validate_item_name(name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter an item name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "name",
                message: "Keep the name under 64 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid item name.".to_string(),
            },
        })?;

        secwet_proto::validate_item_description(description.as_deref()).map_err(|_| {
            Error::Invalid {
                field: "description",
                message: "Keep description under 500 characters.".to_string(),
            }
        })?;

        let existing = self.list_items(label_id)?;
        if existing
            .iter()
            .any(|i| same_name_case_insensitive(&i.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let position = existing
            .iter()
            .map(|i| i.position)
            .max()
            .map(|p| p + 1)
            .unwrap_or(0);

        let item_id = Uuid::now_v7();
        let body = ItemBody::new(label_id, &clean_name, description.clone(), position);
        let bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            item_id.as_bytes(),
            RecordType::Item,
            self.key_epoch,
        );
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &bytes)?;

        let lamport = next_lamport(&self.db)?;
        let row = RecordRow::new_active(
            item_id,
            RecordType::Item,
            Some(label_id),
            self.key_epoch,
            blob,
            lamport,
            &self.device_id,
            current_time_ms(),
        );
        insert_record(&self.db, &row)?;

        Ok(ItemView::new(
            item_id,
            label_id,
            clean_name,
            description,
            position,
            0,
            0,
            0,
            0,
        ))
    }

    /// Renames an existing item and/or updates its description.
    pub fn rename_item(&mut self, id: Uuid, name: &str, description: Option<String>) -> Result<()> {
        let clean_name = secwet_proto::validate_item_name(name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter an item name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "name",
                message: "Keep the name under 64 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid item name.".to_string(),
            },
        })?;

        secwet_proto::validate_item_description(description.as_deref()).map_err(|_| {
            Error::Invalid {
                field: "description",
                message: "Keep description under 500 characters.".to_string(),
            }
        })?;

        let row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if row.deleted
            || (row.record_type != RecordType::Item && row.record_type != RecordType::Project)
        {
            return Err(Error::NotFound);
        }

        let label_id = row.parent_id.ok_or(Error::NotFound)?;

        let siblings = self.list_items(label_id)?;
        if siblings
            .iter()
            .any(|i| i.id != id && same_name_case_insensitive(&i.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let blob = row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Item,
            row.key_epoch,
        );
        let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
        let cur_body: ItemBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        let new_body = ItemBody::new(label_id, &clean_name, description, cur_body.position);
        let new_bytes = postcard::to_stdvec(&new_body).map_err(|_| Error::Storage)?;
        let new_blob = seal_record(self.k_rec.expose_secret(), &aad, &new_bytes)?;

        update_record_blob(&self.db, id, &new_blob, &self.device_id, current_time_ms())?;
        Ok(())
    }

    /// Cascades deletion of an item and all its environments, secrets, files, and notes.
    pub fn delete_item(&mut self, id: Uuid) -> Result<()> {
        cascade_delete_item(&mut self.db, id, &self.device_id, current_time_ms())?;
        Ok(())
    }

    // ========================================================================
    // Optional Environments CRUD (F4)
    // ========================================================================

    /// Lists all active environments belonging to an item, sorted by position ASC.
    pub fn list_environments(&self, item_id: Uuid) -> Result<Vec<EnvironmentView>> {
        let item_row = get_record(&self.db, item_id)?.ok_or(Error::NotFound)?;
        if item_row.deleted {
            return Err(Error::NotFound);
        }

        let env_rows = query_environments_by_item(&self.db, item_id)?;
        let mut views = Vec::with_capacity(env_rows.len());

        for row in env_rows {
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Environment,
                row.key_epoch,
            );
            let bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.vault_id.as_bytes(),
                        row.id.as_bytes(),
                        2,
                        row.key_epoch,
                    );
                    open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
                }
            };
            let body: EnvironmentBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

            let secret_count =
                count_active_records_by_parent_and_type(&self.db, row.id, RecordType::Secret)?;

            views.push(EnvironmentView {
                id: row.id,
                project_id: item_id,
                name: body.name,
                position: body.position,
                secret_count,
            });
        }

        views.sort_by_key(|e| e.position);
        Ok(views)
    }

    /// Adds a new optional environment to an item.
    pub fn add_environment(&mut self, item_id: Uuid, name: &str) -> Result<EnvironmentView> {
        let clean_name =
            secwet_proto::validate_environment_name(name).map_err(|err| match err {
                secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                    field: "name",
                    message: "Enter an environment name.".to_string(),
                },
                secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                    field: "name",
                    message: "Keep the name under 64 characters.".to_string(),
                },
                _ => Error::Invalid {
                    field: "name",
                    message: "Enter a valid environment name.".to_string(),
                },
            })?;

        let item_row = get_record(&self.db, item_id)?.ok_or(Error::NotFound)?;
        if item_row.deleted {
            return Err(Error::NotFound);
        }

        let existing = self.list_environments(item_id)?;
        if existing
            .iter()
            .any(|e| same_name_case_insensitive(&e.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let position = existing
            .iter()
            .map(|e| e.position)
            .max()
            .map(|p| p + 1)
            .unwrap_or(0);

        let env_id = Uuid::now_v7();
        let body = EnvironmentBody::new(item_id, &clean_name, position);
        let bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            env_id.as_bytes(),
            RecordType::Environment,
            self.key_epoch,
        );
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &bytes)?;

        let lamport = next_lamport(&self.db)?;
        let row = RecordRow::new_active(
            env_id,
            RecordType::Environment,
            Some(item_id),
            self.key_epoch,
            blob,
            lamport,
            &self.device_id,
            current_time_ms(),
        );
        insert_record(&self.db, &row)?;

        Ok(EnvironmentView {
            id: env_id,
            project_id: item_id,
            name: clean_name,
            position,
            secret_count: 0,
        })
    }

    /// Renames an active environment within an item.
    pub fn rename_environment(&mut self, id: Uuid, name: &str) -> Result<()> {
        let clean_name =
            secwet_proto::validate_environment_name(name).map_err(|err| match err {
                secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                    field: "name",
                    message: "Enter an environment name.".to_string(),
                },
                secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                    field: "name",
                    message: "Keep the name under 64 characters.".to_string(),
                },
                _ => Error::Invalid {
                    field: "name",
                    message: "Enter a valid environment name.".to_string(),
                },
            })?;

        let row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if row.deleted
            || (row.record_type != RecordType::Environment && row.record_type != RecordType::Item/* legacy 2 */)
        {
            return Err(Error::NotFound);
        }

        let item_id = row.parent_id.ok_or(Error::NotFound)?;

        let siblings = self.list_environments(item_id)?;
        if siblings
            .iter()
            .any(|e| e.id != id && same_name_case_insensitive(&e.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let blob = row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Environment,
            row.key_epoch,
        );
        let bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
            Ok(b) => b,
            Err(_) => {
                let leg_aad = RecordAad::from_raw_type(
                    self.vault_id.as_bytes(),
                    id.as_bytes(),
                    2,
                    row.key_epoch,
                );
                open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
            }
        };
        let cur_body: EnvironmentBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        let new_body = EnvironmentBody::new(item_id, &clean_name, cur_body.position);
        let new_bytes = postcard::to_stdvec(&new_body).map_err(|_| Error::Storage)?;
        let new_aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Environment,
            row.key_epoch,
        );
        let new_blob = seal_record(self.k_rec.expose_secret(), &new_aad, &new_bytes)?;

        update_record_blob(&self.db, id, &new_blob, &self.device_id, current_time_ms())?;
        Ok(())
    }

    /// Reorders active environments belonging to an item.
    pub fn reorder_environments(&mut self, item_id: Uuid, ids: &[Uuid]) -> Result<()> {
        let siblings = self.list_environments(item_id)?;
        let sibling_ids: HashSet<Uuid> = siblings.iter().map(|e| e.id).collect();

        for id in ids {
            if !sibling_ids.contains(id) {
                return Err(Error::NotFound);
            }
        }

        let now_ms = current_time_ms();
        let tx = self.db.transaction().map_err(|_| Error::Storage)?;

        for (pos, id) in ids.iter().enumerate() {
            let row = get_record(&tx, *id)?.ok_or(Error::NotFound)?;
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                id.as_bytes(),
                RecordType::Environment,
                row.key_epoch,
            );
            let bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.vault_id.as_bytes(),
                        id.as_bytes(),
                        2,
                        row.key_epoch,
                    );
                    open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
                }
            };
            let body: EnvironmentBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

            let new_body = EnvironmentBody::new(item_id, body.name, pos as u32);
            let new_bytes = postcard::to_stdvec(&new_body).map_err(|_| Error::Storage)?;
            let new_aad = RecordAad::new(
                self.vault_id.as_bytes(),
                id.as_bytes(),
                RecordType::Environment,
                row.key_epoch,
            );
            let new_blob = seal_record(self.k_rec.expose_secret(), &new_aad, &new_bytes)?;

            update_record_blob(&tx, *id, &new_blob, &self.device_id, now_ms)?;
        }

        tx.commit().map_err(|_| Error::Storage)?;
        Ok(())
    }

    /// Deletes an environment, enforcing last-environment protection if only 1 remains in a project.
    pub fn delete_environment(&mut self, id: Uuid) -> Result<()> {
        cascade_delete_environment(&mut self.db, id, &self.device_id, current_time_ms())?;
        Ok(())
    }

    /// Deletes an environment with explicit content handling.
    ///
    /// - If `preserve_content == true`: child records are reparented to `item_id`.
    /// - If `preserve_content == false`: child records are soft-deleted.
    pub fn delete_environment_with_options(
        &mut self,
        id: Uuid,
        preserve_content: bool,
    ) -> Result<()> {
        delete_environment_records(
            &mut self.db,
            id,
            preserve_content,
            &self.device_id,
            current_time_ms(),
        )?;
        Ok(())
    }

    // ========================================================================
    // Secrets CRUD & Copy (F5)
    // ========================================================================

    /// Lists secret metadata for an item or specific environment.
    ///
    /// Invariant: Strictly returns `SecretMeta` with masked `value_tail`.
    /// NEVER returns the full secret value.
    pub fn list_secrets(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<SecretMeta>> {
        let item_row = get_record(&self.db, item_id)?.ok_or(Error::NotFound)?;
        if item_row.deleted {
            return Err(Error::NotFound);
        }

        if let Some(env_id) = environment_id {
            let env_row = get_record(&self.db, env_id)?.ok_or(Error::NotFound)?;
            if env_row.deleted || env_row.parent_id != Some(item_id) {
                return Err(Error::NotFound);
            }
        }

        let secret_rows =
            query_content_records(&self.db, item_id, environment_id, RecordType::Secret)?;
        let mut metas = Vec::with_capacity(secret_rows.len());

        for s_row in secret_rows {
            let blob = s_row.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                s_row.id.as_bytes(),
                RecordType::Secret,
                s_row.key_epoch,
            );
            let s_bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.vault_id.as_bytes(),
                        s_row.id.as_bytes(),
                        3,
                        s_row.key_epoch,
                    );
                    open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
                }
            };
            let s_body = match postcard::from_bytes::<SecretBody>(&s_bytes) {
                Ok(b) => b,
                Err(_) => {
                    let leg: LegacyV1SecretBody =
                        postcard::from_bytes(&s_bytes).map_err(|_| Error::Storage)?;
                    SecretBody::new(
                        leg.project_id,
                        Some(leg.environment_id),
                        leg.name,
                        leg.kind,
                        leg.value,
                        leg.note,
                    )
                }
            };

            let value_tail = SecretMeta::compute_value_tail(&s_body.value);

            metas.push(SecretMeta {
                id: s_row.id,
                project_id: item_id,
                environment_id,
                name: s_body.name,
                kind: s_body.kind,
                note: s_body.note,
                updated_at: s_row.updated_at,
                value_tail,
            });
        }

        metas.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(metas)
    }

    /// Backwards-compatible secret listing by environment ID alone.
    pub fn list_environment_secrets(&self, environment: Uuid) -> Result<Vec<SecretMeta>> {
        let env_row = get_record(&self.db, environment)?.ok_or(Error::NotFound)?;
        if env_row.deleted {
            return Err(Error::NotFound);
        }
        let item_id = env_row.parent_id.ok_or(Error::NotFound)?;
        self.list_secrets(item_id, Some(environment))
    }

    /// Reveals the full secret value for a single secret.
    pub fn reveal_secret(&self, id: Uuid) -> Result<SecretString> {
        let s_row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if s_row.deleted
            || (s_row.record_type != RecordType::Secret
                && s_row.record_type != RecordType::Environment/* legacy 3 */)
        {
            return Err(Error::NotFound);
        }

        let blob = s_row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Secret,
            s_row.key_epoch,
        );
        let s_bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
            Ok(b) => b,
            Err(_) => {
                let leg_aad = RecordAad::from_raw_type(
                    self.vault_id.as_bytes(),
                    id.as_bytes(),
                    3,
                    s_row.key_epoch,
                );
                open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
            }
        };

        let s_body = match postcard::from_bytes::<SecretBody>(&s_bytes) {
            Ok(b) => b,
            Err(_) => {
                let leg: LegacyV1SecretBody =
                    postcard::from_bytes(&s_bytes).map_err(|_| Error::Storage)?;
                SecretBody::new(
                    leg.project_id,
                    Some(leg.environment_id),
                    leg.name,
                    leg.kind,
                    leg.value,
                    leg.note,
                )
            }
        };

        Ok(SecretString::from(s_body.value))
    }

    /// Creates a new secret at either the item level or within an environment.
    ///
    /// Invariants:
    /// - Name regex `^[A-Za-z_][A-Za-z0-9_.@-]*$`, length 1..=128 chars.
    /// - Case-sensitive uniqueness per container.
    /// - Value max 64 KiB (65,536 bytes).
    /// - Note max 500 chars.
    pub fn create_secret(&mut self, draft: SecretDraft) -> Result<SecretMeta> {
        let item_row = get_record(&self.db, draft.item_id)?.ok_or(Error::NotFound)?;
        if item_row.deleted {
            return Err(Error::NotFound);
        }

        if let Some(env_id) = draft.environment_id {
            let env_row = get_record(&self.db, env_id)?.ok_or(Error::NotFound)?;
            if env_row.deleted || env_row.parent_id != Some(draft.item_id) {
                return Err(Error::NotFound);
            }
        }

        secwet_proto::validate_secret_name(&draft.name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter a secret name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "name",
                message: "Keep the name under 128 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid secret name.".to_string(),
            },
        })?;

        let raw_val = draft.value.expose_secret();
        if raw_val.is_empty() {
            return Err(Error::Invalid {
                field: "value",
                message: "Enter the secret value.".to_string(),
            });
        }
        if raw_val.len() > 65_536 {
            return Err(Error::Invalid {
                field: "value",
                message: "Secret value cannot exceed 64 KiB.".to_string(),
            });
        }

        if let Some(n) = &draft.note {
            if n.chars().count() > 500 {
                return Err(Error::Invalid {
                    field: "note",
                    message: "Keep the note under 500 characters.".to_string(),
                });
            }
        }

        let target_parent = draft.environment_id.unwrap_or(draft.item_id);
        let siblings = query_content_records(
            &self.db,
            draft.item_id,
            draft.environment_id,
            RecordType::Secret,
        )?;
        for sib in siblings {
            let blob = sib.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                sib.id.as_bytes(),
                RecordType::Secret,
                sib.key_epoch,
            );
            let bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.vault_id.as_bytes(),
                        sib.id.as_bytes(),
                        3,
                        sib.key_epoch,
                    );
                    open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
                }
            };
            let body: SecretBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            if body.name == draft.name {
                return Err(Error::Duplicate { field: "name" });
            }
        }

        let secret_id = Uuid::now_v7();
        let value_tail = SecretMeta::compute_value_tail(raw_val);
        let s_body = SecretBody::new(
            draft.item_id,
            draft.environment_id,
            &draft.name,
            draft.kind,
            raw_val,
            draft.note.clone(),
        );
        let s_bytes = postcard::to_stdvec(&s_body).map_err(|_| Error::Storage)?;
        let s_aad = RecordAad::new(
            self.vault_id.as_bytes(),
            secret_id.as_bytes(),
            RecordType::Secret,
            self.key_epoch,
        );
        let s_blob = seal_record(self.k_rec.expose_secret(), &s_aad, &s_bytes)?;

        let now_ms = current_time_ms();
        let lamport = next_lamport(&self.db)?;
        let row = RecordRow::new_active(
            secret_id,
            RecordType::Secret,
            Some(target_parent),
            self.key_epoch,
            s_blob,
            lamport,
            &self.device_id,
            now_ms,
        );
        insert_record(&self.db, &row)?;

        Ok(SecretMeta {
            id: secret_id,
            project_id: draft.item_id,
            environment_id: draft.environment_id,
            name: draft.name,
            kind: draft.kind,
            note: draft.note,
            updated_at: now_ms,
            value_tail,
        })
    }

    /// Updates an existing secret. Supports moving across environments or between item-level and environment-level.
    pub fn update_secret(&mut self, id: Uuid, draft: SecretDraft) -> Result<SecretMeta> {
        let existing_row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if existing_row.deleted
            || (existing_row.record_type != RecordType::Secret
                && existing_row.record_type != RecordType::Environment/* legacy 3 */)
        {
            return Err(Error::NotFound);
        }

        let item_row = get_record(&self.db, draft.item_id)?.ok_or(Error::NotFound)?;
        if item_row.deleted {
            return Err(Error::NotFound);
        }

        if let Some(env_id) = draft.environment_id {
            let env_row = get_record(&self.db, env_id)?.ok_or(Error::NotFound)?;
            if env_row.deleted || env_row.parent_id != Some(draft.item_id) {
                return Err(Error::NotFound);
            }
        }

        secwet_proto::validate_secret_name(&draft.name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter a secret name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "name",
                message: "Keep the name under 128 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid secret name.".to_string(),
            },
        })?;

        let raw_val = draft.value.expose_secret();
        if raw_val.is_empty() {
            return Err(Error::Invalid {
                field: "value",
                message: "Enter the secret value.".to_string(),
            });
        }
        if raw_val.len() > 65_536 {
            return Err(Error::Invalid {
                field: "value",
                message: "Secret value cannot exceed 64 KiB.".to_string(),
            });
        }

        if let Some(n) = &draft.note {
            if n.chars().count() > 500 {
                return Err(Error::Invalid {
                    field: "note",
                    message: "Keep the note under 500 characters.".to_string(),
                });
            }
        }

        let target_parent = draft.environment_id.unwrap_or(draft.item_id);
        let siblings = query_content_records(
            &self.db,
            draft.item_id,
            draft.environment_id,
            RecordType::Secret,
        )?;
        for sib in siblings {
            if sib.id == id {
                continue;
            }
            let blob = sib.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                sib.id.as_bytes(),
                RecordType::Secret,
                sib.key_epoch,
            );
            let bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.vault_id.as_bytes(),
                        sib.id.as_bytes(),
                        3,
                        sib.key_epoch,
                    );
                    open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
                }
            };
            let body: SecretBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            if body.name == draft.name {
                return Err(Error::Duplicate { field: "name" });
            }
        }

        let value_tail = SecretMeta::compute_value_tail(raw_val);
        let s_body = SecretBody::new(
            draft.item_id,
            draft.environment_id,
            &draft.name,
            draft.kind,
            raw_val,
            draft.note.clone(),
        );
        let s_bytes = postcard::to_stdvec(&s_body).map_err(|_| Error::Storage)?;
        let s_aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Secret,
            existing_row.key_epoch,
        );
        let s_blob = seal_record(self.k_rec.expose_secret(), &s_aad, &s_bytes)?;

        let now_ms = current_time_ms();
        let lamport = next_lamport(&self.db)?;

        self.db
            .execute(
                "UPDATE records
                 SET parent_id = ?1, blob = ?2, lamport = ?3, origin_device = ?4, updated_at = ?5, deleted = 0
                 WHERE id = ?6",
                params![
                    target_parent.as_bytes().as_slice(),
                    s_blob,
                    lamport as i64,
                    &self.device_id,
                    now_ms,
                    id.as_bytes().as_slice(),
                ],
            )
            .map_err(|_| Error::Storage)?;

        Ok(SecretMeta {
            id,
            project_id: draft.item_id,
            environment_id: draft.environment_id,
            name: draft.name,
            kind: draft.kind,
            note: draft.note,
            updated_at: now_ms,
            value_tail,
        })
    }

    /// Soft-deletes a secret.
    pub fn delete_secret(&mut self, id: Uuid) -> Result<()> {
        let existing = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if existing.deleted
            || (existing.record_type != RecordType::Secret
                && existing.record_type != RecordType::Environment/* legacy 3 */)
        {
            return Err(Error::NotFound);
        }
        soft_delete_record(&self.db, id, &self.device_id, current_time_ms())?;
        Ok(())
    }

    /// Copies an existing secret to another container (item-level or another environment).
    pub fn copy_secret_to_environment(
        &mut self,
        id: Uuid,
        target_env: impl Into<Option<Uuid>>,
    ) -> Result<SecretMeta> {
        let s_row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if s_row.deleted
            || (s_row.record_type != RecordType::Secret
                && s_row.record_type != RecordType::Environment/* legacy 3 */)
        {
            return Err(Error::NotFound);
        }

        let blob = s_row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Secret,
            s_row.key_epoch,
        );
        let s_bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
            Ok(b) => b,
            Err(_) => {
                let leg_aad = RecordAad::from_raw_type(
                    self.vault_id.as_bytes(),
                    id.as_bytes(),
                    3,
                    s_row.key_epoch,
                );
                open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
            }
        };
        let s_body: SecretBody = postcard::from_bytes(&s_bytes).map_err(|_| Error::Storage)?;

        let target_env_opt = target_env.into();
        let target_item_id = if let Some(env_id) = target_env_opt {
            let target_env_row = get_record(&self.db, env_id)?.ok_or(Error::NotFound)?;
            if target_env_row.deleted {
                return Err(Error::NotFound);
            }
            target_env_row.parent_id.ok_or(Error::NotFound)?
        } else {
            s_body.item_id
        };

        let draft = SecretDraft::new(
            target_item_id,
            target_env_opt,
            s_body.name,
            s_body.kind,
            s_body.value,
            s_body.note,
        );
        self.create_secret(draft)
    }

    /// Decrypts secrets for process injection in `secwet run`.
    ///
    /// - If `environment_id` is None, returns item-level secrets.
    /// - If `environment_id` is Some(env_id), returns item-level secrets overlaid with environment-level secrets.
    pub fn env_for(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<(String, SecretString)>> {
        let item_row = get_record(&self.db, item_id)?.ok_or(Error::NotFound)?;
        if item_row.deleted {
            return Err(Error::NotFound);
        }

        let mut map: HashMap<String, SecretString> = HashMap::new();

        // 1. Item-level base secrets
        let item_secrets = query_content_records(&self.db, item_id, None, RecordType::Secret)?;
        for s_row in item_secrets {
            let blob = s_row.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                s_row.id.as_bytes(),
                RecordType::Secret,
                s_row.key_epoch,
            );
            let bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.vault_id.as_bytes(),
                        s_row.id.as_bytes(),
                        3,
                        s_row.key_epoch,
                    );
                    open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
                }
            };
            let body: SecretBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            map.insert(body.name, SecretString::from(body.value));
        }

        // 2. If environment_id is Some, overlay environment-specific secrets
        if let Some(env_id) = environment_id {
            let env_secrets =
                query_content_records(&self.db, item_id, Some(env_id), RecordType::Secret)?;
            for s_row in env_secrets {
                let blob = s_row.blob.as_ref().ok_or(Error::Storage)?;
                let aad = RecordAad::new(
                    self.vault_id.as_bytes(),
                    s_row.id.as_bytes(),
                    RecordType::Secret,
                    s_row.key_epoch,
                );
                let bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
                    Ok(b) => b,
                    Err(_) => {
                        let leg_aad = RecordAad::from_raw_type(
                            self.vault_id.as_bytes(),
                            s_row.id.as_bytes(),
                            3,
                            s_row.key_epoch,
                        );
                        open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
                    }
                };
                let body: SecretBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
                map.insert(body.name, SecretString::from(body.value));
            }
        }

        let mut pairs: Vec<(String, SecretString)> = map.into_iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(pairs)
    }

    /// Backwards-compatible env_for by environment ID alone.
    pub fn env_for_environment(&self, environment: Uuid) -> Result<Vec<(String, SecretString)>> {
        let env_row = get_record(&self.db, environment)?.ok_or(Error::NotFound)?;
        if env_row.deleted {
            return Err(Error::NotFound);
        }
        let item_id = env_row.parent_id.ok_or(Error::NotFound)?;
        self.env_for(item_id, Some(environment))
    }

    // ========================================================================
    // Files Management (F5b)
    // ========================================================================

    /// Lists metadata for all active assets associated with an item or environment.
    ///
    /// Invariant: Strictly returns `AssetMetaView` containing asset size and SHA-256 fingerprint.
    /// NEVER returns raw asset bytes.
    pub fn list_assets(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<AssetMetaView>> {
        self.validate_container(item_id, environment_id)?;

        let rows = query_content_records(&self.db, item_id, environment_id, RecordType::Asset)?;
        let mut assets = Vec::with_capacity(rows.len());

        for row in rows {
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Asset,
                row.key_epoch,
            );
            let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
            let payload: AssetPayload = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

            assets.push(AssetMetaView::new(
                row.id,
                payload.meta.item_id,
                payload.meta.environment_id,
                payload.meta.name,
                payload.meta.size_bytes,
                payload.meta.mime_type,
                data_encoding::HEXLOWER.encode(&payload.meta.sha256),
                row.updated_at,
            ));
        }

        assets.sort_by_key(|a| std::cmp::Reverse(a.updated_at));
        Ok(assets)
    }

    #[inline]
    pub fn list_files(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<FileMetaView>> {
        self.list_assets(item_id, environment_id)
    }

    /// Uploads, validates, hashes, and encrypts an asset onto local device storage.
    ///
    /// Invariants:
    /// - Max size: <= 50 MiB (52,428,800 bytes).
    /// - Asset name: 1..=255 characters, trimmed, unique per container.
    /// - Payload encrypted with XChaCha20Poly1305 bound by `RecordAad` (type 5).
    pub fn upload_asset(
        &mut self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        name: &str,
        data: &[u8],
        mime_type: Option<&str>,
    ) -> Result<AssetMetaView> {
        self.validate_container(item_id, environment_id)?;

        let clean_name = secwet_proto::validate_asset_name(name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter an asset name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "name",
                message: "Keep the asset name under 255 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid asset name.".to_string(),
            },
        })?;

        let sanitized_name = std::path::Path::new(&clean_name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&clean_name)
            .to_string();

        secwet_proto::validate_asset_size(data.len() as u64).map_err(|_| Error::Invalid {
            field: "size",
            message: "Asset exceeds maximum allowed size of 50 MiB.".to_string(),
        })?;

        let siblings = query_content_records(&self.db, item_id, environment_id, RecordType::Asset)?;
        for sib in siblings {
            let blob = sib.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                sib.id.as_bytes(),
                RecordType::Asset,
                sib.key_epoch,
            );
            let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
            let sib_payload: AssetPayload =
                postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            if sib_payload
                .meta
                .name
                .trim()
                .eq_ignore_ascii_case(&sanitized_name)
            {
                return Err(Error::Duplicate { field: "name" });
            }
        }

        let sha256: [u8; 32] = sha2::Sha256::digest(data).into();
        let asset_id = Uuid::now_v7();
        let mime = mime_type
            .map(|m| m.trim())
            .filter(|m| !m.is_empty())
            .unwrap_or("application/octet-stream")
            .to_string();

        let meta_body = AssetMetaBody::new(
            item_id,
            environment_id,
            sanitized_name.clone(),
            data.len() as u64,
            mime.clone(),
            sha256,
        );
        let payload = AssetPayload::new(meta_body, data.to_vec());
        let payload_bytes = postcard::to_stdvec(&payload).map_err(|_| Error::Storage)?;

        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            asset_id.as_bytes(),
            RecordType::Asset,
            self.key_epoch,
        );
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &payload_bytes)?;

        let parent_id = environment_id.unwrap_or(item_id);
        let lamport = next_lamport(&self.db)?;
        let now_ms = current_time_ms();
        let record = RecordRow::new_active(
            asset_id,
            RecordType::Asset,
            Some(parent_id),
            self.key_epoch,
            blob,
            lamport,
            &self.device_id,
            now_ms,
        );
        insert_record(&self.db, &record)?;

        Ok(AssetMetaView::new(
            asset_id,
            item_id,
            environment_id,
            sanitized_name,
            data.len() as u64,
            mime,
            data_encoding::HEXLOWER.encode(&sha256),
            now_ms,
        ))
    }

    #[inline]
    pub fn upload_file(
        &mut self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        name: &str,
        data: &[u8],
        mime_type: Option<&str>,
    ) -> Result<FileMetaView> {
        self.upload_asset(item_id, environment_id, name, data, mime_type)
    }

    /// Fetches, verifies MAC authenticity, and decrypts raw asset bytes.
    pub fn download_asset(&self, id: Uuid) -> Result<(AssetMetaView, Vec<u8>)> {
        let row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if row.deleted || row.record_type != RecordType::Asset {
            return Err(Error::NotFound);
        }

        let blob = row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Asset,
            row.key_epoch,
        );
        let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
        let payload: AssetPayload = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        // Verify data integrity against embedded SHA-256
        let actual_hash: [u8; 32] = sha2::Sha256::digest(&payload.data).into();
        if actual_hash != payload.meta.sha256 {
            return Err(Error::Crypto);
        }

        let meta_view = AssetMetaView::new(
            row.id,
            payload.meta.item_id,
            payload.meta.environment_id,
            payload.meta.name,
            payload.meta.size_bytes,
            payload.meta.mime_type,
            data_encoding::HEXLOWER.encode(&payload.meta.sha256),
            row.updated_at,
        );

        Ok((meta_view, payload.data))
    }

    #[inline]
    pub fn download_file(&self, id: Uuid) -> Result<(FileMetaView, Vec<u8>)> {
        self.download_asset(id)
    }

    /// Renames an existing asset within its container.
    pub fn rename_asset(&mut self, id: Uuid, name: &str) -> Result<AssetMetaView> {
        let clean_name = secwet_proto::validate_asset_name(name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter an asset name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "name",
                message: "Keep the asset name under 255 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid asset name.".to_string(),
            },
        })?;

        let sanitized_name = std::path::Path::new(&clean_name)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&clean_name)
            .to_string();

        let row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if row.deleted || row.record_type != RecordType::Asset {
            return Err(Error::NotFound);
        }

        let blob = row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Asset,
            row.key_epoch,
        );
        let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
        let mut payload: AssetPayload = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        // Sibling uniqueness check
        let siblings = query_records_by_parent(&self.db, row.parent_id, false)?;
        for sib in siblings {
            if sib.id == id || sib.record_type != RecordType::Asset {
                continue;
            }
            let s_blob = sib.blob.as_ref().ok_or(Error::Storage)?;
            let s_aad = RecordAad::new(
                self.vault_id.as_bytes(),
                sib.id.as_bytes(),
                RecordType::Asset,
                sib.key_epoch,
            );
            let s_bytes = open_record(self.k_rec.expose_secret(), &s_aad, s_blob)?;
            let s_payload: AssetPayload =
                postcard::from_bytes(&s_bytes).map_err(|_| Error::Storage)?;
            if s_payload
                .meta
                .name
                .trim()
                .eq_ignore_ascii_case(&sanitized_name)
            {
                return Err(Error::Duplicate { field: "name" });
            }
        }

        payload.meta.name = sanitized_name.clone();
        let payload_bytes = postcard::to_stdvec(&payload).map_err(|_| Error::Storage)?;
        let new_aad = RecordAad::new(
            self.vault_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Asset,
            row.key_epoch,
        );
        let new_blob = seal_record(self.k_rec.expose_secret(), &new_aad, &payload_bytes)?;

        let now_ms = current_time_ms();
        update_record_blob(&self.db, id, &new_blob, &self.device_id, now_ms)?;

        Ok(AssetMetaView::new(
            row.id,
            payload.meta.item_id,
            payload.meta.environment_id,
            sanitized_name,
            payload.meta.size_bytes,
            payload.meta.mime_type,
            data_encoding::HEXLOWER.encode(&payload.meta.sha256),
            now_ms,
        ))
    }

    #[inline]
    pub fn rename_file(&mut self, id: Uuid, name: &str) -> Result<FileMetaView> {
        self.rename_asset(id, name)
    }

    /// Soft-deletes an asset record and immediately zeroes ciphertext blob.
    pub fn delete_asset(&mut self, id: Uuid) -> Result<()> {
        let existing = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if existing.deleted || existing.record_type != RecordType::Asset {
            return Err(Error::NotFound);
        }
        soft_delete_record(&self.db, id, &self.device_id, current_time_ms())?;
        Ok(())
    }

    #[inline]
    pub fn delete_file(&mut self, id: Uuid) -> Result<()> {
        self.delete_asset(id)
    }

    // ========================================================================
    // Rich-Text Notes Management (F5c)
    // ========================================================================

    /// Lists note previews with plain-text snippets for an item or environment.
    pub fn list_notes(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<Vec<NoteMetaView>> {
        self.validate_container(item_id, environment_id)?;

        let rows = query_content_records(&self.db, item_id, environment_id, RecordType::Note)?;
        let mut notes = Vec::with_capacity(rows.len());

        for row in rows {
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Note,
                row.key_epoch,
            );
            let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
            let body: NoteBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

            let snippet = secwet_proto::snippet_from_content(&body.content, 120);

            notes.push(NoteMetaView::new(
                row.id,
                body.item_id,
                body.environment_id,
                body.title,
                snippet,
                row.updated_at,
                body.position,
            ));
        }

        notes.sort_by(|a, b| {
            a.position
                .cmp(&b.position)
                .then_with(|| b.updated_at.cmp(&a.updated_at))
        });
        Ok(notes)
    }

    /// Fetches and decrypts the complete rich-text note content.
    pub fn get_note(&self, id: Uuid) -> Result<NoteView> {
        let row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if row.deleted || row.record_type != RecordType::Note {
            return Err(Error::NotFound);
        }

        let blob = row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Note,
            row.key_epoch,
        );
        let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
        let body: NoteBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        Ok(NoteView::new(
            row.id,
            body.item_id,
            body.environment_id,
            body.title,
            body.content,
            row.updated_at,
            body.position,
        ))
    }

    /// Creates a new encrypted rich-text note.
    ///
    /// Invariants:
    /// - Title: 1..=128 trimmed characters.
    /// - Content: <= 1,000,000 Unicode characters.
    /// - Multiple notes allowed per container.
    pub fn create_note(
        &mut self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        title: &str,
        content: &str,
    ) -> Result<NoteView> {
        self.validate_container(item_id, environment_id)?;

        let clean_title = secwet_proto::validate_note_title(title).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "title",
                message: "Enter a note title.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                field: "title",
                message: "Keep the title under 128 characters.".to_string(),
            },
            _ => Error::Invalid {
                field: "title",
                message: "Enter a valid note title.".to_string(),
            },
        })?;

        secwet_proto::validate_note_content(content).map_err(|_| Error::Invalid {
            field: "content",
            message: "Note content cannot exceed 1,000,000 characters.".to_string(),
        })?;

        let existing = query_content_records(&self.db, item_id, environment_id, RecordType::Note)?;
        let position = existing.len() as u32;

        let note_id = Uuid::now_v7();
        let body = NoteBody::new(
            item_id,
            environment_id,
            clean_title.clone(),
            content,
            position,
        );
        let body_bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;

        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            note_id.as_bytes(),
            RecordType::Note,
            self.key_epoch,
        );
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &body_bytes)?;

        let parent_id = environment_id.unwrap_or(item_id);
        let lamport = next_lamport(&self.db)?;
        let now_ms = current_time_ms();
        let record = RecordRow::new_active(
            note_id,
            RecordType::Note,
            Some(parent_id),
            self.key_epoch,
            blob,
            lamport,
            &self.device_id,
            now_ms,
        );
        insert_record(&self.db, &record)?;

        Ok(NoteView::new(
            note_id,
            item_id,
            environment_id,
            clean_title,
            content,
            now_ms,
            position,
        ))
    }

    /// Updates title and rich-text content of an existing note.
    pub fn update_note<'a>(
        &mut self,
        id: Uuid,
        title: impl Into<Option<&'a str>>,
        content: impl Into<Option<&'a str>>,
    ) -> Result<NoteView> {
        let title_opt: Option<&'a str> = title.into();
        let content_opt: Option<&'a str> = content.into();

        let row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if row.deleted || row.record_type != RecordType::Note {
            return Err(Error::NotFound);
        }

        let blob = row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Note,
            row.key_epoch,
        );
        let bytes = open_record(self.k_rec.expose_secret(), &aad, blob)?;
        let existing: NoteBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        let final_title = if let Some(t) = title_opt {
            secwet_proto::validate_note_title(t).map_err(|err| match err {
                secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                    field: "title",
                    message: "Enter a note title.".to_string(),
                },
                secwet_proto::ValidationError::TooLong { .. } => Error::Invalid {
                    field: "title",
                    message: "Keep the title under 128 characters.".to_string(),
                },
                _ => Error::Invalid {
                    field: "title",
                    message: "Enter a valid note title.".to_string(),
                },
            })?
        } else {
            existing.title
        };

        let final_content = if let Some(c) = content_opt {
            secwet_proto::validate_note_content(c).map_err(|_| Error::Invalid {
                field: "content",
                message: "Note content cannot exceed 1,000,000 characters.".to_string(),
            })?;
            c.to_string()
        } else {
            existing.content
        };

        let updated_body = NoteBody::new(
            existing.item_id,
            existing.environment_id,
            final_title.clone(),
            &final_content,
            existing.position,
        );
        let updated_bytes = postcard::to_stdvec(&updated_body).map_err(|_| Error::Storage)?;

        let new_aad = RecordAad::new(
            self.vault_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Note,
            row.key_epoch,
        );
        let new_blob = seal_record(self.k_rec.expose_secret(), &new_aad, &updated_bytes)?;

        let now_ms = current_time_ms();
        update_record_blob(&self.db, id, &new_blob, &self.device_id, now_ms)?;

        Ok(NoteView::new(
            id,
            existing.item_id,
            existing.environment_id,
            final_title,
            final_content,
            now_ms,
            existing.position,
        ))
    }

    /// Soft-deletes a note record and immediately zeroes ciphertext blob.
    pub fn delete_note(&mut self, id: Uuid) -> Result<()> {
        let existing = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if existing.deleted || existing.record_type != RecordType::Note {
            return Err(Error::NotFound);
        }
        soft_delete_record(&self.db, id, &self.device_id, current_time_ms())?;
        Ok(())
    }

    // ========================================================================
    // Legacy Projects CRUD (Backward Compatibility)
    // ========================================================================

    /// Lists all projects/items along with their child environments and secret counts.
    pub fn list_projects(&self) -> Result<Vec<ProjectView>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT id, key_epoch, blob FROM records WHERE record_type IN (1, 2) AND deleted = 0 ORDER BY updated_at ASC",
            )
            .map_err(|_| Error::Storage)?;
        let rows = stmt
            .query_map([], |row| {
                let id_bytes: Vec<u8> = row.get(0)?;
                let id = Uuid::from_slice(&id_bytes).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;
                let key_epoch: u32 = row.get(1)?;
                let blob: Option<Vec<u8>> = row.get(2)?;
                Ok((id, key_epoch, blob))
            })
            .map_err(|_| Error::Storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::Storage)?;

        let mut projects = Vec::with_capacity(rows.len());

        for (id, key_epoch, blob_opt) in rows {
            let blob = match blob_opt {
                Some(b) => b,
                None => continue,
            };

            let aad = RecordAad::new(
                self.vault_id.as_bytes(),
                id.as_bytes(),
                RecordType::Item,
                key_epoch,
            );
            let bytes = match open_record(self.k_rec.expose_secret(), &aad, &blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.vault_id.as_bytes(),
                        id.as_bytes(),
                        1,
                        key_epoch,
                    );
                    open_record(self.k_rec.expose_secret(), &leg_aad, &blob)?
                }
            };

            let name = if let Ok(item) = postcard::from_bytes::<ItemBody>(&bytes) {
                item.name
            } else if let Ok(proj) = postcard::from_bytes::<ProjectBody>(&bytes) {
                proj.name
            } else {
                return Err(Error::Storage);
            };

            let env_rows = query_records_by_parent(&self.db, Some(id), false)?;
            let mut env_views = Vec::with_capacity(env_rows.len());

            for env_row in env_rows {
                if env_row.record_type != RecordType::Environment
                    && env_row.record_type != RecordType::Item
                /* legacy 2 */
                {
                    continue;
                }
                let e_blob = match env_row.blob.as_ref() {
                    Some(b) => b,
                    None => continue,
                };
                let e_aad = RecordAad::new(
                    self.vault_id.as_bytes(),
                    env_row.id.as_bytes(),
                    RecordType::Environment,
                    env_row.key_epoch,
                );
                let e_bytes = match open_record(self.k_rec.expose_secret(), &e_aad, e_blob) {
                    Ok(b) => b,
                    Err(_) => {
                        let leg_aad = RecordAad::from_raw_type(
                            self.vault_id.as_bytes(),
                            env_row.id.as_bytes(),
                            2,
                            env_row.key_epoch,
                        );
                        open_record(self.k_rec.expose_secret(), &leg_aad, e_blob)?
                    }
                };
                let e_body: EnvironmentBody =
                    postcard::from_bytes(&e_bytes).map_err(|_| Error::Storage)?;

                let count: i64 = self
                    .db
                    .query_row(
                        "SELECT COUNT(*) FROM records WHERE record_type IN (3, 4) AND parent_id = ?1 AND deleted = 0",
                        params![env_row.id.as_bytes().as_slice()],
                        |r| r.get(0),
                    )
                    .map_err(|_| Error::Storage)?;

                env_views.push(EnvironmentView {
                    id: env_row.id,
                    project_id: id,
                    name: e_body.name,
                    position: e_body.position,
                    secret_count: count as usize,
                });
            }

            env_views.sort_by_key(|e| e.position);

            projects.push(ProjectView {
                id,
                name,
                environments: env_views,
            });
        }

        Ok(projects)
    }

    /// Creates a new project with either specified environments or default ones.
    pub fn create_project(&mut self, name: &str, environments: &[String]) -> Result<ProjectView> {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            return Err(Error::Invalid {
                field: "name",
                message: "Enter a project name.".to_string(),
            });
        }
        if trimmed_name.chars().count() > 64 {
            return Err(Error::Invalid {
                field: "name",
                message: "Keep the name under 64 characters.".to_string(),
            });
        }

        let default_envs = [
            "Development".to_string(),
            "Staging".to_string(),
            "Production".to_string(),
        ];
        let target_envs = if environments.is_empty() {
            &default_envs[..]
        } else {
            environments
        };

        if target_envs.len() > 12 {
            return Err(Error::Invalid {
                field: "environments",
                message: "Use at most 12 environments.".to_string(),
            });
        }

        let mut validated_envs: Vec<String> = Vec::with_capacity(target_envs.len());
        for env in target_envs {
            let t = env.trim();
            if t.is_empty() {
                return Err(Error::Invalid {
                    field: "name",
                    message: "Enter an environment name.".to_string(),
                });
            }
            if t.chars().count() > 64 {
                return Err(Error::Invalid {
                    field: "name",
                    message: "Keep the name under 64 characters.".to_string(),
                });
            }
            if validated_envs
                .iter()
                .any(|e| same_name_case_insensitive(e, t))
            {
                return Err(Error::Duplicate { field: "name" });
            }
            validated_envs.push(t.to_string());
        }

        // Check project case-insensitive uniqueness against existing projects
        let existing = self.list_projects()?;
        if existing
            .iter()
            .any(|p| same_name_case_insensitive(&p.name, trimmed_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        // Find or create default "Projects" label
        let labels = self.list_labels()?;
        let label_id = match labels
            .iter()
            .find(|l| same_name_case_insensitive(&l.name, "projects"))
        {
            Some(l) => l.id,
            None => {
                self.create_label("Projects", Some("folder".to_string()))?
                    .id
            }
        };

        let now_ms = current_time_ms();
        let project_id = Uuid::now_v7();

        let p_body = ItemBody::new(label_id, trimmed_name, None, existing.len() as u32);
        let p_bytes = postcard::to_stdvec(&p_body).map_err(|_| Error::Storage)?;
        let p_aad = RecordAad::new(
            self.vault_id.as_bytes(),
            project_id.as_bytes(),
            RecordType::Item,
            self.key_epoch,
        );
        let p_blob = seal_record(self.k_rec.expose_secret(), &p_aad, &p_bytes)?;

        let mut lamport = next_lamport(&self.db)?;
        let project_row = RecordRow::new_active(
            project_id,
            RecordType::Item,
            Some(label_id),
            self.key_epoch,
            p_blob,
            lamport,
            &self.device_id,
            now_ms,
        );

        let tx = self.db.transaction().map_err(|_| Error::Storage)?;
        insert_record(&tx, &project_row)?;

        let mut env_views = Vec::with_capacity(validated_envs.len());
        for (pos, env_name) in validated_envs.into_iter().enumerate() {
            let env_id = Uuid::now_v7();
            let e_body = EnvironmentBody::new(project_id, &env_name, pos as u32);
            let e_bytes = postcard::to_stdvec(&e_body).map_err(|_| Error::Storage)?;
            let e_aad = RecordAad::new(
                self.vault_id.as_bytes(),
                env_id.as_bytes(),
                RecordType::Environment,
                self.key_epoch,
            );
            let e_blob = seal_record(self.k_rec.expose_secret(), &e_aad, &e_bytes)?;

            lamport += 1;
            let env_row = RecordRow::new_active(
                env_id,
                RecordType::Environment,
                Some(project_id),
                self.key_epoch,
                e_blob,
                lamport,
                &self.device_id,
                now_ms,
            );
            insert_record(&tx, &env_row)?;

            env_views.push(EnvironmentView {
                id: env_id,
                project_id,
                name: env_name,
                position: pos as u32,
                secret_count: 0,
            });
        }

        tx.commit().map_err(|_| Error::Storage)?;

        Ok(ProjectView {
            id: project_id,
            name: trimmed_name.to_string(),
            environments: env_views,
        })
    }

    /// Renames a project and re-seals its body.
    pub fn rename_project(&mut self, id: Uuid, name: &str) -> Result<()> {
        let trimmed_name = name.trim();
        if trimmed_name.is_empty() {
            return Err(Error::Invalid {
                field: "name",
                message: "Enter a project name.".to_string(),
            });
        }
        if trimmed_name.chars().count() > 64 {
            return Err(Error::Invalid {
                field: "name",
                message: "Keep the name under 64 characters.".to_string(),
            });
        }

        let p_row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if p_row.deleted
            || (p_row.record_type != RecordType::Project && p_row.record_type != RecordType::Item)
        {
            return Err(Error::NotFound);
        }

        let existing = self.list_projects()?;
        if existing
            .iter()
            .any(|p| p.id != id && same_name_case_insensitive(&p.name, trimmed_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let blob = p_row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Item,
            p_row.key_epoch,
        );
        let bytes = match open_record(self.k_rec.expose_secret(), &aad, blob) {
            Ok(b) => b,
            Err(_) => {
                let leg_aad = RecordAad::from_raw_type(
                    self.vault_id.as_bytes(),
                    id.as_bytes(),
                    1,
                    p_row.key_epoch,
                );
                open_record(self.k_rec.expose_secret(), &leg_aad, blob)?
            }
        };

        let label_id = p_row.parent_id.unwrap_or(id);
        let cur_pos = if let Ok(item) = postcard::from_bytes::<ItemBody>(&bytes) {
            item.position
        } else {
            0
        };

        let item_body = ItemBody::new(label_id, trimmed_name, None, cur_pos);
        let item_bytes = postcard::to_stdvec(&item_body).map_err(|_| Error::Storage)?;
        let new_aad = RecordAad::new(
            self.vault_id.as_bytes(),
            id.as_bytes(),
            RecordType::Item,
            p_row.key_epoch,
        );
        let p_blob = seal_record(self.k_rec.expose_secret(), &new_aad, &item_bytes)?;

        update_record_blob(&self.db, id, &p_blob, &self.device_id, current_time_ms())?;
        Ok(())
    }

    /// Cascades deletion of a project, marking its environments and secrets deleted.
    pub fn delete_project(&mut self, id: Uuid) -> Result<()> {
        let p_row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if p_row.deleted {
            return Err(Error::NotFound);
        }

        if p_row.record_type == RecordType::Label /* raw 1 */ && !self.is_flexible_migrated() {
            cascade_delete_project(&mut self.db, id, &self.device_id, current_time_ms())?;
        } else {
            cascade_delete_item(&mut self.db, id, &self.device_id, current_time_ms())?;
        }
        Ok(())
    }

    // ========================================================================
    // Overview & Dashboard Configuration (F8)
    // ========================================================================

    /// Computes aggregated statistics across labels, items, environments, secrets,
    /// files, notes, and devices, plus metadata for 5 most recent secrets.
    pub fn overview(&self) -> Result<Overview> {
        let labels_count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM labels WHERE deleted = 0", [], |r| {
                r.get(0)
            })
            .map_err(|_| Error::Storage)?;

        let items_count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type IN (1, 2) AND deleted = 0",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)?;

        let is_migrated = self.is_flexible_migrated();

        let environments_count: i64 = if is_migrated {
            self.db
                .query_row(
                    "SELECT COUNT(*) FROM records WHERE record_type = 3 AND deleted = 0",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| Error::Storage)?
        } else {
            self.db
                .query_row(
                    "SELECT COUNT(*) FROM records WHERE record_type = 2 AND deleted = 0",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| Error::Storage)?
        };

        let secrets_count: i64 = if is_migrated {
            self.db
                .query_row(
                    "SELECT COUNT(*) FROM records WHERE record_type = 4 AND deleted = 0",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| Error::Storage)?
        } else {
            self.db
                .query_row(
                    "SELECT COUNT(*) FROM records WHERE record_type = 3 AND deleted = 0",
                    [],
                    |r| r.get(0),
                )
                .map_err(|_| Error::Storage)?
        };

        let files_count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 5 AND deleted = 0",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)?;

        let notes_count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM records WHERE record_type = 6 AND deleted = 0",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)?;

        let active_devices_count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL",
                [],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)?;

        let projects = self.list_projects()?;

        let mut item_names = HashMap::new();
        let mut env_names = HashMap::new();
        for p in &projects {
            item_names.insert(p.id, p.name.clone());
            for e in &p.environments {
                env_names.insert(e.id, e.name.clone());
            }
        }

        let secret_type = if is_migrated { 4u8 } else { 3u8 };
        let mut stmt = self
            .db
            .prepare(
                "SELECT id, parent_id, key_epoch, blob, updated_at
                 FROM records WHERE record_type = ?1 AND deleted = 0
                 ORDER BY updated_at DESC LIMIT 5",
            )
            .map_err(|_| Error::Storage)?;

        let mut rows = stmt
            .query(params![secret_type])
            .map_err(|_| Error::Storage)?;
        let mut recent = Vec::new();

        while let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let id_bytes: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            let id = Uuid::from_slice(&id_bytes).map_err(|_| Error::Storage)?;
            let key_epoch: u32 = row.get(2).map_err(|_| Error::Storage)?;
            let blob: Vec<u8> = row.get(3).map_err(|_| Error::Storage)?;
            let updated_at: i64 = row.get(4).map_err(|_| Error::Storage)?;

            let s_bytes = if is_migrated {
                let aad = RecordAad::new(
                    self.vault_id.as_bytes(),
                    id.as_bytes(),
                    RecordType::Secret,
                    key_epoch,
                );
                open_record(self.k_rec.expose_secret(), &aad, &blob)?
            } else {
                let leg_aad =
                    RecordAad::from_raw_type(self.vault_id.as_bytes(), id.as_bytes(), 3, key_epoch);
                open_record(self.k_rec.expose_secret(), &leg_aad, &blob)?
            };

            let s_body = match postcard::from_bytes::<SecretBody>(&s_bytes) {
                Ok(b) => b,
                Err(_) => {
                    if let Ok(leg) = postcard::from_bytes::<LegacyV1SecretBody>(&s_bytes) {
                        SecretBody::new(
                            leg.project_id,
                            Some(leg.environment_id),
                            leg.name,
                            leg.kind,
                            leg.value,
                            leg.note,
                        )
                    } else {
                        continue;
                    }
                }
            };

            let (p_id, p_name, e_id, e_name) = match s_body.environment_id {
                Some(env_id) => {
                    let env_name = env_names.get(&env_id).cloned().unwrap_or_default();
                    let item_name = item_names.get(&s_body.item_id).cloned().unwrap_or_default();
                    (s_body.item_id, item_name, env_id, env_name)
                }
                None => {
                    let item_name = item_names.get(&s_body.item_id).cloned().unwrap_or_default();
                    (s_body.item_id, item_name, Uuid::nil(), String::new())
                }
            };

            recent.push(RecentSecret {
                id,
                name: s_body.name,
                project_id: p_id,
                project_name: p_name,
                environment_id: e_id,
                environment_name: e_name,
                updated_at,
            });
        }

        let recovery_key_created = get_meta(&self.db, "recovery_created_at")?.is_some();
        let cli_connected = get_meta(&self.db, "cli_last_used_at")?.is_some();
        let add_device_done = active_devices_count > 1;

        let pending_rotation: Option<String> = self
            .db
            .query_row(
                "SELECT device_id FROM devices WHERE revoked_at IS NOT NULL LIMIT 1",
                [],
                |r| r.get(0),
            )
            .ok();

        let checklist = ChecklistState {
            vault_created: true,
            recovery_key_created,
            cli_connected,
            add_device_done,
            pending_rotation,
        };

        Ok(Overview {
            labels_count: labels_count as usize,
            items_count: items_count as usize,
            projects_count: items_count as usize,
            environments_count: environments_count as usize,
            secrets_count: secrets_count as usize,
            assets_count: files_count as usize,
            files_count: files_count as usize,
            notes_count: notes_count as usize,
            active_devices_count: active_devices_count as usize,
            projects,
            recent,
            checklist,
        })
    }

    /// Reads dashboard configuration from SQLite `settings` table.
    pub fn dashboard_config(&self) -> Result<DashboardConfig> {
        let mut stmt = self
            .db
            .prepare("SELECT value FROM settings WHERE key = 'dashboard_config'")
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt.query([]).map_err(|_| Error::Storage)?;

        if let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let json_str: String = row.get(0).map_err(|_| Error::Storage)?;
            if let Ok(cfg) = serde_json::from_str::<DashboardConfig>(&json_str) {
                return Ok(cfg);
            }
        }

        let home_label = self
            .db
            .query_row(
                "SELECT value FROM settings WHERE key = 'home_label'",
                [],
                |r| r.get(0),
            )
            .unwrap_or_else(|_| "Home".to_string());

        Ok(DashboardConfig {
            home_label,
            ..Default::default()
        })
    }

    /// Persists dashboard configuration into SQLite `settings` table.
    pub fn set_dashboard_config(&mut self, cfg: &DashboardConfig) -> Result<()> {
        let trimmed_home = cfg.home_label.trim();
        if trimmed_home.is_empty() {
            return Err(Error::Invalid {
                field: "home_label",
                message: "Home label cannot be empty.".to_string(),
            });
        }
        if trimmed_home.chars().count() > 64 {
            return Err(Error::Invalid {
                field: "home_label",
                message: "Keep the home label under 64 characters.".to_string(),
            });
        }

        let json_str = serde_json::to_string(cfg).map_err(|_| Error::Storage)?;
        let widgets_json = serde_json::to_string(&cfg.widgets).map_err(|_| Error::Storage)?;

        let tx = self.db.transaction().map_err(|_| Error::Storage)?;

        tx.execute(
            "INSERT INTO settings (key, value) VALUES ('dashboard_config', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![json_str],
        )
        .map_err(|_| Error::Storage)?;

        tx.execute(
            "INSERT INTO settings (key, value) VALUES ('home_label', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![trimmed_home],
        )
        .map_err(|_| Error::Storage)?;

        tx.execute(
            "INSERT INTO settings (key, value) VALUES ('dashboard_widgets', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![widgets_json],
        )
        .map_err(|_| Error::Storage)?;

        tx.commit().map_err(|_| Error::Storage)?;
        Ok(())
    }

    // ========================================================================
    // Settings (F17)
    // ========================================================================

    /// Retrieves preferences from the local settings table and encrypted device name from devices table.
    pub fn settings(&self) -> Result<Settings> {
        let mut theme = "system".to_string();
        let mut lock_timeout_minutes = 15u32;

        let mut stmt = self
            .db
            .prepare("SELECT key, value FROM settings")
            .map_err(|_| Error::Storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| Error::Storage)?;

        for row in rows {
            let (k, v) = row.map_err(|_| Error::Storage)?;
            match k.as_str() {
                "theme" => theme = v,
                "lock_timeout_minutes" => {
                    if let Ok(m) = v.parse::<u32>() {
                        lock_timeout_minutes = m;
                    }
                }
                _ => {}
            }
        }

        let mut stmt = self
            .db
            .prepare("SELECT name_blob FROM devices WHERE device_id = ?1")
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt
            .query(params![self.device_id])
            .map_err(|_| Error::Storage)?;

        let device_name = if let Some(row) = rows.next().map_err(|_| Error::Storage)? {
            let name_blob: Vec<u8> = row.get(0).map_err(|_| Error::Storage)?;
            unseal_device_name(self.k_rec.expose_secret(), &self.device_id, &name_blob)?
        } else {
            "default-device".to_string()
        };

        Ok(Settings {
            theme,
            lock_timeout_minutes,
            device_name,
        })
    }

    /// Validates and updates vault preferences and device name within an atomic transaction.
    pub fn set_settings(&mut self, s: Settings) -> Result<()> {
        if !matches!(s.theme.as_str(), "system" | "light" | "dark") {
            return Err(Error::Invalid {
                field: "theme",
                message: "appearance must be 'system', 'light', or 'dark'".to_string(),
            });
        }

        if !matches!(s.lock_timeout_minutes, 5 | 15 | 30 | 60) {
            return Err(Error::Invalid {
                field: "lock_timeout_minutes",
                message: "lock timeout must be 5, 15, 30, or 60 minutes".to_string(),
            });
        }

        let trimmed_name = s.device_name.trim();
        if trimmed_name.is_empty() {
            return Err(Error::Invalid {
                field: "device_name",
                message: "device name cannot be empty".to_string(),
            });
        }
        if trimmed_name.chars().count() > 64 {
            return Err(Error::Invalid {
                field: "device_name",
                message: "device name cannot exceed 64 characters".to_string(),
            });
        }

        let name_blob =
            seal_device_name(self.k_rec.expose_secret(), &self.device_id, trimmed_name)?;

        let tx = self.db.transaction().map_err(|_| Error::Storage)?;

        tx.execute(
            "INSERT INTO settings (key, value) VALUES ('theme', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![s.theme],
        )
        .map_err(|_| Error::Storage)?;

        tx.execute(
            "INSERT INTO settings (key, value) VALUES ('lock_timeout_minutes', ?1)
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![s.lock_timeout_minutes.to_string()],
        )
        .map_err(|_| Error::Storage)?;

        let updated = tx
            .execute(
                "UPDATE devices SET name_blob = ?1 WHERE device_id = ?2",
                params![name_blob, self.device_id],
            )
            .map_err(|_| Error::Storage)?;

        if updated == 0 {
            let now_ms = current_time_ms();
            tx.execute(
                "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at)
                 VALUES (?1, ?2, X'', X'', ?3, NULL, ?3)",
                params![self.device_id, name_blob, now_ms],
            )
            .map_err(|_| Error::Storage)?;
        }

        tx.commit().map_err(|_| Error::Storage)?;
        Ok(())
    }

    // ========================================================================
    // Testing and Verification Hooks
    // ========================================================================

    #[cfg(any(test, feature = "test-util"))]
    pub fn db_connection(&self) -> &Connection {
        &self.db
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn test_k_rec_witness(&self) -> std::sync::Arc<std::sync::Mutex<[u8; 32]>> {
        self.test_k_rec_witness.clone()
    }

    #[cfg(any(test, feature = "test-util"))]
    pub fn test_k_evt_witness(&self) -> std::sync::Arc<std::sync::Mutex<[u8; 32]>> {
        self.test_k_evt_witness.clone()
    }
}

impl Drop for Vault {
    fn drop(&mut self) {
        self.zeroize_keys_internal();
        if let Ok(mut guard) = ACTIVE_VAULTS.lock() {
            guard.remove(&self.vault_id);
        }
    }
}
