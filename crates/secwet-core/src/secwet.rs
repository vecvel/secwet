//! Public Secwet API Engine.
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
use crate::records::{self, *};
use crate::{Error, Result};
use rand_core::Rng;
use rusqlite::{params, Connection};
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString};
pub use secwet_proto::Settings;
use secwet_proto::{
    AssetMetaBody, AssetMetaView, AssetPayload, DashboardConfig, EnvironmentBody,
    EnvironmentView, EventBody, ExportAad, ExportSummary, FileMetaView, ItemBody, ItemView,
    LabelBody, LabelView, NoteBody, NoteMetaView, NoteView, ProjectBody, ProjectView, RecordAad,
    RecordPayload, RecordType, RecoveryStatus, SecretBody, SecretMeta, SecwetExportEnvelope,
    SecwetSnapshot, SecwetStatus, SnapshotEnvironment, SnapshotFile, SnapshotItem, SnapshotLabel,
    SnapshotNote, SnapshotSecret, SnapshotSetting, SnapshotSpace, SpaceBody, SpaceView,
};
use crate::sync;
use sha2::Digest;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;
use uuid::Uuid;
use zeroize::Zeroize;

/// Environment variables for an item plus the ids of the secrets they came from.
pub type EnvWithIds = (Vec<(String, SecretString)>, Vec<Uuid>);

static ACTIVE_SESSIONS: LazyLock<Mutex<HashSet<Uuid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn same_name_case_insensitive(a: &str, b: &str) -> bool {
    a.trim().to_lowercase() == b.trim().to_lowercase()
}

#[derive(serde::Deserialize)]
struct PreSpaceLabelBody {
    name: String,
    position: u32,
    icon: Option<String>,
}

fn deserialize_label_body(bytes: &[u8]) -> Result<LabelBody> {
    postcard::from_bytes::<LabelBody>(bytes)
        .or_else(|_| {
            postcard::from_bytes::<PreSpaceLabelBody>(bytes).map(|l| LabelBody {
                name: l.name,
                position: l.position,
                icon: l.icon,
                space_id: None,
            })
        })
        .map_err(|_| Error::Storage)
}

pub(crate) fn seal_device_name(k_rec: &[u8; 32], device_id: &str, device_name: &str) -> Result<Vec<u8>> {
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

pub(crate) fn unseal_device_name(k_rec: &[u8; 32], device_id: &str, blob: &[u8]) -> Result<String> {
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
/// Checks `<data_dir>/vaults/<secwet_id>/vault.sqlite3` and `<data_dir>/vault.sqlite3`.
pub(crate) fn find_secwet_db_pub(data_dir: &Path) -> Option<(PathBuf, Uuid)> {
    find_secwet_db(data_dir)
}

pub(crate) fn release_session(id: &Uuid) {
    if let Ok(mut g) = ACTIVE_SESSIONS.lock() {
        g.remove(id);
    }
}

pub(crate) fn deserialize_label_body_pub(bytes: &[u8]) -> Result<LabelBody> {
    deserialize_label_body(bytes)
}

/// Platform shown for a device whose stored name carries none: the local
/// device on the host this code runs on.
fn local_platform_label() -> &'static str {
    if cfg!(target_os = "ios") {
        "iOS"
    } else if cfg!(target_os = "android") {
        "Android"
    } else {
        "Desktop"
    }
}

/// Checks `input` against the stored `recovery_check` seal. `Ok(false)` for
/// a wrong, malformed or missing key; never says which.
fn check_recovery_key(conn: &Connection, secwet_id: &Uuid, input: &str) -> Result<bool> {
    let k_r = match crypto::derive_recovery_key_from_str(input, secwet_id) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };
    let check_b64 = match records::get_meta(conn, "recovery_check")? {
        Some(s) => s,
        None => return Ok(false),
    };
    let blob = match data_encoding::BASE64.decode(check_b64.as_bytes()) {
        Ok(b) => b,
        Err(_) => return Ok(false),
    };
    let check_aad = match postcard::to_stdvec(&("secwet-recovery-check", *secwet_id)) {
        Ok(a) => a,
        Err(_) => return Ok(false),
    };
    match crypto::open_raw(&k_r, &check_aad, &blob) {
        Ok(pt) => Ok(pt == b"secwet-recovery-check"),
        Err(_) => Ok(false),
    }
}

fn find_secwet_db(data_dir: &Path) -> Option<(PathBuf, Uuid)> {
    let direct_db = data_dir.join("secwet.sqlite3");
    if direct_db.is_file() {
        if let Ok(conn) = open_connection(&direct_db) {
            if let Ok(Some(vid_str)) = get_meta(&conn, "secwet_id") {
                if let Ok(vid) = Uuid::parse_str(&vid_str) {
                    return Some((direct_db, vid));
                }
            }
        }
    }

    let secwet_dir = data_dir.join("secwet");
    if secwet_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&secwet_dir) {
            for entry in entries.flatten() {
                let db_path = entry.path().join("secwet.sqlite3");
                if db_path.is_file() {
                    if let Ok(conn) = open_connection(&db_path) {
                        if let Ok(Some(vid_str)) = get_meta(&conn, "secwet_id") {
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
    secwet_id: &Uuid,
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
            secwet_id.as_bytes(),
            l_row.id.as_bytes(),
            RecordType::Label,
            epoch,
        );
        if let Ok(bytes) = open_record(k_rec, &aad, &l_row.name_blob) {
            if let Ok(body) = deserialize_label_body(&bytes) {
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
                secwet_id.as_bytes(),
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
                RecordAad::from_raw_type(secwet_id.as_bytes(), id.as_bytes(), 3, row_epoch);
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
                secwet_id.as_bytes(),
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
                RecordAad::from_raw_type(secwet_id.as_bytes(), id.as_bytes(), 2, row_epoch);
            let plaintext = open_record(k_rec, &old_aad, &blob)?;
            let env_body: EnvironmentBody =
                postcard::from_bytes(&plaintext).map_err(|_| Error::Storage)?;

            let body_bytes = postcard::to_stdvec(&env_body).map_err(|_| Error::Storage)?;
            let new_aad = RecordAad::new(
                secwet_id.as_bytes(),
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
                RecordAad::from_raw_type(secwet_id.as_bytes(), id.as_bytes(), 1, row_epoch);
            let plaintext = open_record(k_rec, &old_aad, &blob)?;
            let p_body: ProjectBody =
                postcard::from_bytes(&plaintext).map_err(|_| Error::Storage)?;

            let item_body = ItemBody::new(target_label_id, &p_body.name, None, idx as u32);
            let body_bytes = postcard::to_stdvec(&item_body).map_err(|_| Error::Storage)?;
            let new_aad = RecordAad::new(
                secwet_id.as_bytes(),
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
pub struct Secwet {
    pub(crate) db: Connection,
    pub(crate) secwet_id: Uuid,
    pub(crate) device_id: String,
    pub(crate) key_epoch: u32,
    pub(crate) k_rec: SecretBox<[u8; 32]>,
    pub(crate) k_evt: SecretBox<[u8; 32]>,
    pub(crate) device_sign_key: ed25519_dalek::SigningKey,
    pub(crate) device_sign_pub: [u8; 32],
    pub(crate) device_enc_pub: [u8; 32],
    /// Every known master key epoch and every held branch bundle (F16, F19).
    pub(crate) keyring: crate::collab::Keyring,
    /// X25519 secret used to unwrap HPKE-wrapped keys sent to this device.
    pub(crate) enc_secret: SecretBox<[u8; 32]>,
    /// `Some` for a collaborator's store, which never holds the master key.
    pub(crate) member_id: Option<Uuid>,
    pub(crate) db_path: PathBuf,
    /// Branch scopes the relay reported on the last key refresh.
    pub(crate) last_scopes: Vec<secwet_proto::BranchScopeDto>,
    #[cfg(any(test, feature = "test-util"))]
    test_k_rec_witness: std::sync::Arc<std::sync::Mutex<[u8; 32]>>,
    #[cfg(any(test, feature = "test-util"))]
    test_k_evt_witness: std::sync::Arc<std::sync::Mutex<[u8; 32]>>,
}

impl std::fmt::Debug for Secwet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secwet")
            .field("secwet_id", &self.secwet_id)
            .field("device_id", &self.device_id)
            .field("key_epoch", &self.key_epoch)
            .field("k_rec", &"[REDACTED]")
            .field("k_evt", &"[REDACTED]")
            .finish()
    }
}

impl Secwet {
    // ========================================================================
    // Lifecycle (F1, F2)
    // ========================================================================

    /// Inspects the data directory for an existing vault database and status.
    pub fn status(data_dir: &Path) -> Result<SecwetStatus> {
        if !data_dir.exists() {
            return Ok(SecwetStatus::Uninitialized);
        }

        if let Some((_, secwet_id)) = find_secwet_db(data_dir) {
            let active = {
                let guard = ACTIVE_SESSIONS.lock().unwrap();
                guard.contains(&secwet_id)
            };
            if active {
                Ok(SecwetStatus::Unlocked { secwet_id })
            } else {
                Ok(SecwetStatus::Locked { secwet_id })
            }
        } else {
            // Check if database files exist but are unreadable/corrupted
            if data_dir.join("secwet.sqlite3").is_file() {
                return Err(Error::Storage);
            }
            if let Ok(entries) = std::fs::read_dir(data_dir.join("secwet")) {
                for entry in entries.flatten() {
                    if entry.path().join("secwet.sqlite3").is_file() {
                        return Err(Error::Storage);
                    }
                }
            }
            Ok(SecwetStatus::Uninitialized)
        }
    }

    /// Creates a new vault.
    ///
    /// Invariants:
    /// - KeyStore writes for device keys and epoch 1 vault key occur BEFORE database creation.
    /// - Database is created and schema migrations 0001 and 0002 are executed.
    /// - Default "Projects" label seeded in `labels` table.
    /// - `meta.flexible_org_migrated = '1'`.
    pub fn create(data_dir: &Path, device_name: &str, keystore: &dyn KeyStore) -> Result<Secwet> {
        if find_secwet_db(data_dir).is_some() {
            return Err(Error::AlreadyInitialized);
        }

        let trimmed_name = device_name.trim();
        let dev_name = if trimmed_name.is_empty() {
            "default-device"
        } else {
            trimmed_name
        };

        let secwet_id = Uuid::new_v4();

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
        keystore.set(&format!("secwet/{secwet_id}/device-sign"), &sign_priv)?;
        keystore.set(&format!("secwet/{secwet_id}/device-enc"), &enc_priv)?;
        crate::collab::store_master_key(keystore, &secwet_id, 1, &k_v)?;

        // 3. Derive runtime symmetric keys
        let (k_rec_bytes, k_evt_bytes) = derive_keys(&k_v, &secwet_id);
        k_v.zeroize();

        let sign_priv_opt = keystore.get(&format!("secwet/{secwet_id}/device-sign"))?;
        let sign_priv_vec = sign_priv_opt.ok_or(Error::KeyStore)?;
        if sign_priv_vec.len() != 32 {
            return Err(Error::KeyStore);
        }
        let mut sign_priv = [0u8; 32];
        sign_priv.copy_from_slice(sign_priv_vec.as_slice());
        let device_sign_key = ed25519_dalek::SigningKey::from_bytes(&sign_priv);
        let device_sign_pub = device_sign_key.verifying_key().to_bytes();

        let enc_priv_opt = keystore.get(&format!("secwet/{secwet_id}/device-enc"))?;
        let enc_priv_vec = enc_priv_opt.ok_or(Error::KeyStore)?;
        if enc_priv_vec.len() != 32 {
            return Err(Error::KeyStore);
        }
        let mut enc_priv = [0u8; 32];
        enc_priv.copy_from_slice(enc_priv_vec.as_slice());
        let enc_secret = x25519_dalek::StaticSecret::from(enc_priv);
        let device_enc_pub = x25519_dalek::PublicKey::from(&enc_secret).to_bytes();

        // 4. Create database on disk
        let db_dir = data_dir.join("secwet").join(secwet_id.to_string());
        std::fs::create_dir_all(&db_dir).map_err(|_| Error::Storage)?;
        let db_path = db_dir.join("secwet.sqlite3");
        let conn = open_and_migrate(&db_path)?;

        let now_ms = current_time_ms();
        set_meta(&conn, "schema_version", "2")?;
        set_meta(&conn, "secwet_id", &secwet_id.to_string())?;
        set_meta(&conn, "created_at", &now_ms.to_string())?;
        set_meta(&conn, "current_key_epoch", "1")?;
        set_meta(&conn, "device_id", &device_id)?;
        set_meta(&conn, "plan", "free")?;
        set_meta(&conn, "relay_url", "")?;
        set_meta(&conn, "flexible_org_migrated", "1")?;

        // 5. Seed default "Personal" space in spaces table
        let default_space_id = Uuid::now_v7();
        let space_body = SpaceBody::new("Personal", 0, Some("user".to_string()), true);
        let space_bytes = postcard::to_stdvec(&space_body).map_err(|_| Error::Storage)?;
        let space_aad = RecordAad::new(
            secwet_id.as_bytes(),
            default_space_id.as_bytes(),
            RecordType::Label,
            1,
        );
        let space_blob = seal_record(&k_rec_bytes, &space_aad, &space_bytes)?;
        let space_row = SpaceRow::new_active(default_space_id, space_blob, 0, now_ms);
        insert_space(&conn, &space_row)?;

        // 6. Seed default "Projects" label under Personal space in labels table
        let default_label_id = Uuid::now_v7();
        let mut label_body = LabelBody::new("Projects", 0, Some("folder".to_string()));
        label_body.space_id = Some(default_space_id);
        let label_bytes = postcard::to_stdvec(&label_body).map_err(|_| Error::Storage)?;
        let label_aad = RecordAad::new(
            secwet_id.as_bytes(),
            default_label_id.as_bytes(),
            RecordType::Label,
            1,
        );
        let label_blob = seal_record(&k_rec_bytes, &label_aad, &label_bytes)?;
        let label_row = LabelRow::new_active_in_space(
            default_label_id,
            Some(default_space_id),
            label_blob,
            0,
            now_ms,
        );
        insert_label(&conn, &label_row)?;

        // 6. Seal device name and insert into devices table
        let name_blob = seal_device_name(&k_rec_bytes, &device_id, dev_name)?;
        conn.execute(
            "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, trust)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5, 'self')",
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
        ACTIVE_SESSIONS.lock().unwrap().insert(secwet_id);

        let k_rec = SecretBox::new(Box::new(*k_rec_bytes));
        let k_evt = SecretBox::new(Box::new(*k_evt_bytes));

        #[cfg(any(test, feature = "test-util"))]
        let test_k_rec_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_rec_bytes));
        #[cfg(any(test, feature = "test-util"))]
        let test_k_evt_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_evt_bytes));

        Ok(Secwet {
            db: conn,
            secwet_id,
            device_id,
            key_epoch: 1,
            k_rec,
            k_evt,
            device_sign_key,
            device_sign_pub,
            device_enc_pub,
            keyring: crate::collab::Keyring::with_epoch(&secwet_id, 1, &k_rec_bytes, &k_evt_bytes),
            enc_secret: SecretBox::new(Box::new(enc_priv)),
            member_id: None,
            db_path: db_path.clone(),
            last_scopes: Vec::new(),
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
    pub fn unlock(data_dir: &Path, keystore: &dyn KeyStore) -> Result<Secwet> {
        let (db_path, secwet_id) = find_secwet_db(data_dir).ok_or(Error::NotInitialized)?;
        let mut conn = open_connection(&db_path)?;

        // Run DDL migrations up to version 2
        records::run_migrations(&mut conn)?;

        let epoch_str = get_meta(&conn, "current_key_epoch")?.unwrap_or_else(|| "1".to_string());
        let epoch: u32 = epoch_str.parse().unwrap_or(1);
        let device_id = get_meta(&conn, "device_id")?.ok_or(Error::Storage)?;

        let key_opt = crate::collab::load_master_key(keystore, &secwet_id, epoch)?;
        let key_vec = key_opt.ok_or(Error::KeyStore)?;
        if key_vec.len() != 32 {
            return Err(Error::KeyStore);
        }
        let mut k_v = [0u8; 32];
        k_v.copy_from_slice(key_vec.as_slice());

        let (k_rec_bytes, k_evt_bytes) = derive_keys(&k_v, &secwet_id);
        k_v.zeroize();

        // Stores created before device identities existed have no device keys.
        // A store never registered with a relay gets fresh ones; a relay
        // registered store must keep its identity, so it fails instead.
        let plan_now = get_meta(&conn, "plan")?.unwrap_or_else(|| "free".into());
        for (entry, gen) in [("device-sign", 0u8), ("device-enc", 1u8)] {
            let name = format!("secwet/{secwet_id}/{entry}");
            if keystore.get(&name)?.is_none() && plan_now != "pro" && plan_now != "paused" {
                let fresh: [u8; 32] = if gen == 0 {
                    ed25519_dalek::SigningKey::generate(&mut OsRng).to_bytes()
                } else {
                    x25519_dalek::StaticSecret::random_from_rng(&mut OsRng).to_bytes()
                };
                keystore.set(&name, &fresh)?;
            }
        }

        let sign_priv_opt = keystore.get(&format!("secwet/{secwet_id}/device-sign"))?;
        let sign_priv_vec = sign_priv_opt.ok_or(Error::KeyStore)?;
        if sign_priv_vec.len() != 32 {
            return Err(Error::KeyStore);
        }
        let mut sign_priv = [0u8; 32];
        sign_priv.copy_from_slice(sign_priv_vec.as_slice());
        let device_sign_key = ed25519_dalek::SigningKey::from_bytes(&sign_priv);
        let device_sign_pub = device_sign_key.verifying_key().to_bytes();

        let enc_priv_opt = keystore.get(&format!("secwet/{secwet_id}/device-enc"))?;
        let enc_priv_vec = enc_priv_opt.ok_or(Error::KeyStore)?;
        if enc_priv_vec.len() != 32 {
            return Err(Error::KeyStore);
        }
        let mut enc_priv = [0u8; 32];
        enc_priv.copy_from_slice(enc_priv_vec.as_slice());
        let enc_secret = x25519_dalek::StaticSecret::from(enc_priv);
        let device_enc_pub = x25519_dalek::PublicKey::from(&enc_secret).to_bytes();

        let keyring = Self::load_keyring(keystore, &secwet_id, epoch)?;
        let member_id = get_meta(&conn, "member_id")?.and_then(|m| Uuid::parse_str(&m).ok());

        // Check Phase 2 non-destructive storage migration
        let flexible_migrated = get_meta(&conn, "flexible_org_migrated")?
            .as_deref()
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false);

        if !flexible_migrated {
            migrate_phase2_flexible_org(&mut conn, &secwet_id, epoch, &k_rec_bytes, &device_id)?;
        }

        ACTIVE_SESSIONS.lock().unwrap().insert(secwet_id);

        let k_rec = SecretBox::new(Box::new(*k_rec_bytes));
        let k_evt = SecretBox::new(Box::new(*k_evt_bytes));

        #[cfg(any(test, feature = "test-util"))]
        let test_k_rec_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_rec_bytes));
        #[cfg(any(test, feature = "test-util"))]
        let test_k_evt_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_evt_bytes));

        let mut secwet = Secwet {
            db: conn,
            secwet_id,
            device_id,
            key_epoch: epoch,
            k_rec,
            k_evt,
            device_sign_key,
            device_sign_pub,
            device_enc_pub,
            keyring,
            enc_secret: SecretBox::new(Box::new(enc_priv)),
            member_id,
            db_path: db_path.clone(),
            last_scopes: Vec::new(),
            #[cfg(any(test, feature = "test-util"))]
            test_k_rec_witness,
            #[cfg(any(test, feature = "test-util"))]
            test_k_evt_witness,
        };

        secwet.load_branch_bundles(keystore)?;
        // Finish a re-seal interrupted by a crash after a rotation.
        let stale: i64 = secwet
            .db
            .query_row(
                "SELECT COUNT(*) FROM records WHERE key_epoch < ?1 AND blob IS NOT NULL",
                params![secwet.key_epoch as i64],
                |r| r.get(0),
            )
            .map_err(|_| Error::Storage)?;
        if stale > 0 {
            secwet.reseal_to_current()?;
        }

        // Ensure default Personal space exists and retrofits any unassigned labels
        secwet.ensure_default_personal_space()?;

        Ok(secwet)
    }

    /// Locks the vault, consuming `self` and zeroizing all in-memory keys.
    pub fn lock(mut self) {
        self.zeroize_all_keys();
        ACTIVE_SESSIONS.lock().unwrap().remove(&self.secwet_id);
    }

    /// Zeroizes every key held in memory: current keys, every epoch, every
    /// branch bundle and the HPKE secret.
    pub(crate) fn zeroize_all_keys(&mut self) {
        self.zeroize_keys_internal();
        self.keyring.clear();
        self.enc_secret.expose_secret_mut().zeroize();
    }

    /// Switches sealing to another epoch's keys (after a rotation).
    pub(crate) fn set_current_keys(&mut self, epoch: u32, rec: [u8; 32], evt: [u8; 32]) {
        self.key_epoch = epoch;
        *self.k_rec.expose_secret_mut() = rec;
        *self.k_evt.expose_secret_mut() = evt;
        #[cfg(any(test, feature = "test-util"))]
        {
            if let Ok(mut w) = self.test_k_rec_witness.lock() {
                *w = rec;
            }
            if let Ok(mut w) = self.test_k_evt_witness.lock() {
                *w = evt;
            }
        }
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

    pub fn secwet_id(&self) -> Uuid {
        self.secwet_id
    }

    pub fn device_id(&self) -> DeviceId {
        DeviceId(self.device_id.clone())
    }

    pub fn key_epoch(&self) -> u32 {
        self.key_epoch
    }

    pub fn current_status(&self) -> SecwetStatus {
        SecwetStatus::Unlocked {
            secwet_id: self.secwet_id,
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
    // Spaces CRUD & Default Space Management
    // ========================================================================

    /// Guarantees that a default "Personal" space exists and retrofits any
    /// legacy or unassigned labels (`space_id IS NULL`) to belong to it.
    pub fn ensure_default_personal_space(&mut self) -> Result<SpaceView> {
        let space_rows = query_active_spaces(&self.db)?;
        let mut personal_space: Option<SpaceView> = None;

        for row in &space_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Label,
                self.key_epoch,
            );
            if let Ok(bytes) = self.open_rec(&aad, &row.name_blob) {
                if let Ok(body) = postcard::from_bytes::<SpaceBody>(&bytes) {
                    if body.is_default || body.name.trim().eq_ignore_ascii_case("personal") {
                        let groups_count = count_active_labels_for_space(&self.db, row.id)?;
                        personal_space = Some(SpaceView::new(
                            row.id,
                            body.name,
                            row.position,
                            body.icon,
                            body.is_default,
                            groups_count,
                        ));
                        break;
                    }
                }
            }
        }

        let personal = match personal_space {
            Some(space) => space,
            None => {
                let now_ms = current_time_ms();
                if space_rows.is_empty() {
                    let space_id = Uuid::now_v7();
                    let space_body = SpaceBody::new("Personal", 0, Some("user".to_string()), true);
                    let body_bytes = postcard::to_stdvec(&space_body).map_err(|_| Error::Storage)?;
                    let aad = RecordAad::new(
                        self.secwet_id.as_bytes(),
                        space_id.as_bytes(),
                        RecordType::Label,
                        self.key_epoch,
                    );
                    let blob = seal_record(self.k_rec.expose_secret(), &aad, &body_bytes)?;
                    let row = SpaceRow::new_active(space_id, blob, 0, now_ms);
                    insert_space(&self.db, &row)?;
                    SpaceView::new(space_id, "Personal", 0, Some("user".to_string()), true, 0)
                } else {
                    let position = next_space_position(&self.db)?;
                    let space_id = Uuid::now_v7();
                    let space_body = SpaceBody::new("Personal", position, Some("user".to_string()), true);
                    let body_bytes = postcard::to_stdvec(&space_body).map_err(|_| Error::Storage)?;
                    let aad = RecordAad::new(
                        self.secwet_id.as_bytes(),
                        space_id.as_bytes(),
                        RecordType::Label,
                        self.key_epoch,
                    );
                    let blob = seal_record(self.k_rec.expose_secret(), &aad, &body_bytes)?;
                    let row = SpaceRow::new_active(space_id, blob, position, now_ms);
                    insert_space(&self.db, &row)?;
                    SpaceView::new(space_id, "Personal", position, Some("user".to_string()), true, 0)
                }
            }
        };

        // Retrofit any unassigned labels in the SQLite table
        let now_ms = current_time_ms();
        let _ = update_null_labels_space(&self.db, personal.id, now_ms);

        // Also ensure encrypted LabelBody contains the space_id
        let label_rows = query_active_labels(&self.db)?;
        for l_row in label_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                l_row.id.as_bytes(),
                RecordType::Label,
                self.key_epoch,
            );
            if let Ok(bytes) = self.open_rec(&aad, &l_row.name_blob) {
                if let Ok(mut body) = deserialize_label_body(&bytes) {
                    if body.space_id.is_none() {
                        body.space_id = Some(personal.id);
                        if let Ok(new_bytes) = postcard::to_stdvec(&body) {
                            if let Ok(new_blob) = seal_record(self.k_rec.expose_secret(), &aad, &new_bytes) {
                                let _ = update_label_name(&self.db, l_row.id, &new_blob, now_ms);
                                let _ = update_label_space(&self.db, l_row.id, Some(personal.id), now_ms);
                            }
                        }
                    }
                }
            }
        }

        let groups_count = count_active_labels_for_space(&self.db, personal.id)?;
        Ok(SpaceView::new(
            personal.id,
            personal.name,
            personal.position,
            personal.icon,
            personal.is_default,
            groups_count,
        ))
    }

    /// Lists all active spaces ordered by position ASC.
    pub fn list_spaces(&self) -> Result<Vec<SpaceView>> {
        let space_rows = query_active_spaces(&self.db)?;
        let mut views = Vec::with_capacity(space_rows.len());

        for row in space_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Label,
                self.key_epoch,
            );
            let bytes = self.open_rec(&aad, &row.name_blob)?;
            let body: SpaceBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            let groups_count = count_active_labels_for_space(&self.db, row.id)?;

            views.push(SpaceView::new(
                row.id,
                body.name,
                row.position,
                body.icon,
                body.is_default,
                groups_count,
            ));
        }

        views.sort_by_key(|a| a.position);
        Ok(views)
    }

    /// Fetches a single space by its UUID.
    pub fn get_space(&self, id: Uuid) -> Result<SpaceView> {
        let row = get_space(&self.db, id)?.ok_or(Error::NotFound)?;
        if row.deleted {
            return Err(Error::NotFound);
        }
        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let bytes = self.open_rec(&aad, &row.name_blob)?;
        let body: SpaceBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
        let groups_count = count_active_labels_for_space(&self.db, row.id)?;
        Ok(SpaceView::new(
            row.id,
            body.name,
            row.position,
            body.icon,
            body.is_default,
            groups_count,
        ))
    }

    /// Creates a new organizational space.
    pub fn create_space(&mut self, name: &str, icon: Option<String>) -> Result<SpaceView> {
        self.ensure_writable()?;
        let clean_name = secwet_proto::validate_space_name(name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter a space name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { max, .. } => Error::Invalid {
                field: "name",
                message: format!("Keep the name under {max} characters."),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid space name.".to_string(),
            },
        })?;

        let existing = self.list_spaces()?;
        if existing
            .iter()
            .any(|s| same_name_case_insensitive(&s.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let position = next_space_position(&self.db)?;
        let space_id = Uuid::now_v7();
        let now_ms = current_time_ms();

        let body = SpaceBody::new(&clean_name, position, icon.clone(), false);
        let bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;
        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            space_id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &bytes)?;

        let row = SpaceRow::new_active(space_id, blob, position, now_ms);
        insert_space(&self.db, &row)?;

        Ok(SpaceView::new(
            space_id,
            clean_name,
            position,
            icon,
            false,
            0,
        ))
    }

    /// Renames an active space while preserving its default status and position.
    pub fn rename_space(&mut self, id: Uuid, name: &str, icon: Option<String>) -> Result<SpaceView> {
        self.guard_write(crate::collab::WriteTarget::Space(Some(id)))?;
        let space_row = get_space(&self.db, id)?.ok_or(Error::NotFound)?;
        if space_row.deleted {
            return Err(Error::NotFound);
        }

        let clean_name = secwet_proto::validate_space_name(name).map_err(|err| match err {
            secwet_proto::ValidationError::EmptyField(_) => Error::Invalid {
                field: "name",
                message: "Enter a space name.".to_string(),
            },
            secwet_proto::ValidationError::TooLong { max, .. } => Error::Invalid {
                field: "name",
                message: format!("Keep the name under {max} characters."),
            },
            _ => Error::Invalid {
                field: "name",
                message: "Enter a valid space name.".to_string(),
            },
        })?;

        let existing = self.list_spaces()?;
        if existing
            .iter()
            .any(|s| s.id != id && same_name_case_insensitive(&s.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let bytes = self.open_rec(&aad, &space_row.name_blob)?;
        let prev_body: SpaceBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        let updated_body = SpaceBody::new(&clean_name, space_row.position, icon.clone(), prev_body.is_default);
        let new_bytes = postcard::to_stdvec(&updated_body).map_err(|_| Error::Storage)?;
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &new_bytes)?;

        update_space_name(&self.db, id, &blob, current_time_ms())?;

        let groups_count = count_active_labels_for_space(&self.db, id)?;
        Ok(SpaceView::new(
            id,
            clean_name,
            space_row.position,
            icon,
            prev_body.is_default,
            groups_count,
        ))
    }

    /// Deletes a space, reassigning any active groups to the default Personal space.
    /// The default Personal space cannot be deleted.
    pub fn delete_space(&mut self, id: Uuid) -> Result<()> {
        self.guard_write(crate::collab::WriteTarget::Space(Some(id)))?;
        let space_row = get_space(&self.db, id)?.ok_or(Error::NotFound)?;
        if space_row.deleted {
            return Err(Error::NotFound);
        }

        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let bytes = self.open_rec(&aad, &space_row.name_blob)?;
        let body: SpaceBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        if body.is_default || body.name.trim().eq_ignore_ascii_case("personal") {
            return Err(Error::Invalid {
                field: "space",
                message: "Cannot delete the default Personal space.".to_string(),
            });
        }

        // Locate default Personal space to safely reassign active groups
        let default_space = self.ensure_default_personal_space()?;
        let now_ms = current_time_ms();

        // Reassign all active groups from this space to default personal space
        let _ = reassign_labels_to_space(&self.db, id, default_space.id, now_ms)?;

        // Update encrypted LabelBody for each reassigned group
        let reassigned_labels = query_active_labels_by_space(&self.db, default_space.id)?;
        for l in reassigned_labels {
            let l_aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                l.id.as_bytes(),
                RecordType::Label,
                self.key_epoch,
            );
            if let Ok(l_bytes) = self.open_rec(&l_aad, &l.name_blob) {
                if let Ok(mut l_body) = deserialize_label_body(&l_bytes) {
                    if l_body.space_id != Some(default_space.id) {
                        l_body.space_id = Some(default_space.id);
                        if let Ok(new_l_bytes) = postcard::to_stdvec(&l_body) {
                            if let Ok(new_blob) = seal_record(self.k_rec.expose_secret(), &l_aad, &new_l_bytes) {
                                let _ = update_label_name(&self.db, l.id, &new_blob, now_ms);
                            }
                        }
                    }
                }
            }
        }

        soft_delete_space(&self.db, id, now_ms)?;
        Ok(())
    }

    /// Reorders active spaces according to the provided ordered slice of UUIDs.
    pub fn reorder_spaces(&mut self, ids: &[Uuid]) -> Result<()> {
        self.ensure_writable()?;
        for id in ids {
            let space = get_space(&self.db, *id)?.ok_or(Error::NotFound)?;
            if space.deleted {
                return Err(Error::NotFound);
            }
        }
        records::reorder_spaces(&mut self.db, ids, current_time_ms())
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
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Label,
                self.key_epoch,
            );
            let bytes = self.open_rec(&aad, &row.name_blob)?;
            let body: LabelBody = deserialize_label_body(&bytes)?;

            let items_count = count_active_items_for_label(&self.db, row.id)?;

            views.push(LabelView::with_space(
                row.id,
                row.space_id.or(body.space_id),
                body.name,
                row.position,
                body.icon,
                items_count,
            ));
        }

        Ok(views)
    }

    /// Lists active organizational labels belonging to a specific space.
    pub fn list_labels_by_space(&self, space_id: Uuid) -> Result<Vec<LabelView>> {
        let all = self.list_labels()?;
        Ok(all.into_iter().filter(|l| l.space_id == Some(space_id)).collect())
    }

    /// Creates a new organizational label in a specific space (or Personal space if None).
    pub fn create_label_in_space(
        &mut self,
        name: &str,
        icon: Option<String>,
        space_id: Option<Uuid>,
    ) -> Result<LabelView> {
        self.guard_write(crate::collab::WriteTarget::Group { space: space_id })?;
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

        let target_space_id = match space_id {
            Some(id) => {
                let _ = self.get_space(id)?;
                id
            }
            None => {
                let personal = self.ensure_default_personal_space()?;
                personal.id
            }
        };

        // Case-insensitive uniqueness check within the target space
        let existing = self.list_labels()?;
        if existing
            .iter()
            .any(|l| l.space_id == Some(target_space_id) && same_name_case_insensitive(&l.name, &clean_name))
        {
            return Err(Error::Duplicate { field: "name" });
        }

        let position = next_label_position(&self.db)?;
        let label_id = Uuid::now_v7();
        let now_ms = current_time_ms();

        let mut body = LabelBody::new(&clean_name, position, icon.clone());
        body.space_id = Some(target_space_id);
        let bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;
        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            label_id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &bytes)?;

        let row = LabelRow::new_active_in_space(label_id, Some(target_space_id), blob, position, now_ms);
        insert_label(&self.db, &row)?;
        let lamport = next_lamport(&self.db)?;
        let _ = self.enqueue_mutation_event(&self.db, label_id, RecordType::Label, lamport, Some(&RecordPayload::Label(body)));

        Ok(LabelView::with_space(
            label_id,
            Some(target_space_id),
            clean_name,
            position,
            icon,
            0,
        ))
    }

    /// Creates a new organizational label in the default space.
    pub fn create_label(&mut self, name: &str, icon: Option<String>) -> Result<LabelView> {
        self.create_label_in_space(name, icon, None)
    }

    /// Moves an active label to another space.
    pub fn move_label_to_space(&mut self, label_id: Uuid, new_space_id: Uuid) -> Result<()> {
        self.guard_write(crate::collab::WriteTarget::Group { space: records::get_label(&self.db, label_id)?.and_then(|l| l.space_id) })?;
        self.guard_write(crate::collab::WriteTarget::Group { space: Some(new_space_id) })?;
        let _ = self.get_space(new_space_id)?;

        let label_row = get_label(&self.db, label_id)?.ok_or(Error::NotFound)?;
        if label_row.deleted {
            return Err(Error::NotFound);
        }

        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            label_id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let bytes = self.open_rec(&aad, &label_row.name_blob)?;
        let mut body: LabelBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        body.space_id = Some(new_space_id);
        let new_bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &new_bytes)?;

        let now_ms = current_time_ms();
        update_label_name(&self.db, label_id, &blob, now_ms)?;
        update_label_space(&self.db, label_id, Some(new_space_id), now_ms)?;
        Ok(())
    }

    /// Renames an active label while preserving its icon and position.
    pub fn rename_label(&mut self, id: Uuid, name: &str) -> Result<()> {
        self.guard_write(crate::collab::WriteTarget::Group { space: records::get_label(&self.db, id)?.and_then(|l| l.space_id) })?;
        let label_row = get_label(&self.db, id)?.ok_or(Error::NotFound)?;
        if label_row.deleted {
            return Err(Error::NotFound);
        }

        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let bytes = self.open_rec(&aad, &label_row.name_blob)?;
        let body: LabelBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        self.update_label(id, name, body.icon)
    }

    /// Updates both the name and icon of an active label.
    pub fn update_label(&mut self, id: Uuid, name: &str, icon: Option<String>) -> Result<()> {
        self.guard_write(crate::collab::WriteTarget::Group { space: records::get_label(&self.db, id)?.and_then(|l| l.space_id) })?;
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

        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Label,
            self.key_epoch,
        );
        let bytes = self.open_rec(&aad, &label_row.name_blob)?;
        let prev_body: LabelBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        let mut body = LabelBody::new(&clean_name, label_row.position, icon);
        body.space_id = label_row.space_id.or(prev_body.space_id);
        let bytes = postcard::to_stdvec(&body).map_err(|_| Error::Storage)?;
        let blob = seal_record(self.k_rec.expose_secret(), &aad, &bytes)?;

        update_label_name(&self.db, id, &blob, current_time_ms())?;
        let lamport = next_lamport(&self.db)?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Label, lamport, Some(&RecordPayload::Label(body)));
        Ok(())
    }

    /// Reorders active labels according to the provided ordered slice of UUIDs.
    pub fn reorder_labels(&mut self, ids: &[Uuid]) -> Result<()> {
        self.ensure_writable()?;
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
        self.guard_write(crate::collab::WriteTarget::Group { space: records::get_label(&self.db, id)?.and_then(|l| l.space_id) })?;
        let lamport = next_lamport(&self.db)?;
        cascade_delete_label(&mut self.db, id, &self.device_id, current_time_ms())?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Label, lamport, None);
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
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Item,
                row.key_epoch,
            );
            let bytes = self.open_rec(&aad, blob)?;
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
        self.guard_write(crate::collab::WriteTarget::Item { group: label_id })?;
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
            self.secwet_id.as_bytes(),
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
        let _ = self.enqueue_mutation_event(&self.db, item_id, RecordType::Item, lamport, Some(&RecordPayload::Item(body)));

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
        self.guard_write(crate::collab::WriteTarget::Environment { item: id })?;
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
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Item,
            row.key_epoch,
        );
        let bytes = self.open_rec(&aad, blob)?;
        let cur_body: ItemBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        let new_body = ItemBody::new(label_id, &clean_name, description, cur_body.position);
        let new_bytes = postcard::to_stdvec(&new_body).map_err(|_| Error::Storage)?;
        let new_blob = seal_record(self.k_rec.expose_secret(), &aad, &new_bytes)?;

        let new_lamport = update_record_blob(&self.db, id, &new_blob, &self.device_id, current_time_ms())?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Item, new_lamport, Some(&RecordPayload::Item(new_body)));
        Ok(())
    }

    /// Cascades deletion of an item and all its environments, secrets, files, and notes.
    pub fn delete_item(&mut self, id: Uuid) -> Result<()> {
        self.guard_write(crate::collab::WriteTarget::Environment { item: id })?;
        let lamport = next_lamport(&self.db)?;
        cascade_delete_item(&mut self.db, id, &self.device_id, current_time_ms())?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Item, lamport, None);
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
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Environment,
                row.key_epoch,
            );
            let bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        row.id.as_bytes(),
                        2,
                        row.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
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
        self.guard_write(crate::collab::WriteTarget::Environment { item: item_id })?;
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
            self.secwet_id.as_bytes(),
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
        let _ = self.enqueue_mutation_event(&self.db, env_id, RecordType::Environment, lamport, Some(&RecordPayload::Environment(body)));

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
        self.guard_write(crate::collab::WriteTarget::Environment { item: get_record(&self.db, id)?.and_then(|r| r.parent_id).ok_or(Error::NotFound)? })?;
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
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Environment,
            row.key_epoch,
        );
        let bytes = match self.open_rec(&aad, blob) {
            Ok(b) => b,
            Err(_) => {
                let leg_aad = RecordAad::from_raw_type(
                    self.secwet_id.as_bytes(),
                    id.as_bytes(),
                    2,
                    row.key_epoch,
                );
                self.open_rec(&leg_aad, blob)?
            }
        };
        let cur_body: EnvironmentBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        let new_body = EnvironmentBody::new(item_id, &clean_name, cur_body.position);
        let new_bytes = postcard::to_stdvec(&new_body).map_err(|_| Error::Storage)?;
        let new_aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Environment,
            row.key_epoch,
        );
        let new_blob = seal_record(self.k_rec.expose_secret(), &new_aad, &new_bytes)?;

        let new_lamport = update_record_blob(&self.db, id, &new_blob, &self.device_id, current_time_ms())?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Environment, new_lamport, Some(&RecordPayload::Environment(new_body)));
        Ok(())
    }

    /// Reorders active environments belonging to an item.
    pub fn reorder_environments(&mut self, item_id: Uuid, ids: &[Uuid]) -> Result<()> {
        self.guard_write(crate::collab::WriteTarget::Environment { item: item_id })?;
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
                self.secwet_id.as_bytes(),
                id.as_bytes(),
                RecordType::Environment,
                row.key_epoch,
            );
            let bytes = match crate::collab::open_rec_with(&self.keyring, &aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        id.as_bytes(),
                        2,
                        row.key_epoch,
                    );
                    crate::collab::open_rec_with(&self.keyring, &leg_aad, blob)?
                }
            };
            let body: EnvironmentBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

            let new_body = EnvironmentBody::new(item_id, body.name, pos as u32);
            let new_bytes = postcard::to_stdvec(&new_body).map_err(|_| Error::Storage)?;
            let new_aad = RecordAad::new(
                self.secwet_id.as_bytes(),
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
        let lamport = next_lamport(&self.db)?;
        cascade_delete_environment(&mut self.db, id, &self.device_id, current_time_ms())?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Environment, lamport, None);
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
        self.guard_write(crate::collab::WriteTarget::Environment { item: get_record(&self.db, id)?.and_then(|r| r.parent_id).ok_or(Error::NotFound)? })?;
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
                self.secwet_id.as_bytes(),
                s_row.id.as_bytes(),
                RecordType::Secret,
                s_row.key_epoch,
            );
            let s_bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        s_row.id.as_bytes(),
                        3,
                        s_row.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
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
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Secret,
            s_row.key_epoch,
        );
        let s_bytes = match self.open_rec(&aad, blob) {
            Ok(b) => b,
            Err(_) => {
                let leg_aad = RecordAad::from_raw_type(
                    self.secwet_id.as_bytes(),
                    id.as_bytes(),
                    3,
                    s_row.key_epoch,
                );
                self.open_rec(&leg_aad, blob)?
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
        self.guard_write(crate::collab::WriteTarget::Content { item: draft.item_id, env: draft.environment_id, delete: false })?;
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
                self.secwet_id.as_bytes(),
                sib.id.as_bytes(),
                RecordType::Secret,
                sib.key_epoch,
            );
            let bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        sib.id.as_bytes(),
                        3,
                        sib.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
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
            self.secwet_id.as_bytes(),
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
        if let Err(e) = self.enqueue_mutation_event(&self.db, secret_id, RecordType::Secret, lamport, Some(&RecordPayload::Secret(s_body))) {
            eprintln!("enqueue_mutation_event secret error: {:?}", e);
        }

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
        self.guard_write(crate::collab::WriteTarget::ContentRecord { id, delete: false })?;
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
                self.secwet_id.as_bytes(),
                sib.id.as_bytes(),
                RecordType::Secret,
                sib.key_epoch,
            );
            let bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        sib.id.as_bytes(),
                        3,
                        sib.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
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
            self.secwet_id.as_bytes(),
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

        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Secret, lamport, Some(&RecordPayload::Secret(s_body)));

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
        self.guard_write(crate::collab::WriteTarget::ContentRecord { id, delete: true })?;
        let existing = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if existing.deleted
            || (existing.record_type != RecordType::Secret
                && existing.record_type != RecordType::Environment/* legacy 3 */)
        {
            return Err(Error::NotFound);
        }
        let del_lamport = soft_delete_record(&self.db, id, &self.device_id, current_time_ms())?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Secret, del_lamport, None);
        Ok(())
    }

    /// Copies an existing secret to another container (item-level or another environment).
    pub fn copy_secret_to_environment(
        &mut self,
        id: Uuid,
        target_env: impl Into<Option<Uuid>>,
    ) -> Result<SecretMeta> {
        self.guard_write(crate::collab::WriteTarget::ContentRecord { id, delete: false })?;
        let s_row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if s_row.deleted
            || (s_row.record_type != RecordType::Secret
                && s_row.record_type != RecordType::Environment/* legacy 3 */)
        {
            return Err(Error::NotFound);
        }

        let blob = s_row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Secret,
            s_row.key_epoch,
        );
        let s_bytes = match self.open_rec(&aad, blob) {
            Ok(b) => b,
            Err(_) => {
                let leg_aad = RecordAad::from_raw_type(
                    self.secwet_id.as_bytes(),
                    id.as_bytes(),
                    3,
                    s_row.key_epoch,
                );
                self.open_rec(&leg_aad, blob)?
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
                self.secwet_id.as_bytes(),
                s_row.id.as_bytes(),
                RecordType::Secret,
                s_row.key_epoch,
            );
            let bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        s_row.id.as_bytes(),
                        3,
                        s_row.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
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
                    self.secwet_id.as_bytes(),
                    s_row.id.as_bytes(),
                    RecordType::Secret,
                    s_row.key_epoch,
                );
                let bytes = match self.open_rec(&aad, blob) {
                    Ok(b) => b,
                    Err(_) => {
                        let leg_aad = RecordAad::from_raw_type(
                            self.secwet_id.as_bytes(),
                            s_row.id.as_bytes(),
                            3,
                            s_row.key_epoch,
                        );
                        self.open_rec(&leg_aad, blob)?
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

    /// Decrypts secrets and collects their record UUIDs for active session tracking.
    pub fn env_for_with_ids(
        &self,
        item_id: Uuid,
        environment_id: Option<Uuid>,
    ) -> Result<EnvWithIds> {
        let item_row = get_record(&self.db, item_id)?.ok_or(Error::NotFound)?;
        if item_row.deleted {
            return Err(Error::NotFound);
        }

        let mut map: HashMap<String, (SecretString, Uuid)> = HashMap::new();

        // 1. Item-level base secrets
        let item_secrets = query_content_records(&self.db, item_id, None, RecordType::Secret)?;
        for s_row in item_secrets {
            let blob = s_row.blob.as_ref().ok_or(Error::Storage)?;
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                s_row.id.as_bytes(),
                RecordType::Secret,
                s_row.key_epoch,
            );
            let bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        s_row.id.as_bytes(),
                        3,
                        s_row.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
                }
            };
            let body: SecretBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            map.insert(body.name, (SecretString::from(body.value), s_row.id));
        }

        // 2. If environment_id is Some, overlay environment-specific secrets
        if let Some(env_id) = environment_id {
            let env_secrets =
                query_content_records(&self.db, item_id, Some(env_id), RecordType::Secret)?;
            for s_row in env_secrets {
                let blob = s_row.blob.as_ref().ok_or(Error::Storage)?;
                let aad = RecordAad::new(
                    self.secwet_id.as_bytes(),
                    s_row.id.as_bytes(),
                    RecordType::Secret,
                    s_row.key_epoch,
                );
                let bytes = match self.open_rec(&aad, blob) {
                    Ok(b) => b,
                    Err(_) => {
                        let leg_aad = RecordAad::from_raw_type(
                            self.secwet_id.as_bytes(),
                            s_row.id.as_bytes(),
                            3,
                            s_row.key_epoch,
                        );
                        self.open_rec(&leg_aad, blob)?
                    }
                };
                let body: SecretBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
                map.insert(body.name, (SecretString::from(body.value), s_row.id));
            }
        }

        let mut pairs: Vec<(String, SecretString)> = Vec::new();
        let mut ids: Vec<Uuid> = Vec::new();
        let mut sorted_keys: Vec<String> = map.keys().cloned().collect();
        sorted_keys.sort();
        for k in sorted_keys {
            if let Some((val, id)) = map.remove(&k) {
                pairs.push((k, val));
                ids.push(id);
            }
        }
        Ok((pairs, ids))
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
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Asset,
                row.key_epoch,
            );
            let bytes = self.open_rec(&aad, blob)?;
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
        self.guard_write(crate::collab::WriteTarget::Content { item: item_id, env: environment_id, delete: false })?;
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
                self.secwet_id.as_bytes(),
                sib.id.as_bytes(),
                RecordType::Asset,
                sib.key_epoch,
            );
            let bytes = self.open_rec(&aad, blob)?;
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
            self.secwet_id.as_bytes(),
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
        let _ = self.enqueue_mutation_event(&self.db, asset_id, RecordType::Asset, lamport, Some(&RecordPayload::File(payload)));

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
            self.secwet_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Asset,
            row.key_epoch,
        );
        let bytes = self.open_rec(&aad, blob)?;
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
        self.guard_write(crate::collab::WriteTarget::ContentRecord { id, delete: false })?;
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
            self.secwet_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Asset,
            row.key_epoch,
        );
        let bytes = self.open_rec(&aad, blob)?;
        let mut payload: AssetPayload = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;

        // Sibling uniqueness check
        let siblings = query_records_by_parent(&self.db, row.parent_id, false)?;
        for sib in siblings {
            if sib.id == id || sib.record_type != RecordType::Asset {
                continue;
            }
            let s_blob = sib.blob.as_ref().ok_or(Error::Storage)?;
            let s_aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                sib.id.as_bytes(),
                RecordType::Asset,
                sib.key_epoch,
            );
            let s_bytes = self.open_rec(&s_aad, s_blob)?;
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
            self.secwet_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Asset,
            row.key_epoch,
        );
        let new_blob = seal_record(self.k_rec.expose_secret(), &new_aad, &payload_bytes)?;

        let now_ms = current_time_ms();
        let new_lamport = update_record_blob(&self.db, id, &new_blob, &self.device_id, now_ms)?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Asset, new_lamport, Some(&RecordPayload::File(payload.clone())));

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
        self.guard_write(crate::collab::WriteTarget::ContentRecord { id, delete: true })?;
        let existing = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if existing.deleted || existing.record_type != RecordType::Asset {
            return Err(Error::NotFound);
        }
        let del_lamport = soft_delete_record(&self.db, id, &self.device_id, current_time_ms())?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Asset, del_lamport, None);
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
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Note,
                row.key_epoch,
            );
            let bytes = self.open_rec(&aad, blob)?;
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
            self.secwet_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Note,
            row.key_epoch,
        );
        let bytes = self.open_rec(&aad, blob)?;
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
        self.guard_write(crate::collab::WriteTarget::Content { item: item_id, env: environment_id, delete: false })?;
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
            self.secwet_id.as_bytes(),
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
        let _ = self.enqueue_mutation_event(&self.db, note_id, RecordType::Note, lamport, Some(&RecordPayload::Note(body)));

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
        self.guard_write(crate::collab::WriteTarget::ContentRecord { id, delete: false })?;
        let title_opt: Option<&'a str> = title.into();
        let content_opt: Option<&'a str> = content.into();

        let row = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if row.deleted || row.record_type != RecordType::Note {
            return Err(Error::NotFound);
        }

        let blob = row.blob.as_ref().ok_or(Error::Storage)?;
        let aad = RecordAad::new(
            self.secwet_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Note,
            row.key_epoch,
        );
        let bytes = self.open_rec(&aad, blob)?;
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
            self.secwet_id.as_bytes(),
            row.id.as_bytes(),
            RecordType::Note,
            row.key_epoch,
        );
        let new_blob = seal_record(self.k_rec.expose_secret(), &new_aad, &updated_bytes)?;

        let now_ms = current_time_ms();
        let new_lamport = update_record_blob(&self.db, id, &new_blob, &self.device_id, now_ms)?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Note, new_lamport, Some(&RecordPayload::Note(updated_body)));

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
        self.guard_write(crate::collab::WriteTarget::ContentRecord { id, delete: true })?;
        let existing = get_record(&self.db, id)?.ok_or(Error::NotFound)?;
        if existing.deleted || existing.record_type != RecordType::Note {
            return Err(Error::NotFound);
        }
        let del_lamport = soft_delete_record(&self.db, id, &self.device_id, current_time_ms())?;
        let _ = self.enqueue_mutation_event(&self.db, id, RecordType::Note, del_lamport, None);
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
                self.secwet_id.as_bytes(),
                id.as_bytes(),
                RecordType::Item,
                key_epoch,
            );
            let bytes = match self.open_rec(&aad, &blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        id.as_bytes(),
                        1,
                        key_epoch,
                    );
                    self.open_rec(&leg_aad, &blob)?
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
                    self.secwet_id.as_bytes(),
                    env_row.id.as_bytes(),
                    RecordType::Environment,
                    env_row.key_epoch,
                );
                let e_bytes = match self.open_rec(&e_aad, e_blob) {
                    Ok(b) => b,
                    Err(_) => {
                        let leg_aad = RecordAad::from_raw_type(
                            self.secwet_id.as_bytes(),
                            env_row.id.as_bytes(),
                            2,
                            env_row.key_epoch,
                        );
                        self.open_rec(&leg_aad, e_blob)?
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
        self.ensure_writable()?;
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
            self.secwet_id.as_bytes(),
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
                self.secwet_id.as_bytes(),
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
        self.ensure_writable()?;
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
            self.secwet_id.as_bytes(),
            id.as_bytes(),
            RecordType::Item,
            p_row.key_epoch,
        );
        let bytes = match self.open_rec(&aad, blob) {
            Ok(b) => b,
            Err(_) => {
                let leg_aad = RecordAad::from_raw_type(
                    self.secwet_id.as_bytes(),
                    id.as_bytes(),
                    1,
                    p_row.key_epoch,
                );
                self.open_rec(&leg_aad, blob)?
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
            self.secwet_id.as_bytes(),
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
        self.ensure_writable()?;
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
                    self.secwet_id.as_bytes(),
                    id.as_bytes(),
                    RecordType::Secret,
                    key_epoch,
                );
                self.open_rec(&aad, &blob)?
            } else {
                let leg_aad =
                    RecordAad::from_raw_type(self.secwet_id.as_bytes(), id.as_bytes(), 3, key_epoch);
                self.open_rec(&leg_aad, &blob)?
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
            secwet_created: true,
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
            self.unseal_device_name_any(&self.device_id, &name_blob)?
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
                "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, trust)
                 VALUES (?1, ?2, X'', X'', ?3, NULL, ?3, 'self')",
                params![self.device_id, name_blob, now_ms],
            )
            .map_err(|_| Error::Storage)?;
        }

        tx.commit().map_err(|_| Error::Storage)?;
        Ok(())
    }

    // ========================================================================
    // Recovery and Export (F9, F10)
    // ========================================================================

    /// Generates a new 125-bit recovery key, computes the `recovery_check` seal,
    /// wraps all master keys across active epochs under K_r, and updates SQLite `meta`
    /// in an atomic transaction.
    ///
    /// Returns the formatted 25-character Crockford Base32 key (5 groups of 5) wrapped in SecretString.
    /// Invariant: The recovery key is returned once and NEVER stored on disk or in the database.
    pub fn create_recovery_key(&mut self, keystore: &dyn KeyStore) -> Result<SecretString> {
        let (key_str, raw_entropy) = crypto::generate_recovery_key();
        let k_r = crypto::derive_recovery_key(&*raw_entropy, &self.secwet_id);

        let check_aad = postcard::to_stdvec(&("secwet-recovery-check", self.secwet_id))
            .map_err(|_| Error::Crypto)?;
        let check_blob = crypto::seal_raw(&k_r, &check_aad, b"secwet-recovery-check")?;
        let check_b64 = data_encoding::BASE64.encode(&check_blob);

        let mut wrapped_map = HashMap::new();
        for epoch in 1..=self.key_epoch {
            let km_vec = crate::collab::load_master_key(keystore, &self.secwet_id, epoch)?;
            if let Some(km_vec) = km_vec {
                let wrap_aad = postcard::to_stdvec(&("recovery-wrap", self.secwet_id, epoch))
                    .map_err(|_| Error::Crypto)?;
                let wrapped_blob = crypto::seal_raw(&k_r, &wrap_aad, km_vec.as_slice())?;
                wrapped_map.insert(epoch, data_encoding::BASE64.encode(&wrapped_blob));
            } else if epoch == self.key_epoch {
                return Err(Error::KeyStore);
            }
        }
        let wrapped_json = serde_json::to_string(&wrapped_map).map_err(|_| Error::Crypto)?;

        let now_ms = current_time_ms();
        let tx = self.db.transaction().map_err(|_| Error::Storage)?;
        set_meta(&tx, "recovery_created_at", &now_ms.to_string())?;
        set_meta(&tx, "recovery_check", &check_b64)?;
        set_meta(&tx, "recovery_wrapped_master_keys", &wrapped_json)?;
        tx.commit().map_err(|_| Error::Storage)?;

        Ok(SecretString::from(key_str))
    }

    /// Generates a new recovery key, re-wraps all master key epochs under the new K_r,
    /// overwrites `recovery_check` and `recovery_wrapped_master_keys`, and invalidates the old key.
    pub fn replace_recovery_key(&mut self, keystore: &dyn KeyStore) -> Result<SecretString> {
        self.create_recovery_key(keystore)
    }

    /// Verifies a user-supplied candidate recovery key string against the stored `recovery_check` seal.
    ///
    /// Returns `Ok(true)` if valid, `Ok(false)` if invalid or uninitialized.
    /// Invariant: Never leaks detailed failure reasons or timing discrepancies.
    pub fn verify_recovery_key(&self, input: &str) -> Result<bool> {
        check_recovery_key(&self.db, &self.secwet_id, input)
    }

    /// [`Secwet::verify_recovery_key`] for a store that is not open: reads
    /// only the `recovery_check` seal, never the keys. `Ok(None)` when no
    /// store exists or no recovery key was created. Phones without a screen
    /// lock ask for the recovery key here before unlocking.
    pub fn verify_recovery_key_closed(data_dir: &Path, input: &str) -> Result<Option<bool>> {
        let Some((db_path, secwet_id)) = find_secwet_db(data_dir) else {
            return Ok(None);
        };
        let conn = open_connection(&db_path)?;
        if records::get_meta(&conn, "recovery_check")?.is_none() {
            return Ok(None);
        }
        check_recovery_key(&conn, &secwet_id, input).map(Some)
    }

    /// Whether the store in `data_dir` has a recovery key, without opening it.
    pub fn recovery_key_exists_closed(data_dir: &Path) -> Result<bool> {
        let Some((db_path, _)) = find_secwet_db(data_dir) else {
            return Ok(false);
        };
        let conn = open_connection(&db_path)?;
        Ok(records::get_meta(&conn, "recovery_check")?.is_some())
    }

    /// Returns the current recovery key creation status and timestamp.
    pub fn recovery_status(&self) -> Result<RecoveryStatus> {
        let created_at_opt = records::get_meta(&self.db, "recovery_created_at")?;
        if let Some(ts_str) = created_at_opt {
            let ts: u64 = ts_str.parse().unwrap_or(0);
            Ok(RecoveryStatus::new(true, Some(ts)))
        } else {
            Ok(RecoveryStatus::new(false, None))
        }
    }

    /// Collects a complete plaintext snapshot across all entity tables.
    pub fn collect_snapshot(&self) -> Result<SecwetSnapshot> {
        let mut spaces = Vec::new();
        let space_rows = records::query_active_spaces(&self.db)?;
        for row in space_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Label,
                self.key_epoch,
            );
            let bytes = self.open_rec(&aad, &row.name_blob)?;
            let body: SpaceBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            spaces.push(SnapshotSpace {
                id: row.id,
                name: body.name,
                position: row.position,
                icon: body.icon,
                is_default: body.is_default,
                created_at: row.created_at,
                updated_at: row.updated_at,
                deleted: row.deleted,
            });
        }

        let mut labels = Vec::new();
        let label_rows = records::query_active_labels(&self.db)?;
        for row in label_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Label,
                self.key_epoch,
            );
            let bytes = self.open_rec(&aad, &row.name_blob)?;
            let body = deserialize_label_body(&bytes)?;
            labels.push(SnapshotLabel {
                id: row.id,
                space_id: row.space_id.or(body.space_id),
                name: body.name,
                position: row.position,
                icon: body.icon,
                created_at: row.created_at,
                updated_at: row.updated_at,
                deleted: row.deleted,
            });
        }

        let mut items = Vec::new();
        let item_rows = records::query_active_records_by_type(&self.db, RecordType::Item)?;
        for row in item_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Item,
                row.key_epoch,
            );
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        row.id.as_bytes(),
                        1,
                        row.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
                }
            };
            let body = postcard::from_bytes::<ItemBody>(&bytes)
                .or_else(|_| postcard::from_bytes::<ProjectBody>(&bytes).map(|p| ItemBody {
                    label_id: row.parent_id.unwrap_or_default(),
                    name: p.name,
                    description: None,
                    position: 0,
                }))
                .map_err(|_| Error::Storage)?;
            items.push(SnapshotItem {
                id: row.id,
                label_id: body.label_id,
                name: body.name,
                description: body.description,
                position: body.position,
                lamport: row.lamport,
                origin_device: row.origin_device,
                updated_at: row.updated_at,
                deleted: row.deleted,
            });
        }

        let mut environments = Vec::new();
        let env_rows = records::query_active_records_by_type(&self.db, RecordType::Environment)?;
        for row in env_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Environment,
                row.key_epoch,
            );
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        row.id.as_bytes(),
                        2,
                        row.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
                }
            };
            let body: EnvironmentBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            environments.push(SnapshotEnvironment {
                id: row.id,
                item_id: body.item_id,
                name: body.name,
                position: body.position,
                lamport: row.lamport,
                origin_device: row.origin_device,
                updated_at: row.updated_at,
                deleted: row.deleted,
            });
        }

        let mut secrets = Vec::new();
        let sec_rows = records::query_active_records_by_type(&self.db, RecordType::Secret)?;
        for row in sec_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Secret,
                row.key_epoch,
            );
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let bytes = match self.open_rec(&aad, blob) {
                Ok(b) => b,
                Err(_) => {
                    let leg_aad = RecordAad::from_raw_type(
                        self.secwet_id.as_bytes(),
                        row.id.as_bytes(),
                        3,
                        row.key_epoch,
                    );
                    self.open_rec(&leg_aad, blob)?
                }
            };
            let body = postcard::from_bytes::<SecretBody>(&bytes)
                .or_else(|_| postcard::from_bytes::<LegacyV1SecretBody>(&bytes).map(|s| SecretBody {
                    item_id: s.project_id,
                    environment_id: Some(s.environment_id),
                    name: s.name,
                    kind: s.kind,
                    value: s.value,
                    note: s.note,
                }))
                .map_err(|_| Error::Storage)?;
            secrets.push(SnapshotSecret {
                id: row.id,
                item_id: body.item_id,
                environment_id: body.environment_id,
                name: body.name,
                kind: body.kind,
                value: body.value,
                note: body.note,
                lamport: row.lamport,
                origin_device: row.origin_device,
                updated_at: row.updated_at,
                deleted: row.deleted,
            });
        }

        let mut notes = Vec::new();
        let note_rows = records::query_active_records_by_type(&self.db, RecordType::Note)?;
        for row in note_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Note,
                row.key_epoch,
            );
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let bytes = self.open_rec(&aad, blob)?;
            let body: NoteBody = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            notes.push(SnapshotNote {
                id: row.id,
                item_id: body.item_id,
                environment_id: body.environment_id,
                title: body.title,
                content: body.content,
                position: body.position,
                lamport: row.lamport,
                origin_device: row.origin_device,
                updated_at: row.updated_at,
                deleted: row.deleted,
            });
        }

        let mut files = Vec::new();
        let file_rows = records::query_active_records_by_type(&self.db, RecordType::Asset)?;
        for row in file_rows {
            let aad = RecordAad::new(
                self.secwet_id.as_bytes(),
                row.id.as_bytes(),
                RecordType::Asset,
                row.key_epoch,
            );
            let blob = row.blob.as_ref().ok_or(Error::Storage)?;
            let bytes = self.open_rec(&aad, blob)?;
            let payload: AssetPayload = postcard::from_bytes(&bytes).map_err(|_| Error::Storage)?;
            files.push(SnapshotFile {
                id: row.id,
                item_id: payload.meta.item_id,
                environment_id: payload.meta.environment_id,
                name: payload.meta.name,
                size_bytes: payload.meta.size_bytes,
                mime_type: payload.meta.mime_type,
                sha256: payload.meta.sha256,
                data: payload.data,
                lamport: row.lamport,
                origin_device: row.origin_device,
                updated_at: row.updated_at,
                deleted: row.deleted,
            });
        }

        let mut settings = Vec::new();
        let mut stmt = self
            .db
            .prepare("SELECT key, value FROM settings")
            .map_err(|_| Error::Storage)?;
        let mut rows = stmt.query([]).map_err(|_| Error::Storage)?;
        while let Some(r) = rows.next().map_err(|_| Error::Storage)? {
            let key: String = r.get(0).map_err(|_| Error::Storage)?;
            let value: String = r.get(1).map_err(|_| Error::Storage)?;
            settings.push(SnapshotSetting { key, value });
        }

        let created_at: i64 = records::get_meta(&self.db, "created_at")?
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let plan = records::get_meta(&self.db, "plan")?.unwrap_or_else(|| "free".to_string());
        let relay_url = records::get_meta(&self.db, "relay_url")?.unwrap_or_default();

        Ok(SecwetSnapshot {
            secwet_id: self.secwet_id,
            created_at,
            key_epoch: self.key_epoch,
            plan,
            relay_url,
            spaces,
            labels,
            items,
            environments,
            secrets,
            notes,
            files,
            settings,
        })
    }

    /// Serializes workspace state into a postcard snapshot, encrypts with K_r and authenticated AAD,
    /// and writes the JSON `.secwet` envelope to `out`.
    pub fn export_encrypted(
        &self,
        recovery_key: &SecretString,
        out: &Path,
    ) -> Result<ExportSummary> {
        let k_r = crypto::derive_recovery_key_from_str(recovery_key.expose_secret(), &self.secwet_id)
            .map_err(|_| Error::RecoveryFailed)?;

        if records::get_meta(&self.db, "recovery_check")?.is_some()
            && !self.verify_recovery_key(recovery_key.expose_secret())?
        {
            return Err(Error::RecoveryFailed);
        }

        let snapshot = self.collect_snapshot()?;
        let spaces_count = snapshot.spaces.len();
        let labels_count = snapshot.labels.len();
        let items_count = snapshot.items.len();
        let environments_count = snapshot.environments.len();
        let secrets_count = snapshot.secrets.len();
        let notes_count = snapshot.notes.len();
        let files_count = snapshot.files.len();

        let snapshot_bytes = postcard::to_stdvec(&snapshot).map_err(|_| Error::Crypto)?;
        let export_aad = ExportAad::new(self.secwet_id);
        let aad_bytes = export_aad.to_bytes().map_err(|_| Error::Crypto)?;
        let (nonce, ciphertext) = crypto::seal_raw_parts(&k_r, &aad_bytes, &snapshot_bytes)?;

        let now_ms = current_time_ms();
        let envelope = SecwetExportEnvelope {
            format: "secwet-export".to_string(),
            version: 1,
            secwet_id: self.secwet_id,
            created_at: now_ms,
            kdf: "hkdf-sha256".to_string(),
            cipher: "xchacha20poly1305".to_string(),
            nonce: data_encoding::BASE64.encode(&nonce),
            ciphertext: data_encoding::BASE64.encode(&ciphertext),
        };

        let json_bytes = serde_json::to_vec_pretty(&envelope).map_err(|_| Error::Crypto)?;
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|_| Error::Storage)?;
            }
        }
        std::fs::write(out, &json_bytes).map_err(|_| Error::Storage)?;

        Ok(ExportSummary::new(
            self.secwet_id,
            now_ms,
            spaces_count,
            labels_count,
            items_count,
            environments_count,
            secrets_count,
            notes_count,
            files_count,
            json_bytes.len(),
        ))
    }

    /// Convenience wrapper for exporting with a string slice recovery key.
    pub fn export_to_file(&self, recovery_key: &str, out: &Path) -> Result<ExportSummary> {
        self.export_encrypted(&SecretString::from(recovery_key), out)
    }

    /// Restores a workspace from an encrypted `.secwet` envelope file.
    ///
    /// Decrypts and authenticates the backup using K_r, provisions fresh device keys,
    /// increments the key epoch, creates a clean SQLite database, re-encrypts all data,
    /// re-computes recovery seals, and returns an unlocked `Secwet` instance.
    pub fn restore_from_export(
        data_dir: &Path,
        file: &Path,
        recovery_key: &SecretString,
        device_name: &str,
        keystore: &dyn KeyStore,
    ) -> Result<Secwet> {
        if !file.is_file() {
            return Err(Error::NotFound);
        }
        let json_bytes = std::fs::read(file).map_err(|_| Error::RecoveryFailed)?;
        let envelope: SecwetExportEnvelope =
            serde_json::from_slice(&json_bytes).map_err(|_| Error::RecoveryFailed)?;

        if envelope.format != "secwet-export"
            || envelope.version != 1
            || envelope.kdf != "hkdf-sha256"
            || envelope.cipher != "xchacha20poly1305"
        {
            return Err(Error::RecoveryFailed);
        }

        let nonce_vec = data_encoding::BASE64
            .decode(envelope.nonce.as_bytes())
            .map_err(|_| Error::RecoveryFailed)?;
        if nonce_vec.len() != crypto::NONCE_LEN {
            return Err(Error::RecoveryFailed);
        }
        let mut nonce = [0u8; crypto::NONCE_LEN];
        nonce.copy_from_slice(&nonce_vec);

        let ciphertext = data_encoding::BASE64
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|_| Error::RecoveryFailed)?;

        let k_r = crypto::derive_recovery_key_from_str(recovery_key.expose_secret(), &envelope.secwet_id)
            .map_err(|_| Error::RecoveryFailed)?;

        let export_aad = ExportAad::new(envelope.secwet_id);
        let aad_bytes = export_aad.to_bytes().map_err(|_| Error::RecoveryFailed)?;

        let decrypted = crypto::open_raw_parts(&k_r, &aad_bytes, &nonce, &ciphertext)
            .map_err(|_| Error::RecoveryFailed)?;

        let snapshot: SecwetSnapshot =
            postcard::from_bytes(&decrypted).map_err(|_| Error::RecoveryFailed)?;

        // Provision fresh device keys
        let trimmed_name = device_name.trim();
        let dev_name = if trimmed_name.is_empty() {
            "default-device"
        } else {
            trimmed_name
        };
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let sign_pub = signing_key.verifying_key().to_bytes();
        let sign_priv = signing_key.to_bytes();
        let device_id = crypto::compute_device_id(&sign_pub);

        let enc_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let enc_pub = x25519_dalek::PublicKey::from(&enc_secret).to_bytes();
        let enc_priv = enc_secret.to_bytes();

        // Increment key epoch: N + 1
        let new_epoch = snapshot.key_epoch + 1;
        let mut new_k_v = zeroize::Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *new_k_v);

        keystore.set(&format!("secwet/{}/device-sign", snapshot.secwet_id), &sign_priv)?;
        keystore.set(&format!("secwet/{}/device-enc", snapshot.secwet_id), &enc_priv)?;
        crate::collab::store_master_key(keystore, &snapshot.secwet_id, new_epoch, &new_k_v)?;

        let (new_k_rec_bytes, new_k_evt_bytes) = derive_keys(&new_k_v, &snapshot.secwet_id);

        let db_dir = data_dir.join("secwet").join(snapshot.secwet_id.to_string());
        std::fs::create_dir_all(&db_dir).map_err(|_| Error::Storage)?;
        let db_path = db_dir.join("secwet.sqlite3");
        if db_path.exists() {
            let _ = std::fs::remove_file(&db_path);
            let _ = std::fs::remove_file(db_dir.join("secwet.sqlite3-wal"));
            let _ = std::fs::remove_file(db_dir.join("secwet.sqlite3-shm"));
        }

        let mut conn = open_connection(&db_path)?;
        records::run_migrations(&mut conn)?;

        let now_ms = current_time_ms();
        let tx = conn.transaction().map_err(|_| Error::Storage)?;

        set_meta(&tx, "schema_version", "3")?;
        set_meta(&tx, "secwet_id", &snapshot.secwet_id.to_string())?;
        set_meta(&tx, "created_at", &snapshot.created_at.to_string())?;
        set_meta(&tx, "current_key_epoch", &new_epoch.to_string())?;
        set_meta(&tx, "device_id", &device_id)?;
        set_meta(&tx, "plan", &snapshot.plan)?;
        set_meta(&tx, "relay_url", &snapshot.relay_url)?;
        set_meta(&tx, "flexible_org_migrated", "1")?;

        // Re-encrypt spaces
        for s in &snapshot.spaces {
            let space_body = SpaceBody::new(&s.name, s.position, s.icon.clone(), s.is_default);
            let space_bytes = postcard::to_stdvec(&space_body).map_err(|_| Error::Storage)?;
            let space_aad = RecordAad::new(
                snapshot.secwet_id.as_bytes(),
                s.id.as_bytes(),
                RecordType::Label,
                new_epoch,
            );
            let space_blob = seal_record(&new_k_rec_bytes, &space_aad, &space_bytes)?;
            let space_row = SpaceRow {
                id: s.id,
                name_blob: space_blob,
                position: s.position,
                created_at: s.created_at,
                updated_at: s.updated_at,
                deleted: s.deleted,
            };
            insert_space(&tx, &space_row)?;
        }

        // Re-encrypt labels
        for l in &snapshot.labels {
            let label_body = LabelBody::with_space(&l.name, l.position, l.icon.clone(), l.space_id);
            let label_bytes = postcard::to_stdvec(&label_body).map_err(|_| Error::Storage)?;
            let label_aad = RecordAad::new(
                snapshot.secwet_id.as_bytes(),
                l.id.as_bytes(),
                RecordType::Label,
                new_epoch,
            );
            let label_blob = seal_record(&new_k_rec_bytes, &label_aad, &label_bytes)?;
            let label_row = LabelRow {
                id: l.id,
                space_id: l.space_id,
                name_blob: label_blob,
                position: l.position,
                created_at: l.created_at,
                updated_at: l.updated_at,
                deleted: l.deleted,
            };
            insert_label(&tx, &label_row)?;
        }

        // Re-encrypt items
        for item in &snapshot.items {
            let item_body =
                ItemBody::new(item.label_id, &item.name, item.description.clone(), item.position);
            let item_bytes = postcard::to_stdvec(&item_body).map_err(|_| Error::Storage)?;
            let item_aad = RecordAad::new(
                snapshot.secwet_id.as_bytes(),
                item.id.as_bytes(),
                RecordType::Item,
                new_epoch,
            );
            let item_blob = seal_record(&new_k_rec_bytes, &item_aad, &item_bytes)?;
            let record_row = RecordRow {
                id: item.id,
                record_type: RecordType::Item,
                parent_id: Some(item.label_id),
                key_epoch: new_epoch,
                blob: Some(item_blob),
                lamport: item.lamport,
                origin_device: item.origin_device.clone(),
                updated_at: item.updated_at,
                deleted: item.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        // Re-encrypt environments
        for env in &snapshot.environments {
            let env_body = EnvironmentBody::new(env.item_id, &env.name, env.position);
            let env_bytes = postcard::to_stdvec(&env_body).map_err(|_| Error::Storage)?;
            let env_aad = RecordAad::new(
                snapshot.secwet_id.as_bytes(),
                env.id.as_bytes(),
                RecordType::Environment,
                new_epoch,
            );
            let env_blob = seal_record(&new_k_rec_bytes, &env_aad, &env_bytes)?;
            let record_row = RecordRow {
                id: env.id,
                record_type: RecordType::Environment,
                parent_id: Some(env.item_id),
                key_epoch: new_epoch,
                blob: Some(env_blob),
                lamport: env.lamport,
                origin_device: env.origin_device.clone(),
                updated_at: env.updated_at,
                deleted: env.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        // Re-encrypt secrets
        for sec in &snapshot.secrets {
            let sec_body = SecretBody::new(
                sec.item_id,
                sec.environment_id,
                &sec.name,
                sec.kind,
                &sec.value,
                sec.note.clone(),
            );
            let sec_bytes = postcard::to_stdvec(&sec_body).map_err(|_| Error::Storage)?;
            let sec_aad = RecordAad::new(
                snapshot.secwet_id.as_bytes(),
                sec.id.as_bytes(),
                RecordType::Secret,
                new_epoch,
            );
            let sec_blob = seal_record(&new_k_rec_bytes, &sec_aad, &sec_bytes)?;
            let parent_id = sec.environment_id.or(Some(sec.item_id));
            let record_row = RecordRow {
                id: sec.id,
                record_type: RecordType::Secret,
                parent_id,
                key_epoch: new_epoch,
                blob: Some(sec_blob),
                lamport: sec.lamport,
                origin_device: sec.origin_device.clone(),
                updated_at: sec.updated_at,
                deleted: sec.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        // Re-encrypt notes
        for note in &snapshot.notes {
            let note_body = NoteBody::new(
                note.item_id,
                note.environment_id,
                &note.title,
                &note.content,
                note.position,
            );
            let note_bytes = postcard::to_stdvec(&note_body).map_err(|_| Error::Storage)?;
            let note_aad = RecordAad::new(
                snapshot.secwet_id.as_bytes(),
                note.id.as_bytes(),
                RecordType::Note,
                new_epoch,
            );
            let note_blob = seal_record(&new_k_rec_bytes, &note_aad, &note_bytes)?;
            let parent_id = note.environment_id.or(Some(note.item_id));
            let record_row = RecordRow {
                id: note.id,
                record_type: RecordType::Note,
                parent_id,
                key_epoch: new_epoch,
                blob: Some(note_blob),
                lamport: note.lamport,
                origin_device: note.origin_device.clone(),
                updated_at: note.updated_at,
                deleted: note.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        // Re-encrypt files
        for file in &snapshot.files {
            let meta = AssetMetaBody::new(
                file.item_id,
                file.environment_id,
                &file.name,
                file.size_bytes,
                &file.mime_type,
                file.sha256,
            );
            let payload = AssetPayload::new(meta, file.data.clone());
            let file_bytes = postcard::to_stdvec(&payload).map_err(|_| Error::Storage)?;
            let file_aad = RecordAad::new(
                snapshot.secwet_id.as_bytes(),
                file.id.as_bytes(),
                RecordType::Asset,
                new_epoch,
            );
            let file_blob = seal_record(&new_k_rec_bytes, &file_aad, &file_bytes)?;
            let parent_id = file.environment_id.or(Some(file.item_id));
            let record_row = RecordRow {
                id: file.id,
                record_type: RecordType::Asset,
                parent_id,
                key_epoch: new_epoch,
                blob: Some(file_blob),
                lamport: file.lamport,
                origin_device: file.origin_device.clone(),
                updated_at: file.updated_at,
                deleted: file.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        // Re-populate settings
        for s in &snapshot.settings {
            tx.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?1, ?2)",
                params![s.key, s.value],
            )
            .map_err(|_| Error::Storage)?;
        }

        // Re-populate device
        let dev_name_blob = seal_device_name(&new_k_rec_bytes, &device_id, dev_name)?;
        tx.execute(
            "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, trust)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5, 'self')",
            params![
                device_id,
                dev_name_blob,
                sign_pub.as_slice(),
                enc_pub.as_slice(),
                now_ms,
            ],
        )
        .map_err(|_| Error::Storage)?;

        // Re-compute recovery check and wrap new epoch master key under K_r
        let check_aad = postcard::to_stdvec(&("secwet-recovery-check", snapshot.secwet_id))
            .map_err(|_| Error::Crypto)?;
        let check_blob = crypto::seal_raw(&k_r, &check_aad, b"secwet-recovery-check")?;
        let check_b64 = data_encoding::BASE64.encode(&check_blob);

        let wrap_aad = postcard::to_stdvec(&("recovery-wrap", snapshot.secwet_id, new_epoch))
            .map_err(|_| Error::Crypto)?;
        let wrapped_km_blob = crypto::seal_raw(&k_r, &wrap_aad, &*new_k_v)?;
        let mut wrapped_map = HashMap::new();
        wrapped_map.insert(new_epoch, data_encoding::BASE64.encode(&wrapped_km_blob));
        let wrapped_json = serde_json::to_string(&wrapped_map).map_err(|_| Error::Crypto)?;

        set_meta(&tx, "recovery_created_at", &now_ms.to_string())?;
        set_meta(&tx, "recovery_check", &check_b64)?;
        set_meta(&tx, "recovery_wrapped_master_keys", &wrapped_json)?;

        tx.commit().map_err(|_| Error::Storage)?;

        ACTIVE_SESSIONS.lock().unwrap().insert(snapshot.secwet_id);
        let k_rec = SecretBox::new(Box::new(*new_k_rec_bytes));
        let k_evt = SecretBox::new(Box::new(*new_k_evt_bytes));

        #[cfg(any(test, feature = "test-util"))]
        let test_k_rec_witness = std::sync::Arc::new(std::sync::Mutex::new(*new_k_rec_bytes));
        #[cfg(any(test, feature = "test-util"))]
        let test_k_evt_witness = std::sync::Arc::new(std::sync::Mutex::new(*new_k_evt_bytes));

        let mut secwet = Secwet {
            db: conn,
            secwet_id: snapshot.secwet_id,
            device_id,
            key_epoch: new_epoch,
            k_rec,
            k_evt,
            device_sign_key: signing_key,
            device_sign_pub: sign_pub,
            device_enc_pub: enc_pub,
            keyring: crate::collab::Keyring::with_epoch(&snapshot.secwet_id, new_epoch, &new_k_rec_bytes, &new_k_evt_bytes),
            enc_secret: SecretBox::new(Box::new(enc_priv)),
            member_id: None,
            db_path: db_path.clone(),
            last_scopes: Vec::new(),
            #[cfg(any(test, feature = "test-util"))]
            test_k_rec_witness,
            #[cfg(any(test, feature = "test-util"))]
            test_k_evt_witness,
        };
        secwet.ensure_default_personal_space()?;
        Ok(secwet)
    }

    /// Convenience wrapper for restoring with a string slice recovery key.
    pub fn restore_from_export_str(
        data_dir: &Path,
        file: &Path,
        recovery_key: &str,
        device_name: &str,
        keystore: &dyn KeyStore,
    ) -> Result<Secwet> {
        Self::restore_from_export(
            data_dir,
            file,
            &SecretString::from(recovery_key),
            device_name,
            keystore,
        )
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


    /// Creates a new paired Secwet instance sharing an existing secwet_id and master key.
    pub fn create_paired(
        data_dir: &Path,
        device_name: &str,
        secwet_id: Uuid,
        master_key: &[u8; 32],
        keystore: &dyn KeyStore,
    ) -> Result<Secwet> {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let enc_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        Self::create_with_identity(
            data_dir,
            device_name,
            secwet_id,
            master_key,
            signing_key,
            enc_secret,
            "pro",
            None,
            keystore,
        )
    }

    /// Creates a store for an existing workspace with given device keys.
    ///
    /// `master_key` is the workspace key for the owner's devices, or a
    /// member-local key that never leaves the device when `member_id` is set.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn create_with_identity(
        data_dir: &Path,
        device_name: &str,
        secwet_id: Uuid,
        master_key: &[u8; 32],
        signing_key: ed25519_dalek::SigningKey,
        enc_secret: x25519_dalek::StaticSecret,
        plan: &str,
        member_id: Option<Uuid>,
        keystore: &dyn KeyStore,
    ) -> Result<Secwet> {
        let trimmed_name = device_name.trim();
        let dev_name = if trimmed_name.is_empty() {
            "paired-device"
        } else {
            trimmed_name
        };

        let sign_pub = signing_key.verifying_key().to_bytes();
        let sign_priv = signing_key.to_bytes();
        let device_id = crypto::compute_device_id(&sign_pub);

        let enc_pub = x25519_dalek::PublicKey::from(&enc_secret).to_bytes();
        let enc_priv = enc_secret.to_bytes();

        keystore.set(&format!("secwet/{secwet_id}/device-sign"), &sign_priv)?;
        keystore.set(&format!("secwet/{secwet_id}/device-enc"), &enc_priv)?;
        crate::collab::store_master_key(keystore, &secwet_id, 1, master_key)?;

        let (k_rec_bytes, k_evt_bytes) = derive_keys(master_key, &secwet_id);

        let db_dir = data_dir.join("secwet").join(secwet_id.to_string());
        std::fs::create_dir_all(&db_dir).map_err(|_| Error::Storage)?;
        let db_path = db_dir.join("secwet.sqlite3");
        let conn = open_and_migrate(&db_path)?;

        let now_ms = current_time_ms();
        set_meta(&conn, "schema_version", "2")?;
        set_meta(&conn, "secwet_id", &secwet_id.to_string())?;
        set_meta(&conn, "created_at", &now_ms.to_string())?;
        set_meta(&conn, "current_key_epoch", "1")?;
        set_meta(&conn, "device_id", &device_id)?;
        set_meta(&conn, "plan", plan)?;
        set_meta(&conn, "relay_url", "")?;
        set_meta(&conn, "flexible_org_migrated", "1")?;
        if let Some(m) = member_id {
            set_meta(&conn, "member_id", &m.to_string())?;
        }

        let name_blob = seal_device_name(&k_rec_bytes, &device_id, dev_name)?;
        conn.execute(
            "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, member_id, trust)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5, ?6, 'self')",
            rusqlite::params![
                device_id,
                name_blob,
                sign_pub.as_slice(),
                enc_pub.as_slice(),
                now_ms,
                member_id.map(|m| m.as_bytes().to_vec()),
            ],
        )
        .map_err(|_| Error::Storage)?;

        ACTIVE_SESSIONS.lock().unwrap().insert(secwet_id);

        let k_rec = SecretBox::new(Box::new(*k_rec_bytes));
        let k_evt = SecretBox::new(Box::new(*k_evt_bytes));

        #[cfg(any(test, feature = "test-util"))]
        let test_k_rec_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_rec_bytes));
        #[cfg(any(test, feature = "test-util"))]
        let test_k_evt_witness = std::sync::Arc::new(std::sync::Mutex::new(*k_evt_bytes));

        let mut secwet = Secwet {
            db: conn,
            secwet_id,
            device_id,
            key_epoch: 1,
            k_rec,
            k_evt,
            device_sign_key: signing_key,
            device_sign_pub: sign_pub,
            device_enc_pub: enc_pub,
            keyring: crate::collab::Keyring::with_epoch(&secwet_id, 1, &k_rec_bytes, &k_evt_bytes),
            enc_secret: SecretBox::new(Box::new(enc_priv)),
            member_id,
            db_path: db_path.clone(),
            last_scopes: Vec::new(),
            #[cfg(any(test, feature = "test-util"))]
            test_k_rec_witness,
            #[cfg(any(test, feature = "test-util"))]
            test_k_evt_witness,
        };
        if member_id.is_some() {
            secwet.ensure_default_personal_space()?;
        }
        Ok(secwet)
    }


    // ========================================================================
    // Relay & Entitlements
    // ========================================================================

    pub fn relay_url(&self) -> Result<String> {
        let url = records::get_meta(&self.db, "relay_url")?.unwrap_or_default();
        if url.trim().is_empty() {
            return Err(Error::Relay {
                code: "relay_not_configured".into(),
            });
        }
        Ok(url)
    }

    pub fn set_relay_url(&mut self, url: &str) -> Result<()> {
        records::set_meta(&self.db, "relay_url", url)?;
        Ok(())
    }

    pub fn device_sign_key(&self) -> &ed25519_dalek::SigningKey {
        &self.device_sign_key
    }

    pub fn device_sign_pub(&self) -> [u8; 32] {
        self.device_sign_pub
    }

    pub fn device_enc_pub(&self) -> [u8; 32] {
        self.device_enc_pub
    }

    pub async fn relay_register(&self, client: &crate::relay_client::RelayClient) -> Result<secwet_proto::RegisterSecwetResponse> {
        let res = client
            .register(
                self.secwet_id,
                self.device_sign_pub,
                self.device_enc_pub,
                &self.device_sign_key,
            )
            .await?;
        Ok(res)
    }

    /// Synchronizes the entitlement from the relay into the local store
    /// (see `plan.rs`). A Free store never contacts the relay.
    pub async fn sync_entitlement_from_relay(&mut self) -> Result<crate::plan::PlanInfo> {
        let relay_url = self.relay_url()?;
        let client = crate::relay_client::RelayClient::new(&relay_url, &self.device_id);
        self.refresh_plan(&client).await
    }

    // ========================================================================
    // Device Management & Pairing (F14)
    // ========================================================================

    /// Lists all registered devices (active and revoked).
    pub fn devices_list(&self) -> Result<Vec<secwet_proto::DeviceDto>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at
                 FROM devices ORDER BY added_at ASC",
            )
            .map_err(|_| Error::Storage)?;

        let rows = stmt
            .query_map([], |row| {
                let id: String = row.get(0)?;
                let name_blob: Vec<u8> = row.get(1)?;
                let sign_pub: Vec<u8> = row.get(2)?;
                let enc_pub: Vec<u8> = row.get(3)?;
                let added_at: i64 = row.get(4)?;
                let revoked_at: Option<i64> = row.get(5)?;
                let last_seen_at: i64 = row.get(6)?;
                Ok((id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at))
            })
            .map_err(|_| Error::Storage)?;

        let mut devices = Vec::new();
        for r in rows {
            let (id, name_blob, sign_pub_bytes, enc_pub_bytes, added_at, revoked_at, last_seen_at) =
                r.map_err(|_| Error::Storage)?;

            let raw_name = self.unseal_device_name_any(&id, &name_blob).unwrap_or_else(|_| "Device".to_string());
            
            // Extract platform if stored as "Name (Platform)"
            let (name, platform) = if let Some(idx) = raw_name.rfind(" (") {
                if raw_name.ends_with(')') {
                    let n = raw_name[..idx].trim().to_string();
                    let p = raw_name[idx + 2..raw_name.len() - 1].trim().to_string();
                    (n, p)
                } else {
                    (raw_name, local_platform_label().to_string())
                }
            } else {
                (raw_name, local_platform_label().to_string())
            };

            let mut sign_arr = [0u8; 32];
            if sign_pub_bytes.len() == 32 {
                sign_arr.copy_from_slice(&sign_pub_bytes);
            }
            let mut enc_arr = [0u8; 32];
            if enc_pub_bytes.len() == 32 {
                enc_arr.copy_from_slice(&enc_pub_bytes);
            }

            let fingerprint = crypto::compute_fingerprint(&sign_arr, &enc_arr);
            let is_current = id == self.device_id;

            devices.push(secwet_proto::DeviceDto {
                id,
                name,
                platform,
                fingerprint,
                added_at,
                last_seen_at,
                revoked_at,
                is_current,
            });
        }

        Ok(devices)
    }

    /// Number of active (non-revoked) devices registered in this workspace.
    pub fn active_devices_count(&self) -> Result<u32> {
        let count: i64 = self
            .db
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(|_| Error::Storage)?;
        Ok(count as u32)
    }

    /// Revokes an existing device by its ID.
    pub fn device_revoke(&mut self, target_device_id: &str) -> Result<()> {
        if target_device_id == self.device_id {
            return Err(Error::Revoked); // Cannot revoke current device
        }

        let now_ms = current_time_ms();
        let updated = self
            .db
            .execute(
                "UPDATE devices SET revoked_at = ?1 WHERE device_id = ?2 AND revoked_at IS NULL",
                rusqlite::params![now_ms, target_device_id],
            )
            .map_err(|_| Error::Storage)?;

        if updated == 0 {
            return Err(Error::NotFound);
        }

        Ok(())
    }

    /// Registers a newly paired device in the local devices table.
    pub fn record_paired_device(
        &mut self,
        device_id: &str,
        name: &str,
        platform: &str,
        sign_pub: &[u8; 32],
        enc_pub: &[u8; 32],
    ) -> Result<secwet_proto::DeviceDto> {
        let full_name = format!("{} ({})", name, platform);
        let name_blob = seal_device_name(self.k_rec.expose_secret(), device_id, &full_name)?;
        let now_ms = current_time_ms();

        self.db
            .execute(
                "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, trust)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5, 'certified')
                 ON CONFLICT(device_id) DO UPDATE SET name_blob = ?2, trust = 'certified', member_id = NULL,
                     revoked_at = NULL, revoked_seq = NULL
                 WHERE sign_pub = ?3 AND enc_pub = ?4",
                rusqlite::params![
                    device_id,
                    name_blob,
                    sign_pub.as_slice(),
                    enc_pub.as_slice(),
                    now_ms,
                ],
            )
            .map_err(|_| Error::Storage)?;
        // The approver vouched for this device after comparing codes: tell
        // the other owner devices, and let the new one learn this device.
        self.emit_device_certificate(device_id, sign_pub, enc_pub, None)?;
        let (me, sp, ep) = (self.device_id.clone(), self.device_sign_pub, self.device_enc_pub);
        self.emit_device_certificate(&me, &sp, &ep, None)?;

        let fingerprint = crypto::compute_fingerprint(sign_pub, enc_pub);

        Ok(secwet_proto::DeviceDto {
            id: device_id.to_string(),
            name: name.to_string(),
            platform: platform.to_string(),
            fingerprint,
            added_at: now_ms,
            last_seen_at: now_ms,
            revoked_at: None,
            is_current: false,
        })
    }
// ========================================================================
    // Synchronization & Outbox Engine (F15 - M6)
    // ========================================================================

    /// Enqueues an encrypted, signed mutation event to the outbox when on the Pro plan.
    pub fn enqueue_mutation_event(
        &self,
        conn: &Connection,
        record_id: Uuid,
        record_type: RecordType,
        lamport: u64,
        payload: Option<&RecordPayload>,
    ) -> Result<()> {
        // Free stores never sync. A paused store keeps queueing so the changes
        // made meanwhile go out once Pro is renewed.
        if self.plan_state().unwrap_or(crate::plan::PlanState::Free) == crate::plan::PlanState::Free {
            return Ok(());
        }

        let next_seq = sync::next_device_seq(conn, &self.device_id)?;
        let event_body = match payload {
            Some(p) => {
                let body_bytes = p.to_bytes().map_err(|_| Error::Crypto)?;
                EventBody::Upsert {
                    record_id,
                    record_type: record_type.into(),
                    lamport,
                    body: body_bytes,
                }
            }
            None => EventBody::Delete {
                record_id,
                record_type: record_type.into(),
                lamport,
            },
        };

        // Records in shared spaces travel under their branch key (F19);
        // everything else is workspace-private and sealed with K_evt.
        let scope = self.scope_for_mutation(record_id, record_type, payload)?;
        let signed_event = match scope {
            Some(scope) => {
                if scope.op == secwet_proto::ScopeOp::Container && payload.is_some() {
                    self.mark_space_dirty(Some(scope.space_id));
                }
                let Ok((epoch, key)) = self.scoped_event_key(&scope) else {
                    // The space is shared but this device's bundle has not
                    // arrived: send the change once it has, never unscoped.
                    return self.queue_pending_emit(record_id, record_type);
                };
                sync::create_signed_event_scoped(
                    self.secwet_id,
                    &self.device_id,
                    next_seq,
                    epoch,
                    &key,
                    &self.device_sign_key,
                    &event_body,
                    Some(scope),
                )?
            }
            None if !self.is_owner() => {
                // A member's own spaces never leave the device.
                return Ok(());
            }
            None => sync::create_signed_event(
                self.secwet_id,
                &self.device_id,
                next_seq,
                self.key_epoch,
                self.k_evt.expose_secret(),
                &self.device_sign_key,
                &event_body,
            )?,
        };

        sync::enqueue_outbox(conn, &signed_event)?;
        Ok(())
    }

    /// Number of local events waiting in outbox to be pushed to relay.
    pub fn pending_outbox_count(&self) -> Result<usize> {
        let count: i64 = self
            .db
            .query_row("SELECT count(*) FROM outbox", [], |row| row.get(0))
            .map_err(|_| Error::Storage)?;
        Ok(count.max(0) as usize)
    }

    /// Returns the current sync cursor.
    pub fn sync_cursor(&self) -> Result<u64> {
        sync::get_sync_cursor(&self.db)
    }

    /// Pushes unacknowledged outbox events to the relay.
    pub async fn push_outbox(&mut self, client: &crate::relay_client::RelayClient) -> Result<usize> {
        if self.unlinked_at()?.is_some() {
            return Err(Error::Revoked);
        }
        self.ensure_relay_allowed(crate::plan::RelayOp::Sync)?;
        let events = sync::peek_outbox(&self.db, 500)?;
        if events.is_empty() {
            return Ok(0);
        }

        let resp = client
            .push_events(self.secwet_id, events.clone(), &self.device_sign_key)
            .await?;

        let max_seq = events
            .iter()
            .take(resp.accepted)
            .map(|e| e.envelope.device_seq)
            .max()
            .unwrap_or(0);

        if max_seq > 0 {
            sync::delete_outbox_events(&self.db, max_seq)?;
        }
        if !resp.rejected.is_empty() {
            eprintln!("sync: relay rejected {} change(s) not allowed by this device's role", resp.rejected.len());
        }

        Ok(resp.accepted)
    }

    /// Pulls events from the relay after the local cursor, applying each event with LWW.
    ///
    /// Events this device may never read or accept are skipped. Events it
    /// cannot read or attribute yet (a key, certificate or grant still on its
    /// way) are deferred and retried by `replay_deferred`, so one event can
    /// never stall sync and none is lost. Tampered events and events from
    /// revoked devices are dropped with a warning.
    pub async fn pull_and_apply_events(&mut self, client: &crate::relay_client::RelayClient) -> Result<usize> {
        let mut total_applied = 0usize;
        if self.unlinked_at()?.is_some() {
            return Err(Error::Revoked);
        }
        self.ensure_relay_allowed(crate::plan::RelayOp::Sync)?;
        let mut restored_snapshot = false;

        loop {
            let cursor = sync::get_sync_cursor(&self.db)?;
            let resp = match client.get_events(self.secwet_id, cursor, 500, &self.device_sign_key).await {
                Ok(r) => r,
                Err(Error::Relay { ref code }) if code == "cursor_expired" || code == "cursorexpired" => {
                    if !self.is_owner() {
                        // Member stores cannot read the workspace snapshot.
                        return Err(Error::Relay { code: "cursor_expired".into() });
                    }
                    if restored_snapshot {
                        // The newest snapshot is older than what the relay
                        // pruned: restoring again would loop.
                        return Err(Error::Relay { code: "snapshot_stale".into() });
                    }
                    self.catch_up_via_snapshot(client).await?;
                    restored_snapshot = true;
                    continue;
                }
                Err(e) => return Err(e),
            };

            if resp.events.is_empty() {
                // A device that sees nothing (a member with quiet spaces)
                // still moves to the relay's head and acks it.
                if resp.head_seq > cursor {
                    sync::set_sync_cursor(&self.db, resp.head_seq)?;
                    client.ack_events(self.secwet_id, resp.head_seq, &self.device_sign_key).await?;
                }
                break;
            }

            let mut last_server_seq = cursor;
            for stored in &resp.events {
                let res = {
                    let mut resolver = crate::collab::SecwetResolver { s: &*self };
                    sync::apply_signed_event_with(
                        &self.db,
                        self.secwet_id,
                        stored.server_seq,
                        &stored.event,
                        self.key_epoch,
                        self.k_rec.expose_secret(),
                        &mut resolver,
                    )
                };
                match res {
                    Ok(outcome) => {
                        if outcome == sync::ApplyOutcome::Applied {
                            total_applied += 1;
                        }
                    }
                    Err(Error::Storage) => return Err(Error::Storage),
                    Err(_) => {
                        eprintln!("sync: dropped an event that failed verification");
                        sync::record_event_applied(&self.db, &stored.event.envelope.event_id, stored.server_seq)?;
                        if stored.server_seq > sync::get_sync_cursor(&self.db)? {
                            sync::set_sync_cursor(&self.db, stored.server_seq)?;
                        }
                    }
                }
                last_server_seq = stored.server_seq;
            }

            if last_server_seq > cursor {
                client.ack_events(self.secwet_id, last_server_seq, &self.device_sign_key).await?;
            }

            if !resp.has_more {
                break;
            }
        }

        Ok(total_applied)
    }

    /// Executes a bidirectional synchronization round: push outbox, then pull events.
    pub async fn sync_now(&mut self, client: &crate::relay_client::RelayClient) -> Result<(usize, usize)> {
        let pushed = self.push_outbox(client).await?;
        let pulled = self.pull_and_apply_events(client).await?;
        Ok((pushed, pulled))
    }

    /// Uploads an encrypted workspace snapshot to the relay.
    pub async fn create_and_upload_snapshot(&mut self, client: &crate::relay_client::RelayClient) -> Result<()> {
        if !self.is_owner() || self.unlinked_at()?.is_some() {
            // Member stores hold only their branches; the workspace snapshot
            // is the owner's. Archived stores never upload.
            return Ok(());
        }
        let snapshot = self.collect_snapshot()?;
        let snapshot_bytes = postcard::to_stdvec(&snapshot).map_err(|_| Error::Crypto)?;

        let cursor = sync::get_sync_cursor(&self.db)?;
        let aad = postcard::to_stdvec(&("secwet-snapshot-v1", self.secwet_id, cursor, self.key_epoch))
            .map_err(|_| Error::Crypto)?;

        let (nonce, ciphertext) = crypto::seal_raw_parts(
            self.k_evt.expose_secret(),
            &aad,
            &snapshot_bytes,
        )?;

        let req = secwet_proto::SnapshotUploadRequest {
            server_seq: cursor,
            key_epoch: self.key_epoch,
            nonce,
            ciphertext,
        };

        client.upload_snapshot(self.secwet_id, &req, &self.device_sign_key).await?;
        Ok(())
    }

    /// Restores workspace state from the newest encrypted snapshot on the relay.
    pub async fn catch_up_via_snapshot(&mut self, client: &crate::relay_client::RelayClient) -> Result<()> {
        if !self.is_owner() {
            return Err(Error::Forbidden);
        }
        let snap_resp = client
            .get_snapshot(self.secwet_id, &self.device_sign_key)
            .await?
            .ok_or(Error::NotFound)?;

        let aad = postcard::to_stdvec(&(
            "secwet-snapshot-v1",
            self.secwet_id,
            snap_resp.server_seq,
            snap_resp.key_epoch,
        ))
        .map_err(|_| Error::Crypto)?;

        let snap_key = *self.keyring.evt(snap_resp.key_epoch).ok_or(Error::KeyStore)?;
        let plaintext = crypto::open_raw_parts(
            &snap_key,
            &aad,
            &snap_resp.nonce,
            &snap_resp.ciphertext,
        )?;

        let snapshot: secwet_proto::SecwetSnapshot =
            postcard::from_bytes(&plaintext).map_err(|_| Error::Crypto)?;

        self.restore_from_snapshot(&snapshot, snap_resp.server_seq)?;
        Ok(())
    }

    // ========================================================================
    // Active Sessions Tracking
    // ========================================================================

    pub fn list_active_sessions(&self) -> Result<Vec<secwet_proto::ActiveSession>> {
        crate::sessions::list_active_sessions(&self.db)
    }

    pub fn stop_active_session(&self, session_id: &str) -> Result<()> {
        crate::sessions::stop_session(&self.db, session_id)
    }

    pub fn delete_active_session(&self, session_id: &str) -> Result<()> {
        crate::sessions::delete_active_session(&self.db, session_id)
    }

    pub fn create_active_session(
        &self,
        pid: u32,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        command: &str,
        secret_ids: &[Uuid],
    ) -> Result<secwet_proto::ActiveSession> {
        let session = secwet_proto::ActiveSession {
            session_id: Uuid::now_v7().to_string(),
            pid,
            item_id,
            environment_id,
            command: command.to_string(),
            secret_ids: secret_ids.to_vec(),
            started_at: current_time_ms(),
        };
        crate::sessions::insert_active_session(&self.db, &session)?;
        Ok(session)
    }

    // ========================================================================
    // Sync Helpers for Testing & Offline Catch-up
    // ========================================================================

    pub fn apply_signed_event(&mut self, server_seq: u64, event: &secwet_proto::SignedEvent) -> Result<bool> {
        let mut resolver = crate::collab::SecwetResolver { s: &*self };
        let outcome = crate::sync::apply_signed_event_with(
            &self.db,
            self.secwet_id,
            server_seq,
            event,
            self.key_epoch,
            self.k_rec.expose_secret(),
            &mut resolver,
        )?;
        Ok(outcome == crate::sync::ApplyOutcome::Applied)
    }

    pub fn peek_outbox(&self, limit: usize) -> Result<Vec<secwet_proto::SignedEvent>> {
        crate::sync::peek_outbox(&self.db, limit)
    }

    pub fn delete_outbox_events(&self, up_to_device_seq: u64) -> Result<usize> {
        crate::sync::delete_outbox_events(&self.db, up_to_device_seq)
    }

    pub fn restore_from_snapshot(&mut self, snapshot: &secwet_proto::SecwetSnapshot, server_seq: u64) -> Result<()> {
        let pending_outbox = crate::sync::peek_outbox(&self.db, 10000)?;

        let tx = self.db.transaction().map_err(|_| Error::Storage)?;
        tx.execute("DELETE FROM records", []).map_err(|_| Error::Storage)?;
        tx.execute("DELETE FROM spaces", []).map_err(|_| Error::Storage)?;
        tx.execute("DELETE FROM labels", []).map_err(|_| Error::Storage)?;

        for s in &snapshot.spaces {
            let space_body = secwet_proto::SpaceBody::new(&s.name, s.position, s.icon.clone(), s.is_default);
            let space_bytes = postcard::to_stdvec(&space_body).map_err(|e| {
                eprintln!("restore spaces serialize error: {:?}", e);
                Error::Crypto
            })?;
            let space_aad = RecordAad::new(self.secwet_id.as_bytes(), s.id.as_bytes(), RecordType::Label, self.key_epoch);
            let space_blob = crypto::seal_record(self.k_rec.expose_secret(), &space_aad, &space_bytes).inspect_err(|&e| {
                eprintln!("restore spaces seal error: {:?}", e);
            })?;
            tx.execute(
                "INSERT INTO spaces (id, name_blob, position, created_at, updated_at, deleted) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![s.id.as_bytes().as_slice(), space_blob, s.position as i64, s.created_at, s.updated_at, if s.deleted { 1 } else { 0 }],
            ).map_err(|_| Error::Storage)?;
        }

        for l in &snapshot.labels {
            let label_body = secwet_proto::LabelBody::with_space(&l.name, l.position, l.icon.clone(), l.space_id);
            let label_bytes = postcard::to_stdvec(&label_body).map_err(|e| {
                eprintln!("restore labels serialize error: {:?}", e);
                Error::Crypto
            })?;
            let label_aad = RecordAad::new(self.secwet_id.as_bytes(), l.id.as_bytes(), RecordType::Label, self.key_epoch);
            let label_blob = crypto::seal_record(self.k_rec.expose_secret(), &label_aad, &label_bytes).inspect_err(|&e| {
                eprintln!("restore labels seal error: {:?}", e);
            })?;
            tx.execute(
                "INSERT INTO labels (id, name_blob, position, created_at, updated_at, deleted) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![l.id.as_bytes().as_slice(), label_blob, l.position as i64, l.created_at, l.updated_at, if l.deleted { 1 } else { 0 }],
            ).map_err(|_| Error::Storage)?;
        }

        for item in &snapshot.items {
            let item_body = secwet_proto::ItemBody::new(item.label_id, &item.name, item.description.clone(), item.position);
            let item_bytes = postcard::to_stdvec(&item_body).map_err(|e| {
                eprintln!("restore items serialize error: {:?}", e);
                Error::Crypto
            })?;
            let item_aad = RecordAad::new(self.secwet_id.as_bytes(), item.id.as_bytes(), RecordType::Item, self.key_epoch);
            let item_blob = crypto::seal_record(self.k_rec.expose_secret(), &item_aad, &item_bytes).inspect_err(|&e| {
                eprintln!("restore items seal error: {:?}", e);
            })?;
            let record_row = RecordRow {
                id: item.id,
                record_type: RecordType::Item,
                parent_id: Some(item.label_id),
                key_epoch: self.key_epoch,
                blob: Some(item_blob),
                lamport: item.lamport,
                origin_device: item.origin_device.clone(),
                updated_at: item.updated_at,
                deleted: item.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        for env in &snapshot.environments {
            let env_body = secwet_proto::EnvironmentBody::new(env.item_id, &env.name, env.position);
            let env_bytes = postcard::to_stdvec(&env_body).map_err(|e| {
                eprintln!("restore envs serialize error: {:?}", e);
                Error::Crypto
            })?;
            let env_aad = RecordAad::new(self.secwet_id.as_bytes(), env.id.as_bytes(), RecordType::Environment, self.key_epoch);
            let env_blob = crypto::seal_record(self.k_rec.expose_secret(), &env_aad, &env_bytes).inspect_err(|&e| {
                eprintln!("restore envs seal error: {:?}", e);
            })?;
            let record_row = RecordRow {
                id: env.id,
                record_type: RecordType::Environment,
                parent_id: Some(env.item_id),
                key_epoch: self.key_epoch,
                blob: Some(env_blob),
                lamport: env.lamport,
                origin_device: env.origin_device.clone(),
                updated_at: env.updated_at,
                deleted: env.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        for sec in &snapshot.secrets {
            let sec_body = secwet_proto::SecretBody::new(
                sec.item_id,
                sec.environment_id,
                &sec.name,
                sec.kind,
                &sec.value,
                sec.note.clone(),
            );
            let sec_bytes = postcard::to_stdvec(&sec_body).map_err(|e| {
                eprintln!("restore secrets serialize error: {:?}", e);
                Error::Crypto
            })?;
            let sec_aad = RecordAad::new(self.secwet_id.as_bytes(), sec.id.as_bytes(), RecordType::Secret, self.key_epoch);
            let sec_blob = crypto::seal_record(self.k_rec.expose_secret(), &sec_aad, &sec_bytes).inspect_err(|&e| {
                eprintln!("restore secrets seal error: {:?}", e);
            })?;
            let record_row = RecordRow {
                id: sec.id,
                record_type: RecordType::Secret,
                parent_id: sec.environment_id.or(Some(sec.item_id)),
                key_epoch: self.key_epoch,
                blob: Some(sec_blob),
                lamport: sec.lamport,
                origin_device: sec.origin_device.clone(),
                updated_at: sec.updated_at,
                deleted: sec.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        for note in &snapshot.notes {
            let note_body = secwet_proto::NoteBody::new(
                note.item_id,
                note.environment_id,
                &note.title,
                &note.content,
                note.position,
            );
            let note_bytes = postcard::to_stdvec(&note_body).map_err(|_| Error::Crypto)?;
            let note_aad = RecordAad::new(self.secwet_id.as_bytes(), note.id.as_bytes(), RecordType::Note, self.key_epoch);
            let note_blob = crypto::seal_record(self.k_rec.expose_secret(), &note_aad, &note_bytes)?;
            let record_row = RecordRow {
                id: note.id,
                record_type: RecordType::Note,
                parent_id: note.environment_id.or(Some(note.item_id)),
                key_epoch: self.key_epoch,
                blob: Some(note_blob),
                lamport: note.lamport,
                origin_device: note.origin_device.clone(),
                updated_at: note.updated_at,
                deleted: note.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        for file in &snapshot.files {
            let meta = secwet_proto::AssetMetaBody::new(
                file.item_id,
                file.environment_id,
                &file.name,
                file.size_bytes,
                &file.mime_type,
                file.sha256,
            );
            let payload = secwet_proto::AssetPayload::new(meta, file.data.clone());
            let file_bytes = postcard::to_stdvec(&payload).map_err(|_| Error::Crypto)?;
            let file_aad = RecordAad::new(self.secwet_id.as_bytes(), file.id.as_bytes(), RecordType::Asset, self.key_epoch);
            let file_blob = crypto::seal_record(self.k_rec.expose_secret(), &file_aad, &file_bytes)?;
            let record_row = RecordRow {
                id: file.id,
                record_type: RecordType::Asset,
                parent_id: file.environment_id.or(Some(file.item_id)),
                key_epoch: self.key_epoch,
                blob: Some(file_blob),
                lamport: file.lamport,
                origin_device: file.origin_device.clone(),
                updated_at: file.updated_at,
                deleted: file.deleted,
            };
            insert_record(&tx, &record_row)?;
        }

        tx.execute(
            "INSERT INTO sync_state (key, value) VALUES ('cursor', ?1)
             ON CONFLICT(key) DO UPDATE SET value = ?1",
            rusqlite::params![server_seq.to_string()],
        ).map_err(|_| Error::Storage)?;

        tx.commit().map_err(|_| Error::Storage)?;

        for event in pending_outbox {
            let _ = crate::sync::enqueue_outbox(&self.db, &event);
        }

        Ok(())
    }
}


impl Drop for Secwet {
    fn drop(&mut self) {
        self.zeroize_all_keys();
        if let Ok(mut guard) = ACTIVE_SESSIONS.lock() {
            guard.remove(&self.secwet_id);
        }
    }
}
