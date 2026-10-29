//! Revocation, master key rotation (F16, M7) and collaboration with
//! cryptographically scoped tree-wise roles (F19, M8).
//!
//! Design: `docs/m7-m8-architecture.md`. Wire types: `secwet_proto::collab`.
//!
//! Invariants:
//! - A remote wipe only runs after the signed directive verifies against a
//!   known device key; the relay alone can never trigger it.
//! - Revoked devices are never recipients of a new master key or branch key.
//! - Branch keys leave a device only HPKE-wrapped; member stores never hold
//!   the workspace master key.
//! - Key material lives in `Zeroizing` buffers and the OS keystore only.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;
use rand_core::Rng;
use rusqlite::{params, Connection, OptionalExtension};
use secrecy::ExposeSecret;
use secwet_proto::{
    AcceptInvitationRequest, BranchKeyBundle, BranchKeyEntry, BranchKeyKind,
    BranchPublishStatement, DeviceWrappedKey, EventBody, EventEnvelope, EventScope,
    InvitationStatus, InviteCollaboratorRequest, KeyRotationRequest, KeyRotationStatement,
    KeyWrapInfo, MemberGrant, MemberGrantSet, PublishBranchKeysRequest, RecordAad,
    RecordPayload, RecordType, RemoveMemberRequest, RevocationDirective, RevokeRequest,
    ScopeOp, ScopeTarget, ScopedBranchKey, SignedGrantSet, SignedRevocation, SpaceBody,
    TreeNode, TreeRole, UpdateMemberGrantsRequest,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, OsRng};
use crate::keys::KeyStore;
use crate::records::{self, get_meta, set_meta};
use crate::relay_client::RelayClient;
use crate::secwet::Secwet;
use crate::sync;
use crate::{Error, Result};

const INVITE_LINK_SCHEME: &str = "secwet://invite";
const BRANCH_BUNDLE_PURPOSE: &str = "secwet/v1/branch-bundle";
const MASTER_KEY_PURPOSE: &str = "secwet/v1/master-key";

pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ============================================================================
// Local schema
// ============================================================================

/// Creates the collaboration tables. Idempotent; runs after every migration.
pub(crate) fn init_collab_tables(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS collab_branches (
            space_id BLOB NOT NULL,
            epoch INTEGER NOT NULL,
            received_at INTEGER NOT NULL,
            PRIMARY KEY (space_id, epoch)
         );
         CREATE TABLE IF NOT EXISTS collab_members (
            member_id BLOB PRIMARY KEY,
            email_blob BLOB,
            grants BLOB NOT NULL,
            status TEXT NOT NULL,
            invitation_id BLOB,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS collab_invitations (
            invitation_id BLOB PRIMARY KEY,
            member_id BLOB NOT NULL,
            secret_blob BLOB NOT NULL,
            status TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS collab_dirty_spaces (
            space_id BLOB PRIMARY KEY
         );",
    )
    .map_err(|_| Error::Storage)?;

    add_column_if_missing(conn, "devices", "member_id", "BLOB")?;
    // Trust level: 'self', 'certified' (pairing, verified invite, signed
    // certificate or bundle admin list) or 'relay' (listed by the relay only;
    // never receives keys, never issues wipes, never counts as an owner).
    add_column_if_missing(conn, "devices", "trust", "TEXT NOT NULL DEFAULT 'relay'")?;
    add_column_if_missing(conn, "devices", "revoked_seq", "INTEGER")?;
    add_column_if_missing(conn, "collab_branches", "digest", "BLOB")?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS collab_deferred (
            server_seq INTEGER PRIMARY KEY,
            envelope BLOB NOT NULL,
            deferred_at INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS collab_pending (
            kind TEXT NOT NULL,
            space_id BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (kind, space_id)
         );
         CREATE TABLE IF NOT EXISTS collab_pending_emit (
            record_id BLOB PRIMARY KEY,
            record_type INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS collab_cert_outbox (
            device_id TEXT PRIMARY KEY,
            certificate BLOB NOT NULL
         );
         CREATE TABLE IF NOT EXISTS collab_scopes (
            space_id BLOB PRIMARY KEY,
            current_epoch INTEGER NOT NULL
         );",
    )
    .map_err(|_| Error::Storage)?;
    // Stores created before trust levels existed cannot tell paired devices
    // from relay-mirrored ones, so only this device is trusted; the others
    // re-certify themselves with workspace-key-sealed certificates on their
    // next sync.
    if get_meta(conn, "trust_levels_migrated")?.is_none() {
        if let Some(me) = get_meta(conn, "device_id")? {
            conn.execute("UPDATE devices SET trust = 'self' WHERE device_id = ?1", params![me])
                .map_err(|_| Error::Storage)?;
        }
        set_meta(conn, "trust_levels_migrated", "1")?;
    }
    Ok(())
}

fn add_column_if_missing(conn: &Connection, table: &str, column: &str, decl: &str) -> Result<()> {
    let exists: bool = conn
        .prepare(&format!("PRAGMA table_info({table})"))
        .and_then(|mut stmt| {
            let mut rows = stmt.query([])?;
            let mut found = false;
            while let Some(row) = rows.next()? {
                let name: String = row.get(1)?;
                if name == column {
                    found = true;
                }
            }
            Ok(found)
        })
        .unwrap_or(false);
    if !exists {
        conn.execute(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"), [])
            .map_err(|_| Error::Storage)?;
    }
    Ok(())
}

// ============================================================================
// Keyring
// ============================================================================

/// Store keys derived from one master key epoch.
pub(crate) struct EpochKeys {
    pub rec: Zeroizing<[u8; 32]>,
    pub evt: Zeroizing<[u8; 32]>,
}

/// A branch key bundle held by this device.
pub(crate) struct HeldEntry {
    pub path: Vec<Uuid>,
    pub kind: BranchKeyKind,
    pub key: Zeroizing<[u8; 32]>,
}

pub(crate) struct HeldBundle {
    pub entries: Vec<HeldEntry>,
}

impl HeldBundle {
    fn from_proto(mut b: BranchKeyBundle) -> Self {
        let entries = b
            .entries
            .iter_mut()
            .map(|e| {
                let held = HeldEntry {
                    path: e.path.clone(),
                    kind: e.kind,
                    key: Zeroizing::new(e.key),
                };
                e.key.zeroize();
                held
            })
            .collect();
        HeldBundle { entries }
    }

    fn root(&self, space_id: Uuid) -> Option<&Zeroizing<[u8; 32]>> {
        self.entries
            .iter()
            .find(|e| e.kind == BranchKeyKind::Subtree && e.path == [space_id])
            .map(|e| &e.key)
    }
}

/// All key material the unlocked store holds in memory.
#[derive(Default)]
pub(crate) struct Keyring {
    pub epochs: BTreeMap<u32, EpochKeys>,
    pub branches: HashMap<Uuid, BTreeMap<u32, HeldBundle>>,
}

impl Keyring {
    pub fn with_epoch(_secwet_id: &Uuid, epoch: u32, rec: &[u8; 32], evt: &[u8; 32]) -> Self {
        let mut ring = Keyring::default();
        ring.epochs.insert(
            epoch,
            EpochKeys {
                rec: Zeroizing::new(*rec),
                evt: Zeroizing::new(*evt),
            },
        );
        ring
    }

    pub fn insert_master(&mut self, epoch: u32, k_m: &[u8; 32], secwet_id: &Uuid) {
        let (rec, evt) = crypto::derive_keys(k_m, secwet_id);
        self.epochs.insert(epoch, EpochKeys { rec, evt });
    }

    pub fn rec(&self, epoch: u32) -> Option<&[u8; 32]> {
        self.epochs.get(&epoch).map(|k| &*k.rec)
    }

    pub fn evt(&self, epoch: u32) -> Option<&[u8; 32]> {
        self.epochs.get(&epoch).map(|k| &*k.evt)
    }

    pub fn clear(&mut self) {
        self.epochs.clear();
        self.branches.clear();
    }

    /// Highest branch epoch held for a space.
    pub fn branch_epoch(&self, space_id: Uuid) -> Option<u32> {
        self.branches
            .get(&space_id)
            .and_then(|m| m.keys().next_back().copied())
    }

    /// Event key named by a scope at an epoch, if this device can derive it.
    pub fn branch_target_key(
        &self,
        secwet_id: &Uuid,
        scope: &EventScope,
        epoch: u32,
    ) -> Option<Zeroizing<[u8; 32]>> {
        let bundle = self.branches.get(&scope.space_id)?.get(&epoch)?;
        let mut full = Vec::with_capacity(scope.path.len() + 1);
        full.push(scope.space_id);
        full.extend_from_slice(&scope.path);

        let direct_kind = match scope.target {
            ScopeTarget::Name => Some(BranchKeyKind::Name),
            ScopeTarget::General => Some(BranchKeyKind::General),
            ScopeTarget::Content => None,
        };
        if let Some(kind) = direct_kind {
            if let Some(e) = bundle.entries.iter().find(|e| e.kind == kind && e.path == full) {
                return Some(Zeroizing::new(*e.key));
            }
        }

        // Longest subtree prefix, then derive downwards.
        let subtree = bundle
            .entries
            .iter()
            .filter(|e| e.kind == BranchKeyKind::Subtree && full.starts_with(&e.path))
            .max_by_key(|e| e.path.len())?;
        let mut node = Zeroizing::new(*subtree.key);
        for id in &full[subtree.path.len()..] {
            node = derive_branch_child(&node, secwet_id, id);
        }
        Some(match scope.target {
            ScopeTarget::Name => derive_branch_purpose(&node, secwet_id, b"secwet/v1/branch/name"),
            ScopeTarget::General => derive_branch_purpose(&node, secwet_id, b"secwet/v1/branch/general"),
            ScopeTarget::Content => derive_branch_purpose(&node, secwet_id, b"secwet/v1/branch/content"),
        })
    }
}

impl Drop for Keyring {
    fn drop(&mut self) {
        self.clear();
    }
}

/// Opens a record with any known epoch key; see `Secwet::open_rec`.
///
/// Only an AAD naming the current epoch falls back to older epochs: that is
/// how callers address `labels`, `spaces` and device names, which carry no
/// epoch column. An AAD naming any other epoch comes from a row's own
/// `key_epoch` and must match exactly, so tampering with it still fails.
pub(crate) fn open_rec_with(ring: &Keyring, aad: &RecordAad, blob: &[u8]) -> Result<Vec<u8>> {
    if let Some(k) = ring.rec(aad.key_epoch) {
        if let Ok(pt) = crypto::open_record(k, aad, blob) {
            return Ok(pt);
        }
    }
    let current = ring.epochs.keys().next_back().copied();
    if current != Some(aad.key_epoch) {
        return Err(Error::Crypto);
    }
    for (epoch, keys) in ring.epochs.iter().rev() {
        if *epoch == aad.key_epoch {
            continue;
        }
        let mut alt = *aad;
        alt.key_epoch = *epoch;
        if let Ok(pt) = crypto::open_record(&keys.rec, &alt, blob) {
            return Ok(pt);
        }
    }
    Err(Error::Crypto)
}

/// Writes a master key epoch under the §4.1 entry name `master-key/<epoch>`.
/// Readers also accept the legacy `vault-key/<epoch>` name of earlier builds.
pub fn store_master_key(keystore: &dyn KeyStore, secwet_id: &Uuid, epoch: u32, key: &[u8; 32]) -> Result<()> {
    keystore.set(&format!("secwet/{secwet_id}/master-key/{epoch}"), key)
}

/// Reads a master key epoch, preferring the §4.1 name.
pub fn load_master_key(keystore: &dyn KeyStore, secwet_id: &Uuid, epoch: u32) -> Result<Option<crate::SecretVec<u8>>> {
    match keystore.get(&format!("secwet/{secwet_id}/master-key/{epoch}"))? {
        Some(k) => Ok(Some(k)),
        None => keystore.get(&format!("secwet/{secwet_id}/vault-key/{epoch}")),
    }
}

pub(crate) fn derive_branch_child(parent: &[u8; 32], secwet_id: &Uuid, child: &Uuid) -> Zeroizing<[u8; 32]> {
    let mut info = b"secwet/v1/branch/node".to_vec();
    info.extend_from_slice(child.as_bytes());
    crypto::derive_hkdf_sha256(parent, secwet_id.as_bytes(), &info)
}

pub(crate) fn derive_branch_purpose(node: &[u8; 32], secwet_id: &Uuid, info: &[u8]) -> Zeroizing<[u8; 32]> {
    crypto::derive_hkdf_sha256(node, secwet_id.as_bytes(), info)
}

fn derive_path_secret(root: &[u8; 32], secwet_id: &Uuid, below_space: &[Uuid]) -> Zeroizing<[u8; 32]> {
    let mut node = Zeroizing::new(*root);
    for id in below_space {
        node = derive_branch_child(&node, secwet_id, id);
    }
    node
}

/// Signing key, membership, trust and revocation of a revocation issuer.
type IssuerRow = (Vec<u8>, Option<Vec<u8>>, String, Option<i64>);

/// Commitment to a master key, signed in rotation statements.
pub(crate) fn key_commitment(k_m: &[u8; 32], secwet_id: &Uuid) -> Zeroizing<[u8; 32]> {
    crypto::derive_hkdf_sha256(k_m, secwet_id.as_bytes(), b"secwet/v1/key-commit")
}

fn random_key() -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *k);
    k
}

// ============================================================================
// Invitation helpers
// ============================================================================

/// Email hash for invitation matching, keyed with the invite token so the
/// relay (which never learns the token) cannot test guesses against it.
pub fn email_hash(token: &[u8; 32], invitation_id: &Uuid, email: &str) -> [u8; 32] {
    let mut info = b"secwet/v1/invite-email".to_vec();
    info.extend_from_slice(email.trim().to_lowercase().as_bytes());
    *crypto::derive_hkdf_sha256(token, invitation_id.as_bytes(), &info)
}

fn invite_auth(token: &[u8; 32], invitation_id: &Uuid) -> Zeroizing<[u8; 32]> {
    crypto::derive_hkdf_sha256(token, invitation_id.as_bytes(), b"secwet/v1/invite-auth")
}

fn invite_binding(token: &[u8; 32], invitation_id: &Uuid, sign_pub: &[u8; 32], enc_pub: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut info = b"secwet/v1/invite-binding".to_vec();
    info.extend_from_slice(sign_pub);
    info.extend_from_slice(enc_pub);
    crypto::derive_hkdf_sha256(token, invitation_id.as_bytes(), &info)
}

/// Parsed `secwet://invite` link.
pub struct InviteLink {
    pub secwet_id: Uuid,
    pub invitation_id: Uuid,
    pub token: Zeroizing<[u8; 32]>,
    pub relay_url: String,
    /// The inviting device. The invitee trusts it from the link (the same
    /// out-of-band channel that carries the token), never from the relay.
    pub inviter: secwet_proto::TrustedDevice,
    /// Set when the inviter is a member admin rather than an owner device.
    pub inviter_member: Option<Uuid>,
}

impl std::fmt::Debug for InviteLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteLink")
            .field("secwet_id", &self.secwet_id)
            .field("invitation_id", &self.invitation_id)
            .field("token", &"[redacted]")
            .finish()
    }
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn percent_decode(s: &str) -> Option<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = s.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

pub fn format_invite_link(
    secwet_id: &Uuid,
    invitation_id: &Uuid,
    token: &[u8; 32],
    relay_url: &str,
    inviter: &secwet_proto::TrustedDevice,
    inviter_member: Option<Uuid>,
) -> String {
    let b = |x: &[u8]| data_encoding::BASE64URL_NOPAD.encode(x);
    let mut link = format!(
        "{INVITE_LINK_SCHEME}?v=1&w={}&i={}&t={}&r={}&a={}&s={}&e={}",
        secwet_id,
        invitation_id,
        b(token),
        percent_encode(relay_url),
        inviter.device_id,
        b(&inviter.sign_pub),
        b(&inviter.enc_pub),
    );
    if let Some(m) = inviter_member {
        link.push_str(&format!("&m={m}"));
    }
    link
}

pub fn parse_invite_link(link: &str) -> Result<InviteLink> {
    let invalid = || Error::Invalid {
        field: "link",
        message: "This invite link isn't valid.".into(),
    };
    let rest = link.trim().strip_prefix(INVITE_LINK_SCHEME).ok_or_else(invalid)?;
    let query = rest.strip_prefix('?').ok_or_else(invalid)?;
    let mut fields: HashMap<&str, &str> = HashMap::new();
    for pair in query.split('&') {
        let (k, v) = pair.split_once('=').ok_or_else(invalid)?;
        fields.insert(k, v);
    }
    if fields.get("v") != Some(&"1") {
        return Err(invalid());
    }
    let b32 = |k: &str| -> Result<[u8; 32]> {
        let v = data_encoding::BASE64URL_NOPAD
            .decode(fields.get(k).ok_or_else(invalid)?.as_bytes())
            .map_err(|_| invalid())?;
        <[u8; 32]>::try_from(v.as_slice()).map_err(|_| invalid())
    };
    let secwet_id = Uuid::parse_str(fields.get("w").ok_or_else(invalid)?).map_err(|_| invalid())?;
    let invitation_id = Uuid::parse_str(fields.get("i").ok_or_else(invalid)?).map_err(|_| invalid())?;
    let token = Zeroizing::new(b32("t")?);
    let relay_url = percent_decode(fields.get("r").ok_or_else(invalid)?).ok_or_else(invalid)?;
    if !(relay_url.starts_with("https://") || relay_url.starts_with("http://")) {
        return Err(invalid());
    }
    let inviter = secwet_proto::TrustedDevice {
        device_id: fields.get("a").ok_or_else(invalid)?.to_string(),
        sign_pub: b32("s")?,
        enc_pub: b32("e")?,
    };
    if crypto::compute_device_id(&inviter.sign_pub) != inviter.device_id {
        return Err(invalid());
    }
    let inviter_member = match fields.get("m") {
        Some(m) => Some(Uuid::parse_str(m).map_err(|_| invalid())?),
        None => None,
    };
    Ok(InviteLink {
        secwet_id,
        invitation_id,
        token,
        relay_url,
        inviter,
        inviter_member,
    })
}

fn validate_email(email: &str) -> Result<String> {
    let e = email.trim().to_lowercase();
    let ok = e.len() <= 254
        && e.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
        })
        && !e.chars().any(char::is_whitespace);
    if ok {
        Ok(e)
    } else {
        Err(Error::Invalid {
            field: "email",
            message: "Enter a valid email address.".into(),
        })
    }
}

// ============================================================================
// Public result types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRotationReport {
    pub previous_epoch: u32,
    pub epoch: u32,
    pub resealed: usize,
    pub recipients: usize,
    pub adopted_from_conflict: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyStatus {
    pub epoch: u32,
    pub rotated_at: Option<i64>,
    pub rotation_recommended: bool,
    pub pending_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationOutcome {
    /// Keys crypto-shredded and the local store deleted. Drop the `Secwet`.
    Wiped,
    /// Store kept as a read-only archive; sync disabled.
    Archived,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteResult {
    pub invitation_id: Uuid,
    pub member_id: Uuid,
    pub link: String,
    pub expires_at: i64,
}

impl std::fmt::Debug for InviteResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InviteResult")
            .field("invitation_id", &self.invitation_id)
            .field("member_id", &self.member_id)
            .field("link", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDeviceInfo {
    pub id: String,
    pub fingerprint: String,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberInfo {
    pub member_id: Uuid,
    pub email: Option<String>,
    /// `invited`, `accepted`, `active`, `removed` or `expired`.
    pub status: String,
    pub grants: Vec<MemberGrant>,
    pub devices: Vec<MemberDeviceInfo>,
    pub invited_at: i64,
    pub invitation_id: Option<Uuid>,
}

/// A node of a space's tree, for scope pickers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeNode {
    pub node: TreeNode,
    pub label: String,
    pub depth: u8,
    pub parent: Option<TreeNode>,
}

/// Where a write lands, for local role checks.
#[derive(Debug, Clone, Copy)]
pub(crate) enum WriteTarget {
    /// Create, rename or delete a space.
    Space(Option<Uuid>),
    /// Create a group in, or change a group of, a space.
    Group { space: Option<Uuid> },
    /// Create in, or change an item of, a group.
    Item { group: Uuid },
    /// Create in, or change an environment of, an item.
    Environment { item: Uuid },
    /// Write a secret, file or note.
    Content { item: Uuid, env: Option<Uuid>, delete: bool },
    /// Change an existing content record by id.
    ContentRecord { id: Uuid, delete: bool },
}

// ============================================================================
// impl Secwet: keyring helpers
// ============================================================================

impl Secwet {
    /// Opens a sealed record, trying the epoch named in the AAD first and then
    /// every other known epoch (newest first). Rows of `labels`, `spaces` and
    /// device names carry no epoch column, so this is how they stay readable
    /// while a re-seal is in progress.
    pub(crate) fn open_rec(&self, aad: &RecordAad, blob: &[u8]) -> Result<Vec<u8>> {
        open_rec_with(&self.keyring, aad, blob)
    }

    /// Opens a sealed record and also reports the epoch that opened it.
    fn open_rec_epoch(&self, aad: &RecordAad, blob: &[u8]) -> Result<(Vec<u8>, u32)> {
        for (epoch, keys) in self.keyring.epochs.iter().rev() {
            let mut alt = *aad;
            alt.key_epoch = *epoch;
            if let Ok(pt) = crypto::open_record(&keys.rec, &alt, blob) {
                return Ok((pt, *epoch));
            }
        }
        Err(Error::Crypto)
    }

    /// Device names are sealed with the store key and the device id as AAD.
    pub(crate) fn unseal_device_name_any(&self, device_id: &str, blob: &[u8]) -> Result<String> {
        for keys in self.keyring.epochs.values().rev() {
            if let Ok(name) = crate::secwet::unseal_device_name(&keys.rec, device_id, blob) {
                return Ok(name);
            }
        }
        Err(Error::Crypto)
    }

    /// Loads every master key epoch present in the keystore.
    pub(crate) fn load_keyring(keystore: &dyn KeyStore, secwet_id: &Uuid, current: u32) -> Result<Keyring> {
        let mut ring = Keyring::default();
        for epoch in 1..=current {
            let entry = load_master_key(keystore, secwet_id, epoch)?;
            if let Some(v) = entry {
                if v.len() == 32 {
                    let mut k = Zeroizing::new([0u8; 32]);
                    k.copy_from_slice(v.as_slice());
                    ring.insert_master(epoch, &k, secwet_id);
                }
            }
        }
        if ring.rec(current).is_none() {
            return Err(Error::KeyStore);
        }
        Ok(ring)
    }

    /// Loads branch bundles listed in `collab_branches` from the keystore.
    pub(crate) fn load_branch_bundles(&mut self, keystore: &dyn KeyStore) -> Result<()> {
        let rows: Vec<(Vec<u8>, i64)> = {
            let mut stmt = self
                .db
                .prepare("SELECT space_id, epoch FROM collab_branches")
                .map_err(|_| Error::Storage)?;
            let it = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|_| Error::Storage)?;
            it.collect::<std::result::Result<_, _>>().map_err(|_| Error::Storage)?
        };
        for (space, epoch) in rows {
            let space_id = Uuid::from_slice(&space).map_err(|_| Error::Storage)?;
            let entry = format!("secwet/{}/branch-bundle/{}/{}", self.secwet_id, space_id, epoch);
            if let Some(bytes) = keystore.get(&entry)? {
                let bundle: BranchKeyBundle = postcard::from_bytes(bytes.as_slice()).map_err(|_| Error::KeyStore)?;
                if bundle.space_id == space_id && bundle.epoch as i64 == epoch && bundle.secwet_id == self.secwet_id {
                    self.keyring
                        .branches
                        .entry(space_id)
                        .or_default()
                        .insert(bundle.epoch, HeldBundle::from_proto(bundle));
                }
            }
        }
        Ok(())
    }

    /// Whether this store belongs to the workspace owner (holds the master key).
    pub fn is_owner(&self) -> bool {
        self.member_id.is_none()
    }

    pub fn member_id(&self) -> Option<Uuid> {
        self.member_id
    }

    // ========================================================================
    // M7: revocation state
    // ========================================================================

    /// `Some(revoked_at)` when this device was unlinked with "Revoke sync only".
    pub fn unlinked_at(&self) -> Result<Option<i64>> {
        match get_meta(&self.db, "revoked_state")?.as_deref() {
            Some("sync_only") => Ok(Some(
                get_meta(&self.db, "revoked_at")?
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0),
            )),
            _ => Ok(None),
        }
    }

    /// Fails with `Error::Revoked` when the store is a read-only archive.
    pub(crate) fn ensure_writable(&self) -> Result<()> {
        if self.unlinked_at()?.is_some() {
            return Err(Error::Revoked);
        }
        Ok(())
    }

    /// Local role check before a write (F19). Owner stores only check the
    /// archive state; member stores also check their signed grants.
    pub(crate) fn guard_write(&self, target: WriteTarget) -> Result<()> {
        self.ensure_writable()?;
        if self.is_owner() {
            return Ok(());
        }
        let (space, nodes, needed) = match target {
            WriteTarget::Space(id) => match id {
                // Members create spaces only in their own local store.
                None => return Ok(()),
                Some(s) => (Some(s), vec![TreeNode::Workspace, TreeNode::Space(s)], TreeRole::Admin),
            },
            WriteTarget::Group { space } => match space {
                None => return Ok(()),
                Some(s) => (Some(s), vec![TreeNode::Workspace, TreeNode::Space(s)], TreeRole::Admin),
            },
            WriteTarget::Item { group } => {
                let (s, nodes) = self.group_nodes(group)?;
                (s, nodes, TreeRole::Admin)
            }
            WriteTarget::Environment { item } => {
                let (s, nodes) = self.item_nodes(item)?;
                (s, nodes, TreeRole::Admin)
            }
            WriteTarget::Content { item, env, delete } => {
                let (s, mut nodes) = self.item_nodes(item)?;
                nodes.push(match env {
                    Some(e) => TreeNode::Environment(e),
                    None => TreeNode::General(item),
                });
                (s, nodes, if delete { TreeRole::Admin } else { TreeRole::Editor })
            }
            WriteTarget::ContentRecord { id, delete } => {
                let row = records::get_record(&self.db, id)?.ok_or(Error::NotFound)?;
                let parent = row.parent_id.ok_or(Error::NotFound)?;
                let parent_row = records::get_record(&self.db, parent)?.ok_or(Error::NotFound)?;
                let (item, env) = if parent_row.record_type == RecordType::Environment {
                    (parent_row.parent_id.ok_or(Error::NotFound)?, Some(parent))
                } else {
                    (parent, None)
                };
                return self.guard_write(WriteTarget::Content { item, env, delete });
            }
        };
        match space {
            Some(s) if self.is_space_shared(s) => {
                if secwet_proto::effective_role(&self.my_grants(), &nodes) >= needed {
                    Ok(())
                } else {
                    Err(Error::Forbidden)
                }
            }
            // A member's own local spaces are never shared.
            _ => Ok(()),
        }
    }

    fn group_nodes(&self, group: Uuid) -> Result<(Option<Uuid>, Vec<TreeNode>)> {
        let label = records::get_label(&self.db, group)?.ok_or(Error::NotFound)?;
        let mut nodes = vec![TreeNode::Workspace];
        if let Some(s) = label.space_id {
            nodes.push(TreeNode::Space(s));
        }
        nodes.push(TreeNode::Group(group));
        Ok((label.space_id, nodes))
    }

    fn item_nodes(&self, item: Uuid) -> Result<(Option<Uuid>, Vec<TreeNode>)> {
        let row = records::get_record(&self.db, item)?.ok_or(Error::NotFound)?;
        let group = row.parent_id.ok_or(Error::NotFound)?;
        let (space, mut nodes) = self.group_nodes(group)?;
        nodes.push(TreeNode::Item(item));
        Ok((space, nodes))
    }

    /// Grants of this member store (empty for owner stores).
    pub fn my_grants(&self) -> Vec<MemberGrant> {
        get_meta(&self.db, "my_grants")
            .ok()
            .flatten()
            .and_then(|hex| data_encoding::HEXLOWER.decode(hex.as_bytes()).ok())
            .and_then(|b| postcard::from_bytes::<SignedGrantSet>(&b).ok())
            .map(|s| s.set.grants)
            .unwrap_or_default()
    }

    pub fn is_space_shared(&self, space_id: Uuid) -> bool {
        self.keyring.branches.contains_key(&space_id)
            || self
                .db
                .query_row(
                    "SELECT 1 FROM collab_scopes WHERE space_id = ?1 LIMIT 1",
                    params![space_id.as_bytes().as_slice()],
                    |_| Ok(()),
                )
                .optional()
                .ok()
                .flatten()
                .is_some()
            || self
                .db
                .query_row(
                    "SELECT 1 FROM collab_branches WHERE space_id = ?1 LIMIT 1",
                    params![space_id.as_bytes().as_slice()],
                    |_| Ok(()),
                )
                .optional()
                .ok()
                .flatten()
                .is_some()
    }

    pub fn key_status(&self) -> Result<KeyStatus> {
        Ok(KeyStatus {
            epoch: self.key_epoch,
            rotated_at: get_meta(&self.db, "key_rotated_at")?.and_then(|v| v.parse().ok()),
            rotation_recommended: get_meta(&self.db, "rotation_recommended")?.as_deref() == Some("1"),
            pending_reason: get_meta(&self.db, "rotation_reason")?.filter(|s| !s.is_empty()),
        })
    }

    // ========================================================================
    // M7: devices from the relay
    // ========================================================================

    /// Mirrors the relay's device list into the local `devices` table.
    ///
    /// The relay is not trusted to say who belongs to the workspace: devices
    /// it lists that this store has never seen are recorded with trust
    /// `relay`, which lets their signatures be checked but never makes them
    /// key recipients, wipe issuers or owners. Existing rows only ever gain
    /// revocations; their keys, membership and trust never change here.
    pub async fn refresh_devices_from_relay(&mut self, client: &RelayClient) -> Result<secwet_proto::DeviceListResponse> {
        let list = client.list_devices(self.secwet_id, &self.device_sign_key).await?;
        let rec = *self.k_rec.expose_secret();
        for d in &list.devices {
            let exists: Option<i64> = self
                .db
                .query_row("SELECT 1 FROM devices WHERE device_id = ?1", params![d.id], |r| r.get(0))
                .optional()
                .map_err(|_| Error::Storage)?;
            if exists.is_none() {
                if crypto::compute_device_id(&d.sign_pub) != d.id {
                    continue;
                }
                let name_blob = crate::secwet::seal_device_name(&rec, &d.id, "Device")?;
                self.db
                    .execute(
                        "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, member_id, trust, revoked_seq)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?5, NULL, 'relay', ?7)",
                        params![d.id, name_blob, d.sign_pub.as_slice(), d.enc_pub.as_slice(), d.added_at, d.revoked_at, d.revoked_seq.map(|v| v as i64)],
                    )
                    .map_err(|_| Error::Storage)?;
            } else if d.revoked_at.is_some() {
                self.db
                    .execute(
                        "UPDATE devices SET revoked_at = COALESCE(revoked_at, ?2),
                             revoked_seq = COALESCE(revoked_seq, ?3)
                         WHERE device_id = ?1",
                        params![d.id, d.revoked_at, d.revoked_seq.map(|v| v as i64)],
                    )
                    .map_err(|_| Error::Storage)?;
            }
        }
        Ok(list)
    }

    /// Records a device as trusted (pairing, verified invite, signed
    /// certificate or a verified bundle admin list). A device id is the hash
    /// of its signing key, so a mismatching key is rejected.
    pub(crate) fn certify_device(
        &mut self,
        device_id: &str,
        sign_pub: &[u8; 32],
        enc_pub: &[u8; 32],
        member_id: Option<Uuid>,
    ) -> Result<bool> {
        if crypto::compute_device_id(sign_pub) != device_id || device_id == self.device_id {
            return Ok(false);
        }
        let existing: Option<(Vec<u8>, Vec<u8>, String)> = self
            .db
            .query_row(
                "SELECT sign_pub, enc_pub, trust FROM devices WHERE device_id = ?1",
                params![device_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        let member = member_id.map(|m| m.as_bytes().to_vec());
        match existing {
            Some((sp, ep, trust)) => {
                if sp != sign_pub.as_slice() || ep != enc_pub.as_slice() {
                    return Ok(false);
                }
                if trust == "certified" || trust == "self" {
                    return Ok(false);
                }
                self.db
                    .execute(
                        "UPDATE devices SET trust = 'certified', member_id = ?2 WHERE device_id = ?1",
                        params![device_id, member],
                    )
                    .map_err(|_| Error::Storage)?;
            }
            None => {
                let label = if member_id.is_some() { "Member device" } else { "Device" };
                let name_blob = crate::secwet::seal_device_name(self.k_rec.expose_secret(), device_id, label)?;
                self.db
                    .execute(
                        "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, member_id, trust)
                         VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5, ?6, 'certified')",
                        params![device_id, name_blob, sign_pub.as_slice(), enc_pub.as_slice(), now_ms(), member],
                    )
                    .map_err(|_| Error::Storage)?;
            }
        }
        Ok(true)
    }

    /// Vouches for a trusted device two ways: a signed certificate queued for
    /// the relay's certificate store (verified by chain, never pruned), and a
    /// workspace-key-sealed event for owner devices that do not trust this
    /// device's key yet (just paired).
    pub(crate) fn emit_device_certificate(&self, device_id: &str, sign_pub: &[u8; 32], enc_pub: &[u8; 32], member_id: Option<Uuid>) -> Result<()> {
        if !self.is_owner() || self.plan_state().unwrap_or(crate::plan::PlanState::Free) == crate::plan::PlanState::Free {
            return Ok(());
        }
        if device_id != self.device_id {
            let certificate = secwet_proto::DeviceCertificate {
                secwet_id: self.secwet_id,
                device_id: device_id.to_string(),
                sign_pub: *sign_pub,
                enc_pub: *enc_pub,
                member_id,
                certifier_device_id: self.device_id.clone(),
                issued_at: now_ms(),
            };
            let signature = crypto::sign_payload(&self.device_sign_key, &certificate.signing_bytes().map_err(|_| Error::Crypto)?).to_bytes();
            let bytes = postcard::to_stdvec(&secwet_proto::SignedDeviceCertificate { certificate, signature }).map_err(|_| Error::Storage)?;
            self.db
                .execute(
                    "INSERT OR REPLACE INTO collab_cert_outbox (device_id, certificate) VALUES (?1, ?2)",
                    params![device_id, bytes],
                )
                .map_err(|_| Error::Storage)?;
        }
        let body = EventBody::DeviceCertified {
            device_id: device_id.to_string(),
            sign_pub: *sign_pub,
            enc_pub: *enc_pub,
            member_id,
        };
        let seq = sync::next_device_seq(&self.db, &self.device_id)?;
        let ev = sync::create_signed_event(
            self.secwet_id,
            &self.device_id,
            seq,
            self.key_epoch,
            self.k_evt.expose_secret(),
            &self.device_sign_key,
            &body,
        )?;
        sync::enqueue_outbox(&self.db, &ev)
    }

    /// Uploads queued certificates to the relay's certificate store.
    pub async fn upload_certificates(&mut self, client: &RelayClient) -> Result<usize> {
        let rows: Vec<(String, Vec<u8>)> = {
            let mut stmt = self.db.prepare("SELECT device_id, certificate FROM collab_cert_outbox").map_err(|_| Error::Storage)?;
            let it = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(|_| Error::Storage)?;
            it.flatten().collect()
        };
        if rows.is_empty() {
            return Ok(0);
        }
        let certificates = rows
            .iter()
            .filter_map(|(_, b)| postcard::from_bytes::<secwet_proto::SignedDeviceCertificate>(b).ok())
            .collect();
        client
            .post_certificates(self.secwet_id, &secwet_proto::DeviceCertificates { certificates }, &self.device_sign_key)
            .await?;
        for (id, _) in &rows {
            self.db
                .execute("DELETE FROM collab_cert_outbox WHERE device_id = ?1", params![id])
                .map_err(|_| Error::Storage)?;
        }
        Ok(rows.len())
    }

    /// Imports certificates from the relay, accepting each only when its
    /// certifier is already trusted here (an owner device, or this device),
    /// is not revoked, and signed it. Repeats until nothing new is learned,
    /// so trust follows chains of certificates.
    pub async fn import_certificates(&mut self, client: &RelayClient) -> Result<usize> {
        let certs = client.get_certificates(self.secwet_id, &self.device_sign_key).await?.certificates;
        let mut learned = 0;
        loop {
            let mut progress = false;
            for sc in &certs {
                let c = &sc.certificate;
                if c.secwet_id != self.secwet_id || c.device_id == self.device_id {
                    continue;
                }
                if matches!(self.device_trust(&c.device_id), Some((ref t, _)) if t == "certified" || t == "self") {
                    continue;
                }
                let certifier_pub = if c.certifier_device_id == self.device_id {
                    Some(self.device_sign_pub)
                } else {
                    match self.device_trust(&c.certifier_device_id) {
                        Some((t, None)) if t == "certified" => {
                            let revoked: Option<i64> = self
                                .db
                                .query_row(
                                    "SELECT revoked_at FROM devices WHERE device_id = ?1",
                                    params![c.certifier_device_id],
                                    |r| r.get(0),
                                )
                                .ok()
                                .flatten();
                            if revoked.is_some() {
                                None
                            } else {
                                self.device_sign_pub_of(&c.certifier_device_id)?.map(|(p, _)| p)
                            }
                        }
                        _ => None,
                    }
                };
                let Some(pk) = certifier_pub else { continue };
                let Ok(bytes) = c.signing_bytes() else { continue };
                if crypto::verify_signature_strict_bytes(&pk, &bytes, &sc.signature).is_err() {
                    continue;
                }
                if self.certify_device(&c.device_id, &c.sign_pub, &c.enc_pub, c.member_id)? {
                    learned += 1;
                    progress = true;
                }
            }
            if !progress {
                break;
            }
        }
        Ok(learned)
    }

    /// Trusted, non-revoked owner devices (including this one when it is an owner).
    pub(crate) fn certified_owner_devices(&self) -> Result<Vec<secwet_proto::TrustedDevice>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT device_id, sign_pub, enc_pub FROM devices
                 WHERE member_id IS NULL AND revoked_at IS NULL AND trust IN ('self', 'certified')",
            )
            .map_err(|_| Error::Storage)?;
        let rows = stmt
            .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?)))
            .map_err(|_| Error::Storage)?;
        let mut out = Vec::new();
        for (id, sp, ep) in rows.flatten() {
            if id == self.device_id && !self.is_owner() {
                continue;
            }
            if let (Ok(sign_pub), Ok(enc_pub)) = (<[u8; 32]>::try_from(sp.as_slice()), <[u8; 32]>::try_from(ep.as_slice())) {
                out.push(secwet_proto::TrustedDevice { device_id: id, sign_pub, enc_pub });
            }
        }
        out.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        Ok(out)
    }

    /// Trusted, non-revoked devices of one member.
    fn certified_member_devices(&self, member_id: Uuid) -> Result<Vec<secwet_proto::TrustedDevice>> {
        let mut stmt = self
            .db
            .prepare(
                "SELECT device_id, sign_pub, enc_pub FROM devices
                 WHERE member_id = ?1 AND revoked_at IS NULL AND trust = 'certified'",
            )
            .map_err(|_| Error::Storage)?;
        let rows = stmt
            .query_map(params![member_id.as_bytes().as_slice()], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?, r.get::<_, Vec<u8>>(2)?))
            })
            .map_err(|_| Error::Storage)?;
        let mut out = Vec::new();
        for (id, sp, ep) in rows.flatten() {
            if let (Ok(sign_pub), Ok(enc_pub)) = (<[u8; 32]>::try_from(sp.as_slice()), <[u8; 32]>::try_from(ep.as_slice())) {
                out.push(secwet_proto::TrustedDevice { device_id: id, sign_pub, enc_pub });
            }
        }
        Ok(out)
    }

    /// Revokes another device on the relay with a signed directive and records
    /// it locally. `wipe` asks the device to crypto-shred itself. Branch keys
    /// the device could hold are queued for rotation before the relay call, so
    /// the intent survives a lost response or a crash.
    pub async fn device_revoke_remote(
        &mut self,
        client: &RelayClient,
        target_device_id: &str,
        wipe: bool,
    ) -> Result<secwet_proto::RevokeResponse> {
        self.ensure_writable()?;
        if target_device_id == self.device_id {
            return Err(Error::Invalid {
                field: "device",
                message: "You can't revoke this device.".into(),
            });
        }
        let target_member = self.device_sign_pub_of(target_device_id)?.and_then(|(_, m)| m);
        let spaces: Vec<Uuid> = match target_member {
            None => self.keyring.branches.keys().copied().collect(),
            Some(m) => match self.member_grants_local(m)? {
                Some(g) => self.spaces_touched(&g.set.grants)?,
                None => self.keyring.branches.keys().copied().collect(),
            },
        };
        for s in &spaces {
            self.queue_pending("branch_rotate", *s)?;
        }
        let revocation = self.sign_revocation(target_device_id, wipe)?;
        let req = RevokeRequest { wipe, revocation };
        let resp = match client.revoke_device(self.secwet_id, &req, &self.device_sign_key).await {
            Ok(r) => r,
            // A replay after a lost response: the revocation is in place.
            Err(Error::Relay { code }) if code == "already_revoked" => secwet_proto::RevokeResponse {
                device_id: target_device_id.to_string(),
                revoked_at: now_ms(),
                wipe_requested: wipe,
            },
            Err(e) => return Err(e),
        };
        self.record_local_revocation(target_device_id, resp.revoked_at)?;
        Ok(resp)
    }

    pub(crate) fn queue_pending(&self, kind: &str, space_id: Uuid) -> Result<()> {
        self.db
            .execute(
                "INSERT OR IGNORE INTO collab_pending (kind, space_id, created_at) VALUES (?1, ?2, ?3)",
                params![kind, space_id.as_bytes().as_slice(), now_ms()],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    fn pending(&self, kind: &str) -> Result<Vec<Uuid>> {
        let mut stmt = self
            .db
            .prepare("SELECT space_id FROM collab_pending WHERE kind = ?1")
            .map_err(|_| Error::Storage)?;
        let rows = stmt
            .query_map(params![kind], |r| r.get::<_, Vec<u8>>(0))
            .map_err(|_| Error::Storage)?;
        Ok(rows.flatten().filter_map(|b| Uuid::from_slice(&b).ok()).collect())
    }

    fn clear_pending(&self, kind: &str, space_id: Uuid) -> Result<()> {
        self.db
            .execute(
                "DELETE FROM collab_pending WHERE kind = ?1 AND space_id = ?2",
                params![kind, space_id.as_bytes().as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    fn sign_revocation(&self, target_device_id: &str, wipe: bool) -> Result<SignedRevocation> {
        let directive = RevocationDirective {
            secwet_id: self.secwet_id,
            target_device_id: target_device_id.to_string(),
            issuer_device_id: self.device_id.clone(),
            wipe,
            issued_at: now_ms(),
        };
        let bytes = directive.signing_bytes().map_err(|_| Error::Crypto)?;
        let signature = crypto::sign_payload(&self.device_sign_key, &bytes).to_bytes();
        Ok(SignedRevocation { directive, signature })
    }

    fn record_local_revocation(&mut self, target_device_id: &str, revoked_at: i64) -> Result<()> {
        self.db
            .execute(
                "UPDATE devices SET revoked_at = COALESCE(revoked_at, ?1) WHERE device_id = ?2",
                params![revoked_at, target_device_id],
            )
            .map_err(|_| Error::Storage)?;
        let is_member_device: bool = self
            .db
            .query_row(
                "SELECT member_id IS NOT NULL FROM devices WHERE device_id = ?1",
                params![target_device_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?
            .unwrap_or(false);
        if self.is_owner() && !is_member_device {
            let name = self
                .devices_list()?
                .into_iter()
                .find(|d| d.id == target_device_id)
                .map(|d| d.name)
                .unwrap_or_else(|| "A device".into());
            set_meta(&self.db, "rotation_recommended", "1")?;
            set_meta(&self.db, "rotation_reason", &format!("{name} was revoked."))?;
        }
        Ok(())
    }

    /// True once this store has crypto-shredded itself.
    pub fn is_wiped(&self) -> bool {
        self.keyring.epochs.is_empty() && !self.db_path.exists()
    }

    /// Verifies a revocation directive the relay attached to a `403 revoked`
    /// and executes it. Returns `Err(Error::Crypto)` and changes nothing when
    /// the directive does not verify. Idempotent: a store already wiped or
    /// archived reports that outcome again.
    pub fn handle_revocation_notice(
        &mut self,
        notice: &SignedRevocation,
        keystore: &dyn KeyStore,
    ) -> Result<RevocationOutcome> {
        if self.is_wiped() {
            return Ok(RevocationOutcome::Wiped);
        }
        let d = &notice.directive;
        if d.secwet_id != self.secwet_id
            || d.target_device_id != self.device_id
            || d.issuer_device_id == self.device_id
        {
            return Err(Error::Crypto);
        }
        // The issuer must be a device this store trusts on its own (pairing,
        // verified invite, signed certificate), not one only the relay
        // listed, and it must not be revoked itself.
        let row: Option<IssuerRow> = self
            .db
            .query_row(
                "SELECT sign_pub, member_id, trust, revoked_at FROM devices WHERE device_id = ?1",
                params![d.issuer_device_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        let (pk, member, trust, revoked) = row.ok_or(Error::Crypto)?;
        if trust != "certified" || revoked.is_some() {
            return Err(Error::Crypto);
        }
        let issuer_pub = <[u8; 32]>::try_from(pk.as_slice()).map_err(|_| Error::Crypto)?;
        let issuer_member = member.and_then(|m| Uuid::from_slice(&m).ok());
        // Only the owner's devices or another device of the same member may revoke.
        if issuer_member.is_some() && issuer_member != self.member_id {
            return Err(Error::Crypto);
        }
        let bytes = d.signing_bytes().map_err(|_| Error::Crypto)?;
        crypto::verify_signature_strict_bytes(&issuer_pub, &bytes, &notice.signature)
            .map_err(|_| Error::Crypto)?;

        if d.wipe {
            self.crypto_shred(keystore)?;
            Ok(RevocationOutcome::Wiped)
        } else {
            if self.unlinked_at()?.is_none() {
                set_meta(&self.db, "revoked_state", "sync_only")?;
                set_meta(&self.db, "revoked_at", &d.issued_at.to_string())?;
            }
            Ok(RevocationOutcome::Archived)
        }
    }

    fn device_sign_pub_of(&self, device_id: &str) -> Result<Option<([u8; 32], Option<Uuid>)>> {
        let row: Option<(Vec<u8>, Option<Vec<u8>>)> = self
            .db
            .query_row(
                "SELECT sign_pub, member_id FROM devices WHERE device_id = ?1",
                params![device_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        Ok(match row {
            Some((pk, member)) if pk.len() == 32 => {
                let mut a = [0u8; 32];
                a.copy_from_slice(&pk);
                Some((a, member.and_then(|m| Uuid::from_slice(&m).ok())))
            }
            _ => None,
        })
    }

    /// Whether a device is the inviter named in this member store's invite link.
    fn is_invite_anchor(&self, device_id: &str) -> bool {
        !self.is_owner() && get_meta(&self.db, "invite_anchor").ok().flatten().as_deref() == Some(device_id)
    }

    /// Trust level and membership of a device as this store knows it.
    pub(crate) fn device_trust(&self, device_id: &str) -> Option<(String, Option<Uuid>)> {
        self.db
            .query_row(
                "SELECT trust, member_id FROM devices WHERE device_id = ?1",
                params![device_id],
                |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<Vec<u8>>>(1)?)),
            )
            .optional()
            .ok()
            .flatten()
            .map(|(t, m)| (t, m.and_then(|b| Uuid::from_slice(&b).ok())))
    }

    /// Crypto-shredding: deletes every keystore entry of this workspace, then
    /// the local database, its WAL and every cached file, and zeroizes memory.
    /// The `Secwet` is unusable afterwards and must be dropped.
    ///
    /// Before any key is deleted, a marker next to the workspace directory
    /// records the wipe and the entry names (never values), synced to disk.
    /// It is removed only once the keys and files are gone, so a process
    /// killed midway (common on phones) is finished by
    /// `Secwet::finish_pending_wipes` on the next start instead of leaving a
    /// store that can neither unlock nor be created again.
    pub fn crypto_shred(&mut self, keystore: &dyn KeyStore) -> Result<()> {
        let id = self.secwet_id;
        let max_epoch = self.keyring.epochs.keys().next_back().copied().unwrap_or(1).max(self.key_epoch);
        let branches: Vec<(Uuid, u32)> = {
            let mut out = Vec::new();
            if let Ok(mut stmt) = self.db.prepare("SELECT space_id, epoch FROM collab_branches") {
                if let Ok(rows) = stmt.query_map([], |r| Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, i64>(1)?))) {
                    for (s, e) in rows.flatten() {
                        if let Ok(u) = Uuid::from_slice(&s) {
                            out.push((u, e as u32));
                        }
                    }
                }
            }
            out
        };

        let mut entries = vec![
            format!("secwet/{id}/device-sign"),
            format!("secwet/{id}/device-enc"),
            // The app layer's biometric-unlock flag (no key material).
            format!("secwet/{id}/biometric-unlock"),
        ];
        for e in 1..=max_epoch + 1 {
            entries.push(format!("secwet/{id}/vault-key/{e}"));
            entries.push(format!("secwet/{id}/master-key/{e}"));
        }
        for (s, e) in &branches {
            entries.push(format!("secwet/{id}/branch-bundle/{s}/{e}"));
        }
        let data_dir = self
            .db_path
            .parent()
            .and_then(Path::parent)
            .and_then(Path::parent)
            .map(Path::to_path_buf);
        let marker = data_dir.as_ref().map(|dd| pending_wipe_marker(dd, id));
        if let Some(marker) = &marker {
            write_durably(marker, &serde_json::to_vec(&entries).unwrap_or_default());
        }
        // Delete keys first: once they are gone the database is unreadable
        // even if file deletion is interrupted.
        let failed: Vec<String> = entries.iter().filter(|e| keystore.delete(e).is_err()).cloned().collect();
        if let Some(marker) = &marker {
            write_durably(marker, &serde_json::to_vec(&failed).unwrap_or_default());
        }

        self.zeroize_all_keys();
        let old = std::mem::replace(&mut self.db, Connection::open_in_memory().map_err(|_| Error::Storage)?);
        drop(old);

        let dir = self.db_path.parent().map(Path::to_path_buf);
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut p = self.db_path.clone().into_os_string();
            p.push(suffix);
            let p = PathBuf::from(p);
            if p.exists() {
                overwrite_and_remove(&p);
            }
        }
        let mut files_gone = true;
        if let Some(dir) = dir {
            if dir.file_name().map(|n| n == id.to_string().as_str()).unwrap_or(false) {
                files_gone = std::fs::remove_dir_all(&dir).is_ok() || !dir.exists();
            }
        }
        crate::secwet::release_session(&id);
        if failed.is_empty() && files_gone {
            if let Some(marker) = &marker {
                let _ = std::fs::remove_file(marker);
            }
        }
        if !failed.is_empty() {
            return Err(Error::KeyStore);
        }
        Ok(())
    }

    /// Finishes a crypto-shred that was interrupted: retries the keystore
    /// deletions and removes what is left of the workspace directory
    /// (`<data_dir>/secwet/<id>`), so the next status reads Uninitialized.
    /// Call at startup, before unlocking. Returns how many markers were cleared.
    pub fn finish_pending_wipes(data_dir: &Path, keystore: &dyn KeyStore) -> Result<usize> {
        let mut cleared = 0;
        let Ok(entries) = std::fs::read_dir(data_dir) else { return Ok(0) };
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_prefix(".secwet-pending-wipe-") else { continue };
            let list: Vec<String> = std::fs::read(e.path())
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
            let remaining: Vec<String> = list.into_iter().filter(|k| keystore.delete(k).is_err()).collect();
            // Only a real workspace id names a directory to remove.
            let mut files_gone = true;
            if let Ok(id) = Uuid::parse_str(id) {
                let dir = data_dir.join("secwet").join(id.to_string());
                if dir.exists() {
                    for file in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
                        if file.path().is_file() {
                            overwrite_and_remove(&file.path());
                        }
                    }
                    files_gone = std::fs::remove_dir_all(&dir).is_ok() || !dir.exists();
                }
            }
            if remaining.is_empty() && files_gone {
                let _ = std::fs::remove_file(e.path());
                cleared += 1;
            } else {
                write_durably(&e.path(), &serde_json::to_vec(&remaining).unwrap_or_default());
            }
        }
        Ok(cleared)
    }

    // ========================================================================
    // M7: master key rotation
    // ========================================================================

    /// Rotates the workspace master key to epoch N+1 for every active owner
    /// device, then re-seals local data. On a concurrent rotation
    /// (`epoch_conflict`) it adopts the winner's verified key instead, and
    /// rotates once more if the winner still included a device this store
    /// knows is revoked. Branch keys queued for rotation are rotated after.
    pub async fn rotate_master_key(
        &mut self,
        client: &RelayClient,
        keystore: &dyn KeyStore,
    ) -> Result<KeyRotationReport> {
        self.ensure_writable()?;
        if !self.is_owner() {
            return Err(Error::Forbidden);
        }
        // Learn device certificates other owner devices published.
        if let Err(e @ Error::RevocationNotice(_)) = self.pull_and_apply_events(client).await { return Err(e) }
        self.upload_certificates(client).await?;
        self.import_certificates(client).await?;
        let mut report = self.rotate_master_once(client, keystore).await?;
        if report.adopted_from_conflict && self.newest_rotation_includes_revoked(client).await? {
            let again = self.rotate_master_once(client, keystore).await?;
            report.epoch = again.epoch;
            report.resealed += again.resealed;
            report.recipients = again.recipients;
        }
        self.process_pending_rotations(client, keystore).await?;
        Ok(report)
    }

    async fn rotate_master_once(&mut self, client: &RelayClient, keystore: &dyn KeyStore) -> Result<KeyRotationReport> {
        let previous = self.key_epoch;
        let list = self.refresh_devices_from_relay(client).await?;
        if list.current_epoch > previous {
            // Another device already rotated; catch up instead.
            let resealed = self.refresh_master_keys(client, keystore).await?;
            return Ok(KeyRotationReport {
                previous_epoch: previous,
                epoch: self.key_epoch,
                resealed,
                recipients: 0,
                adopted_from_conflict: true,
            });
        }

        // Recipients are the relay's active owner devices, each of which must
        // be trusted here: a device only the relay vouches for never gets
        // the master key.
        let trusted: HashMap<String, secwet_proto::TrustedDevice> =
            self.certified_owner_devices()?.into_iter().map(|d| (d.device_id.clone(), d)).collect();
        let mut recipients: Vec<secwet_proto::TrustedDevice> = Vec::new();
        for d in list.devices.iter().filter(|d| d.member_id.is_none() && d.revoked_at.is_none()) {
            match trusted.get(&d.id) {
                Some(t) if t.sign_pub == d.sign_pub && t.enc_pub == d.enc_pub => recipients.push(t.clone()),
                _ => {
                    return Err(Error::Relay {
                        code: "untrusted_device".into(),
                    })
                }
            }
        }
        recipients.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        if !recipients.iter().any(|d| d.device_id == self.device_id) {
            return Err(Error::Revoked);
        }

        let epoch = previous + 1;
        let k_m = random_key();
        let mut wrapped = Vec::with_capacity(recipients.len());
        for d in &recipients {
            let info = postcard::to_stdvec(&KeyWrapInfo {
                purpose: MASTER_KEY_PURPOSE,
                secwet_id: self.secwet_id.as_bytes(),
                key_epoch: epoch,
                recipient_device_id: &d.device_id,
            })
            .map_err(|_| Error::Crypto)?;
            wrapped.push(DeviceWrappedKey {
                device_id: d.device_id.clone(),
                wrapped: crypto::wrap_for_device(&d.enc_pub, &info, &k_m)?,
            });
        }
        let statement = KeyRotationStatement {
            secwet_id: self.secwet_id,
            epoch,
            issuer_device_id: self.device_id.clone(),
            recipients: recipients.iter().map(|d| d.device_id.clone()).collect(),
            key_commitment: *key_commitment(&k_m, &self.secwet_id),
        };
        let sig = crypto::sign_payload(&self.device_sign_key, &statement.signing_bytes().map_err(|_| Error::Crypto)?);
        let req = KeyRotationRequest {
            statement,
            signature: sig.to_bytes(),
            wrapped,
        };

        match client.rotate_keys(self.secwet_id, &req, &self.device_sign_key).await {
            Ok(_) => {
                let resealed = self.adopt_master_epoch(epoch, &k_m, keystore)?;
                set_meta(&self.db, "key_rotated_at", &now_ms().to_string())?;
                set_meta(&self.db, "rotation_recommended", "0")?;
                set_meta(&self.db, "rotation_reason", "")?;
                if let Err(e) = self.create_and_upload_snapshot(client).await {
                    eprintln!("snapshot after rotation failed: {e}");
                }
                Ok(KeyRotationReport {
                    previous_epoch: previous,
                    epoch,
                    resealed,
                    recipients: recipients.len(),
                    adopted_from_conflict: false,
                })
            }
            Err(Error::Relay { code }) if code == "epoch_conflict" => {
                let resealed = self.refresh_master_keys(client, keystore).await?;
                set_meta(&self.db, "rotation_recommended", "0")?;
                Ok(KeyRotationReport {
                    previous_epoch: previous,
                    epoch: self.key_epoch,
                    resealed,
                    recipients: 0,
                    adopted_from_conflict: true,
                })
            }
            Err(e) => Err(e),
        }
    }

    /// Whether the newest rotation's recipients include a device revoked here.
    async fn newest_rotation_includes_revoked(&mut self, client: &RelayClient) -> Result<bool> {
        let resp = client.get_wrapped_keys(self.secwet_id, &self.device_sign_key).await?;
        let Some(st) = resp.statements.iter().max_by_key(|s| s.statement.epoch) else { return Ok(false) };
        for r in &st.statement.recipients {
            let revoked: Option<i64> = self
                .db
                .query_row("SELECT revoked_at FROM devices WHERE device_id = ?1", params![r], |row| row.get(0))
                .optional()
                .map_err(|_| Error::Storage)?
                .flatten();
            if revoked.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Fetches this device's wrapped master keys and adopts newer epochs, one
    /// at a time, each only when a signed statement from a trusted,
    /// non-revoked owner device names this device and commits to that exact
    /// key. Returns how many rows were re-sealed.
    pub async fn refresh_master_keys(&mut self, client: &RelayClient, keystore: &dyn KeyStore) -> Result<usize> {
        if !self.is_owner() {
            return Ok(0);
        }
        let resp = client.get_wrapped_keys(self.secwet_id, &self.device_sign_key).await?;
        let enc = x25519_dalek::StaticSecret::from(*self.enc_secret.expose_secret());
        let mut resealed = 0;
        let mut keys: Vec<_> = resp.keys.iter().filter(|k| k.epoch > self.key_epoch).cloned().collect();
        keys.sort_by_key(|k| k.epoch);
        for k in keys {
            if k.epoch != self.key_epoch + 1 {
                break;
            }
            let Some(st) = resp.statements.iter().find(|s| s.statement.epoch == k.epoch) else { break };
            if !self.verify_rotation_statement(st) {
                break;
            }
            let Ok(unwrapped) = crypto::unwrap_master_keys_for_me(std::slice::from_ref(&k), &enc, &self.device_id, &self.secwet_id) else {
                break;
            };
            let Some((epoch, key)) = unwrapped.into_iter().next() else { break };
            if !bool::from(key_commitment(&key, &self.secwet_id).ct_eq(&st.statement.key_commitment)) {
                break;
            }
            resealed += self.adopt_master_epoch(epoch, &key, keystore)?;
        }
        if resp.current_epoch > self.key_epoch {
            set_meta(&self.db, "missing_epoch", &resp.current_epoch.to_string())?;
        } else {
            set_meta(&self.db, "missing_epoch", "")?;
        }
        Ok(resealed)
    }

    fn verify_rotation_statement(&self, st: &secwet_proto::SignedRotationStatement) -> bool {
        let s = &st.statement;
        if s.secwet_id != self.secwet_id || !s.recipients.iter().any(|r| r == &self.device_id) {
            return false;
        }
        let pk = if s.issuer_device_id == self.device_id {
            Some(self.device_sign_pub)
        } else {
            match self.device_trust(&s.issuer_device_id) {
                Some((t, None)) if t == "certified" => {
                    let revoked: Option<i64> = self
                        .db
                        .query_row(
                            "SELECT revoked_at FROM devices WHERE device_id = ?1",
                            params![s.issuer_device_id],
                            |r| r.get(0),
                        )
                        .ok()
                        .flatten();
                    if revoked.is_some() {
                        None
                    } else {
                        self.device_sign_pub_of(&s.issuer_device_id).ok().flatten().map(|(p, _)| p)
                    }
                }
                _ => None,
            }
        };
        let Some(pk) = pk else { return false };
        let Ok(bytes) = s.signing_bytes() else { return false };
        crypto::verify_signature_strict_bytes(&pk, &bytes, &st.signature).is_ok()
    }

    /// Stores a new master key epoch, switches sealing to it, re-seals local
    /// rows and re-encrypts queued outbox events for the new epoch.
    pub fn adopt_master_epoch(&mut self, epoch: u32, k_m: &[u8; 32], keystore: &dyn KeyStore) -> Result<usize> {
        store_master_key(keystore, &self.secwet_id, epoch, k_m)?;
        self.keyring.insert_master(epoch, k_m, &self.secwet_id);
        if epoch > self.key_epoch {
            set_meta(&self.db, "current_key_epoch", &epoch.to_string())?;
            self.switch_current_epoch(epoch)?;
        }
        let resealed = self.reseal_to_current()?;
        // F9: the recovery blob wraps master keys per epoch and needs the
        // recovery key, which is never stored; the UI asks for a new one.
        if records::get_meta(&self.db, "recovery_created_at")?.is_some() {
            set_meta(&self.db, "recovery_needs_refresh", "1")?;
        }
        self.reencrypt_outbox()?;
        Ok(resealed)
    }

    fn switch_current_epoch(&mut self, epoch: u32) -> Result<()> {
        let keys = self.keyring.epochs.get(&epoch).ok_or(Error::KeyStore)?;
        let rec = *keys.rec;
        let evt = *keys.evt;
        self.set_current_keys(epoch, rec, evt);
        Ok(())
    }

    /// Re-seals every local row that is not on the current epoch, committing
    /// `RESEAL_BATCH_SIZE` rows per transaction. Safe to re-run after a crash.
    pub fn reseal_to_current(&mut self) -> Result<usize> {
        let current = self.key_epoch;
        let batch = secwet_proto::RESEAL_BATCH_SIZE;
        let mut total = 0usize;

        // 1. records: tracked by key_epoch, paged by id so a row that cannot
        // be opened is skipped (and stays readable by nobody) instead of
        // aborting the re-seal or looping on it.
        let mut after: Vec<u8> = Vec::new();
        loop {
            let rows: Vec<(Vec<u8>, i64, i64, Vec<u8>)> = {
                let mut stmt = self
                    .db
                    .prepare(
                        "SELECT id, record_type, key_epoch, blob FROM records
                         WHERE key_epoch < ?1 AND blob IS NOT NULL AND id > ?2
                         ORDER BY id LIMIT ?3",
                    )
                    .map_err(|_| Error::Storage)?;
                let it = stmt
                    .query_map(params![current as i64, after, batch as i64], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                    })
                    .map_err(|_| Error::Storage)?;
                it.collect::<std::result::Result<_, _>>().map_err(|_| Error::Storage)?
            };
            let Some(last) = rows.last() else { break };
            after = last.0.clone();
            let mut updates = Vec::with_capacity(rows.len());
            for (id, rtype, epoch, blob) in &rows {
                let Ok(idb) = <[u8; 16]>::try_from(id.as_slice()) else { continue };
                let aad = RecordAad::from_raw_type(self.secwet_id.as_bytes(), &idb, *rtype as u8, *epoch as u32);
                let Ok(pt) = self.open_rec(&aad, blob) else {
                    eprintln!("reseal: skipped a record that could not be opened");
                    continue;
                };
                let pt = Zeroizing::new(pt);
                let new_aad = RecordAad::from_raw_type(self.secwet_id.as_bytes(), &idb, *rtype as u8, current);
                let sealed = crypto::seal_record(self.k_rec.expose_secret(), &new_aad, &pt)?;
                updates.push((id.clone(), sealed));
            }
            let tx = self.db.transaction().map_err(|_| Error::Storage)?;
            for (id, sealed) in &updates {
                tx.execute(
                    "UPDATE records SET blob = ?1, key_epoch = ?2 WHERE id = ?3",
                    params![sealed, current as i64, id],
                )
                .map_err(|_| Error::Storage)?;
            }
            tx.commit().map_err(|_| Error::Storage)?;
            total += updates.len();
        }

        // 2. labels and spaces (no epoch column): re-seal rows not on current.
        for table in ["labels", "spaces"] {
            let rows: Vec<(Vec<u8>, Vec<u8>)> = {
                let mut stmt = self
                    .db
                    .prepare(&format!("SELECT id, name_blob FROM {table}"))
                    .map_err(|_| Error::Storage)?;
                let it = stmt
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                    .map_err(|_| Error::Storage)?;
                it.collect::<std::result::Result<_, _>>().map_err(|_| Error::Storage)?
            };
            for chunk in rows.chunks(batch) {
                let mut updates = Vec::new();
                for (id, blob) in chunk {
                    if id.len() != 16 || blob.is_empty() {
                        continue;
                    }
                    let mut idb = [0u8; 16];
                    idb.copy_from_slice(id);
                    let aad = RecordAad::new(self.secwet_id.as_bytes(), &idb, RecordType::Label, current);
                    let Ok((pt, opened_epoch)) = self.open_rec_epoch(&aad, blob) else { continue };
                    if opened_epoch == current {
                        continue;
                    }
                    let pt = Zeroizing::new(pt);
                    updates.push((id.clone(), crypto::seal_record(self.k_rec.expose_secret(), &aad, &pt)?));
                }
                if updates.is_empty() {
                    continue;
                }
                let tx = self.db.transaction().map_err(|_| Error::Storage)?;
                for (id, sealed) in &updates {
                    tx.execute(&format!("UPDATE {table} SET name_blob = ?1 WHERE id = ?2"), params![sealed, id])
                        .map_err(|_| Error::Storage)?;
                }
                tx.commit().map_err(|_| Error::Storage)?;
                total += updates.len();
            }
        }

        // 3. device names.
        let devs: Vec<(String, Vec<u8>)> = {
            let mut stmt = self
                .db
                .prepare("SELECT device_id, name_blob FROM devices")
                .map_err(|_| Error::Storage)?;
            let it = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .map_err(|_| Error::Storage)?;
            it.collect::<std::result::Result<_, _>>().map_err(|_| Error::Storage)?
        };
        let rec = *self.k_rec.expose_secret();
        for (id, blob) in devs {
            if crate::secwet::unseal_device_name(&rec, &id, &blob).is_ok() {
                continue;
            }
            if let Ok(name) = self.unseal_device_name_any(&id, &blob) {
                let sealed = crate::secwet::seal_device_name(&rec, &id, &name)?;
                self.db
                    .execute("UPDATE devices SET name_blob = ?1 WHERE device_id = ?2", params![sealed, id])
                    .map_err(|_| Error::Storage)?;
                total += 1;
            }
        }
        Ok(total)
    }

    /// Re-encrypts queued outbox events whose epoch is no longer current
    /// (master epoch for workspace events, branch epoch for scoped ones), so
    /// writes queued offline never leave under a key a removed member or
    /// revoked device still holds. Events this device can no longer encrypt
    /// for (branch access lost) are dropped.
    pub(crate) fn reencrypt_outbox(&self) -> Result<usize> {
        let events = sync::peek_outbox(&self.db, 100_000)?;
        let mut changed = 0;
        for ev in events {
            let env = &ev.envelope;
            let (want_epoch, new_key) = match &env.scope {
                None => {
                    if env.key_epoch == self.key_epoch {
                        continue;
                    }
                    (self.key_epoch, Zeroizing::new(*self.k_evt.expose_secret()))
                }
                Some(scope) => match self.keyring.branch_epoch(scope.space_id) {
                    Some(e) if e == env.key_epoch => continue,
                    Some(e) => match self.keyring.branch_target_key(&self.secwet_id, scope, e) {
                        Some(k) => (e, k),
                        None => {
                            self.drop_outbox_event(&env.event_id)?;
                            continue;
                        }
                    },
                    None => continue,
                },
            };
            let old_key = match &env.scope {
                None => self.keyring.evt(env.key_epoch).map(|k| Zeroizing::new(*k)),
                Some(scope) => self.keyring.branch_target_key(&self.secwet_id, scope, env.key_epoch),
            };
            let Some(old_key) = old_key else {
                self.drop_outbox_event(&env.event_id)?;
                continue;
            };
            let Ok(body) = sync::decrypt_event_body(&ev, &old_key) else {
                self.drop_outbox_event(&env.event_id)?;
                continue;
            };
            let fresh = sync::reseal_signed_event(&ev, want_epoch, &new_key, &self.device_sign_key, &body)?;
            let bytes = postcard::to_stdvec(&fresh).map_err(|_| Error::Storage)?;
            self.db
                .execute(
                    "UPDATE outbox SET envelope = ?1 WHERE event_id = ?2",
                    params![bytes, &env.event_id[..]],
                )
                .map_err(|_| Error::Storage)?;
            changed += 1;
        }
        Ok(changed)
    }

    fn drop_outbox_event(&self, event_id: &[u8; 16]) -> Result<()> {
        // Keep device_seq contiguous for the relay: replace the dropped event
        // by a harmless no-op only the owner's devices can read.
        let events = sync::peek_outbox(&self.db, 100_000)?;
        if let Some(ev) = events.iter().find(|e| &e.envelope.event_id == event_id) {
            let noop = EventBody::DeviceRenamed {
                device_id: String::new(),
                name: String::new(),
            };
            if self.is_owner() {
                let fresh = sync::reseal_signed_event_unscoped(ev, self.key_epoch, self.k_evt.expose_secret(), &self.device_sign_key, &noop)?;
                let bytes = postcard::to_stdvec(&fresh).map_err(|_| Error::Storage)?;
                self.db
                    .execute("UPDATE outbox SET envelope = ?1 WHERE event_id = ?2", params![bytes, &event_id[..]])
                    .map_err(|_| Error::Storage)?;
            } else {
                // Members cannot write unscoped events; the relay consumes an
                // unauthorized one without storing it, keeping the sequence.
                let _ = ev;
            }
        }
        Ok(())
    }

    // ========================================================================
    // M8: scope resolution for local records
    // ========================================================================

    /// Space and path of a group (label).
    fn label_space(&self, label_id: Uuid) -> Result<Option<Uuid>> {
        Ok(records::get_label(&self.db, label_id)?.and_then(|l| l.space_id))
    }

    /// Computes the routing scope of a mutation, or `None` when the record is
    /// in a space that is not shared.
    pub(crate) fn scope_for_mutation(
        &self,
        record_id: Uuid,
        record_type: RecordType,
        payload: Option<&RecordPayload>,
    ) -> Result<Option<EventScope>> {
        match self.location_of(record_id, record_type, payload)? {
            Some(scope) if self.is_space_shared(scope.space_id) => Ok(Some(scope)),
            _ => Ok(None),
        }
    }

    /// Where a record lives in the tree, shared or not. For an existing
    /// record pass `payload = None` to read its location from the local
    /// parent chain (the op is then reported as a delete for content).
    pub(crate) fn location_of(
        &self,
        record_id: Uuid,
        record_type: RecordType,
        payload: Option<&RecordPayload>,
    ) -> Result<Option<EventScope>> {
        let deleting = payload.is_none();
        let parent_of = |id: Uuid| -> Result<Option<Uuid>> { Ok(records::get_record(&self.db, id)?.and_then(|r| r.parent_id)) };

        let (space, path, target, op): (Option<Uuid>, Vec<Uuid>, ScopeTarget, ScopeOp) = match record_type {
            RecordType::Space => (Some(record_id), vec![], ScopeTarget::Name, ScopeOp::Container),
            RecordType::Label => {
                let space = match payload {
                    Some(RecordPayload::Label(b)) => b.space_id.or(self.label_space(record_id)?),
                    _ => self.label_space(record_id)?,
                };
                (space, vec![record_id], ScopeTarget::Name, ScopeOp::Container)
            }
            RecordType::Item => {
                let label = match payload {
                    Some(RecordPayload::Item(b)) => Some(b.label_id),
                    _ => parent_of(record_id)?,
                };
                let Some(label) = label else { return Ok(None) };
                (self.label_space(label)?, vec![label, record_id], ScopeTarget::Name, ScopeOp::Container)
            }
            RecordType::Environment => {
                let item = match payload {
                    Some(RecordPayload::Environment(b)) => Some(b.item_id),
                    _ => parent_of(record_id)?,
                };
                let Some(item) = item else { return Ok(None) };
                let Some(label) = parent_of(item)? else { return Ok(None) };
                (self.label_space(label)?, vec![label, item, record_id], ScopeTarget::Name, ScopeOp::Container)
            }
            RecordType::Secret | RecordType::Asset | RecordType::Note => {
                let (item, env) = match payload {
                    Some(RecordPayload::Secret(b)) => (Some(b.item_id), b.environment_id),
                    Some(RecordPayload::Note(b)) => (Some(b.item_id), b.environment_id),
                    Some(RecordPayload::File(b)) => (Some(b.meta.item_id), b.meta.environment_id),
                    _ => {
                        let Some(parent) = parent_of(record_id)? else { return Ok(None) };
                        match records::get_record(&self.db, parent)? {
                            Some(p) if p.record_type == RecordType::Environment => (p.parent_id, Some(parent)),
                            Some(_) => (Some(parent), None),
                            None => return Ok(None),
                        }
                    }
                };
                let Some(item) = item else { return Ok(None) };
                let Some(label) = parent_of(item)? else { return Ok(None) };
                let op = if deleting { ScopeOp::Delete } else { ScopeOp::Write };
                match env {
                    Some(e) => (self.label_space(label)?, vec![label, item, e], ScopeTarget::Content, op),
                    None => (self.label_space(label)?, vec![label, item], ScopeTarget::General, op),
                }
            }
        };
        let Some(space_id) = space else { return Ok(None) };
        Ok(Some(EventScope { space_id, path, target, op }))
    }

    /// Event key and epoch for a scoped event this device writes.
    pub(crate) fn scoped_event_key(&self, scope: &EventScope) -> Result<(u32, Zeroizing<[u8; 32]>)> {
        let epoch = self.keyring.branch_epoch(scope.space_id).ok_or(Error::Forbidden)?;
        let key = self
            .keyring
            .branch_target_key(&self.secwet_id, scope, epoch)
            .ok_or(Error::Forbidden)?;
        Ok((epoch, key))
    }

    // ========================================================================
    // M8: tree listing for scope pickers
    // ========================================================================

    /// Space, groups, items, General and environments of a space, depth-first.
    pub fn scope_nodes(&self, space_id: Uuid) -> Result<Vec<ScopeNode>> {
        let space = self.get_space(space_id)?;
        let mut out = vec![ScopeNode {
            node: TreeNode::Space(space_id),
            label: space.name.clone(),
            depth: 0,
            parent: None,
        }];
        for label in self.list_labels_by_space(space_id)? {
            out.push(ScopeNode {
                node: TreeNode::Group(label.id),
                label: label.name.clone(),
                depth: 1,
                parent: Some(TreeNode::Space(space_id)),
            });
            for item in self.list_items(label.id)? {
                out.push(ScopeNode {
                    node: TreeNode::Item(item.id),
                    label: item.name.clone(),
                    depth: 2,
                    parent: Some(TreeNode::Group(label.id)),
                });
                out.push(ScopeNode {
                    node: TreeNode::General(item.id),
                    label: "General".into(),
                    depth: 3,
                    parent: Some(TreeNode::Item(item.id)),
                });
                for env in self.list_environments(item.id)? {
                    out.push(ScopeNode {
                        node: TreeNode::Environment(env.id),
                        label: env.name.clone(),
                        depth: 3,
                        parent: Some(TreeNode::Item(item.id)),
                    });
                }
            }
        }
        Ok(out)
    }

    /// Space that contains a tree node (for grant `space_id`).
    pub fn space_of_node(&self, node: TreeNode) -> Result<Option<Uuid>> {
        Ok(match node {
            TreeNode::Workspace => None,
            TreeNode::Space(s) => Some(s),
            TreeNode::Group(g) => self.label_space(g)?,
            TreeNode::Item(i) | TreeNode::General(i) => {
                let label = records::get_record(&self.db, i)?.and_then(|r| r.parent_id).ok_or(Error::NotFound)?;
                self.label_space(label)?
            }
            TreeNode::Environment(e) => {
                let item = records::get_record(&self.db, e)?.and_then(|r| r.parent_id).ok_or(Error::NotFound)?;
                let label = records::get_record(&self.db, item)?.and_then(|r| r.parent_id).ok_or(Error::NotFound)?;
                self.label_space(label)?
            }
        })
    }

    /// Human-readable path of a node: "Backend / auth-service / Production".
    pub fn node_label(&self, node: TreeNode) -> String {
        let name_of_item = |id: Uuid| -> Option<(String, Uuid)> {
            let row = records::get_record(&self.db, id).ok()??;
            let label_id = row.parent_id?;
            let item = self.list_items(label_id).ok()?.into_iter().find(|i| i.id == id)?;
            Some((item.name, label_id))
        };
        let group_name = |id: Uuid| -> Option<String> {
            self.list_labels().ok()?.into_iter().find(|l| l.id == id).map(|l| l.name)
        };
        let space_name = |id: Uuid| -> Option<String> { self.get_space(id).ok().map(|s| s.name) };
        let parts: Option<Vec<String>> = (|| match node {
            TreeNode::Workspace => Some(vec!["Whole workspace".to_string()]),
            TreeNode::Space(s) => Some(vec![space_name(s)?]),
            TreeNode::Group(g) => Some(vec![group_name(g)?]),
            TreeNode::Item(i) => {
                let (n, l) = name_of_item(i)?;
                Some(vec![group_name(l)?, n])
            }
            TreeNode::General(i) => {
                let (n, l) = name_of_item(i)?;
                Some(vec![group_name(l)?, n, "General".into()])
            }
            TreeNode::Environment(e) => {
                let item = records::get_record(&self.db, e).ok()??.parent_id?;
                let env = self.list_environments(item).ok()?.into_iter().find(|x| x.id == e)?;
                let (n, l) = name_of_item(item)?;
                Some(vec![group_name(l)?, n, env.name])
            }
        })();
        parts.map(|p| p.join(" / ")).unwrap_or_else(|| "Unavailable".into())
    }

    // ========================================================================
    // M8: branch keys
    // ========================================================================

    /// Children of a node in the local tree (for bundle computation).
    fn tree_children(&self, node: TreeNode) -> Result<Vec<TreeNode>> {
        Ok(match node {
            TreeNode::Space(s) => records::query_active_labels_by_space(&self.db, s)?
                .into_iter()
                .map(|l| TreeNode::Group(l.id))
                .collect(),
            TreeNode::Group(g) => records::query_items_by_label(&self.db, g)?
                .into_iter()
                .map(|r| TreeNode::Item(r.id))
                .collect(),
            TreeNode::Item(i) => {
                let mut v = vec![TreeNode::General(i)];
                v.extend(
                    records::query_environments_by_item(&self.db, i)?
                        .into_iter()
                        .map(|r| TreeNode::Environment(r.id)),
                );
                v
            }
            _ => vec![],
        })
    }

    fn subtree_nodes(&self, node: TreeNode, out: &mut Vec<TreeNode>) -> Result<()> {
        for c in self.tree_children(node)? {
            out.push(c);
            self.subtree_nodes(c, out)?;
        }
        Ok(())
    }

    /// Minimal key entries a member with `grants` needs in a space.
    pub(crate) fn compute_bundle_entries(&self, space_id: Uuid, root: &[u8; 32], grants: &[MemberGrant]) -> Result<Vec<BranchKeyEntry>> {
        let mut entries = Vec::new();
        let base = vec![TreeNode::Workspace];
        self.bundle_walk(TreeNode::Space(space_id), &base, &[space_id], root, grants, &mut entries)?;
        Ok(entries)
    }

    #[allow(clippy::too_many_arguments)]
    fn bundle_walk(
        &self,
        node: TreeNode,
        ancestors: &[TreeNode],
        id_path: &[Uuid],
        root: &[u8; 32],
        grants: &[MemberGrant],
        out: &mut Vec<BranchKeyEntry>,
    ) -> Result<bool> {
        let mut nodes = ancestors.to_vec();
        nodes.push(node);
        let role = secwet_proto::effective_role(grants, &nodes);
        let mut below = Vec::new();
        self.subtree_nodes(node, &mut below)?;
        let restricted = grants
            .iter()
            .any(|g| g.role == TreeRole::NoAccess && below.contains(&g.node));
        let node_secret = derive_path_secret(root, &self.secwet_id, &id_path[1..]);

        if let TreeNode::General(item) = node {
            if role.can_read() {
                let item_secret = derive_path_secret(root, &self.secwet_id, &id_path[1..id_path.len() - 1]);
                let k = derive_branch_purpose(&item_secret, &self.secwet_id, b"secwet/v1/branch/general");
                out.push(BranchKeyEntry { path: id_path[..id_path.len() - 1].to_vec(), kind: BranchKeyKind::General, key: *k });
                let _ = item;
                return Ok(true);
            }
            return Ok(false);
        }

        if role.can_read() && !restricted {
            out.push(BranchKeyEntry { path: id_path.to_vec(), kind: BranchKeyKind::Subtree, key: *node_secret });
            return Ok(true);
        }
        let mut any = false;
        for child in self.tree_children(node)? {
            let mut child_path = id_path.to_vec();
            if let TreeNode::General(_) = child {
                // General shares its item's id path; marker element dropped above.
                child_path.push(Uuid::nil());
            } else {
                child_path.push(child.id().ok_or(Error::Storage)?);
            }
            any |= self.bundle_walk(child, &nodes, &child_path, root, grants, out)?;
        }
        if any {
            let k = derive_branch_purpose(&node_secret, &self.secwet_id, b"secwet/v1/branch/name");
            out.push(BranchKeyEntry { path: id_path.to_vec(), kind: BranchKeyKind::Name, key: *k });
        }
        Ok(any)
    }

    /// Stores a verified bundle. A root already held for the same space and
    /// epoch is never replaced by a different one.
    fn store_bundle(&mut self, keystore: &dyn KeyStore, bundle: BranchKeyBundle, issuer_is_owner: bool) -> Result<bool> {
        let (space, epoch) = (bundle.space_id, bundle.epoch);
        if let (Some(old), Some(new_root)) = (
            self.space_root(space, epoch),
            bundle
                .entries
                .iter()
                .find(|e| e.kind == BranchKeyKind::Subtree && e.path == [space])
                .map(|e| e.key),
        ) {
            if !bool::from(old.ct_eq(&new_root)) {
                return Ok(false);
            }
        }
        let bytes = Zeroizing::new(postcard::to_stdvec(&bundle).map_err(|_| Error::Crypto)?);
        let digest: [u8; 32] = Sha256::digest(&*bytes).into();
        let stored: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT digest FROM collab_branches WHERE space_id = ?1 AND epoch = ?2",
                params![space.as_bytes().as_slice(), epoch as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?
            .flatten();
        if stored.as_deref() == Some(digest.as_slice()) {
            return Ok(false);
        }
        keystore.set(&format!("secwet/{}/branch-bundle/{}/{}", self.secwet_id, space, epoch), &bytes)?;
        self.db
            .execute(
                "INSERT OR REPLACE INTO collab_branches (space_id, epoch, received_at, digest) VALUES (?1, ?2, ?3, ?4)",
                params![space.as_bytes().as_slice(), epoch as i64, now_ms(), digest.as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        // On member stores, owner devices vouched for by a trusted owner
        // device become trusted: that is how members learn admin keys
        // without trusting the relay. Owner stores learn owner devices only
        // from pairing and certificates; member admins never vouch.
        if !self.is_owner() && issuer_is_owner {
            for a in &bundle.admins {
                self.certify_device(&a.device_id, &a.sign_pub, &a.enc_pub, None)?;
            }
        }
        self.keyring
            .branches
            .entry(space)
            .or_default()
            .insert(epoch, HeldBundle::from_proto(bundle));
        Ok(true)
    }

    fn bundle_aad(&self, space_id: Uuid, epoch: u32, device_id: &str) -> Result<Vec<u8>> {
        postcard::to_stdvec(&("secwet-branch-bundle-v1", self.secwet_id, space_id, epoch, device_id)).map_err(|_| Error::Crypto)
    }

    fn wrap_bundle(&self, device_id: &str, enc_pub: &[u8; 32], bundle: &BranchKeyBundle) -> Result<ScopedBranchKey> {
        let bundle_key = random_key();
        let info = postcard::to_stdvec(&KeyWrapInfo {
            purpose: BRANCH_BUNDLE_PURPOSE,
            secwet_id: self.secwet_id.as_bytes(),
            key_epoch: bundle.epoch,
            recipient_device_id: device_id,
        })
        .map_err(|_| Error::Crypto)?;
        let wrapped = crypto::wrap_for_device(enc_pub, &info, &bundle_key)?;
        let plain = Zeroizing::new(postcard::to_stdvec(bundle).map_err(|_| Error::Crypto)?);
        let sealed_bundle = crypto::seal_raw(&bundle_key, &self.bundle_aad(bundle.space_id, bundle.epoch, device_id)?, &plain)?;
        Ok(ScopedBranchKey {
            space_id: bundle.space_id,
            epoch: bundle.epoch,
            device_id: device_id.to_string(),
            wrapped,
            sealed_bundle,
            statement: None,
        })
    }

    fn unwrap_bundle(&self, sbk: &ScopedBranchKey) -> Result<BranchKeyBundle> {
        let info = postcard::to_stdvec(&KeyWrapInfo {
            purpose: BRANCH_BUNDLE_PURPOSE,
            secwet_id: self.secwet_id.as_bytes(),
            key_epoch: sbk.epoch,
            recipient_device_id: &self.device_id,
        })
        .map_err(|_| Error::Crypto)?;
        let enc = x25519_dalek::StaticSecret::from(*self.enc_secret.expose_secret());
        let bundle_key = crypto::unwrap_for_me(&enc, &info, &sbk.wrapped)?;
        let plain = Zeroizing::new(crypto::open_raw(&bundle_key, &self.bundle_aad(sbk.space_id, sbk.epoch, &self.device_id)?, &sbk.sealed_bundle)?);
        let bundle: BranchKeyBundle = postcard::from_bytes(&plain).map_err(|_| Error::Crypto)?;
        if bundle.secwet_id != self.secwet_id || bundle.space_id != sbk.space_id || bundle.epoch != sbk.epoch {
            return Err(Error::Crypto);
        }
        Ok(bundle)
    }

    /// Checks the signed publish a bundle came from: a trusted issuer that
    /// may administer the space, and a digest matching these exact bytes.
    /// Returns `Some(issuer_is_owner)` when the statement verifies.
    fn verify_bundle_statement(&self, sbk: &ScopedBranchKey) -> Option<bool> {
        let Some(signed) = &sbk.statement else { return None };
        let st = &signed.statement;
        if st.secwet_id != self.secwet_id || st.space_id != sbk.space_id || st.epoch != sbk.epoch {
            return None;
        }
        let Ok(input) = sbk.digest_input() else { return None };
        let digest: [u8; 32] = Sha256::digest(&input).into();
        if !st.digests.iter().any(|d| d.device_id == self.device_id && bool::from(d.digest.ct_eq(&digest))) {
            return None;
        }
        let mut issuer_is_owner = self.is_owner() && st.issuer_device_id == self.device_id;
        let issuer_pub = if st.issuer_device_id == self.device_id {
            self.device_sign_pub
        } else {
            let (trust, member) = self.device_trust(&st.issuer_device_id)?;
            if trust != "certified" {
                return None;
            }
            issuer_is_owner = member.is_none();
            if member.is_some() && self.is_invite_anchor(&st.issuer_device_id) {
                // The member admin who invited this store: the relay checked
                // its admin rights when the invitation was created.
            } else if let Some(m) = member {
                // A member admin may publish only for spaces its verified
                // grants let it administer (owner stores hold those grants).
                let ok = self
                    .member_grants_local(m)
                    .ok()
                    .flatten()
                    .filter(|g| self.verify_grant_set(g, m))
                    .map(|g| {
                        secwet_proto::effective_role(&g.set.grants, &[TreeNode::Workspace, TreeNode::Space(st.space_id)])
                            .can_manage()
                    })
                    .unwrap_or(false);
                if !ok {
                    return None;
                }
            }
            match self.device_sign_pub_of(&st.issuer_device_id) {
                Ok(Some((pk, _))) => pk,
                _ => return None,
            }
        };
        let Ok(bytes) = st.signing_bytes() else { return None };
        crypto::verify_signature_strict_bytes(&issuer_pub, &bytes, &signed.signature)
            .ok()
            .map(|_| issuer_is_owner)
    }

    /// Downloads and stores every branch bundle addressed to this device whose
    /// signed publish verifies. Returns the number of newly stored bundles.
    pub async fn refresh_branch_keys(&mut self, client: &RelayClient, keystore: &dyn KeyStore) -> Result<usize> {
        let resp = client.get_branch_keys(self.secwet_id, &self.device_sign_key).await?;
        for sc in &resp.scopes {
            self.db
                .execute(
                    "INSERT OR REPLACE INTO collab_scopes (space_id, current_epoch) VALUES (?1, ?2)",
                    params![sc.space_id.as_bytes().as_slice(), sc.current_epoch as i64],
                )
                .map_err(|_| Error::Storage)?;
        }
        let mut stored = 0;
        let mut keys = resp.keys.clone();
        keys.sort_by_key(|k| k.epoch);
        for sbk in &keys {
            if sbk.device_id != self.device_id {
                continue;
            }
            let Some(issuer_is_owner) = self.verify_bundle_statement(sbk) else { continue };
            let Ok(bundle) = self.unwrap_bundle(sbk) else { continue };
            if self.store_bundle(keystore, bundle, issuer_is_owner)? {
                stored += 1;
            }
        }
        if stored > 0 {
            self.flush_pending_emits()?;
            self.reencrypt_outbox()?;
        }
        self.last_scopes = resp.scopes;
        Ok(stored)
    }

    /// Fetches this device's role (member stores) or every member's signed
    /// grants (owner stores) so incoming events can be authorized locally.
    pub async fn refresh_access(&mut self, client: &RelayClient) -> Result<()> {
        if self.is_owner() {
            let members = client.list_members(self.secwet_id, &self.device_sign_key).await?;
            for m in &members.members {
                if !self.verify_grant_set(&m.grants, m.member_id) {
                    continue;
                }
                let status = if m.status == secwet_proto::MemberStatus::Removed { "removed" } else { m.status.as_str() };
                self.upsert_member_row(m.member_id, None, &m.grants, status, None)?;
            }
        } else if let Some(me) = self.member_id {
            let access = client.get_access(self.secwet_id, &self.device_sign_key).await?;
            if let Some(g) = access.grants {
                let current = self.my_grant_set();
                let newer = current.as_ref().map(|c| g.set.version > c.set.version).unwrap_or(true);
                if newer && self.verify_grant_set(&g, me) {
                    let bytes = postcard::to_stdvec(&g).map_err(|_| Error::Storage)?;
                    set_meta(&self.db, "my_grants", &data_encoding::HEXLOWER.encode(&bytes))?;
                }
            }
        }
        Ok(())
    }

    fn my_grant_set(&self) -> Option<SignedGrantSet> {
        get_meta(&self.db, "my_grants")
            .ok()
            .flatten()
            .and_then(|hex| data_encoding::HEXLOWER.decode(hex.as_bytes()).ok())
            .and_then(|b| postcard::from_bytes::<SignedGrantSet>(&b).ok())
    }

    /// A grant set counts only when it names the expected member, every grant
    /// is labelled with the space its node is in, and its issuer is a trusted
    /// owner device (or this device), or a trusted member admin of every space
    /// it grants.
    pub(crate) fn verify_grant_set(&self, g: &SignedGrantSet, member_id: Uuid) -> bool {
        if g.set.secwet_id != self.secwet_id || g.set.member_id != member_id {
            return false;
        }
        if secwet_proto::validate_grants(&g.set.grants).is_err() {
            return false;
        }
        if self.is_owner() {
            for gr in &g.set.grants {
                if gr.node == TreeNode::Workspace {
                    continue;
                }
                // Nodes this store has placed must sit in the space the grant
                // names; nodes not synced yet cannot be checked here and are
                // still bound to their label by effective_role.
                if let Ok(Some(sp)) = self.space_of_node(gr.node) {
                    if Some(sp) != gr.space_id {
                        return false;
                    }
                }
            }
        }
        let pk = if g.set.issuer_device_id == self.device_id {
            self.device_sign_pub
        } else {
            let Some((trust, issuer_member)) = self.device_trust(&g.set.issuer_device_id) else { return false };
            if trust != "certified" {
                return false;
            }
            if issuer_member.is_some() && self.is_invite_anchor(&g.set.issuer_device_id) && Some(member_id) == self.member_id {
                // This store's own grants, issued by the member admin who invited it.
            } else if let Some(im) = issuer_member {
                if im == member_id {
                    return false;
                }
                let Some(ig) = self.member_grants_local(im).ok().flatten() else { return false };
                let spaces: Vec<Uuid> = g.set.grants.iter().filter_map(|x| x.space_id).collect();
                let all_admin = !g.set.grants.iter().any(|x| x.node == TreeNode::Workspace)
                    && spaces.iter().all(|s| {
                        secwet_proto::effective_role(&ig.set.grants, &[TreeNode::Workspace, TreeNode::Space(*s)]).can_manage()
                    });
                if !all_admin {
                    return false;
                }
            }
            match self.device_sign_pub_of(&g.set.issuer_device_id) {
                Ok(Some((pk, _))) => pk,
                _ => return false,
            }
        };
        let Ok(bytes) = g.set.signing_bytes() else { return false };
        crypto::verify_signature_strict_bytes(&pk, &bytes, &g.signature).is_ok()
    }

    /// Records a member locally. Grants only ever move forward in version,
    /// and a member recorded as removed stays removed.
    fn upsert_member_row(
        &mut self,
        member_id: Uuid,
        email: Option<&str>,
        grants: &SignedGrantSet,
        status: &str,
        invitation_id: Option<Uuid>,
    ) -> Result<()> {
        let existing = self.member_grants_local(member_id)?;
        let replace_grants = existing.as_ref().map(|e| grants.set.version > e.set.version).unwrap_or(true);
        let grants_bytes = postcard::to_stdvec(grants).map_err(|_| Error::Storage)?;
        let email_blob = match email {
            Some(e) => Some(crypto::seal_raw(self.k_rec.expose_secret(), &self.member_email_aad(member_id)?, e.as_bytes())?),
            None => None,
        };
        let now = now_ms();
        self.db
            .execute(
                "INSERT INTO collab_members (member_id, email_blob, grants, status, invitation_id, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                 ON CONFLICT(member_id) DO UPDATE SET
                    email_blob = COALESCE(?2, email_blob),
                    grants = CASE WHEN ?7 THEN ?3 ELSE grants END,
                    status = CASE WHEN status = 'removed' THEN 'removed' ELSE ?4 END,
                    invitation_id = COALESCE(?5, invitation_id),
                    updated_at = ?6",
                params![
                    member_id.as_bytes().as_slice(),
                    email_blob,
                    grants_bytes,
                    status,
                    invitation_id.map(|i| i.as_bytes().to_vec()),
                    now,
                    replace_grants,
                ],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    fn member_email_aad(&self, member_id: Uuid) -> Result<Vec<u8>> {
        postcard::to_stdvec(&("secwet-member-email-v1", self.secwet_id, member_id)).map_err(|_| Error::Crypto)
    }

    fn member_grants_local(&self, member_id: Uuid) -> Result<Option<SignedGrantSet>> {
        let bytes: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT grants FROM collab_members WHERE member_id = ?1",
                params![member_id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        Ok(bytes.and_then(|b| postcard::from_bytes(&b).ok()))
    }

    fn member_status_local(&self, member_id: Uuid) -> Option<String> {
        self.db
            .query_row(
                "SELECT status FROM collab_members WHERE member_id = ?1",
                params![member_id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
    }

    /// Root secret of a space at an epoch, if this device holds it.
    fn space_root(&self, space_id: Uuid, epoch: u32) -> Option<Zeroizing<[u8; 32]>> {
        self.keyring
            .branches
            .get(&space_id)?
            .get(&epoch)?
            .root(space_id)
            .map(|k| Zeroizing::new(**k))
    }

    /// Whether this device may administer a space (share, invite, rotate).
    fn can_admin_space(&self, space_id: Uuid) -> bool {
        if self.is_owner() {
            return true;
        }
        let role = secwet_proto::effective_role(&self.my_grants(), &[TreeNode::Workspace, TreeNode::Space(space_id)]);
        role.can_manage()
            && self
                .keyring
                .branch_epoch(space_id)
                .and_then(|e| self.space_root(space_id, e))
                .is_some()
    }

    /// Publishes branch bundles for a space to every authorized device and
    /// returns the epoch and the recipients.
    ///
    /// Recipients come from this store's trusted devices only: the owner's
    /// certified devices get the root, and each member's certified devices
    /// get the minimal keys their locally verified grants allow. The relay's
    /// lists can only remove devices (revoked or not registered).
    ///
    /// `rotate = true` (or a space not shared yet) creates a fresh root at the
    /// next epoch; a conflicting rotation by another admin is adopted and
    /// then rotated past once more, so a removal is never undone by a race.
    pub async fn publish_space_keys(
        &mut self,
        client: &RelayClient,
        keystore: &dyn KeyStore,
        space_id: Uuid,
        rotate: bool,
    ) -> Result<(u32, Vec<String>)> {
        match self.publish_space_keys_once(client, keystore, space_id, rotate).await {
            Err(Error::Relay { code }) if code == "epoch_conflict" => {
                self.refresh_branch_keys(client, keystore).await?;
                self.publish_space_keys_once(client, keystore, space_id, rotate).await
            }
            other => other,
        }
    }

    async fn publish_space_keys_once(
        &mut self,
        client: &RelayClient,
        keystore: &dyn KeyStore,
        space_id: Uuid,
        rotate: bool,
    ) -> Result<(u32, Vec<String>)> {
        self.ensure_writable()?;
        let space = self.get_space(space_id)?;
        if space.is_default {
            return Err(Error::Invalid {
                field: "space",
                message: "The Personal space can't be shared.".into(),
            });
        }
        if !self.can_admin_space(space_id) {
            return Err(Error::Forbidden);
        }
        let current = self.keyring.branch_epoch(space_id);
        let new_root = rotate || current.is_none();
        let (epoch, root) = if new_root {
            (current.map(|e| e + 1).unwrap_or(1), random_key())
        } else {
            let e = current.ok_or(Error::Forbidden)?;
            (e, self.space_root(space_id, e).ok_or(Error::Forbidden)?)
        };

        let relay_devices = self.refresh_devices_from_relay(client).await?;
        let relay_active: HashSet<String> = relay_devices
            .devices
            .iter()
            .filter(|d| d.revoked_at.is_none())
            .map(|d| d.id.clone())
            .collect();
        // Members whose verified grants we hold; the relay's member list only
        // confirms who is still active.
        let relay_members = client.list_members(self.secwet_id, &self.device_sign_key).await?;
        let admins = self.certified_owner_devices()?;

        let mut targets: Vec<(secwet_proto::TrustedDevice, Vec<BranchKeyEntry>)> = Vec::new();
        for d in &admins {
            if relay_active.contains(&d.device_id) {
                targets.push((d.clone(), vec![BranchKeyEntry { path: vec![space_id], kind: BranchKeyKind::Subtree, key: *root }]));
            }
        }
        for m in &relay_members.members {
            if m.status == secwet_proto::MemberStatus::Removed || self.member_status_local(m.member_id).as_deref() == Some("removed") {
                continue;
            }
            let Some(g) = self.member_grants_local(m.member_id)? else { continue };
            if !self.verify_grant_set(&g, m.member_id) {
                continue;
            }
            let touches = match secwet_proto::granted_spaces(&g.set.grants) {
                None => true,
                Some(list) => list.contains(&space_id),
            };
            if !touches {
                continue;
            }
            let entries = self.compute_bundle_entries(space_id, &root, &g.set.grants)?;
            if entries.is_empty() {
                continue;
            }
            for d in self.certified_member_devices(m.member_id)? {
                if relay_active.contains(&d.device_id) {
                    targets.push((d, entries.clone()));
                }
            }
        }

        let mut keys = Vec::new();
        let mut own_bundle: Option<BranchKeyBundle> = None;
        for (d, entries) in targets {
            let bundle = BranchKeyBundle {
                secwet_id: self.secwet_id,
                space_id,
                epoch,
                entries,
                admins: admins.clone(),
            };
            keys.push(self.wrap_bundle(&d.device_id, &d.enc_pub, &bundle)?);
            if d.device_id == self.device_id {
                own_bundle = Some(bundle);
            }
        }
        keys.sort_by(|a, b| a.device_id.cmp(&b.device_id));
        let mut digests = Vec::with_capacity(keys.len());
        for k in &keys {
            let input = k.digest_input().map_err(|_| Error::Crypto)?;
            digests.push(secwet_proto::BranchKeyDigest {
                device_id: k.device_id.clone(),
                digest: Sha256::digest(&input).into(),
            });
        }
        let statement = BranchPublishStatement {
            secwet_id: self.secwet_id,
            space_id,
            epoch,
            rotate: new_root,
            issuer_device_id: self.device_id.clone(),
            digests,
        };
        let sig = crypto::sign_payload(&self.device_sign_key, &statement.signing_bytes().map_err(|_| Error::Crypto)?);
        let recipients: Vec<String> = keys.iter().map(|k| k.device_id.clone()).collect();
        let req = PublishBranchKeysRequest { statement, signature: sig.to_bytes(), keys };
        client.publish_branch_keys(self.secwet_id, &req, &self.device_sign_key).await?;
        if let Some(b) = own_bundle {
            self.store_bundle(keystore, b, self.is_owner())?;
        }
        self.db
            .execute(
                "INSERT OR REPLACE INTO collab_scopes (space_id, current_epoch) VALUES (?1, ?2)",
                params![space_id.as_bytes().as_slice(), epoch as i64],
            )
            .map_err(|_| Error::Storage)?;
        self.db
            .execute("DELETE FROM collab_dirty_spaces WHERE space_id = ?1", params![space_id.as_bytes().as_slice()])
            .map_err(|_| Error::Storage)?;
        self.flush_pending_emits()?;
        if new_root {
            self.reencrypt_outbox()?;
            self.seed_space_events(space_id)?;
        }
        Ok((epoch, recipients))
    }

    /// Re-emits every record of a shared space as scoped `Seed` events under
    /// the current branch epoch. Seeds are applied only by devices that do
    /// not have the record yet, with the original author as origin, so they
    /// never win last-writer-wins. Returns the number of events queued.
    pub fn seed_space_events(&mut self, space_id: Uuid) -> Result<usize> {
        let mut count = 0;
        let lamport_origin = |db: &Connection, id: Uuid, me: &str| -> (u64, String) {
            records::get_record(db, id)
                .ok()
                .flatten()
                .map(|r| (r.lamport, r.origin_device))
                .unwrap_or((0, me.to_string()))
        };

        let space_row = records::get_space(&self.db, space_id)?.ok_or(Error::NotFound)?;
        let aad = RecordAad::new(self.secwet_id.as_bytes(), space_id.as_bytes(), RecordType::Label, self.key_epoch);
        let body: SpaceBody = postcard::from_bytes(&Zeroizing::new(self.open_rec(&aad, &space_row.name_blob)?)).map_err(|_| Error::Storage)?;
        let (l, o) = lamport_origin(&self.db, space_id, &self.device_id);
        self.enqueue_seed(space_id, RecordType::Space, l, &o, &RecordPayload::Space(body))?;
        count += 1;

        for label in records::query_active_labels_by_space(&self.db, space_id)? {
            let aad = RecordAad::new(self.secwet_id.as_bytes(), label.id.as_bytes(), RecordType::Label, self.key_epoch);
            let pt = Zeroizing::new(self.open_rec(&aad, &label.name_blob)?);
            let mut body = crate::secwet::deserialize_label_body_pub(&pt)?;
            body.space_id = Some(space_id);
            let (l, o) = lamport_origin(&self.db, label.id, &self.device_id);
            self.enqueue_seed(label.id, RecordType::Label, l, &o, &RecordPayload::Label(body))?;
            count += 1;
            for item in records::query_items_by_label(&self.db, label.id)? {
                count += self.seed_record(&item)?;
                for env in records::query_environments_by_item(&self.db, item.id)? {
                    count += self.seed_record(&env)?;
                }
                for rt in [RecordType::Secret, RecordType::Asset, RecordType::Note] {
                    for rec in records::query_all_item_content_records(&self.db, item.id, rt)? {
                        count += self.seed_record(&rec)?;
                    }
                }
            }
        }
        Ok(count)
    }

    fn seed_record(&self, row: &records::RecordRow) -> Result<usize> {
        let Some(blob) = &row.blob else { return Ok(0) };
        if row.deleted {
            return Ok(0);
        }
        let aad = RecordAad::new(self.secwet_id.as_bytes(), row.id.as_bytes(), row.record_type, row.key_epoch);
        let pt = match self.open_rec(&aad, blob) {
            Ok(p) => Zeroizing::new(p),
            Err(_) => return Ok(0),
        };
        let Ok(payload) = RecordPayload::from_bytes(row.record_type, &pt) else { return Ok(0) };
        self.enqueue_seed(row.id, row.record_type, row.lamport, &row.origin_device, &payload)?;
        Ok(1)
    }

    fn enqueue_seed(&self, record_id: Uuid, record_type: RecordType, lamport: u64, origin: &str, payload: &RecordPayload) -> Result<()> {
        let Some(scope) = self.scope_for_mutation(record_id, record_type, Some(payload))? else { return Ok(()) };
        let Ok((epoch, key)) = self.scoped_event_key(&scope) else { return Ok(()) };
        let body = EventBody::Seed {
            record_id,
            record_type: record_type.into(),
            lamport,
            origin_device: origin.to_string(),
            body: payload.to_bytes().map_err(|_| Error::Crypto)?,
        };
        let seq = sync::next_device_seq(&self.db, &self.device_id)?;
        let ev = sync::create_signed_event_scoped(
            self.secwet_id,
            &self.device_id,
            seq,
            epoch,
            &key,
            &self.device_sign_key,
            &body,
            Some(scope),
        )?;
        sync::enqueue_outbox(&self.db, &ev)
    }

    /// Remembers a write in a shared space this device cannot encrypt yet
    /// (its bundle has not arrived); it is emitted once the key is here.
    pub(crate) fn queue_pending_emit(&self, record_id: Uuid, record_type: RecordType) -> Result<()> {
        self.db
            .execute(
                "INSERT OR REPLACE INTO collab_pending_emit (record_id, record_type) VALUES (?1, ?2)",
                params![record_id.as_bytes().as_slice(), u8::from(record_type) as i64],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    /// Emits queued writes whose branch key is now available, using the
    /// record's current state (an upsert, or a delete for a tombstone).
    pub(crate) fn flush_pending_emits(&self) -> Result<usize> {
        let rows: Vec<(Vec<u8>, i64)> = {
            let mut stmt = self
                .db
                .prepare("SELECT record_id, record_type FROM collab_pending_emit")
                .map_err(|_| Error::Storage)?;
            let it = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(|_| Error::Storage)?;
            it.flatten().collect()
        };
        let mut n = 0;
        for (id, rt) in rows {
            let (Ok(id), Ok(rt)) = (Uuid::from_slice(&id), RecordType::try_from(rt as u8)) else { continue };
            let row = records::get_record(&self.db, id)?;
            let payload = match &row {
                Some(r) if !r.deleted => {
                    let Some(blob) = &r.blob else { continue };
                    let aad = RecordAad::new(self.secwet_id.as_bytes(), id.as_bytes(), rt, r.key_epoch);
                    let Ok(pt) = self.open_rec(&aad, blob) else { continue };
                    RecordPayload::from_bytes(rt, &Zeroizing::new(pt)).ok()
                }
                _ => None,
            };
            let Some(scope) = self.scope_for_mutation(id, rt, payload.as_ref())? else { continue };
            if self.scoped_event_key(&scope).is_err() {
                continue;
            }
            let lamport = row.as_ref().map(|r| r.lamport).unwrap_or(0);
            self.enqueue_mutation_event(&self.db, id, rt, lamport, payload.as_ref())?;
            self.db
                .execute("DELETE FROM collab_pending_emit WHERE record_id = ?1", params![id.as_bytes().as_slice()])
                .map_err(|_| Error::Storage)?;
            n += 1;
        }
        Ok(n)
    }

    /// Marks a shared space so its bundles are republished on the next sync
    /// (a new container may need keys for restricted members).
    pub(crate) fn mark_space_dirty(&self, space_id: Option<Uuid>) {
        if let Some(s) = space_id {
            if self.is_owner() && self.is_space_shared(s) {
                let _ = self.db.execute(
                    "INSERT OR IGNORE INTO collab_dirty_spaces (space_id) VALUES (?1)",
                    params![s.as_bytes().as_slice()],
                );
            }
        }
    }

    /// Finishes branch rotations queued by revocations and removals.
    pub async fn process_pending_rotations(&mut self, client: &RelayClient, keystore: &dyn KeyStore) -> Result<usize> {
        let mut n = 0;
        for s in self.pending("branch_rotate")? {
            if !self.is_space_shared(s) || !self.can_admin_space(s) {
                self.clear_pending("branch_rotate", s)?;
                continue;
            }
            self.publish_space_keys(client, keystore, s, true).await?;
            self.clear_pending("branch_rotate", s)?;
            n += 1;
        }
        Ok(n)
    }

    /// Republishes a shared space to trusted owner devices that do not hold
    /// its current epoch yet (devices paired after the space was shared).
    pub async fn ensure_owner_coverage(&mut self, client: &RelayClient, keystore: &dyn KeyStore) -> Result<usize> {
        if !self.is_owner() {
            return Ok(0);
        }
        let owners: HashSet<String> = self.certified_owner_devices()?.into_iter().map(|d| d.device_id).collect();
        let relay_active: HashSet<String> = self
            .refresh_devices_from_relay(client)
            .await?
            .devices
            .into_iter()
            .filter(|d| d.revoked_at.is_none())
            .map(|d| d.id)
            .collect();
        let mut n = 0;
        for sc in self.last_scopes.clone() {
            if self.space_root(sc.space_id, sc.current_epoch).is_none() {
                continue;
            }
            let missing = owners
                .iter()
                .any(|o| relay_active.contains(o) && !sc.recipients.contains(o));
            if missing {
                self.publish_space_keys(client, keystore, sc.space_id, false).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    // ========================================================================
    // M8: members and invitations (admin side)
    // ========================================================================

    fn sign_grant_set(&self, member_id: Uuid, version: u64, grants: Vec<MemberGrant>) -> Result<SignedGrantSet> {
        let set = MemberGrantSet {
            secwet_id: self.secwet_id,
            member_id,
            version,
            grants,
            issuer_device_id: self.device_id.clone(),
            issued_at: now_ms(),
        };
        let sig = crypto::sign_payload(&self.device_sign_key, &set.signing_bytes().map_err(|_| Error::Crypto)?);
        Ok(SignedGrantSet { set, signature: sig.to_bytes() })
    }

    /// Fills in `space_id` for each grant from the local tree and validates.
    pub fn normalize_grants(&self, grants: &[(TreeNode, TreeRole)]) -> Result<Vec<MemberGrant>> {
        let mut out = Vec::with_capacity(grants.len());
        for (node, role) in grants {
            let space_id = self.space_of_node(*node)?;
            if let Some(s) = space_id {
                if self.get_space(s)?.is_default {
                    return Err(Error::Invalid {
                        field: "grants",
                        message: "The Personal space can't be shared.".into(),
                    });
                }
            }
            out.push(MemberGrant { node: *node, space_id, role: *role });
        }
        secwet_proto::validate_grants(&out).map_err(|m| Error::Invalid {
            field: "grants",
            message: m.to_string(),
        })?;
        Ok(out)
    }

    fn spaces_touched(&self, grants: &[MemberGrant]) -> Result<Vec<Uuid>> {
        Ok(match secwet_proto::granted_spaces(grants) {
            Some(list) => list,
            None => self
                .list_spaces()?
                .into_iter()
                .filter(|s| !s.is_default && self.is_space_shared(s.id))
                .map(|s| s.id)
                .collect(),
        })
    }

    /// Invites a collaborator by email with the given grants. Spaces named by
    /// the grants are shared first if needed. Returns the one-time link.
    pub async fn invite_member(
        &mut self,
        client: &RelayClient,
        keystore: &dyn KeyStore,
        email: &str,
        grants: &[(TreeNode, TreeRole)],
    ) -> Result<InviteResult> {
        self.ensure_writable()?;
        let email = validate_email(email)?;
        let grants = self.normalize_grants(grants)?;
        let spaces: Vec<Uuid> = grants.iter().filter_map(|g| g.space_id).collect::<HashSet<_>>().into_iter().collect();
        for s in &spaces {
            if !self.can_admin_space(*s) {
                return Err(Error::Forbidden);
            }
        }
        if grants.iter().any(|g| g.node == TreeNode::Workspace) && !self.is_owner() {
            return Err(Error::Forbidden);
        }
        for s in &spaces {
            if !self.is_space_shared(*s) {
                self.publish_space_keys(client, keystore, *s, true).await?;
            }
        }

        let invitation_id = Uuid::new_v4();
        let member_id = Uuid::new_v4();
        let token = random_key();
        let auth = invite_auth(&token, &invitation_id);
        let token_hash: [u8; 32] = Sha256::digest(*auth).into();
        let expires_at = now_ms() + secwet_proto::INVITATION_TTL_MS;
        let signed = self.sign_grant_set(member_id, 1, grants)?;
        let req = InviteCollaboratorRequest {
            invitation_id,
            member_id,
            email_hash: email_hash(&token, &invitation_id, &email),
            token_hash,
            expires_at,
            grants: signed.clone(),
        };
        client.create_invitation(self.secwet_id, &req, &self.device_sign_key).await?;

        let secret = Zeroizing::new(postcard::to_stdvec(&(email.as_str(), *token)).map_err(|_| Error::Crypto)?);
        let secret_blob = crypto::seal_raw(self.k_rec.expose_secret(), &self.invitation_aad(invitation_id)?, &secret)?;
        self.db
            .execute(
                "INSERT INTO collab_invitations (invitation_id, member_id, secret_blob, status, created_at, expires_at)
                 VALUES (?1, ?2, ?3, 'pending', ?4, ?5)",
                params![invitation_id.as_bytes().as_slice(), member_id.as_bytes().as_slice(), secret_blob, now_ms(), expires_at],
            )
            .map_err(|_| Error::Storage)?;
        self.upsert_member_row(member_id, Some(&email), &signed, "invited", Some(invitation_id))?;

        let relay = self.relay_url()?;
        let me = secwet_proto::TrustedDevice {
            device_id: self.device_id.clone(),
            sign_pub: self.device_sign_pub,
            enc_pub: self.device_enc_pub,
        };
        Ok(InviteResult {
            invitation_id,
            member_id,
            link: format_invite_link(&self.secwet_id, &invitation_id, &token, &relay, &me, self.member_id),
            expires_at,
        })
    }

    fn invitation_aad(&self, invitation_id: Uuid) -> Result<Vec<u8>> {
        postcard::to_stdvec(&("secwet-invitation-v1", self.secwet_id, invitation_id)).map_err(|_| Error::Crypto)
    }

    fn invitation_secret(&self, invitation_id: Uuid) -> Result<Option<(String, Zeroizing<[u8; 32]>)>> {
        let blob: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT secret_blob FROM collab_invitations WHERE invitation_id = ?1",
                params![invitation_id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .map_err(|_| Error::Storage)?;
        let Some(blob) = blob else { return Ok(None) };
        let pt = Zeroizing::new(self.open_raw_any(&self.invitation_aad(invitation_id)?, &blob)?);
        let (email, token): (String, [u8; 32]) = postcard::from_bytes(&pt).map_err(|_| Error::Crypto)?;
        Ok(Some((email, Zeroizing::new(token))))
    }

    fn open_raw_any(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>> {
        for keys in self.keyring.epochs.values().rev() {
            if let Ok(pt) = crypto::open_raw(&keys.rec, aad, blob) {
                return Ok(pt);
            }
        }
        Err(Error::Crypto)
    }

    /// Admin side of step 3 in §7: for every accepted invitation this device
    /// created, verify the key binding, certify the device, deliver branch
    /// keys and seed the shared data, then activate the invitation.
    pub async fn process_invitations(&mut self, client: &RelayClient, keystore: &dyn KeyStore) -> Result<usize> {
        if self.unlinked_at()?.is_some() {
            return Ok(0);
        }
        let members = client.list_members(self.secwet_id, &self.device_sign_key).await?;
        let mut delivered = 0;
        for inv in members.invitations.iter().filter(|i| i.status == InvitationStatus::Accepted) {
            let Some((_email, token)) = self.invitation_secret(inv.invitation_id)? else { continue };
            let Some(acc) = &inv.acceptance else { continue };
            let expected = invite_binding(&token, &inv.invitation_id, &acc.sign_pub, &acc.enc_pub);
            let ok = bool::from(expected.ct_eq(&acc.binding)) && crypto::compute_device_id(&acc.sign_pub) == acc.device_id;
            if !ok {
                // Keys were swapped in transit: withdraw the invitation.
                let _ = client.delete_invitation(self.secwet_id, inv.invitation_id, &self.device_sign_key).await;
                self.set_invitation_status(inv.invitation_id, "revoked")?;
                continue;
            }
            let Some(local) = self.member_grants_local(inv.member_id)? else { continue };
            self.certify_device(&acc.device_id, &acc.sign_pub, &acc.enc_pub, Some(inv.member_id))?;
            self.emit_device_certificate(&acc.device_id, &acc.sign_pub, &acc.enc_pub, Some(inv.member_id))?;
            self.upsert_member_row(inv.member_id, None, &local, "active", None)?;
            let mut all_delivered = true;
            for s in self.spaces_touched(&local.set.grants)? {
                if !self.can_admin_space(s) {
                    continue;
                }
                let (_, recipients) = self.publish_space_keys(client, keystore, s, false).await?;
                if !recipients.contains(&acc.device_id) {
                    all_delivered = false;
                }
                // The member joined after this data was written: send it again.
                self.seed_space_events(s)?;
            }
            if !all_delivered {
                continue;
            }
            client.activate_invitation(self.secwet_id, inv.invitation_id, &self.device_sign_key).await?;
            self.set_invitation_status(inv.invitation_id, "active")?;
            delivered += 1;
        }
        Ok(delivered)
    }

    fn set_invitation_status(&self, invitation_id: Uuid, status: &str) -> Result<()> {
        self.db
            .execute(
                "UPDATE collab_invitations SET status = ?1 WHERE invitation_id = ?2",
                params![status, invitation_id.as_bytes().as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    /// Withdraws a pending invitation.
    pub async fn revoke_invitation(&mut self, client: &RelayClient, invitation_id: Uuid) -> Result<()> {
        self.ensure_writable()?;
        client.delete_invitation(self.secwet_id, invitation_id, &self.device_sign_key).await?;
        self.set_invitation_status(invitation_id, "revoked")?;
        self.db
            .execute(
                "UPDATE collab_members SET status = 'removed' WHERE invitation_id = ?1 AND status = 'invited'",
                params![invitation_id.as_bytes().as_slice()],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    /// Replaces a member's grants. A downgrade rotates every affected space's
    /// branch key; otherwise bundles are republished at the current epoch and
    /// spaces the member gains are seeded. The previous grants come from this
    /// store's own verified record, never from the relay.
    pub async fn set_member_grants(
        &mut self,
        client: &RelayClient,
        keystore: &dyn KeyStore,
        member_id: Uuid,
        grants: &[(TreeNode, TreeRole)],
    ) -> Result<()> {
        self.ensure_writable()?;
        let grants = self.normalize_grants(grants)?;
        if self.member_status_local(member_id).as_deref() == Some("removed") {
            return Err(Error::NotFound);
        }
        let local = self.member_grants_local(member_id)?.filter(|g| self.verify_grant_set(g, member_id));
        let remote = client
            .list_members(self.secwet_id, &self.device_sign_key)
            .await?
            .members
            .into_iter()
            .find(|m| m.member_id == member_id)
            .ok_or(Error::NotFound)?;
        let version = local
            .as_ref()
            .map(|g| g.set.version)
            .unwrap_or(0)
            .max(remote.grants.set.version);
        let old = match &local {
            Some(g) => g.set.grants.clone(),
            None if self.verify_grant_set(&remote.grants, member_id) => remote.grants.set.grants.clone(),
            None => Vec::new(),
        };
        let old_spaces: HashSet<Uuid> = self.spaces_touched(&old)?.into_iter().collect();
        let new_spaces: HashSet<Uuid> = self.spaces_touched(&grants)?.into_iter().collect();
        for s in old_spaces.union(&new_spaces) {
            if !self.can_admin_space(*s) {
                return Err(Error::Forbidden);
            }
        }
        let downgrade = secwet_proto::is_downgrade(&old, &grants);
        // Record the rotations before telling the relay, so they happen even
        // if this call is interrupted after the relay accepted the change.
        for s in &old_spaces {
            if downgrade || !new_spaces.contains(s) {
                self.queue_pending("branch_rotate", *s)?;
            }
        }
        let signed = self.sign_grant_set(member_id, version + 1, grants.clone())?;
        client
            .update_member_grants(self.secwet_id, member_id, &UpdateMemberGrantsRequest { grants: signed.clone() }, &self.device_sign_key)
            .await?;
        self.upsert_member_row(member_id, None, &signed, remote.status.as_str(), None)?;
        self.process_pending_rotations(client, keystore).await?;
        for s in &new_spaces {
            if !old_spaces.contains(s) || !self.is_space_shared(*s) {
                self.publish_space_keys(client, keystore, *s, !self.is_space_shared(*s)).await?;
                self.seed_space_events(*s)?;
            } else if !downgrade {
                self.publish_space_keys(client, keystore, *s, false).await?;
                // Newly granted nodes inside a space the member already had:
                // send their existing records (seeds are insert-only).
                self.seed_space_events(*s)?;
            }
        }
        Ok(())
    }

    /// Removes a member: revokes all their devices (optionally asking them to
    /// wipe) and rotates the branch keys of every space they could read. The
    /// rotations are recorded first and finished on a later sync if needed.
    pub async fn remove_member(
        &mut self,
        client: &RelayClient,
        keystore: &dyn KeyStore,
        member_id: Uuid,
        wipe: bool,
    ) -> Result<()> {
        self.ensure_writable()?;
        let members = client.list_members(self.secwet_id, &self.device_sign_key).await?;
        let remote = members.members.iter().find(|m| m.member_id == member_id);
        let grants = match self.member_grants_local(member_id)?.filter(|g| self.verify_grant_set(g, member_id)) {
            Some(g) => g.set.grants,
            None => remote.map(|m| m.grants.set.grants.clone()).ok_or(Error::NotFound)?,
        };
        let spaces = self.spaces_touched(&grants)?;
        for s in &spaces {
            if !self.can_admin_space(*s) {
                return Err(Error::Forbidden);
            }
            self.queue_pending("branch_rotate", *s)?;
        }
        if let Some(m) = remote.filter(|m| m.status != secwet_proto::MemberStatus::Removed) {
            let mut revocations = Vec::new();
            for d in m.devices.iter().filter(|d| d.revoked_at.is_none()) {
                revocations.push(self.sign_revocation(&d.id, wipe)?);
            }
            match client
                .remove_member(self.secwet_id, member_id, &RemoveMemberRequest { revocations }, &self.device_sign_key)
                .await
            {
                Ok(_) => {}
                Err(Error::Relay { code }) if code == "not_found" || code == "already_revoked" => {}
                Err(e) => return Err(e),
            }
            let now = now_ms();
            for d in &m.devices {
                self.record_local_revocation(&d.id, now)?;
            }
        }
        self.db
            .execute(
                "UPDATE collab_members SET status = 'removed', updated_at = ?2 WHERE member_id = ?1",
                params![member_id.as_bytes().as_slice(), now_ms()],
            )
            .map_err(|_| Error::Storage)?;
        self.process_pending_rotations(client, keystore).await?;
        Ok(())
    }

    /// Members of the workspace with locally known emails merged in.
    pub async fn members_list(&mut self, client: &RelayClient) -> Result<Vec<MemberInfo>> {
        let resp = client.list_members(self.secwet_id, &self.device_sign_key).await?;
        let mut out = Vec::new();
        for m in &resp.members {
            let email = self.member_email(m.member_id);
            let inv = resp.invitations.iter().filter(|i| i.member_id == m.member_id).max_by_key(|i| i.created_at);
            let status = match (m.status, inv.map(|i| i.status)) {
                (secwet_proto::MemberStatus::Removed, _) => "removed",
                (_, Some(InvitationStatus::Pending)) if inv.map(|i| i.expires_at < now_ms()).unwrap_or(false) => "expired",
                (_, Some(InvitationStatus::Expired)) => "expired",
                (_, Some(InvitationStatus::Pending)) => "invited",
                (_, Some(InvitationStatus::Accepted)) => "accepted",
                (_, Some(InvitationStatus::Revoked)) => "removed",
                (secwet_proto::MemberStatus::Active, _) => "active",
                (secwet_proto::MemberStatus::Invited, _) => "invited",
            };
            out.push(MemberInfo {
                member_id: m.member_id,
                email,
                status: status.to_string(),
                grants: m.grants.set.grants.clone(),
                devices: m
                    .devices
                    .iter()
                    .map(|d| MemberDeviceInfo {
                        id: d.id.clone(),
                        fingerprint: crypto::compute_fingerprint(&d.sign_pub, &d.enc_pub),
                        revoked: d.revoked_at.is_some(),
                    })
                    .collect(),
                invited_at: m.created_at,
                invitation_id: inv.map(|i| i.invitation_id),
            });
        }
        Ok(out)
    }

    fn member_email(&self, member_id: Uuid) -> Option<String> {
        let blob: Option<Vec<u8>> = self
            .db
            .query_row(
                "SELECT email_blob FROM collab_members WHERE member_id = ?1",
                params![member_id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .optional()
            .ok()
            .flatten()
            .flatten();
        let blob = blob?;
        let pt = self.open_raw_any(&self.member_email_aad(member_id).ok()?, &blob).ok()?;
        String::from_utf8(pt).ok()
    }

    // ========================================================================
    // M8: invitee side
    // ========================================================================

    /// Accepts an invite link on a device with no store yet: creates the member
    /// store first (so a failure afterwards can be cleaned up and retried),
    /// trusts the inviting device named in the link, registers this device
    /// with the relay and starts the sync cursor at the relay's head. The
    /// branch keys arrive once the inviter's device verifies the acceptance.
    pub async fn accept_invitation(
        data_dir: &Path,
        link: &str,
        email: &str,
        device_name: &str,
        keystore: &dyn KeyStore,
    ) -> Result<Secwet> {
        if crate::secwet::find_secwet_db_pub(data_dir).is_some() {
            return Err(Error::AlreadyInitialized);
        }
        let link = parse_invite_link(link)?;
        let email = validate_email(email)?;

        let signing_key = SigningKey::generate(&mut OsRng);
        let sign_pub = signing_key.verifying_key().to_bytes();
        let enc_secret = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
        let enc_pub = x25519_dalek::PublicKey::from(&enc_secret).to_bytes();
        let device_id = crypto::compute_device_id(&sign_pub);

        let auth = invite_auth(&link.token, &link.invitation_id);
        let binding = invite_binding(&link.token, &link.invitation_id, &sign_pub, &enc_pub);
        let proof_bytes = AcceptInvitationRequest::signing_bytes(&link.invitation_id, &link.secwet_id, &sign_pub, &enc_pub, &binding)
            .map_err(|_| Error::Crypto)?;
        let proof = crypto::sign_payload(&signing_key, &proof_bytes).to_bytes();
        let req = AcceptInvitationRequest {
            secwet_id: link.secwet_id,
            email_hash: email_hash(&link.token, &link.invitation_id, &email),
            auth: *auth,
            sign_pub,
            enc_pub,
            binding: *binding,
            proof,
        };

        let local_key = random_key();
        let mut secwet = Secwet::create_with_identity(
            data_dir,
            device_name,
            link.secwet_id,
            &local_key,
            signing_key,
            enc_secret,
            "pro",
            None,
            keystore,
        )?;
        let result = async {
            secwet.set_relay_url(&link.relay_url)?;
            let client = RelayClient::new(&link.relay_url, &device_id);
            let resp = client.accept_invitation(link.invitation_id, &req).await?;
            if resp.secwet_id != link.secwet_id || resp.device_id != device_id {
                return Err(Error::Crypto);
            }
            Ok(resp)
        }
        .await;
        match result {
            Ok(resp) => {
                secwet.member_id = Some(resp.member_id);
                set_meta(&secwet.db, "member_id", &resp.member_id.to_string())?;
                secwet
                    .db
                    .execute(
                        "UPDATE devices SET member_id = ?1 WHERE device_id = ?2",
                        params![resp.member_id.as_bytes().as_slice(), device_id],
                    )
                    .map_err(|_| Error::Storage)?;
                secwet.certify_device(&link.inviter.device_id, &link.inviter.sign_pub, &link.inviter.enc_pub, link.inviter_member)?;
                set_meta(&secwet.db, "invite_anchor", &link.inviter.device_id)?;
                sync::set_sync_cursor(&secwet.db, resp.head_seq)?;
                secwet.ensure_default_personal_space()?;
                Ok(secwet)
            }
            Err(e) => {
                let _ = secwet.crypto_shred(keystore);
                Err(e)
            }
        }
    }

    /// Authorization of an incoming event (F19).
    ///
    /// Workspace-private events are sealed with the workspace event key, so
    /// decrypting them already proves an owner device wrote them; they are
    /// refused only from devices this store knows to be a member's. Scoped
    /// events are attributed through this store's own trust records: the
    /// owner's certified devices may write anything; a member's device must
    /// be certified and its verified grants must permit the change, the body
    /// must stay inside the scope, and an existing record may not change
    /// type or move between branches. Unknown authors are deferred.
    pub(crate) fn authorize_event(&self, envelope: &EventEnvelope, body: &EventBody, _server_seq: u64) -> sync::Authorization {
        use sync::Authorization::{Allow, Defer, Deny};
        let sender = self.device_trust(&envelope.device_id);
        let sender_member = sender.as_ref().and_then(|(_, m)| *m);

        if let EventBody::DeviceCertified { .. } = body {
            // Only the owner's devices hold the workspace event key; a revoked
            // one would only hold an older epoch.
            return if envelope.scope.is_none() && envelope.key_epoch == self.key_epoch && sender_member.is_none() {
                Allow
            } else {
                Deny
            };
        }
        let Some(scope) = &envelope.scope else {
            return if sender_member.is_some() { Deny } else { Allow };
        };
        if envelope.device_id == self.device_id {
            return Allow;
        }
        let Some((trust, member)) = sender else { return Defer };

        let grants: Vec<MemberGrant> = match member {
            None if trust == "certified" => return self.check_body_in_scope(scope, body, None),
            None => return Defer,
            Some(m) if Some(m) == self.member_id => self.my_grants(),
            Some(m) => {
                if !self.is_owner() {
                    // Member stores do not hold other members' grants; the
                    // relay enforced them on push.
                    return self.check_body_in_scope(scope, body, None);
                }
                if trust != "certified" {
                    return Defer;
                }
                match self.member_grants_local(m) {
                    Ok(Some(g)) if self.verify_grant_set(&g, m) => g.set.grants,
                    _ => return Defer,
                }
            }
        };
        if !scope.permits(&grants) {
            return Deny;
        }
        self.check_body_in_scope(scope, body, Some(&grants))
    }

    /// The op matches the body, the body stays inside the scope, existing
    /// records keep their type and branch, and lamports stay sane.
    fn check_body_in_scope(&self, scope: &EventScope, body: &EventBody, member_grants: Option<&[MemberGrant]>) -> sync::Authorization {
        use sync::Authorization::{Allow, Deny};
        let (record_id, rtype, payload, lamport) = match body {
            EventBody::Upsert { record_id, record_type, body, lamport }
            | EventBody::Seed { record_id, record_type, body, lamport, .. } => {
                let Ok(rt) = RecordType::try_from(*record_type) else { return Deny };
                let Ok(p) = RecordPayload::from_bytes(rt, body) else { return Deny };
                (*record_id, rt, Some(p), *lamport)
            }
            EventBody::Delete { record_id, record_type, lamport } => {
                let Ok(rt) = RecordType::try_from(*record_type) else { return Deny };
                (*record_id, rt, None, *lamport)
            }
            EventBody::DeviceRenamed { .. } | EventBody::DeviceCertified { .. } => return Deny,
        };
        let is_content = matches!(rtype, RecordType::Secret | RecordType::Asset | RecordType::Note);
        let op_ok = matches!(
            (is_content, payload.is_some(), scope.op),
            (true, true, ScopeOp::Write) | (true, false, ScopeOp::Delete) | (false, _, ScopeOp::Container)
        );
        if !op_ok {
            return Deny;
        }
        // An existing record keeps its type.
        if let Ok(Some(existing)) = records::get_record(&self.db, record_id) {
            if existing.record_type != rtype {
                return Deny;
            }
        }
        if member_grants.is_some() {
            // Lamports from members may not jump arbitrarily far ahead.
            let highest = records::get_highest_lamport(&self.db).unwrap_or(0);
            if lamport > highest.saturating_add(1_000_000_000) {
                return Deny;
            }
        }
        // Where the body says the record lives must equal the scope.
        let claimed = match &payload {
            Some(p) => self.location_of(record_id, rtype, Some(p)),
            None => self.location_of(record_id, rtype, None),
        };
        match claimed {
            Ok(Some(c)) if c.space_id == scope.space_id && c.path == scope.path && c.target == scope.target => {}
            // Parents not received yet: the scope alone was authorized.
            Ok(None) if payload.is_some() && records::get_record(&self.db, record_id).ok().flatten().is_none() => {}
            _ => return Deny,
        }
        // An existing record cannot be moved out of another branch.
        if payload.is_some() {
            if let Ok(Some(_)) = records::get_record(&self.db, record_id) {
                match self.location_of(record_id, rtype, None) {
                    Ok(Some(e)) if e.space_id == scope.space_id && e.path == scope.path && e.target == scope.target => {}
                    _ => return Deny,
                }
            }
        }
        Allow
    }

    /// Retries deferred events (keys, certificates or grants may have arrived).
    pub fn replay_deferred(&mut self) -> Result<usize> {
        // Events still unreadable after 30 days will not become readable.
        self.db
            .execute(
                "DELETE FROM collab_deferred WHERE deferred_at < ?1",
                params![now_ms() - 30 * 24 * 60 * 60 * 1000],
            )
            .map_err(|_| Error::Storage)?;
        let rows: Vec<(i64, Vec<u8>)> = {
            let mut stmt = self
                .db
                .prepare("SELECT server_seq, envelope FROM collab_deferred ORDER BY server_seq")
                .map_err(|_| Error::Storage)?;
            let it = stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?))).map_err(|_| Error::Storage)?;
            it.flatten().collect()
        };
        let mut applied = 0;
        for (seq, bytes) in rows {
            let Ok(ev) = secwet_proto::SignedEvent::from_postcard_compat(&bytes) else {
                self.db.execute("DELETE FROM collab_deferred WHERE server_seq = ?1", params![seq]).map_err(|_| Error::Storage)?;
                continue;
            };
            let res = {
                let mut resolver = SecwetResolver { s: &*self };
                sync::apply_signed_event_with(&self.db, self.secwet_id, seq as u64, &ev, self.key_epoch, self.k_rec.expose_secret(), &mut resolver)
            };
            match res {
                Ok(sync::ApplyOutcome::Deferred) => {}
                Ok(o) => {
                    if o == sync::ApplyOutcome::Applied {
                        applied += 1;
                    }
                    self.db.execute("DELETE FROM collab_deferred WHERE server_seq = ?1", params![seq]).map_err(|_| Error::Storage)?;
                }
                Err(Error::Storage) => return Err(Error::Storage),
                Err(_) => {
                    let _ = sync::record_event_applied(&self.db, &ev.envelope.event_id, seq as u64);
                    self.db.execute("DELETE FROM collab_deferred WHERE server_seq = ?1", params![seq]).map_err(|_| Error::Storage)?;
                }
            }
        }
        Ok(applied)
    }

    /// Number of events waiting for a key, certificate or grant.
    pub fn deferred_count(&self) -> Result<usize> {
        let n: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM collab_deferred", [], |r| r.get(0))
            .map_err(|_| Error::Storage)?;
        Ok(n as usize)
    }

    /// Republishes bundles for shared spaces whose tree changed.
    pub async fn publish_dirty_spaces(&mut self, client: &RelayClient, keystore: &dyn KeyStore) -> Result<usize> {
        let dirty: Vec<Uuid> = {
            let mut stmt = self.db.prepare("SELECT space_id FROM collab_dirty_spaces").map_err(|_| Error::Storage)?;
            let it = stmt.query_map([], |r| r.get::<_, Vec<u8>>(0)).map_err(|_| Error::Storage)?;
            it.flatten().filter_map(|b| Uuid::from_slice(&b).ok()).collect()
        };
        let mut n = 0;
        for s in dirty {
            if self.can_admin_space(s) {
                self.publish_space_keys(client, keystore, s, false).await?;
                n += 1;
            }
        }
        Ok(n)
    }

    /// Uploads a fresh snapshot once a day or after 200 synced changes.
    async fn maybe_upload_snapshot(&mut self, client: &RelayClient, changes: usize) -> Result<()> {
        if !self.is_owner() {
            return Ok(());
        }
        let count: usize = get_meta(&self.db, "changes_since_snapshot")?.and_then(|v| v.parse().ok()).unwrap_or(0) + changes;
        let last: i64 = get_meta(&self.db, "last_snapshot_at")?.and_then(|v| v.parse().ok()).unwrap_or(0);
        let due = count >= 200 || (count > 0 && now_ms() - last > 24 * 60 * 60 * 1000);
        if due && self.create_and_upload_snapshot(client).await.is_ok() {
            set_meta(&self.db, "changes_since_snapshot", "0")?;
            set_meta(&self.db, "last_snapshot_at", &now_ms().to_string())?;
        } else {
            set_meta(&self.db, "changes_since_snapshot", &count.to_string())?;
        }
        Ok(())
    }

    /// Full collaboration-aware sync round.
    ///
    /// Order: devices and keys, deferred replay, pull (certificates arrive
    /// here), keys again, deferred replay, admin duties (invitations, dirty
    /// spaces, queued rotations, owner coverage), then push with the outbox
    /// re-encrypted for current epochs. Returns `(pushed, applied)`. A
    /// `403 revoked` carrying a verified directive is executed and surfaced
    /// as `Error::RevocationNotice`.
    pub async fn sync_round(&mut self, client: &RelayClient, keystore: &dyn KeyStore) -> Result<(usize, usize)> {
        if self.is_wiped() {
            return Err(Error::NotInitialized);
        }
        if self.unlinked_at()?.is_some() {
            return Err(Error::Revoked);
        }
        // F13: Free never contacts the relay; a paused store only checks
        // whether Pro was renewed.
        self.ensure_relay_allowed(crate::plan::RelayOp::Entitlement)?;
        let result = async {
            if self.refresh_plan(client).await?.state != crate::plan::PlanState::Pro {
                return Err(Error::SyncPaused);
            }
            if self.is_owner() && get_meta(&self.db, "self_certified")?.as_deref() != Some("1") {
                let (id, sp, ep) = (self.device_id.clone(), self.device_sign_pub, self.device_enc_pub);
                self.emit_device_certificate(&id, &sp, &ep, None)?;
                set_meta(&self.db, "self_certified", "1")?;
            }
            self.refresh_devices_from_relay(client).await?;
            self.upload_certificates(client).await?;
            self.import_certificates(client).await?;
            if self.is_owner() {
                self.refresh_master_keys(client, keystore).await?;
            }
            self.refresh_access(client).await.or_else(|e| match e {
                Error::Relay { ref code } if code == "forbidden" => Ok(()),
                e => Err(e),
            })?;
            self.refresh_branch_keys(client, keystore).await?;
            let mut applied = self.replay_deferred()?;
            applied += self.pull_and_apply_events(client).await?;
            if self.is_owner() {
                self.refresh_master_keys(client, keystore).await?;
                self.refresh_access(client).await.ok();
            }
            self.refresh_branch_keys(client, keystore).await?;
            applied += self.replay_deferred()?;
            if self.is_owner() || self.my_grants().iter().any(|g| g.role.can_manage()) {
                match self.process_invitations(client, keystore).await {
                    Err(Error::Relay { ref code }) if code == "forbidden" => {}
                    other => {
                        other?;
                    }
                }
                self.publish_dirty_spaces(client, keystore).await?;
                self.process_pending_rotations(client, keystore).await?;
                self.ensure_owner_coverage(client, keystore).await?;
            }
            self.reencrypt_outbox()?;
            let pushed = match self.push_outbox(client).await {
                Err(Error::Relay { code }) if code == "epoch_conflict" => {
                    self.refresh_master_keys(client, keystore).await?;
                    self.refresh_branch_keys(client, keystore).await?;
                    self.reencrypt_outbox()?;
                    self.push_outbox(client).await?
                }
                other => other?,
            };
            self.maybe_upload_snapshot(client, pushed + applied).await?;
            Ok((pushed, applied))
        }
        .await;
        match result {
            Err(Error::RevocationNotice(notice)) => {
                self.handle_revocation_notice(&notice, keystore)?;
                Err(Error::RevocationNotice(notice))
            }
            other => other,
        }
    }
}

// ============================================================================
// Test hooks (feature `test-util` only): drive the real key paths without a relay.
// ============================================================================

#[cfg(any(test, feature = "test-util"))]
impl Secwet {
    /// Shares a space locally with a fresh root at `epoch` (owner side of a publish).
    pub fn test_install_space_root(&mut self, keystore: &dyn KeyStore, space_id: Uuid, epoch: u32) -> Result<()> {
        let root = random_key();
        let bundle = BranchKeyBundle {
            secwet_id: self.secwet_id,
            space_id,
            epoch,
            entries: vec![BranchKeyEntry { path: vec![space_id], kind: BranchKeyKind::Subtree, key: *root }],
            admins: Vec::new(),
        };
        self.store_bundle(keystore, bundle, true).map(|_| ())
    }

    /// Bundle a member with `grants` would receive, HPKE-wrapped for a device.
    pub fn test_wrap_member_bundle(
        &self,
        space_id: Uuid,
        grants: &[MemberGrant],
        device_id: &str,
        enc_pub: &[u8; 32],
    ) -> Result<ScopedBranchKey> {
        let epoch = self.keyring.branch_epoch(space_id).ok_or(Error::Forbidden)?;
        let root = self.space_root(space_id, epoch).ok_or(Error::Forbidden)?;
        let entries = self.compute_bundle_entries(space_id, &root, grants)?;
        let bundle = BranchKeyBundle { secwet_id: self.secwet_id, space_id, epoch, entries, admins: self.certified_owner_devices()? };
        self.wrap_bundle(device_id, enc_pub, &bundle)
    }

    /// Unwraps and stores a bundle addressed to this device.
    pub fn test_accept_bundle(&mut self, keystore: &dyn KeyStore, sbk: &ScopedBranchKey) -> Result<()> {
        let b = self.unwrap_bundle(sbk)?;
        self.store_bundle(keystore, b, true).map(|_| ())
    }

    /// Creates a member store for `secwet_id` with a member-local key.
    pub fn test_create_member(data_dir: &Path, secwet_id: Uuid, member_id: Uuid, keystore: &dyn KeyStore) -> Result<Secwet> {
        let local = random_key();
        Secwet::create_with_identity(
            data_dir,
            "Member laptop",
            secwet_id,
            &local,
            SigningKey::generate(&mut OsRng),
            x25519_dalek::StaticSecret::random_from_rng(&mut OsRng),
            "pro",
            Some(member_id),
            keystore,
        )
    }

    /// Registers another device (owner's or a member's) in the local devices table.
    pub fn test_register_device(&mut self, device_id: &str, sign_pub: &[u8; 32], enc_pub: &[u8; 32], member_id: Option<Uuid>) -> Result<()> {
        let name_blob = crate::secwet::seal_device_name(self.k_rec.expose_secret(), device_id, "Device")?;
        self.db
            .execute(
                "INSERT OR REPLACE INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, member_id, trust)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5, ?6, 'certified')",
                params![device_id, name_blob, sign_pub.as_slice(), enc_pub.as_slice(), now_ms(), member_id.map(|m| m.as_bytes().to_vec())],
            )
            .map_err(|_| Error::Storage)?;
        Ok(())
    }

    /// Signs a grant set as this (admin) device.
    pub fn test_sign_grants(&self, member_id: Uuid, version: u64, grants: Vec<MemberGrant>) -> Result<SignedGrantSet> {
        self.sign_grant_set(member_id, version, grants)
    }

    /// Records a member's signed grants locally (owner side).
    pub fn test_set_member_grants(&mut self, grants: &SignedGrantSet) -> Result<()> {
        self.upsert_member_row(grants.set.member_id, None, grants, "active", None)
    }

    /// Sets this member store's own grants.
    pub fn test_set_my_grants(&mut self, grants: &SignedGrantSet) -> Result<()> {
        let bytes = postcard::to_stdvec(grants).map_err(|_| Error::Storage)?;
        set_meta(&self.db, "my_grants", &data_encoding::HEXLOWER.encode(&bytes))
    }

    /// Signs a revocation directive as this device.
    pub fn test_sign_revocation(&self, target: &str, wipe: bool) -> Result<SignedRevocation> {
        self.sign_revocation(target, wipe)
    }

    /// Whether this device can derive the event key for a scope at its newest epoch.
    pub fn test_can_derive(&self, scope: &EventScope) -> bool {
        self.scoped_event_key(scope).is_ok()
    }

    /// Re-encrypts and re-signs one of this device's own scoped events with a
    /// different body, as a modified client could.
    pub fn test_forge_scoped(&self, ev: &secwet_proto::SignedEvent, body: &EventBody) -> Result<secwet_proto::SignedEvent> {
        let scope = ev.envelope.scope.clone().ok_or(Error::Crypto)?;
        let key = self
            .keyring
            .branch_target_key(&self.secwet_id, &scope, ev.envelope.key_epoch)
            .ok_or(Error::Crypto)?;
        sync::reseal_signed_event(ev, ev.envelope.key_epoch, &key, &self.device_sign_key, body)
    }

    pub fn test_enc_pub(&self) -> [u8; 32] {
        self.device_enc_pub
    }
}

/// Key and role lookups for applying events pulled from the relay.
pub(crate) struct SecwetResolver<'a> {
    pub s: &'a Secwet,
}

impl sync::EventKeyResolver for SecwetResolver<'_> {
    fn event_key(&mut self, envelope: &EventEnvelope) -> Result<sync::KeyLookup> {
        let s = self.s;
        match &envelope.scope {
            None => {
                if !s.is_owner() {
                    return Ok(sync::KeyLookup::Skip);
                }
                if let Some(k) = s.keyring.evt(envelope.key_epoch) {
                    return Ok(sync::KeyLookup::Key(Zeroizing::new(*k)));
                }
                Ok(if envelope.key_epoch > s.key_epoch { sync::KeyLookup::Defer } else { sync::KeyLookup::Skip })
            }
            Some(scope) => {
                if let Some(k) = s.keyring.branch_target_key(&s.secwet_id, scope, envelope.key_epoch) {
                    return Ok(sync::KeyLookup::Key(k));
                }
                let held_this_epoch = s
                    .keyring
                    .branches
                    .get(&scope.space_id)
                    .map(|m| m.contains_key(&envelope.key_epoch))
                    .unwrap_or(false);
                // Holding this epoch's bundle without the key means no access.
                Ok(if held_this_epoch { sync::KeyLookup::Skip } else { sync::KeyLookup::Defer })
            }
        }
    }

    fn authorize(&mut self, envelope: &EventEnvelope, body: &EventBody, server_seq: u64) -> sync::Authorization {
        self.s.authorize_event(envelope, body, server_seq)
    }
}

/// Best-effort overwrite before unlinking, so freed blocks do not keep the
/// ciphertext on file systems without copy-on-write. Keys are already gone.
fn pending_wipe_marker(data_dir: &Path, id: Uuid) -> PathBuf {
    data_dir.join(format!(".secwet-pending-wipe-{id}"))
}

/// Writes a small file and syncs it and its directory, so it survives a
/// process kill or power loss right after.
fn write_durably(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::File::create(path) {
        let _ = f.write_all(bytes).and_then(|_| f.sync_all());
    }
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        if let Ok(d) = std::fs::File::open(dir) {
            let _ = d.sync_all();
        }
    }
}

fn overwrite_and_remove(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open(path) {
            use std::io::Write;
            let zeros = vec![0u8; 64 * 1024];
            let mut left = meta.len();
            while left > 0 {
                let n = left.min(zeros.len() as u64) as usize;
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                left -= n as u64;
            }
            let _ = f.sync_all();
        }
    }
    let _ = std::fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_killed_after_key_deletion_finishes_on_next_start() {
        let dir = tempfile::tempdir().unwrap();
        let ks = crate::MemoryStore::new();
        let s = Secwet::create(dir.path(), "Phone", &ks).unwrap();
        let id = s.secwet_id();
        s.lock();
        // The state crypto_shred leaves when the process dies right after its
        // delete loop: marker written first, keys gone, database still there.
        let entries = vec![format!("secwet/{id}/device-sign"), format!("secwet/{id}/device-enc")];
        write_durably(&pending_wipe_marker(dir.path(), id), &serde_json::to_vec(&entries).unwrap());
        for e in &entries {
            ks.delete(e).unwrap();
        }
        assert!(matches!(Secwet::status(dir.path()).unwrap(), secwet_proto::SecwetStatus::Locked { .. }));

        assert_eq!(Secwet::finish_pending_wipes(dir.path(), &ks).unwrap(), 1);
        assert!(!pending_wipe_marker(dir.path(), id).exists());
        assert!(!dir.path().join("secwet").join(id.to_string()).exists());
        assert_eq!(Secwet::status(dir.path()).unwrap(), secwet_proto::SecwetStatus::Uninitialized);
        Secwet::create(dir.path(), "Phone", &ks).expect("onboarding works again");
    }

    #[test]
    fn invite_link_roundtrip() {
        let w = Uuid::new_v4();
        let i = Uuid::new_v4();
        let t = [7u8; 32];
        let sk = SigningKey::generate(&mut OsRng);
        let sign_pub = sk.verifying_key().to_bytes();
        let inviter = secwet_proto::TrustedDevice {
            device_id: crypto::compute_device_id(&sign_pub),
            sign_pub,
            enc_pub: [5u8; 32],
        };
        let link = format_invite_link(&w, &i, &t, "https://relay.example.com:8443/base", &inviter, None);
        let parsed = parse_invite_link(&link).unwrap();
        assert_eq!(parsed.secwet_id, w);
        assert_eq!(parsed.invitation_id, i);
        assert_eq!(*parsed.token, t);
        assert_eq!(parsed.relay_url, "https://relay.example.com:8443/base");
        assert_eq!(parsed.inviter, inviter);
        assert!(parse_invite_link("secwet://invite?v=2&w=x").is_err());
        assert!(parse_invite_link("https://evil").is_err());
    }

    #[test]
    fn email_hash_normalizes_and_is_keyed() {
        let i = Uuid::new_v4();
        assert_eq!(email_hash(&[1; 32], &i, " A@B.com "), email_hash(&[1; 32], &i, "a@b.com"));
        assert_ne!(email_hash(&[1; 32], &i, "a@b.com"), email_hash(&[2; 32], &i, "a@b.com"));
    }

    #[test]
    fn binding_depends_on_keys() {
        let i = Uuid::new_v4();
        let t = [1u8; 32];
        let a = invite_binding(&t, &i, &[2u8; 32], &[3u8; 32]);
        let b = invite_binding(&t, &i, &[2u8; 32], &[4u8; 32]);
        assert_ne!(*a, *b);
        assert_ne!(*invite_auth(&t, &i), *a);
    }
}
