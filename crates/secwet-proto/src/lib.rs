//! Shared wire, envelope, and model types for Secwet.
//!
//! Architectural Invariant: This crate contains zero I/O and zero cryptographic primitives.
//! It defines pure serializable data structures, wire envelopes, and validation logic.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub mod collab;
pub use collab::*;

// ============================================================================
// 1. Discriminators & Taxonomy Enums
// ============================================================================

/// Record type discriminator stored in records.record_type and bound in RecordAad.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum RecordType {
    Label = 1,
    Item = 2,
    Environment = 3,
    Secret = 4,
    Asset = 5,
    Note = 6,
    /// Space record in sync events. Local storage keeps sealing spaces with the
    /// `Label` discriminator for backwards compatibility.
    Space = 7,
}

impl RecordType {
    /// Backwards compatibility alias for code migrating from legacy projects.
    #[allow(non_upper_case_globals)]
    pub const Project: RecordType = RecordType::Item;

    /// Backwards compatibility alias for code migrating from legacy files.
    #[allow(non_upper_case_globals)]
    pub const File: RecordType = RecordType::Asset;

    pub const fn as_str(&self) -> &'static str {
        match self {
            RecordType::Label => "label",
            RecordType::Item => "item",
            RecordType::Environment => "environment",
            RecordType::Secret => "secret",
            RecordType::Asset => "asset",
            RecordType::Note => "note",
            RecordType::Space => "space",
        }
    }
}

impl TryFrom<u8> for RecordType {
    type Error = u8;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(RecordType::Label),
            2 => Ok(RecordType::Item),
            3 => Ok(RecordType::Environment),
            4 => Ok(RecordType::Secret),
            5 => Ok(RecordType::Asset),
            6 => Ok(RecordType::Note),
            7 => Ok(RecordType::Space),
            other => Err(other),
        }
    }
}

impl From<RecordType> for u8 {
    #[inline]
    fn from(t: RecordType) -> Self {
        t as u8
    }
}

impl std::fmt::Display for RecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Secret taxonomy as visible in UI and serialized in payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    Password,
    ApiKey,
    AccessToken,
    EnvVar,
    SshKey,
    Certificate,
    Codes,
}

impl SecretKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            SecretKind::Password => "password",
            SecretKind::ApiKey => "api_key",
            SecretKind::AccessToken => "access_token",
            SecretKind::EnvVar => "env_var",
            SecretKind::SshKey => "ssh_key",
            SecretKind::Certificate => "certificate",
            SecretKind::Codes => "codes",
        }
    }
}

impl std::fmt::Display for SecretKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl std::str::FromStr for SecretKind {
    type Err = ParseKindError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "password" => Ok(SecretKind::Password),
            "api_key" => Ok(SecretKind::ApiKey),
            "access_token" => Ok(SecretKind::AccessToken),
            "env_var" => Ok(SecretKind::EnvVar),
            "ssh_key" => Ok(SecretKind::SshKey),
            "certificate" => Ok(SecretKind::Certificate),
            "codes" => Ok(SecretKind::Codes),
            _ => Err(ParseKindError(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseKindError(pub String);

impl std::fmt::Display for ParseKindError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unknown secret kind: {}", self.0)
    }
}

impl std::error::Error for ParseKindError {}

// Transparent compatibility wrappers to allow `.project_id` or `.item_id` field access.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProjectIdCompat {
    pub project_id: Uuid,
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ItemIdCompat {
    pub item_id: Uuid,
}

// ============================================================================
// 2. Record Payloads (Decrypted Bodies Sealed inside Blobs)
// ============================================================================

/// Body of a Space record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceBody {
    pub name: String,
    pub position: u32,
    pub icon: Option<String>,
    #[serde(default)]
    pub is_default: bool,
}

impl SpaceBody {
    pub fn new(name: impl Into<String>, position: u32, icon: Option<String>, is_default: bool) -> Self {
        Self {
            name: name.into(),
            position,
            icon,
            is_default,
        }
    }
}

/// Body of a Label record (type 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelBody {
    pub name: String,
    pub position: u32,
    pub icon: Option<String>,
    #[serde(default)]
    pub space_id: Option<Uuid>,
}

impl LabelBody {
    pub fn new(name: impl Into<String>, position: u32, icon: Option<String>) -> Self {
        Self {
            name: name.into(),
            position,
            icon,
            space_id: None,
        }
    }

    pub fn with_space(name: impl Into<String>, position: u32, icon: Option<String>, space_id: Option<Uuid>) -> Self {
        Self {
            name: name.into(),
            position,
            icon,
            space_id,
        }
    }
}

/// Body of an Item record (type 2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemBody {
    pub label_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub position: u32,
}

impl ItemBody {
    pub fn new(
        label_id: Uuid,
        name: impl Into<String>,
        description: Option<String>,
        position: u32,
    ) -> Self {
        Self {
            label_id,
            name: name.into(),
            description,
            position,
        }
    }
}

/// Body of an Environment record (type 3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentBody {
    #[serde(alias = "project_id")]
    pub item_id: Uuid,
    pub name: String,
    pub position: u32,
}

impl EnvironmentBody {
    pub fn new(item_id: Uuid, name: impl Into<String>, position: u32) -> Self {
        Self {
            item_id,
            name: name.into(),
            position,
        }
    }

    /// Backwards compatibility alias for code migrating from projects.
    #[inline]
    pub fn project_id(&self) -> Uuid {
        self.item_id
    }
}

impl std::ops::Deref for EnvironmentBody {
    type Target = ProjectIdCompat;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // Safety: ProjectIdCompat is repr(transparent) around Uuid, with identical layout to item_id.
        unsafe { &*(&self.item_id as *const Uuid as *const ProjectIdCompat) }
    }
}

/// Body of a Secret record (type 4).
///
/// Custom Debug implementation ensures secret value is never printed to logs or stdout.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretBody {
    #[serde(alias = "project_id")]
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub kind: SecretKind,
    pub value: String,
    pub note: Option<String>,
}

impl SecretBody {
    pub fn new(
        item_id: Uuid,
        environment_id: impl Into<Option<Uuid>>,
        name: impl Into<String>,
        kind: SecretKind,
        value: impl Into<String>,
        note: Option<String>,
    ) -> Self {
        Self {
            item_id,
            environment_id: environment_id.into(),
            name: name.into(),
            kind,
            value: value.into(),
            note,
        }
    }

    #[inline]
    pub fn project_id(&self) -> Uuid {
        self.item_id
    }
}

impl std::ops::Deref for SecretBody {
    type Target = ProjectIdCompat;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // Safety: ProjectIdCompat is repr(transparent) around Uuid, with identical layout to item_id.
        unsafe { &*(&self.item_id as *const Uuid as *const ProjectIdCompat) }
    }
}

impl std::fmt::Debug for SecretBody {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretBody")
            .field("item_id", &self.item_id)
            .field("environment_id", &self.environment_id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"[redacted]")
            .field("note", &self.note)
            .finish()
    }
}

/// Body of an Asset metadata record (type 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetMetaBody {
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub size_bytes: u64,
    pub mime_type: String,
    pub sha256: [u8; 32],
}

impl AssetMetaBody {
    pub fn new(
        item_id: Uuid,
        environment_id: Option<Uuid>,
        name: impl Into<String>,
        size_bytes: u64,
        mime_type: impl Into<String>,
        sha256: [u8; 32],
    ) -> Self {
        Self {
            item_id,
            environment_id,
            name: name.into(),
            size_bytes,
            mime_type: mime_type.into(),
            sha256,
        }
    }
}

pub type FileMetaBody = AssetMetaBody;

/// Sealed payload in records.blob containing both metadata and raw asset bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetPayload {
    pub meta: AssetMetaBody,
    pub data: Vec<u8>,
}

impl AssetPayload {
    pub fn new(meta: AssetMetaBody, data: Vec<u8>) -> Self {
        Self { meta, data }
    }
}

pub type FilePayload = AssetPayload;

/// Body of a Rich-Text Note record (type 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteBody {
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub title: String,
    pub content: String,
    pub position: u32,
}

impl NoteBody {
    pub fn new(
        item_id: Uuid,
        environment_id: Option<Uuid>,
        title: impl Into<String>,
        content: impl Into<String>,
        position: u32,
    ) -> Self {
        Self {
            item_id,
            environment_id,
            title: title.into(),
            content: content.into(),
            position,
        }
    }

    /// Validated constructor for `NoteBody`.
    ///
    /// Enforces `title` length (1..=128 trimmed characters) and `content`
    /// length (<= 1,000,000 characters). Stores the sanitized (trimmed) title.
    pub fn try_new(
        item_id: Uuid,
        environment_id: Option<Uuid>,
        title: impl Into<String>,
        content: impl Into<String>,
        position: u32,
    ) -> Result<Self, ValidationError> {
        let title_str = title.into();
        let content_str = content.into();
        let clean_title = validate_note_title(&title_str)?;
        validate_note_content(&content_str)?;
        Ok(Self {
            item_id,
            environment_id,
            title: clean_title,
            content: content_str,
            position,
        })
    }

    /// Validates the fields of this `NoteBody` against protocol invariants.
    pub fn validate(&self) -> Result<(), ValidationError> {
        validate_note_title(&self.title)?;
        validate_note_content(&self.content)?;
        Ok(())
    }
}

/// Body of a legacy Project record (retained for migration Phase 2 and tests).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectBody {
    pub name: String,
}

impl ProjectBody {
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

/// Union of decrypted record bodies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecordPayload {
    Label(LabelBody),
    Item(ItemBody),
    Environment(EnvironmentBody),
    Secret(SecretBody),
    File(FilePayload),
    Note(NoteBody),
    Project(ProjectBody), // Retained for backwards compatibility
    Space(SpaceBody),
}

impl RecordPayload {
    pub fn record_type(&self) -> RecordType {
        match self {
            RecordPayload::Label(_) => RecordType::Label,
            RecordPayload::Item(_) => RecordType::Item,
            RecordPayload::Environment(_) => RecordType::Environment,
            RecordPayload::Secret(_) => RecordType::Secret,
            RecordPayload::File(_) => RecordType::File,
            RecordPayload::Note(_) => RecordType::Note,
            RecordPayload::Project(_) => RecordType::Item,
            RecordPayload::Space(_) => RecordType::Space,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        match self {
            RecordPayload::Label(b) => postcard::to_stdvec(b),
            RecordPayload::Item(b) => postcard::to_stdvec(b),
            RecordPayload::Environment(b) => postcard::to_stdvec(b),
            RecordPayload::Secret(b) => postcard::to_stdvec(b),
            RecordPayload::File(b) => postcard::to_stdvec(b),
            RecordPayload::Note(b) => postcard::to_stdvec(b),
            RecordPayload::Project(b) => postcard::to_stdvec(b),
            RecordPayload::Space(b) => postcard::to_stdvec(b),
        }
    }

    pub fn from_bytes(record_type: RecordType, bytes: &[u8]) -> Result<Self, postcard::Error> {
        match record_type {
            RecordType::Label => postcard::from_bytes(bytes).map(RecordPayload::Label),
            RecordType::Item => postcard::from_bytes(bytes).map(RecordPayload::Item),
            RecordType::Environment => postcard::from_bytes(bytes).map(RecordPayload::Environment),
            RecordType::Secret => postcard::from_bytes(bytes).map(RecordPayload::Secret),
            RecordType::File => postcard::from_bytes(bytes).map(RecordPayload::File),
            RecordType::Note => postcard::from_bytes(bytes).map(RecordPayload::Note),
            RecordType::Space => postcard::from_bytes(bytes).map(RecordPayload::Space),
        }
    }
}

// ============================================================================
// 3. Associated Data (AAD) & Sealed Envelopes
// ============================================================================

/// Strict Authenticated Data bound to every sealed record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RecordAad<'a> {
    pub format: u8,
    pub secwet_id: &'a [u8; 16],
    pub record_id: &'a [u8; 16],
    pub record_type: u8,
    pub key_epoch: u32,
}

impl<'a> RecordAad<'a> {
    pub const FORMAT_V1: u8 = 1;

    #[inline]
    pub fn new(
        secwet_id: &'a [u8; 16],
        record_id: &'a [u8; 16],
        record_type: RecordType,
        key_epoch: u32,
    ) -> Self {
        Self {
            format: Self::FORMAT_V1,
            secwet_id,
            record_id,
            record_type: record_type as u8,
            key_epoch,
        }
    }

    /// Construct AAD with arbitrary raw discriminator byte (used in Phase 2 migration of legacy records).
    #[inline]
    pub fn from_raw_type(
        secwet_id: &'a [u8; 16],
        record_id: &'a [u8; 16],
        record_type: u8,
        key_epoch: u32,
    ) -> Self {
        Self {
            format: Self::FORMAT_V1,
            secwet_id,
            record_id,
            record_type,
            key_epoch,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }
}

/// Owned variant of RecordAad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordAadOwned {
    pub format: u8,
    pub secwet_id: [u8; 16],
    pub record_id: [u8; 16],
    pub record_type: u8,
    pub key_epoch: u32,
}

impl RecordAadOwned {
    pub const FORMAT_V1: u8 = 1;

    #[inline]
    pub fn new(
        secwet_id: [u8; 16],
        record_id: [u8; 16],
        record_type: RecordType,
        key_epoch: u32,
    ) -> Self {
        Self {
            format: Self::FORMAT_V1,
            secwet_id,
            record_id,
            record_type: record_type as u8,
            key_epoch,
        }
    }

    #[inline]
    pub fn from_raw_type(
        secwet_id: [u8; 16],
        record_id: [u8; 16],
        record_type: u8,
        key_epoch: u32,
    ) -> Self {
        Self {
            format: Self::FORMAT_V1,
            secwet_id,
            record_id,
            record_type,
            key_epoch,
        }
    }

    pub fn as_borrowed(&self) -> RecordAad<'_> {
        RecordAad {
            format: self.format,
            secwet_id: &self.secwet_id,
            record_id: &self.record_id,
            record_type: self.record_type,
            key_epoch: self.key_epoch,
        }
    }
}

/// Sealed record wire envelope (storage representation in SQLite records.blob).
/// Stored layout: version (1 byte = 0x01) || nonce (24 bytes) || ciphertext (includes 16-byte Poly1305 tag).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordEnvelope {
    pub version: u8,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    BlobTooShort(usize),
    UnsupportedVersion(u8),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::BlobTooShort(len) => {
                write!(f, "blob length {} is shorter than minimum 41 bytes", len)
            }
            EnvelopeError::UnsupportedVersion(v) => write!(f, "unsupported blob version: {}", v),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl RecordEnvelope {
    pub const VERSION_V1: u8 = 1;
    pub const NONCE_LEN: usize = 24;
    pub const TAG_LEN: usize = 16;
    pub const MIN_BLOB_LEN: usize = 1 + Self::NONCE_LEN + Self::TAG_LEN; // 41 bytes

    pub fn from_blob(blob: &[u8]) -> Result<Self, EnvelopeError> {
        if blob.len() < Self::MIN_BLOB_LEN {
            return Err(EnvelopeError::BlobTooShort(blob.len()));
        }
        if blob[0] != Self::VERSION_V1 {
            return Err(EnvelopeError::UnsupportedVersion(blob[0]));
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&blob[1..25]);
        let ciphertext = blob[25..].to_vec();
        Ok(Self {
            version: blob[0],
            nonce,
            ciphertext,
        })
    }

    pub fn to_blob(&self) -> Vec<u8> {
        let mut blob = Vec::with_capacity(1 + 24 + self.ciphertext.len());
        blob.push(self.version);
        blob.extend_from_slice(&self.nonce);
        blob.extend_from_slice(&self.ciphertext);
        blob
    }
}

// ============================================================================
// 4. Record Metadata & Client Views
// ============================================================================

/// Non-secret record metadata stored in SQLite columns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordMeta {
    pub id: Uuid,
    pub lamport: u64,
    pub origin_device: String,
    pub updated_at: i64,
    pub deleted: bool,
}

/// View model for an organizational space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceView {
    pub id: Uuid,
    pub name: String,
    pub position: u32,
    pub icon: Option<String>,
    pub is_default: bool,
    pub groups_count: usize,
}

impl SpaceView {
    pub fn new(
        id: Uuid,
        name: impl Into<String>,
        position: u32,
        icon: Option<String>,
        is_default: bool,
        groups_count: usize,
    ) -> Self {
        Self {
            id,
            name: name.into(),
            position,
            icon,
            is_default,
            groups_count,
        }
    }
}

/// View model for an organizational label / group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelView {
    pub id: Uuid,
    #[serde(default)]
    pub space_id: Option<Uuid>,
    pub name: String,
    pub position: u32,
    pub icon: Option<String>,
    pub items_count: usize,
}

impl LabelView {
    pub fn new(
        id: Uuid,
        name: impl Into<String>,
        position: u32,
        icon: Option<String>,
        items_count: usize,
    ) -> Self {
        Self {
            id,
            space_id: None,
            name: name.into(),
            position,
            icon,
            items_count,
        }
    }

    pub fn with_space(
        id: Uuid,
        space_id: Option<Uuid>,
        name: impl Into<String>,
        position: u32,
        icon: Option<String>,
        items_count: usize,
    ) -> Self {
        Self {
            id,
            space_id,
            name: name.into(),
            position,
            icon,
            items_count,
        }
    }
}

/// View model for an item container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemView {
    pub id: Uuid,
    pub label_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub position: u32,
    pub environments_count: usize,
    pub secrets_count: usize,
    pub assets_count: usize,
    pub files_count: usize,
    pub notes_count: usize,
}

impl ItemView {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        label_id: Uuid,
        name: impl Into<String>,
        description: Option<String>,
        position: u32,
        environments_count: usize,
        secrets_count: usize,
        assets_count: usize,
        notes_count: usize,
    ) -> Self {
        Self {
            id,
            label_id,
            name: name.into(),
            description,
            position,
            environments_count,
            secrets_count,
            assets_count,
            files_count: assets_count,
            notes_count,
        }
    }
}

/// View model for an environment including its secret count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentView {
    pub id: Uuid,
    #[serde(alias = "item_id")]
    pub project_id: Uuid,
    pub name: String,
    pub position: u32,
    pub secret_count: usize,
}

impl EnvironmentView {
    pub fn new(
        id: Uuid,
        item_id: Uuid,
        name: impl Into<String>,
        position: u32,
        secret_count: usize,
    ) -> Self {
        Self {
            id,
            project_id: item_id,
            name: name.into(),
            position,
            secret_count,
        }
    }

    #[inline]
    pub fn item_id(&self) -> Uuid {
        self.project_id
    }
}

impl std::ops::Deref for EnvironmentView {
    type Target = ItemIdCompat;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // Safety: ItemIdCompat is repr(transparent) around Uuid, matching project_id.
        unsafe { &*(&self.project_id as *const Uuid as *const ItemIdCompat) }
    }
}

/// Secret metadata sent to UI (strictly excludes full secret value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretMeta {
    pub id: Uuid,
    #[serde(alias = "item_id")]
    pub project_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub kind: SecretKind,
    pub note: Option<String>,
    pub updated_at: i64,
    pub value_tail: String,
}

impl SecretMeta {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        item_id: Uuid,
        environment_id: impl Into<Option<Uuid>>,
        name: impl Into<String>,
        kind: SecretKind,
        note: Option<String>,
        updated_at: i64,
        value_tail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            project_id: item_id,
            environment_id: environment_id.into(),
            name: name.into(),
            kind,
            note,
            updated_at,
            value_tail: value_tail.into(),
        }
    }

    #[inline]
    pub fn item_id(&self) -> Uuid {
        self.project_id
    }

    /// Computes value_tail: last 4 characters of value with whitespace stripped.
    pub fn compute_value_tail(raw_val: &str) -> String {
        let stripped: String = raw_val.chars().filter(|c| !c.is_whitespace()).collect();
        let len = stripped.chars().count();
        if len <= 4 {
            stripped
        } else {
            stripped.chars().skip(len - 4).collect()
        }
    }
}

impl std::ops::Deref for SecretMeta {
    type Target = ItemIdCompat;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // Safety: ItemIdCompat is repr(transparent) around Uuid, matching project_id.
        unsafe { &*(&self.project_id as *const Uuid as *const ItemIdCompat) }
    }
}

/// Active session tracking running processes with injected secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveSession {
    pub session_id: String,
    pub pid: u32,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub command: String,
    pub secret_ids: Vec<Uuid>,
    pub started_at: i64,
}

impl ActiveSession {
    pub fn new(
        session_id: impl Into<String>,
        pid: u32,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        command: impl Into<String>,
        secret_ids: Vec<Uuid>,
        started_at: i64,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            pid,
            item_id,
            environment_id,
            command: command.into(),
            secret_ids,
            started_at,
        }
    }
}

/// View model for asset metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetMetaView {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub size_bytes: u64,
    pub mime_type: String,
    pub sha256: String, // Hex string
    pub updated_at: i64,
}

impl AssetMetaView {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: Uuid,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        name: impl Into<String>,
        size_bytes: u64,
        mime_type: impl Into<String>,
        sha256: impl Into<String>,
        updated_at: i64,
    ) -> Self {
        Self {
            id,
            item_id,
            environment_id,
            name: name.into(),
            size_bytes,
            mime_type: mime_type.into(),
            sha256: sha256.into(),
            updated_at,
        }
    }
}

pub type FileMetaView = AssetMetaView;

/// Lightweight view model for note list / preview snippet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteMetaView {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub title: String,
    pub snippet: String,
    pub updated_at: i64,
    pub position: u32,
}

impl NoteMetaView {
    pub fn new(
        id: Uuid,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        title: impl Into<String>,
        snippet: impl Into<String>,
        updated_at: i64,
        position: u32,
    ) -> Self {
        Self {
            id,
            item_id,
            environment_id,
            title: title.into(),
            snippet: snippet.into(),
            updated_at,
            position,
        }
    }
}

/// Full view model for note viewing / editing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteView {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub title: String,
    pub content: String,
    pub updated_at: i64,
    pub position: u32,
}

impl NoteView {
    pub fn new(
        id: Uuid,
        item_id: Uuid,
        environment_id: Option<Uuid>,
        title: impl Into<String>,
        content: impl Into<String>,
        updated_at: i64,
        position: u32,
    ) -> Self {
        Self {
            id,
            item_id,
            environment_id,
            title: title.into(),
            content: content.into(),
            updated_at,
            position,
        }
    }
}

/// Customizable dashboard configuration persisted in SQLite settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashboardConfig {
    pub home_label: String,
    pub visible_kpis: Vec<String>,
    pub widgets: Vec<String>,
}

impl Default for DashboardConfig {
    fn default() -> Self {
        Self {
            home_label: "Home".to_string(),
            visible_kpis: vec![
                "items".to_string(),
                "secrets".to_string(),
                "files".to_string(),
                "notes".to_string(),
                "devices".to_string(),
            ],
            widgets: vec![
                "recent_secrets".to_string(),
                "recent_notes".to_string(),
                "quick_actions".to_string(),
                "checklist".to_string(),
            ],
        }
    }
}

/// View model for a project including its environments (retained for backward compatibility).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectView {
    pub id: Uuid,
    pub name: String,
    pub environments: Vec<EnvironmentView>,
}

/// Secwet status state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecwetStatus {
    Uninitialized,
    Locked { secwet_id: Uuid },
    Unlocked { secwet_id: Uuid },
}

/// User and device preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// Appearance preference: "system" | "light" | "dark".
    pub theme: String,
    /// Auto-lock timeout in minutes: 5 | 15 | 30 | 60.
    #[serde(alias = "lock_minutes")]
    pub lock_timeout_minutes: u32,
    /// Human-readable device label (stored encrypted).
    pub device_name: String,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: "system".to_string(),
            lock_timeout_minutes: 15,
            device_name: "default-device".to_string(),
        }
    }
}

// ============================================================================
// 5. Sync Event Wire Envelope & Bodies
// ============================================================================

/// Wire event envelope readable by relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub event_id: [u8; 16],
    pub secwet_id: [u8; 16],
    pub device_id: String,
    pub device_seq: u64,
    pub key_epoch: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    /// Routing scope for events in collaborative spaces (F19). `None` for
    /// workspace-private events, which only the owner's devices receive.
    #[serde(default)]
    pub scope: Option<EventScope>,
}

/// Field layout of envelopes written before scoped events existed.
#[derive(Serialize, Deserialize)]
struct LegacyEventEnvelope {
    event_id: [u8; 16],
    secwet_id: [u8; 16],
    device_id: String,
    device_seq: u64,
    key_epoch: u32,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct LegacySignedEvent {
    envelope: LegacyEventEnvelope,
    #[serde(with = "signature_bytes")]
    signature: [u8; 64],
}

impl EventEnvelope {
    /// Bytes covered by the Ed25519 event signature. Unscoped envelopes sign
    /// the original seven-field layout so events signed before scopes existed
    /// still verify; scoped envelopes sign every field including the scope.
    pub fn signing_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        match &self.scope {
            None => postcard::to_stdvec(&(
                &self.event_id,
                &self.secwet_id,
                &self.device_id,
                self.device_seq,
                self.key_epoch,
                &self.nonce,
                &self.ciphertext,
            )),
            Some(_) => postcard::to_stdvec(self),
        }
    }
}

impl SignedEvent {
    /// Decodes a postcard `SignedEvent`, accepting the pre-scope layout too.
    pub fn from_postcard_compat(bytes: &[u8]) -> Result<SignedEvent, postcard::Error> {
        match postcard::from_bytes::<SignedEvent>(bytes) {
            Ok(ev) => Ok(ev),
            Err(e) => match postcard::from_bytes::<LegacySignedEvent>(bytes) {
                Ok(l) => Ok(SignedEvent {
                    envelope: EventEnvelope {
                        event_id: l.envelope.event_id,
                        secwet_id: l.envelope.secwet_id,
                        device_id: l.envelope.device_id,
                        device_seq: l.envelope.device_seq,
                        key_epoch: l.envelope.key_epoch,
                        nonce: l.envelope.nonce,
                        ciphertext: l.envelope.ciphertext,
                        scope: None,
                    },
                    signature: l.signature,
                }),
                Err(_) => Err(e),
            },
        }
    }
}

mod signature_bytes {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor;
        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 64-byte signature")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.try_into().map_err(|_| E::invalid_length(v.len(), &self))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut bytes = [0u8; 64];
                for (i, byte) in bytes.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(bytes)
            }
        }

        deserializer.deserialize_bytes(SigVisitor)
    }
}

/// Signed event container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedEvent {
    pub envelope: EventEnvelope,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

/// Event AAD structure for postcard canonicalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EventAad<'a> {
    pub event_id: &'a [u8; 16],
    pub secwet_id: &'a [u8; 16],
    pub device_id: &'a str,
    pub device_seq: u64,
    pub key_epoch: u32,
}

/// Owned variant of EventAad.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventAadOwned {
    pub event_id: [u8; 16],
    pub secwet_id: [u8; 16],
    pub device_id: String,
    pub device_seq: u64,
    pub key_epoch: u32,
}

impl EventAadOwned {
    pub fn as_borrowed(&self) -> EventAad<'_> {
        EventAad {
            event_id: &self.event_id,
            secwet_id: &self.secwet_id,
            device_id: &self.device_id,
            device_seq: self.device_seq,
            key_epoch: self.key_epoch,
        }
    }
}

/// Decrypted event mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EventBody {
    Upsert {
        record_id: Uuid,
        record_type: u8,
        lamport: u64,
        body: Vec<u8>,
    },
    Delete {
        record_id: Uuid,
        record_type: u8,
        lamport: u64,
    },
    DeviceRenamed {
        device_id: String,
        name: String,
    },
    /// An owner device vouches for a device's keys and membership. Sealed
    /// with the workspace event key, so only workspace-key holders can
    /// produce it; the relay's device list is never trusted on its own.
    DeviceCertified {
        device_id: String,
        sign_pub: [u8; 32],
        enc_pub: [u8; 32],
        member_id: Option<Uuid>,
    },
    /// Re-emission of an existing record when a branch is shared or rotated.
    /// Applied only when the receiver does not have the record yet, with the
    /// original author as origin, so it never wins last-writer-wins.
    Seed {
        record_id: Uuid,
        record_type: u8,
        lamport: u64,
        origin_device: String,
        body: Vec<u8>,
    },
}

// ============================================================================
// 6. Key Wrap & Pairing Models
// ============================================================================

/// Context bound to HPKE key wrap operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KeyWrapInfo<'a> {
    pub purpose: &'a str,
    pub secwet_id: &'a [u8; 16],
    pub key_epoch: u32,
    pub recipient_device_id: &'a str,
}

/// Owned variant of KeyWrapInfo.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyWrapInfoOwned {
    pub purpose: String,
    pub secwet_id: [u8; 16],
    pub key_epoch: u32,
    pub recipient_device_id: String,
}

impl KeyWrapInfoOwned {
    pub fn as_borrowed(&self) -> KeyWrapInfo<'_> {
        KeyWrapInfo {
            purpose: &self.purpose,
            secwet_id: &self.secwet_id,
            key_epoch: self.key_epoch,
            recipient_device_id: &self.recipient_device_id,
        }
    }
}

/// HPKE Wrapped key packet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKey {
    pub enc: [u8; 32],
    pub ciphertext: Vec<u8>,
}

/// Pairing approval record signed by authorized device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingApproval {
    pub secwet_id: [u8; 16],
    pub session_id: [u8; 16],
    pub device_id: String,
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    pub approved_at: i64,
}

/// Device profile sealed inside pairing join payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingProfile {
    pub name: String,
    pub platform: String,
}

/// Request to create a pairing session on the relay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePairingSessionRequest {
    pub secwet_id: Uuid,
    pub a_eph_pub: [u8; 32],
}

/// Response returned when a pairing session is created.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreatePairingSessionResponse {
    pub session_id: Uuid,
    pub expires_at: String,
    pub qr_payload: String,
}

/// Join payload submitted by new device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingJoinRequest {
    pub n_eph_pub: [u8; 32],
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    pub sealed_profile: Vec<u8>,
}

/// A wrapped key for a specific master key epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedEpochKey {
    pub epoch: u32,
    pub wrapped: WrappedKey,
}

/// Request to approve a pairing session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingApproveRequest {
    pub approval: PairingApproval,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
    pub wrapped_keys: Vec<WrappedEpochKey>,
}

/// Response returned on GET /v1/pairing/{id}.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingSessionStatusResponse {
    pub session_id: Uuid,
    pub secwet_id: Uuid,
    pub created_by: String,
    pub expires_at: String,
    pub status: String,
    pub join_payload: Option<PairingJoinRequest>,
}

/// Response returned on GET /v1/pairing/{id}/result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingResultResponse {
    pub secwet_id: Uuid,
    pub device_id: String,
    pub wrapped_keys: Vec<WrappedEpochKey>,
}

/// Unified Device DTO matching desktop and CLI presentations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceDto {
    pub id: String,
    pub name: String,
    pub platform: String,
    pub fingerprint: String,
    pub added_at: i64,
    pub last_seen_at: i64,
    pub revoked_at: Option<i64>,
    pub is_current: bool,
}

/// Pairing session information returned to UI or CLI when starting pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingSessionInfo {
    pub session_id: Uuid,
    pub expires_at: String,
    pub qr_payload: String,
}

/// Status of an active pairing session polled by the approving device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PairingPollResponse {
    Waiting,
    Found {
        name: String,
        platform: String,
        fingerprint: String,
        code: String,
        device_id: String,
    },
    Expired,
    Approved,
}

// ============================================================================
// Sync DTOs (M6)
// ============================================================================

/// Request body for POST /v1/secwets/{id}/events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushEventsRequest {
    pub events: Vec<SignedEvent>,
}

/// Response body for POST /v1/secwets/{id}/events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushEventsResponse {
    pub accepted: usize,
    pub latest_server_seq: u64,
    /// Event ids the relay consumed without storing because the author's role
    /// does not permit them (F19). Counted in `accepted`.
    #[serde(default)]
    pub rejected: Vec<[u8; 16]>,
}

/// Stored event representation returned during event pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredEventDto {
    pub server_seq: u64,
    pub event: SignedEvent,
    pub received_at: i64,
}

/// Response body for GET /v1/secwets/{id}/events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PullEventsResponse {
    pub events: Vec<StoredEventDto>,
    pub has_more: bool,
    /// Newest `server_seq` in the workspace, so a device that sees no events
    /// (a member with quiet spaces) can still advance and ack.
    #[serde(default)]
    pub head_seq: u64,
}

/// Request body for POST /v1/secwets/{id}/ack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AckEventsRequest {
    pub server_seq: u64,
}

/// Request body for PUT /v1/secwets/{id}/snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotUploadRequest {
    pub server_seq: u64,
    pub key_epoch: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

/// Response body for GET /v1/secwets/{id}/snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotResponse {
    pub server_seq: u64,
    pub key_epoch: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub updated_at: i64,
}

/// Message emitted over the WebSocket stream (GET /v1/secwets/{id}/stream).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamEventMessage {
    pub r#type: String,
    pub server_seq: u64,
}

// ============================================================================
// 7. Relay Error Codes, Constants & Wire Models
// ============================================================================

pub const HEADER_DEVICE: &str = "x-secwet-device";
pub const HEADER_TIME: &str = "x-secwet-time";
pub const HEADER_NONCE: &str = "x-secwet-nonce";
pub const HEADER_SIGNATURE: &str = "x-secwet-signature";
pub const REQUEST_SIGNATURE_CONTEXT: &str = "secwet-req-v1";
pub const REGISTRATION_PROOF_CONTEXT: &str = "secwet-reg-proof-v1";
pub const MAX_CLOCK_SKEW_MS: i64 = 60_000;
pub const NONCE_RETENTION_SECS: i64 = 600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayErrorCode {
    Exists,
    NotEntitled,
    Expired,
    AlreadyJoined,
    DeviceLimit,
    BadSignature,
    Pending,
    CannotRevokeSelf,
    EpochConflict,
    SeqGap,
    Revoked,
    CursorExpired,
    NotFound,
    Internal,
    ReusedNonce,
    ExpiredTimestamp,
    Unauthorized,
    RateLimited,
    Forbidden,
    AlreadyRevoked,
    InvalidInvitation,
    InvalidRequest,
}

impl RelayErrorCode {
    pub const fn http_status_code(&self) -> u16 {
        match self {
            Self::Exists => 409,
            Self::NotEntitled => 403,
            Self::Expired => 400,
            Self::AlreadyJoined => 409,
            Self::DeviceLimit => 403,
            Self::BadSignature => 401,
            Self::Pending => 202,
            Self::CannotRevokeSelf => 400,
            Self::EpochConflict => 409,
            Self::SeqGap => 400,
            Self::Revoked => 403,
            Self::CursorExpired => 410,
            Self::NotFound => 404,
            Self::Internal => 500,
            Self::ReusedNonce => 401,
            Self::ExpiredTimestamp => 401,
            Self::Unauthorized => 401,
            Self::RateLimited => 429,
            Self::Forbidden => 403,
            Self::AlreadyRevoked => 409,
            Self::InvalidInvitation => 403,
            Self::InvalidRequest => 400,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayErrorDetail {
    pub code: RelayErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayError {
    pub error: RelayErrorDetail,
    /// Present on `revoked` errors sent to the revoked device itself: the
    /// signed directive it verifies before wiping or archiving (F16).
    #[serde(default)]
    pub revocation: Option<SignedRevocation>,
}

impl RelayError {
    pub fn new(code: RelayErrorCode, message: impl Into<String>) -> Self {
        Self {
            error: RelayErrorDetail {
                code,
                message: message.into(),
            },
            revocation: None,
        }
    }
}

/// Computes the exact canonical byte sequence for a signed relay request.
/// Format: postcard(("secwet-req-v1", method, path_and_query, time_ms, nonce, body_sha256))
pub fn canonical_request_bytes(
    method: &str,
    path_and_query: &str,
    time_ms: i64,
    nonce: &[u8],
    body_sha256: &[u8; 32],
) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(&(
        REQUEST_SIGNATURE_CONTEXT,
        method,
        path_and_query,
        time_ms,
        nonce,
        *body_sha256,
    ))
}

/// Computes canonical proof bytes for store and first device registration.
/// Format: postcard(("secwet-reg-proof-v1", secwet_id, sign_pub, enc_pub))
pub fn canonical_registration_proof_bytes(
    secwet_id: &Uuid,
    sign_pub: &[u8; 32],
    enc_pub: &[u8; 32],
) -> Result<Vec<u8>, postcard::Error> {
    postcard::to_stdvec(&(
        REGISTRATION_PROOF_CONTEXT,
        secwet_id.as_bytes(),
        sign_pub,
        enc_pub,
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSecwetRequest {
    pub secwet_id: Uuid,
    pub sign_pub: [u8; 32],
    pub enc_pub: [u8; 32],
    #[serde(with = "signature_bytes")]
    pub proof: [u8; 64],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSecwetResponse {
    pub secwet_id: Uuid,
    pub device_id: String,
    pub created_at: String,
    pub current_epoch: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitlementResponse {
    pub secwet_id: Uuid,
    pub plan: String,
    pub device_limit: u32,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatusDto {
    pub connected: bool,
    pub relay_url: String,
    pub plan: String,
    pub device_limit: u32,
    pub active_devices: u32,
    pub expires_at: Option<String>,
    pub pending_outbox_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminGrantRequest {
    pub secwet_id: Uuid,
    pub plan: String,
    pub device_limit: u32,
    pub expires_at: Option<String>,
}

// ============================================================================
// 8. Field Validation Helpers & Invariants
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    EmptyField(&'static str),
    TooLong {
        field: &'static str,
        max: usize,
        actual: usize,
    },
    InvalidName(&'static str),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::EmptyField(field) => write!(f, "field {} cannot be empty", field),
            ValidationError::TooLong { field, max, actual } => {
                write!(
                    f,
                    "field {} exceeded max length {} (was {})",
                    field, max, actual
                )
            }
            ValidationError::InvalidName(field) => {
                write!(f, "field {} contains invalid characters", field)
            }
        }
    }
}

impl std::error::Error for ValidationError {}

pub fn validate_space_name(name: &str) -> Result<String, ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::EmptyField("space_name"));
    }
    let char_count = trimmed.chars().count();
    if char_count > 64 {
        return Err(ValidationError::TooLong {
            field: "space_name",
            max: 64,
            actual: char_count,
        });
    }
    Ok(trimmed.to_string())
}

pub fn validate_label_name(name: &str) -> Result<String, ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::EmptyField("label_name"));
    }
    let char_count = trimmed.chars().count();
    if char_count > 64 {
        return Err(ValidationError::TooLong {
            field: "label_name",
            max: 64,
            actual: char_count,
        });
    }
    Ok(trimmed.to_string())
}

pub fn validate_item_name(name: &str) -> Result<String, ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::EmptyField("item_name"));
    }
    let char_count = trimmed.chars().count();
    if char_count > 64 {
        return Err(ValidationError::TooLong {
            field: "item_name",
            max: 64,
            actual: char_count,
        });
    }
    Ok(trimmed.to_string())
}

pub fn validate_item_description(desc: Option<&str>) -> Result<(), ValidationError> {
    if let Some(d) = desc {
        let char_count = d.chars().count();
        if char_count > 500 {
            return Err(ValidationError::TooLong {
                field: "item_description",
                max: 500,
                actual: char_count,
            });
        }
    }
    Ok(())
}

pub fn validate_asset_name(name: &str) -> Result<String, ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::EmptyField("asset_name"));
    }
    let char_count = trimmed.chars().count();
    if char_count > 255 {
        return Err(ValidationError::TooLong {
            field: "asset_name",
            max: 255,
            actual: char_count,
        });
    }
    Ok(trimmed.to_string())
}

pub use validate_asset_name as validate_file_name;

pub fn validate_asset_size(size_bytes: u64) -> Result<(), ValidationError> {
    const MAX_ASSET_SIZE: u64 = 50 * 1024 * 1024; // 50 MiB = 52,428,800 bytes
    if size_bytes > MAX_ASSET_SIZE {
        return Err(ValidationError::TooLong {
            field: "asset_size",
            max: MAX_ASSET_SIZE as usize,
            actual: size_bytes as usize,
        });
    }
    Ok(())
}

pub use validate_asset_size as validate_file_size;

pub fn validate_note_title(title: &str) -> Result<String, ValidationError> {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::EmptyField("note_title"));
    }
    let char_count = trimmed.chars().count();
    if char_count > 128 {
        return Err(ValidationError::TooLong {
            field: "note_title",
            max: 128,
            actual: char_count,
        });
    }
    Ok(trimmed.to_string())
}

/// Maximum allowed length of a note's rich-text content in Unicode characters (scalar values).
pub const MAX_NOTE_CONTENT_CHARS: usize = 1_000_000;

/// Validates note rich-text content against length invariants.
///
/// Rich-text note content can be empty (e.g. newly initialized notes),
/// but its character count must not exceed `MAX_NOTE_CONTENT_CHARS` (1,000,000 characters).
///
/// # Errors
/// Returns `ValidationError::TooLong` if `content.chars().count() > MAX_NOTE_CONTENT_CHARS`.
pub fn validate_note_content(content: &str) -> Result<(), ValidationError> {
    // Fast path: if byte length <= MAX_NOTE_CONTENT_CHARS, char count cannot exceed it
    if content.len() <= MAX_NOTE_CONTENT_CHARS {
        return Ok(());
    }
    let char_count = content.chars().count();
    if char_count > MAX_NOTE_CONTENT_CHARS {
        return Err(ValidationError::TooLong {
            field: "note_content",
            max: MAX_NOTE_CONTENT_CHARS,
            actual: char_count,
        });
    }
    Ok(())
}

/// Validates both note title and rich-text note content.
///
/// Sanitizes `title` by trimming leading/trailing whitespace and enforcing 1..=128 characters.
/// Validates that `content` does not exceed `MAX_NOTE_CONTENT_CHARS` (1,000,000 characters).
///
/// Returns the sanitized (trimmed) title on success.
pub fn validate_note(title: &str, content: &str) -> Result<String, ValidationError> {
    let clean_title = validate_note_title(title)?;
    validate_note_content(content)?;
    Ok(clean_title)
}

#[inline]
pub fn validate_project_name(name: &str) -> Result<String, ValidationError> {
    validate_item_name(name).map_err(|e| match e {
        ValidationError::EmptyField(_) => ValidationError::EmptyField("project_name"),
        ValidationError::TooLong { max, actual, .. } => ValidationError::TooLong {
            field: "project_name",
            max,
            actual,
        },
        other => other,
    })
}

pub fn validate_environment_name(name: &str) -> Result<String, ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::EmptyField("environment_name"));
    }
    let char_count = trimmed.chars().count();
    if char_count > 64 {
        return Err(ValidationError::TooLong {
            field: "environment_name",
            max: 64,
            actual: char_count,
        });
    }
    Ok(trimmed.to_string())
}

pub fn validate_secret_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::EmptyField("secret_name"));
    }
    let char_count = name.chars().count();
    if char_count > 128 {
        return Err(ValidationError::TooLong {
            field: "secret_name",
            max: 128,
            actual: char_count,
        });
    }

    // Regex check: ^[A-Za-z_][A-Za-z0-9_.@-]*$
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return Err(ValidationError::EmptyField("secret_name"));
    };
    if !first.is_ascii_alphabetic() && first != '_' {
        return Err(ValidationError::InvalidName("secret_name"));
    }
    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '@' && c != '-' {
            return Err(ValidationError::InvalidName("secret_name"));
        }
    }
    Ok(())
}

pub fn validate_secret_value(value: &str) -> Result<(), ValidationError> {
    // Value must not exceed 64 KiB = 65,536 bytes
    if value.len() > 65_536 {
        return Err(ValidationError::TooLong {
            field: "secret_value",
            max: 65_536,
            actual: value.len(),
        });
    }
    Ok(())
}

pub fn validate_secret_note(note: Option<&str>) -> Result<(), ValidationError> {
    if let Some(n) = note {
        let char_count = n.chars().count();
        if char_count > 500 {
            return Err(ValidationError::TooLong {
                field: "secret_note",
                max: 500,
                actual: char_count,
            });
        }
    }
    Ok(())
}

pub fn validate_theme(theme: &str) -> Result<(), ValidationError> {
    match theme {
        "system" | "light" | "dark" => Ok(()),
        _ => Err(ValidationError::InvalidName("theme")),
    }
}

pub fn validate_lock_timeout_minutes(minutes: u32) -> Result<(), ValidationError> {
    match minutes {
        5 | 15 | 30 | 60 => Ok(()),
        _ => Err(ValidationError::InvalidName("lock_timeout_minutes")),
    }
}

pub fn validate_device_name(name: &str) -> Result<String, ValidationError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ValidationError::EmptyField("device_name"));
    }
    let char_count = trimmed.chars().count();
    if char_count > 64 {
        return Err(ValidationError::TooLong {
            field: "device_name",
            max: 64,
            actual: char_count,
        });
    }
    Ok(trimmed.to_string())
}

// ============================================================================
// 9. Rich-Text & Formatting Helpers
// ============================================================================

/// Extracts clean, readable plain text from HTML or Markdown note content.
///
/// Strips HTML tags while preserving line breaks, list structure (bullets with indentation),
/// unescaping standard HTML entities, ignoring script/style block contents,
/// and preserving mathematical comparison operators like `<` and `>`.
pub fn extract_plain_text(content: &str) -> String {
    let mut out = String::with_capacity(content.len());
    let mut list_depth: usize = 0;
    let mut skip_until: Option<&'static str> = None;

    let chars: Vec<char> = content.chars().collect();
    let len = chars.len();
    let mut i = 0;

    while i < len {
        let c = chars[i];

        // 1. Script/style content skipping
        if let Some(skip_tag) = skip_until {
            if c == '<' && i + 1 < len && chars[i + 1] == '/' {
                let mut j = i + 2;
                while j < len && chars[j] != '>' {
                    j += 1;
                }
                if j < len {
                    let tag_content: String = chars[i + 2..j].iter().collect();
                    let tag_name = tag_content
                        .trim()
                        .split(|ch: char| ch.is_whitespace() || ch == '/')
                        .next()
                        .unwrap_or("");
                    if tag_name.eq_ignore_ascii_case(skip_tag) {
                        skip_until = None;
                        i = j + 1;
                        continue;
                    }
                }
            }
            i += 1;
            continue;
        }

        // 2. HTML Tag detection & parsing
        if c == '<' {
            let mut j = i + 1;
            let mut quote: Option<char> = None;
            let mut found_close = false;
            while j < len {
                let ch = chars[j];
                if let Some(q) = quote {
                    if ch == q {
                        quote = None;
                    }
                } else if ch == '"' || ch == '\'' {
                    quote = Some(ch);
                } else if ch == '>' {
                    found_close = true;
                    break;
                } else if ch == '<' {
                    break;
                }
                j += 1;
            }

            if found_close {
                let raw_content: String = chars[i + 1..j].iter().collect();
                let trimmed = raw_content.trim();

                // Empty tag: <> or <   >
                if trimmed.is_empty() {
                    i = j + 1;
                    continue;
                }

                // If raw_content starts with whitespace (and is not empty),
                // e.g. "< 10 and 10 >", it is a mathematical operator, not a tag
                if raw_content.starts_with(|ch: char| ch.is_whitespace()) {
                    out.push('<');
                    i += 1;
                    continue;
                }

                // Comment or doctype: <!-- ... --> or <!DOCTYPE ...>
                if raw_content.starts_with("!--") || raw_content.starts_with('!') {
                    i = j + 1;
                    continue;
                }

                // Closing tag: </tag>
                if let Some(rest) = trimmed.strip_prefix('/') {
                    let tag_name = rest
                        .trim_start()
                        .split(|ch: char| ch.is_whitespace() || ch == '/')
                        .next()
                        .unwrap_or("");

                    if !tag_name.is_empty()
                        && tag_name.starts_with(|ch: char| ch.is_ascii_alphabetic())
                    {
                        if tag_name.eq_ignore_ascii_case("p")
                            || tag_name.eq_ignore_ascii_case("div")
                            || tag_name.eq_ignore_ascii_case("h1")
                            || tag_name.eq_ignore_ascii_case("h2")
                            || tag_name.eq_ignore_ascii_case("h3")
                            || tag_name.eq_ignore_ascii_case("h4")
                            || tag_name.eq_ignore_ascii_case("h5")
                            || tag_name.eq_ignore_ascii_case("h6")
                            || tag_name.eq_ignore_ascii_case("blockquote")
                            || tag_name.eq_ignore_ascii_case("pre")
                            || tag_name.eq_ignore_ascii_case("tr")
                        {
                            out.push('\n');
                        } else if tag_name.eq_ignore_ascii_case("li") {
                            if !out.ends_with('\n') {
                                out.push('\n');
                            }
                        } else if tag_name.eq_ignore_ascii_case("ul")
                            || tag_name.eq_ignore_ascii_case("ol")
                        {
                            list_depth = list_depth.saturating_sub(1);
                            if !out.is_empty() && !out.ends_with('\n') {
                                out.push('\n');
                            }
                        }
                        i = j + 1;
                        continue;
                    }
                } else {
                    // Opening or self-closing tag
                    let is_self_closing = trimmed.ends_with('/')
                        || (trimmed.split_whitespace().next_back() == Some("/"));

                    let tag_name = trimmed
                        .split(|ch: char| ch.is_whitespace() || ch == '/')
                        .next()
                        .unwrap_or("");

                    if !tag_name.is_empty()
                        && tag_name.starts_with(|ch: char| ch.is_ascii_alphabetic())
                    {
                        if tag_name.eq_ignore_ascii_case("script") {
                            if !is_self_closing {
                                skip_until = Some("script");
                            }
                            i = j + 1;
                            continue;
                        } else if tag_name.eq_ignore_ascii_case("style") {
                            if !is_self_closing {
                                skip_until = Some("style");
                            }
                            i = j + 1;
                            continue;
                        } else if tag_name.eq_ignore_ascii_case("br")
                            || tag_name.eq_ignore_ascii_case("p")
                            || tag_name.eq_ignore_ascii_case("div")
                            || tag_name.eq_ignore_ascii_case("h1")
                            || tag_name.eq_ignore_ascii_case("h2")
                            || tag_name.eq_ignore_ascii_case("h3")
                            || tag_name.eq_ignore_ascii_case("h4")
                            || tag_name.eq_ignore_ascii_case("h5")
                            || tag_name.eq_ignore_ascii_case("h6")
                            || tag_name.eq_ignore_ascii_case("blockquote")
                            || tag_name.eq_ignore_ascii_case("pre")
                            || tag_name.eq_ignore_ascii_case("hr")
                        {
                            out.push('\n');
                            i = j + 1;
                            continue;
                        } else if tag_name.eq_ignore_ascii_case("ul")
                            || tag_name.eq_ignore_ascii_case("ol")
                        {
                            list_depth += 1;
                            i = j + 1;
                            continue;
                        } else if tag_name.eq_ignore_ascii_case("li") {
                            while out.ends_with(' ') || out.ends_with('\t') {
                                out.pop();
                            }
                            if !out.is_empty() && !out.ends_with('\n') {
                                out.push('\n');
                            }
                            for _ in 0..list_depth.saturating_sub(1) {
                                out.push_str("  ");
                            }
                            out.push_str("• ");
                            i = j + 1;
                            continue;
                        } else if tag_name.eq_ignore_ascii_case("tr") {
                            out.push('\n');
                            i = j + 1;
                            continue;
                        } else {
                            // Any other valid inline tag: b, i, strong, em, span, a, etc.
                            i = j + 1;
                            continue;
                        }
                    }
                }

                // If candidate did NOT match valid tag syntax (e.g. "5 < 10 and 10 > 5"),
                // it is treated as plain text mathematical '<'
                out.push('<');
                i += 1;
                continue;
            } else {
                // No matching '>' found before EOF or next '<'
                if i + 1 < len {
                    let next_c = chars[i + 1];
                    if next_c.is_ascii_alphabetic() || next_c == '/' || next_c == '!' {
                        // Unclosed HTML tag: discard from '<' to EOF
                        break;
                    } else if next_c == '<' {
                        // Sequential '<', skip this one
                        i += 1;
                        continue;
                    }
                    out.push('<');
                    i += 1;
                    continue;
                } else {
                    // Trailing lone '<' at EOF without closing '>'
                    break;
                }
            }
        }

        // 3. Entity decoding
        if c == '&' {
            let rest: String = chars[i..chars.len().min(i + 10)].iter().collect();
            if rest.starts_with("&amp;") {
                out.push('&');
                i += 5;
                continue;
            } else if rest.starts_with("&lt;") {
                out.push('<');
                i += 4;
                continue;
            } else if rest.starts_with("&gt;") {
                out.push('>');
                i += 4;
                continue;
            } else if rest.starts_with("&quot;") {
                out.push('"');
                i += 6;
                continue;
            } else if rest.starts_with("&#39;") || rest.starts_with("&apos;") {
                out.push('\'');
                i += if rest.starts_with("&apos;") { 6 } else { 5 };
                continue;
            } else if rest.starts_with("&nbsp;") {
                out.push(' ');
                i += 6;
                continue;
            }
        }

        // 4. Default character emission
        out.push(c);
        i += 1;
    }

    // 5. Normalization pass: collapse blank lines (> 2 newlines) into 2 newlines,
    // preserving leading indentation for list items
    let mut normalized = String::with_capacity(out.len());
    let mut newline_count = 0;
    for line in out.lines() {
        let trimmed_line = line.trim_end();
        if trimmed_line.is_empty() {
            newline_count += 1;
            if newline_count <= 2 {
                normalized.push('\n');
            }
        } else {
            newline_count = 0;
            if !normalized.is_empty() && !normalized.ends_with('\n') {
                normalized.push('\n');
            }
            normalized.push_str(trimmed_line);
            normalized.push('\n');
        }
    }

    normalized.trim().to_string()
}

/// Generates a preview snippet of at most `max_chars` from rich text note content.
pub fn snippet_from_content(content: &str, max_chars: usize) -> String {
    let plain = extract_plain_text(content);
    let chars: Vec<char> = plain.chars().collect();
    if chars.len() <= max_chars {
        plain
    } else {
        let prefix: String = chars[..max_chars].iter().collect();
        format!("{}...", prefix.trim_end())
    }
}

// ============================================================================
// 10. Snapshot, Export, and Recovery Models (Milestone 3)
// ============================================================================

/// Snapshot representation of an organizational space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSpace {
    pub id: Uuid,
    pub name: String,
    pub position: u32,
    pub icon: Option<String>,
    pub is_default: bool,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
}

/// Snapshot representation of an organizational label / group.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLabel {
    pub id: Uuid,
    pub space_id: Option<Uuid>,
    pub name: String,
    pub position: u32,
    pub icon: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub deleted: bool,
}

/// Snapshot representation of an item container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotItem {
    pub id: Uuid,
    pub label_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub position: u32,
    pub lamport: u64,
    pub origin_device: String,
    pub updated_at: i64,
    pub deleted: bool,
}

/// Snapshot representation of an environment record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEnvironment {
    pub id: Uuid,
    pub item_id: Uuid,
    pub name: String,
    pub position: u32,
    pub lamport: u64,
    pub origin_device: String,
    pub updated_at: i64,
    pub deleted: bool,
}

/// Snapshot representation of a secret record.
///
/// Custom Debug implementation ensures plaintext value is redacted.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSecret {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub kind: SecretKind,
    pub value: String,
    pub note: Option<String>,
    pub lamport: u64,
    pub origin_device: String,
    pub updated_at: i64,
    pub deleted: bool,
}

impl std::fmt::Debug for SnapshotSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotSecret")
            .field("id", &self.id)
            .field("item_id", &self.item_id)
            .field("environment_id", &self.environment_id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"[REDACTED]")
            .field("note", &self.note)
            .field("lamport", &self.lamport)
            .field("origin_device", &self.origin_device)
            .field("updated_at", &self.updated_at)
            .field("deleted", &self.deleted)
            .finish()
    }
}

/// Snapshot representation of a rich-text note record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotNote {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub title: String,
    pub content: String,
    pub position: u32,
    pub lamport: u64,
    pub origin_device: String,
    pub updated_at: i64,
    pub deleted: bool,
}

/// Snapshot representation of an asset file payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub size_bytes: u64,
    pub mime_type: String,
    pub sha256: [u8; 32],
    pub data: Vec<u8>,
    pub lamport: u64,
    pub origin_device: String,
    pub updated_at: i64,
    pub deleted: bool,
}

/// Snapshot representation of a setting key-value pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSetting {
    pub key: String,
    pub value: String,
}

/// Canonical Secwet Snapshot for encrypted backup and disaster recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecwetSnapshot {
    pub secwet_id: Uuid,
    pub created_at: i64,
    pub key_epoch: u32,
    pub plan: String,
    pub relay_url: String,
    pub spaces: Vec<SnapshotSpace>,
    pub labels: Vec<SnapshotLabel>,
    #[serde(alias = "projects")]
    pub items: Vec<SnapshotItem>,
    pub environments: Vec<SnapshotEnvironment>,
    pub secrets: Vec<SnapshotSecret>,
    pub notes: Vec<SnapshotNote>,
    pub files: Vec<SnapshotFile>,
    pub settings: Vec<SnapshotSetting>,
}

impl SecwetSnapshot {
    #[inline]
    pub fn projects(&self) -> &[SnapshotItem] {
        &self.items
    }
}

/// Authenticated Additional Data (AAD) bound to the encrypted backup envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportAad {
    pub format: String,
    pub version: u8,
    pub secwet_id: Uuid,
}

impl ExportAad {
    pub const FORMAT_V1: &'static str = "secwet-export";
    pub const VERSION_V1: u8 = 1;

    pub fn new(secwet_id: Uuid) -> Self {
        Self {
            format: Self::FORMAT_V1.to_string(),
            version: Self::VERSION_V1,
            secwet_id,
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, postcard::Error> {
        postcard::to_stdvec(self)
    }
}

/// Wire JSON envelope for encrypted `.secwet` workspace exports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecwetExportEnvelope {
    pub format: String,
    pub version: u32,
    pub secwet_id: Uuid,
    pub created_at: i64,
    pub kdf: String,
    pub cipher: String,
    pub nonce: String,
    pub ciphertext: String,
}

/// Summary metrics returned upon successful workspace export.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSummary {
    pub secwet_id: Uuid,
    pub created_at: i64,
    pub spaces_count: usize,
    pub labels_count: usize,
    pub items_count: usize,
    pub environments_count: usize,
    pub secrets_count: usize,
    pub notes_count: usize,
    pub files_count: usize,
    pub bytes_written: usize,
    #[serde(default)]
    pub projects_count: usize,
    #[serde(default)]
    pub assets_count: usize,
}

impl ExportSummary {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        secwet_id: Uuid,
        created_at: i64,
        spaces_count: usize,
        labels_count: usize,
        items_count: usize,
        environments_count: usize,
        secrets_count: usize,
        notes_count: usize,
        files_count: usize,
        bytes_written: usize,
    ) -> Self {
        Self {
            secwet_id,
            created_at,
            spaces_count,
            labels_count,
            items_count,
            environments_count,
            secrets_count,
            notes_count,
            files_count,
            bytes_written,
            projects_count: items_count,
            assets_count: files_count,
        }
    }
}

/// Recovery key status for UI and overview queries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveryStatus {
    pub created: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<u64>,
}

impl RecoveryStatus {
    pub fn new(created: bool, created_at: Option<u64>) -> Self {
        Self { created, created_at }
    }
}

// ============================================================================
// 11. Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_roundtrip() {
        for (byte, expected) in [
            (1u8, RecordType::Label),
            (2, RecordType::Item),
            (3, RecordType::Environment),
            (4, RecordType::Secret),
            (5, RecordType::File),
            (6, RecordType::Note),
            (7, RecordType::Space),
        ] {
            assert_eq!(RecordType::try_from(byte).unwrap(), expected);
            assert_eq!(u8::from(expected), byte);

            let encoded = postcard::to_stdvec(&expected).unwrap();
            let decoded: RecordType = postcard::from_bytes(&encoded).unwrap();
            assert_eq!(decoded, expected);
        }

        assert!(RecordType::try_from(0).is_err());
        assert!(RecordType::try_from(8).is_err());
        assert!(RecordType::try_from(255).is_err());
    }

    #[test]
    fn test_secret_kind_roundtrip() {
        let kinds = [
            SecretKind::Password,
            SecretKind::ApiKey,
            SecretKind::AccessToken,
            SecretKind::EnvVar,
            SecretKind::SshKey,
            SecretKind::Certificate,
            SecretKind::Codes,
        ];

        for kind in kinds {
            let encoded = postcard::to_stdvec(&kind).unwrap();
            let decoded: SecretKind = postcard::from_bytes(&encoded).unwrap();
            assert_eq!(decoded, kind);

            let parsed: SecretKind = kind.as_str().parse().unwrap();
            assert_eq!(parsed, kind);
        }

        assert!("unknown_kind".parse::<SecretKind>().is_err());
    }

    #[test]
    fn test_body_structs_roundtrip() {
        // LabelBody
        let label = LabelBody::new("Work", 1, Some("briefcase".to_string()));
        let enc = postcard::to_stdvec(&label).unwrap();
        let dec: LabelBody = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, label);

        // ItemBody
        let item_id = Uuid::new_v4();
        let item = ItemBody::new(
            item_id,
            "Backend API",
            Some("Main API server".to_string()),
            0,
        );
        let enc = postcard::to_stdvec(&item).unwrap();
        let dec: ItemBody = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, item);

        // EnvironmentBody
        let env = EnvironmentBody::new(item_id, "Production", 2);
        let enc = postcard::to_stdvec(&env).unwrap();
        let dec: EnvironmentBody = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, env);
        assert_eq!(dec.project_id(), item_id);
        assert_eq!(dec.project_id, item_id);

        // SecretBody
        let env_id = Uuid::new_v4();
        let secret = SecretBody::new(
            item_id,
            Some(env_id),
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://localhost:5432/db",
            Some("Main db conn".to_string()),
        );
        let enc = postcard::to_stdvec(&secret).unwrap();
        let dec: SecretBody = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, secret);
        assert_eq!(dec.project_id(), item_id);
        assert_eq!(dec.project_id, item_id);

        // SecretBody at item level (environment_id = None)
        let item_secret = SecretBody::new(
            item_id,
            None,
            "SHARED_TOKEN",
            SecretKind::ApiKey,
            "token123",
            None,
        );
        let enc = postcard::to_stdvec(&item_secret).unwrap();
        let dec: SecretBody = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, item_secret);
        assert_eq!(dec.environment_id, None);

        // FileMetaBody & FilePayload
        let meta = FileMetaBody::new(
            item_id,
            Some(env_id),
            "cert.pem",
            1024,
            "application/x-pem-file",
            [42u8; 32],
        );
        let payload = FilePayload::new(meta, vec![1, 2, 3, 4, 5]);
        let enc = postcard::to_stdvec(&payload).unwrap();
        let dec: FilePayload = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, payload);

        // NoteBody
        let note = NoteBody::new(
            item_id,
            None,
            "Deployment Runbook",
            "<h1>Runbook</h1><p>Steps to deploy.</p>",
            0,
        );
        let enc = postcard::to_stdvec(&note).unwrap();
        let dec: NoteBody = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, note);

        // ProjectBody
        let proj = ProjectBody::new("secwet-backend");
        let enc = postcard::to_stdvec(&proj).unwrap();
        let dec: ProjectBody = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, proj);
    }

    #[test]
    fn test_secret_body_roundtrip_and_redaction() {
        let project_id = Uuid::new_v4();
        let env_id = Uuid::new_v4();
        let sensitive =
            "-----BEGIN OPENSSH PRIVATE KEY-----\ntest-key\n-----END OPENSSH PRIVATE KEY-----";
        let body = SecretBody::new(
            project_id,
            Some(env_id),
            "ID_RSA",
            SecretKind::SshKey,
            sensitive,
            Some("Deploy key".to_string()),
        );

        // Verify postcard roundtrip
        let encoded = postcard::to_stdvec(&body).unwrap();
        let decoded: SecretBody = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, body);
        assert_eq!(decoded.value, sensitive);

        // Critical Security Check: Debug output must redact value
        let debug_str = format!("{:?}", body);
        assert!(
            debug_str.contains("[redacted]"),
            "Debug output must contain [redacted]"
        );
        assert!(
            !debug_str.contains("OPENSSH PRIVATE KEY"),
            "Debug output must NEVER leak secret values"
        );
    }

    #[test]
    fn test_record_payload_roundtrip() {
        let label_body = LabelBody::new("Work", 0, None);
        let payload = RecordPayload::Label(label_body);
        let bytes = payload.to_bytes().unwrap();
        let decoded = RecordPayload::from_bytes(RecordType::Label, &bytes).unwrap();
        assert_eq!(decoded, payload);

        let note_body = NoteBody::new(Uuid::new_v4(), None, "Title", "Content", 0);
        let payload = RecordPayload::Note(note_body);
        let bytes = payload.to_bytes().unwrap();
        let decoded = RecordPayload::from_bytes(RecordType::Note, &bytes).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_record_aad_canonical() {
        let secwet_id = [7u8; 16];
        let record_id = [9u8; 16];
        let aad = RecordAad::new(&secwet_id, &record_id, RecordType::Secret, 1);
        let bytes1 = aad.to_bytes().unwrap();
        let bytes2 = aad.to_bytes().unwrap();
        assert_eq!(
            bytes1, bytes2,
            "Postcard serialization must be deterministic"
        );

        let owned = RecordAadOwned::new(secwet_id, record_id, RecordType::Secret, 1);
        let bytes_owned = owned.as_borrowed().to_bytes().unwrap();
        assert_eq!(bytes1, bytes_owned);

        let raw_aad = RecordAad::from_raw_type(&secwet_id, &record_id, 4, 1);
        assert_eq!(bytes1, raw_aad.to_bytes().unwrap());
    }

    #[test]
    fn test_record_envelope_framing() {
        let nonce = [42u8; 24];
        let ciphertext = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let envelope = RecordEnvelope {
            version: RecordEnvelope::VERSION_V1,
            nonce,
            ciphertext,
        };

        let blob = envelope.to_blob();
        assert_eq!(blob.len(), 1 + 24 + 16);

        let parsed = RecordEnvelope::from_blob(&blob).unwrap();
        assert_eq!(parsed, envelope);

        // Edge case: too short blob
        let short_blob = vec![1u8; 40];
        assert!(matches!(
            RecordEnvelope::from_blob(&short_blob),
            Err(EnvelopeError::BlobTooShort(40))
        ));

        // Edge case: unsupported version
        let mut bad_ver_blob = blob.clone();
        bad_ver_blob[0] = 2;
        assert!(matches!(
            RecordEnvelope::from_blob(&bad_ver_blob),
            Err(EnvelopeError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn test_value_tail_computation() {
        assert_eq!(SecretMeta::compute_value_tail("secret1234"), "1234");
        assert_eq!(SecretMeta::compute_value_tail("  a b c d  "), "abcd");
        assert_eq!(SecretMeta::compute_value_tail("xyz"), "xyz");
        assert_eq!(SecretMeta::compute_value_tail(""), "");
    }

    #[test]
    fn test_extract_plain_text_and_snippets() {
        let html = "<h1>Heading</h1><p>First paragraph with <strong>bold</strong> &amp; &lt;special&gt; text.</p><ul><li>First item</li><li>Second item</li></ul>";
        let plain = extract_plain_text(html);
        assert!(plain.contains("Heading"));
        assert!(plain.contains("First paragraph with bold & <special> text."));
        assert!(plain.contains("• First item"));
        assert!(plain.contains("• Second item"));

        let snippet = snippet_from_content(html, 20);
        assert!(snippet.ends_with("..."));
        assert!(snippet.len() <= 23);
    }

    #[test]
    fn test_validation_flexible_org() {
        // Label name
        assert_eq!(validate_label_name("  Work  ").unwrap(), "Work");
        assert!(validate_label_name("   ").is_err());
        assert!(validate_label_name(&"a".repeat(65)).is_err());

        // Item name
        assert_eq!(
            validate_item_name("  Backend API  ").unwrap(),
            "Backend API"
        );
        assert!(validate_item_name("   ").is_err());
        assert!(validate_item_name(&"b".repeat(65)).is_err());

        // Item description
        assert!(validate_item_description(None).is_ok());
        assert!(validate_item_description(Some(&"x".repeat(500))).is_ok());
        assert!(validate_item_description(Some(&"x".repeat(501))).is_err());

        // File name & size
        assert_eq!(validate_file_name("config.json").unwrap(), "config.json");
        assert!(validate_file_name("  ").is_err());
        assert!(validate_file_name(&"f".repeat(256)).is_err());

        assert!(validate_file_size(50 * 1024 * 1024).is_ok());
        assert!(validate_file_size(50 * 1024 * 1024 + 1).is_err());

        // Note title
        assert_eq!(validate_note_title("My Notes").unwrap(), "My Notes");
        assert!(validate_note_title("  ").is_err());
        assert!(validate_note_title(&"t".repeat(129)).is_err());

        // Note content validation
        assert!(validate_note_content("").is_ok());
        assert!(validate_note_content("<p>Hello <strong>world</strong></p>").is_ok());
        assert!(validate_note_content(&"c".repeat(1_000_000)).is_ok());
        assert!(validate_note_content(&"c".repeat(1_000_001)).is_err());
        assert_eq!(
            validate_note_content(&"c".repeat(1_000_001)),
            Err(ValidationError::TooLong {
                field: "note_content",
                max: 1_000_000,
                actual: 1_000_001,
            })
        );

        // Combined validate_note
        assert_eq!(
            validate_note("  Meeting Notes  ", "<p>Plan</p>").unwrap(),
            "Meeting Notes"
        );
        assert!(validate_note("", "valid content").is_err());
        assert!(validate_note("Valid Title", &"x".repeat(1_000_001)).is_err());

        // NoteBody try_new and validate
        let item_id = Uuid::new_v4();
        let valid_note = NoteBody::try_new(item_id, None, " Title ", "Content", 0).unwrap();
        assert_eq!(valid_note.title, "Title");
        assert_eq!(valid_note.content, "Content");
        assert!(valid_note.validate().is_ok());

        assert!(NoteBody::try_new(item_id, None, "", "Content", 0).is_err());
        assert!(NoteBody::try_new(item_id, None, "Title", "x".repeat(1_000_001), 0).is_err());
    }

    #[test]
    fn test_note_content_validation_comprehensive() {
        // 1. Boundary: 0 chars (empty)
        assert!(validate_note_content("").is_ok());

        // 2. Whitespace and rich formatting
        assert!(validate_note_content("   \n\t\r\n   ").is_ok());
        assert!(validate_note_content("<h1>Heading</h1><p>Text &amp; more</p>").is_ok());

        // 3. Embedded null bytes and control chars
        assert!(validate_note_content("null\0byte\0included").is_ok());

        // 4. Multibyte UTF-8 within limit
        let emoji_note = "🦀".repeat(500_000); // 500,000 chars, 2,000,000 bytes
        assert_eq!(emoji_note.chars().count(), 500_000);
        assert_eq!(emoji_note.len(), 2_000_000);
        assert!(validate_note_content(&emoji_note).is_ok());

        // 5. Exactly 1,000,000 characters (ASCII)
        let max_ascii = "a".repeat(1_000_000);
        assert!(validate_note_content(&max_ascii).is_ok());

        // 6. Exactly 1,000,000 characters (4-byte Unicode = 4,000,000 bytes)
        let max_unicode = "🚀".repeat(1_000_000);
        assert!(validate_note_content(&max_unicode).is_ok());

        // 7. Exactly 1,000,001 characters (ASCII) -> TooLong
        let overflow_ascii = "a".repeat(1_000_001);
        match validate_note_content(&overflow_ascii) {
            Err(ValidationError::TooLong { field, max, actual }) => {
                assert_eq!(field, "note_content");
                assert_eq!(max, 1_000_000);
                assert_eq!(actual, 1_000_001);
            }
            other => panic!("Expected ValidationError::TooLong, got {:?}", other),
        }

        // 8. Exactly 1,000,001 characters (Unicode) -> TooLong
        let overflow_unicode = "🚀".repeat(1_000_001);
        match validate_note_content(&overflow_unicode) {
            Err(ValidationError::TooLong { field, max, actual }) => {
                assert_eq!(field, "note_content");
                assert_eq!(max, 1_000_000);
                assert_eq!(actual, 1_000_001);
            }
            other => panic!("Expected ValidationError::TooLong, got {:?}", other),
        }

        // 9. Error display formatting
        let err = validate_note_content(&overflow_ascii).unwrap_err();
        assert_eq!(
            format!("{}", err),
            "field note_content exceeded max length 1000000 (was 1000001)"
        );
    }

    #[test]
    fn test_validation_rules() {
        // Project name validation
        assert_eq!(validate_project_name("  core-api  ").unwrap(), "core-api");
        assert!(validate_project_name("   ").is_err());
        let long_name = "a".repeat(65);
        assert!(validate_project_name(&long_name).is_err());

        // Secret name regex validation
        assert!(validate_secret_name("VALID_NAME_123").is_ok());
        assert!(validate_secret_name("_underscore").is_ok());
        assert!(validate_secret_name("config.database-url@dev").is_ok());
        assert!(validate_secret_name("123starts_with_number").is_err());
        assert!(validate_secret_name("has spaces").is_err());
        assert!(validate_secret_name("has$invalid#chars").is_err());

        // Secret value length
        let max_val = "x".repeat(65_536);
        assert!(validate_secret_value(&max_val).is_ok());
        let too_large_val = "x".repeat(65_537);
        assert!(validate_secret_value(&too_large_val).is_err());

        // Note length
        let max_note = "n".repeat(500);
        assert!(validate_secret_note(Some(&max_note)).is_ok());
        let too_long_note = "n".repeat(501);
        assert!(validate_secret_note(Some(&too_long_note)).is_err());
    }

    #[test]
    fn test_view_dtos_roundtrip() {
        let label_view = LabelView::new(Uuid::new_v4(), "Personal", 0, None, 5);
        let enc = postcard::to_stdvec(&label_view).unwrap();
        let dec: LabelView = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, label_view);

        let item_view = ItemView::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "Item 1",
            None,
            0,
            1,
            2,
            3,
            4,
        );
        let enc = postcard::to_stdvec(&item_view).unwrap();
        let dec: ItemView = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, item_view);

        let env_view = EnvironmentView::new(Uuid::new_v4(), Uuid::new_v4(), "Staging", 1, 10);
        let enc = postcard::to_stdvec(&env_view).unwrap();
        let dec: EnvironmentView = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, env_view);

        let config = DashboardConfig::default();
        let enc = postcard::to_stdvec(&config).unwrap();
        let dec: DashboardConfig = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, config);
    }

    #[test]
    fn test_snapshot_and_recovery_models_roundtrip() {
        let secwet_id = Uuid::new_v4();
        let space_id = Uuid::new_v4();
        let label_id = Uuid::new_v4();
        let item_id = Uuid::new_v4();
        let env_id = Uuid::new_v4();
        let secret_id = Uuid::new_v4();
        let note_id = Uuid::new_v4();
        let file_id = Uuid::new_v4();

        let space = SnapshotSpace {
            id: space_id,
            name: "Personal".to_string(),
            position: 0,
            icon: Some("user".to_string()),
            is_default: true,
            created_at: 1000,
            updated_at: 1000,
            deleted: false,
        };

        let label = SnapshotLabel {
            id: label_id,
            space_id: Some(space_id),
            name: "Work".to_string(),
            position: 0,
            icon: Some("folder".to_string()),
            created_at: 1001,
            updated_at: 1001,
            deleted: false,
        };

        let item = SnapshotItem {
            id: item_id,
            label_id,
            name: "API Service".to_string(),
            description: Some("Core API".to_string()),
            position: 0,
            lamport: 1,
            origin_device: "dev-1".to_string(),
            updated_at: 1002,
            deleted: false,
        };

        let env = SnapshotEnvironment {
            id: env_id,
            item_id,
            name: "Production".to_string(),
            position: 0,
            lamport: 2,
            origin_device: "dev-1".to_string(),
            updated_at: 1003,
            deleted: false,
        };

        let secret = SnapshotSecret {
            id: secret_id,
            item_id,
            environment_id: Some(env_id),
            name: "DATABASE_URL".to_string(),
            kind: SecretKind::EnvVar,
            value: "postgres://localhost/prod".to_string(),
            note: Some("Production DB".to_string()),
            lamport: 3,
            origin_device: "dev-1".to_string(),
            updated_at: 1004,
            deleted: false,
        };

        let note = SnapshotNote {
            id: note_id,
            item_id,
            environment_id: Some(env_id),
            title: "Runbook".to_string(),
            content: "Deployment checklist".to_string(),
            position: 0,
            lamport: 4,
            origin_device: "dev-1".to_string(),
            updated_at: 1005,
            deleted: false,
        };

        let file = SnapshotFile {
            id: file_id,
            item_id,
            environment_id: Some(env_id),
            name: "ca.crt".to_string(),
            size_bytes: 4,
            mime_type: "application/x-x509-ca-cert".to_string(),
            sha256: [1u8; 32],
            data: vec![0xCA, 0xFE, 0xBA, 0xBE],
            lamport: 5,
            origin_device: "dev-1".to_string(),
            updated_at: 1006,
            deleted: false,
        };

        let setting = SnapshotSetting {
            key: "theme".to_string(),
            value: "dark".to_string(),
        };

        let snapshot = SecwetSnapshot {
            secwet_id,
            created_at: 1000,
            key_epoch: 1,
            plan: "pro".to_string(),
            relay_url: "https://relay.secwet.test".to_string(),
            spaces: vec![space],
            labels: vec![label],
            items: vec![item],
            environments: vec![env],
            secrets: vec![secret],
            notes: vec![note],
            files: vec![file],
            settings: vec![setting],
        };

        let enc_snapshot = postcard::to_stdvec(&snapshot).unwrap();
        let dec_snapshot: SecwetSnapshot = postcard::from_bytes(&enc_snapshot).unwrap();
        assert_eq!(dec_snapshot, snapshot);
        assert_eq!(dec_snapshot.projects().len(), 1);

        let aad = ExportAad::new(secwet_id);
        let enc_aad = aad.to_bytes().unwrap();
        let dec_aad: ExportAad = postcard::from_bytes(&enc_aad).unwrap();
        assert_eq!(dec_aad, aad);

        let envelope = SecwetExportEnvelope {
            format: "secwet-export".to_string(),
            version: 1,
            secwet_id,
            created_at: 1000,
            kdf: "hkdf-sha256".to_string(),
            cipher: "xchacha20poly1305".to_string(),
            nonce: "AQID".to_string(),
            ciphertext: "BAUG".to_string(),
        };
        let enc_env = postcard::to_stdvec(&envelope).unwrap();
        let dec_env: SecwetExportEnvelope = postcard::from_bytes(&enc_env).unwrap();
        assert_eq!(dec_env, envelope);

        let summary = ExportSummary::new(secwet_id, 1000, 1, 1, 1, 1, 1, 1, 1, 2048);
        assert_eq!(summary.projects_count, 1);
        assert_eq!(summary.assets_count, 1);
        assert_eq!(summary.bytes_written, 2048);

        let status = RecoveryStatus::new(true, Some(1000));
        assert!(status.created);
        assert_eq!(status.created_at, Some(1000));

        let push_req = PushEventsRequest {
            events: vec![SignedEvent {
                envelope: EventEnvelope {
                    event_id: [1u8; 16],
                    secwet_id: [2u8; 16],
                    device_id: "dev-1".to_string(),
                    device_seq: 1,
                    key_epoch: 1,
                    nonce: [3u8; 24],
                    ciphertext: vec![4, 5, 6],
                    scope: None,
                },
                signature: [7u8; 64],
            }],
        };
        let enc_push = postcard::to_stdvec(&push_req).unwrap();
        let dec_push: PushEventsRequest = postcard::from_bytes(&enc_push).unwrap();
        assert_eq!(dec_push, push_req);

        let pull_resp = PullEventsResponse {
            events: vec![StoredEventDto {
                server_seq: 42,
                event: push_req.events[0].clone(),
                received_at: 1234567,
            }],
            has_more: false,
            head_seq: 42,
        };
        let enc_pull = postcard::to_stdvec(&pull_resp).unwrap();
        let dec_pull: PullEventsResponse = postcard::from_bytes(&enc_pull).unwrap();
        assert_eq!(dec_pull, pull_resp);

        let snap_req = SnapshotUploadRequest {
            server_seq: 100,
            key_epoch: 2,
            nonce: [9u8; 24],
            ciphertext: vec![10, 11, 12],
        };
        let enc_snap = postcard::to_stdvec(&snap_req).unwrap();
        let dec_snap: SnapshotUploadRequest = postcard::from_bytes(&enc_snap).unwrap();
        assert_eq!(dec_snap, snap_req);
    }
}
