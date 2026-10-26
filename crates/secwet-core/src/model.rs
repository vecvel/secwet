use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub use secwet_proto::{
    AssetMetaView, DashboardConfig, EnvironmentView, FileMetaView, ItemView, LabelView,
    NoteMetaView, NoteView, ProjectView, SecretKind, SecretMeta, VaultStatus,
};

/// Device ID wrapper.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DeviceId(pub String);

impl std::fmt::Display for DeviceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for DeviceId {
    fn from(s: String) -> Self {
        DeviceId(s)
    }
}

impl From<&str> for DeviceId {
    fn from(s: &str) -> Self {
        DeviceId(s.to_string())
    }
}

/// A draft representing user input to create or update a secret.
///
/// Invariant: Supports both item-level secrets (`environment_id: None`) and
/// environment-scoped secrets (`environment_id: Some(env_id)`).
/// Sensitive value is wrapped in `secrecy::SecretString` and redacted in Debug output.
#[derive(Clone)]
pub struct SecretDraft {
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub kind: SecretKind,
    pub value: SecretString,
    pub note: Option<String>,
}

impl SecretDraft {
    /// Constructs a new SecretDraft supporting item-level (`None`) or environment-scoped (`Some`).
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
            value: SecretString::from(value.into()),
            note,
        }
    }

    /// Backwards compatibility accessor for project_id.
    #[inline]
    pub fn project_id(&self) -> Uuid {
        self.item_id
    }
}

impl std::ops::Deref for SecretDraft {
    type Target = secwet_proto::ProjectIdCompat;

    #[inline]
    fn deref(&self) -> &Self::Target {
        // Safety: ProjectIdCompat is repr(transparent) around Uuid with identical layout to item_id.
        unsafe { &*(&self.item_id as *const Uuid as *const secwet_proto::ProjectIdCompat) }
    }
}

impl std::fmt::Debug for SecretDraft {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretDraft")
            .field("item_id", &self.item_id)
            .field("environment_id", &self.environment_id)
            .field("name", &self.name)
            .field("kind", &self.kind)
            .field("value", &"[REDACTED]")
            .field("note", &self.note)
            .finish()
    }
}

/// Type alias for secret patch operations.
pub type SecretPatch = SecretDraft;

/// Recent secret metadata item for overview screen (strictly excludes secret values).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentSecret {
    pub id: Uuid,
    pub name: String,
    pub project_id: Uuid,
    pub project_name: String,
    pub environment_id: Uuid,
    pub environment_name: String,
    pub updated_at: i64,
}

/// Overview setup and safety checklist state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecklistState {
    pub vault_created: bool,
    pub recovery_key_created: bool,
    pub cli_connected: bool,
    pub add_device_done: bool,
    pub pending_rotation: Option<String>,
}

/// Aggregated dashboard statistics and overview data across all content types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Overview {
    pub labels_count: usize,
    pub items_count: usize,
    pub projects_count: usize, // Backwards-compatible alias equal to items_count
    pub environments_count: usize,
    pub secrets_count: usize,
    pub assets_count: usize,
    pub files_count: usize, // Backwards-compatible alias equal to assets_count
    pub notes_count: usize,
    pub active_devices_count: usize,
    pub projects: Vec<ProjectView>,
    pub recent: Vec<RecentSecret>,
    pub checklist: ChecklistState,
}

/// Backwards-compatible type alias for Overview.
pub type OverviewData = Overview;

// ============================================================================
// Legacy Models (Backwards compatibility)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub environments: Vec<Environment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Environment {
    pub id: String,
    pub name: String,
}

/// A secret as seen by the UI after decryption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub id: String,
    pub project_id: String,
    pub environment_id: String,
    pub name: String,
    pub kind: SecretKind,
    pub value: String,
    pub note: Option<String>,
    pub updated_at: i64,
}
