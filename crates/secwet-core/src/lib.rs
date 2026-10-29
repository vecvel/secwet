//! Secwet shared security core.
//!
//! Every client (desktop, mobile via FFI, CLI) goes through this crate for
//! storage and security operations, so encryption and sync rules live in one place.

pub mod collab;
pub mod crypto;
pub mod keys;
pub mod model;
pub mod pairing_join;
pub mod plan;
pub mod records;
pub mod relay_client;
pub mod secwet;
pub mod sessions;
pub mod sync;

pub use plan::{PlanInfo, PlanState, RelayOp};
pub use relay_client::RelayClient;

pub use crypto::CryptoError;
#[cfg(any(test, feature = "test-util"))]
pub use keys::MemoryStore;
#[cfg(feature = "os-keyring")]
pub use keys::KeyringStore;
pub use keys::{KeyStore, SecretVec};
pub use model::{
    ActiveSession, ChecklistState, DashboardConfig, DeviceId, Environment, EnvironmentView,
    ExportAad, ExportSummary, FileMetaView, ItemView, LabelView, NoteMetaView, NoteView, Overview,
    OverviewData, Project, ProjectView, RecentSecret, RecoveryStatus, Secret, SecretDraft,
    SecretKind, SecretMeta, SecretPatch, SecwetExportEnvelope, SecwetSnapshot, SecwetStatus,
    SnapshotEnvironment, SnapshotFile, SnapshotItem, SnapshotLabel, SnapshotNote, SnapshotSecret,
    SnapshotSetting, SnapshotSpace, SpaceView,
};
pub use records::{
    cascade_delete_environment, cascade_delete_item, cascade_delete_label, cascade_delete_project,
    configure_connection, count_active_items_for_label, count_active_labels_for_space,
    count_active_records_by_parent_and_type, count_item_content_recursive,
    delete_environment_records, get_highest_lamport, get_label, get_meta, get_record, get_space,
    insert_label, insert_record, insert_space, next_label_position, next_lamport,
    next_space_position, open_and_migrate, open_connection, open_in_memory, query_active_labels,
    query_active_labels_by_space, query_active_records_by_parent_and_type,
    query_active_records_by_type, query_active_spaces, query_all_item_content_records,
    query_content_records, query_environments_by_item, query_items_by_label,
    query_records_by_parent, reassign_labels_to_space, reorder_labels, reorder_spaces,
    run_migrations, set_meta, soft_delete_label, soft_delete_record, soft_delete_space,
    update_label_name, update_label_space, update_null_labels_space, update_record_blob,
    update_space_name, CascadeDeleteItemSummary, CascadeDeleteLabelSummary, CascadeDeleteSummary,
    LabelRow, RecordRow, SpaceRow,
};
pub use secwet::Secwet;

/// Unified error taxonomy for Secwet.
///
/// Error messages never expose decrypted values, record names, or specific
/// cryptographic check failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("secwet is locked")]
    Locked,
    #[error("not initialized on this device")]
    NotInitialized,
    #[error("already initialized in this directory")]
    AlreadyInitialized,
    #[error("not found")]
    NotFound,
    #[error("{field}: {message}")]
    Invalid {
        field: &'static str,
        message: String,
    },
    #[error("name already used")]
    Duplicate { field: &'static str },
    #[error("cannot delete the last environment")]
    LastEnvironment,
    #[error("needs the Pro plan")]
    NeedsPro,
    /// Pro ended: sync is paused until the plan is renewed. Local data stays usable.
    #[error("sync is paused because Pro ended")]
    SyncPaused,
    #[error("device limit reached")]
    DeviceLimit,
    #[error("this device was revoked")]
    Revoked,
    /// The relay reported this device as revoked and attached the signed
    /// directive; `Secwet::handle_revocation_notice` verifies and executes it.
    #[error("this device was revoked")]
    RevocationNotice(Box<secwet_proto::SignedRevocation>),
    /// The local role does not allow this change (F19).
    #[error("you don't have permission to do this")]
    Forbidden,
    #[error("wrong recovery key or damaged file")]
    RecoveryFailed,
    #[error("sync is offline")]
    Offline,
    #[error("relay error: {code}")]
    Relay { code: String },
    #[error("secure storage error")]
    KeyStore,
    #[error("storage error")]
    Storage,
    #[error("crypto error")]
    Crypto,
    #[error("not implemented yet: {0}")]
    Unimplemented(&'static str),
}

impl From<crypto::CryptoError> for Error {
    fn from(_: crypto::CryptoError) -> Self {
        Error::Crypto
    }
}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Error::Storage
    }
}

pub type Result<T> = std::result::Result<T, Error>;
