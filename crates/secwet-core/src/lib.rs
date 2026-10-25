//! Secwet shared security core.
//!
//! Every client (desktop, mobile via FFI, CLI) goes through this crate for
//! vault operations, so encryption and sync rules live in one place.

pub mod crypto;
pub mod keys;
pub mod model;
pub mod records;
pub mod sync;
pub mod vault;

pub use crypto::CryptoError;
#[cfg(any(test, feature = "test-util"))]
pub use keys::MemoryStore;
pub use keys::{KeyStore, KeyringStore, SecretVec};
pub use model::{
    ChecklistState, DashboardConfig, DeviceId, Environment, EnvironmentView, FileMetaView,
    ItemView, LabelView, NoteMetaView, NoteView, Overview, OverviewData, Project, ProjectView,
    RecentSecret, Secret, SecretDraft, SecretKind, SecretMeta, SecretPatch, VaultStatus,
};
pub use records::{
    cascade_delete_environment, cascade_delete_item, cascade_delete_label, cascade_delete_project,
    configure_connection, count_active_items_for_label, count_active_records_by_parent_and_type,
    count_item_content_recursive, delete_environment_records, get_highest_lamport, get_label,
    get_meta, get_record, insert_label, insert_record, next_label_position, next_lamport,
    open_and_migrate, open_connection, open_in_memory, query_active_labels,
    query_active_records_by_parent_and_type, query_active_records_by_type,
    query_all_item_content_records, query_content_records, query_environments_by_item,
    query_items_by_label, query_records_by_parent, reorder_labels, run_migrations, set_meta,
    soft_delete_label, soft_delete_record, update_label_name, update_record_blob,
    CascadeDeleteItemSummary, CascadeDeleteLabelSummary, CascadeDeleteSummary, LabelRow, RecordRow,
};
pub use vault::Vault;

/// Unified error taxonomy for Secwet.
///
/// Error messages never expose decrypted values, record names, or specific
/// cryptographic check failures.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("vault is locked")]
    Locked,
    #[error("no vault on this device")]
    NoVault,
    #[error("vault already initialized in this directory")]
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
    #[error("device limit reached")]
    DeviceLimit,
    #[error("this device was revoked")]
    Revoked,
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
