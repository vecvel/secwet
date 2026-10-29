//! Structured error taxonomy shared by every host.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §9.1 and §10.
//! Every app-layer call returns `Result<T, UiError>`; hosts serialize it as is
//! (the desktop webview receives it as the rejected Promise value).

use serde::{Deserialize, Serialize};

/// Structured error returned to the UI by every app-layer call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiError {
    pub code: String,
    pub field: Option<String>,
    pub message: String,
}

impl UiError {
    pub fn new(code: impl Into<String>, field: Option<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            field,
            message: message.into(),
        }
    }

    pub fn locked() -> Self {
        Self::new("locked", None, "Secwet is locked.")
    }

    pub fn already_initialized() -> Self {
        Self::new(
            "already_initialized",
            None,
            "A Secwet already exists on this device.",
        )
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::new("internal", None, msg)
    }

    pub fn invalid(field: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new("invalid", Some(field.into()), message)
    }
}

impl std::fmt::Display for UiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref field) = self.field {
            write!(f, "{}[{}]: {}", self.code, field, self.message)
        } else {
            write!(f, "{}: {}", self.code, self.message)
        }
    }
}

impl std::error::Error for UiError {}

impl From<secwet_core::Error> for UiError {
    fn from(err: secwet_core::Error) -> Self {
        match err {
            secwet_core::Error::Locked => UiError::locked(),
            secwet_core::Error::NotInitialized => {
                UiError::new("not_initialized", None, "Secwet not initialized on this device.")
            }
            secwet_core::Error::AlreadyInitialized => UiError::already_initialized(),
            secwet_core::Error::NotFound => UiError::new("not_found", None, "Item not found."),
            secwet_core::Error::Invalid { field, message } => {
                UiError::new("invalid", Some(field.to_string()), message)
            }
            secwet_core::Error::Duplicate { field } => UiError::new(
                "duplicate",
                Some(field.to_string()),
                format!("A {field} with this name already exists."),
            ),
            secwet_core::Error::LastEnvironment => UiError::new(
                "last_environment",
                None,
                "Cannot delete the last environment.",
            ),
            secwet_core::Error::NeedsPro => {
                UiError::new("needs_pro", None, "This feature requires the Pro plan.")
            }
            secwet_core::Error::SyncPaused => UiError::new(
                "sync_paused",
                None,
                "Sync is paused because Pro ended. Everything on this device stays available.",
            ),
            secwet_core::Error::DeviceLimit => {
                UiError::new("device_limit", None, "Device limit reached.")
            }
            secwet_core::Error::Revoked | secwet_core::Error::RevocationNotice(_) => {
                UiError::new("revoked", None, "This device was revoked.")
            }
            secwet_core::Error::Forbidden => {
                UiError::new("forbidden", None, "You don't have permission to do this.")
            }
            secwet_core::Error::RecoveryFailed => UiError::new(
                "recovery_failed",
                None,
                "Wrong recovery key or damaged file.",
            ),
            secwet_core::Error::Offline => UiError::new("offline", None, "Sync is offline."),
            secwet_core::Error::Relay { code } if code == "not_entitled" => {
                UiError::new("needs_pro", None, "This needs an active Pro plan.")
            }
            secwet_core::Error::Relay { code } => {
                UiError::new(format!("relay_{code}"), None, "Relay server error.")
            }
            secwet_core::Error::KeyStore => {
                UiError::new("keystore_error", None, "Secure storage error.")
            }
            secwet_core::Error::Storage => UiError::new("storage_error", None, "Storage error."),
            secwet_core::Error::Crypto => {
                // §10: "Crypto failures say only 'This item could not be decrypted.' and are logged as a code with the record id, never with data."
                UiError::new("crypto_error", None, "This item could not be decrypted.")
            }
            secwet_core::Error::Unimplemented(msg) => UiError::new(
                "unimplemented",
                None,
                format!("{msg} is not implemented yet."),
            ),
        }
    }
}
