//! Secwet application layer, shared by the desktop (Tauri) and mobile hosts.
//!
//! Hosts keep one [`AppState`] and call its command methods; each returns
//! `Result<T, UiError>` with serde-ready DTOs. Platform services come in
//! through small traits: [`KeyStore`] (secure key storage), [`ClipboardPort`]
//! (native clipboard) and [`EventSink`] (UI change notifications).

pub mod biometric;
pub mod clipboard;
pub mod collab;
pub mod commands;
pub mod error;
pub mod events;
pub mod pairing_join;
pub mod plan;
pub mod runtime;
pub mod state;

pub use biometric::{BiometricStatusDto, BiometryKind, PresenceError, PresenceVerifier};
pub use clipboard::{AutoClearManager, ClipboardPort};
pub use error::UiError;
pub use events::{AppEvent, EventSink, NoEvents};
pub use plan::PlanStatusDto;
pub use secwet_core::keys::KeyStore;
pub use state::{AppState, SecwetStatusDto};
