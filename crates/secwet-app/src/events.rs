//! UI change notifications.
//!
//! The app layer tells the host what changed; the host forwards it to its UI
//! (the desktop emits Tauri events, mobile hosts post to their own channel).

use std::sync::Arc;

/// A notification for the UI. Event names and payloads match `docs/IMPLEMENTATION.md` §9.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppEvent {
    /// Data in `scope` changed (`spaces`, `labels`, `items`, `secrets`, `all`, ...).
    Changed { scope: &'static str },
    /// The store was locked and its keys dropped.
    Locked,
    /// A verified remote wipe erased this device.
    Wiped,
    /// This device was unlinked from the Secwet; sync is disabled.
    Unlinked,
}

impl AppEvent {
    pub const fn changed(scope: &'static str) -> Self {
        Self::Changed { scope }
    }

    /// Event name as the UI listens for it.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Changed { .. } => "secwet://changed",
            Self::Locked => "secwet://locked",
            Self::Wiped => "secwet://wiped",
            Self::Unlinked => "secwet://unlinked",
        }
    }

    /// JSON payload as the UI receives it.
    pub fn payload(&self) -> serde_json::Value {
        match self {
            Self::Changed { scope } => serde_json::json!({ "scope": scope }),
            Self::Locked => serde_json::Value::Null,
            Self::Wiped | Self::Unlinked => serde_json::json!({}),
        }
    }
}

/// Host-side receiver for [`AppEvent`]s. Must not block: it is called while
/// app-layer commands run.
pub trait EventSink: Send + Sync + 'static {
    fn emit(&self, event: AppEvent);
}

/// Sink that drops every event; the default until the host installs its own.
pub struct NoEvents;

impl EventSink for NoEvents {
    fn emit(&self, _event: AppEvent) {}
}

impl<F: Fn(AppEvent) + Send + Sync + 'static> EventSink for F {
    fn emit(&self, event: AppEvent) {
        self(event)
    }
}

pub(crate) fn no_events() -> Arc<dyn EventSink> {
    Arc::new(NoEvents)
}
