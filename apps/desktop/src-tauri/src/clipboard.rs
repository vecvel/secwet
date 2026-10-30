//! Native clipboard for the desktop host.
//!
//! The copy and 30-second auto-clear logic lives in `secwet_app::clipboard`;
//! this module only provides the Tauri-backed `ClipboardPort`.
//!
//! Security Invariants:
//! 1. The webview never receives the plaintext secret value for a copy operation.
//! 2. `write_secret` sets OS-level hints (ConcealedType/CLIPBOARD_HIST_DONT_RECORD)
//!    to prevent third-party clipboard managers from indexing the secret.

use tauri::AppHandle;
use tauri_plugin_clipboard_manager::ClipboardExt;

pub use secwet_app::clipboard::{extract_plain_text, AutoClearManager, ClipboardPort};

/// Production clipboard backend wrapping Tauri 2's clipboard manager plugin.
pub struct TauriClipboard {
    app: AppHandle,
}

impl TauriClipboard {
    pub fn new(app: AppHandle) -> Self {
        Self { app }
    }
}

impl ClipboardPort for TauriClipboard {
    fn write_secret(&self, text: &str) -> Result<(), String> {
        self.app
            .clipboard()
            .write_secret(text)
            .map_err(|e| e.to_string())
    }

    fn read_text(&self) -> Result<String, String> {
        self.app.clipboard().read_text().map_err(|e| e.to_string())
    }

    fn clear(&self) -> Result<(), String> {
        self.app.clipboard().clear().map_err(|e| e.to_string())
    }
}
