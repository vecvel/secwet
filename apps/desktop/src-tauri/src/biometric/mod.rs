//! Native biometric checks for the desktop: Touch ID on macOS, Windows Hello
//! on Windows and fprintd on Linux. [`NativeVerifier`] plugs them into the
//! app layer, which owns the policy and enforces it at unlock (see
//! `secwet_app::biometric`). On other systems the kind is always `None`, so
//! the UI hides biometric unlock and the default unlock is used.

// Unit-tested on every Unix; only used on Linux.
#[cfg(all(unix, any(target_os = "linux", test)))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod dbus;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use std::sync::atomic::{AtomicIsize, Ordering};

pub use secwet_app::biometric::{BiometricStatusDto, BiometryKind, PresenceError, PresenceVerifier};
use tauri::{AppHandle, Manager};

use crate::error::UiError;
use crate::state::AppState;

/// The platform's presence check.
#[derive(Debug, Default)]
pub struct NativeVerifier {
    /// Main window handle on Windows, so the Hello prompt opens in front of
    /// it. Unused elsewhere.
    owner_window: AtomicIsize,
}

impl NativeVerifier {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records the window that owns the system prompt (Windows only).
    pub fn set_owner_window(&self, handle: isize) {
        self.owner_window.store(handle, Ordering::SeqCst);
    }
}

impl PresenceVerifier for NativeVerifier {
    fn kind(&self) -> BiometryKind {
        #[cfg(target_os = "macos")]
        return macos::kind();
        #[cfg(target_os = "windows")]
        return windows::kind();
        #[cfg(target_os = "linux")]
        return linux::kind();
        #[allow(unreachable_code)]
        BiometryKind::None
    }

    fn verify(&self, reason: &str) -> Result<(), PresenceError> {
        #[cfg(target_os = "macos")]
        return macos::verify(reason);
        #[cfg(target_os = "windows")]
        return windows::verify(reason, self.owner_window.load(Ordering::SeqCst));
        #[cfg(target_os = "linux")]
        return linux::verify(reason);
        #[allow(unreachable_code)]
        {
            let _ = reason;
            Err(PresenceError::Unavailable)
        }
    }

    fn cancel(&self) {
        #[cfg(target_os = "linux")]
        linux::cancel();
    }
}

/// Runs `f` on a blocking thread: detection talks to OS services and
/// verification waits for the user, so neither may hold the UI thread.
pub(crate) async fn blocking<T, F>(app: AppHandle, f: F) -> Result<T, UiError>
where
    T: Send + 'static,
    F: FnOnce(&AppState) -> Result<T, UiError> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(move || f(&app.state::<AppState>()))
        .await
        .map_err(|e| UiError::internal(format!("Biometric task failed: {e}")))?
}

#[tauri::command]
pub async fn biometric_status(app: AppHandle) -> Result<BiometricStatusDto, UiError> {
    blocking(app, |state| state.biometric_status()).await
}

#[tauri::command]
pub async fn biometric_set_enabled(
    app: AppHandle,
    enabled: bool,
) -> Result<BiometricStatusDto, UiError> {
    blocking(app, move |state| state.biometric_set_enabled(enabled)).await
}

#[tauri::command]
pub fn biometric_cancel(state: tauri::State<'_, AppState>) {
    state.biometric_cancel();
}
