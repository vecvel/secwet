//! Biometric unlock policy, shared by every host.
//!
//! Hosts that can verify the user's presence with the OS (Touch ID, Windows
//! Hello, fprintd, Face ID on phones) install a [`PresenceVerifier`] with
//! [`AppState::set_presence_verifier`]. The user turns biometric unlock on in
//! Settings; from then on [`AppState::secwet_unlock`] refuses to open the
//! store until the verifier reports a successful check. The check runs here,
//! in Rust, so a webview that skips its own prompt cannot open the store.
//!
//! The on/off flag lives in OS secure storage next to the store's keys
//! (`secwet/{id}/biometric-unlock`), not in the store's settings table: the
//! store is still closed when the flag is needed, and keeping it beside the
//! keys means removing it needs the same access as reading the keys.
//!
//! Once the flag is on, unlock always runs the check, whatever the sensor
//! reports at that moment: a closed MacBook lid, an unplugged Touch ID
//! keyboard or USB reader must not skip it. The verifiers fall back to the
//! OS owner check where there is one (the Mac account password, the Windows
//! Hello PIN). When even that is unavailable (fprintd without its reader,
//! Hello removed) the store's recovery key opens it instead; without a
//! recovery key the user has to reconnect the sensor. The recovery key is
//! an owner check of its own, so it also opens the store directly.
//!
//! Verification blocks while the OS prompt is open. Hosts call these methods
//! from a blocking thread, never from the UI thread.

use std::sync::Arc;

use secwet_core::{Secwet, SecwetStatus};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::UiError;
use crate::state::AppState;

/// Prompt text shown by the OS when unlocking.
pub const UNLOCK_REASON: &str = "unlock Secwet";
/// Prompt text shown by the OS when turning biometric unlock on.
pub const ENABLE_REASON: &str = "turn on biometric unlock for Secwet";

/// The biometric the OS offers, so the UI can name it correctly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BiometryKind {
    None,
    TouchId,
    FaceId,
    OpticId,
    WindowsHelloFace,
    WindowsHelloFingerprint,
    WindowsHelloIris,
    Fingerprint,
    /// Face unlock on Android (class 3 face sensors).
    Face,
    /// Iris unlock on Android.
    Iris,
    /// Several enrolled biometrics; the OS prompt picks one.
    Multiple,
}

impl BiometryKind {
    pub fn is_available(self) -> bool {
        self != BiometryKind::None
    }

    /// Name for messages ("Touch ID", "Windows Hello").
    pub fn label(self) -> &'static str {
        match self {
            BiometryKind::None => "Biometrics",
            BiometryKind::TouchId => "Touch ID",
            BiometryKind::FaceId => "Face ID",
            BiometryKind::OpticId => "Optic ID",
            BiometryKind::WindowsHelloFace
            | BiometryKind::WindowsHelloFingerprint
            | BiometryKind::WindowsHelloIris => "Windows Hello",
            BiometryKind::Fingerprint => "Fingerprint",
            BiometryKind::Face => "Face unlock",
            BiometryKind::Iris => "Iris unlock",
            BiometryKind::Multiple => "Biometrics",
        }
    }
}

/// Why a presence check did not succeed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    /// The user (or the system) dismissed the prompt.
    Cancelled,
    /// The OS could not match the user.
    Failed,
    /// No usable biometric right now (not enrolled, no sensor, disabled).
    Unavailable,
    /// The sensor is used by another app.
    Busy,
    /// Anything else, with a message fit for the UI.
    Other(String),
}

impl From<PresenceError> for UiError {
    fn from(err: PresenceError) -> Self {
        match err {
            PresenceError::Cancelled => {
                UiError::new("biometric_cancelled", None, "Biometric check was cancelled.")
            }
            PresenceError::Failed => UiError::new(
                "biometric_failed",
                None,
                "Biometric check failed. Try again.",
            ),
            PresenceError::Unavailable => UiError::new(
                "biometric_unavailable",
                None,
                "Biometrics are not set up on this device.",
            ),
            PresenceError::Busy => UiError::new(
                "biometric_busy",
                None,
                "The biometric sensor is in use by another app. Try again.",
            ),
            PresenceError::Other(message) => UiError::new("biometric_error", None, message),
        }
    }
}

/// OS user-presence check, implemented by each host.
pub trait PresenceVerifier: Send + Sync {
    /// The biometric that is set up and usable now, or `None`.
    fn kind(&self) -> BiometryKind;

    /// Shows the OS prompt and blocks until the user passes or dismisses it.
    fn verify(&self, reason: &str) -> Result<(), PresenceError>;

    /// Stops a running [`verify`](Self::verify) for hosts whose prompt is
    /// drawn by the app (Linux fprintd). OS-drawn prompts have their own
    /// cancel button, so the default does nothing.
    fn cancel(&self) {}
}

/// What the UI needs to show or hide the biometric controls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BiometricStatusDto {
    /// A biometric is set up and usable on this device.
    pub available: bool,
    pub kind: BiometryKind,
    /// Unlock requires the biometric check. Always false when unavailable.
    pub enabled: bool,
}

fn flag_entry(secwet_id: Uuid) -> String {
    format!("secwet/{secwet_id}/biometric-unlock")
}

impl AppState {
    /// Installs the host's presence check. Hosts without one never install
    /// it, and biometric unlock stays hidden and off there.
    pub fn set_presence_verifier(&self, verifier: Arc<dyn PresenceVerifier>) {
        if let Ok(mut slot) = self.presence.write() {
            *slot = Some(verifier);
        }
    }

    fn presence_verifier(&self) -> Option<Arc<dyn PresenceVerifier>> {
        self.presence.read().ok().and_then(|slot| slot.clone())
    }

    /// Store id, open or not; `None` before the store exists.
    fn current_secwet_id(&self) -> Result<Option<Uuid>, UiError> {
        let guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        if let Some(secwet) = guard.as_ref() {
            return Ok(Some(secwet.secwet_id()));
        }
        drop(guard);
        Ok(match Secwet::status(&self.data_dir)? {
            SecwetStatus::Uninitialized => None,
            SecwetStatus::Locked { secwet_id } | SecwetStatus::Unlocked { secwet_id } => {
                Some(secwet_id)
            }
        })
    }

    fn biometric_flag(&self, secwet_id: Uuid) -> Result<bool, UiError> {
        let value = self.keystore.get(&flag_entry(secwet_id))?;
        Ok(value.is_some_and(|v| {
            use secrecy::ExposeSecret;
            v.expose_secret() == b"1"
        }))
    }

    fn kind_now(&self) -> BiometryKind {
        self.presence_verifier()
            .map(|v| v.kind())
            .unwrap_or(BiometryKind::None)
    }

    /// Whether a biometric is usable and whether unlock requires it. The
    /// flag is reported as set even while the sensor is unavailable, since
    /// unlock still requires the check (or the recovery key) then.
    pub fn biometric_status(&self) -> Result<BiometricStatusDto, UiError> {
        let kind = self.kind_now();
        let enabled = match self.current_secwet_id()? {
            Some(id) => self.biometric_flag(id)?,
            None => false,
        };
        Ok(BiometricStatusDto {
            available: kind.is_available(),
            kind,
            enabled,
        })
    }

    /// Turns biometric unlock on or off. Needs the store open. Turning it on
    /// first runs a successful check, so a sensor that cannot match the user
    /// is never required at unlock. Turning it off always works.
    pub fn biometric_set_enabled(&self, enabled: bool) -> Result<BiometricStatusDto, UiError> {
        let secwet_id = self.with_secwet(|v| Ok(v.secwet_id()))?;
        let entry = flag_entry(secwet_id);
        if enabled {
            let verifier = self
                .presence_verifier()
                .filter(|v| v.kind().is_available())
                .ok_or(PresenceError::Unavailable)?;
            verifier.verify(ENABLE_REASON)?;
            // The user may have locked the app while the prompt was open.
            if self.with_secwet(|v| Ok(v.secwet_id()))? != secwet_id {
                return Err(UiError::locked());
            }
            self.keystore.set(&entry, b"1")?;
        } else {
            self.keystore.delete(&entry)?;
        }
        self.emit_changed("settings");
        self.biometric_status()
    }

    /// Stops a running app-drawn biometric prompt (see
    /// [`PresenceVerifier::cancel`]).
    pub fn biometric_cancel(&self) {
        if let Some(verifier) = self.presence_verifier() {
            verifier.cancel();
        }
    }

    /// Runs the biometric check when unlock requires it. Called by
    /// [`AppState::secwet_unlock_with`] before it opens the store. A
    /// `recovery_key` stands in for the check; it is how the user gets in
    /// while the device cannot check anything.
    pub(crate) fn unlock_presence_gate(&self, recovery_key: Option<&str>) -> Result<(), UiError> {
        let Some(secwet_id) = self.current_secwet_id()? else {
            return Ok(());
        };
        if !self.biometric_flag(secwet_id)? {
            return Ok(());
        }
        if let Some(key) = recovery_key {
            return self.recovery_key_gate(key);
        }
        // Never skipped because the sensor reads as missing right now; the
        // verifier offers the OS owner check where the biometric is gone.
        let checked = match self.presence_verifier() {
            Some(verifier) => verifier.verify(UNLOCK_REASON),
            None => Err(PresenceError::Unavailable),
        };
        match checked {
            Ok(()) => Ok(()),
            Err(PresenceError::Unavailable) => {
                if Secwet::recovery_key_exists_closed(&self.data_dir)? {
                    Err(UiError::new(
                        "recovery_key_required",
                        Some("recovery_key".to_owned()),
                        "This device can't check biometric unlock right now. Reconnect the sensor, or enter your recovery key.",
                    ))
                } else {
                    Err(UiError::new(
                        "biometric_unavailable",
                        None,
                        "This device can't check biometric unlock right now. Reconnect the sensor and try again.",
                    ))
                }
            }
            Err(err) => Err(err.into()),
        }
    }

    /// Opens the gate with the store's recovery key, checked against its
    /// `recovery_check` seal without opening anything.
    fn recovery_key_gate(&self, key: &str) -> Result<(), UiError> {
        match Secwet::verify_recovery_key_closed(&self.data_dir, key)? {
            Some(true) => Ok(()),
            Some(false) => Err(UiError::new(
                "recovery_key_invalid",
                Some("recovery_key".to_owned()),
                "That recovery key doesn't match this Secwet.",
            )),
            None => Err(UiError::new(
                "biometric_unavailable",
                None,
                "This Secwet has no recovery key. Reconnect the sensor and try again.",
            )),
        }
    }
}
