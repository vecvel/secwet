//! Platform services registered by the native host (Swift on iOS, the JNI
//! bridge on Android) as C function pointers, adapted to the app-layer traits:
//! [`KeyStore`], [`ClipboardPort`] and [`PresenceVerifier`].
//!
//! Keys only ever pass between Rust and the OS secure storage here; they are
//! held in zeroized buffers on the Rust side and never reach Dart.
//!
//! On a phone with a screen lock the native secure storage only opens after
//! the system prompt: `biometric_verify` shows it (biometric with the
//! passcode or PIN as fallback) and authorizes the stored keys for one
//! session, which `keystore_end_session` closes again on lock.

use std::ffi::{c_char, CString};

use secwet_app::{BiometryKind, ClipboardPort, PresenceError, PresenceVerifier};
use secwet_core::keys::{KeyStore, SecretVec};
use zeroize::{Zeroize, Zeroizing};

/// Mirror of `SecwetPlatform` in `include/secwet_ffi.h`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SecwetPlatform {
    pub keystore_get: extern "C" fn(entry: *const c_char, out: *mut u8, cap: usize) -> i64,
    pub keystore_set: extern "C" fn(entry: *const c_char, value: *const u8, len: usize) -> i32,
    pub keystore_delete: extern "C" fn(entry: *const c_char) -> i32,
    pub clipboard_write: extern "C" fn(text: *const u8, len: usize) -> i32,
    pub clipboard_read: extern "C" fn(out: *mut u8, cap: usize) -> i64,
    pub clipboard_clear: extern "C" fn() -> i32,
    pub biometric_kind: extern "C" fn() -> i32,
    pub biometric_verify: extern "C" fn(reason: *const u8, len: usize) -> i32,
    pub device_lock: extern "C" fn() -> i32,
    pub keystore_end_session: extern "C" fn(),
}

/// Return value of the `*_get`/`*_read` callbacks for a missing value.
const MISSING: i64 = -1;

/// Calls a "copy into my buffer" callback, growing the buffer until the value
/// fits. `Ok(None)` for a missing value. The buffer zeroizes itself on drop.
fn read_grow(
    mut fill: impl FnMut(*mut u8, usize) -> i64,
) -> Result<Option<Zeroizing<Vec<u8>>>, ()> {
    let mut buf = Zeroizing::new(vec![0u8; 256]);
    // Two rounds are enough unless the value changes in between; allow a few.
    for _ in 0..4 {
        let n = fill(buf.as_mut_ptr(), buf.len());
        if n == MISSING {
            return Ok(None);
        }
        if n < 0 {
            return Err(());
        }
        let n = n as usize;
        if n <= buf.len() {
            buf.truncate(n);
            return Ok(Some(buf));
        }
        // Grow into a fresh zeroed buffer; the old one is wiped on drop.
        buf = Zeroizing::new(vec![0u8; n]);
    }
    Err(())
}

fn entry_cstr(entry: &str) -> secwet_core::Result<CString> {
    CString::new(entry).map_err(|_| secwet_core::Error::KeyStore)
}

/// [`KeyStore`] over the native secure storage: iOS Keychain items behind
/// `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` and user presence,
/// Android entries sealed under a data key that an authentication-bound
/// Android Keystore key wraps (see `docs/mobile-ffi.md`).
pub struct NativeKeyStore(pub SecwetPlatform);

impl KeyStore for NativeKeyStore {
    fn get(&self, entry: &str) -> secwet_core::Result<Option<SecretVec<u8>>> {
        let name = entry_cstr(entry)?;
        let got = read_grow(|out, cap| (self.0.keystore_get)(name.as_ptr(), out, cap))
            .map_err(|_| secwet_core::Error::KeyStore)?;
        Ok(got.map(|mut bytes| {
            let value = SecretVec::new(bytes.to_vec());
            bytes.zeroize();
            value
        }))
    }

    fn set(&self, entry: &str, value: &[u8]) -> secwet_core::Result<()> {
        let name = entry_cstr(entry)?;
        match (self.0.keystore_set)(name.as_ptr(), value.as_ptr(), value.len()) {
            0 => Ok(()),
            _ => Err(secwet_core::Error::KeyStore),
        }
    }

    fn delete(&self, entry: &str) -> secwet_core::Result<()> {
        let name = entry_cstr(entry)?;
        match (self.0.keystore_delete)(name.as_ptr()) {
            0 => Ok(()),
            _ => Err(secwet_core::Error::KeyStore),
        }
    }
}

/// [`ClipboardPort`] over the native clipboard: iOS `UIPasteboard` (local
/// only, with expiry), Android `ClipboardManager` (`EXTRA_IS_SENSITIVE`).
pub struct NativeClipboard(pub SecwetPlatform);

impl ClipboardPort for NativeClipboard {
    fn write_secret(&self, text: &str) -> Result<(), String> {
        match (self.0.clipboard_write)(text.as_ptr(), text.len()) {
            0 => Ok(()),
            _ => Err("Could not write to the clipboard.".to_string()),
        }
    }

    /// `MISSING` means the host read the clipboard and found it empty. A
    /// clipboard the host cannot read (Android without focus, when it has
    /// no record of its own value there) is an error, so the auto-clear
    /// leaves it alone rather than guessing.
    fn read_text(&self) -> Result<String, String> {
        let got = read_grow(|out, cap| (self.0.clipboard_read)(out, cap))
            .map_err(|_| "Could not read the clipboard.".to_string())?;
        match got {
            // Empty: nothing of ours to clear; it hashes unequal to any copy.
            None => Ok(String::new()),
            Some(bytes) => Ok(String::from_utf8_lossy(&bytes).into_owned()),
        }
    }

    fn clear(&self) -> Result<(), String> {
        match (self.0.clipboard_clear)() {
            0 => Ok(()),
            _ => Err("Could not clear the clipboard.".to_string()),
        }
    }
}

/// Biometric kind codes of `SecwetPlatform::biometric_kind`, also reported to
/// the UI so it can name the biometric the phone uses.
pub fn platform_kind_name(code: i32) -> &'static str {
    match code {
        1 => "touch_id",
        2 => "face_id",
        3 => "optic_id",
        4 => "fingerprint",
        5 => "face",
        6 => "iris",
        7 => "multiple",
        _ => "none",
    }
}

/// [`PresenceVerifier`] over iOS LocalAuthentication and Android
/// `BiometricPrompt`, plus the screen-lock state and the key session the
/// prompt opens. The FFI dispatcher runs it on every unlock.
pub struct NativePresence(pub SecwetPlatform);

impl NativePresence {
    pub fn platform_kind(&self) -> i32 {
        (self.0.biometric_kind)()
    }

    /// The phone has a passcode, PIN, pattern or password.
    pub fn device_lock(&self) -> bool {
        (self.0.device_lock)() == 1
    }

    /// Closes the secure-storage session the last successful prompt opened.
    pub fn end_session(&self) {
        (self.0.keystore_end_session)()
    }
}

impl PresenceVerifier for NativePresence {
    fn kind(&self) -> BiometryKind {
        match self.platform_kind() {
            1 => BiometryKind::TouchId,
            2 => BiometryKind::FaceId,
            3 => BiometryKind::OpticId,
            4 => BiometryKind::Fingerprint,
            5 => BiometryKind::Face,
            6 => BiometryKind::Iris,
            7 => BiometryKind::Multiple,
            _ => BiometryKind::None,
        }
    }

    fn verify(&self, reason: &str) -> Result<(), PresenceError> {
        match (self.0.biometric_verify)(reason.as_ptr(), reason.len()) {
            0 => Ok(()),
            1 => Err(PresenceError::Cancelled),
            2 => Err(PresenceError::Failed),
            3 => Err(PresenceError::Unavailable),
            4 => Err(PresenceError::Busy),
            // The hosts map every known outcome; no codes in the UI.
            _ => Err(PresenceError::Other(
                "Couldn't confirm it's you. Try again.".to_owned(),
            )),
        }
    }
}
