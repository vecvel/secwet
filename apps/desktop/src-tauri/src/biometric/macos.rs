//! Touch ID (and Face ID / Optic ID where a Mac has it) through
//! LocalAuthentication, via the small Objective-C bridge in `macos.m`.

use std::ffi::CString;
use std::os::raw::c_char;

use super::{BiometryKind, PresenceError};

extern "C" {
    fn secwet_biometric_kind() -> i32;
    fn secwet_biometric_verify(reason: *const c_char) -> i32;
}

pub fn kind() -> BiometryKind {
    // SAFETY: takes no arguments and only reads LocalAuthentication state.
    match unsafe { secwet_biometric_kind() } {
        1 => BiometryKind::TouchId,
        2 => BiometryKind::FaceId,
        3 => BiometryKind::OpticId,
        _ => BiometryKind::None,
    }
}

pub fn verify(reason: &str) -> Result<(), PresenceError> {
    let reason = CString::new(reason).map_err(|_| PresenceError::Other("Invalid prompt text.".into()))?;
    // SAFETY: `reason` is a valid NUL-terminated string that outlives the call;
    // the bridge copies it before returning.
    match unsafe { secwet_biometric_verify(reason.as_ptr()) } {
        0 => Ok(()),
        1 => Err(PresenceError::Unavailable),
        2 => Err(PresenceError::Failed),
        3 => Err(PresenceError::Cancelled),
        _ => Err(PresenceError::Other("Touch ID could not check your identity.".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Detection never prompts; it reports this Mac's sensor or `None`.
    #[test]
    fn kind_detection_runs_without_prompting() {
        let found = kind();
        eprintln!("biometric kind on this Mac: {found:?}");
        assert_ne!(found, BiometryKind::WindowsHelloFace);
        assert_ne!(found, BiometryKind::Fingerprint);
    }
}
