//! Windows Hello through the official WinRT `UserConsentVerifier`, with the
//! Windows Biometric Framework telling which sensor (face, fingerprint, iris)
//! is present.
//!
//! `UserConsentVerifier` also reports "available" for a PIN-only Hello set
//! up; without a biometric sensor the feature stays hidden, as on any other
//! system without biometrics. The Hello prompt itself offers the PIN as its
//! fallback, so a failing sensor never locks the user out.

use std::ffi::c_void;

use windows::core::{factory, HSTRING};
use windows::Security::Credentials::UI::{
    UserConsentVerificationResult, UserConsentVerifier, UserConsentVerifierAvailability,
};
use windows::Win32::Devices::BiometricFramework::{
    WinBioEnumBiometricUnits, WinBioFree, WINBIO_UNIT_SCHEMA,
};
use windows::Win32::Foundation::HWND;
use windows::Win32::System::WinRT::IUserConsentVerifierInterop;
use windows_future::IAsyncOperation;

use super::{BiometryKind, PresenceError};

// WINBIO_BIOMETRIC_TYPE values from winbio_types.h (not in the bindings).
const WINBIO_TYPE_FACIAL_FEATURES: u32 = 0x0000_0002;
const WINBIO_TYPE_FINGERPRINT: u32 = 0x0000_0008;
const WINBIO_TYPE_IRIS: u32 = 0x0000_0010;

/// Whether a biometric unit of `factor` is installed.
fn has_unit(factor: u32) -> bool {
    let mut units: *mut WINBIO_UNIT_SCHEMA = std::ptr::null_mut();
    let mut count = 0usize;
    // SAFETY: both out pointers are valid; the array is freed with WinBioFree.
    let found = unsafe { WinBioEnumBiometricUnits(factor, &mut units, &mut count) };
    if !units.is_null() {
        // SAFETY: `units` was allocated by WinBioEnumBiometricUnits.
        let _ = unsafe { WinBioFree(units as *const c_void) };
    }
    found.is_ok() && count > 0
}

pub fn kind() -> BiometryKind {
    let availability = UserConsentVerifier::CheckAvailabilityAsync().and_then(|op| op.join());
    match availability {
        // Busy is temporary; treating it as missing would skip the check.
        Ok(a)
            if a == UserConsentVerifierAvailability::Available
                || a == UserConsentVerifierAvailability::DeviceBusy => {}
        _ => return BiometryKind::None,
    }
    if has_unit(WINBIO_TYPE_FACIAL_FEATURES) {
        BiometryKind::WindowsHelloFace
    } else if has_unit(WINBIO_TYPE_FINGERPRINT) {
        BiometryKind::WindowsHelloFingerprint
    } else if has_unit(WINBIO_TYPE_IRIS) {
        BiometryKind::WindowsHelloIris
    } else {
        BiometryKind::None
    }
}

/// Shows the Hello prompt, owned by `hwnd` when the app window is known so
/// it opens in front of it.
pub fn verify(reason: &str, hwnd: isize) -> Result<(), PresenceError> {
    let message = HSTRING::from(reason);
    let request = || -> windows::core::Result<UserConsentVerificationResult> {
        let op: IAsyncOperation<UserConsentVerificationResult> = if hwnd != 0 {
            let interop = factory::<UserConsentVerifier, IUserConsentVerifierInterop>()?;
            // SAFETY: `hwnd` is the live main window handle given by Tauri.
            unsafe { interop.RequestVerificationForWindowAsync(HWND(hwnd as *mut c_void), &message)? }
        } else {
            UserConsentVerifier::RequestVerificationAsync(&message)?
        };
        op.join()
    };
    let result = request().map_err(|e| PresenceError::Other(format!("Windows Hello failed: {}", e.message())))?;
    if result == UserConsentVerificationResult::Verified {
        Ok(())
    } else if result == UserConsentVerificationResult::Canceled {
        Err(PresenceError::Cancelled)
    } else if result == UserConsentVerificationResult::RetriesExhausted {
        Err(PresenceError::Failed)
    } else if result == UserConsentVerificationResult::DeviceBusy {
        Err(PresenceError::Busy)
    } else {
        // DeviceNotPresent, NotConfiguredForUser, DisabledByPolicy.
        Err(PresenceError::Unavailable)
    }
}
