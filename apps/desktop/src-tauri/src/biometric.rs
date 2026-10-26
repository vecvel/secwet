//! macOS Biometric (Touch ID / LocalAuthentication) native interop.

use serde::Serialize;
use crate::error::UiError;

#[cfg(target_os = "macos")]
extern "C" {
    fn secwet_biometric_available() -> i32;
    fn secwet_authenticate_biometrics(reason: *const std::os::raw::c_char) -> i32;
}

#[cfg(not(target_os = "macos"))]
unsafe fn secwet_biometric_available() -> i32 {
    0
}

#[cfg(not(target_os = "macos"))]
unsafe fn secwet_authenticate_biometrics(_reason: *const std::os::raw::c_char) -> i32 {
    0
}

#[derive(Debug, Clone, Serialize)]
pub struct BiometricStatus {
    pub available: bool,
    pub biometry_type: &'static str,
}

pub fn check_biometric_available() -> BiometricStatus {
    let code = unsafe { secwet_biometric_available() };
    match code {
        1 => BiometricStatus {
            available: true,
            biometry_type: "touch_id",
        },
        2 => BiometricStatus {
            available: true,
            biometry_type: "system_auth",
        },
        _ => BiometricStatus {
            available: false,
            biometry_type: "none",
        },
    }
}

pub fn authenticate(reason: Option<&str>) -> Result<bool, UiError> {
    let r = reason.unwrap_or("Unlock Secwet");
    let c_str = std::ffi::CString::new(r).map_err(|_| UiError::internal("Invalid auth reason"))?;
    let code = unsafe { secwet_authenticate_biometrics(c_str.as_ptr()) };
    match code {
        0 => Ok(true),
        1 => Err(UiError::internal("Biometric authentication is not supported or not enrolled")),
        3 => Err(UiError::internal("Authentication was cancelled")),
        _ => Err(UiError::internal("Authentication failed")),
    }
}
