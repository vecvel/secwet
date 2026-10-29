//! JNI entry points for Android. The JNI work itself lives in
//! `android/jni_bridge.c` (compiled by build.rs); these exports make the
//! symbols visible from `libsecwet_ffi.so` to the Kotlin side
//! (`app.secwet.secwet_mobile.SecwetNative.nativeInstall`).

use std::ffi::c_void;

extern "C" {
    fn secwet_jni_install(
        env: *mut c_void,
        class: *mut c_void,
        data_dir: *mut c_void,
        device_name: *mut c_void,
    ) -> i32;
}

/// `SecwetNative.nativeInstall(dataDir: ByteArray, deviceName: ByteArray): Int`,
/// both UTF-8.
///
/// # Safety
/// Called by the JVM with a valid `JNIEnv`, class and byte array references.
#[no_mangle]
pub unsafe extern "C" fn Java_app_secwet_secwet_1mobile_SecwetNative_nativeInstall(
    env: *mut c_void,
    class: *mut c_void,
    data_dir: *mut c_void,
    device_name: *mut c_void,
) -> i32 {
    secwet_jni_install(env, class, data_dir, device_name)
}
