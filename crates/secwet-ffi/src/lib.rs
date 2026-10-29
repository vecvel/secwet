//! C ABI over `secwet-app` for the mobile hosts. Our own small layer, no
//! binding generator: four functions (see `include/secwet_ffi.h`).
//!
//! - The native host registers its platform services once
//!   ([`secwet_ffi_register_platform`]): secure storage, clipboard and the
//!   biometric check, as C function pointers.
//! - Dart sends JSON requests through [`secwet_ffi_call`] from a background
//!   isolate; network commands block that thread on the app-layer runtime.
//! - Every buffer handed out is zeroized when freed ([`secwet_ffi_free`]).
//! - Change notifications reach Dart through one callback
//!   ([`secwet_ffi_set_event_callback`]).
//!
//! The protocol is documented in `docs/mobile-ffi.md`.

#[cfg(target_os = "android")]
mod android;
pub mod dispatch;
pub mod platform;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use secwet_app::{AppEvent, AppState};
use zeroize::{Zeroize, Zeroizing};

pub use dispatch::Bridge;
pub use platform::{NativeClipboard, NativeKeyStore, NativePresence, SecwetPlatform};

/// Event callback type of `secwet_ffi_set_event_callback`.
pub type SecwetEventCallback = extern "C" fn(ptr: *mut u8, len: usize);

struct Registration {
    platform: SecwetPlatform,
    data_dir: PathBuf,
    device_name: String,
}

static REGISTRATION: OnceLock<Registration> = OnceLock::new();
static BRIDGE: OnceLock<Bridge> = OnceLock::new();
/// The Dart event callback as a raw function address (0 when unset).
static EVENT_CALLBACK: AtomicUsize = AtomicUsize::new(0);

/// Builds a bridge over `platform` with events forwarded to the registered
/// callback. Used by the C entry points and by tests.
pub fn bridge_for(platform: SecwetPlatform, data_dir: PathBuf, device_name: String) -> Bridge {
    let state = AppState::new(data_dir, Arc::new(NativeKeyStore(platform)));
    let session = Arc::new(AtomicBool::new(false));
    let sink_session = session.clone();
    state.set_event_sink(Arc::new(move |event: AppEvent| {
        // However the store closed (idle lock, wipe), the keys close with it.
        if matches!(event, AppEvent::Locked | AppEvent::Wiped) {
            sink_session.store(false, Ordering::SeqCst);
            (platform.keystore_end_session)();
        }
        forward_event(event);
    }));
    Bridge::new(
        state,
        Arc::new(NativeClipboard(platform)),
        Arc::new(NativePresence(platform)),
        session,
        device_name,
    )
}

fn bridge() -> Option<&'static Bridge> {
    if let Some(b) = BRIDGE.get() {
        return Some(b);
    }
    let reg = REGISTRATION.get()?;
    Some(
        BRIDGE.get_or_init(|| {
            bridge_for(reg.platform, reg.data_dir.clone(), reg.device_name.clone())
        }),
    )
}

fn forward_event(event: AppEvent) {
    let raw = EVENT_CALLBACK.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }
    let body = serde_json::json!({ "name": event.name(), "payload": event.payload() });
    let Ok(bytes) = serde_json::to_vec(&body) else {
        return;
    };
    let (ptr, len) = into_raw(bytes);
    // SAFETY: `raw` was stored from a valid `SecwetEventCallback` by
    // `secwet_ffi_set_event_callback`; function pointers fit in usize.
    let callback: SecwetEventCallback =
        unsafe { std::mem::transmute::<usize, SecwetEventCallback>(raw) };
    callback(ptr, len);
}

/// Hands a buffer to the caller; it comes back through [`secwet_ffi_free`].
fn into_raw(bytes: Vec<u8>) -> (*mut u8, usize) {
    let boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    (Box::into_raw(boxed) as *mut u8, len)
}

/// # Safety
/// `ptr` must point to `len` readable bytes (or be null with `len == 0`).
unsafe fn bytes_arg<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return (len == 0).then_some(&[]);
    }
    Some(std::slice::from_raw_parts(ptr, len))
}

/// The device name as given, decoded lossily: an odd name (the user edits it
/// in the phone's settings) must never keep the app from starting.
fn device_name_or_default(name: &[u8]) -> String {
    let name = String::from_utf8_lossy(name);
    let name = name.trim();
    if name.is_empty() {
        "Phone".to_owned()
    } else {
        name.to_owned()
    }
}

/// Registers the native platform services, the app's data directory and the
/// device name. Returns 0, 1 when already registered, -1 on invalid input
/// (a null platform or a data directory that is empty or not UTF-8).
///
/// # Safety
/// `platform` must point to a valid `SecwetPlatform` whose functions stay
/// callable for the life of the process; the byte arguments must point to
/// buffers of the given lengths.
#[no_mangle]
pub unsafe extern "C" fn secwet_ffi_register_platform(
    platform: *const SecwetPlatform,
    data_dir: *const u8,
    data_dir_len: usize,
    device_name: *const u8,
    device_name_len: usize,
) -> i32 {
    if platform.is_null() {
        return -1;
    }
    let (Some(dir), Some(name)) = (
        bytes_arg(data_dir, data_dir_len),
        bytes_arg(device_name, device_name_len),
    ) else {
        return -1;
    };
    let Ok(dir) = std::str::from_utf8(dir) else {
        return -1;
    };
    if dir.is_empty() {
        return -1;
    }
    let reg = Registration {
        platform: *platform,
        data_dir: PathBuf::from(dir),
        device_name: device_name_or_default(name),
    };
    match REGISTRATION.set(reg) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

/// Runs one JSON command. Returns a buffer to free with [`secwet_ffi_free`]
/// and writes its length to `out_len`.
///
/// # Safety
/// `request` must point to `request_len` readable bytes and `out_len` must
/// be a valid pointer.
#[no_mangle]
pub unsafe extern "C" fn secwet_ffi_call(
    request: *const u8,
    request_len: usize,
    out_len: *mut usize,
) -> *mut u8 {
    let response: Zeroizing<Vec<u8>> = match bytes_arg(request, request_len) {
        None => Zeroizing::new(not_ready("Malformed request.", "invalid")),
        Some(req) => match bridge() {
            None => Zeroizing::new(not_ready(
                "The native platform is not registered yet.",
                "not_ready",
            )),
            Some(b) => catch_unwind(AssertUnwindSafe(|| b.handle(req))).unwrap_or_else(|_| {
                // A panic may have left the store half-changed (and its
                // mutex poisoned): lock it so the keys leave memory and the
                // next unlock starts from disk.
                let _ = catch_unwind(AssertUnwindSafe(|| b.handle(br#"{"cmd":"secwet_lock"}"#)));
                Zeroizing::new(not_ready("Secwet hit an internal error.", "internal"))
            }),
        },
    };
    // Move the bytes into an exact-size box without leaving a copy behind.
    let mut response = response;
    let boxed: Box<[u8]> = std::mem::take(&mut *response).into_boxed_slice();
    let len = boxed.len();
    if !out_len.is_null() {
        *out_len = len;
    }
    Box::into_raw(boxed) as *mut u8
}

fn not_ready(message: &str, code: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "err": { "code": code, "field": null, "message": message }
    }))
    .unwrap_or_default()
}

/// Zeroizes and frees a buffer from [`secwet_ffi_call`] or the event callback.
///
/// # Safety
/// `ptr` and `len` must come from one of those calls and be freed only once.
#[no_mangle]
pub unsafe extern "C" fn secwet_ffi_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    let mut boxed: Box<[u8]> = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
    boxed.zeroize();
}

/// Sets the event callback, or removes it with null.
#[no_mangle]
pub extern "C" fn secwet_ffi_set_event_callback(callback: Option<SecwetEventCallback>) {
    let raw = callback.map(|f| f as usize).unwrap_or(0);
    EVENT_CALLBACK.store(raw, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::device_name_or_default;

    #[test]
    fn device_name_never_blocks_registration() {
        assert_eq!(device_name_or_default(b" Pixel 9 "), "Pixel 9");
        assert_eq!(device_name_or_default(b"  "), "Phone");
        // U+1F4F1 in the modified UTF-8 form JNI's GetStringUTFChars returns.
        let cesu = b"Pixel \xED\xA0\xBD\xED\xB3\xB1";
        assert!(device_name_or_default(cesu).starts_with("Pixel "));
        assert_eq!(
            device_name_or_default("Pixel \u{1F4F1}".as_bytes()),
            "Pixel \u{1F4F1}"
        );
    }
}
