// C ABI of crates/secwet-ffi. The mobile hosts use it as follows:
//   1. Native code (Swift AppDelegate, Android JNI bridge) registers the
//      platform services with secwet_ffi_register_platform before Dart runs.
//   2. Dart (dart:ffi, apps/mobile/lib/core/ffi_bindings.dart) sends JSON
//      requests through secwet_ffi_call and frees every returned buffer with
//      secwet_ffi_free, which zeroizes it first.
//   3. Dart registers one event callback for change notifications.
// Protocol details: docs/mobile-ffi.md.

#ifndef SECWET_FFI_H
#define SECWET_FFI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Platform services, implemented natively and called by Rust from any
// thread. Byte strings are not NUL-terminated unless noted.
typedef struct SecwetPlatform {
  // Copies the stored value into out (capacity cap) and returns its full
  // length; when that exceeds cap, Rust calls again with a larger buffer.
  // Returns -1 when the entry is missing and -2 on error. entry is NUL-terminated.
  int64_t (*keystore_get)(const char *entry, uint8_t *out, size_t cap);
  // Stores value under entry, replacing any previous one. 0 on success.
  int32_t (*keystore_set)(const char *entry, const uint8_t *value, size_t len);
  // Removes entry. A missing entry counts as success (0).
  int32_t (*keystore_delete)(const char *entry);
  // Puts UTF-8 text on the clipboard, marked sensitive / local-only. 0 on success.
  int32_t (*clipboard_write)(const uint8_t *text, size_t len);
  // Like keystore_get for the clipboard's current text. -1 when it holds no
  // text, any other negative value when it cannot be read (then nothing is
  // cleared). A host that cannot read the clipboard from the background
  // (Android 10+) answers with the value it wrote itself, as long as it has
  // not seen anything else being copied since.
  int64_t (*clipboard_read)(uint8_t *out, size_t cap);
  // Empties the clipboard. 0 on success.
  int32_t (*clipboard_clear)(void);
  // The usable biometric right now: 0 none, 1 Touch ID, 2 Face ID,
  // 3 Optic ID, 4 fingerprint, 5 face, 6 iris, 7 several (Android).
  int32_t (*biometric_kind)(void);
  // Shows the system unlock prompt (biometric, with the passcode or PIN as
  // fallback) and blocks until it ends. On success the secure storage opens
  // its key session: keystore_get and keystore_set work until
  // keystore_end_session. Never called on the UI thread. 0 passed,
  // 1 cancelled, 2 failed, 3 unavailable, 4 busy, anything else is an error.
  int32_t (*biometric_verify)(const uint8_t *reason, size_t len);
  // 1 when the phone has a screen lock (passcode, PIN, pattern, password),
  // 0 when it has none. Without one the keys cannot be bound to the prompt
  // and the stores keep them readable whenever the phone is unlocked.
  int32_t (*device_lock)(void);
  // Closes the key session opened by biometric_verify (on lock and wipe).
  void (*keystore_end_session)(void);
} SecwetPlatform;

// Registers the platform services, the app's private data directory and the
// device's user-visible name, both UTF-8. Returns 0, or 1 when already
// registered (the first registration stays), or -1 on invalid input (a null
// platform, an empty data directory, or one that is not UTF-8). The name
// never fails registration: invalid bytes are replaced and an empty name
// becomes "Phone".
int32_t secwet_ffi_register_platform(const SecwetPlatform *platform,
                                     const uint8_t *data_dir, size_t data_dir_len,
                                     const uint8_t *device_name, size_t device_name_len);

// Runs one command. request is UTF-8 JSON {"cmd": "...", "args": {...}}.
// Returns UTF-8 JSON {"ok": value} or {"err": {"code", "field", "message"}}
// and writes its length to out_len. Free the result with secwet_ffi_free.
uint8_t *secwet_ffi_call(const uint8_t *request, size_t request_len, size_t *out_len);

// Zeroizes and frees a buffer returned by secwet_ffi_call or passed to the
// event callback.
void secwet_ffi_free(uint8_t *ptr, size_t len);

// Receives events as UTF-8 JSON {"name": "secwet://changed", "payload": ...}.
// Called from any thread; the receiver frees the buffer with secwet_ffi_free.
typedef void (*SecwetEventCallback)(uint8_t *ptr, size_t len);

// Sets (or with NULL removes) the event callback.
void secwet_ffi_set_event_callback(SecwetEventCallback callback);

#ifdef __cplusplus
}
#endif

#endif // SECWET_FFI_H
