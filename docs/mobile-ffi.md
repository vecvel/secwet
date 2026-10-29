# Mobile bridge (`crates/secwet-ffi`)

How the Flutter app (`apps/mobile`) reaches the Rust app layer
(`crates/secwet-app`, see `docs/app-layer.md`). Our own small C ABI, no
binding generator.

```
Flutter UI (lib/screens, lib/widgets)
  -> SecwetApi (lib/core/secwet_api.dart): typed calls and models
     -> NativeSecwetBridge (lib/core/bridge.dart): JSON over dart:ffi, one background isolate per call
        -> secwet-ffi (C ABI): JSON routing to AppState methods
           -> secwet-app -> secwet-core
Native host (Swift / Kotlin + JNI C) -> secwet_ffi_register_platform: Keychain/Keystore, clipboard, biometrics
```

## C ABI (`crates/secwet-ffi/include/secwet_ffi.h`)

| Function | Called by | Purpose |
| --- | --- | --- |
| `secwet_ffi_register_platform(platform, data_dir, device_name)` | iOS `AppDelegate`, Android `MainActivity` (JNI) | Registers the native services once, before Dart runs. |
| `secwet_ffi_call(request, len, &out_len)` | Dart (background isolate) | Runs one JSON command; returns a JSON buffer. |
| `secwet_ffi_free(ptr, len)` | Dart | Zeroizes and frees a returned buffer. |
| `secwet_ffi_set_event_callback(cb)` | Dart (`NativeCallable.listener`) | Receives `{name, payload}` events from any thread. |

Requests are `{"cmd": "<command>", "args": {...}}`. Command and argument
names are the desktop Tauri commands with snake_case keys
(`apps/desktop/src-tauri/src/commands.rs`, `collab_commands.rs`), so both
hosts use one contract. Responses are `{"ok": value}` (the DTO exactly as the
desktop receives it) or `{"err": {"code", "field", "message"}}` (`UiError`).
Mobile differences: `secwet_unlock`, `secwet_create`, restore, pairing and
invite accept are refused with `screen_lock_required` on a phone without a
screen lock (see "Unlock" below); `biometric_status` reports how the phone
unlocks (`available`, `kind`, `enabled`, `platform_kind`, `device_lock`); there is no `biometric_set_enabled` or
`biometric_cancel`, because the prompt is not optional on a phone; and
`system_device_name` returns the name the native side registered. The plan
commands `plan_status`, `plan_refresh` and `plan_activate` are routed too.

Joining as a new device (the other side of `pairing_start`):
`pairing_join_start {link, device_name?}` joins the session from a scanned
`secwet://pair` link and returns `{code, fingerprint}` to compare;
`pairing_join_poll` returns `waiting`, `expired` or
`approved {secwet, synced}` (the store now exists and is open);
`pairing_join_cancel` forgets the join. The new identity stays in memory
until approval (`crates/secwet-core/src/pairing_join.rs`).

`workspace_export` and `workspace_restore` require `path`; the app gets it
from the system document picker (`PlatformServices.pickFile`) or writes to its
temp folder and hands the file to the save dialog (`PlatformServices.saveFile`).
Decrypted asset downloads never go through a plain temp file:
`PlatformServices.saveBytes` writes them straight into the document the user
creates on Android, and on iOS through a `NSFileProtectionComplete` file that
lives only while the export dialog is open. The native side empties the temp
folder (`secwet-files`) on every launch before Dart starts, and Dart asks it to
on every lock. Android PDF previews render from an in-memory `memfd` on
Android 11 and later.

## Platform services

| Service | iOS (`ios/Runner/SecwetPlatform.swift`) | Android (`SecwetNative.kt` via `android/jni_bridge.c`) |
| --- | --- | --- |
| Key storage | Keychain generic passwords behind `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` + `.userPresence`; the unlock prompt's evaluated `LAContext` authorizes reads for one session | Entries sealed with AES-256-GCM under a random data key; the data key is stored only wrapped (RSA-OAEP) by an Android Keystore key pair whose private key needs `AUTH_BIOMETRIC_STRONG` or `AUTH_DEVICE_CREDENTIAL`: on Android 11+ an auth-per-use key that only the unlock prompt can authorize (its unwrap cipher is the prompt's `CryptoObject`), before that any authentication within 15 s; the unlock prompt unwraps it into memory for one session; ciphertext in private preferences, backups off |
| Clipboard | `UIPasteboard` local-only items expiring after 30 s; only reads back its own item | `ClipboardManager` with `EXTRA_IS_SENSITIVE`; Android 10+ cannot read the clipboard from the background, so Secwet remembers the value it wrote and reports it until it sees another copy (a change it cannot read counts as another copy); a value whose clear could not run (frozen process) is cleared when Secwet regains focus |
| Unlock prompt | LocalAuthentication `.deviceOwnerAuthentication`: Face ID, Touch ID or Optic ID with the passcode as fallback, or the passcode alone | `BiometricPrompt` with `BIOMETRIC_STRONG \| DEVICE_CREDENTIAL` (Android 11+; `BIOMETRIC_WEAK \| DEVICE_CREDENTIAL` before) |
| Screen lock | `canEvaluatePolicy(.deviceOwnerAuthentication)` | `KeyguardManager.isDeviceSecure` |

The device name the host registers is the phone's own (`UIDevice.name`,
`Settings.Global.DEVICE_NAME`, passed as real UTF-8; an odd or empty name
falls back to "Phone" and never fails registration). On iOS 16 and later
`UIDevice.name` is only the model ("iPhone") unless the app has the
`com.apple.developer.device-information.user-assigned-device-name`
entitlement, which Apple grants on request; until Secwet has it, the user
names the phone in the onboarding field (prefilled) or in Settings > General.

They are C function pointers, called by Rust synchronously from any thread.
That is why they are native and not Dart: Dart platform channels are
asynchronous, and Dart memory cannot be zeroized. Keys move only between Rust
(zeroized buffers) and the OS secure storage; they never reach Dart.

## Unlock

The phone's unlock policy lives in the FFI dispatcher
(`crates/secwet-ffi/src/dispatch.rs`), not in the app layer's opt-in
biometric flag that the desktop uses:

- **With a screen lock** every `secwet_unlock` runs `biometric_verify`, the
  system prompt. A pass opens the native key session, Rust reads the keys and
  opens the store; a cancel or failure refuses (`biometric_cancelled`,
  `biometric_failed`) and the keys stay unreadable. `secwet_lock`, the
  `locked` and `wiped` events end the session (`keystore_end_session`).
  Creating, restoring or joining a store runs the prompt once first, because
  writing the new keys is followed by reading them back.
- **Without a screen lock** the OS cannot bind the keys to a prompt, so the
  app does not open at all: RootGate shows "Set a screen lock to use Secwet"
  in place of onboarding and the lock screen, with a button that opens the
  phone's security settings (`openSecuritySettings` on `app.secwet/platform`:
  Android `Settings.ACTION_SECURITY_SETTINGS`, iOS
  `UIApplication.openSettingsURLString`), and re-reads `biometric_status`
  whenever the app comes back. The recovery key is never asked for to unlock.
  Rust enforces the same rule as a backstop for any other caller: without a
  screen lock every command that would store or open keys fails with
  `screen_lock_required`.
- Setting a screen lock later moves the keys behind it on the next unlock.
  Removing the screen lock makes iOS and Android delete the protected keys;
  the recovery key and an export are then the way back.

## Memory hygiene

- Rust zeroizes every response buffer on free and wipes the strings of each
  parsed request and serialized response (secret values, recovery keys).
  Secret strings (`secret_reveal`, recovery keys) move into the response
  without a copy; responses are written into exact-size buffers.
- Dart zeroes its native request copy before freeing it.
- Copy actions (`secret_copy`, `note_copy_plain`) go from Rust to the native
  clipboard directly; the value never passes through Dart.
- Nothing is logged.

## Building

- iOS: `apps/mobile/scripts/build_rust_ios.sh [iphoneos|iphonesimulator]`
  builds `aarch64-apple-ios`, `aarch64-apple-ios-sim` and `x86_64-apple-ios`
  (release) and writes `ios/Frameworks/SecwetFFI.xcframework`. The Runner's
  "Build Rust" phase runs it for the current platform; `ios/Flutter/Secwet.xcconfig`
  force-loads the slice (Dart finds the symbols with `DynamicLibrary.process()`)
  and links Security and LocalAuthentication. Minimum iOS 15.
- Android: the `buildRust` Gradle task (runs before `preBuild`) calls
  `cargo ndk -t arm64-v8a -t armeabi-v7a -t x86_64 build -p secwet-ffi --release`
  into `build/rustJniLibs`, packaged as `libsecwet_ffi.so`. The JNI bridge C file
  is compiled into the same library by `crates/secwet-ffi/build.rs`.
- Required: rustup targets `aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
  aarch64-linux-android armv7-linux-androideabi x86_64-linux-android`, `cargo-ndk`,
  and the NDK Flutter pins (`flutter.ndkVersion`).

## Dart side

- `lib/core/secwet_api.dart`: the stable API for screens (`SecwetScope.of(context).api`).
- `lib/core/session.dart`: lock state, how the phone unlocks, the auto-lock timeout (also applied when the app comes back from the background).
- `lib/app/auto_lock.dart`: records when the app goes to the background and
  locks when it comes back after the Settings auto-lock time or longer
  ("Never" keeps it open); covers the UI while inactive (app switcher
  snapshot). Until that return the keys and the native key session stay in
  memory while the app is suspended, as on the desktop.
  Wrap native screens you open (pickers) in `session.external(...)`.
- `lib/app/shell.dart`: three tabs (Groups, Overview in the center, Settings),
  one navigator per tab; push screens with `pushScreen(context, ...)`.
- Tests use `test/support/fake_bridge.dart`; product code always uses the FFI.
