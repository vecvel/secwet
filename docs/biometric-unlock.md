# Biometric unlock

Secwet offers biometric unlock wherever the system has a usable biometric, and hides it everywhere else. With it off, or hidden, unlock works exactly as before.

## Behaviour

| System | What Secwet uses | Kind reported | Fallback inside the prompt |
| --- | --- | --- | --- |
| macOS | LocalAuthentication (Touch ID; Face ID / Optic ID if a Mac ever has them) | `touch_id`, `face_id`, `optic_id` | Mac account password |
| Windows | Windows Hello `UserConsentVerifier`, sensor type from the Windows Biometric Framework | `windows_hello_face`, `windows_hello_fingerprint`, `windows_hello_iris` | Windows Hello PIN |
| Linux | fprintd (`net.reactivated.Fprint`) on the system bus, through our own D-Bus client | `fingerprint` | none (see below) |
| Anything else, no sensor, nothing enrolled | — | `none` | — |

- **Hidden when unusable.** `biometric_status` returns `available: false` and kind `none`; Settings > Security then shows no biometric section and the lock screen shows the plain Unlock button.
- **Turning it on** (Settings > Security > Biometric unlock) needs the store open and one successful check, so a sensor that cannot match the user is never required.
- **Unlock.** When it is on, `secwet_unlock` runs the check in Rust before it opens the store and refuses on cancel or failure. The webview cannot skip it. The lock screen prompts at launch and again when the user comes back to the window, so locking never opens a prompt by itself.
- **Never skipped while on.** Once the flag is set, every unlock runs the check, whatever the sensor reports at that moment: a closed MacBook lid, an unplugged Touch ID keyboard, USB reader or Hello camera must not open Secwet without it. macOS and Windows then offer the account password or Hello PIN in the same prompt (`LAPolicyDeviceOwnerAuthentication`, `UserConsentVerifier`). When the OS has no check left at all (fprintd without its reader, Hello removed), unlock answers `recovery_key_required` and the lock screen asks for the store's recovery key, which `secwet_unlock` accepts as `recovery_key` (checked against the `recovery_check` seal without opening the store). Without a recovery key the user reconnects the sensor (`biometric_unavailable`). Settings keeps showing the switch while the flag is on, so it can be turned off once the store is open. Turning it off always works.

## Where things live

- `crates/secwet-app/src/biometric.rs`: the policy, shared with the mobile hosts. `PresenceVerifier` trait (`kind`, `verify`, `cancel`), `AppState::set_presence_verifier`, `biometric_status`, `biometric_set_enabled`, `biometric_cancel` and the unlock gate called from `AppState::secwet_unlock`.
- `apps/desktop/src-tauri/src/biometric/`: `NativeVerifier` and the Tauri commands `biometric_status`, `biometric_set_enabled`, `biometric_cancel`; `macos.rs` + `macos.m`, `windows.rs`, `linux.rs` + `dbus.rs`.
- UI: `src/components/UnlockScreen.tsx`, `src/screens/settings/BiometricSection.tsx`, labels in `src/lib/biometric.ts`. In the browser preview, `?biometric=<kind>` picks what the mock reports (`none` hides it).

## The on/off flag

The flag is stored in OS secure storage as `secwet/{secwet_id}/biometric-unlock`, next to the store's keys, rather than in the store's `settings` table: the store is still closed when the gate needs the flag, and keeping it beside the keys means clearing it needs the same access as reading the keys. It holds no key material.

## Binding the master key to biometry: evaluated, not done

- **macOS keychain access control** (`SecAccessControl` with `.biometryCurrentSet`): only works in the data-protection keychain, which needs a signed app with a `keychain-access-groups` entitlement and provisioning profile. Development and ad-hoc builds get `errSecMissingEntitlement`. It would also move every existing key out of the login keychain the `keyring` crate uses, and the CLI shares those entries (`service = "secwet"`): every CLI command would need Touch ID, and builds without the entitlement could no longer read the keys. That breaks existing keychain entries, so the key is not bound; the presence check gates `secwet_unlock` instead.
- **Windows Hello key credential** (`KeyCredentialManager`): it signs with a private key, it does not release a secret. Deriving the master key's wrapping key from a signature would be our own cryptographic construction, which the project rules forbid (IMPLEMENTATION.md §4), and it would also move the keys out of Credential Manager where the CLI reads them. Not done.
- **Linux**: fprintd only answers match or no match; there is nothing to bind a key to.

## Phones

On iOS and Android the system prompt is not a setting: with a screen lock it guards every unlock, and the stored keys are bound to it (iOS Keychain user presence, Android Keystore authentication). The policy is in `crates/secwet-ffi/src/dispatch.rs`; the full description is in `docs/mobile-ffi.md` ("Unlock"). Biometric wording follows the same rule as the desktop: it appears only when a biometric is enrolled (`available`); otherwise the prompt is the passcode or PIN alone and Settings says so. A phone without any screen lock is refused: the app stops at "Set a screen lock to use Secwet", and the recovery key is never used to unlock.

## Not verified on real hardware

The macOS path is built and unit tested on macOS. The Windows module type-checks and passes clippy for `x86_64-pc-windows-msvc`, and the Linux module (with the D-Bus marshalling tests) for `x86_64-unknown-linux-gnu`, both through a stand-alone check crate, since the full desktop crate cannot be cross-compiled from a Mac. Neither has been run against Windows Hello or fprintd yet.
