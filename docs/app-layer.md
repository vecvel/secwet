# App layer (`crates/secwet-app`)

One implementation of every app command, shared by the desktop (Tauri) host
and the mobile hosts. Hosts only adapt arguments and provide platform
services; they hold no app logic.

```
UI (React webview / Flutter)
  -> host adapter (src-tauri commands / mobile FFI)
     -> secwet-app: AppState methods -> Result<T, UiError>
        -> secwet-core (store, crypto, sync, relay client)
```

## Using it

```rust
use std::sync::Arc;
use secwet_app::{AppState, AppEvent};

let state = AppState::new(data_dir, keystore);         // keystore: Arc<dyn KeyStore>
state.set_event_sink(Arc::new(|e: AppEvent| post_to_ui(e.name(), e.payload())));
state.secwet_unlock()?;                                 // after the host's own user check
let groups = state.labels_list()?;
let pushed_pulled = secwet_app::runtime::block_on(state.sync_round())?;
```

- Desktop/CLI: `AppState::default_state()` (feature `os-keyring`) picks the
  platform data dir (`SECWET_DATA_DIR` overrides) and the OS keychain
  (`SECWET_TEST_KEYSTORE=memory` selects the in-memory store for e2e tests).
- One `AppState` per process, kept for the app's lifetime. All methods take
  `&self` and are safe to call from several threads.
- Every method returns `Result<T, UiError>`. `UiError { code, field, message }`
  serializes as is; codes are listed in `docs/IMPLEMENTATION.md` §10 plus
  `busy`, `wiped`, `revoked`, `relay_not_configured`.
- DTOs are serde types: inputs deserialize from the same JSON the desktop UI
  sends today, outputs serialize to what it receives. A mobile bridge can
  pass JSON across FFI without new types.

### Methods (by module)

`commands.rs` (store):

| Area | Methods |
| --- | --- |
| Lifecycle | `secwet_status`, `secwet_create(device_name)`, `secwet_unlock`, `secwet_lock` |
| Spaces | `spaces_list`, `space_create`, `space_rename`, `space_delete`, `space_reorder` |
| Groups | `labels_list`, `label_create`, `label_create_in_space`, `label_rename`, `label_delete`, `label_reorder`, `label_move_to_space` |
| Items | `items_list(label_id?)`, `item_create`, `item_rename`, `item_delete` |
| Environments | `environments_list`, `environment_add`, `environment_rename`, `environment_delete(id, preserve_content?)` |
| Secrets | `secrets_list`, `secret_reveal`, `secret_copy(clipboard, id)`, `secret_create`, `secret_update`, `secret_delete`, `secret_copy_to_environment` |
| Assets | `assets_list`, `asset_upload`, `asset_download`, `asset_rename`, `asset_delete` (`file_*` aliases) |
| Notes | `notes_list`, `note_get`, `note_create`, `note_update`, `note_delete`, `note_copy_plain(clipboard, id)`, `clipboard_copy_text(clipboard, text)` |
| Overview | `overview`, `dashboard_get`, `dashboard_set` |
| Settings | `settings_get`, `settings_set(patch)`; free fn `commands::system_device_name()` |
| Projects (compat) | `projects_list`, `project_create`, `project_rename`, `project_delete` |
| CLI sessions | `active_sessions_list`, `active_session_stop` |
| Recovery | `recovery_key_create`, `recovery_key_replace`, `recovery_status`, `workspace_export(path, key)`, `workspace_restore(path, key, device_name)` |
| Relay | async `relay_status`, async `relay_register`, `relay_set_url` |
| Plans (F13) | `plan_status` (cached, never networked), async `plan_refresh` (Pro/paused only), async `plan_activate` (the user's "Check for Pro": the one relay call Free makes) -> `PlanStatusDto` |
| Devices, pairing | `devices_list`, async `pairing_start`, async `pairing_poll`, async `pairing_approve`, `pairing_cancel` |
| Sync | async `sync_now` / `sync_round` -> `(pushed, pulled)`, `sync_status` |

`collab.rs` (M7/M8, contract in `docs/m7-m8-architecture.md` §10):
async `device_revoke(device_id, wipe)`, `key_status`, async `key_rotate`,
`link_status`, async `members_list`, async `member_invite(email, grants)`,
async `member_set_grants`, async `member_remove(member_id, wipe)`,
async `invitation_revoke`, async `invitation_accept(link, email, device_name)`,
`scope_nodes(space_id)`, `my_access`, `invite_link_copy(clipboard, invitation_id)`.

Network commands take the store out of state for the duration of the call
(other commands then get `busy`), and put it back unless the app was locked
meanwhile. A verified revocation notice from the relay runs the wipe or
archive before the error is returned.

Paths: `workspace_export`/`workspace_restore` require a path. Hosts with a
file picker resolve it first (the desktop uses the native dialog; on mobile
use the platform document picker and pass the resulting file path).

### Plans (F13)

The plan lives in `secwet_core::plan` (meta keys `plan`, `plan_device_limit`, `plan_expires_at`, `plan_checked_at`) and is one of `free`, `pro` or `paused` (Pro that ended). Free never contacts the relay: `AppState::take` and the pairing commands return `needs_pro` before any request, and `relay_status` reports the cached plan offline. Every `sync_round` re-reads the entitlement first; an ended entitlement pauses sync (`sync_paused`) while local reads, writes and export keep working and changes stay queued for renewal. Revocation and key rotation stay available while paused. Operators manage entitlements with `secwet-relay admin grant|expire|ungrant|status`.

## Platform traits

| Trait | Where | Implement it with |
| --- | --- | --- |
| `KeyStore` (`get`/`set`/`delete` of raw bytes) | `secwet_core::keys`, re-exported | Desktop: `KeyringStore` (feature `os-keyring`). iOS: Keychain (`kSecClassGenericPassword`, `ThisDeviceOnly`). Android: Keystore-wrapped values. Every key read, write and delete, including crypto-shred and remote wipe, goes through this trait only. |
| `ClipboardPort` (`write_secret`/`read_text`/`clear`) | `secwet_app::clipboard` | Desktop: `TauriClipboard`. iOS: `UIPasteboard` with `localOnly` + expiry. Android: `ClipboardManager` with `EXTRA_IS_SENSITIVE`. Passed per call as `Arc<C>` (`C` may be `dyn ClipboardPort`). |
| `EventSink` (`emit(AppEvent)`) | `secwet_app::events` | Desktop: Tauri `emit`. Mobile: post to the UI isolate/channel. Closures `Fn(AppEvent)` implement it. Must not block. |

`AppEvent::name()`/`payload()` give the wire form the desktop UI listens for:
`secwet://changed {scope}`, `secwet://locked null`, `secwet://wiped {}`,
`secwet://unlinked {}`.

Copy semantics (unchanged): the value goes to the OS clipboard with history
suppression, only its SHA-256 is kept, and after 30 s (`clear_duration`,
`SECWET_TEST_CLIPBOARD_CLEAR_MS` in tests) the clipboard is cleared if it
still holds that value. A newer copy cancels the older timer.

## Runtime

Async methods are plain futures (no runtime of their own). Background work
(the clipboard timer) runs on `secwet_app::runtime`: the desktop installs
Tauri's tokio handle with `runtime::install`; otherwise the app layer starts
one multi-thread runtime on first use. FFI entry points can call
`runtime::block_on(fut)` from a non-runtime thread.

## Features and targets

- `secwet-core` feature `os-keyring` (default) gates `KeyringStore` and the
  `keyring` crate. The workspace dependency has `default-features = false`;
  desktop and CLI enable it explicitly.
- `secwet-app` feature `os-keyring` (default) forwards it and enables
  `AppState::default_state`/`resolve_keystore`.
- Mobile checks:
  - `cargo check -p secwet-app --no-default-features --target aarch64-apple-ios-sim`
  - `cargo ndk -t arm64-v8a check -p secwet-app --no-default-features`
    (`ANDROID_NDK_HOME=~/Library/Android/sdk/ndk/28.2.13676358`)
- `commands::system_device_name()` returns "Phone" on iOS/Android, since apps
  cannot run `hostname` there; mobile hosts pass the real device name to
  `secwet_create`/`workspace_restore`/`invitation_accept`.

## Tests

The command tests moved with the code: `crates/secwet-app/tests/` (lifecycle,
CRUD, clipboard adversarial, concurrency, recovery, events). They drive
`AppState` directly with `MemoryStore` and a mock `ClipboardPort`.
