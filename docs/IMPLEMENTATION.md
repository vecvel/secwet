# Secwet implementation guide

This is the build plan for every Secwet feature: what each one does, how to implement it, how to handle errors and edge cases, and how to test it. It is written so that any agent can follow it step by step without guessing.

Product in one line: a passwordless, end-to-end encrypted secrets manager for developers. Local use is free; multi-device sync is the paid Pro plan. Your secrets. Your devices. Your keys.

---

## 0. Rules for whoever implements this

Read these before writing any code.

1. **Work milestone by milestone** (section 12), in order. Do not start a milestone until the previous one's "Done when" list is fully checked.
2. **Never weaken the security rules** in section 13. If a task seems to require breaking one, stop and ask a human.
3. **Never write your own cryptography.** Use only the crates named in section 4. Never change an algorithm, key size, nonce size or encoding without a human's approval.
4. **Never log, print or put secret values in error messages.** This includes secret values, encryption keys, device private keys, recovery keys and decrypted names. Use the `secrecy` crate's `SecretString` / `SecretBox` for these in Rust.
5. **Every feature ships with tests.** The tests listed for a feature are the minimum. A feature is not done until its tests pass in CI.
6. **Keep the existing UI design.** The desktop UI is already built and approved (see `docs/design-decisions.md` and `docs/ui-rules.md`). Wire it to real data; do not restyle it. If a feature needs a new screen or control, follow `docs/ui-rules.md` and get a human to approve a visual preview first.
7. **Run all checks before you say something is done** (section 11.6). Report real output; never claim a check passed if you did not run it.
8. **When unsure, ask.** Write down the question, what you checked and the options. Do not invent behavior that this document does not describe.

---

## 1. Principles the code must keep

- **Local-first.** Everything works offline on one device with no account and no server.
- **User-defined organization.** Users define how their information is organized. The sidebar handles high-level navigation (Overview, user labels, Settings), while items and their contents (secrets, files, notes, optional environments) are managed inside their respective screens. Secwet imposes no rigid project hierarchy and no mandatory environments.
- **End-to-end encrypted.** Secrets, files, notes, and names are encrypted on the device before they are stored or sent. The relay server only ever sees ciphertext and minimal routing metadata.
- **Passwordless.** No accounts, emails, passwords or OAuth. A device is identified by its own key pair. The master encryption key lives in the OS secure storage (Keychain, Credential Manager, Secret Service, Android Keystore, iOS Keychain).
- **Separation of concerns.** Device identity (signing keys), subscription authorization (relay entitlements) and data encryption (master encryption key) are separate keys and separate code paths.
- **A subscription ending never deletes or locks local data.** Only sync stops.
- **Audited libraries only**, and an independent security review before production.

Known limitations (show these in the UI and docs; never hide them):

- A revoked or stolen device keeps whatever it already decrypted. Revocation and key rotation only protect changes made afterwards.
- If every device is lost and there is no recovery key plus export (or Pro backup), Secwet data cannot be recovered. Nobody, including Secwet, can reset access.

---

## 2. Current state of the repo

| Path | What it is | State |
|---|---|---|
| `Cargo.toml` | Rust workspace: `secwet-core`, `secwet-cli`, `secwet-relay`, `apps/desktop/src-tauri` | Done |
| `crates/secwet-core/src/model.rs` | `Project`, `Environment`, `Secret`, `SecretKind` | Types only |
| `crates/secwet-core/src/crypto.rs` | `RecordCipher`, `DeviceIdentity` traits | Traits only, no implementation |
| `crates/secwet-core/src/sync.rs` | `SyncEvent` envelope struct | Struct only |
| `crates/secwet-cli/src/main.rs` | `secwet list/get/run` | Prints usage; not implemented |
| `crates/secwet-relay/src/main.rs` | Axum server with `GET /health` | Skeleton |
| `apps/desktop/src-tauri/src/lib.rs` | Tauri host, one command `core_version`, Dock icon switch | Skeleton |
| `apps/desktop/src/` | React UI: Overview, Secrets, Devices, Recovery, Settings, all dialogs | Complete UI on mock data |
| `apps/desktop/src/data/mock.ts` | Sample projects, secrets, devices | Replace with real data (M2) |
| `apps/desktop/src/data/validation.ts` | Validation helpers and ID generation | Cleaned from legacy mock prototype |
| `apps/mobile/` | Flutter shell with theme and bottom navigation | Shell only |
| `packages/design-tokens/` | Design tokens to CSS and Dart (`pnpm tokens`) | Done |
| `packages/brand/` | Logo geometry and every app icon (`pnpm brand`) | Done |
| `docs/` | Design decisions, UI rules, this guide | Done |

The UI already shows every flow described below (create, edit, delete, reveal, copy, pairing with QR and a 6-digit code, revoke, rotate key, recovery key, export, plans). Your job is to make those flows real.

---

## 3. Architecture

```
 Desktop (Tauri)              Mobile (Flutter)            CLI (Rust)
 React UI  <-- Tauri cmds -->  Dart UI <-- FFI bridge -->  clap commands
      \                          |                          /
       \______________  secwet-core (Rust library)  ________/
                       |  crypto, store, storage, sync  |
                       |  SQLite file + OS keychain     |
                                  |
                       HTTPS + WebSocket (TLS 1.3)
                                  |
                        secwet-relay (Axum + PostgreSQL)
                        stores: device public keys, entitlements,
                        encrypted events, latest encrypted snapshot
```

- **secwet-core** owns all logic: keys, encryption, the local database, the record model, sync and conflict resolution. Apps are thin layers that call it.
- **Desktop** calls core through Tauri commands (section 9). The webview never sees keys and only sees a secret value when the user reveals it.
- **CLI** links secwet-core directly and opens the same local Secwet store as the desktop app on that machine.
- **Mobile** calls core through `flutter_rust_bridge` bindings in a new crate `crates/secwet-ffi`.
- **Relay** is only used on the Pro plan. Free plans never contact it.

Trust boundaries: the device is trusted while unlocked. The relay is untrusted for confidentiality and integrity: it can delay, drop or reorder events, but it cannot read or forge them. The network is untrusted.

### 3.1 Crates to add to the workspace

| Crate | Purpose |
|---|---|
| `crates/secwet-core` (exists) | Library: `crypto`, `keys`, `store`, `vault`, `records`, `sync`, `pairing`, `recovery`, `export`, `relay_client` modules |
| `crates/secwet-proto` (new) | Shared wire types used by core and relay: request and response bodies, event envelope, error codes. No crypto, no IO |
| `crates/secwet-ffi` (new, M9) | `flutter_rust_bridge` API for mobile |
| `crates/secwet-relay` (exists) | Server |
| `crates/secwet-cli` (exists) | CLI |

---

## 4. Cryptography specification

Use only these crates (latest stable versions; pin them in the workspace `Cargo.toml`):

| Need | Crate | Notes |
|---|---|---|
| Record and event encryption | `chacha20poly1305` (XChaCha20Poly1305) | 32-byte key, 24-byte random nonce per message |
| Key derivation | `hkdf` + `sha2` (HKDF-SHA256) | |
| Device signatures | `ed25519-dalek` | Strict verification (`verify_strict`) |
| Key agreement for pairing | `x25519-dalek` | Ephemeral keys only |
| Encrypting a key to a device | `hpke` (RFC 9180) | Mode Base, X25519-HKDF-SHA256, HKDF-SHA256, ChaCha20Poly1305 |
| Randomness | `rand_core::OsRng` / `getrandom` | Never use a seeded or thread RNG for keys |
| Secret memory | `zeroize`, `secrecy` | Zeroize all key material on drop |
| Constant-time compare | `subtle` | For codes and MAC-like comparisons |
| Canonical bytes | `postcard` | Every signed or AAD byte string is `postcard::to_stdvec` of the exact structs in this document. Never sign JSON |
| OS secure storage | `keyring` | Desktop and CLI. Mobile uses platform storage through the FFI layer |
| Base32 | `data-encoding` (Crockford alphabet) | Recovery key and fingerprints |

### 4.1 Keys

| Key | Size | Created | Stored | Never leaves |
|---|---|---|---|---|
| Device signing key (Ed25519) | 32 B seed | First launch on each device | OS secure storage, entry `secwet/<vault_id>/device-sign` | The device |
| Device encryption key (X25519, for HPKE) | 32 B | First launch on each device | OS secure storage, `secwet/<vault_id>/device-enc` | The device |
| Master encryption key `K_v` (per epoch) | 32 B random | Workspace creation, and each key rotation | OS secure storage, `secwet/<vault_id>/vault-key/<epoch>` | Paired devices (sent only HPKE-encrypted to approved devices) |
| Record key `K_rec` | 32 B | Derived: `HKDF(ikm=K_v, salt=vault_id bytes, info="secwet/v1/record")` | Memory only | |
| Event key `K_evt` | 32 B | Derived: `HKDF(ikm=K_v, salt=vault_id bytes, info="secwet/v1/event")` | Memory only | |
| Recovery key | 125 bits, shown as 25 Crockford base32 chars in groups of 5 (the UI already does this) | User clicks Create | Never stored by Secwet; the user stores it | The user |
| Recovery wrap key `K_r` | 32 B | Derived: `HKDF(ikm=recovery key bytes, salt=vault_id bytes, info="secwet/v1/recovery")` | Memory only | |

- **Device id** = first 26 characters of Crockford base32 of `SHA-256(ed25519 public key)`.
- **Fingerprint** shown in the UI (for example `7F3A 18E0 91C2`) = the first 6 bytes of `SHA-256(ed25519 public key || x25519 public key)` as uppercase hex in groups of 4.
- **Store / Workspace id** (`vault_id`) = UUID v4 from `OsRng`, created with the workspace.

### 4.2 Encrypting a record (local storage and sync payloads)

```rust
// In secwet-core::crypto
pub struct Sealed { pub nonce: [u8; 24], pub ciphertext: Vec<u8> } // ciphertext includes the 16-byte tag

#[derive(Serialize)]
struct RecordAad<'a> {
    format: u8,            // 1
    vault_id: &'a [u8; 16],
    record_id: &'a [u8; 16],
    record_type: u8,       // 1 label, 2 item, 3 environment, 4 secret, 5 file, 6 note
    key_epoch: u32,
}

pub fn seal_record(k_rec: &Key, aad: &RecordAad, plaintext: &[u8]) -> Sealed;
pub fn open_record(k_rec: &Key, aad: &RecordAad, sealed: &Sealed) -> Result<SecretVec<u8>, CryptoError>;
```

- Nonce: 24 random bytes from `OsRng` for every seal. Never reuse.
- AAD binds the ciphertext to its workspace / store, record id, type and key epoch, so a ciphertext cannot be moved to another record or workspace without failing decryption.
- Stored bytes layout (`blob` columns): `version (1 byte = 1) || nonce (24) || ciphertext`.

### 4.3 Encrypting a key for another device (HPKE)

Used for master encryption key provisioning during pairing and for key rotation.

```rust
pub fn wrap_for_device(recipient_x25519_pub: &[u8; 32], info: &[u8], plaintext_key: &[u8; 32]) -> WrappedKey; // { enc: [u8;32], ciphertext: Vec<u8> }
pub fn unwrap_for_me(my_x25519_secret: &StaticSecret, info: &[u8], wrapped: &WrappedKey) -> Result<SecretBox<[u8;32]>, CryptoError>;
```

`info` = `postcard(KeyWrapInfo { purpose: "vault-key", vault_id, key_epoch, recipient_device_id })`.

### 4.4 Signing

Everything a device sends to the relay is signed with its Ed25519 key: request headers (section 8.2), sync event envelopes (section 7.15) and pairing approvals (section 7.14). Verify with `verify_strict`.

---

## 5. Data model and local storage

### 5.1 Records

```rust
// secwet-core::records (flexible organization model)
pub struct LabelBody { pub name: String, pub position: u32, pub icon: Option<String> }
pub struct ItemBody { pub label_id: Uuid, pub name: String, pub description: Option<String>, pub position: u32 }
pub struct EnvironmentBody { pub item_id: Uuid, pub name: String, pub position: u32 }
pub struct SecretBody {
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>, // None when content is at item-level
    pub name: String,                 // regex ^[A-Za-z_][A-Za-z0-9_.@-]*$ , 1..=128 chars
    pub kind: SecretKind,             // password | api_key | access_token | env_var | ssh_key | certificate
    pub value: SecretString,          // 0..=64 KiB, any UTF-8 (multi-line allowed for keys and certs)
    pub note: Option<String>,         // 0..=500 chars
}
pub struct FileMetaBody {
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,                 // 1..=255 chars
    pub size_bytes: u64,              // <= 50 MiB limit
    pub mime_type: String,
    pub sha256: [u8; 32],
}
pub struct NoteBody {
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub title: String,                // 1..=128 chars
    pub content: String,              // Rich text HTML/Markdown with formatting
    pub position: u32,
}
pub struct RecordMeta { pub id: Uuid, pub lamport: u64, pub origin_device: DeviceId, pub updated_at: i64, pub deleted: bool }
```

Validation rules:

- Label names: unique per workspace / store, case-insensitive, trimmed, 1 to 64 chars.
- Item names: unique per label, case-insensitive, trimmed, 1 to 64 chars.
- Environment names: unique per item, case-insensitive, 1 to 64 chars. Environments are **optional**; new items do not create default environments.
- Secret names: unique per environment (or per item when item-level), case-sensitive, must match regex.
- File names: unique per container (item or environment), 1 to 255 chars, max 50 MiB.
- Note titles: 1 to 128 chars; rich-text notes can be multiple per item or environment.

### 5.2 SQLite schema

File: `<data_dir>/vaults/<vault_id>/vault.sqlite3`. Open with `rusqlite` (feature `bundled`), `PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;`.

```sql
CREATE TABLE meta (            -- plaintext, non-secret
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
); -- schema_version, vault_id, created_at, current_key_epoch, device_id, plan, relay_url

CREATE TABLE labels (          -- user-defined organizational labels
  id BLOB PRIMARY KEY,         -- 16-byte UUID v7
  name_blob BLOB NOT NULL,     -- sealed with K_rec
  position INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE records (         -- items, environments, secrets, files, notes
  id BLOB PRIMARY KEY,         -- 16-byte UUID v7
  record_type INTEGER NOT NULL,-- 1 label, 2 item, 3 environment, 4 secret, 5 file, 6 note
  parent_id BLOB,              -- label_id for items; item_id for environments/item-level content; environment_id for env-level content
  key_epoch INTEGER NOT NULL,
  blob BLOB,                   -- sealed body (section 4.2); NULL when deleted
  lamport INTEGER NOT NULL,
  origin_device TEXT NOT NULL,
  updated_at INTEGER NOT NULL, -- unix ms, informational
  deleted INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX records_parent ON records(parent_id);
CREATE INDEX records_type ON records(record_type);

CREATE TABLE devices (         -- devices paired with this workspace
  device_id TEXT PRIMARY KEY,
  name_blob BLOB NOT NULL,     -- device name, sealed with K_rec
  sign_pub BLOB NOT NULL,
  enc_pub BLOB NOT NULL,
  added_at INTEGER NOT NULL,
  revoked_at INTEGER,
  last_seen_at INTEGER
);

CREATE TABLE outbox (          -- local changes not yet accepted by the relay (Pro only)
  event_id BLOB PRIMARY KEY,
  device_seq INTEGER NOT NULL UNIQUE,
  envelope BLOB NOT NULL       -- postcard(SignedEvent)
);

CREATE TABLE applied_events (event_id BLOB PRIMARY KEY, server_seq INTEGER NOT NULL); -- for dedupe
CREATE TABLE sync_state (key TEXT PRIMARY KEY, value TEXT NOT NULL); -- cursor, last_snapshot_seq, last_error
CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);   -- theme, lock_minutes, home_label, dashboard_widgets
```

Rules:

- Names, values, notes and file metadata exist only inside `blob`. `parent_id`, ids, timestamps and counts are plaintext metadata.
- Migration `0002_flexible_organization.sql` migrates legacy projects into items under a default "Projects" label and adapts records smoothly without data loss.
- All writes for one user action happen in one SQLite transaction.

### 5.3 In-memory state

When unlocked, the core keeps `K_rec` and `K_evt` for the current and previous epochs in memory (zeroized on lock). Decrypted bodies are decrypted on demand and never cached longer than one call, except names, which may be cached for list views and are cleared on lock.

---

## 6. secwet-core public API

Implement `Vault` as the single entry point. Every app calls these and nothing lower.

```rust
pub struct Vault { /* db, keys, device, clock, relay client */ }

impl Vault {
    // lifecycle (F1, F2)
    pub fn status(data_dir: &Path) -> Result<VaultStatus>;           // Uninitialized | Locked{vault_id} | Unlocked
    pub fn create(data_dir: &Path, device_name: &str, keystore: &dyn KeyStore) -> Result<Vault>;
    pub fn unlock(data_dir: &Path, keystore: &dyn KeyStore) -> Result<Vault>;
    pub fn lock(self);

    // labels (F3)
    pub fn list_labels(&self) -> Result<Vec<LabelView>>;
    pub fn create_label(&mut self, name: &str, icon: Option<String>) -> Result<LabelView>;
    pub fn rename_label(&mut self, id: Uuid, name: &str) -> Result<()>;
    pub fn reorder_labels(&mut self, ids: &[Uuid]) -> Result<()>;
    pub fn delete_label(&mut self, id: Uuid) -> Result<()>;

    // items (F3)
    pub fn list_items(&self, label_id: Uuid) -> Result<Vec<ItemView>>;
    pub fn create_item(&mut self, label_id: Uuid, name: &str, description: Option<String>) -> Result<ItemView>;
    pub fn rename_item(&mut self, id: Uuid, name: &str, description: Option<String>) -> Result<()>;
    pub fn delete_item(&mut self, id: Uuid) -> Result<()>; // cascades to environments, secrets, files, notes

    // optional environments inside items (F4)
    pub fn list_environments(&self, item_id: Uuid) -> Result<Vec<EnvironmentView>>;
    pub fn add_environment(&mut self, item_id: Uuid, name: &str) -> Result<EnvironmentView>;
    pub fn rename_environment(&mut self, id: Uuid, name: &str) -> Result<()>;
    pub fn reorder_environments(&mut self, item_id: Uuid, ids: &[Uuid]) -> Result<()>;
    pub fn delete_environment(&mut self, id: Uuid) -> Result<()>; // safe deletion with content handling

    // secrets (F5) - item-level or environment-level
    pub fn list_secrets(&self, item_id: Uuid, environment_id: Option<Uuid>) -> Result<Vec<SecretMeta>>; // no values
    pub fn reveal_secret(&self, id: Uuid) -> Result<SecretString>;
    pub fn create_secret(&mut self, draft: SecretDraft) -> Result<SecretMeta>;
    pub fn update_secret(&mut self, id: Uuid, draft: SecretDraft) -> Result<SecretMeta>;
    pub fn delete_secret(&mut self, id: Uuid) -> Result<()>;
    pub fn copy_secret_to_environment(&mut self, id: Uuid, target_env: Option<Uuid>) -> Result<SecretMeta>;
    pub fn env_for(&self, item_id: Uuid, environment_id: Option<Uuid>) -> Result<Vec<(String, SecretString)>>; // for `secwet run`

    // files (F5b) - item-level or environment-level
    pub fn list_files(&self, item_id: Uuid, environment_id: Option<Uuid>) -> Result<Vec<FileMetaView>>;
    pub fn upload_file(&mut self, item_id: Uuid, environment_id: Option<Uuid>, name: &str, mime_type: &str, data: &[u8]) -> Result<FileMetaView>;
    pub fn download_file(&self, id: Uuid) -> Result<(FileMetaView, Vec<u8>)>;
    pub fn rename_file(&mut self, id: Uuid, name: &str) -> Result<()>;
    pub fn delete_file(&mut self, id: Uuid) -> Result<()>;

    // rich-text notes (F5c) - item-level or environment-level
    pub fn list_notes(&self, item_id: Uuid, environment_id: Option<Uuid>) -> Result<Vec<NoteMetaView>>;
    pub fn get_note(&self, id: Uuid) -> Result<NoteView>;
    pub fn create_note(&mut self, item_id: Uuid, environment_id: Option<Uuid>, title: &str, content: &str) -> Result<NoteView>;
    pub fn update_note(&mut self, id: Uuid, title: &str, content: &str) -> Result<NoteView>;
    pub fn delete_note(&mut self, id: Uuid) -> Result<()>;

    // overview & dashboard (F8)
    pub fn overview(&self) -> Result<Overview>;                    // counts, recent changes (names only), checklist state
    pub fn dashboard_config(&self) -> Result<DashboardConfig>;
    pub fn set_dashboard_config(&mut self, cfg: &DashboardConfig) -> Result<()>;

    // recovery and export (F9, F10)
    pub fn create_recovery_key(&mut self) -> Result<SecretString>; // returns the key once
    pub fn recovery_status(&self) -> Result<RecoveryStatus>;
    pub fn export_encrypted(&self, recovery_key: &SecretString, out: &Path) -> Result<ExportSummary>;
    pub fn restore_from_export(data_dir: &Path, file: &Path, recovery_key: &SecretString, device_name: &str, keystore: &dyn KeyStore) -> Result<Vault>;

    // devices, pairing, sync (F12 to F16), Pro only
    pub fn devices(&self) -> Result<Vec<DeviceView>>;
    pub fn start_pairing(&mut self) -> Result<PairingSession>;     // QR payload + expiry
    pub fn pairing_state(&self, session: &PairingSession) -> Result<PairingState>; // Waiting | Found{name, platform, fingerprint, code} | Expired
    pub fn approve_pairing(&mut self, session: &PairingSession) -> Result<DeviceView>;
    pub fn join_by_pairing(data_dir: &Path, qr_payload: &str, device_name: &str, keystore: &dyn KeyStore) -> Result<JoinProgress>;
    pub fn revoke_device(&mut self, device: &DeviceId) -> Result<()>;
    pub fn rotate_vault_key(&mut self) -> Result<u32>;             // new epoch (rotates master encryption key)
    pub fn sync_now(&mut self) -> Result<SyncReport>;

    // settings (F17)
    pub fn settings(&self) -> Result<Settings>;
    pub fn set_settings(&mut self, s: Settings) -> Result<()>;
}

pub trait KeyStore { fn get(&self, entry: &str) -> Result<Option<SecretVec<u8>>>; fn set(&self, entry: &str, value: &[u8]) -> Result<()>; fn delete(&self, entry: &str) -> Result<()>; }
```

Provide `KeyringStore` (desktop and CLI, using `keyring`) and `MemoryStore` (tests only, behind `#[cfg(any(test, feature = "test-util"))]`).

### 6.1 Error type

```rust
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Secwet is locked")] Locked,
    #[error("Secwet is uninitialized on this device")] NoVault,
    #[error("not found")] NotFound,
    #[error("{field}: {message}")] Invalid { field: &'static str, message: String }, // user-facing, no secret data
    #[error("name already used")] Duplicate { field: &'static str },
    #[error("cannot delete the last environment")] LastEnvironment,
    #[error("needs the Pro plan")] NeedsPro,
    #[error("device limit reached")] DeviceLimit,
    #[error("this device was revoked")] Revoked,
    #[error("wrong recovery key or damaged file")] RecoveryFailed,
    #[error("sync is offline")] Offline,
    #[error("relay error: {code}")] Relay { code: String },
    #[error("secure storage error")] KeyStore,
    #[error("storage error")] Storage,      // wrap rusqlite errors without their text
    #[error("crypto error")] Crypto,        // never say which check failed
}
```

Every error crossing to the UI is mapped to a code plus the UI message already written in the dialogs (for example "A project called X already exists.").

---

## 7. Feature specifications

Each feature lists: behavior, implementation steps, edge cases, and tests. Test names are the names to use.

### F1. First run and workspace creation

Behavior: on first launch Secwet is uninitialized. The app initializes silently (no setup wizard, no password): it generates device keys and the master encryption key, stores them in the OS secure storage and opens the Overview. The device name defaults to the OS host name (editable later in Settings).

Steps:
1. `Vault::status` finds no `meta` row: return `Uninitialized`.
2. `Vault::create`: generate Ed25519 and X25519 device keys, vault id, `K_v` epoch 1. Store keys with `KeyStore::set` before creating the database (if the keychain write fails, abort and create nothing).
3. Create the database, run migrations, write `meta`, insert this device into `devices`.
4. Seed nothing. The UI shows "Create your first project" (already built).

Edge cases: keychain unavailable (Linux without Secret Service): show an error explaining what to install; never fall back to storing keys in plaintext. A database exists but its keys are missing (keychain wiped): treat as `Locked` and offer "Restore from export" (F10); do not initialize a second store silently.

Tests: `create_writes_keys_before_db`, `create_fails_cleanly_when_keystore_fails`, `status_uninitialized_then_unlocked`, `db_contains_no_plaintext_names` (create a project and secret, then scan the raw SQLite file bytes for the name and value strings; none may appear).

### F2. Lock, unlock and auto-lock

Behavior: Secwet is unlocked while the app runs. After the idle time chosen in Settings (5, 15, 30 or 60 minutes; default 15) it locks: keys are zeroized, revealed values hide, and the UI shows a locked state with an Unlock button. Unlock reads the keys from the OS secure storage again (the OS may ask for Touch ID or the login password). The CLI unlocks per command.

Steps: an idle timer in each app (desktop: reset on any UI input event and on Tauri commands); on expiry call `Vault::lock`. On macOS, store keychain items with access control requiring user presence when the user enables "Require Touch ID to unlock" (a later setting; default off).

Tests: `lock_zeroizes_keys` (use a test hook that checks the key buffers are zero), `calls_fail_with_locked_after_lock`, desktop Playwright test `auto_lock_hides_values` with a 1-minute test override.

### F3. User-defined labels and items: create, rename, reorder, delete

UI:
- **Sidebar**: Displays user-defined labels directly (e.g. Projects, Passwords, Personal, Work, Clients). A `+` button in the sidebar allows adding new labels. Labels can be renamed, reordered, and deleted.
- **Label Screen**: Clicking a label in the sidebar navigates to that label's screen. Shows the list of items belonging to the label with search, sorting, and an "Add item" button.
- **Item Creation**: Simple, focused dialog asking only for basic item information (name, description). **Does not display an Environments field, does not require environments, and does not create default environments.**
- **Item Screen**: Clicking an item opens its dedicated screen with:
  - Header: Item name, description, actions (rename, delete, add environment).
  - Internal content navigation: Tabs for Secrets, Files, Notes, and Environments (when present).
  - Main content area: Displays the selected content section.
- **Global Sidebar Rule**: Items, individual secrets, files, notes, and environments **never** appear as sidebar navigation entries.

Steps:
1. `create_label`: validate, write label record, bump lamport.
2. `create_item`: validate name, associate with `label_id`, seal body with `RecordAad` (type 2 = Item), write record in transaction.
3. `rename_item`: re-seal body with updated name/description.
4. `delete_item`: mark item, its environments, secrets, files, and notes `deleted=1`, set `blob=NULL`, bump lamport on each.

Edge cases: duplicate label or item names within the same container; deleting active item redirects back to the label screen.

Tests: `label_crud_and_reorder`, `item_creation_without_environments`, `delete_item_cascades_all_contents`.

### F4. Optional environments inside items

Behavior: Environments are optional subdivisions within an individual item. They are never mandatory and never appear in the global sidebar.

UI: Managed strictly inside the item's screen.
- If an item has no environments, no environment selector is shown, and the content tabs manage item-level secrets, files, and notes directly.
- Adding an environment introduces an Environments section/selector within that item's screen.
- Adding content while viewing an environment automatically associates the content with that environment.
- Users can switch between the item-level content view and specific environment views.

Steps:
1. `add_environment`: writes environment record with `parent_id = item_id`.
2. `rename_environment`: re-seals body with new name.
3. `delete_environment`: provides user choice to preserve environment-specific content (moving it to item-level) or delete it; never silently discards.

Tests: `item_functions_without_environments`, `add_environment_preserves_item_content`, `delete_environment_preserves_or_cascades`.

### F5. Secrets management: item-level and environment-level

UI: Managed inside `ItemScreen` under the Secrets tab.
- Works identically at the item level (no environments) and inside a selected environment.
- Context-aware secret creation dialog: when adding at item level, no environment dropdown is shown. When inside an environment, it is automatically associated.
- Row actions: reveal (eye), copy (clipboard), edit, delete, copy to environment/item.

Steps:
1. `list_secrets`: returns `SecretMeta` with masked `value_tail`. Never returns full values in lists.
2. `reveal_secret`: returns the value for one secret on demand; auto-purged on lock or row unmount.
3. `copy_secret`: executed in Rust via `tauri-plugin-clipboard-manager` with SHA-256 fingerprint verification and 30-second auto-clear timer. Webview receives unit `()` and never sees the secret value.
4. `create_secret` / `update_secret`: validates, seals with `RecordAad` (type 4 = Secret), writes in transaction.

Tests: `secret_roundtrip_multiline`, `secret_isolation_no_values_in_list`, `copy_clears_clipboard_after_30s`, `tampered_blob_fails_to_open`.

### F5b. File management: upload, preview, download, rename, delete

Behavior: Files are first-class content in Secwet, managed under an item or inside one of its environments. Supported formats include PDFs, images (PNG, JPEG, SVG, WebP), Markdown, spreadsheets (CSV, XLSX), plain text, and documents.

UI: Managed inside `ItemScreen` under the Files tab.
- Drag-and-drop or file picker upload.
- Displays filename, file size, MIME type, and upload date.
- In-app preview for supported formats (images, markdown, text, PDFs).
- Download / open action for all formats.
- Delete and rename actions with confirmation.

Steps:
1. `upload_file`: Reads bytes, computes SHA-256, validates size (max 50 MiB). Encrypts file metadata and data chunks with `XChaCha20Poly1305` bound by `RecordAad` (type 5 = File).
2. `download_file`: Fetches sealed record, verifies AAD and MAC, decrypts into memory, writes to user-selected download path via OS save dialog.
3. `delete_file`: Marks file record deleted.

Tests: `file_upload_download_roundtrip_encrypted`, `file_tampered_blob_fails_decryption`, `file_preview_supported_formats`.

### F5c. Rich-text notes: formatting toolbar, clipboard support, Copy as Plain Text

Behavior: Each item and each environment supports multiple independent rich-text notes with meaningful titles.

UI: Managed inside `ItemScreen` under the Notes tab.
- List of notes with title, last updated timestamp, and snippet preview.
- Rich-text editor with full formatting toolbar:
  - Headings (H1–H3) and paragraphs
  - Bold, italic, underline, strikethrough
  - Ordered and unordered lists, nested lists
  - Inline code, code blocks, blockquotes
  - Tables, text alignment, hyperlinks
  - Undo and redo
- Note actions: Save, rename, duplicate, delete.
- **Clipboard actions**:
  - Copy formatted note (preserves rich text).
  - Paste formatted rich text or plain text without unwanted styling.
  - **Copy as Plain Text**: Dedicated button that extracts readable plain text without HTML tags while preserving meaningful line breaks and list structure.

Steps:
1. `create_note` / `update_note`: validates title and rich-text payload, seals with `RecordAad` (type 6 = Note), writes to SQLite in transaction.
2. Note bodies are encrypted end-to-end with `K_rec`.

Tests: `note_rich_text_roundtrip`, `note_copy_as_plain_text_strips_html_preserves_structure`, `multiple_notes_per_item`.

### F7. Filter and search by name

Client-side and indexed search within the active label, item, or environment screen. Filters secrets, files, and notes by name/title.

### F8. Customizable Overview / Home dashboard

UI:
- The starting dashboard screen.
- **Editable Home Label**: Users can rename the "Home" / "Overview" label to their preferred workspace title.
- **Customizable Widgets**:
  - Show or hide individual KPI cards (Items, Secrets, Files, Notes, Active Devices).
  - Add, remove, and reorder dashboard widgets (Recent Secrets, Recent Notes, Quick Actions, Setup Checklist).
  - Persist dashboard configuration in SQLite `settings` table (`dashboard_widgets`, `home_label`).
  - Useful default widget set for new users, independent of hardcoded project or environment assumptions.

Core: `Vault::overview()` returns updated counts across labels, items, secrets, files, notes, and devices. `Vault::dashboard_config()` and `set_dashboard_config()` read/write widget layout.

Tests: `dashboard_preferences_persist_across_restart`, `overview_counts_match_all_content_types`.

| Step | Done when |
|---|---|
| Secwet initialized on this device | always true once initialized |
| Create a recovery key | `recovery_status().created_at.is_some()` |
| Connect the command line | the CLI has run `secwet` at least once against this workspace (the CLI writes `meta.cli_last_used_at`), or the user copied the command in the app |
| Add another device | Pro plan and more than one active device |
| Rotate the encryption key (only shown when needed) | a device was revoked after the last rotation |

Tests: `overview_counts_match_records`, `overview_recent_sorted_and_limited`, `checklist_reflects_state`.

### F9. Recovery key

UI (exists): Recovery and backup screen, Create or Replace, a dialog that shows the key once with Copy and the "I have stored my recovery key" checkbox.

Steps:
1. `create_recovery_key`: generate 16 random bytes, keep 125 bits, format as 25 Crockford base32 chars in 5 groups. Derive `K_r` (section 4.1). Store in `meta`: `recovery_created_at` and `recovery_check` = `seal(K_r, "secwet-recovery-check")` (lets the app verify a typed key later). Store `recovery_wrapped_vault_keys` = each epoch's `K_v` sealed with `K_r`.
2. Return the key string once. Never store it.
3. Replacing a key: generate a new one, re-wrap all epochs, delete the old wrapped copies. Old exports still need the old key (the dialog already says so).
4. Pro: also upload `recovery_wrapped_vault_keys` to the relay (ciphertext only) so a brand-new device plus the recovery key can restore from the relay snapshot (F15.6).

Edge cases: user types the key with lowercase letters, spaces or dashes: normalize (uppercase, remove spaces and dashes; map I and L to 1 and O to 0, as Crockford does).

Tests: `recovery_key_format`, `recovery_key_normalizes_input`, `recovery_check_detects_wrong_key`, `replace_recovery_key_invalidates_old`.

### F10. Encrypted export and restore

UI (exists): Export dialog (currently says saving is not available yet; replace that message with a save dialog using `tauri-plugin-dialog`).

Export file `secwet-export-YYYYMMDD.secwet`:

```
{ "format": "secwet-export", "version": 1, "vault_id": "...", "created_at": 1730000000000,
  "kdf": "hkdf-sha256", "cipher": "xchacha20poly1305", "nonce": "<base64>", "ciphertext": "<base64>" }
```

`ciphertext` = `seal(K_r, postcard(VaultSnapshot { projects, environments, secrets with values, settings, key_epoch }))`, AAD = `postcard(("secwet-export", 1u8, vault_id))`.

Restore (`restore_from_export`): used on a new device or after a reinstall. Asks for the file and the recovery key, decrypts, creates a fresh local store with the same store id and data, new device keys, and the next key epoch. On Pro it must then be re-approved by another device or re-registered as the workspace's first device if no active devices remain (section 8 endpoint `POST /v1/vaults/{id}/recover`).

CLI: `secwet export --out file.secwet` (asks for the recovery key on the terminal without echo) and `secwet export --env production --format dotenv --plaintext --out .env` (plaintext requires the explicit `--plaintext` flag and prints a warning).

Tests: `export_then_restore_roundtrip`, `export_wrong_key_fails_without_detail`, `export_file_contains_no_plaintext`, `dotenv_export_requires_plaintext_flag`.

### F11. Command line

```
secwet list   [--item I | --project P] [--env E]           # names and kinds, never values
secwet get    NAME [--item I | --project P] [--env E]      # prints one value to stdout (for piping)
secwet run    [--item I | --project P] [--env E] -- CMD... # runs CMD with the container's secrets as env vars
secwet set    NAME [--item I | --project P] [--env E] [--kind K]  # reads the value from stdin
secwet import FILE.env [--item I | --project P] [--env E]  # adds or updates secrets from a dotenv file
secwet export ...                                          # see F10
secwet status                                              # store id, device, plan, sync state
```

- Use `clap` (derive). Supports `--item` (with `--project` as a backwards-compatible alias). If the item has no environments, `--env` is optional and omitted. `--item` and `--env` default to values in a `.secwet.toml` in the current directory or any parent (`item = "payments-api"`).
- `run`: build child environment from parent plus secrets, spawn with `std::process::Command`, forward exit code. Never print secret values.
- Exit codes: 0 success, 1 runtime error, 2 Secwet locked or missing, 64 usage error.
- `get` writes the value with no trailing newline when stdout is not a terminal.

Tests: `cli_list_hides_values`, `cli_run_injects_env_and_forwards_exit_code`, `cli_reads_item_from_secwet_toml`, `cli_works_without_env_flag`.

### F12. Device identity

Each device has its own Ed25519 and X25519 keys (F1). The Devices screen lists this device (badge "This device", key fingerprint), other active devices (last sync time, Revoke), and revoked devices.

Tests: `device_id_is_stable_hash_of_public_key`, `fingerprint_format`.

### F13. Plans and entitlements

| Plan | What it allows |
|---|---|
| Free | One device, unlimited local projects and secrets, CLI, export. No relay contact at all |
| Pro | Pairing, sync, revocation, key rotation over the relay, relay-stored encrypted snapshot for recovery, device limit from the entitlement (default 5) |

- Entitlements live on the relay (section 8.3). The client caches `plan` in `meta` and refreshes it on each sync.
- Payment integration is out of scope for this guide. Until a provider is chosen, grant Pro with the relay admin command `secwet-relay admin grant --vault <id> --devices 5 --until 2027-01-01`.
- When Pro ends: sync stops, other devices show "Paused" (UI exists), local data stays fully usable and exportable. Never delete or lock anything.
- The dev-only "Simulate plan" switch in Settings stays dev-only.

Tests: `free_plan_never_calls_relay` (a relay client mock that fails the test if called), `expired_plan_pauses_sync_keeps_local_access`.

### F14. Pairing (Pro)

UI (exists): Pair a device dialog with a QR code, a countdown, "Waiting for the new device", then the new device's name, platform, fingerprint and a 6-digit code to compare, and "Codes match, approve".

Protocol (the QR never contains the master encryption key or a reusable credential):

1. Authorized device A calls `start_pairing`: creates a relay pairing session (`POST /v1/pairing`), gets `session_id` and `expires_at` (5 minutes). Generates an ephemeral X25519 key `a`. QR payload: `secwet://pair?v=1&s=<session_id>&k=<base64url(A_eph_pub)>&r=<relay host>`.
2. New device N scans the QR (mobile) or pastes the link (desktop). It generates its device keys and an ephemeral X25519 key `n`, computes `shared = X25519(n, A_eph_pub)`, and posts to `POST /v1/pairing/{id}/join`: `{ n_eph_pub, sign_pub, enc_pub, sealed_profile }` where `sealed_profile` = device name and platform sealed with `HKDF(shared, "secwet/v1/pair-profile")`.
3. A polls `GET /v1/pairing/{id}` (or gets a WebSocket push), computes the same `shared`, opens the profile and shows it.
4. Both compute the comparison code: `SAS = HKDF(shared, salt=session_id, info=transcript)`, where `transcript = SHA-256(postcard((session_id, A_eph_pub, n_eph_pub, sign_pub, enc_pub)))`, take the first 4 bytes as a big-endian u32, modulo 1,000,000, padded to 6 digits and shown as `482 913`.
5. The user checks both screens show the same code and presses approve on A. A then: checks the device limit, wraps every `K_v` epoch to N's `enc_pub` with HPKE (section 4.3), signs an approval `postcard(Approval { vault_id, session_id, device_id, sign_pub, enc_pub, approved_at })` with A's signing key and posts `POST /v1/pairing/{id}/approve { approval, signature, wrapped_keys }`.
6. The relay verifies A's signature and A's active status, enforces the device limit, registers N, and hands `wrapped_keys` to N. N unwraps, stores the keys in its secure storage, downloads the latest snapshot and events (F15), and opens.

Edge cases: code expired (UI shows "Show a new code"); A cancels (session deleted); N joins twice (second join rejected); device limit reached (relay returns `device_limit`; UI shows the plan dialog); codes differ (user cancels; nothing is registered); relay replaces keys (the codes will not match).

Tests: `pairing_happy_path` (two `Vault`s and an in-process relay), `pairing_sas_mismatch_when_relay_swaps_key`, `pairing_qr_contains_no_key_material`, `pairing_expires_after_5_minutes` (fake clock), `pairing_respects_device_limit`, `pairing_rejects_approval_from_revoked_device`.

### F15. Sync (Pro)

#### 15.1 Events

Every local change on a Pro plan creates one event:

```rust
#[derive(Serialize, Deserialize)]
pub struct EventEnvelope {        // readable by the relay
    pub event_id: [u8; 16],       // UUID v7
    pub vault_id: [u8; 16],
    pub device_id: String,
    pub device_seq: u64,          // strictly increasing per device, starts at 1
    pub key_epoch: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,      // seal(K_evt, AAD = postcard(envelope without nonce, ciphertext, signature), postcard(EventBody))
}
pub struct SignedEvent { pub envelope: EventEnvelope, pub signature: [u8; 64] } // Ed25519 over postcard(envelope)

pub enum EventBody {              // only inside the ciphertext
    Upsert { record_id: Uuid, record_type: u8, lamport: u64, body: Vec<u8> }, // body = postcard of the record body
    Delete { record_id: Uuid, record_type: u8, lamport: u64 },
    DeviceRenamed { device_id: String, name: String },
}
```

This replaces the placeholder `SyncEvent` in `crates/secwet-core/src/sync.rs`.

#### 15.2 Sending

Write the record change and the event into `outbox` in the same SQLite transaction. A background task (desktop: Tokio task in the Tauri host; mobile: when the app is active; CLI: at the end of a write command) pushes the outbox with `POST /v1/vaults/{id}/events` in order of `device_seq`, then deletes accepted events from `outbox`. Network failures retry with exponential backoff (1 s doubling to 5 min, with jitter). The UI shows "Sync paused" only for plan problems, and "Offline, will retry" for network ones.

#### 15.3 Receiving

The device holds a WebSocket (`GET /v1/vaults/{id}/stream`) that pushes `{ "type": "events", "server_seq": N }`. On a push, at startup and every 5 minutes, it pulls `GET /v1/vaults/{id}/events?after=<cursor>&limit=500` until empty, applies each event, then posts `POST /v1/vaults/{id}/ack { server_seq }`.

#### 15.4 Applying events and resolving conflicts

For each received event, in `server_seq` order:
1. Skip if `event_id` is in `applied_events` (duplicate).
2. Verify the signature with the sender's `sign_pub` from `devices`. If the sender is unknown, refresh devices from the relay; if still unknown or revoked before the event was accepted, drop it and record a warning (no secret data in the warning).
3. Decrypt with `K_evt` of `key_epoch` (if the epoch is unknown, fetch wrapped keys first).
4. Apply with last-writer-wins per record: the stored record is replaced only if `(event.lamport, event.origin_device)` is greater than `(stored.lamport, stored.origin_device)`, compared lexicographically. A delete is a write with `deleted=1`; a later upsert with a higher lamport undoes it.
5. Lamport clock: every local write uses `lamport = max(highest lamport seen) + 1`. Every applied event updates the highest seen.
6. Parents and children: a secret or environment whose parent project or environment is deleted is hidden and not counted. If the parent is later restored by a higher-lamport upsert, the children appear again.
7. Record the event in `applied_events` and advance the cursor in the same transaction.

This makes applying events commutative and idempotent: duplicates, reordering and replays converge to the same state.

#### 15.5 Retention

The relay keeps an event until every active device has acked it, or for 30 days (`RETENTION_DAYS`), whichever comes first. It then deletes it.

#### 15.6 Snapshots and offline catch-up

- Each device uploads an encrypted snapshot (`seal(K_evt, postcard(VaultSnapshot))`) after every 200 events it applies or creates, or once a day if anything changed (`PUT /v1/vaults/{id}/snapshot { server_seq, key_epoch, nonce, ciphertext }`). The relay keeps only the newest.
- If a device's cursor is older than the oldest retained event, the relay answers `410 cursor_expired`. The device downloads the snapshot, replaces its local state with it (keeping local outbox events, which it re-applies on top with fresh lamports), then pulls events after the snapshot's `server_seq`.

Tests (all in `crates/secwet-core/tests/sync.rs` with an in-process relay and a fake clock):
`two_devices_converge_on_concurrent_edits`, `delete_vs_update_resolves_by_lamport`, `duplicate_events_applied_once`, `out_of_order_events_converge` (shuffle delivery 100 times with a fixed seed), `offline_device_catches_up`, `offline_device_after_retention_uses_snapshot`, `tampered_event_rejected`, `event_from_revoked_device_rejected`, `replayed_request_rejected` (relay side), and a property test with `proptest`: any interleaving of operations from three devices ends in identical state on all three.

### F16. Revoking devices and rotating the encryption key (Pro)

UI (exists): Revoke on a device row (confirmation explains that copies stay on the device), then a "Rotate key" notice and Recovery screen action.

Revoke: `POST /v1/vaults/{id}/devices/{device}/revoke`, signed by an active device. The relay marks the device revoked, closes its WebSocket and rejects every later request from it with `revoked`. A revoked device that comes online shows "This device was removed from Secwet" and keeps its local data read-only; it may export.

Rotate: `rotate_vault_key` creates `K_v` epoch N+1, wraps it with HPKE for each active device (including itself), posts `POST /v1/vaults/{id}/keys { epoch, wrapped: [{device_id, wrapped_key}], signature }`, and from then on seals all new records and events with the new epoch. Existing records are re-sealed with the new epoch in the background (batches of 100, each in its own transaction, then synced as normal upserts). Recovery wrapped keys are updated (F9).

Edge cases: rotating while another device is offline (it receives its wrapped key when it reconnects); two devices rotate at the same time (the relay accepts the first epoch N+1 and rejects the second with `epoch_conflict`; the loser fetches the winner's key and retries nothing); revoking yourself is not allowed in the UI.

Tests: `revoked_device_cannot_push_or_pull`, `rotation_new_writes_use_new_epoch`, `rotation_reseals_existing_records`, `revoked_device_cannot_read_after_rotation`, `concurrent_rotation_conflict`.

### F17. Consolidated Settings

The legacy Vault section and its nested items are removed from the global sidebar. Settings consolidates all application preferences, security, and device/recovery operations into dedicated, clearly named sections:

1. **General**: Appearance (system, light, dark), auto-lock time (5, 15, 30, 60 min), editable Home/Overview label, device name.
2. **Security & Encryption**: Key rotation status and prompt, zeroization policies, biometric presence (Touch ID) options.
3. **Devices**: List of active and revoked devices (migrated from former sidebar Devices), device limit indicator, pair new device, revoke device.
4. **Recovery & Backups**: Recovery key creation/replacement, encrypted `.secwet` export and restore (migrated from former sidebar Recovery).
5. **Synchronization**: Plan entitlements (Free vs. Pro), relay status, outbox count, pause/resume sync indicators.

Settings persistence: stored in SQLite `settings` table through `set_settings`.

Tests: `settings_persist_across_restart`, `settings_consolidated_navigation`, Playwright `appearance_switches_theme`.

### F18. Mobile app

Build in this order after M8, reusing secwet-core through `crates/secwet-ffi` (`flutter_rust_bridge` v2):

1. Bindings for the `Vault` API in section 6. Key storage: implement `KeyStore` in Dart with `flutter_secure_storage` (Keychain on iOS, Keystore-backed on Android) and pass it through the bridge as callbacks.
2. Screens in the same order and with the same copy as desktop: Overview, Secrets (project picker at the top), Devices, Recovery, Settings, using `apps/mobile/lib/theme/app_theme.dart` (tokens already generated).
3. Pairing on mobile: scan the QR with `mobile_scanner`. A phone can also be the approving device (shows its own QR).
4. Copy on mobile clears the clipboard after 30 seconds where the OS allows; on iOS mark the item as local-only and expiring.

Tests: Dart unit tests for view models, `flutter test` widget tests per screen, and `integration_test` for create, reveal and delete of a secret.

---

## 8. Relay server

### 8.1 Stack

Axum and Tokio, `sqlx` (PostgreSQL, compile-time checked queries, migrations in `crates/secwet-relay/migrations/`), `rustls` with TLS 1.3 only when terminating TLS directly (or a reverse proxy enforcing TLS 1.3), `tower_governor` for rate limits, `tracing` with a redaction layer (never log bodies), configuration from environment variables: `DATABASE_URL`, `SECWET_RELAY_ADDR`, `RETENTION_DAYS`, `PUBLIC_URL`.

Run on one small VM with PostgreSQL on the same machine (the initial infrastructure decision). Keep modules separate (`auth`, `pairing`, `devices`, `events`, `snapshots`, `entitlements`, `admin`) so they can be split later. Add `infra/docker-compose.yml` with `postgres` and `relay` for local development and tests.

### 8.2 Authentication of requests

Every request except `POST /v1/pairing/{id}/join` and `GET /health` carries:

```
X-Secwet-Device: <device_id>
X-Secwet-Time: <unix ms>
X-Secwet-Nonce: <16 random bytes, base64url>
X-Secwet-Signature: <base64url Ed25519 signature>
```

The signature covers `postcard(("secwet-req-v1", method, path_and_query, time, nonce, SHA-256(body)))`. The relay rejects the request if: the device is unknown or revoked; the time is more than 60 seconds away from server time; the nonce was already used by this device in the last 10 minutes (store nonces in the `seen_nonces` table, purge after 10 minutes); or the signature fails. WebSocket upgrade requests are signed the same way.

### 8.3 Database

```sql
CREATE TABLE vaults (id UUID PRIMARY KEY, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), current_epoch INT NOT NULL DEFAULT 1);
CREATE TABLE entitlements (vault_id UUID PRIMARY KEY REFERENCES vaults ON DELETE CASCADE, plan TEXT NOT NULL, device_limit INT NOT NULL, expires_at TIMESTAMPTZ);
CREATE TABLE devices (id TEXT PRIMARY KEY, vault_id UUID NOT NULL REFERENCES vaults ON DELETE CASCADE, sign_pub BYTEA NOT NULL, enc_pub BYTEA NOT NULL,
                      added_at TIMESTAMPTZ NOT NULL DEFAULT now(), revoked_at TIMESTAMPTZ, last_seen_at TIMESTAMPTZ, ack_seq BIGINT NOT NULL DEFAULT 0);
CREATE TABLE wrapped_keys (vault_id UUID, device_id TEXT, epoch INT, enc BYTEA NOT NULL, ciphertext BYTEA NOT NULL, PRIMARY KEY (vault_id, device_id, epoch));
CREATE TABLE events (server_seq BIGSERIAL PRIMARY KEY, vault_id UUID NOT NULL REFERENCES vaults ON DELETE CASCADE, event_id BYTEA NOT NULL UNIQUE,
                     device_id TEXT NOT NULL, device_seq BIGINT NOT NULL, envelope BYTEA NOT NULL, received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                     UNIQUE (device_id, device_seq));
CREATE INDEX events_vault_seq ON events (vault_id, server_seq);
CREATE TABLE snapshots (vault_id UUID PRIMARY KEY REFERENCES vaults ON DELETE CASCADE, server_seq BIGINT NOT NULL, key_epoch INT NOT NULL, nonce BYTEA NOT NULL, ciphertext BYTEA NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE recovery_blobs (vault_id UUID PRIMARY KEY REFERENCES vaults ON DELETE CASCADE, ciphertext BYTEA NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE pairing_sessions (id UUID PRIMARY KEY, vault_id UUID NOT NULL, created_by TEXT NOT NULL, expires_at TIMESTAMPTZ NOT NULL, join_payload BYTEA, approved BOOLEAN NOT NULL DEFAULT false);
CREATE TABLE seen_nonces (device_id TEXT, nonce BYTEA, seen_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (device_id, nonce));
```

The relay stores no names, values, notes or plaintext of any kind. Device names exist only inside encrypted events.

### 8.4 Endpoints

| Method and path | Who | Does | Errors |
|---|---|---|---|
| `GET /health` | anyone | `{ "status": "ok" }` | |
| `POST /v1/vaults` | first device of a workspace upgrading to Pro | registers the workspace and device (body: vault_id, sign_pub, enc_pub, proof signature) | `exists`, `not_entitled` |
| `GET /v1/vaults/{id}/entitlement` | device | plan, device_limit, expires_at | |
| `POST /v1/pairing` | active device | creates a session, 5-minute expiry | `not_entitled` |
| `POST /v1/pairing/{id}/join` | new device (unauthenticated) | stores the join payload once | `expired`, `already_joined` |
| `GET /v1/pairing/{id}` | creating device | session state and join payload | `expired` |
| `POST /v1/pairing/{id}/approve` | creating device | verifies approval, enforces device limit, registers device, stores wrapped keys | `device_limit`, `expired`, `bad_signature` |
| `GET /v1/pairing/{id}/result` | new device (signed with its new key) | its wrapped keys once approved | `pending`, `expired` |
| `GET /v1/vaults/{id}/devices` | device | device list (public keys, dates, revoked) | |
| `POST /v1/vaults/{id}/devices/{device}/revoke` | active device | revokes | `cannot_revoke_self` |
| `POST /v1/vaults/{id}/keys` | active device | new epoch with wrapped keys for every active device | `epoch_conflict` |
| `GET /v1/vaults/{id}/keys` | device | its wrapped keys for all epochs | |
| `POST /v1/vaults/{id}/events` | active device | appends signed events (max 500 per call, 256 KiB each) | `bad_signature`, `seq_gap`, `revoked`, `not_entitled` |
| `GET /v1/vaults/{id}/events?after=N&limit=500` | device | events after the cursor | `cursor_expired` (410) |
| `POST /v1/vaults/{id}/ack` | device | records the device's acked `server_seq` | |
| `GET /v1/vaults/{id}/stream` | device | WebSocket push of new `server_seq` | |
| `PUT/GET /v1/vaults/{id}/snapshot` | device | newest encrypted snapshot | |
| `PUT/GET /v1/vaults/{id}/recovery` | device / new device with proof | encrypted recovery blob (F9) | |

Error body for every failure: `{ "error": { "code": "device_limit", "message": "Device limit reached." } }` with a matching HTTP status (400, 401, 403, 404, 409, 410, 429). `code` values are a closed list in `secwet-proto`.

### 8.5 Rate limits and jobs

- Per device: 20 requests per second burst 50; per IP for unauthenticated join: 10 per minute.
- Background jobs every minute: delete expired pairing sessions, nonces older than 10 minutes, and events past retention (section 15.5).

### 8.6 Relay tests

`#[sqlx::test]` integration tests against Postgres from `infra/docker-compose.yml`: `rejects_unsigned_request`, `rejects_old_timestamp`, `rejects_reused_nonce`, `revoked_device_rejected_everywhere`, `device_limit_enforced`, `events_dedupe_by_event_id`, `seq_gap_rejected`, `retention_job_deletes_acked_events`, `cursor_expired_returns_410`, `relay_never_stores_plaintext` (send events with a known marker in the plaintext before encryption; scan every table; the marker must not appear).

---

## 9. Wiring the desktop app to the core

The UI interacts with the Rust backend via Tauri 2 commands, maintaining strict separation between presentation and cryptographic storage.

### 9.1 Tauri commands

Add in `apps/desktop/src-tauri/src/commands/*.rs`. Hold the `Vault` in `tauri::State<Mutex<Option<Vault>>>`. Every command returns `Result<T, UiError>` where `UiError { code: String, field: Option<String>, message: String }`.

| Command | Args | Returns | Called from |
|---|---|---|---|
| `vault_status` | | `VaultStatus` | `App.tsx` on load |
| `vault_create` | `device_name` | `VaultStatus` | first run |
| `vault_unlock` / `vault_lock` | | | lock screen, idle timer |
| `labels_list` | | `LabelView[]` | `Sidebar.tsx`, `LabelScreen.tsx` |
| `label_create` | `name, icon?` | `LabelView` | `Sidebar.tsx` + |
| `label_rename` / `label_delete` | `id, name?` | | `LabelScreen.tsx` header |
| `label_reorder` | `ids` | | `Sidebar.tsx` drag/reorder |
| `items_list` | `label_id` | `ItemView[]` | `LabelScreen.tsx` |
| `item_create` | `label_id, name, description?` | `ItemView` | `NewItemDialog` |
| `item_rename` / `item_delete` | `id, name?, description?` | | `ItemScreen.tsx` header |
| `environments_list` | `item_id` | `EnvironmentView[]` | `ItemScreen.tsx` |
| `environment_add` / `environment_rename` / `environment_delete` | | | `ItemScreen.tsx` Environments tab |
| `secrets_list` | `item_id, environment_id?` | `SecretMeta[]` | `ItemScreen.tsx` Secrets tab |
| `secret_reveal` | `id` | `string` | `SecretRow` eye button |
| `secret_copy` | `id` | | `SecretRow` copy button (Rust clipboard with 30s auto-clear) |
| `secret_create` / `secret_update` / `secret_delete` | | `SecretMeta` | `SecretDialog`, row menu |
| `files_list` | `item_id, environment_id?` | `FileMetaView[]` | `ItemScreen.tsx` Files tab |
| `file_upload` | `item_id, environment_id?, name, mime, bytes` | `FileMetaView` | `ItemScreen.tsx` upload |
| `file_download` | `id` | `(FileMetaView, Vec<u8>)` | file preview / download |
| `file_rename` / `file_delete` | `id, name?` | | `ItemScreen.tsx` Files tab |
| `notes_list` | `item_id, environment_id?` | `NoteMetaView[]` | `ItemScreen.tsx` Notes tab |
| `note_get` | `id` | `NoteView` | `ItemScreen.tsx` note editor |
| `note_create` / `note_update` / `note_delete` | | `NoteView` | `RichTextEditor.tsx` |
| `overview` | | `Overview` | `OverviewScreen.tsx` |
| `dashboard_get` / `dashboard_set` | | `DashboardConfig` | `OverviewScreen.tsx` customize |
| `recovery_create` / `recovery_status` | | `string` once / status | `SettingsScreen.tsx` (Recovery) |
| `export_vault` | `recovery_key` | path chosen in save dialog | `SettingsScreen.tsx` (Backups) |
| `restore_vault` | `file, recovery_key, device_name` | `VaultStatus` | first run "Restore from export" |
| `devices_list` | | `DeviceView[]` | `SettingsScreen.tsx` (Devices) |
| `device_revoke` | `device_id` | | `SettingsScreen.tsx` (Devices) |
| `vault_rotate_key` | | `epoch` | `SettingsScreen.tsx` (Security) |
| `settings_get` / `settings_set` | | `Settings` | `SettingsScreen.tsx` |
| `sync_now` | | `SyncReport` | `SettingsScreen.tsx` (Sync) |

Events emitted: `vault://changed { scope }`, `vault://locked`, `sync://status`.

### 9.2 Frontend architecture

1. **Sidebar Navigation**:
   - Contains ONLY: Overview (Home), user-defined labels, and Settings.
   - The former legacy "Vault" section is completely removed from the sidebar.
   - Items, individual secrets, files, notes, and environments **never** create separate sidebar navigation entries.
2. **Dedicated Item Screen (`ItemScreen.tsx`)**:
   - Clicking an item from a label screen opens that item's dedicated screen.
   - Header: Item name, description, actions (rename, delete, add environment).
   - Internal content tabs: Secrets, Files, Notes, and Environments (when present).
   - Content context is strictly scoped to the selected item or its active environment.
3. **Context-Aware Forms**:
   - If an item has no environments, secret, file, and note creation forms omit environment selectors entirely.
   - If viewing an environment, new content is automatically scoped to that environment.
4. **Rich-Text Notes & Clipboard Support**:
   - Full WYSIWYG editor with formatting toolbar (headings, bold, lists, tables, code blocks, links).
   - Standard copy/paste preserving formatting, plus a dedicated **"Copy as Plain Text"** button that strips HTML tags while preserving readable structure.
5. **File Management**:
   - Integrated under the Files tab of `ItemScreen`.
   - On-device encryption before writing; in-app previews for images, markdown, text, PDFs; download for all formats.
6. **Consolidated Settings**:
   - Settings is organized into clean tabs: General, Security & Encryption, Devices, Recovery & Backups, Synchronization.
7. **Customizable Dashboard**:
   - Overview title is editable (persists `home_label`).
   - KPI cards and dashboard widgets can be toggled and reordered, persisting user preferences.

---

## 10. Error handling and copy

- Show errors next to the field that caused them (dialogs already do this) or in a notice at the top of the screen for non-field errors.
- Copy rules: say what happened and what to do, no apologies, no "Error:" prefix, sentence case, no em dashes. Examples already in the UI are the reference.
- Network problems never block local work. Writes always succeed locally first; sync catches up later.
- Crypto failures say only "This item could not be decrypted." and are logged as a code with the record id, never with data.

---

## 11. Testing

### 11.1 Layers

| Layer | Tool | Where |
|---|---|---|
| Rust unit tests | `cargo test` | next to each module in `secwet-core`, `secwet-relay`, `secwet-cli` |
| Property tests | `proptest` | `crates/secwet-core/tests/convergence.rs` |
| Sync integration | in-process relay (`axum` on a random port) + two or three `Vault`s with `MemoryStore` and a fake clock | `crates/secwet-core/tests/sync.rs` |
| Relay integration | `#[sqlx::test]` with Postgres from `infra/docker-compose.yml` | `crates/secwet-relay/tests/` |
| CLI | `assert_cmd`, `predicates`, `tempfile` | `crates/secwet-cli/tests/` |
| Fuzzing | `cargo fuzz` targets for envelope parsing, export parsing, dotenv import | `fuzz/` |
| Desktop unit | `vitest` + Testing Library for the store and dialogs | `apps/desktop/src/**/*.test.tsx` |
| Desktop end to end | Playwright against `pnpm desktop:dev` with `api.ts` mocked to an in-memory backend that mirrors the Rust behavior | `apps/desktop/e2e/` |
| Native desktop smoke | build with `pnpm tauri build --debug`, launch, check the window opens and `vault_status` works (manual on macOS; WebDriver via `tauri-driver` on Linux and Windows CI) | CI |
| Mobile | `flutter test`, `integration_test` | `apps/mobile/test`, `apps/mobile/integration_test` |

### 11.2 Security tests that must always exist

`db_contains_no_plaintext_names`, `export_file_contains_no_plaintext`, `relay_never_stores_plaintext`, `tampered_blob_fails_to_open`, `tampered_event_rejected`, `replayed_request_rejected`, `pairing_qr_contains_no_key_material`, `revoked_device_cannot_read_after_rotation`, `logs_contain_no_secrets` (run a full sync scenario with `tracing` captured to a buffer and scan for the test values).

### 11.3 Test data

Use obviously fake values (`sk_test_EXAMPLE...`, `example-...`). Never use real-looking live keys in fixtures.

### 11.4 Fake clock and randomness

Inject `Clock` (now in ms) and an RNG into `Vault` through a `Deps` struct so tests can control expiry, retention and lamport ties. Production uses the system clock and `OsRng`. Never allow a seeded RNG in release builds (`#[cfg(test)]` only).

### 11.5 Continuous integration (GitHub Actions)

Jobs on every push: `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (with a Postgres service for the relay), `cargo audit`, `pnpm install --frozen-lockfile`, `pnpm typecheck`, `pnpm --filter @secwet/desktop test`, Playwright, `pnpm desktop:build`, `flutter analyze`, `flutter test`. Release jobs build signed desktop bundles per platform.

### 11.6 Commands to run before saying "done"

```bash
cargo fmt --check && cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
pnpm typecheck
pnpm desktop:build
pnpm --filter @secwet/desktop test   # this script is added in M0
cd apps/mobile && flutter analyze && flutter test
```

---

## 12. Milestones

Do them in order. Each ends with all its tests passing and every item checked.

### M0. Tooling
- [ ] Workspace dependencies from section 4 pinned in the root `Cargo.toml`.
- [ ] `secwet-proto` crate created.
- [ ] `infra/docker-compose.yml` with Postgres.
- [ ] CI workflow from section 11.5 running (jobs for later milestones may be empty).
- [ ] `vitest` and Playwright set up in `apps/desktop` with one passing smoke test each.

### M1. Core: crypto, records, local storage (no UI)
- [ ] Section 4 functions with unit tests, including tamper and AAD tests.
- [ ] Section 5 schema, migrations, `KeyringStore`, `MemoryStore`.
- [ ] F1, F2, F3, F4, F5, F6, F8 in `Vault` with their tests.
- [ ] `db_contains_no_plaintext_names` passes.

### M2. Desktop and CLI on real data (flexible organization redesign)
- [ ] Schema migration `0002_flexible_organization.sql` adding `labels` table and non-destructive migration of projects to items under "Projects" label.
- [ ] Core & Proto: `RecordType` for `Label`, `Item`, `File`, `Note` with `RecordAad` cryptographic bindings.
- [ ] Core API for labels, items, files, rich-text notes, and optional environments.
- [ ] Tauri IPC commands in section 9.1 implemented and verified.
- [ ] Desktop UI redesign:
  - Sidebar: Overview (Home), user-defined labels, and Settings. Former legacy "Vault" section removed from sidebar.
  - `LabelScreen`: lists items belonging to the selected label.
  - `ItemScreen`: header plus internal tabs for Secrets, Files, Notes, and Environments (when present).
  - Context-aware forms: no environment dropdowns when adding content to items without environments.
  - Rich-text notes editor with formatting toolbar and "Copy as Plain Text".
  - File management: upload, encrypted on-device storage, in-app previews, and downloads.
  - Overview: editable Home label and customizable dashboard widgets with persistent preferences.
  - Consolidated Settings: General, Security & Encryption, Devices, Recovery & Backups, Synchronization.
- [ ] CLI updated with `--item` and optional `--env`.
- [ ] Copy through Rust with 30-second clear and SHA-256 fingerprint verification.
- [ ] Auto-lock and unlock screen.
- [ ] All workspace tests pass (`cargo test --workspace`, `cargo clippy`, `pnpm typecheck`, `pnpm desktop:build`).

### M3. Recovery and export
- [ ] F9 and F10, CLI export, restore on first run.
- [ ] `export_file_contains_no_plaintext` passes.

### M4. Relay foundation
- [ ] Section 8.1 to 8.3, request authentication, store registration, entitlements, admin grant command.
- [ ] Relay tests for authentication and replay pass.

### M5. Pairing
- [ ] F14 end to end, desktop dialog wired, mobile not yet.
- [ ] Pairing tests pass.

### M6. Sync
- [ ] F15 complete with outbox, stream, pull, apply, ack, retention, snapshots.
- [ ] All sync tests and the convergence property test pass.

### M7. Revocation and key rotation
- [ ] F16 complete; revoked-device and rotation tests pass.

### M8. Plans in the product
- [ ] F13: plan from relay, paused state, never locks local data; Settings and Devices reflect the real plan.

### M9. Mobile
- [ ] F18 in the listed order with its tests.

### M10. Hardening and release
- [ ] Fuzz targets run for at least one hour each with no crash.
- [ ] `logs_contain_no_secrets` and every section 11.2 test pass.
- [ ] Threat model document written and reviewed by a human.
- [ ] Independent security review booked before production. Do not ship before it.
- [ ] Signed and notarized macOS build, signed Windows build, Linux packages; Icon assets from `pnpm brand` (macOS uses `icons/Assets.car`).

---

## 13. Security checklist (non-negotiable)

- [ ] No custom crypto; only the crates in section 4.
- [ ] Random nonces from `OsRng` for every encryption; never a counter shared across devices.
- [ ] AAD on every encryption, exactly as specified.
- [ ] Keys only in OS secure storage or zeroized memory; never in SQLite, files, logs, crash reports, analytics or the webview.
- [ ] The webview receives a secret value only from `secret_reveal`.
- [ ] Every relay request signed, time-checked and nonce-checked.
- [ ] The relay never receives plaintext names, values, notes, file bytes or keys.
- [ ] The pairing QR contains only a session id, an ephemeral public key and the relay host.
- [ ] Revoked devices are rejected on every endpoint; revocation is followed by a rotation prompt.
- [ ] A Pro expiry never deletes or locks local data.
- [ ] `Debug` implementations of every type holding secrets print `[redacted]`.
- [ ] Error messages never include decrypted data or which crypto check failed.
- [ ] Dependencies checked with `cargo audit` and `pnpm audit` in CI.
- [ ] Clipboard copies of secrets clear after 30 seconds.

---

## 14. Glossary

| Term | Meaning |
|---|---|
| Workspace (Store) | All items, labels, environments, secrets, files, and notes that a set of devices share |
| Label | A user-defined organizational group in the sidebar (e.g. Projects, Passwords, Personal, Work, Clients) |
| Item | The primary content container (not synonymous with a project). Can contain secrets, files, rich-text notes, and optional environments |
| Environment | An optional subdivision inside an individual item (not mandatory, never global) |
| Secret | An encrypted credential or secret string belonging to an item or environment |
| File | An encrypted document, PDF, image, spreadsheet, or markdown file belonging to an item or environment |
| Note | An encrypted rich-text note with formatting belonging to an item or environment |
| Device | One install of Secwet with its own key pair |
| Master encryption key (`K_v`) | The 32-byte master key that protects the workspace; changes on rotation (epochs) |
| Epoch | The version number of the master encryption key |
| Relay | The Pro sync server; it only forwards and stores ciphertext |
| Event | One encrypted, signed change sent through the relay |
| Lamport clock | A counter that orders changes across devices for last-writer-wins |
| Snapshot | An encrypted copy of the whole workspace / store, used to catch up after a long time offline |
| SAS | Short authentication string: the 6-digit code compared during pairing |
| HPKE | Hybrid public key encryption (RFC 9180), used to send a key to one device |
