# Project: Secwet Milestone 3 (Recovery and Export)

## Architecture

Milestone 3 implements non-custodial disaster recovery and encrypted offline backups across three layers:
1. **Core Cryptography and Storage (`crates/secwet-core`, `crates/secwet-proto`)**:
   - 125-bit entropy generation formatted as 25 Crockford base32 characters in 5 groups of 5 (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`).
   - Normalization: upper-casing, stripping hyphens/whitespace, Crockford alias substitution (`I`/`L` -> `1`, `O` -> `0`).
   - $K_r$ key derivation via HKDF-SHA256 (`salt = secwet_id`, `info = "secwet/v1/recovery"`).
   - `recovery_check` verification seal ($XChaCha20Poly1305_{K_r}(\text{"secwet-recovery-check"})$).
   - Wrapping master keys across all active epochs under $K_r$.
   - Snapshot serialization: canonical `postcard` byte serialization of `SecwetSnapshot` containing spaces, labels, items, environments, secrets, notes, and file attachments.
   - Encrypted `.secwet` envelope: JSON envelope containing metadata, version 1, random 24-byte nonce, ciphertext sealed with $XChaCha20Poly1305_{K_r}$, and authenticated AAD bound to `("secwet-export", 1, secwet_id)`.
   - Restore workflow: envelope decryption, AAD/MAC authentication, postcard deserialization, fresh device identity generation, next master key epoch provisioned in keystore, re-encryption of all entities into target SQLite database, returning active `Secwet`.

2. **Desktop Tauri IPC & CLI (`apps/desktop/src-tauri`, `crates/secwet-cli`)**:
   - Tauri commands `recovery_key_create`, `recovery_key_replace`, `recovery_status`, `workspace_export`, and `workspace_restore`.
   - `tauri-plugin-dialog` integrated with ACL permissions in `capabilities/default.json` for native save and open file dialogs, with headless `Option<PathBuf>` parameter fallback for automated tests.
   - CLI parity: `secwet export --out <file.secwet>` prompting for recovery key without echo, and `secwet export --env <name> --format dotenv --plaintext --out .env` requiring explicit `--plaintext`.

3. **Desktop Frontend UI (`apps/desktop/src`)**:
   - Persistent `recoveryStatus` in `store.ts` querying `api.recoveryStatus()`.
   - Real `CreateRecoveryKeyDialog.tsx` calling backend derivation, with one-time view and confirmation checkbox.
   - Real `ExportDialog.tsx` collecting recovery key, invoking native save dialog, and calling `workspaceExport`.
   - First-run `OnboardingScreen.tsx` offering "Create New Workspace" or "Restore from Backup".
   - `RestoreDialog.tsx` invoked from Onboarding and `UnlockScreen.tsx` ("Restore from backup").
   - Strict adherence to `docs/ui-rules.md` (removing `ui-monospace` from `ConfirmDialog.module.css`, steady 1px borders, theme parity).

## Feature Inventory

Every feature identified in the Survey phase appears here with its assigned milestone.

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | `F-CRYPTO-1` | `create_recovery_key`: 125-bit entropy, 25 Crockford base32 chars in 5 groups, derives $K_r$, computes `recovery_check` seal, wraps master keys across epochs | M3-1 | ORIGINAL_REQUEST R2 / IMPLEMENTATION F9 |
| 2 | `F-CRYPTO-2` | `replace_recovery_key`: generates new key, re-wraps all epochs of $K_m$, overwrites `recovery_check`, invalidates old key | M3-1 | ORIGINAL_REQUEST R2 / IMPLEMENTATION F9 |
| 3 | `F-CRYPTO-3` | Recovery key normalization: lowercase, spaces, dashes, Crockford aliases (`I`/`L` -> `1`, `O` -> `0`) | M3-1 | ORIGINAL_REQUEST R2 / IMPLEMENTATION F9 |
| 4 | `F-CRYPTO-4` | `verify_recovery_key`: verifies candidate key against `recovery_check` seal without leaking details; detects wrong key | M3-1 | ORIGINAL_REQUEST R2 / IMPLEMENTATION F9 |
| 5 | `F-STORAGE-1` | `export_to_file` / `export_encrypted`: snapshots all spaces, groups, items, environments, secrets, notes, and files into postcard bytes, sealed with $K_r$ and authenticated AAD into `.secwet` envelope | M3-1 | ORIGINAL_REQUEST R2 / IMPLEMENTATION F10 |
| 6 | `F-STORAGE-2` | `restore_from_export`: decrypts `.secwet` envelope, verifies AAD/MAC, deserializes postcard snapshot, provisions new device keys & next master key epoch, re-encrypts into SQLite database with 100% data fidelity | M3-1 | ORIGINAL_REQUEST R2 / IMPLEMENTATION F10 |
| 7 | `F-IPC-1` | Tauri commands `recovery_key_create`, `recovery_key_replace`, `recovery_status` with pure `*_impl` architecture | M3-2 | ORIGINAL_REQUEST R3 |
| 8 | `F-IPC-2` | Tauri commands `workspace_export` and `workspace_restore` with `tauri-plugin-dialog` native dialogs, ACL permissions, and `Option<PathBuf>` headless test fallback | M3-2 | ORIGINAL_REQUEST R3 |
| 9 | `F-CLI-1` | `secwet export --out <file.secwet>` prompting for recovery key without echo (e.g. `rpassword`) | M3-2 | ORIGINAL_REQUEST R5 |
| 10 | `F-CLI-2` | `secwet export --env <name> --format dotenv --plaintext --out .env` requiring explicit `--plaintext` confirmation flag | M3-2 | ORIGINAL_REQUEST R5 |
| 11 | `F-UI-1` | Typography & dead code audit: remove `ui-monospace` from `ConfirmDialog.module.css` (line 12), remove dead `RecoveryScreen.tsx` | M3-3 | ORIGINAL_REQUEST R1 / docs/ui-rules.md |
| 12 | `F-UI-2` | State persistence: `store.ts` tracks `recoveryStatus`, queries `api.recoveryStatus()`, wires actions, non-mock Tauri IPC delegation with mock fallback | M3-3 | ORIGINAL_REQUEST R1 & R4 |
| 13 | `F-UI-3` | `CreateRecoveryKeyDialog.tsx`: real backend key generation, one-time view, copy button, confirmation checkbox | M3-3 | ORIGINAL_REQUEST R4 |
| 14 | `F-UI-4` | `ExportDialog.tsx`: recovery key input, native save dialog trigger, real `.secwet` file export, updated M2 entity summary | M3-3 | ORIGINAL_REQUEST R4 |
| 15 | `F-UI-5` | `OnboardingScreen.tsx`: first-run screen when `uninitialized`, offering "Create New Workspace" or "Restore from Backup" | M3-3 | ORIGINAL_REQUEST R4 |
| 16 | `F-UI-6` | `RestoreDialog.tsx`: backup file selector, recovery key input, device name input, wired to Onboarding and `UnlockScreen.tsx` | M3-3 | ORIGINAL_REQUEST R4 |
| 17 | `F-INVARIANT-1` | Invariant tests in `secwet-core`: `export_then_restore_roundtrip`, `export_wrong_key_fails_without_detail`, `export_file_contains_no_plaintext` | M3-1 | ORIGINAL_REQUEST Verification |
| 18 | `F-INVARIANT-2` | Invariant test in `secwet-cli`: `dotenv_export_requires_plaintext_flag` | M3-2 | ORIGINAL_REQUEST Verification |
| 19 | `F-E2E-1` | Reference `.secwet` export fixtures and roundtrip test suite across Tiers 1-4 | M3-4 | ORIGINAL_REQUEST R6 |
| 20 | `F-E2E-2` | Live roundtrip verification (create -> populate -> recovery key -> export -> clean restore -> verify) documented in `walkthrough.md` | M3-4 | ORIGINAL_REQUEST R6 |

## Milestones

| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M3-1 | Core Cryptography and Storage | `F-CRYPTO-1`, `F-CRYPTO-2`, `F-CRYPTO-3`, `F-CRYPTO-4`, `F-STORAGE-1`, `F-STORAGE-2`, `F-INVARIANT-1` | none | DONE |
| M3-2 | Desktop Tauri IPC & CLI Parity | `F-IPC-1`, `F-IPC-2`, `F-CLI-1`, `F-CLI-2`, `F-INVARIANT-2` | M3-1 | DONE |
| M3-3 | Desktop UI Integration & UI/UX Audit Fixes | `F-UI-1`, `F-UI-2`, `F-UI-3`, `F-UI-4`, `F-UI-5`, `F-UI-6` | M3-2 | DONE |
| M3-4 | Final Milestone: E2E Verification & Adversarial Hardening | `F-E2E-1`, `F-E2E-2`, full verification suites, live roundtrip, `walkthrough.md` | M3-3, E2E Test Suite | DONE |

## Interface Contracts

### `secwet-core` Public Recovery & Export API
```rust
impl Secwet {
    pub fn create_recovery_key(&mut self, keystore: &dyn KeyStore) -> Result<SecretString, Error>;
    pub fn replace_recovery_key(&mut self, keystore: &dyn KeyStore) -> Result<SecretString, Error>;
    pub fn verify_recovery_key(&self, input: &str) -> Result<bool, Error>;
    pub fn recovery_status(&self) -> Result<RecoveryStatus, Error>;
    pub fn export_encrypted(&self, recovery_key: &SecretString, out: &Path) -> Result<ExportSummary, Error>;
    pub fn restore_from_export(
        data_dir: &Path,
        file: &Path,
        recovery_key: &SecretString,
        device_name: &str,
        keystore: &dyn KeyStore,
    ) -> Result<Secwet, Error>;
}
```

### Tauri IPC Commands (`apps/desktop/src-tauri`)
```rust
#[tauri::command]
pub fn recovery_key_create(app: AppHandle, state: State<'_, AppState>) -> Result<String, UiError>;

#[tauri::command]
pub fn recovery_key_replace(app: AppHandle, state: State<'_, AppState>) -> Result<String, UiError>;

#[tauri::command]
pub fn recovery_status(state: State<'_, AppState>) -> Result<RecoveryStatusDto, UiError>;

#[tauri::command]
pub fn workspace_export(
    app: AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    recovery_key: String,
) -> Result<ExportSummaryDto, UiError>;

#[tauri::command]
pub fn workspace_restore(
    app: AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    recovery_key: String,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError>;
```

### Frontend TypeScript API (`apps/desktop/src/lib/api.ts`)
```typescript
recoveryCreate: () => Promise<string>;
recoveryKeyReplace: () => Promise<string>;
recoveryStatus: () => Promise<{ created: boolean; createdAt?: number }>;
workspaceExport: (filePath: string, recoveryKey: string) => Promise<ExportSummaryDto>;
workspaceRestore: (filePath: string, recoveryKey: string, deviceName?: string) => Promise<SecwetStatus>;
```

## Code Layout

- `crates/secwet-core/src/`:
  - `crypto.rs`: Recovery key formatting, normalization, parsing, HKDF derivation, raw sealing/opening with AAD.
  - `model.rs` / `records.rs`: `SecwetSnapshot`, `SecwetExportEnvelope`, `ExportAad`, `ExportSummary`, `RecoveryStatus`.
  - `secwet.rs`: Implementation of `create_recovery_key`, `replace_recovery_key`, `verify_recovery_key`, `recovery_status`, `export_encrypted`, `restore_from_export`.
  - `tests/recovery_export_tests.rs`: Invariant tests (`export_then_restore_roundtrip`, `export_wrong_key_fails_without_detail`, `export_file_contains_no_plaintext`, `replace_recovery_key_invalidates_old`).
- `crates/secwet-cli/`:
  - `src/main.rs` & `src/commands/export.rs`: Export CLI command with `--plaintext` flag check and `.secwet` envelope handling.
  - `tests/cli_tests.rs`: `dotenv_export_requires_plaintext_flag`, `cli_export_secwet_roundtrip`.
- `apps/desktop/src-tauri/`:
  - `Cargo.toml`: Add `tauri-plugin-dialog = "2"`.
  - `capabilities/default.json`: Add dialog permissions (`dialog:default`).
  - `src/lib.rs`: Register plugin and commands in `generate_handler!`.
  - `src/commands.rs`: Implement commands and `*_impl` handlers.
- `apps/desktop/src/`:
  - `lib/api.ts` & `lib/store.ts`: IPC bindings, store state and actions.
  - `components/ConfirmDialog.module.css`: Monospace font removal.
  - `components/UnlockScreen.tsx`: Add "Restore from backup" action button.
  - `screens/onboarding/OnboardingScreen.tsx` & `.module.css`: Workspace creation vs restore selection.
  - `screens/recovery/RestoreDialog.tsx` & `.module.css`: File selection, recovery key entry, device name, restore execution.
  - `screens/recovery/CreateRecoveryKeyDialog.tsx`: Real key derivation, one-time view, confirmation check.
  - `screens/recovery/ExportDialog.tsx`: Recovery key entry, native save dialog, real export.
  - Remove dead file `screens/recovery/RecoveryScreen.tsx`.
