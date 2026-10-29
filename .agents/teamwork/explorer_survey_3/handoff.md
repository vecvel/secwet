# Handoff Report: Milestone 3 Survey — Desktop Tauri IPC, Native Dialogs, and CLI Parity

**Author**: Explorer Survey 3 (`teamwork_explorer`)  
**Target Milestone**: Milestone 3 (Requirements R3 & R5 — Desktop Tauri IPC, Native Dialogs, and CLI Parity)  
**Parent Agent**: `1ebf4374-d237-49fe-9aa4-ecab43ee8aa1`  
**Date**: 2026-10-27T16:26:00Z  

---

## 1. Observation

### 1.1 Tauri Host & IPC Registration (`apps/desktop/src-tauri`)
- In `apps/desktop/src-tauri/src/lib.rs` (lines 28–111):
  - The `tauri::generate_handler![...]` registers 44 commands across lifecycle, spaces, groups, items, environments, secrets, assets, files, notes, overview, settings, projects, and active sessions.
  - **Zero recovery or export commands are registered**: `recovery_key_create`, `recovery_key_replace`, `workspace_export`, and `workspace_restore` (or `recovery_create`, `export_secwet`, `restore_secwet`) are completely absent from `generate_handler!`.
- In `apps/desktop/src-tauri/src/commands.rs` (lines 1–1517):
  - Grepping for `recovery`, `export`, or `restore` yields 0 matches. No command handlers or pure `*_impl` functions exist for recovery keys or workspace export/restore.
- In `apps/desktop/src-tauri/Cargo.toml` (lines 16–29):
  - Dependencies list: `tauri`, `serde`, `serde_json`, `secwet-core`, `secwet-proto`, `uuid`, `directories`, `secrecy`, `subtle`, `sha2`, `tokio`, and `tauri-plugin-clipboard-manager = "2"`.
  - **`tauri-plugin-dialog` is missing entirely**.
- In `apps/desktop/src-tauri/capabilities/default.json` (lines 6–13):
  ```json
  "permissions": [
    "core:default",
    "core:window:allow-start-dragging",
    "core:window:allow-toggle-maximize",
    "clipboard-manager:allow-write-text",
    "clipboard-manager:allow-read-text",
    "clipboard-manager:allow-clear"
  ]
  ```
  - **No dialog permissions exist**. Any attempt to invoke dialog commands or use dialog plugins will be rejected by Tauri 2 security ACLs.
- In `apps/desktop/package.json` (lines 13–19):
  - `@tauri-apps/plugin-dialog` is not listed in `dependencies` or `devDependencies`.

### 1.2 Frontend API & UI Screens (`apps/desktop/src`)
- In `apps/desktop/src/lib/api.ts` (lines 2060–2071):
  ```typescript
  recoveryCreate: async (): Promise<string> => {
    return mockBackend.recoveryCreate();
  },

  recoveryStatus: async (): Promise<{ created: boolean; createdAt?: number }> => {
    return mockBackend.recoveryStatus();
  },

  exportSecwet: async (recoveryKey: string): Promise<string> => {
    return mockBackend.exportSecwet(recoveryKey);
  },
  ```
  - `recoveryCreate`, `recoveryStatus`, and `exportSecwet` bypass Tauri `invoke(...)` completely and always return in-memory mock responses from `mockBackend`.
  - `recovery_key_replace` (or `recoveryReplace`) and `workspace_restore` (or `restoreSecwet`) do not exist in `api.ts`.
- In `apps/desktop/src/screens/recovery/CreateRecoveryKeyDialog.tsx` (lines 10–14):
  ```typescript
  function generateKey() {
    const bytes = crypto.getRandomValues(new Uint8Array(25));
    const chars = Array.from(bytes, (b) => ALPHABET[b % 32]).join("");
    return chars.match(/.{5}/g)!.join("-");
  }
  ```
  - The dialog generates an unseeded, pseudo-random client-side string via browser `crypto.getRandomValues` and never invokes `api` or Rust backend.
  - When `replacing={true}`, clicking "Done" only calls `onDone()` which sets React state in `App.tsx` (line 493: `onRecoveryKeyCreated={() => setRecoveryKeyCreatedAt(Date.now())}`).
- In `apps/desktop/src/screens/recovery/ExportDialog.tsx` (lines 20, 36–40):
  ```typescript
  <Button variant="primary" onClick={() => setAttempted(true)}>Save export</Button>
  ...
  {attempted && (
    <p className={styles.unavailable} role="status">
      Saving exports isn't available in this build yet.
    </p>
  )}
  ```
  - Clicking "Save export" sets a local boolean `attempted` and renders the placeholder notice. No export API is called.
- In `apps/desktop/src/components/UnlockScreen.tsx` (lines 10–72):
  - Contains only an "Unlock" button. There is no "Restore from Backup" link or action.
- In `apps/desktop/src/lib/store.ts` (lines 216–220):
  ```typescript
  let status = await api.secwetStatus();
  if (isUninitialized(status)) {
    const sysDevName = await api.systemDeviceName().catch(() => undefined);
    status = await api.secwetCreate(sysDevName);
  }
  ```
  - When uninitialized, the app immediately creates a new Secwet workspace automatically, providing no onboarding screen or option to restore from an existing `.secwet` export file.

### 1.3 Core Cryptography & Storage Support (`crates/secwet-core`)
- In `crates/secwet-core/src/crypto.rs` (lines 448–530):
  - `generate_recovery_key() -> (String, Zeroizing<[u8; 16]>)` generates 125 bits of entropy formatted as 25 Crockford base32 characters in 5 groups (`XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`).
  - `normalize_recovery_key(input: &str) -> Result<String, CryptoError>` normalizes whitespace, hyphens, lowercase characters, and Crockford aliases (`I`/`L` -> `1`, `O` -> `0`).
  - `parse_recovery_key(input: &str) -> Result<Zeroizing<[u8; 16]>, CryptoError>` parses into 16-byte zeroizing entropy.
  - `derive_recovery_key(recovery_secret: &[u8], secwet_id: &Uuid) -> Zeroizing<[u8; 32]>` derives `K_r` via HKDF-SHA256 (`salt = secwet_id.as_bytes()`, `info = b"secwet/v1/recovery"`).
- In `crates/secwet-core/src/secwet.rs`:
  - `create_recovery_key`, `replace_recovery_key`, `export_encrypted`, and `restore_from_export` are **not implemented**.
  - `recovery_created_at` is read from `meta` table in `overview()` for checklist tracking (`checklist.recovery_key_created = get_meta(&self.db, "recovery_created_at")?.is_some()`).

### 1.4 CLI Export Command Parity (`crates/secwet-cli`)
- In `crates/secwet-cli/src/main.rs` (lines 141–149):
  ```rust
  #[derive(Args, Debug)]
  pub struct ExportArgs {
      #[arg(short = 'o', long = "out")]
      pub out: Option<PathBuf>,
      #[arg(short = 'f', long = "format", default_value = "dotenv")]
      pub format: String,
  }
  ```
  - `ExportArgs` lacks the `--plaintext` flag entirely.
  - `Commands::Export` (lines 369–393) requires `--item` (or `--project`), resolves item and environment, and calls `commands::export::execute_export`.
  - In `crates/secwet-cli/src/commands/export.rs` (lines 6–64):
    - Exports secrets as dotenv or JSON without requiring `--plaintext`.
    - Cannot export encrypted workspace envelopes (`.secwet`).
    - Does not prompt for recovery key without echo.
- In `crates/secwet-cli/Cargo.toml` (lines 16–28):
  - Dependencies do not include `rpassword` or `dialoguer` for password/key prompt without terminal echo.
- In existing CLI tests (`crates/secwet-cli/tests/cli_tests.rs`, lines 471–533):
  - `cli_export_dotenv_and_json_roundtrip` runs `export` without `--plaintext`.
  - Invariant test `dotenv_export_requires_plaintext_flag` does not exist.
  - Invariant tests `export_then_restore_roundtrip`, `export_wrong_key_fails_without_detail`, and `export_file_contains_no_plaintext` do not exist.

---

## 2. Logic Chain

1. **Tauri IPC Command Gap**:
   - *Observation 1.1*: `generate_handler!` in `src-tauri/src/lib.rs` does not include `recovery_key_create`, `recovery_key_replace`, `workspace_export`, or `workspace_restore`.
   - *Observation 1.2*: `api.ts` falls back to `mockBackend` for recovery creation and export, and lacks replace/restore entirely.
   - *Logic*: Desktop frontend cannot communicate with the Rust backend for Milestone 3 recovery or backup actions. All current recovery actions are purely simulated in the browser DOM.
   - *Deduction*: Tauri commands with `*_impl` separation must be added to `commands.rs`, registered in `src-tauri/src/lib.rs`, and wired in `api.ts` via `invoke(...)`.

2. **Dialog Plugin & Permissions Gap**:
   - *Observation 1.1*: Neither `tauri-plugin-dialog` in Cargo.toml nor permissions in `capabilities/default.json` exist.
   - *Logic*: Requirement R3 requires wiring native save and open file dialogs via `tauri-plugin-dialog` for `.secwet` export and restore.
   - *Deduction*:
     - `apps/desktop/src-tauri/Cargo.toml` must add `tauri-plugin-dialog = "2"`.
     - `src-tauri/src/lib.rs` must initialize `.plugin(tauri_plugin_dialog::init())`.
     - `capabilities/default.json` must include permissions `"dialog:default"` (or `"dialog:allow-save"`, `"dialog:allow-open"`).
     - Furthermore, Tauri command design for `workspace_export` and `workspace_restore` should accept `path: Option<String>`: if `Some(path)` is provided (e.g. from tests or UI-managed dialog), it executes with that path; if `None`, it triggers `app.dialog().file()...`. This guarantees 100% testability in headless environments without window servers.

3. **Frontend Dialog & Screen Gaps**:
   - *Observation 1.2*:
     - `CreateRecoveryKeyDialog.tsx` uses a client-side random string generator.
     - `ExportDialog.tsx` has a hardcoded text "Saving exports isn't available in this build yet."
     - `UnlockScreen.tsx` lacks a "Restore from Backup" action.
     - `store.ts` auto-creates on `isUninitialized`.
   - *Logic*: Requirements R1, R3, and R4 require real recovery key generation from the engine, real `.secwet` file export with native save dialog, and a restore entrypoint in the onboarding/unlock flow.
   - *Deduction*:
     - `CreateRecoveryKeyDialog.tsx` must call `api.recoveryKeyCreate()` or `api.recoveryKeyReplace()` on load/confirmation, display the genuine 125-bit Crockford key returned by the backend, enforce the one-time view and confirmation checkbox, and clear it on close.
     - `ExportDialog.tsx` must trigger native save dialog (or backend save dialog), invoke `api.workspaceExport()`, and display export summary (file path, secret/item count).
     - `UnlockScreen.tsx` (and `store.ts`) must offer "Restore from Backup", allowing the user to select an existing `.secwet` file and type their recovery key to restore their workspace.

4. **CLI Parity & Invariants Gap**:
   - *Observation 1.4*: `secwet export` currently dumps unencrypted secrets to stdout/file without `--plaintext`, fails if no item is specified, and lacks `.secwet` envelope export.
   - *Logic*: Requirement R5 and acceptance criteria lines 50–52 require:
     1. `secwet export --out <file.secwet>` prompts for recovery key without echo and exports the encrypted envelope.
     2. `secwet export --env <name> --format dotenv --plaintext --out .env` requires explicit `--plaintext`, failing if omitted.
   - *Deduction*:
     - `ExportArgs` in `crates/secwet-cli/src/main.rs` must be split or branched:
       - If `--out` has extension `.secwet` (or command specifies envelope export): prompt for recovery key without echo, normalize, derive `K_r`, call `secwet.export_encrypted(&recovery_key, &out)`.
       - If format is `dotenv` or `json`: require `--plaintext` flag; error with exit code 1 or 64 if `--plaintext` is absent.
     - Invariant test `dotenv_export_requires_plaintext_flag` must be implemented in `crates/secwet-cli/tests/cli_tests.rs`.
     - Invariant tests `export_then_restore_roundtrip`, `export_wrong_key_fails_without_detail`, and `export_file_contains_no_plaintext` must be implemented in `crates/secwet-core/tests/`.

---

## 3. Caveats

1. **Relay Recovery (F15.6)**: The relay-stored recovery snapshot (F15.6 / Pro pairing relay recovery) belongs to Milestone 4+ (Relay Foundation & Pairing). Milestone 3 scope is strictly local recovery keys and `.secwet` file-based export and restore.
2. **Terminal Echo Library**: Neither `rpassword` nor `dialoguer` is currently in `crates/secwet-cli/Cargo.toml`. Adding a dependency must comply with workspace dependency policies (and `scan_dependencies`). If external dependencies are avoided, POSIX `termios` / `tcsetattr` can disable `ECHO` on Unix/macOS, or `rpassword = "7"` can be added to workspace dependencies.
3. **Headless Test Compatibility for Tauri Dialogs**: Tauri's `app.dialog().file()` requires a running window event loop. In headless integration tests (e.g. `commands_tests.rs`), calling native file dialogs directly will hang or fail without user interaction. Thus, `workspace_export_impl` and `workspace_restore_impl` MUST take `path: Option<PathBuf>` so tests can provide an explicit path.

---

## 4. Conclusion & Proposed Architecture

### 4.1 Proposed Tauri IPC Commands (`apps/desktop/src-tauri/src/commands.rs`)

```rust
// 1. Recovery Key Create
#[tauri::command]
pub fn recovery_key_create(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, UiError> {
    recovery_key_create_impl(Some(&app), &state)
}

pub fn recovery_key_create_impl(
    app: Option<&AppHandle>,
    state: &AppState,
) -> Result<String, UiError> {
    state.with_secwet_mut(|secwet| {
        let key = secwet.create_recovery_key()?;
        if let Some(app) = app {
            let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "settings" }));
        }
        Ok(key.expose_secret().to_string())
    })
}

// 2. Recovery Key Replace
#[tauri::command]
pub fn recovery_key_replace(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<String, UiError> {
    recovery_key_replace_impl(Some(&app), &state)
}

pub fn recovery_key_replace_impl(
    app: Option<&AppHandle>,
    state: &AppState,
) -> Result<String, UiError> {
    state.with_secwet_mut(|secwet| {
        let key = secwet.replace_recovery_key()?;
        if let Some(app) = app {
            let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "settings" }));
        }
        Ok(key.expose_secret().to_string())
    })
}

// 3. Workspace Export
#[derive(Serialize)]
pub struct ExportSummaryDto {
    pub file_path: String,
    pub secrets_count: usize,
    pub items_count: usize,
    pub spaces_count: usize,
    pub bytes_written: u64,
}

#[tauri::command]
pub fn workspace_export(
    app: AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    recovery_key: Option<String>,
) -> Result<ExportSummaryDto, UiError> {
    workspace_export_impl(Some(&app), &state, path.map(PathBuf::from), recovery_key)
}

pub fn workspace_export_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    path: Option<PathBuf>,
    recovery_key: Option<String>,
) -> Result<ExportSummaryDto, UiError> {
    let out_path = match path {
        Some(p) => p,
        None => {
            #[cfg(feature = "desktop")]
            {
                use tauri_plugin_dialog::DialogExt;
                let app = app.ok_or_else(|| UiError::invalid("AppHandle required for dialog"))?;
                app.dialog()
                    .file()
                    .add_filter("Secwet Archive", &["secwet"])
                    .set_file_name(&format!("secwet-export-{}.secwet", chrono_or_timestamp()))
                    .blocking_save_file()
                    .map(|p| p.as_path().unwrap().to_path_buf())
                    .ok_or_else(|| UiError::invalid("Export cancelled"))?
            }
            #[cfg(not(feature = "desktop"))]
            return Err(UiError::invalid("Path required"));
        }
    };
    
    // Validate recovery key or retrieve and export
    state.with_secwet(|secwet| {
        let summary = secwet.export_encrypted(&recovery_key_secret, &out_path)?;
        Ok(ExportSummaryDto {
            file_path: out_path.to_string_lossy().to_string(),
            secrets_count: summary.secrets_count,
            items_count: summary.items_count,
            spaces_count: summary.spaces_count,
            bytes_written: summary.bytes_written,
        })
    })
}

// 4. Workspace Restore
#[tauri::command]
pub fn workspace_restore(
    app: AppHandle,
    state: State<'_, AppState>,
    path: Option<String>,
    recovery_key: String,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError> {
    workspace_restore_impl(Some(&app), &state, path.map(PathBuf::from), recovery_key, device_name)
}

pub fn workspace_restore_impl(
    app: Option<&AppHandle>,
    state: &AppState,
    path: Option<PathBuf>,
    recovery_key: String,
    device_name: Option<String>,
) -> Result<SecwetStatusDto, UiError> {
    let in_path = match path {
        Some(p) => p,
        None => {
            use tauri_plugin_dialog::DialogExt;
            let app = app.ok_or_else(|| UiError::invalid("AppHandle required for dialog"))?;
            app.dialog()
                .file()
                .add_filter("Secwet Archive", &["secwet"])
                .blocking_pick_file()
                .map(|p| p.as_path().unwrap().to_path_buf())
                .ok_or_else(|| UiError::invalid("Restore cancelled"))?
        }
    };

    let dev_name = device_name.unwrap_or_else(system_device_name_impl);
    let recovery_secret = SecretString::new(recovery_key);

    let secwet = Secwet::restore_from_export(
        &state.data_dir,
        &in_path,
        &recovery_secret,
        &dev_name,
        state.keystore.as_ref(),
    )?;

    let secwet_id = secwet.secwet_id();
    *state.secwet.lock().map_err(|_| UiError::internal("Mutex poisoned"))? = Some(secwet);

    if let Some(app) = app {
        let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "all" }));
    }

    Ok(SecwetStatusDto::Unlocked { secwet_id })
}
```

### 4.2 Proposed CLI Export Changes (`crates/secwet-cli/src/main.rs`)

```rust
#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output file path (defaults to stdout if omitted; .secwet triggers encrypted envelope export)
    #[arg(short = 'o', long = "out")]
    pub out: Option<PathBuf>,

    /// Export format: dotenv (default) or json
    #[arg(short = 'f', long = "format", default_value = "dotenv")]
    pub format: String,

    /// Explicitly allow exporting unencrypted secrets
    #[arg(long = "plaintext")]
    pub plaintext: bool,
}
```

Execution logic in `main.rs`:
```rust
Commands::Export(args) => {
    let is_secwet_archive = args.out.as_ref().map_or(false, |p| {
        p.extension().map_or(false, |ext| ext == "secwet")
    });

    if is_secwet_archive {
        // Prompt for recovery key without echo
        eprint!("Enter recovery key: ");
        std::io::stderr().flush().ok();
        let recovery_key = rpassword::read_password()
            .map_err(|e| format!("failed to read recovery key: {e}"))?;
        let out_file = args.out.unwrap();
        if let Err(e) = secwet.export_encrypted(&SecretString::new(recovery_key), &out_file) {
            eprintln!("error: export failed: {e}");
            return ExitCode::from(1);
        }
        eprintln!("Exported encrypted workspace to {}", out_file.display());
        ExitCode::SUCCESS
    } else {
        // Dotenv / JSON plaintext export
        if !args.plaintext {
            eprintln!("error: exporting plaintext secrets requires the explicit --plaintext flag");
            return ExitCode::from(1);
        }
        eprintln!("warning: exporting secrets in plaintext");
        // Proceed with item/env resolution and execute_export
    }
}
```

---

## 5. Verification Method

To verify the implementation of Milestone 3:

1. **Rust Core Tests**:
   ```bash
   cargo test -p secwet-core
   ```
   Verify mandatory invariants pass:
   - `export_then_restore_roundtrip`
   - `export_wrong_key_fails_without_detail`
   - `export_file_contains_no_plaintext`
   - `replace_recovery_key_invalidates_old`

2. **Rust Desktop Tests**:
   ```bash
   cargo test -p secwet-desktop
   ```
   Verify headless `commands_tests.rs` covers:
   - `test_recovery_key_create_and_status`
   - `test_recovery_key_replace`
   - `test_workspace_export_and_restore_roundtrip`
   - `test_workspace_restore_wrong_key_fails`

3. **Rust CLI Tests**:
   ```bash
   cargo test -p secwet-cli
   ```
   Verify:
   - `dotenv_export_requires_plaintext_flag` (fails when `--plaintext` is omitted, succeeds with `--plaintext`)
   - `cli_export_secwet_envelope_roundtrip`

4. **Frontend Typecheck & Build**:
   ```bash
   pnpm --dir apps/desktop typecheck
   pnpm --dir apps/desktop build
   node apps/desktop/scripts/empirical_challenge.mjs
   ```

5. **Invalidation Conditions**:
   - Any test failing where plaintext secret values appear in the `.secwet` file.
   - Any failure of `export --env <name> --format dotenv` to reject invocations missing `--plaintext`.
   - Any Tauri command failing to enforce lock state or emitting unhandled errors to the UI.
