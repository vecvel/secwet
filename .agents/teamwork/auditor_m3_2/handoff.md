# Forensic Audit Report: Milestone M3-2 (Desktop Tauri IPC and CLI Parity)

**Work Product**: `apps/desktop/src-tauri` and `crates/secwet-cli`  
**Profile**: General Project (Integrity Mode: Development)  
**Verdict**: **CLEAN**  
**Auditor**: Forensic Auditor (`teamwork_auditor`)  
**Date**: 2026-10-27T17:40:00Z  

---

## 1. Observation

### 1.1 Forensic Checklist & Target Verifications

1. **Genuine `secwet-core` Calls in `commands.rs` (No Mocks/Facades)**:
   - `recovery_key_create_impl`: Calls `state.with_secwet_mut(|secwet| secwet.create_recovery_key(state.keystore.as_ref()))`. Emits `secwet://changed` with scope `"settings"`. Returns real 29-character Crockford base32 key string.
   - `recovery_key_replace_impl`: Calls `state.with_secwet_mut(|secwet| secwet.replace_recovery_key(state.keystore.as_ref()))`. Emits `secwet://changed` with scope `"settings"`. Returns newly wrapped key string.
   - `recovery_status_impl`: Calls `state.with_secwet(|secwet| secwet.recovery_status())`. Returns `RecoveryStatusDto { created: status.created, created_at: status.created_at }`.
   - `workspace_export_impl`: Accepts `Option<PathBuf>`, falls back to `app.dialog().file().add_filter("Secwet Archive", &["secwet"]).blocking_save_file()` when `None`, and calls `secwet.export_encrypted(&recovery_secret, &out_path)`. Returns genuine `ExportSummaryDto` populated from `secwet-core`.
   - `workspace_restore_impl`: Takes and locks existing `Secwet` instance to release SQLite file handles, calls `Secwet::restore_from_export(&state.data_dir, &in_path, &recovery_secret, dev_name, state.keystore.as_ref())`, replaces state instance, and emits `secwet://changed` with scope `"all"`.
   - All 5 commands are registered in `tauri::generate_handler![...]` in `src-tauri/src/lib.rs`.

2. **`tauri-plugin-dialog` Existence and Registration**:
   - `apps/desktop/src-tauri/Cargo.toml` contains `tauri-plugin-dialog = "2"`.
   - `apps/desktop/src-tauri/capabilities/default.json` grants `"dialog:default"` permission to the main window.
   - `apps/desktop/src-tauri/src/lib.rs` initializes the plugin via `.plugin(tauri_plugin_dialog::init())`.
   - `commands.rs` uses `app.dialog().file().blocking_save_file()` and `blocking_pick_file()`.

3. **CLI Terminal Prompting & Plaintext Flag Enforcement**:
   - `crates/secwet-cli/Cargo.toml` contains `rpassword = "7"`.
   - In `crates/secwet-cli/src/main.rs`:
     - When `--out` ends with `.secwet` (case-insensitive): prompts `Enter recovery key: ` to stderr, calls `rpassword::read_password()` when `std::io::stdin().is_terminal() == true` (no terminal echo), seamlessly falls back to reading stdin when piped, rejects empty keys with exit code 1, and calls `secwet.export_encrypted()`.
     - When exporting unencrypted formats (`dotenv` or `json`): verifies `args.plaintext`. If `false`, terminates immediately with exit code 1 and prints `error: exporting plaintext secrets requires the explicit --plaintext flag`. If `true`, emits `warning: exporting unencrypted plaintext secrets` to stderr and executes export.

4. **Test Authenticity in `commands_tests.rs` and `cli_tests.rs`**:
   - `commands_tests.rs` contains `test_recovery_and_workspace_export_restore_lifecycle_roundtrip`:
     - Verifies `locked` error code on uninitialized state.
     - Tests creation of entities (spaces, labels, items, environments, password secret with value `"super-secret-jwt-signing-key"`, rich-text notes, binary encrypted file attachments).
     - Generates `key1` (29 chars), replaces with `key2` (`key1 != key2`).
     - Verifies old `key1` fails on export (`recovery_failed`).
     - Verifies headless mode without path fails cleanly (`invalid`).
     - Performs genuine `.secwet` export with `key2`.
     - Attempts restore on clean state with wrong key (`recovery_failed`).
     - Restores with `key2` on clean state, verifies `Unlocked` status, and checks 100% data fidelity: secret reveal matches `"super-secret-jwt-signing-key"`, file download matches binary payload, note content matches.
   - `cli_tests.rs`:
     - `dotenv_export_requires_plaintext_flag`: executes CLI binary via `assert_cmd`, verifies failure without `--plaintext`, verifies success and warning with `--plaintext`.
     - `cli_export_secwet_envelope_roundtrip`: executes CLI binary with recovery key on stdin, verifies `.secwet` file created, verifies file bytes contain NO plaintext secret string, restores into fresh directory with `Secwet::restore_from_export`, and verifies secret reveal.
   - No dummy tests, no fake mocks, and no hardcoded assertion shortcuts.

### 1.2 Independent Test Execution Proof

#### `cargo test -p secwet-desktop`
```
running 7 tests in src/lib.rs ... ok (7 passed)
running 5 tests in challenger_stress_tests.rs ... ok (5 passed)
running 18 tests in clipboard_adversarial_tests.rs ... ok (18 passed)
running 6 tests in commands_tests.rs ... ok (6 passed)
running 5 tests in concurrency_lifecycle_stress_tests.rs ... ok (5 passed)
test result: ok. 41 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.69s
```

#### `cargo test -p secwet-cli`
```
running 10 tests in src/lib.rs ... ok (10 passed)
running 12 tests in adversarial_cli_stress_tests.rs ... ok (12 passed)
running 8 tests in challenger_stress_tests.rs ... ok (8 passed)
running 7 tests in cli_export_e2e_tests.rs ... ok (7 passed)
running 4 tests in cli_full_suite_tests.rs ... ok (4 passed)
running 1 test in cli_spaces_tests.rs ... ok (1 passed)
running 24 tests in cli_tests.rs ... ok (24 passed)
test result: ok. 66 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.15s
```

#### Specific Milestone M3-2 Invariant Tests
```
test dotenv_export_requires_plaintext_flag ... ok (0.53s)
test cli_export_secwet_envelope_roundtrip ... ok (0.52s)
test test_recovery_and_workspace_export_restore_lifecycle_roundtrip ... ok (0.07s)
```

#### Clippy Quality Checks
- `cargo clippy -p secwet-desktop`: 0 warnings.
- `cargo clippy -p secwet-cli`: 0 warnings.

---

## 2. Logic Chain

1. **Ground-Truth Requirements Compliance**:
   - `ORIGINAL_REQUEST.md` (R3, R5) requires Tauri IPC commands `recovery_key_create`, `recovery_key_replace`, `workspace_export`, and `workspace_restore` with native dialogs via `tauri-plugin-dialog`, CLI recovery key prompt without terminal echo, and CLI `--plaintext` enforcement.
   - Every requirement is directly satisfied in code with zero deviations.

2. **Absence of Facades and Mocks**:
   - Forensic inspection of `apps/desktop/src-tauri/src/commands.rs` verifies that all methods delegate to the active `Secwet` instance holding genuine SQLite connections and cryptographic keystores.
   - In `apps/desktop/src-tauri/src/lib.rs`, `tauri-plugin-dialog` is fully initialized and registered into Tauri's builder pipeline.
   - In `crates/secwet-cli/src/main.rs`, `rpassword::read_password()` is executed when running interactively, and the `--plaintext` check is strictly enforced before secret decryption or formatting occurs.

3. **Data Protection Invariant Verification**:
   - The `.secwet` export envelope is verified to contain zero plaintext secrets when inspected raw.
   - Restoration creates a fresh device identity and provisions master keys across epochs, restoring workspace entities with 100% data fidelity.

4. **Zero Regressions**:
   - All 41 desktop tests and all 66 CLI tests pass without warnings or failures.

---

## 3. Caveats

- **No Caveats**: All audited code is fully functional, tested, and compliant with all project constraints.

---

## 4. Conclusion

**Verdict: CLEAN**

Milestone M3-2 contains no cheating, no mocks, no facades, and no integrity violations. Both `apps/desktop/src-tauri` and `crates/secwet-cli` genuinely implement their contracts and integrate seamlessly with `secwet-core`.

---

## 5. Verification Method

To independently verify these results:

1. Run the desktop test suite:
   ```bash
   cargo test -p secwet-desktop
   ```
2. Run the CLI test suite:
   ```bash
   cargo test -p secwet-cli
   ```
3. Run the specific M3-2 invariant tests:
   ```bash
   cargo test -p secwet-cli --test cli_tests dotenv_export_requires_plaintext_flag
   cargo test -p secwet-cli --test cli_tests cli_export_secwet_envelope_roundtrip
   cargo test -p secwet-desktop --test commands_tests test_recovery_and_workspace_export_restore_lifecycle_roundtrip
   ```
4. Verify clippy cleanliness:
   ```bash
   cargo clippy -p secwet-desktop
   cargo clippy -p secwet-cli
   ```
