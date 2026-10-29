# Review & Adversarial Challenge Report: Milestone M3-2

**Author**: Reviewer M3-2 (`teamwork_reviewer`, `reviewer`, `critic`)  
**Target Milestone**: Milestone M3-2 (Desktop Tauri IPC and CLI Parity — Requirements R3 & R5)  
**Parent Agent**: `1ebf4374-d237-49fe-9aa4-ecab43ee8aa1`  
**Date**: 2026-10-27T17:40:00Z  

---

## Review Summary

**Verdict**: **APPROVE**

---

## 1. Observation

### 1.1 Tauri IPC Commands & Plugin Registration (`apps/desktop/src-tauri`)
- **`Cargo.toml`** (line 29):
  `tauri-plugin-dialog = "2"` is added to `[dependencies]`.
- **`capabilities/default.json`** (line 13):
  `"dialog:default"` is granted in the main window capability set.
- **`src/lib.rs`**:
  - Line 27: `.plugin(tauri_plugin_dialog::init())` is registered in `tauri::Builder::default()`.
  - Lines 113–117: Registered all 5 recovery commands in `tauri::generate_handler!`:
    - `commands::recovery_key_create`
    - `commands::recovery_key_replace`
    - `commands::recovery_status`
    - `commands::workspace_export`
    - `commands::workspace_restore`
- **`src/commands.rs`**:
  - Lines 37–59: Defined `RecoveryStatusDto { created: bool, created_at: Option<u64> }` and `ExportSummaryDto`.
  - Lines 1547–1558: `recovery_key_create_impl` generates 125-bit recovery key via `secwet.create_recovery_key`, emits `secwet://changed` with scope `"settings"`, and returns key.
  - Lines 1568–1579: `recovery_key_replace_impl` rotates key via `secwet.replace_recovery_key`, emits `secwet://changed` with scope `"settings"`, and returns key.
  - Lines 1589–1597: `recovery_status_impl` queries `secwet.recovery_status()`.
  - Lines 1604–1647: `workspace_export_impl` accepts `path: Option<PathBuf>`. When `None`, invokes `app.dialog().file().add_filter("Secwet Archive", &["secwet"]).blocking_save_file()`. Invokes `secwet.export_encrypted(&recovery_secret, &out_path)` and returns `ExportSummaryDto`.
  - Lines 1659–1725: `workspace_restore_impl` accepts `path: Option<PathBuf>`. When `None`, invokes `app.dialog().file().add_filter("Secwet Archive", &["secwet"]).blocking_pick_file()`. Takes existing `secwet` from `AppState` mutex and locks/consumes it to prevent SQLite connection collisions. Restores workspace via `Secwet::restore_from_export`, replaces state instance, emits `secwet://changed` with scope `"all"`, and returns `SecwetStatusDto::Unlocked`.

### 1.2 CLI Parity (`crates/secwet-cli`)
- **`Cargo.toml`** (line 28): Added `rpassword = "7"`.
- **`src/main.rs`**:
  - Line 152: `ExportArgs` defines `pub plaintext: bool`.
  - Lines 374–420: In `Commands::Export`:
    - If `--out` ends with `.secwet` (case-insensitive): prompts for recovery key via `eprint!("Enter recovery key: "); std::io::stderr().flush();`. Reads without terminal echo via `rpassword::read_password()` (falling back to `std::io::stdin().read_line()` when `!is_terminal()`). Validates non-empty input and calls `secwet.export_encrypted(&recovery_secret, out_file)`. Prints summary to stderr and exits with `ExitCode::SUCCESS` on success or code 1 on failure.
    - If exporting unencrypted format (`dotenv` or `json`): verifies `--plaintext`. If omitted, immediately aborts with exit code 1 and prints:
      `error: exporting plaintext secrets requires the explicit --plaintext flag`
      If `--plaintext` is provided, prints warning `warning: exporting unencrypted plaintext secrets` to stderr and calls `commands::export::execute_export`.

### 1.3 Independent Test Execution Results
All test commands were executed directly by this reviewer:
1. `cargo test -p secwet-desktop`:
   ```
   running 7 tests in src/lib.rs ... ok
   running 5 tests in tests/challenger_stress_tests.rs ... ok
   running 18 tests in tests/clipboard_adversarial_tests.rs ... ok
   running 6 tests in tests/commands_tests.rs ... ok
   running 5 tests in tests/concurrency_lifecycle_stress_tests.rs ... ok
   test result: ok. 41 passed; 0 failed; 0 ignored; finished in 12.0s
   ```
2. `cargo test -p secwet-cli`:
   ```
   running 10 tests in src/lib.rs ... ok
   running 12 tests in tests/adversarial_cli_stress_tests.rs ... ok
   running 8 tests in tests/challenger_stress_tests.rs ... ok
   running 7 tests in tests/cli_export_e2e_tests.rs ... ok
   running 4 tests in tests/cli_full_suite_tests.rs ... ok
   running 1 test in tests/cli_spaces_tests.rs ... ok
   running 24 tests in tests/cli_tests.rs ... ok
   test result: ok. 66 passed; 0 failed; 0 ignored; finished in 1.70s
   ```
3. Mandatory Invariant Tests:
   - `cargo test -p secwet-cli --test cli_tests dotenv_export_requires_plaintext_flag` -> PASSED (1 passed)
   - `cargo test -p secwet-cli --test cli_tests cli_export_secwet_envelope_roundtrip` -> PASSED (1 passed)
   - `cargo test -p secwet-desktop --test commands_tests test_recovery_and_workspace_export_restore_lifecycle_roundtrip` -> PASSED (1 passed)
4. Comprehensive E2E Test Suite:
   - `cargo test -p secwet-core --test recovery_e2e_suite` -> PASSED (88 passed)
   - `cargo test -p secwet-cli --test cli_export_e2e_tests` -> PASSED (7 passed)
5. Compilation & Clippy:
   - `cargo check --workspace` -> Exit code 0 (Finished in 24.36s)
   - `cargo clippy -p secwet-desktop -p secwet-cli` -> 0 warnings in `secwet-desktop` and `secwet-cli`.

---

## 2. Logic Chain

1. **Verification of Requirements R3 & R5**:
   - Observations 1.1 and 1.2 demonstrate that all required IPC commands (`recovery_key_create`, `recovery_key_replace`, `recovery_status`, `workspace_export`, `workspace_restore`) are fully implemented and wired to Tauri 2's handler registry and dialog plugin.
   - Observation 1.2 demonstrates CLI export parity: `.secwet` exports prompt for the recovery key with echo suppressed, and plaintext exports strictly reject invocation without `--plaintext` with exit code 1.

2. **Integrity and Anti-Cheating Assessment**:
   - Examination of `apps/desktop/src-tauri/src/commands.rs` and `crates/secwet-cli/src/main.rs` confirms direct invocation of genuine core cryptographic and storage primitives (`secwet.create_recovery_key`, `secwet.replace_recovery_key`, `secwet.export_encrypted`, `Secwet::restore_from_export`).
   - Zero hardcoded outputs, fake key generators, or stubbed responses exist.
   - All tests independently reproduce the claimed outputs without failure or flakiness.

3. **Database Concurrency and State Safety on Restore**:
   - `Secwet::restore_from_export` completely overwrites target database files on disk. Holding an active SQLite handle in `AppState` would cause database locks or file corruption on Windows/macOS.
   - By locking and consuming the existing connection (`guard.take().unwrap().lock()`) before `restore_from_export`, the implementation guarantees atomic and safe workspace replacement.

4. **Headless Testability Architecture**:
   - Desktop native dialogs (`blocking_save_file()`, `blocking_pick_file()`) rely on OS window servers.
   - Exposing `path: Option<PathBuf>` in `workspace_export_impl` and `workspace_restore_impl` allows headless unit/integration test suites to supply paths directly while production GUI callers trigger native dialogs when `path` is `None`.

---

## 3. Adversarial Challenges & Stress-Test Findings

### Challenge Summary
**Overall Risk Assessment**: **LOW**

### Challenge 1: Plaintext Exfiltration Protection (Requirement R5 Invariant)
- **Assumption Challenged**: Missing `--plaintext` flag on CLI export must prevent secret exfiltration to files or stdout across all unencrypted formats.
- **Attack Scenario**: User or script invokes `secwet export -f dotenv` or `secwet export -f json` without `--plaintext`.
- **Stress-Test Result**: Aborts immediately with exit code 1 and writes `error: exporting plaintext secrets requires the explicit --plaintext flag` to stderr. Target output files are never created; stdout remains empty. Verified in `dotenv_export_requires_plaintext_flag` and `test_t1_cli_export_requires_plaintext_flag`.
- **Verdict**: Defended.

### Challenge 2: Invalidation of Superseded Recovery Keys
- **Assumption Challenged**: When a recovery key is replaced (`recovery_key_replace`), old recovery keys must be rendered invalid for export and verification.
- **Attack Scenario**: Attacker obtains previously valid recovery key `key1` after owner rotated to `key2`, and attempts `workspace_export` or `verify_recovery_key`.
- **Stress-Test Result**: Export attempt with `key1` fails with `UiError::recovery_failed` (`code: "recovery_failed"`). Verified in `test_recovery_and_workspace_export_restore_lifecycle_roundtrip`.
- **Verdict**: Defended.

### Challenge 3: Headless Invocations without Path
- **Assumption Challenged**: If `workspace_export_impl` or `workspace_restore_impl` is invoked with `path: None` and `app: None` (e.g. In headless automated testing or misconfigured backend calls), it must fail gracefully rather than panic or hang.
- **Attack Scenario**: Programmatic call with `path: None` and `app: None`.
- **Stress-Test Result**: Cleanly returns `UiError::invalid("path", "Export path is required when running in headless mode")` or `"Restore path is required when running in headless mode"`.
- **Verdict**: Defended.

### Challenge 4: Zero Plaintext Leakage in Export Archives
- **Assumption Challenged**: `.secwet` archives must contain zero plaintext secret bytes.
- **Attack Scenario**: Substring analysis and Shannon entropy inspection of exported binary archive.
- **Stress-Test Result**: Verified in `cli_export_secwet_envelope_roundtrip` and `test_t4_scenario_3_zero_plaintext_cold_storage_security_and_shannon_entropy` that zero secret substrings appear in the raw envelope and ciphertext entropy exceeds 7.5 bits/byte.
- **Verdict**: Defended.

---

## 4. Caveats

- **No Caveats**: All tasks assigned for Milestone M3-2 across Tauri IPC and CLI have been verified with complete test coverage, zero warnings, and clean isolation.

---

## 5. Conclusion

Milestone M3-2 meets all requirements:
1. Tauri IPC commands (`recovery_key_create`, `recovery_key_replace`, `recovery_status`, `workspace_export`, `workspace_restore`) are fully implemented and registered with ACL capabilities and dialog plugin.
2. CLI parity for non-echo recovery key prompt, `.secwet` encrypted archive export, and strict `--plaintext` enforcement is implemented and verified.
3. All mandatory invariant tests pass.
4. Independent execution of 41 desktop tests and 66 CLI tests succeeded with 0 failures and 0 warnings.
5. No integrity violations or facades were found.

**Final Verdict**: **APPROVE**

---

## 6. Verification Method

To independently reproduce this verification:
```bash
# 1. Run all tests in secwet-desktop
cargo test -p secwet-desktop

# 2. Run all tests in secwet-cli
cargo test -p secwet-cli

# 3. Run Milestone M3-2 specific invariant tests
cargo test -p secwet-cli --test cli_tests dotenv_export_requires_plaintext_flag
cargo test -p secwet-cli --test cli_tests cli_export_secwet_envelope_roundtrip
cargo test -p secwet-desktop --test commands_tests test_recovery_and_workspace_export_restore_lifecycle_roundtrip

# 4. Verify clippy cleanliness
cargo clippy -p secwet-desktop -p secwet-cli
```
