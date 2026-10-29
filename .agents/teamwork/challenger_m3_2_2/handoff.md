# Empirical Challenge & Verification Report: Milestone M3-2

**Author**: Empirical Challenger M3-2 (`teamwork_challenger`)  
**Target Milestone**: Milestone M3-2 (Desktop Tauri IPC and CLI Parity)  
**Parent Agent**: `1ebf4374-d237-49fe-9aa4-ecab43ee8aa1`  
**Verdict**: **`APPROVE`**  
**Date**: 2026-10-27T17:52:00Z  

---

## Challenge Summary

**Overall risk assessment**: **LOW** (Production-ready with 100% empirical verification pass rate)

---

## 1. Observation

### 1.1 Scope of Review & Adversarial Stress Vectors
The empirical challenge evaluated Milestone M3-2 across two primary tracks:
1. **End-to-End CLI `.secwet` Export Roundtrip & Plaintext Protections**:
   - Creating spaces, groups, items, environments, diverse secrets, binary file assets (4KB raw binary), and rich markdown notes purely via `secwet` CLI binary commands.
   - Exporting the populated workspace to a `.secwet` archive via `secwet export --out <file.secwet>`.
   - Auditing raw file bytes for zero plaintext leakage (Shannon entropy audit).
   - Restoring onto a clean, unpopulated target directory and verifying 100% data fidelity.
   - Enforcing `--plaintext` flag requirement on unencrypted exports (`dotenv`, `json`).
2. **Tauri IPC Concurrent Operations & Event Emission**:
   - Rapid sequential recovery key replacements (30 cycles) and assertion that all older 30 keys are invalidated.
   - Multi-threaded concurrent key replacement race under simultaneous readers (8 replacers, 8 readers across 40 mutations).
   - Interleaved concurrent export and recovery key replacement race conditions.
   - Source and static contract auditing of `secwet://changed` event scopes (`"settings"`, `"all"`).

### 1.2 Verbatim Test Executions & Outputs

#### Test 1: CLI Export Roundtrip & Plaintext Flag Protections
```
$ cargo test -p secwet-cli --test cli_export_roundtrip_stress_tests -- --nocapture
    Finished `test` profile [unoptimized + debuginfo] target(s) in 2.44s
     Running tests/cli_export_roundtrip_stress_tests.rs

running 2 tests
test test_cli_export_plaintext_flag_protections ... ok
test test_cli_secwet_export_roundtrip_100_percent_fidelity ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.69s
```

#### Test 2: Tauri IPC Concurrency, Lifecycle & Historical Key Invalidation
```
$ cargo test -p secwet-desktop --test recovery_concurrency_stress_tests -- --nocapture
    Finished `test` profile [unoptimized + debuginfo] target(s) in 7.42s
     Running tests/recovery_concurrency_stress_tests.rs

running 5 tests
test test_recovery_ipc_invariants_locked_and_headless ... ok
test test_rapid_sequential_recovery_key_replacements ... ok
test test_recovery_ipc_create_replace_and_restore_lifecycle ... ok
test test_concurrent_recovery_key_replace_and_readers_race ... ok
test test_concurrent_export_interleaved_with_key_replacement ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.13s
```

#### Test 3: Frontend & IPC Contract Empirical Verification Harness
```
$ node apps/desktop/scripts/empirical_challenge.mjs
=================================================================
SECWET MILESTONE 2B: EMPIRICAL CHALLENGER VERIFICATION HARNESS
=================================================================

Running 24 empirical challenge tests...

  ✓ PASS: 1.1 Source Code Audit: SecretRow never references secret.value in handleCopy
  ✓ PASS: 1.2 Source Code Audit: components/SecretRow.tsx re-exports securely
  ✓ PASS: 1.3 Adversarial Object Trap: Copy action NEVER reads secret.value property
  ✓ PASS: 1.4 Global Clipboard Audit: No secret plaintext passed to navigator.clipboard across frontend
  ✓ PASS: 1.5 Tauri IPC Contract: api.secretCopy issues invoke('secret_copy', { id })
  ✓ PASS: 2.1 Event Invalidation: secwet://locked wipes store secrets and sets status to locked
  ✓ PASS: 2.2 SecretRow Ephemeral State: secwet://locked wipes revealedValue to null
  ✓ PASS: 2.3 Event Invalidation: secwet://changed scopes trigger appropriate data re-fetching
  ✓ PASS: 3.1 useIdleTimer: Registers all 6 required user interaction events
  ✓ PASS: 3.2 useIdleTimer: Resets activity on interaction and triggers onIdle on timeout
  ✓ PASS: 3.3 useIdleTimer: Event handler throttling avoids performance degradation
  ✓ PASS: 4.1 Build Artifacts: dist/index.html and assets exist and are non-empty
  ✓ PASS: 5.1 Adversarial: Rapid multi-click burst on copy never races or leaks
  ✓ PASS: 5.2 Adversarial: SecretRow unlisten race condition analysis
  ✓ PASS: 5.3 Adversarial: Rapid burst of 50 secwet://changed events handled safely
  ✓ PASS: 5.4 Adversarial: Idle Timer firing interval analysis when lock is asynchronous
  ✓ PASS: 6.1 Active Sessions: Dynamic session registration, store synchronization, and GUI stop
  ✓ PASS: 6.2 Source Audit: SecretRow & SecretUsageDialog conditionally render In use and stop process
  ✓ PASS: 6.3 Source Audit: NewItemDialog renders Group selector and App wires group selection from Home
  ✓ PASS: 7.1 IPC Event Emission Audit: commands.rs emits secwet://changed scope 'settings' on recovery key create/replace
  ✓ PASS: 7.2 IPC Event Emission Audit: commands.rs emits secwet://changed scope 'all' on workspace restore
  ✓ PASS: 7.3 CLI Parity Audit: secwet-cli enforces --plaintext flag for unencrypted exports
  ✓ PASS: 7.4 CLI Parity Audit: secwet-cli reads recovery key without echo via rpassword
  ✓ PASS: 7.5 Tauri IPC Command Registration Audit: lib.rs registers all 5 recovery commands

=================================================================
SUMMARY: 24 passed, 0 failed out of 24 tests.
=================================================================
```

#### Test 4: Comprehensive Crate Test Suites & Full E2E Test Suite
- `cargo test -p secwet-core`: 88 E2E tests + hundreds of unit/adversarial tests passing (0 failed).
- `cargo test -p secwet-cli`: 73 tests passing (0 failed).
- `cargo test -p secwet-desktop`: 47 tests passing (0 failed).
- `bash scripts/run_e2e_tests.sh`: 88 core E2E tests + 7 CLI E2E tests + 13 reference fixtures verified (0 failed).
- `cargo clippy -p secwet-desktop && cargo clippy -p secwet-cli`: 0 warnings.
- `pnpm typecheck` & `pnpm desktop:build`: 0 errors.

---

## 2. Logic Chain

1. **CLI Entity Generation and 100% Data Fidelity**:
   - The CLI was exercised to populate all entity types: spaces (`"Platform Infrastructure"`, `"Financial Operations"`), groups (`"Cloud Services"`, `"Billing Engine"`), items (`"auth-gateway"`, `"payment-service"`), environments (`"staging"`, `"production"`), secrets (`password`, `api_key`, multiline JSON `env_var`), binary file attachments (4096-byte non-text asset with full byte gamut), and rich markdown notes.
   - The CLI was used to export the workspace using `secwet export --out <file.secwet>` with Crockford recovery key formatting (lowercase, spaces, dashes, Crockford aliases `I`/`L` -> `1`, `O` -> `0`).
   - The raw archive file was scanned for plaintext: zero instances of secret passwords, API keys, markdown note contents, or metadata names were found.
   - The export was restored onto a fresh directory with zero existing data. All spaces, groups, items, environments, secret values, binary bytes (byte-for-byte matching), and markdown notes were re-read and matched verbatim.

2. **Plaintext Protection Invariants**:
   - In `crates/secwet-cli/src/main.rs:442-446`:
     ```rust
     if !args.plaintext {
         eprintln!("error: exporting plaintext secrets requires the explicit --plaintext flag");
         return ExitCode::from(1);
     }
     ```
   - Both `dotenv` and `json` export commands were tested without `--plaintext` and exited with code 1 without writing any files.
   - Supplying `--plaintext` succeeded and printed the warning `"warning: exporting unencrypted plaintext secrets"` to stderr.

3. **Tauri IPC Concurrency & Recovery Key Lifecycle**:
   - Sequential rapid replacement of recovery keys (30 replacements in succession) proved that every past recovery key is invalidated. In `crates/secwet-core/src/secwet.rs:4080`, `replace_recovery_key` replaces `recovery_check` and re-wraps all master keys. Any export attempt with an older key returns `UiError { code: "recovery_failed" }`.
   - Multi-threaded stress testing (8 threads performing 5 replacements each, competing against 8 continuous reader threads) demonstrated zero deadlocks, zero mutex poisoning, and proper synchronization of `AppState.with_secwet_mut`.
   - Concurrent export interleaved with key replacement showed that every export operation either completes atomically with its contemporary key or returns a clean `recovery_failed` error. No half-written archives or SQLite corruptions occurred.

4. **Event Emission Audit**:
   - In `apps/desktop/src-tauri/src/commands.rs:1554-1556` and `1575-1577`, `recovery_key_create_impl` and `recovery_key_replace_impl` call:
     ```rust
     if let Some(app) = app {
         let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "settings" }));
     }
     ```
   - In `apps/desktop/src-tauri/src/commands.rs:1720-1722`, `workspace_restore_impl` calls:
     ```rust
     if let Some(app) = app {
         let _ = app.emit("secwet://changed", serde_json::json!({ "scope": "all" }));
     }
     ```
   - Frontend store listener tests in `empirical_challenge.mjs` confirmed that `scope: "settings"` triggers settings refresh, and `scope: "all"` triggers complete workspace state reload.

---

## 3. Caveats

1. **Non-Generic `AppHandle` Parameter in `*_impl` Functions**:
   - In `apps/desktop/src-tauri/src/commands.rs`, `app: Option<&AppHandle>` uses the default type parameter `R = tauri::Wry` instead of a generic `<R: tauri::Runtime>`.
   - In headless unit tests, passing `tauri::test::mock_app().handle()` yields `AppHandle<MockRuntime>`, causing type mismatch with `&AppHandle<Wry>`.
   - While `*_impl` functions gracefully accept `None` for headless operation and event emission is confirmed via AST audit and frontend integration harnesses, declaring `pub fn recovery_key_create_impl<R: tauri::Runtime>(app: Option<&AppHandle<R>>, ...)` in a future refactor would allow unit test suites to pass mock runtimes directly.

---

## 4. Conclusion

Milestone M3-2 satisfies all acceptance criteria, security invariants, and performance boundaries:
- CLI `.secwet` export roundtrip restored with 100% data fidelity across all entity kinds and binary files.
- Plaintext export protections strictly enforced.
- Tauri IPC commands are registered, locked-enforced, and concurrent-safe under multi-threaded contention.
- Event emission payloads conform to specification.
- Verdict is an unqualified **`APPROVE`**.

---

## 5. Verification Method

To independently reproduce the empirical evidence:

```bash
# 1. Run the CLI export roundtrip & plaintext protection stress suite
cargo test -p secwet-cli --test cli_export_roundtrip_stress_tests

# 2. Run the Tauri IPC recovery concurrency stress suite
cargo test -p secwet-desktop --test recovery_concurrency_stress_tests

# 3. Run the empirical challenger JS audit harness
node apps/desktop/scripts/empirical_challenge.mjs

# 4. Run the full project E2E test suite and fixture verification
bash scripts/run_e2e_tests.sh

# 5. Verify zero clippy warnings across desktop and CLI crates
cargo clippy -p secwet-desktop
cargo clippy -p secwet-cli
```
