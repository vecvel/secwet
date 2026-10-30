## 2026-10-27T17:10:18Z
**Context**: Milestone M3-2: Desktop Tauri IPC and CLI Parity (Requirements R3 & R5).
**Identity & Working Directory**:
- Type: teamwork_worker
- Working directory: /Users/besaoct/Desktop/secwet/.agents/teamwork/worker_m3_2
- Parent Conversation ID: 1ebf4374-d237-49fe-9aa4-ecab43ee8aa1

**Mandatory Task**:
Read the original user request at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/ORIGINAL_REQUEST.md`

Read the project scope and architecture at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/orchestrator/PROJECT.md`

Read the detailed survey report for Tauri IPC & CLI Parity at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/explorer_survey_3/handoff.md`

Read M3-1 implementation details at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/worker_m3_1/handoff.md`

Implement Milestone M3-2 across `apps/desktop/src-tauri` and `crates/secwet-cli`:
1. **Desktop Tauri IPC (`apps/desktop/src-tauri`)**:
   - Add `tauri-plugin-dialog = "2"` to `apps/desktop/src-tauri/Cargo.toml`.
   - Update `capabilities/default.json` to grant permissions for dialog (`dialog:default`).
   - In `src-tauri/src/lib.rs`: initialize `.plugin(tauri_plugin_dialog::init())`.
   - In `src-tauri/src/commands.rs`: implement commands and pure `*_impl` functions:
     - `recovery_key_create` / `recovery_key_create_impl(app: Option<&AppHandle>, state: &AppState) -> Result<String, UiError>`
     - `recovery_key_replace` / `recovery_key_replace_impl(app: Option<&AppHandle>, state: &AppState) -> Result<String, UiError>`
     - `recovery_status` / `recovery_status_impl(state: &AppState) -> Result<RecoveryStatusDto, UiError>` (returning `{ created: bool, created_at: Option<u64> }`)
     - `workspace_export` / `workspace_export_impl(app: Option<&AppHandle>, state: &AppState, path: Option<PathBuf>, recovery_key: String) -> Result<ExportSummaryDto, UiError>`:
       - If `path` is Some, use it directly (for tests).
       - If `path` is None, trigger native save dialog via `app.dialog().file().add_filter("Secwet Archive", &["secwet"]).blocking_save_file()`.
       - Derive $K_r$, call `secwet.export_encrypted(...)`, return `ExportSummaryDto`.
     - `workspace_restore` / `workspace_restore_impl(app: Option<&AppHandle>, state: &AppState, path: Option<PathBuf>, recovery_key: String, device_name: Option<String>) -> Result<SecwetStatusDto, UiError>`:
       - If `path` is Some, use it directly.
       - If `path` is None, trigger native file picker via `app.dialog().file().add_filter("Secwet Archive", &["secwet"]).blocking_pick_file()`.
       - Call `Secwet::restore_from_export(...)`, store active secwet in state, emit change event, return `SecwetStatusDto::Unlocked`.
   - Register all 5 commands in `tauri::generate_handler![...]` in `src-tauri/src/lib.rs`.
   - Add automated headless integration tests in `apps/desktop/src-tauri/tests/commands_tests.rs` (or crate test file) verifying key creation, status, replacement, export, and restore roundtrip with pure `*_impl` functions.

2. **CLI Parity (`crates/secwet-cli`)**:
   - Add `rpassword = "7"` (or standard secure password prompt) to `crates/secwet-cli/Cargo.toml`.
   - Update `ExportArgs` in `crates/secwet-cli/src/main.rs`: add `pub plaintext: bool`.
   - When `--out` path ends with `.secwet`:
     - Prompt for recovery key on stderr without echo using `rpassword::read_password()`.
     - Derive key, execute `secwet.export_encrypted(&recovery_secret, &out_file)`.
   - When exporting unencrypted format (`dotenv` or `json`):
     - If `--plaintext` flag is NOT passed: abort immediately with exit code 1 and error message `error: exporting plaintext secrets requires the explicit --plaintext flag`.
     - If `--plaintext` flag is provided: print warning to stderr and output dotenv/json content.
   - In `crates/secwet-cli/tests/cli_tests.rs`:
     - Implement mandatory invariant test `dotenv_export_requires_plaintext_flag`: verifies export fails without `--plaintext` and succeeds with `--plaintext`.
     - Implement `cli_export_secwet_envelope_roundtrip`.

3. **Verification**:
   - Run `cargo test -p secwet-desktop`
   - Run `cargo test -p secwet-cli`
   - Verify all tests pass with zero failures and zero warnings.

**Write Ownership**:
You exclusively own:
- `apps/desktop/src-tauri/`
- `crates/secwet-cli/`
