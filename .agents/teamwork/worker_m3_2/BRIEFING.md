# BRIEFING — 2026-10-27T17:31:00Z

## Mission
Milestone M3-2: Desktop Tauri IPC and CLI Parity (Requirements R3 & R5).

## 🔒 My Identity
- Archetype: teamwork_worker
- Roles: [implementer, qa, specialist]
- Working directory: /Users/besaoct/Desktop/secwet/.agents/teamwork/worker_m3_2
- Original parent: 1ebf4374-d237-49fe-9aa4-ecab43ee8aa1
- Milestone: M3-2

## 🔒 Key Constraints
- Desktop Tauri IPC: Add tauri-plugin-dialog = "2", update capabilities, commands (recovery_key_create, recovery_key_replace, recovery_status, workspace_export, workspace_restore), register handlers, add automated headless integration tests.
- CLI Parity: Add rpassword = "7", update ExportArgs (pub plaintext: bool), secure export for .secwet with prompt, plaintext guard requiring --plaintext, invariant tests in cli_tests.rs.
- Zero failures, zero warnings, genuine logic, strict write ownership: apps/desktop/src-tauri/ and crates/secwet-cli/.

## Current Parent
- Conversation ID: 1ebf4374-d237-49fe-9aa4-ecab43ee8aa1
- Updated: 2026-10-27T17:31:00Z

## Task Summary
- **What to build**: Tauri IPC commands + CLI export/restore parity with recovery keys and encrypted envelope export.
- **Success criteria**:
  - `cargo test -p secwet-desktop` passes cleanly (all 41 tests pass).
  - `cargo test -p secwet-cli` passes cleanly (all 66 tests pass).
  - Invariant tests pass.
- **Interface contracts**: PROJECT.md, survey report, M3-1 handoff.
- **Code layout**: apps/desktop/src-tauri/, crates/secwet-cli/.

## Key Decisions Made
- Added `tauri-plugin-dialog = "2"` and granted `"dialog:default"` in `capabilities/default.json`.
- Implemented `recovery_key_create`, `recovery_key_replace`, `recovery_status`, `workspace_export`, and `workspace_restore` with pure `*_impl` separation to support both GUI interactions and headless testing.
- Added headless fallback in `workspace_export_impl` and `workspace_restore_impl` when `path: Option<PathBuf>` is `Some(...)`; when `None`, invokes native Tauri dialog.
- Closed active database instances in `workspace_restore_impl` before invoking `Secwet::restore_from_export` to prevent file locking issues during SQLite database re-creation.
- Added `rpassword = "7"` and `--plaintext` flag requirement in `secwet export`:
  - When `--out` ends with `.secwet`, prompts for recovery key on stderr without echo using `rpassword` (or piped stdin in non-terminal environments) and creates encrypted envelope snapshot.
  - When exporting unencrypted formats (`dotenv` or `json`), aborts with code 1 unless explicit `--plaintext` flag is provided.
- Added mandatory invariant tests:
  - `dotenv_export_requires_plaintext_flag` in `crates/secwet-cli/tests/cli_tests.rs`
  - `cli_export_secwet_envelope_roundtrip` in `crates/secwet-cli/tests/cli_tests.rs`
  - `test_recovery_and_workspace_export_restore_lifecycle_roundtrip` in `apps/desktop/src-tauri/tests/commands_tests.rs`

## Artifact Index
- DISPATCH.md — Assignment from orchestrator
- BRIEFING.md — Situational awareness
- progress.md — Liveness & step tracking
- handoff.md — Final deliverable report

## Change Tracker
- **Files modified**:
  - `apps/desktop/src-tauri/Cargo.toml`: Added `tauri-plugin-dialog = "2"`
  - `apps/desktop/src-tauri/capabilities/default.json`: Added `"dialog:default"`
  - `apps/desktop/src-tauri/src/lib.rs`: Initialized `tauri_plugin_dialog::init()` and registered 5 recovery/backup commands in `generate_handler!`
  - `apps/desktop/src-tauri/src/commands.rs`: Implemented `RecoveryStatusDto`, `ExportSummaryDto`, and commands `recovery_key_create`, `recovery_key_replace`, `recovery_status`, `workspace_export`, `workspace_restore` with `*_impl` separation
  - `apps/desktop/src-tauri/tests/commands_tests.rs`: Added `test_recovery_and_workspace_export_restore_lifecycle_roundtrip`
  - `crates/secwet-cli/Cargo.toml`: Added `rpassword = "7"`
  - `crates/secwet-cli/src/main.rs`: Added `ExportArgs.plaintext` flag, .secwet encrypted export with password prompt, and plaintext guard requiring `--plaintext`
  - `crates/secwet-cli/tests/cli_tests.rs`: Added `dotenv_export_requires_plaintext_flag` and `cli_export_secwet_envelope_roundtrip`, updated existing export test
  - `crates/secwet-cli/tests/cli_export_e2e_tests.rs`: Updated unencrypted export invocations with `--plaintext`
  - `crates/secwet-cli/tests/challenger_stress_tests.rs`: Updated unencrypted export invocation with `--plaintext`
  - `crates/secwet-cli/src/commands/file.rs`: Resolved needless_option_as_deref lint
  - `crates/secwet-cli/src/commands/init.rs`: Resolved useless_conversion lint
  - `crates/secwet-cli/src/commands/secret.rs`: Resolved useless_borrows_in_formatting and useless_conversion lints
- **Build status**: PASS
- **Pending issues**: None

## Quality Status
- **Build/test result**:
  - `cargo test -p secwet-desktop`: 41 passed; 0 failed; 0 warnings
  - `cargo test -p secwet-cli`: 66 passed; 0 failed; 0 warnings
- **Lint status**:
  - `cargo clippy -p secwet-desktop`: 0 warnings
  - `cargo clippy -p secwet-cli`: 0 warnings
- **Tests added/modified**:
  - `test_recovery_and_workspace_export_restore_lifecycle_roundtrip` (Tauri IPC headless roundtrip)
  - `dotenv_export_requires_plaintext_flag` (CLI plaintext requirement invariant)
  - `cli_export_secwet_envelope_roundtrip` (CLI encrypted envelope export and restore roundtrip)

## Loaded Skills
- None
