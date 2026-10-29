# Original User Request

## Approved Task Prompt — 2026-10-27T16:10:50Z

Team: Lead Architect & System Designer, Backend Engineer (Rust / Tauri / CLI), Frontend Engineer (React / TypeScript / CSS Tokens), UI/UX Critics (Multi-Critic Panel), QA & Security Testers, and Supervisor. Execute Milestone 3 (Recovery and Export) as defined in docs/IMPLEMENTATION.md (Sections F9 & F10) with an upfront gap analysis of existing UI/UX and backend functionality, complete end-to-end implementation across core crypto, desktop Tauri IPC and UI, and CLI, followed by an iterative testing and multi-critic review loop until 100% approval is achieved.

Working directory: /Users/besaoct/Desktop/secwet
Integrity mode: development

Reference: docs/IMPLEMENTATION.md (Sections F9 & F10, Section 12 M3), docs/ui-rules.md, packages/design-tokens/tokens.json

## Requirements

### R1. Upfront UI/UX and Functionality Gap Audit
Audit existing screens and dialogs related to Milestone 3 (Settings > Recovery & Backups, CreateRecoveryKeyDialog, UnlockScreen, and Onboarding restore flow) for unstyled elements, broken event handlers, or design token inconsistencies against docs/ui-rules.md and packages/design-tokens/tokens.json. Formulate and execute the fix list for identified gaps alongside Milestone 3 implementation without removing or regressing any existing features or mock-free capabilities from previous milestones.

### R2. Core Cryptography and Storage (secwet-core)
Implement `create_recovery_key` and `replace_recovery_key` generating 125-bit entropy formatted as 25-character Crockford base32 in 5 groups, deriving K_r, computing `recovery_check` verification seal, and wrapping master keys across epochs. Implement `export_to_file` and `restore_from_export` using `.secwet` envelope serialization with postcard snapshot sealed with K_r and authenticated AAD.

### R3. Desktop Tauri IPC and Dialogs (apps/desktop/src-tauri & api.ts)
Register Tauri commands `recovery_key_create`, `recovery_key_replace`, `workspace_export`, and `workspace_restore`, wiring native save and open file dialogs via `tauri-plugin-dialog` for `.secwet` export and restore.

### R4. Frontend UI Integration (apps/desktop)
Wire the Recovery Key modal in Settings > Recovery & Backups with one-time view and confirmation checkbox. Connect the Export dialog to generate real `.secwet` files, and add a Restore from Backup option to the initial onboarding/unlock flow.

### R5. CLI Parity (crates/secwet-cli)
Implement `secwet export --out <file.secwet>` prompting for recovery key without echo, and `secwet export --env <name> --format dotenv --plaintext --out .env` requiring explicit confirmation flags.

### R6. Verification Resources and Multi-Critic Quality Loop
Synthesize reference `.secwet` export fixtures and test suites for round-trip verification without removing existing test coverage. Execute an iterative multi-critic review and automated testing loop across UI/UX compliance (docs/ui-rules.md, steady borders, surface color-mix tints, theme parity) and automated suites until all tests pass with zero warnings, then perform live roundtrip verification and document proofs in walkthrough.md.

## Acceptance Criteria

### Cryptography & Storage
- [ ] `create_recovery_key` generates 125 bits of entropy formatted as 25 Crockford base32 characters in 5 groups, and derives K_r.
- [ ] `replace_recovery_key` wraps master keys across epochs with the new K_r and invalidates old recovery check.
- [ ] Recovery key input normalizes lowercase letters, spaces, dashes, and Crockford aliases (I/L -> 1, O -> 0).
- [ ] Recovery check verifies correct key and detects wrong key.
- [ ] `export_to_file` serializes all spaces, groups, items, environments, secrets, notes, and files into an encrypted `.secwet` envelope sealed with K_r and authenticated AAD.
- [ ] `restore_from_export` decrypts `.secwet` envelope and restores workspace state with 100% data fidelity.

### Desktop & UI Integration
- [ ] Settings > Recovery & Backups displays recovery key status and allows creating and replacing recovery keys with one-time view and confirmation checklist.
- [ ] Native file dialogs prompt for `.secwet` file export and restore.
- [ ] Initial onboarding/unlock flow provides a working "Restore from Backup" option.
- [ ] All new and modified UI components adhere to docs/ui-rules.md (steady borders, surface color-mix tints, light/dark mode parity, no layout shifts).
- [ ] Existing features and non-mock functionality from previous milestones remain intact with zero regressions.

### CLI Parity
- [ ] `secwet export --out <file.secwet>` exports workspace prompting for recovery key without terminal echo.
- [ ] `secwet export --env <name> --format dotenv --plaintext --out .env` outputs dotenv file only when `--plaintext` is explicitly provided.

### Verification & Invariants
- [ ] Mandatory invariant test `export_then_restore_roundtrip` passes.
- [ ] Mandatory invariant test `export_wrong_key_fails_without_detail` passes.
- [ ] Mandatory invariant test `export_file_contains_no_plaintext` passes.
- [ ] Mandatory invariant test `dotenv_export_requires_plaintext_flag` passes.
- [ ] Synthesized reference `.secwet` export fixtures and test suites pass round-trip validation.
- [ ] `cargo test -p secwet-core`, `cargo test -p secwet-cli`, and `cargo test -p secwet-desktop` pass with zero failures.
- [ ] `node apps/desktop/scripts/empirical_challenge.mjs` passes.
- [ ] `pnpm typecheck` and `pnpm desktop:build` succeed without errors.
- [ ] Live roundtrip verification (create workspace -> add secrets/files/notes -> create recovery key -> export `.secwet` -> restore on clean state -> verify 100% data fidelity) succeeds and is documented with verification proofs in `walkthrough.md`.

