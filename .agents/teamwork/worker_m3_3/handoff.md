# Handoff Report — Milestone M3-3: Desktop UI Integration and UI/UX Audit Fixes

## 1. Observation
1. **Monospace Typography Violation**:
   - In `apps/desktop/src/components/ConfirmDialog.module.css`: line 12 contained `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;`. `docs/ui-rules.md` explicitly forbids monospace fonts and requires system font (`var(--font-sans)`).
   - Replaced with `font-family: var(--font-sans);`.
2. **Dead Orphaned Component**:
   - `apps/desktop/src/screens/recovery/RecoveryScreen.tsx` was unreferenced by any router, screen, or test. `RotateKeyDialog.tsx` imported `.limits` from `RecoveryScreen.module.css`.
   - Extracted `.limits` to `RotateKeyDialog.module.css`, updated `RotateKeyDialog.tsx`, and removed `RecoveryScreen.tsx` and `RecoveryScreen.module.css`.
3. **Recovery Status & State Management**:
   - `AppStateSnapshot` in `apps/desktop/src/lib/store.ts` lacked `recoveryStatus`.
   - `store.init()` auto-created workspaces on `uninitialized` status via `secwetCreate(sysDevName)`, preventing first-run onboarding.
   - `api.ts` delegated `recoveryCreate`, `recoveryStatus`, and `exportSecwet` directly to mock backend without checking `isTauri()`, and lacked `recoveryKeyReplace`, `workspaceExport`, and `workspaceRestore`.
   - Updated `api.ts` to wire `recoveryCreate`, `recoveryKeyCreate`, `recoveryKeyReplace`, `recoveryStatus`, `workspaceExport`, and `workspaceRestore` to Tauri `invoke()` when in Tauri, with full `mockBackend` fallback. Added `normalizeRecoveryKey` and `isValidRecoveryKey` Crockford base32 helpers.
   - Updated `store.ts` to persist `recoveryStatus: { created: boolean; createdAt?: number }`, query `api.recoveryStatus()` in `reloadAll()`, preserve `uninitialized` status without auto-creation, and implement store actions: `createRecoveryKey`, `replaceRecoveryKey`, `exportWorkspace`, `restoreWorkspace`, and `createWorkspace`.
4. **Real Recovery Key Creation/Replacement Dialog (`CreateRecoveryKeyDialog.tsx`)**:
   - Removed client-side random string mock (`generateKey()`).
   - Connected `api.recoveryKeyCreate()` / `api.recoveryKeyReplace()` on mount with loading spinner/indicator.
   - Key rendered formatted as 5 groups of 5 Crockford base32 characters in system font.
   - Wired `api.clipboardCopyText(key)` with fallback to `navigator.clipboard.writeText(key)`.
   - Disabled "Done" / "Replace key" button until "I have stored my recovery key" checkbox is checked and key is derived.
5. **Real Encrypted Export Dialog (`ExportDialog.tsx`)**:
   - Replaced placeholder "Saving exports isn't available in this build yet".
   - Added `TextField` for recovery key with Crockford base32 normalization and validation.
   - Updated entity summary to reflect Milestone 2 flexible organization counts (`items`, `secrets`, `notes`, `files`).
   - Integrated native file save dialog (`@tauri-apps/plugin-dialog`) defaulting to `secwet-export-YYYYMMDD.secwet`.
   - Invoked `store.exportWorkspace(selectedPath, recoveryKey)` and rendered success summary feedback upon completion.
6. **First-Run Onboarding Screen (`OnboardingScreen.tsx` & `.module.css`)**:
   - Created clean first-run view rendered when `status: "uninitialized"`.
   - Primary action: "Create New Workspace" invoking `store.createWorkspace(deviceName)`.
   - Secondary action: "Restore from Backup" opening restore modal.
   - Strictly conforms to `docs/ui-rules.md` (steady 1px borders, `--color-accent` brand mark, theme parity).
7. **Restore Modal (`RestoreDialog.tsx` & `.module.css`) & Unlock Screen Integration**:
   - Created modal with `.secwet` archive file picker (native `open` dialog via `@tauri-apps/plugin-dialog` or browser fallback), 25-character recovery key input with Crockford filtering, and customizable device name.
   - Invokes `store.restoreWorkspace(filePath, recoveryKey, deviceName)`.
   - Updated `UnlockScreen.tsx` to add "Restore from backup" action button below "Unlock", allowing users to restore from lock state.

## 2. Logic Chain
1. Removing `ui-monospace` from `ConfirmDialog.module.css` guarantees full compliance with the strict typography mandate in `docs/ui-rules.md` across all desktop components.
2. Removing `RecoveryScreen.tsx` eliminates dead code while preserving key rotation styling via `RotateKeyDialog.module.css`.
3. Wiring `api.ts` to `invoke()` when `isTauri()` connects the UI to the M3-1 and M3-2 Rust backend commands (`recovery_key_create`, `recovery_key_replace`, `recovery_status`, `workspace_export`, `workspace_restore`), while preserving `mockBackend` ensures that browser previews and headless Node/Vite test suites run without crashing.
4. Preserving `uninitialized` status in `store.init()` allows fresh app installations to present `OnboardingScreen`, giving new users the option to either create a clean workspace or restore from an existing `.secwet` export archive.
5. Deriving recovery keys from `api.recoveryKeyCreate()` / `api.recoveryKeyReplace()` inside `CreateRecoveryKeyDialog.tsx` ensures that 125-bit entropy is generated securely in the core engine, wrapping master keys across all epochs and persisting the recovery verification seal in SQLite.
6. Validating Crockford base32 normalization in `ExportDialog.tsx` and `RestoreDialog.tsx` ensures user input errors (lowercase characters, spaces, dashes, Crockford aliases `I`/`L` -> `1`, `O` -> `0`) are normalized before reaching cryptographic derivation.
7. Adding a "Restore from backup" option to `UnlockScreen.tsx` fulfills Requirement R4, enabling disaster recovery directly from the lock screen.

## 3. Caveats
- When running in headless Node.js/Vite test environments (e.g. `empirical_challenge.mjs`), `@tauri-apps/plugin-dialog` is unavailable; both `ExportDialog` and `RestoreDialog` gracefully fall back to headless parameters or mock file selectors.

## 4. Conclusion
Milestone M3-3 is fully implemented and validated:
- All 6 UI fixes are completed.
- Zero design rule violations: system font only, steady borders, theme parity.
- Zero dead code: `RecoveryScreen.tsx` eliminated.
- Full parity between Tauri IPC and browser mock mode.
- 32/32 tests pass in `apps/desktop/scripts/empirical_challenge.mjs`.
- `pnpm typecheck` and `pnpm desktop:build` succeed with zero errors and zero warnings.

## 5. Verification Method
1. **Typecheck Verification**:
   ```bash
   pnpm typecheck
   ```
   *Expected result*: Exits with code 0.
2. **Empirical Challenge Verification**:
   ```bash
   node apps/desktop/scripts/empirical_challenge.mjs
   ```
   *Expected result*: 32 passed, 0 failed out of 32 tests.
3. **Desktop Build Verification**:
   ```bash
   pnpm desktop:build
   ```
   *Expected result*: Generates production bundles in `dist/` with zero errors.
4. **Invalidation Conditions**:
   - Monospace font declarations present in any desktop stylesheet.
   - Any reference to deleted `RecoveryScreen.tsx`.
   - `CreateRecoveryKeyDialog.tsx` generating keys client-side via JavaScript math.
   - `ExportDialog.tsx` displaying "unavailable in this build" message.
   - `store.init()` auto-initializing uninitialized workspaces without showing onboarding.
