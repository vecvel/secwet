## 2026-10-27T17:54:18Z
**Context**: Milestone M3-3: Desktop UI Integration and UI/UX Audit Fixes (Requirements R1 & R4).
**Identity & Working Directory**:
- Type: teamwork_worker
- Working directory: /Users/besaoct/Desktop/secwet/.agents/teamwork/worker_m3_3
- Parent Conversation ID: 1ebf4374-d237-49fe-9aa4-ecab43ee8aa1

**Mandatory Task**:
Read the original user request at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/ORIGINAL_REQUEST.md`

Read the project scope and architecture at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/orchestrator/PROJECT.md`

Read the detailed UI/UX and Frontend Gap Audit report:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/explorer_survey_1/handoff.md`

Read the UI styling specifications:
- `docs/ui-rules.md`
- `packages/design-tokens/tokens.json`

Implement Milestone M3-3 in `apps/desktop/src`:
1. **Fix 1: State Management & Store Persistence (`apps/desktop/src/lib/store.ts` and `api.ts`)**:
   - In `api.ts`: Wire `recoveryCreate`, `recoveryKeyReplace`, `recoveryStatus`, `workspaceExport`, and `workspaceRestore` to Tauri `invoke()` when in Tauri (`isTauri()`), while preserving complete, functional browser `mockBackend` implementations so tests and browser previews work.
   - In `store.ts`:
     - Add `recoveryStatus: { created: boolean; createdAt?: number }` to `AppStateSnapshot`.
     - Query `api.recoveryStatus()` in `store.init()` and `reloadAll()`.
     - In `store.init()`: DO NOT auto-create workspaces when status is `uninitialized`. Preserve `status: { status: "uninitialized" }` so `OnboardingScreen` renders.
     - Implement store actions: `createRecoveryKey`, `replaceRecoveryKey`, `exportWorkspace`, `restoreWorkspace`, `createWorkspace`.

2. **Fix 2: Typography & Dead Code Audit (`docs/ui-rules.md`)**:
   - Remove `ui-monospace` from `apps/desktop/src/components/ConfirmDialog.module.css` (line 12), ensuring all code/key/ID displays use system font (`var(--font-sans)`).
   - Remove dead orphaned file `apps/desktop/src/screens/recovery/RecoveryScreen.tsx`.

3. **Fix 3: Real Recovery Key Creation/Replacement Dialog (`CreateRecoveryKeyDialog.tsx`)**:
   - Remove client-side random string mock (`generateKey()`).
   - Call `api.recoveryKeyCreate()` or `api.recoveryKeyReplace()` on mount (with loading indicator).
   - Render the engine-derived 25-character key in 5 groups of 5 Crockford characters.
   - Support copy via `api.clipboardCopyText(key)` with fallback.
   - Enforce one-time view and disable "Done" / "Replace key" until "I have stored my recovery key" confirmation checkbox is checked.

4. **Fix 4: Real Encrypted Export Dialog (`ExportDialog.tsx`)**:
   - Add `TextField` for recovery key entry with Crockford base32 normalization.
   - Update summary fact to reflect M2 flexible organization (`items`, `secrets`, `notes`, `files`).
   - Trigger native save dialog (`@tauri-apps/plugin-dialog` or fallback `showSaveFilePicker` / mock) defaulting to `secwet-export-YYYYMMDD.secwet`.
   - Invoke `store.exportWorkspace(selectedPath, recoveryKey)`.
   - Show success notification / feedback upon export completion.

5. **Fix 5: First-Run Onboarding Screen (`OnboardingScreen.tsx` & `.module.css`)**:
   - Rendered when `status: "uninitialized"`.
   - Primary button: "Create New Workspace" (calls `store.createWorkspace()`).
   - Secondary button: "Restore from Backup" (opens restore modal).
   - Strict adherence to `docs/ui-rules.md` (steady borders, token colors, light/dark mode parity).

6. **Fix 6: Restore Modal (`RestoreDialog.tsx` & `.module.css`)**:
   - File selection for `.secwet` archive (calls native `open` file dialog filtering `.secwet`).
   - Recovery key input field with helper text and Crockford character filtering.
   - Device name input field (defaults to current system device name).
   - "Restore Workspace" button with loading/restoring state and error feedback.
   - In `apps/desktop/src/components/UnlockScreen.tsx`: Add "Restore from backup" action button below "Unlock" that opens `RestoreDialog`.

7. **Verification**:
   - Run `pnpm typecheck`
   - Run `node apps/desktop/scripts/empirical_challenge.mjs`
   - Run `pnpm desktop:build`
   - Verify zero errors and zero regressions from previous milestones.

**Write Ownership**:
You exclusively own:
- `apps/desktop/src/`
- `apps/desktop/package.json` (if `@tauri-apps/plugin-dialog` needs to be added)
- `apps/desktop/scripts/empirical_challenge.mjs`
