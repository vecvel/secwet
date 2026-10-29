# Upfront UI/UX and Frontend Gap Audit (Milestone 3: Requirements R1 & R4)

**Survey Date**: 2026-10-27T16:26:00Z  
**Author**: teamwork_explorer (`explorer_survey_1`)  
**Workspace**: `/Users/besaoct/Desktop/secwet`  
**Reference Specifications**:
- `docs/IMPLEMENTATION.md` (Sections F9 & F10, Section 12 M3)
- `docs/ui-rules.md`
- `packages/design-tokens/tokens.json`
- `.agents/teamwork/ORIGINAL_REQUEST.md` (Requirements R1–R6)

---

## 1. Observation

Direct code observations from inspecting `apps/desktop/src/`, `apps/desktop/src-tauri/`, and core contracts:

### 1.1 Settings > Recovery & Backups Screen & Tab
1. **Orphaned Dead Screen**:
   - `apps/desktop/src/screens/recovery/RecoveryScreen.tsx` (110 lines) is completely orphaned. It is never imported or rendered in `App.tsx` or `SettingsScreen.tsx`.
2. **Settings Tab Recovery Implementation**:
   - In `apps/desktop/src/screens/settings/SettingsScreen.tsx` (lines 860–922), tab `"recovery"` is rendered directly with two list rows: "Recovery key" and "Encrypted export".
   - Line 43: accepts `recoveryKeyCreatedAt?: number;` and line 44: `onRecoveryKeyCreated?: () => void;`.
   - Line 239: `const hasRecoveryKey = recoveryKeyCreatedAt !== undefined;`
   - Lines 881–886: Button toggles between `"Replace"` and `"Create"`:
     ```tsx
     <Button
       variant={hasRecoveryKey ? "secondary" : "primary"}
       onClick={() => setOpenRecoveryModal("create")}
     >
       {hasRecoveryKey ? "Replace" : "Create"}
     </Button>
     ```
   - Lines 897–903: Encrypted export row button:
     ```tsx
     <Button
       variant="secondary"
       onClick={() => setOpenRecoveryModal(hasRecoveryKey ? "export" : "create")}
     >
       {hasRecoveryKey ? "Export data" : "Create key first"}
     </Button>
     ```
3. **Transient React State (No Persistent Recovery Status)**:
   - In `apps/desktop/src/App.tsx`:
     - Line 61: `const [recoveryKeyCreatedAt, setRecoveryKeyCreatedAt] = useState<number>();`
     - Line 492: `recoveryKeyCreatedAt={recoveryKeyCreatedAt}`
     - Line 493: `onRecoveryKeyCreated={() => setRecoveryKeyCreatedAt(Date.now())}`
   - `recoveryKeyCreatedAt` is held in ephemeral React state. When the app is refreshed, closed, or restarted, `recoveryKeyCreatedAt` resets to `undefined`.
   - In `OverviewScreen.tsx` line 119:
     ```tsx
     {
       id: "recovery",
       title: "Create a recovery key",
       detail: recoveryKeyCreatedAt
         ? "Stored by you, away from this device."
         : "The only way back in if you lose every device.",
       done: recoveryKeyCreatedAt !== undefined,
       action: ...
     }
     ```
     Because `recoveryKeyCreatedAt` is ephemeral, the Overview checklist resets to "Create a recovery key" on every launch.
   - In `crates/secwet-core/src/secwet.rs` line 3523:
     ```rust
     let recovery_key_created = get_meta(&self.db, "recovery_created_at")?.is_some();
     ```
     The SQLite core backend already tracks `recovery_created_at` in the `meta` table, but the frontend store never queries or binds this persistent status.

---

### 1.2 CreateRecoveryKeyDialog / Recovery Key Display Modal
1. **Client-Side Fake Key Generation**:
   - In `apps/desktop/src/screens/recovery/CreateRecoveryKeyDialog.tsx` (lines 7–14):
     ```tsx
     const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32, no I, L, O, U

     /** 25 random characters in groups of five. Display-only until the Secwet engine derives it. */
     function generateKey() {
       const bytes = crypto.getRandomValues(new Uint8Array(25));
       const chars = Array.from(bytes, (b) => ALPHABET[b % 32]).join("");
       return chars.match(/.{5}/g)!.join("-");
     }
     ```
   - The key is generated via browser client-side math rather than calling the real cryptographic engine in `secwet-core` (`create_recovery_key` or `replace_recovery_key`).
2. **Missing Backend Connection & Loading State**:
   - Line 17: `const [key] = useState(generateKey);`
   - Lines 41–43: `<Button variant="primary" onClick={onDone} disabled={!stored}>{replacing ? "Replace key" : "Done"}</Button>`
   - The modal never calls any backend command or API on mount or on confirm.
   - There is no loading spinner or error handling for backend derivation.
3. **Clipboard Handling**:
   - Line 23: `await navigator.clipboard.writeText(key);`
   - In Tauri desktop builds, secure clipboard copying should go through `api.clipboardCopyText(key)` to leverage Rust-backed clipboard management with 30-second clear.

---

### 1.3 UnlockScreen
1. **Missing Restore Option**:
   - In `apps/desktop/src/components/UnlockScreen.tsx` (lines 63–67):
     ```tsx
     action={
       <Button variant="primary" disabled={unlocking} onClick={handleUnlock}>
         {unlocking ? "Unlocking…" : "Unlock"}
       </Button>
     }
     ```
   - There is ONLY a single "Unlock" button.
   - Requirement R4 states: "add a Restore from Backup option to the initial onboarding/unlock flow. Initial onboarding/unlock flow provides a working 'Restore from Backup' option."
   - If a device is locked and the user has a `.secwet` backup, there is no UI entry point to initiate a restore.

---

### 1.4 Onboarding / Setup Flow & Restore Flow
1. **Auto-Initialization Bypassing First-Run / Onboarding**:
   - In `apps/desktop/src/lib/store.ts` (lines 216–220):
     ```typescript
     // 2. Fetch initial status
     let status = await api.secwetStatus();
     if (isUninitialized(status)) {
       const sysDevName = await api.systemDeviceName().catch(() => undefined);
       status = await api.secwetCreate(sysDevName);
     }
     ```
   - On a fresh install (`isUninitialized(status)`), `store.ts` automatically and silently invokes `secwetCreate(sysDevName)`, immediately creating a blank workspace.
   - The user is never given a first-run choice to "Create new workspace" or "Restore from backup".
2. **Absence of Restore Flow UI**:
   - There is no `RestoreDialog.tsx` or Onboarding component anywhere in `apps/desktop/src`.
   - There is no UI to pick a `.secwet` file, enter a 25-character recovery key, specify a device name, and restore the workspace.

---

### 1.5 ExportDialog & Export Trigger
1. **Placeholder Button with Hardcoded Unavailable Message**:
   - In `apps/desktop/src/screens/recovery/ExportDialog.tsx` (lines 20–22, 36–40):
     ```tsx
     <Button variant="primary" onClick={() => setAttempted(true)}>
       Save export
     </Button>
     ...
     {attempted && (
       <p className={styles.unavailable} role="status">
         Saving exports isn't available in this build yet.
       </p>
     )}
     ```
   - Clicking "Save export" merely sets `attempted = true` and shows a warning that exports are unavailable.
2. **Missing Recovery Key Input**:
   - As specified in `docs/IMPLEMENTATION.md` F9 & F10:
     - `K_r` is NEVER stored on disk in plaintext; only `recovery_check` and wrapped keys are stored in `meta`.
     - `export_encrypted(&self, recovery_key: &SecretString, out: &Path)` requires the recovery key to derive `K_r` and seal the snapshot.
   - The current `ExportDialog` has no input for the recovery key.
3. **Missing File Picker & IPC Call**:
   - Does not invoke `tauri-plugin-dialog` native file save dialog (`secwet-export-YYYYMMDD.secwet`).
   - Does not invoke Tauri command `workspace_export`.
4. **Outdated Terminology**:
   - Line 29: `{plural(secretCount, "secret")} in {plural(projectCount, "project")}, with names, notes and environments`
   - In Milestone 2's flexible organization, projects were replaced by items and groups.

---

### 1.6 API Layer & Tauri IPC
1. **Mock Backend Delegation in `api.ts`**:
   - In `apps/desktop/src/lib/api.ts` (lines 2060–2070):
     ```ts
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
     These methods delegate exclusively to `mockBackend` even when `isTauri()` is true. They never invoke Tauri IPC!
   - `recoveryKeyReplace` does not exist in `api.ts`.
   - `workspaceRestore` / `restoreSecwet` does not exist in `api.ts`.
2. **Tauri Backend Commands (`src-tauri`)**:
   - `apps/desktop/src-tauri/Cargo.toml`: does not list `tauri-plugin-dialog`.
   - `apps/desktop/package.json`: does not list `@tauri-apps/plugin-dialog`.
   - `apps/desktop/src-tauri/src/commands.rs`: does not define `recovery_key_create`, `recovery_key_replace`, `workspace_export`, or `workspace_restore`.

---

### 1.7 Design Tokens & UI Rules (`docs/ui-rules.md`)
1. **Monospace Font Violation**:
   - In `apps/desktop/src/components/ConfirmDialog.module.css` (line 12):
     ```css
     font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
     ```
   - `docs/ui-rules.md` explicitly mandates:
     > "System font only. No extra fonts, including no monospace (secret values, code names and IDs use the system font too)."
2. **Steady Borders & Surface Tints**:
   - Existing controls (`Field.module.css`, `Button.module.css`, `Checkbox.module.css`, `Dialog.module.css`) consistently adhere to:
     - 1px steady borders without layout shifts (`--color-border-strong`, `--color-border`)
     - Focus states using `color-mix(in srgb, var(--color-accent) 45%, transparent)`
     - Backgrounds using `--color-surface`, `--color-surface-sunken`, and `--color-bg`
   - All newly added inputs (recovery key input, backup file selector) must strictly follow these established classes.

---

## 2. Logic Chain

1. **Observation 1.1 & 1.6** show that `recoveryKeyCreatedAt` is stored only in ephemeral React state (`useState`) and `api.recoveryStatus()` unconditionally delegates to a mock backend that returns a fake timestamp.
   $\rightarrow$ **Inference**: Restarting the desktop app loses recovery key status in the UI, causing Overview and Settings to report "Not created" even when the SQLite database has `recovery_created_at`.
   $\rightarrow$ **Required Action**: `AppStore` must track `recoveryKeyCreatedAt` / `recoveryStatus`, populate it during `store.init()` / `reloadAll()` via `api.recoveryStatus()`, and reactively update it when keys are created or replaced.

2. **Observation 1.2 & 1.6** show that `CreateRecoveryKeyDialog` computes a mock string in JavaScript via `crypto.getRandomValues(new Uint8Array(25))` and never calls the backend.
   $\rightarrow$ **Inference**: The generated key displayed to the user is NOT derived by `secwet-core`, `K_r` is NOT derived, and `recovery_check` and `recovery_wrapped_master_keys` are never computed or saved to SQLite.
   $\rightarrow$ **Required Action**: `CreateRecoveryKeyDialog` must call `api.recoveryKeyCreate()` (or `api.recoveryKeyReplace()`) on mount, display a loading state during key generation, present the engine-derived 25-character Crockford base32 key, provide copy through `api.clipboardCopyText()`, and only activate "Done" once the confirmation checkbox is checked.

3. **Observation 1.4** shows that `store.init()` unconditionally calls `api.secwetCreate(sysDevName)` when `status` is `uninitialized`.
   $\rightarrow$ **Inference**: Users installing the app on a secondary device or after a system wipe are forced into a newly generated blank workspace without an option to restore from their `.secwet` export envelope.
   $\rightarrow$ **Required Action**: When `status` is `uninitialized`, `store.ts` must keep `status: { status: "uninitialized" }`. `App.tsx` must render an Onboarding view offering two distinct paths: "Create New Workspace" and "Restore from Backup".

4. **Observation 1.3** shows that `UnlockScreen` contains only an "Unlock" action.
   $\rightarrow$ **Inference**: If a user is locked out, forgot their passcode, or transferred an export to a locked device, there is no restore mechanism available from the lock screen.
   $\rightarrow$ **Required Action**: Add a secondary/tertiary action button "Restore from backup" on `UnlockScreen` that opens the restore dialog.

5. **Observation 1.5 & 1.6** show that `ExportDialog` shows "Saving exports isn't available in this build yet" and does not collect a recovery key or open a native save dialog.
   $\rightarrow$ **Inference**: Encrypted export cannot function because `export_encrypted` requires the user's recovery key to derive `K_r` and seal the postcard snapshot.
   $\rightarrow$ **Required Action**: `ExportDialog` must include a recovery key input field (with Crockford normalization), trigger `save()` from `@tauri-apps/plugin-dialog` (defaulting to `secwet-export-YYYYMMDD.secwet`), call `api.workspaceExport(filePath, recoveryKey)`, and report export success.

6. **Observation 1.7** shows that `ConfirmDialog.module.css` uses `ui-monospace`.
   $\rightarrow$ **Inference**: This directly violates the typography rule in `docs/ui-rules.md`.
   $\rightarrow$ **Required Action**: Replace monospace font family in `ConfirmDialog.module.css` with system font (`var(--font-sans)`).

---

## 3. Caveats

1. **Backend Dependency**: Full frontend integration relies on Tauri IPC commands (`recovery_key_create`, `recovery_key_replace`, `workspace_export`, `workspace_restore`, `recovery_status`) implemented in `secwet-desktop` and `secwet-core`. The frontend must provide graceful fallback in browser mock mode (`mockBackend`) so empirical tests and browser previews continue to function without Tauri.
2. **File Dialog Testing in CI**: In headless Node.js/Vite environments (such as `empirical_challenge.mjs`), `@tauri-apps/plugin-dialog` is unavailable. The file selection and save logic in the frontend must use an abstraction that falls back to file inputs/mock paths in non-Tauri environments.
3. **No Regressions**: No existing functionality from Milestone 1 and Milestone 2 (secret rows, in-use badges, flexible organization spaces/groups/items, rich text editor, assets manager) may be altered or regressed.

---

## 4. Conclusion & Itemized Fix Plan

### Final Assessment
The frontend codebase in `apps/desktop/` contains polished design primitives (tokens, buttons, fields, dialogs) and a high baseline of test passing, but Milestone 3 functionality is currently 100% mocked or placeholder:
- Recovery key creation is a client-side JavaScript mock.
- Export displays a placeholder "unavailable" message and lacks recovery key input and native save dialog.
- Restore is completely missing (no UI, no store action, no first-run onboarding screen).
- Recovery status is ephemeral and not persisted in `store.ts`.
- `RecoveryScreen.tsx` is orphaned dead code.
- `ConfirmDialog.module.css` contains an illegal monospace font declaration.

### Itemized Implementation Fix List

#### Fix 1: State Management & Store Persistence (`apps/desktop/src/lib/store.ts` & `api.ts`)
- [ ] Add `recoveryStatus: { created: boolean; createdAt?: number }` to `AppStateSnapshot`.
- [ ] In `store.init()`: Query `api.recoveryStatus()` on load when unlocked.
- [ ] In `store.init()`: DO NOT auto-call `secwetCreate` on `uninitialized`; preserve `status: { status: "uninitialized" }` so onboarding can render.
- [ ] Add store methods:
  - `createRecoveryKey(): Promise<string>`
  - `replaceRecoveryKey(): Promise<string>`
  - `exportWorkspace(filePath: string, recoveryKey: string): Promise<string>`
  - `restoreWorkspace(filePath: string, recoveryKey: string, deviceName?: string): Promise<SecwetStatus>`
  - `createWorkspace(deviceName?: string): Promise<SecwetStatus>`
- [ ] Update `apps/desktop/src/lib/api.ts`:
  - Wire `recoveryCreate`, `recoveryKeyReplace`, `recoveryStatus`, `workspaceExport`, and `workspaceRestore` to Tauri `invoke()` when `isTauri()`, with complete browser `mockBackend` fallbacks.

#### Fix 2: First-Run Onboarding & Restore Entry Point
- [ ] Create `apps/desktop/src/screens/onboarding/OnboardingScreen.tsx` and `.module.css`:
  - Presented when `status` is `"uninitialized"`.
  - Prominent "Create New Workspace" primary action.
  - Secondary "Restore from Backup" action.
- [ ] Update `apps/desktop/src/components/UnlockScreen.tsx`:
  - Add "Restore from backup" action button below "Unlock".
  - Wire `onOpenRestore` prop from `App.tsx`.

#### Fix 3: Restore Backup Modal (`RestoreDialog.tsx`)
- [ ] Create `apps/desktop/src/screens/recovery/RestoreDialog.tsx` and `.module.css`:
  - Step 1: Backup file selector (calls native `open` file dialog filtering `.secwet`, with file path display).
  - Step 2: Recovery key `TextField` with helper text (auto-uppercasing and Crockford character filtering).
  - Step 3: Device name `TextField` (defaults to current system device name).
  - Step 4: "Restore Workspace" button with loading/restoring state and error banner.
  - On success: updates store and transitions app to unlocked.

#### Fix 4: Real Recovery Key Creation/Replacement Dialog (`CreateRecoveryKeyDialog.tsx`)
- [ ] Remove `generateKey()` client-side mock.
- [ ] Call `api.recoveryKeyCreate()` or `api.recoveryKeyReplace()` on mount (with loading indicator).
- [ ] Display the engine-derived 25-character key formatted as 5 groups of 5 Crockford characters.
- [ ] Update copy action to use `api.clipboardCopyText(key)` with fallback to `navigator.clipboard.writeText`.
- [ ] Ensure "Done" / "Replace key" is disabled until "I have stored my recovery key" is checked.
- [ ] Clean up orphaned `apps/desktop/src/screens/recovery/RecoveryScreen.tsx`.

#### Fix 5: Real Encrypted Export Dialog (`ExportDialog.tsx`)
- [ ] Add `TextField` for Recovery Key entry in `ExportDialog.tsx` with Crockford base32 normalization.
- [ ] Update fact summary to reflect M2 flexible organization (`items`, `secrets`, `notes`, `files`).
- [ ] Replace "Saving exports isn't available in this build yet" with real action:
  - Prompts native save file dialog via `tauri-plugin-dialog` default filename `secwet-export-YYYYMMDD.secwet`.
  - Calls `store.exportWorkspace(selectedPath, recoveryKey)`.
  - Shows success notification / feedback upon export completion.

#### Fix 6: UI Rules & Typography Parity (`docs/ui-rules.md`)
- [ ] Remove `ui-monospace` from `apps/desktop/src/components/ConfirmDialog.module.css` (line 12), ensuring all code/key/ID displays use system font (`var(--font-sans)`).
- [ ] Ensure all new dialogs and inputs use steady 1px borders (`--color-border-strong`), token-based surface colors (`--color-surface`, `--color-surface-sunken`), and light/dark theme parity.

---

## 5. Verification Method

To independently verify the audit findings and validate future implementation:

1. **Verify Current Gaps**:
   ```bash
   # Confirm orphaned RecoveryScreen
   git grep -n "RecoveryScreen" apps/desktop/src/
   # Confirm mock key generation in CreateRecoveryKeyDialog
   git grep -n "generateKey" apps/desktop/src/screens/recovery/
   # Confirm auto-create on uninitialized status in store.ts
   git grep -n "isUninitialized" apps/desktop/src/lib/store.ts
   # Confirm monospace violation in ConfirmDialog.module.css
   git grep -n "ui-monospace" apps/desktop/src/
   ```

2. **Verify Baseline Non-Regression**:
   ```bash
   pnpm --filter @secwet/desktop typecheck
   node apps/desktop/scripts/empirical_challenge.mjs
   cargo test --workspace --no-run
   ```

3. **Invalidation Conditions**:
   - If `CreateRecoveryKeyDialog` already derives keys from `secwet-core`, this finding is invalidated (verified: it currently uses `crypto.getRandomValues(new Uint8Array(25))`).
   - If `ExportDialog` already generates `.secwet` files, this finding is invalidated (verified: line 38 explicitly renders "Saving exports isn't available in this build yet").
   - If a Restore flow already exists in `apps/desktop/src`, this finding is invalidated (verified: grep for `restore` across `apps/desktop/src` returns zero matches).
