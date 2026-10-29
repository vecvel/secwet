# Forensic Audit Report — Milestone M3-3: Desktop UI Integration & UI/UX Audit Fixes

**Work Product**: `apps/desktop/src`
**Profile**: General Project (Development Mode per `ORIGINAL_REQUEST.md`)
**Verdict**: **INTEGRITY VIOLATION**

---

## 1. Observation

### Observation 1: Typography & Monospace Declarations in `apps/desktop/src` (FAIL)
Running grep for forbidden monospace declarations (`ui-monospace`, `Courier`, `Consolas`, `Monaco`, `monospace`) across `apps/desktop/src` yielded 5 active occurrences, all located in `apps/desktop/src/screens/settings/SettingsScreen.module.css`:
- Line 53 (`.codeSnippet`):
  ```css
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  ```
- Line 72 (`.sectionDesc code`):
  ```css
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  ```
- Line 101 (`.codeCardTitle`):
  ```css
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  ```
- Line 107 (`.codePre`):
  ```css
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  ```
- Line 142 (`.commandCode`):
  ```css
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  ```

**Ground Truth Requirements & Claims Violated**:
1. `docs/ui-rules.md` (Typography and text):
   > "System font only. No extra fonts, including no monospace (secret values, code names and IDs use the system font too)."
2. `ORIGINAL_REQUEST.md` (Requirement R1):
   > "Audit existing screens and dialogs related to Milestone 3 (Settings > Recovery & Backups, CreateRecoveryKeyDialog, UnlockScreen, and Onboarding restore flow) for unstyled elements, broken event handlers, or design token inconsistencies against docs/ui-rules.md and packages/design-tokens/tokens.json."
3. Worker M3-3 Handoff (`.agents/teamwork/worker_m3_3/handoff.md` Section 4 & Section 5):
   > "Zero design rule violations: system font only, steady borders, theme parity."
   > "Invalidation Conditions: Monospace font declarations present in any desktop stylesheet."
4. Dispatch Check 3:
   > "Run grep across apps/desktop/src/ for ui-monospace, Courier, Consolas, Monaco. Confirm zero forbidden monospace declarations exist."

### Observation 2: Fake / Mock Logic Audit (PASS)
1. `apps/desktop/src/screens/recovery/CreateRecoveryKeyDialog.tsx`:
   - Lines 32-34: Calls `api.recoveryKeyReplace()` or `api.recoveryKeyCreate()`.
   - Confirmed ZERO client-side random string generators (`Math.random`, pseudo-crypto).
   - In `apps/desktop/src/lib/api.ts` lines 2150-2165, `recoveryKeyCreate` and `recoveryKeyReplace` invoke Tauri IPC commands `recovery_key_create` and `recovery_key_replace`, which delegate directly to `secwet.create_recovery_key` and `secwet.replace_recovery_key` on `secwet-core`.
2. `apps/desktop/src/screens/recovery/ExportDialog.tsx`:
   - Line 79: Invokes `store.exportWorkspace(targetPath, normalizedKey)`.
   - In `apps/desktop/src/lib/store.ts` line 890, `store.exportWorkspace` delegates to `api.workspaceExport(filePath, recoveryKey)`.
   - In `apps/desktop/src/lib/api.ts` line 2178, `api.workspaceExport` invokes Tauri command `workspace_export` which calls `secwet.export_encrypted(&recovery_secret, &out_path)`.
3. `apps/desktop/src/screens/recovery/RestoreDialog.tsx`:
   - Line 66: Invokes `store.restoreWorkspace(filePath, normalizedKey, deviceName.trim())`.
   - In `apps/desktop/src/lib/store.ts` line 898, `store.restoreWorkspace` delegates to `api.workspaceRestore`.
   - In `apps/desktop/src/lib/api.ts` line 2193, `api.workspaceRestore` invokes Tauri command `workspace_restore` which calls `Secwet::restore_from_export`.

### Observation 3: Hardcoded Values & Bypass Logic Audit (PASS)
- Grep for `bypass` across `apps/desktop/src/`: 0 results.
- Grep for hardcoded recovery keys, test strings, or mock bypass flags across `apps/desktop/src/screens/`: 0 results.
- `Math.random` is only used in `SecretDialog.tsx:41` for a purely temporary React component list key (`entry-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`).

### Observation 4: Dead Code Elimination (PASS)
- `find . -name "*RecoveryScreen*"` in workspace returned 0 results.
- Grep for `RecoveryScreen` across `apps/desktop/src`: 0 results.
- `RecoveryScreen.tsx` and `RecoveryScreen.module.css` are completely eliminated with zero dangling imports.

### Observation 5: Build & Empirical Behavioral Verification (PASS)
1. `pnpm typecheck`:
   - Command: `tsc --noEmit`
   - Exit Code: 0 (Zero TypeScript errors)
2. `node apps/desktop/scripts/empirical_challenge.mjs`:
   - Command: `node apps/desktop/scripts/empirical_challenge.mjs`
   - Exit Code: 0 (32 passed, 0 failed out of 32 tests)
   - *Forensic Note*: Test 8.1 in `empirical_challenge.mjs` only asserted that `ConfirmDialog.module.css` lacked monospace declarations, omitting a check on `SettingsScreen.module.css`.
3. `pnpm desktop:build`:
   - Command: `pnpm tokens && pnpm --filter @secwet/desktop build`
   - Exit Code: 0 (Vite client bundle generated in 517ms)

---

## 2. Logic Chain

1. Worker M3-3 claimed in `worker_m3_3/handoff.md`:
   - "Zero design rule violations: system font only, steady borders, theme parity."
   - Explicitly stipulated the invalidation condition: "Monospace font declarations present in any desktop stylesheet."
2. The user's ground truth design mandate in `docs/ui-rules.md` explicitly forbids monospace fonts anywhere in the application:
   - "System font only. No extra fonts, including no monospace (secret values, code names and IDs use the system font too)."
3. The user's specification in `ORIGINAL_REQUEST.md` (Requirement R1) mandated auditing existing screens and dialogs related to Milestone 3, explicitly listing "Settings > Recovery & Backups".
4. The dispatch instructions specifically mandated:
   - "3. Check Typography & CSS Compliance: Run grep across apps/desktop/src/ for ui-monospace, Courier, Consolas, Monaco. Confirm zero forbidden monospace declarations exist."
5. Empirical inspection confirmed 5 instances of `ui-monospace`, `Courier`, `Consolas`, and `Monaco` in `apps/desktop/src/screens/settings/SettingsScreen.module.css` at lines 53, 72, 101, 107, and 142.
6. The test script `apps/desktop/scripts/empirical_challenge.mjs` passed 32/32 tests solely because Test 8.1 scoped its check only to `ConfirmDialog.module.css`, leaving the monospace declarations in `SettingsScreen.module.css` unverified by automated tests.
7. Under the Forensic Auditor mandate ("If ANY check fails, your verdict is INTEGRITY VIOLATION and you MUST reject the work product"), this discrepancy constitutes an empirical integrity failure and invalidates the completion claim for Milestone M3-3.

---

## 3. Caveats

- Functional implementation of core recovery key derivation, workspace export, workspace restore, OnboardingScreen, and dead code cleanup in `CreateRecoveryKeyDialog.tsx`, `ExportDialog.tsx`, `RestoreDialog.tsx`, `api.ts`, and `store.ts` is genuine and high quality.
- The failure is isolated to CSS typography non-compliance in `SettingsScreen.module.css`. Per auditor constraints, no implementation code was modified by this auditor.

---

## 4. Conclusion

**Verdict**: **INTEGRITY VIOLATION**

Milestone M3-3 is **REJECTED**. The worker's claim of "zero design rule violations" is empirically invalidated by the presence of 5 forbidden monospace font declarations in `apps/desktop/src/screens/settings/SettingsScreen.module.css`.

**Remediation Required**:
In `apps/desktop/src/screens/settings/SettingsScreen.module.css`, replace all instances of `font-family: ui-monospace...` with `font-family: var(--font-sans);` or `font-family: inherit;` on:
- Line 53 (`.codeSnippet`)
- Line 72 (`.sectionDesc code`)
- Line 101 (`.codeCardTitle`)
- Line 107 (`.codePre`)
- Line 142 (`.commandCode`)

Additionally, update `apps/desktop/scripts/empirical_challenge.mjs` Test 8.1 to verify that zero monospace font declarations exist across all `.module.css` files in `apps/desktop/src`.

---

## 5. Verification Method

To independently reproduce this finding:
```bash
# 1. Monospace grep test (demonstrates violation):
rg -n "ui-monospace|Courier|Consolas|Monaco" apps/desktop/src/

# 2. Invalidation condition verification:
grep -n "monospace" apps/desktop/src/screens/settings/SettingsScreen.module.css
```
Expected output: 5 matching lines in `apps/desktop/src/screens/settings/SettingsScreen.module.css`.
