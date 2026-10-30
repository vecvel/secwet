# Forensic Audit Report — Milestone M3-3 Remediation

**Work Product**: `apps/desktop/src` and test harness (`apps/desktop/scripts/empirical_challenge.mjs`)  
**Profile**: General Project (Development Mode per `ORIGINAL_REQUEST.md`)  
**Verdict**: **CLEAN**

---

## 1. Observation

### 1.1 Monospace Font Audit (PASS)
- Executed empirical grep across the entirety of `apps/desktop/src/`:
  ```bash
  grep -rnEI "ui-monospace|Courier|Consolas|Monaco|Menlo|monospace" apps/desktop/src/
  ```
  **Result**: Exit code 1 (0 matches found across all 43 desktop stylesheets).
- Directly inspected `apps/desktop/src/screens/settings/SettingsScreen.module.css` at the 5 lines previously flagged in `auditor_m3_3/handoff.md`:
  - Line 53 (`.codeSnippet`): `font-family: var(--font-sans);`
  - Line 72 (`.sectionDesc code`): `font-family: var(--font-sans);`
  - Line 101 (`.codeCardTitle`): `font-family: var(--font-sans);`
  - Line 107 (`.codePre`): `font-family: var(--font-sans);`
  - Line 142 (`.commandCode`): `font-family: var(--font-sans);`
- Confirmed: ZERO forbidden monospace font declarations exist anywhere in `apps/desktop/src/`. All secret values, code snippets, pre elements, and card titles strictly follow `docs/ui-rules.md` ("System font only. No extra fonts, including no monospace").

### 1.2 Steady Border & Hover Audit (PASS)
- Executed empirical grep across `apps/desktop/src/` for fractional border widths:
  ```bash
  grep -rnEI "1\.5px" apps/desktop/src/
  grep -rnEI "border.*[0-9]+\.[0-9]+px" apps/desktop/src/
  ```
  **Result**: Exit code 1 (0 matches found across `apps/desktop/src/`).
- Inspected `apps/desktop/src/screens/items/AssetManager.module.css`:
  - Line 15: `border: 1px dashed var(--color-border-strong);` (steady 1px border; replaced `1.5px`).
  - Line 20: `transition: border-color var(--duration-fast) ease;` (background transition removed).
  - Lines 23–25: `.dropzone:hover { border-color: var(--color-accent); }` (forbidden `background: var(--color-accent-tint-soft)` removed; complies with `docs/ui-rules.md` "No hover backgrounds anywhere").
- Inspected `apps/desktop/src/screens/overview/OverviewScreen.module.css`:
  - Line 196: `border: 1px solid var(--color-border-strong);` on `.num` (steady 1px border; replaced `1.5px`).
- Inspected `apps/desktop/src/screens/settings/SettingsScreen.module.css`:
  - Lines 157–162: `.copyIconBtn:hover { color: var(--color-text-primary) !important; }` (forbidden `background: var(--color-surface) !important;` removed; background remains `transparent !important`).

### 1.3 Fake/Mock Logic Audit (PASS)
- `apps/desktop/src/screens/recovery/CreateRecoveryKeyDialog.tsx`:
  - Lines 32–34: Invokes `await api.recoveryKeyReplace()` or `await api.recoveryKeyCreate()` based on `replacing` prop.
  - Confirmed ZERO client-side random string generators or math/pseudo-crypto mocks. Key generation delegates to Tauri backend / core engine.
- `apps/desktop/src/screens/recovery/ExportDialog.tsx`:
  - Lines 63–72: Dynamically invokes `@tauri-apps/plugin-dialog` `save()` with default filename `secwet-export-YYYYMMDD.secwet` and `.secwet` filter.
  - Line 79: Invokes `await store.exportWorkspace(targetPath, normalizedKey)`.
- `apps/desktop/src/screens/recovery/RestoreDialog.tsx`:
  - Lines 36–44: Dynamically invokes `@tauri-apps/plugin-dialog` `open()` with `.secwet` filter.
  - Line 66: Invokes `await store.restoreWorkspace(filePath, normalizedKey, deviceName.trim())`.
- `apps/desktop/src/screens/onboarding/OnboardingScreen.tsx`:
  - Line 95: Provides genuine "Restore from Backup" action button invoking `onRestoreBackup`.
- `apps/desktop/src/components/UnlockScreen.tsx`:
  - Lines 74–78: Conditionally renders "Restore from backup" action button invoking `onRestore`.
- `apps/desktop/src/lib/store.ts`:
  - Lines 882–887: `replaceRecoveryKey()` delegates to `api.recoveryKeyReplace()`.
  - Lines 889–891: `exportWorkspace()` delegates to `api.workspaceExport(filePath, recoveryKey)`.
  - Lines 893–904: `restoreWorkspace()` delegates to `api.workspaceRestore(filePath, recoveryKey, deviceName)` and reloads all state upon unlock.
- `apps/desktop/src/lib/api.ts`:
  - Lines 2192–2208: `recoveryKeyCreate` and `recoveryKeyReplace` invoke Tauri commands `recovery_key_create` and `recovery_key_replace`.
  - Lines 2218–2244: `workspaceExport` and `workspaceRestore` invoke Tauri commands `workspace_export` and `workspace_restore`.

### 1.4 Test Harness Dynamic Audit (PASS)
- Inspected `apps/desktop/scripts/empirical_challenge.mjs` Test 8.1 (lines 766–851):
  - Uses recursive filesystem directory walk `getAllCssFiles(srcDir)` discovering all 43 stylesheets in `apps/desktop/src/` (`assert.ok(cssFiles.length >= 40)`).
  - Dynamically scans every single file line-by-line for:
    - Forbidden monospace fonts: `ui-monospace`, `Courier`, `Consolas`, `Monaco`, `Menlo`, `monospace`.
    - Fractional border widths: `(?<![\w-])border(?:-(?:top|right|bottom|left|width))?\s*:[^;]*\b\d+\.\d+px\b`.
    - Non-steady box borders: values other than `1px` or `0px`.
    - Explicit usage of `var(--font-sans)` in `ConfirmDialog.module.css`.
  - Confirmed: Test 8.1 is fully dynamic and no longer hardcoded to a single CSS file.

### 1.5 Verification Suite Execution (PASS)
1. **TypeScript Typecheck**:
   - Command: `pnpm typecheck` (`tsc --noEmit`)
   - Result: Exit code 0 (zero errors).
2. **Empirical Challenge Test Suite**:
   - Command: `node apps/desktop/scripts/empirical_challenge.mjs`
   - Result: Exit code 0 (`SUMMARY: 32 passed, 0 failed out of 32 tests`).
3. **Desktop Production Build**:
   - Command: `pnpm desktop:build` (`pnpm tokens && pnpm --filter @secwet/desktop build`)
   - Result: Exit code 0 (124 modules transformed, Vite production bundle generated in 2.18s).

---

## 2. Logic Chain

1. In `auditor_m3_3/handoff.md`, the previous forensic audit issued an **INTEGRITY VIOLATION** verdict because:
   - 5 forbidden monospace font declarations were present in `apps/desktop/src/screens/settings/SettingsScreen.module.css`.
   - The test script `empirical_challenge.mjs` Test 8.1 had a test coverage gap (scoping its check to only `ConfirmDialog.module.css`).
2. Additionally, UI critics flagged 1.5px fractional borders in `AssetManager.module.css` and `OverviewScreen.module.css`, as well as hover background color changes in `SettingsScreen.module.css` and `AssetManager.module.css` in violation of `docs/ui-rules.md`.
3. The remediation performed by `worker_m3_3_rem`:
   - Replaced all 5 monospace declarations in `SettingsScreen.module.css` with `var(--font-sans)`.
   - Replaced 1.5px borders in `AssetManager.module.css` and `OverviewScreen.module.css` with 1px steady borders.
   - Removed hover background overrides from `.copyIconBtn:hover` and `.dropzone:hover`.
   - Upgraded `empirical_challenge.mjs` Test 8.1 to recursively scan all 43 stylesheets for typography and border compliance.
4. Independent forensic inspection confirmed:
   - Total monospace font declarations in `apps/desktop/src/`: 0.
   - Total fractional (1.5px) border declarations in `apps/desktop/src/`: 0.
   - Hover backgrounds in target components: 0.
   - Client-side fake key generators or mock bypasses: 0.
   - Typecheck, empirical challenger tests (32/32), and production build all succeed cleanly with exit code 0.
5. All previously identified integrity violations and design rule defects have been authentically remediated without bypasses, facades, or regressions.

---

## 3. Caveats

- **Scope**: The audit was strictly scoped to `apps/desktop/src` and its verification harness (`apps/desktop/scripts/empirical_challenge.mjs`), in accordance with the dispatch assignment.
- **Cargo Test External Status**: As noted in worker handoffs, `secwet-core/src/relay_client.rs` currently contains work-in-progress relay code authored by other concurrent work streams; this does not affect the desktop frontend bundle or its IPC layer.

---

## 4. Conclusion

**Verdict**: **CLEAN**

The work product for Milestone M3-3 Remediation is authentic, verified, and complete:
- Zero monospace fonts exist across `apps/desktop/src`.
- Zero fractional (1.5px) borders exist across `apps/desktop/src`.
- All hover states strictly adhere to `docs/ui-rules.md`.
- Key derivation, export, and restore logic are fully wired to genuine Tauri IPC commands and core engine routines with zero mocks.
- Test 8.1 dynamically enforces design rules across all 43 desktop stylesheets.
- `pnpm typecheck`, `node apps/desktop/scripts/empirical_challenge.mjs`, and `pnpm desktop:build` all pass cleanly with exit code 0.

Milestone M3-3 is **APPROVED** from a Forensic Integrity perspective.

---

## 5. Verification Method

To independently reproduce this forensic audit:

```bash
# 1. Monospace font scan across desktop source (must return exit code 1 / zero matches)
grep -rnEI "ui-monospace|Courier|Consolas|Monaco|Menlo|monospace" apps/desktop/src/

# 2. Fractional border scan across desktop source (must return exit code 1 / zero matches)
grep -rnEI "1\.5px" apps/desktop/src/

# 3. Check SettingsScreen.module.css replacement lines (must show var(--font-sans))
sed -n '51,55p;70,74p;99,103p;105,109p;140,144p' apps/desktop/src/screens/settings/SettingsScreen.module.css

# 4. Check hover states in SettingsScreen.module.css and AssetManager.module.css
grep -A 2 "copyIconBtn:hover" apps/desktop/src/screens/settings/SettingsScreen.module.css
grep -A 2 "dropzone:hover" apps/desktop/src/screens/items/AssetManager.module.css

# 5. Run TypeScript typecheck
pnpm typecheck

# 6. Run Empirical Challenge verification suite (32/32 tests)
node apps/desktop/scripts/empirical_challenge.mjs

# 7. Run Desktop production build
pnpm desktop:build
```

### Invalidation Conditions:
- Any occurrence of forbidden monospace font strings in `apps/desktop/src/`.
- Any fractional border width (e.g., `1.5px`) in `apps/desktop/src/`.
- Hover background modifications in `copyIconBtn:hover` or `dropzone:hover`.
- Failure of `pnpm typecheck`, `empirical_challenge.mjs`, or `pnpm desktop:build`.
