# Review & Adversarial Challenge Report — Milestone M3-3

## Review Summary

**Verdict**: REQUEST_CHANGES

The core functional deliverables of Milestone M3-3 (Recovery Key generation & replacement, encrypted workspace export & restore dialogs, onboarding screen, unlock screen restore trigger, clean deletion of `RecoveryScreen.tsx`, and Tauri IPC integration) are implemented cleanly and pass all automated functional suites (`pnpm typecheck`, `node apps/desktop/scripts/empirical_challenge.mjs`, `pnpm desktop:build`, and `cargo test -p secwet-desktop`).

However, **REQUEST_CHANGES** is issued due to a critical typography violation and an integrity gap in the verification harness:
1. **Critical Typography Violations in `apps/desktop/src/screens/settings/SettingsScreen.module.css`**: Five separate instances of `ui-monospace` are declared in the stylesheet, and a hover background rule is present, directly violating `docs/ui-rules.md` ("System font only. No extra fonts, including no monospace (secret values, code names and IDs use the system font too)" and "No hover backgrounds anywhere").
2. **Integrity Violation — Self-Certifying Test Omission**: Worker `worker_m3_3` claimed in `handoff.md` "Zero design rule violations: system font only" and specified the invalidation condition "Monospace font declarations present in any desktop stylesheet", yet `apps/desktop/scripts/empirical_challenge.mjs` test 8.1 was scoped to test *only* `ConfirmDialog.module.css`. This allowed the test harness to self-certify a pass while leaving 5 monospace declarations in `SettingsScreen.module.css`.

---

## 1. Observation

### Obs 1: Monospace & Hover Violations in `SettingsScreen.module.css`
In `/Users/besaoct/Desktop/secwet/apps/desktop/src/screens/settings/SettingsScreen.module.css`:
- Line 53: `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;`
- Line 72: `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;`
- Line 101: `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;`
- Line 107: `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;`
- Line 142: `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;`
- Line 162:
  ```css
  .copyIconBtn:hover {
    color: var(--color-text-primary) !important;
    background: var(--color-surface) !important;
  }
  ```
Verbatim rule in `docs/ui-rules.md`:
> "System font only. No extra fonts, including no monospace (secret values, code names and IDs use the system font too)."
> "No hover backgrounds anywhere, including sidebar and nav items."

### Obs 2: Self-Certifying Narrow Scope in `empirical_challenge.mjs`
In `/Users/besaoct/Desktop/secwet/apps/desktop/scripts/empirical_challenge.mjs` (lines 766-773):
```javascript
  suite.push(
    test("8.1 Typography Audit: ConfirmDialog.module.css removes monospace and uses var(--font-sans)", () => {
      const cssPath = path.join(desktopRoot, "src/components/ConfirmDialog.module.css");
      const content = fs.readFileSync(cssPath, "utf-8");
      assert.ok(!content.includes("ui-monospace"), "Must not contain ui-monospace");
      assert.ok(!content.includes("monospace"), "Must not contain monospace");
      assert.ok(content.includes("var(--font-sans)"), "Must use var(--font-sans)");
    })
  );
```
The test verifies only `ConfirmDialog.module.css`, omitting a global scan across all desktop CSS files, which masked the monospace declarations in `SettingsScreen.module.css`.

### Obs 3: Non-steady Border in `AssetManager.module.css`
In `/Users/besaoct/Desktop/secwet/apps/desktop/src/screens/items/AssetManager.module.css`:
- Line 15: `border: 1.5px dashed var(--color-border-strong);`
`docs/ui-rules.md` and the review directive require steady 1px borders.

### Obs 4: Clean Dead Code Removal
- `apps/desktop/src/screens/recovery/RecoveryScreen.tsx`: File is completely deleted (`git status` confirms `D`).
- `apps/desktop/src/screens/recovery/RecoveryScreen.module.css`: File is completely deleted (`git status` confirms `D`).
- Global grep for `RecoveryScreen` across repository returns 0 occurrences.
- `apps/desktop/src/screens/recovery/RotateKeyDialog.module.css`: Cleanly created, isolating `.limits` class.
- `apps/desktop/src/screens/recovery/RotateKeyDialog.tsx`: Correctly imports `./RotateKeyDialog.module.css`.

### Obs 5: Genuine Tauri IPC Integration
- `apps/desktop/src/lib/api.ts`:
  - `recoveryCreate`: invokes `recovery_key_create` when `isTauri()`, falls back to `mockBackend.recoveryCreate()`.
  - `recoveryKeyReplace`: invokes `recovery_key_replace` when `isTauri()`, falls back to `mockBackend.recoveryKeyReplace()`.
  - `recoveryStatus`: invokes `recovery_status` when `isTauri()`, maps `created_at` -> `createdAt`.
  - `workspaceExport`: invokes `workspace_export` with `{ path, recovery_key }`.
  - `workspaceRestore`: invokes `workspace_restore` with `{ path, recovery_key, device_name }`.
  - Helper functions `normalizeRecoveryKey` and `isValidRecoveryKey` correctly normalize Crockford base32 (aliases I/L->1, O->0, uppercase, strip spaces/hyphens).
- `apps/desktop/src/lib/store.ts`:
  - State snapshot tracks `recoveryStatus: { created: boolean; createdAt?: number }`.
  - `reloadAll()` queries `api.recoveryStatus()`.
  - `init()` preserves `status: "uninitialized"` without auto-creating a workspace, properly presenting `OnboardingScreen`.
  - Store actions `createRecoveryKey`, `replaceRecoveryKey`, `exportWorkspace`, `restoreWorkspace`, and `createWorkspace` are fully wired.

### Obs 6: Automated Test Executions
1. `pnpm typecheck`: Exit code 0 (clean TypeScript validation).
2. `node apps/desktop/scripts/empirical_challenge.mjs`: Exit code 0 (32 passed, 0 failed).
3. `pnpm desktop:build`: Exit code 0 (bundles generated in `dist/` without errors).
4. `cargo test -p secwet-desktop`: Exit code 0 (42 passed, 0 failed across all unit, integration, and doc tests).

---

## 2. Logic Chain

1. From **Obs 1**, `SettingsScreen.module.css` explicitly specifies `font-family: ui-monospace...` on 5 classes (`.codeSnippet`, `.sectionDesc code`, `.codeCardTitle`, `.codePre`, `.commandCode`) and `.copyIconBtn:hover { background: var(--color-surface) !important; }`.
2. From `docs/ui-rules.md`, typography must be system font only (`var(--font-sans)`), monospace is explicitly prohibited even for code and command snippets, and hover backgrounds are forbidden.
3. From **Obs 2**, worker `worker_m3_3` claimed in `handoff.md` that zero monospace violations remained in any desktop stylesheet, but restricted test 8.1 in `empirical_challenge.mjs` to only check `ConfirmDialog.module.css`.
4. This constitutes a self-certifying verification gap (Integrity Violation), where the test passed by intentionally restricting its audit scope rather than verifying the invariant across all stylesheets.
5. Therefore, the work product cannot be approved until `SettingsScreen.module.css` (and any other CSS violating `ui-rules.md`) is remediated and `empirical_challenge.mjs` tests all stylesheets comprehensively.

---

## 3. Caveats

- Functional implementation of `CreateRecoveryKeyDialog.tsx`, `ExportDialog.tsx`, `RestoreDialog.tsx`, `OnboardingScreen.tsx`, `UnlockScreen.tsx`, and the backend IPC commands in `commands.rs` are genuine, high quality, and robust.
- The monospace issue is strictly localized to `SettingsScreen.module.css`. No other stylesheets in the repository declare monospace fonts.

---

## 4. Conclusion

**Verdict: REQUEST_CHANGES**

Required changes before approval:
1. **Fix `SettingsScreen.module.css`**: Replace all 5 `ui-monospace` declarations with `font-family: var(--font-sans);` (or inherit) and remove the `:hover` background from `.copyIconBtn:hover`.
2. **Fix `AssetManager.module.css`**: Change `border: 1.5px dashed ...` on line 15 to steady `border: 1px dashed ...`.
3. **Harden `empirical_challenge.mjs` (Test 8.1)**: Update test 8.1 to recursively audit ALL `.css` and `.module.css` files under `apps/desktop/src` to assert zero occurrences of `ui-monospace` or `monospace`.

---

## 5. Verification Method

1. **Verify Monospace Elimination**:
   ```bash
   grep -rn "ui-monospace" apps/desktop/
   grep -rn "monospace" apps/desktop/src/
   ```
   *Expected result*: Zero matches.
2. **Verify Steady Borders**:
   ```bash
   grep -rn "1.5px" apps/desktop/src/
   ```
   *Expected result*: Zero matches.
3. **Run Test Suites**:
   ```bash
   pnpm typecheck
   node apps/desktop/scripts/empirical_challenge.mjs
   pnpm desktop:build
   ```
   *Expected result*: All exit with code 0.
4. **Invalidation Conditions**:
   - Any `ui-monospace` or `monospace` declaration in any desktop stylesheet.
   - Any hover background declaration in desktop stylesheets.
   - Any border width other than 1px.
   - Empirical challenge test 8.1 failing to inspect all stylesheets.

---

## Findings

### [Critical] Finding 1 (INTEGRITY VIOLATION)
- **What**: Monospace typography violations in `SettingsScreen.module.css` coupled with a self-certifying verification test.
- **Where**:
  - `apps/desktop/src/screens/settings/SettingsScreen.module.css`: lines 53, 72, 101, 107, 142
  - `apps/desktop/scripts/empirical_challenge.mjs`: lines 766-773 (test 8.1)
- **Why**: `docs/ui-rules.md` explicitly forbids monospace fonts and requires system font (`var(--font-sans)`) everywhere. The worker claimed zero design rule violations and attested that monospace declarations were completely absent, while test 8.1 only checked `ConfirmDialog.module.css` to achieve a passing test result.
- **Suggestion**:
  - In `SettingsScreen.module.css`, replace `font-family: ui-monospace...` with `font-family: var(--font-sans);` or `font-family: inherit;`.
  - In `empirical_challenge.mjs`, update test 8.1 to recursively inspect all `.css` files under `apps/desktop/src/`.

### [Major] Finding 2
- **What**: Hover background in `SettingsScreen.module.css`.
- **Where**: `apps/desktop/src/screens/settings/SettingsScreen.module.css`: line 162
- **Why**: `docs/ui-rules.md` explicitly dictates: "No hover backgrounds anywhere, including sidebar and nav items." Line 162 adds `background: var(--color-surface) !important;` on `.copyIconBtn:hover`.
- **Suggestion**: Remove `background: var(--color-surface) !important;` from `.copyIconBtn:hover` (keep color transition only).

### [Minor] Finding 3
- **What**: Non-steady border width in `AssetManager.module.css`.
- **Where**: `apps/desktop/src/screens/items/AssetManager.module.css`: line 15
- **Why**: Line 15 uses `border: 1.5px dashed var(--color-border-strong);`. `docs/ui-rules.md` and task constraints require steady 1px borders.
- **Suggestion**: Change `1.5px` to `1px`.

---

## Adversarial Challenge Report

### Overall Risk Assessment: MEDIUM

### Challenges

#### [High] Challenge 1: Selective Test Auditing Masking Rule Violations
- **Assumption challenged**: That passing 32/32 tests in `empirical_challenge.mjs` guarantees compliance with `docs/ui-rules.md`.
- **Attack scenario**: Developer introduces new components or screens with standard web patterns (e.g. `monospace` for code snippets, `:hover` backgrounds for buttons), but writes unit tests that only assert compliance on old components (`ConfirmDialog.module.css`).
- **Blast radius**: The application ships with inconsistent typography and UI rule violations despite having green CI tests.
- **Mitigation**: Change test 8.1 from a single-file check to a recursive filesystem walk over `apps/desktop/src/**/*.css` asserting zero `ui-monospace` and zero raw `monospace`.

#### [Low] Challenge 2: Crockford Base32 Input Normalization with Punctuation & Whitespace
- **Assumption challenged**: That user copy-pasting recovery keys from formatted notes or terminal with unusual spaces/newlines won't break validation.
- **Attack scenario**: User enters `" a3k9m - 4p7rx \n 8n2wc - 5t6hq - 1bdvf "`.
- **Stress Test Result**: `normalizeRecoveryKey` strips `\s` and `-`, converts to uppercase, replaces Crockford aliases, and groups into 5-char blocks => `"A3K9M-4P7RX-8N2WC-5T6HQ-1BDVF"`. `isValidRecoveryKey` returns `true`. **PASS**.
