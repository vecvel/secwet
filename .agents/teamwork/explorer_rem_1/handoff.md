# Forensic Investigation & Remediation Strategy Report — Milestone M3-3 Font & UI Compliance

**Investigator**: Explorer Remediation 1 (`explorer_rem_1`)  
**Scope**: `apps/desktop/src` font declarations, forensic verification of M3-3 audit findings, and line-by-line replacement strategy  
**Status**: COMPLETE (Read-Only Investigation)  

---

## 1. Observation

### Observation 1: Verification of Forensic Auditor's Findings in `SettingsScreen.module.css`
A file inspection of `/Users/besaoct/Desktop/secwet/apps/desktop/src/screens/settings/SettingsScreen.module.css` confirmed the 5 forbidden monospace font declarations reported in `auditor_m3_3/handoff.md`:

1. **Line 53** (`.codeSnippet`):
   ```css
   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
   ```
2. **Line 72** (`.sectionDesc code`):
   ```css
   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
   ```
3. **Line 101** (`.codeCardTitle`):
   ```css
   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
   ```
4. **Line 107** (`.codePre`):
   ```css
   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
   ```
5. **Line 142** (`.commandCode`):
   ```css
   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
   ```

Git history inspection (`git diff apps/desktop/src/screens/settings/SettingsScreen.module.css`) revealed that these declarations were newly introduced in Milestone M3-3 when adding styles for the CLI settings tab and code preview cards.

### Observation 2: Full Scans Across `apps/desktop/src`
Comprehensive grep and regex scans were executed across all files in `apps/desktop/src` to identify ANY other occurrences of forbidden monospace font families (`ui-monospace`, `Courier`, `Consolas`, `Monaco`, `Menlo`, `SFMono`, `Liberation Mono`, `monospace`):

- **Regex Query**: `(ui-monospace|SFMono|Menlo|Monaco|Consolas|Liberation Mono|Courier|monospace)` (case-insensitive) across `apps/desktop/src`
  - **Results**: Exactly 5 matches, all residing in `apps/desktop/src/screens/settings/SettingsScreen.module.css` (lines 53, 72, 101, 107, 142).
  - **Matches elsewhere in `apps/desktop/src`**: ZERO.
  - **Matches elsewhere in `apps/desktop`**: ZERO.
  - **Matches in `packages/`**: ZERO.

- **Exhaustive `font-family` Audit**:
  Running pattern match for `font-family:` across all stylesheets in `apps/desktop/src` returned 19 occurrences:
  - `apps/desktop/src/styles/global.css`: Line 62 (`var(--font-sans)`), Line 98 (`inherit`)
  - `apps/desktop/src/components/ConfirmDialog.module.css`: Line 12 (`var(--font-sans)`)
  - `apps/desktop/src/components/Toast.module.css`: Line 16 (`var(--font-sans)`)
  - `apps/desktop/src/App.module.css`: Line 60 (`inherit`)
  - `apps/desktop/src/layout/SpaceSwitcher.module.css`: Lines 17, 115, 139, 231, 326 (`var(--font-sans)`)
  - `apps/desktop/src/screens/items/RichTextEditor.module.css`: Line 147 (`inherit`)
  - `apps/desktop/src/screens/items/AssetPreviewDialog.module.css`: Line 27 (`inherit`)
  - `apps/desktop/src/screens/secrets/SecretUsageDialog.module.css`: Line 62 (`inherit`)
  - `apps/desktop/src/screens/settings/SettingsScreen.module.css`:
    - Line 23: `font-family: inherit;` (compliant)
    - Lines 53, 72, 101, 107, 142: Non-compliant monospace declarations

### Observation 3: Additional UI Rule Findings
Cross-referencing `reviewer_m3_3_1/handoff.md` and `docs/ui-rules.md` revealed three additional design rule non-compliances in the desktop stylesheets:

1. **Hover Background in `SettingsScreen.module.css`**:
   - Lines 160–163:
     ```css
     .copyIconBtn:hover {
       color: var(--color-text-primary) !important;
       background: var(--color-surface) !important;
     }
     ```
   - Direct violation of `docs/ui-rules.md`: *"No hover backgrounds anywhere, including sidebar and nav items."*
2. **Non-Steady Border Width in `AssetManager.module.css`**:
   - Line 15: `border: 1.5px dashed var(--color-border-strong);`
   - Direct violation of steady 1px border rule.
3. **Non-Steady Border Width in `OverviewScreen.module.css`**:
   - Line 196: `border: 1.5px solid var(--color-border-strong);`
   - Direct violation of steady 1px border rule.

### Observation 4: Test Harness Scope in `empirical_challenge.mjs`
Inspection of `apps/desktop/scripts/empirical_challenge.mjs` lines 766–773 confirmed the audit finding:
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
The test was narrowly targeted only to `ConfirmDialog.module.css`, allowing the 5 violations in `SettingsScreen.module.css` to pass undetected.

---

## 2. Logic Chain

1. **Premise 1 (`docs/ui-rules.md`)**: The design specification strictly dictates:
   > "System font only. No extra fonts, including no monospace (secret values, code names and IDs use the system font too)."
   > "No hover backgrounds anywhere, including sidebar and nav items."
2. **Premise 2 (`ORIGINAL_REQUEST.md` R1)**: Mandates auditing existing screens including "Settings > Recovery & Backups" for token inconsistencies against `docs/ui-rules.md`.
3. **Evidence (Observation 1 & 2)**: Exactly 5 forbidden monospace font declarations exist in `apps/desktop/src`, all in `apps/desktop/src/screens/settings/SettingsScreen.module.css` at lines 53, 72, 101, 107, and 142. No other files in `apps/desktop/src` contain monospace declarations.
4. **Evidence (Observation 3)**: A hover background rule exists on `.copyIconBtn:hover` in `SettingsScreen.module.css` line 162, and 1.5px borders exist in `AssetManager.module.css` and `OverviewScreen.module.css`.
5. **Evidence (Observation 4)**: Test 8.1 in `empirical_challenge.mjs` is narrowly scoped and must be expanded to recursively inspect all stylesheets in `apps/desktop/src`.
6. **Inference**: Replacing the 5 monospace declarations in `SettingsScreen.module.css` with `var(--font-sans)` will achieve 100% typography compliance across the desktop application. Eliminating the hover background and non-steady borders, alongside hardening Test 8.1, will fully resolve all integrity and review objections.

---

## 3. Caveats

- **Scope boundary**: This investigation is strictly read-only per Teamwork Explorer protocol. No production code was modified during this investigation.
- **Font-family selection**: While `inherit` would inherit `var(--font-sans)` from `body` in `global.css`, using explicit `font-family: var(--font-sans);` matches the established pattern in `ConfirmDialog.module.css:12` and eliminates any ambiguity or browser stylesheet edge cases. Both options are valid, but `var(--font-sans)` is recommended for primary elements.

---

## 4. Conclusion & Exact Replacement Strategy

All monospace font violations in the application are isolated to `apps/desktop/src/screens/settings/SettingsScreen.module.css`.

### Exact Line-by-Line Replacement Strategy

#### File 1: `apps/desktop/src/screens/settings/SettingsScreen.module.css`

##### 1. Line 53 (`.codeSnippet`)
- **Current**:
  ```css
  52:   display: inline-block;
  53:   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  54:   font-size: var(--font-size-sm);
  ```
- **Replacement**:
  ```css
  52:   display: inline-block;
  53:   font-family: var(--font-sans);
  54:   font-size: var(--font-size-sm);
  ```

##### 2. Line 72 (`.sectionDesc code`)
- **Current**:
  ```css
  71: .sectionDesc code {
  72:   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  73:   font-size: 0.9em;
  ```
- **Replacement**:
  ```css
  71: .sectionDesc code {
  72:   font-family: var(--font-sans);
  73:   font-size: 0.9em;
  ```

##### 3. Line 101 (`.codeCardTitle`)
- **Current**:
  ```css
  100:   color: var(--color-text-secondary);
  101:   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  102: }
  ```
- **Replacement**:
  ```css
  100:   color: var(--color-text-secondary);
  101:   font-family: var(--font-sans);
  102: }
  ```

##### 4. Line 107 (`.codePre`)
- **Current**:
  ```css
  106:   padding: var(--space-3);
  107:   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  108:   font-size: var(--font-size-sm);
  ```
- **Replacement**:
  ```css
  106:   padding: var(--space-3);
  107:   font-family: var(--font-sans);
  108:   font-size: var(--font-size-sm);
  ```

##### 5. Line 142 (`.commandCode`)
- **Current**:
  ```css
  141: .commandCode {
  142:   font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
  143:   font-size: var(--font-size-sm);
  ```
- **Replacement**:
  ```css
  141: .commandCode {
  142:   font-family: var(--font-sans);
  143:   font-size: var(--font-size-sm);
  ```

##### 6. Secondary UI Fix — Lines 157 & 160–163 (`.copyIconBtn` and hover)
- **Current**:
  ```css
  157:   transition: color var(--duration-fast, 120ms) ease, background-color var(--duration-fast, 120ms) ease !important;
  ...
  160: .copyIconBtn:hover {
  161:   color: var(--color-text-primary) !important;
  162:   background: var(--color-surface) !important;
  163: }
  ```
- **Replacement**:
  ```css
  157:   transition: color var(--duration-fast, 120ms) ease !important;
  ...
  160: .copyIconBtn:hover {
  161:   color: var(--color-text-primary) !important;
  162: }
  ```

---

#### File 2: `apps/desktop/src/screens/items/AssetManager.module.css`

##### Line 15 (`.dropzone` border width)
- **Current**:
  ```css
  15:   border: 1.5px dashed var(--color-border-strong);
  ```
- **Replacement**:
  ```css
  15:   border: 1px dashed var(--color-border-strong);
  ```

---

#### File 3: `apps/desktop/src/screens/overview/OverviewScreen.module.css`

##### Line 196 (`.stepNum` border width)
- **Current**:
  ```css
  196:   border: 1.5px solid var(--color-border-strong);
  ```
- **Replacement**:
  ```css
  196:   border: 1px solid var(--color-border-strong);
  ```

---

#### File 4: `apps/desktop/scripts/empirical_challenge.mjs`

##### Lines 765–773 (Test 8.1 hardening)
- **Current**:
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
- **Replacement**:
  ```javascript
  suite.push(
    test("8.1 Typography Audit: apps/desktop/src stylesheets contain zero monospace font declarations", () => {
      const srcDir = path.join(desktopRoot, "src");
      function walk(dir) {
        const entries = fs.readdirSync(dir, { withFileTypes: true });
        for (const entry of entries) {
          const full = path.join(dir, entry.name);
          if (entry.isDirectory()) {
            walk(full);
          } else if (entry.name.endsWith(".css")) {
            const content = fs.readFileSync(full, "utf-8");
            assert.ok(!content.includes("ui-monospace"), `File ${entry.name} must not contain ui-monospace`);
            assert.ok(!content.includes("monospace"), `File ${entry.name} must not contain monospace`);
            assert.ok(!content.includes("Courier"), `File ${entry.name} must not contain Courier`);
            assert.ok(!content.includes("Consolas"), `File ${entry.name} must not contain Consolas`);
            assert.ok(!content.includes("Monaco"), `File ${entry.name} must not contain Monaco`);
            assert.ok(!content.includes("Menlo"), `File ${entry.name} must not contain Menlo`);
          }
        }
      }
      walk(srcDir);
    })
  );
  ```

---

## 5. Verification Method

To independently verify after remediation:

### 1. Monospace Font Elimination
```bash
# Must return ZERO matches
rg "ui-monospace|Courier|Consolas|Monaco|Menlo|monospace" apps/desktop/src/
```

### 2. Hover Background Elimination
```bash
# Verify no hover background in SettingsScreen.module.css
rg -A 3 "copyIconBtn:hover" apps/desktop/src/screens/settings/SettingsScreen.module.css
```

### 3. Steady Borders Verification
```bash
# Must return ZERO matches
rg "1\.5px" apps/desktop/src/
```

### 4. Build & Test Commands
```bash
# 1. Typecheck
pnpm typecheck

# 2. Empirical Challenge Suite (including hardened Test 8.1)
node apps/desktop/scripts/empirical_challenge.mjs

# 3. Desktop Build
pnpm desktop:build

# 4. Tauri Desktop Unit & Integration Tests
cargo test -p secwet-desktop
```

**Invalidation Conditions**:
- Any match returned by `rg "ui-monospace|Courier|Consolas|Monaco|Menlo|monospace" apps/desktop/src/`.
- Any match returned by `rg "1\.5px" apps/desktop/src/`.
- Any background declaration inside a `:hover` pseudo-class in `apps/desktop/src/screens/settings/SettingsScreen.module.css`.
- Failure in `pnpm typecheck`, `node apps/desktop/scripts/empirical_challenge.mjs`, or `pnpm desktop:build`.
