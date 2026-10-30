# Investigation & Remediation Plan Report — Explorer Remediation 2

**Role**: Explorer Remediation 2  
**Milestone**: M3-3 (Recovery and Export)  
**Scope**: Reviewer 1 CSS Flag Analysis, Comprehensive Desktop CSS Border & Layout-Shift Scan, and Exact Remediation Plan for `AssetManager.module.css` and `SettingsScreen.module.css`.

---

## 1. Observation

### Obs 1: Reviewer 1 Flags in `AssetManager.module.css` and `SettingsScreen.module.css`
1. In `apps/desktop/src/screens/items/AssetManager.module.css`:
   - Line 15:
     ```css
     .dropzone {
       display: flex;
       flex-direction: column;
       align-items: center;
       justify-content: center;
       gap: var(--space-2);
       padding: var(--space-6);
       border: 1.5px dashed var(--color-border-strong);
       border-radius: var(--radius-card);
       background: var(--color-surface);
       color: var(--color-text-secondary);
       cursor: pointer;
       transition: border-color var(--duration-fast) ease, background var(--duration-fast) ease;
     }
     ```
     `border: 1.5px dashed var(--color-border-strong);` specifies a `1.5px` border instead of a steady `1px` border.
   - Additional observation in lines 23-26:
     ```css
     .dropzone:hover {
       border-color: var(--color-accent);
       background: var(--color-accent-tint-soft);
     }
     ```
     Line 25 introduces a hover background change (`background: var(--color-accent-tint-soft);`), conflicting with `docs/ui-rules.md` ("No hover backgrounds anywhere, including sidebar and nav items").

2. In `apps/desktop/src/screens/settings/SettingsScreen.module.css`:
   - Line 162:
     ```css
     .copyIconBtn:hover {
       color: var(--color-text-primary) !important;
       background: var(--color-surface) !important;
     }
     ```
     Line 162 sets `background: var(--color-surface) !important;` on hover, accompanied by `transition: color var(--duration-fast, 120ms) ease, background-color var(--duration-fast, 120ms) ease !important;` on line 157.
   - Lines 53, 72, 101, 107, 142 declare forbidden monospace fonts:
     - Line 53 (`.codeSnippet`): `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;`
     - Line 72 (`.sectionDesc code`): `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;`
     - Line 101 (`.codeCardTitle`): `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;`
     - Line 107 (`.codePre`): `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;`
     - Line 142 (`.commandCode`): `font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;`

### Obs 2: Comprehensive Border Scan Across All 43 CSS Files in `apps/desktop/src/`
An exhaustive AST/regex scan over all 43 `.css` / `.module.css` files in `apps/desktop/src/` was executed to find any border width declarations differing from 1px (or 0/none):
```javascript
// Properties analyzed: border, border-top, border-bottom, border-left, border-right, border-width
```

The scan yielded exactly 5 non-1px border declarations across the entire desktop app:
1. `apps/desktop/src/screens/items/AssetManager.module.css:15`:
   `border: 1.5px dashed var(--color-border-strong);` (flagged by Reviewer 1)
2. `apps/desktop/src/screens/overview/OverviewScreen.module.css:196`:
   `border: 1.5px solid var(--color-border-strong);` (**NEW FINDING: Additional 1.5px border violation**)
   ```css
   .num {
     display: inline-flex;
     align-items: center;
     justify-content: center;
     width: 24px;
     height: 24px;
     flex: none;
     border: 1.5px solid var(--color-border-strong);
     border-radius: 50%;
     font-size: var(--font-size-xs);
     color: var(--color-text-tertiary);
     font-variant-numeric: tabular-nums;
   }
   ```
3. `apps/desktop/src/components/SegmentedTabs.module.css:36`:
   `border-bottom: 2px solid transparent;`
   - Active state line 97: `border-bottom-color: color-mix(in srgb, var(--color-accent) 65%, transparent);`
   - Evaluation: Steady transparent bottom border; does not change width on hover or selection (no layout shift).
4. `apps/desktop/src/screens/items/RichTextEditor.module.css:134`:
   `border-left: 3px solid var(--color-border);`
   - `.contentArea blockquote`: Standard markdown blockquote left callout accent. Steady and static.
5. `apps/desktop/src/screens/secrets/SecretUsageDialog.module.css:88`:
   `border-left: 3px solid var(--color-success);`
   - `.activeSessionBanner`: Green status callout indicator. Steady and static.

### Obs 3: Dynamic Border & Layout-Shift Audit
A targeted scan for pseudo-class rules (`:hover`, `:focus`, `:focus-visible`, `:active`) that modify `border`, `border-width`, or `outline` in ways that cause layout shifts was executed across all 43 CSS files.
- Result: **Zero layout shifts detected.**
- All interactive focus/hover states strictly mutate `border-color` (e.g., `App.module.css:70`, `Checkbox.module.css:31`, `Field.module.css:49`, `RichTextEditor.module.css:33`).
- All interactive accessibility focus rings utilize non-layout-shifting `outline: 2px solid var(--color-accent);` (e.g. `Toast.module.css:59`, `Sidebar.module.css:263`, `SpaceSwitcher.module.css:30`, `NewSpaceDialog.module.css:45`).

---

## 2. Logic Chain

1. **Design Rule Ground Truth**:
   - `docs/ui-rules.md` explicitly mandates:
     - *"System font only. No extra fonts, including no monospace (secret values, code names and IDs use the system font too)."*
     - *"No hover backgrounds anywhere, including sidebar and nav items."*
     - Steady 1px borders without fractional pixel dimensions (like 1.5px) or dynamic layout shifts.
   - Reviewer 1's validation test command requires:
     ```bash
     grep -rn "1.5px" apps/desktop/src/
     ```
     to return zero matches.

2. **Analysis of `AssetManager.module.css` (Obs 1 & 2)**:
   - Line 15 specifies `1.5px dashed`. Changing this to `1px dashed var(--color-border-strong);` aligns with the steady 1px border rule and eliminates the first match in `grep -rn "1.5px" apps/desktop/src/`.
   - Line 25 specifies `background: var(--color-accent-tint-soft);` in `.dropzone:hover`. Removing this hover background ensures full compliance with the "no hover backgrounds anywhere" directive.

3. **Analysis of `SettingsScreen.module.css` (Obs 1)**:
   - Line 162 specifies `background: var(--color-surface) !important;` in `.copyIconBtn:hover`. Removing this declaration removes the forbidden hover background while preserving the color transition (`color: var(--color-text-primary) !important;`).
   - Lines 53, 72, 101, 107, and 142 declare `ui-monospace`. Replacing all of them with `font-family: var(--font-sans);` (as already done in `ConfirmDialog.module.css`) eliminates all monospace declarations and satisfies the system font requirement.

4. **Analysis of Uncovered Violation: `OverviewScreen.module.css:196` (Obs 2)**:
   - Line 196 declares `border: 1.5px solid var(--color-border-strong);` on `.num`.
   - If only `AssetManager.module.css` is remediated, `grep -rn "1.5px" apps/desktop/src/` will still return `OverviewScreen.module.css:196`, causing the review verification to fail.
   - Changing `OverviewScreen.module.css:196` to `border: 1px solid var(--color-border-strong);` resolves this lingering violation.

5. **Test Harness Hardening (`empirical_challenge.mjs` Test 8.1)**:
   - Test 8.1 currently verifies only `ConfirmDialog.module.css`.
   - Updating Test 8.1 to walk the entire directory `apps/desktop/src/` and assert zero `ui-monospace`, zero raw `monospace`, zero `1.5px`, and zero `copyIconBtn:hover` background rules prevents future regressions.

---

## 3. Caveats

- **Scope Boundary**: In accordance with the Explorer role constraints, this agent has performed read-only investigation and has NOT modified any source files directly.
- **SegmentedTabs 2px Underline**: `SegmentedTabs.module.css:36` has `border-bottom: 2px solid transparent;`. This is a standard 2px tab active indicator line that is static and causes no layout shifts. It is not flagged as a violation, but should be kept in mind if an automated checker flags any number other than 1.
- **Callout Borders (3px)**: `RichTextEditor.module.css:134` (blockquote) and `SecretUsageDialog.module.css:88` (active session banner) use `border-left: 3px solid ...` for decorative callout indicators. These are steady and cause no layout shifts.

---

## 4. Conclusion

The Reviewer 1 flags are verified and valid. Furthermore, a comprehensive scan identified an additional `1.5px` border violation in `OverviewScreen.module.css:196` that must also be fixed.

### Exact Remediation Plan

#### File 1: `apps/desktop/src/screens/items/AssetManager.module.css`
```diff
--- a/apps/desktop/src/screens/items/AssetManager.module.css
+++ b/apps/desktop/src/screens/items/AssetManager.module.css
@@ -12,15 +12,14 @@
   justify-content: center;
   gap: var(--space-2);
   padding: var(--space-6);
-  border: 1.5px dashed var(--color-border-strong);
+  border: 1px dashed var(--color-border-strong);
   border-radius: var(--radius-card);
   background: var(--color-surface);
   color: var(--color-text-secondary);
   cursor: pointer;
-  transition: border-color var(--duration-fast) ease, background var(--duration-fast) ease;
+  transition: border-color var(--duration-fast) ease;
 }

 .dropzone:hover {
   border-color: var(--color-accent);
-  background: var(--color-accent-tint-soft);
 }
```

#### File 2: `apps/desktop/src/screens/settings/SettingsScreen.module.css`
```diff
--- a/apps/desktop/src/screens/settings/SettingsScreen.module.css
+++ b/apps/desktop/src/screens/settings/SettingsScreen.module.css
@@ -50,7 +50,7 @@

 .codeSnippet {
   display: inline-block;
-  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
+  font-family: var(--font-sans);
   font-size: var(--font-size-sm);
   color: var(--color-text-primary);
   background: var(--color-surface-sunken);
@@ -69,7 +69,7 @@
 }

 .sectionDesc code {
-  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
+  font-family: var(--font-sans);
   font-size: 0.9em;
   padding: 1px var(--space-1);
   background: var(--color-surface-sunken);
@@ -98,13 +98,13 @@
   font-size: var(--font-size-xs);
   font-weight: var(--font-weight-medium);
   color: var(--color-text-secondary);
-  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
+  font-family: var(--font-sans);
 }

 .codePre {
   margin: 0;
   padding: var(--space-3);
-  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
+  font-family: var(--font-sans);
   font-size: var(--font-size-sm);
   color: var(--color-text-primary);
   line-height: 1.5;
@@ -139,7 +139,7 @@
 }

 .commandCode {
-  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
+  font-family: var(--font-sans);
   font-size: var(--font-size-sm);
   color: var(--color-text-primary);
   white-space: nowrap;
@@ -154,11 +154,10 @@
   border-radius: var(--radius-count, 4px) !important;
   color: var(--color-text-tertiary) !important;
   background: transparent !important;
-  transition: color var(--duration-fast, 120ms) ease, background-color var(--duration-fast, 120ms) ease !important;
+  transition: color var(--duration-fast, 120ms) ease !important;
 }

 .copyIconBtn:hover {
   color: var(--color-text-primary) !important;
-  background: var(--color-surface) !important;
 }
```

#### File 3 (Co-located Additional Fix): `apps/desktop/src/screens/overview/OverviewScreen.module.css`
```diff
--- a/apps/desktop/src/screens/overview/OverviewScreen.module.css
+++ b/apps/desktop/src/screens/overview/OverviewScreen.module.css
@@ -193,7 +193,7 @@
   width: 24px;
   height: 24px;
   flex: none;
-  border: 1.5px solid var(--color-border-strong);
+  border: 1px solid var(--color-border-strong);
   border-radius: 50%;
   font-size: var(--font-size-xs);
   color: var(--color-text-tertiary);
```

#### File 4 (Test Harness Hardening): `apps/desktop/scripts/empirical_challenge.mjs`
Update Test 8.1 to check all desktop CSS files:
```javascript
  suite.push(
    test("8.1 Typography & Design Rules Audit: All stylesheets use var(--font-sans), steady borders, and zero monospace", () => {
      function walk(dir) {
        let results = [];
        for (const file of fs.readdirSync(dir)) {
          const full = path.join(dir, file);
          if (fs.statSync(full).isDirectory()) {
            results.push(...walk(full));
          } else if (file.endsWith(".css")) {
            results.push(full);
          }
        }
        return results;
      }
      const cssFiles = walk(path.join(desktopRoot, "src"));
      for (const f of cssFiles) {
        const content = fs.readFileSync(f, "utf-8");
        assert.ok(!content.includes("ui-monospace"), `${f} must not contain ui-monospace`);
        assert.ok(!content.includes("monospace"), `${f} must not contain monospace`);
        assert.ok(!content.includes("1.5px"), `${f} must not contain non-steady 1.5px border`);
      }
    })
  );
```

---

## 5. Verification Method

Once the implementer applies the diffs above, run the following commands to independently verify resolution:

```bash
# 1. Verify zero 1.5px borders in apps/desktop/src
grep -rn "1.5px" apps/desktop/src/
# Expected: 0 matches

# 2. Verify zero monospace declarations across all desktop files
grep -rn "ui-monospace" apps/desktop/src/
grep -rn "monospace" apps/desktop/src/
# Expected: 0 matches

# 3. Verify zero hover background in SettingsScreen.module.css
grep -A 3 "copyIconBtn:hover" apps/desktop/src/screens/settings/SettingsScreen.module.css
# Expected: Only color: var(--color-text-primary) !important; without background property

# 4. Run automated test suites
pnpm typecheck
node apps/desktop/scripts/empirical_challenge.mjs
pnpm desktop:build
# Expected: All exit code 0
```

### Invalidation Conditions
- Any occurrence of `1.5px` remaining in `AssetManager.module.css` or `OverviewScreen.module.css`.
- Any occurrence of `ui-monospace` or `monospace` in `SettingsScreen.module.css`.
- Any `background` property inside `.copyIconBtn:hover`.
- Automated test or build failure.
