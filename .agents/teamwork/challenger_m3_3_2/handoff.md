# Empirical Challenge & Verification Report: Milestone M3-3

**Author**: Empirical Challenger 2 (`challenger_m3_3_2`)  
**Target Milestone**: Milestone M3-3 (Desktop UI Integration & UI/UX Audit Fixes)  
**Parent Agent**: `1ebf4374-d237-49fe-9aa4-ecab43ee8aa1`  
**Verdict**: **`APPROVE`**  
**Date**: 2026-10-27T18:52:00Z  

---

## Challenge Summary

**Overall risk assessment**: **LOW** (Production-ready with 100% empirical verification pass rate across all unit, integration, UI flow, and stress suites).

---

## 1. Observation

The implementation and integration of Milestone M3-3 were evaluated across four core focus areas via empirical test execution and code analysis:

### 1.1 First-run Onboarding vs Restore Flow
- In `apps/desktop/src/App.tsx` (lines 151–170):
  ```tsx
  if (isUninitialized(status)) {
    return (
      <div className={styles.shell}>
        <OnboardingScreen
          onCreateWorkspace={async (deviceName) => {
            await store.createWorkspace(deviceName);
          }}
          onRestoreBackup={() => setRestoringBackup(true)}
          defaultDeviceName={effectiveDeviceName}
        />
        {restoringBackup && (
          <RestoreDialog
            onClose={() => setRestoringBackup(false)}
            onRestored={() => setRestoringBackup(false)}
            defaultDeviceName={effectiveDeviceName}
          />
        )}
      </div>
    );
  }
  ```
- In `apps/desktop/src/screens/onboarding/OnboardingScreen.tsx` (lines 25–35, 82–97):
  - Primary button triggers `onCreateWorkspace(deviceName.trim() || undefined)`.
  - Secondary button triggers `onRestoreBackup`, setting `restoringBackup = true` and mounting `RestoreDialog`.
  - Inputs and action buttons are disabled during `creating` state.
  - Failures in workspace creation are trapped and surfaced in `<Notice tone="warning" label="Setup error">{error}</Notice>`.
- In `apps/desktop/src/lib/store.ts` (lines 906–914):
  - `store.createWorkspace(deviceName)` invokes `api.secwetCreate()`, transitions store status from `uninitialized` to `unlocked`, and triggers `reloadAll()` to provision default space and groups.

### 1.2 UnlockScreen Restore Integration
- In `apps/desktop/src/components/UnlockScreen.tsx` (lines 65–75):
  ```tsx
  <div className={styles.actions}>
    <Button variant="primary" disabled={unlocking} onClick={handleUnlock}>
      {unlocking ? "Unlocking…" : "Unlock"}
    </Button>
    {onRestore && (
      <Button variant="secondary" disabled={unlocking} onClick={onRestore}>
        Restore from backup
      </Button>
    )}
  </div>
  ```
- In `apps/desktop/src/App.tsx` (lines 173–190):
  - When `isLocked(status)` is true, `UnlockScreen` renders with `onRestore={() => setRestoringBackup(true)}`.
  - When "Restore from backup" is clicked, `restoringBackup` mounts `RestoreDialog`.
  - Upon successful restore, `store.restoreWorkspace` calls `api.workspaceRestore`, closing old active instances, restoring state into SQLite, transitioning status to `unlocked`, and updating `App.tsx` state to unmount the lock screen.

### 1.3 Corrupted & Invalid Backup Handling
- Crockford Base32 normalization and validation in `apps/desktop/src/lib/api.ts` (lines 283–318):
  - `CROCKFORD_CHARS = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"`
  - `normalizeRecoveryKey` converts lowercase letters, strips hyphens and whitespace, substitutes aliases (`I`/`L` -> `1`, `O` -> `0`), and clamps output to groups of 5 up to 25 characters.
  - `isValidRecoveryKey` rejects keys that are not exactly 25 characters or contain non-Crockford characters (e.g. `U`, `!`, `@`).
- Form submission gating in `apps/desktop/src/screens/recovery/RestoreDialog.tsx` (lines 29–32, 86–92):
  - `const canSubmit = Boolean(filePath.trim()) && isKeyValid && Boolean(deviceName.trim()) && !restoring;`
  - "Restore Workspace" button has `disabled={!canSubmit}`.
- Error handling and recovery in `RestoreDialog.tsx` (lines 61–74, 97–101):
  - Traps backend rejection (e.g. wrong key, corrupted envelope, missing file) via `try/catch`.
  - Formats error with `formatUiError(err, "Failed to restore workspace. Verify your recovery key and archive file.")` and renders it in `<Notice tone="warning" label="Restore error">`.
  - `finally` block sets `setRestoring(false)`, allowing user to correct input and retry without reloading the app.
  - Store state remains unpoisoned and operational.

### 1.4 Design Tokens, Steady Borders, and Typography Audit
- `apps/desktop/src/components/ConfirmDialog.module.css`:
  - Line 12: `font-family: var(--font-sans);`
  - Zero instances of `ui-monospace`, `monospace`, `Menlo`, `Monaco`, `Consolas`, or `Courier`.
- `apps/desktop/src/screens/onboarding/OnboardingScreen.module.css`:
  - Steady border: `border: 1px solid var(--color-border-strong);`
  - Tokens: `var(--color-bg)`, `var(--color-accent)`, `var(--color-surface)`, `var(--radius-dialog)`, `var(--shadow-overlay)`.
  - Zero hardcoded colors.
- `apps/desktop/src/screens/recovery/RestoreDialog.module.css`:
  - Steady border: `border: 1px solid var(--color-border-strong);`
  - Tokens: `var(--control-height)`, `var(--radius-control)`, `var(--color-surface)`.
  - Zero hardcoded colors.
- `apps/desktop/src/screens/recovery/RotateKeyDialog.module.css`:
  - Tokens: `var(--space-2)`, `var(--space-5)`, `var(--font-size-md)`, `var(--color-text-secondary)`.
- Dead code audit:
  - `apps/desktop/src/screens/recovery/RecoveryScreen.tsx` and `RecoveryScreen.module.css` do not exist.
- Dynamic border shift audit:
  - Zero pseudo-classes (`:hover`, `:focus`, `:active`) in any recovery or dialog stylesheet modify `border-width` or alter element sizing.

### 1.5 Automated Verification Suite Results

#### Command 1: TypeScript Check
```bash
$ pnpm typecheck
$ pnpm --filter @secwet/desktop typecheck
$ tsc --noEmit
# Exit code: 0 (zero errors)
```

#### Command 2: Existing Empirical Challenge Harness
```bash
$ node apps/desktop/scripts/empirical_challenge.mjs
# Exit code: 0
SUMMARY: 32 passed, 0 failed out of 32 tests.
```

#### Command 3: Challenger 2 Adversarial Stress Harness (`apps/desktop/scripts/challenger_2_m3_3.mjs`)
```bash
$ node apps/desktop/scripts/challenger_2_m3_3.mjs
=================================================================
SECWET MILESTONE M3-3: CHALLENGER 2 EMPIRICAL ADVERSARIAL HARNESS
=================================================================

Executing 17 adversarial tests...

  ✓ PASS: 1.1 App.tsx renders OnboardingScreen when status is uninitialized
  ✓ PASS: 1.2 OnboardingScreen source: Create button triggers onCreateWorkspace with deviceName
  ✓ PASS: 1.3 Store Lifecycle: store.createWorkspace transitions from uninitialized to unlocked
  ✓ PASS: 2.1 App.tsx renders UnlockScreen with Restore from backup action
  ✓ PASS: 2.2 UnlockScreen source: Renders secondary Restore from backup button when onRestore provided
  ✓ PASS: 2.3 Store Lifecycle: store.restoreWorkspace restores over locked workspace and transitions to unlocked
  ✓ PASS: 3.1 Recovery Key Normalization: Handles aliases, punctuation, lowercase and clamps at 25
  ✓ PASS: 3.2 Recovery Key Validation: Enforces Crockford base32 alphabet and exact 25-character length
  ✓ PASS: 3.3 RestoreDialog Form Guarding: Prevents submission with incomplete inputs
  ✓ PASS: 3.4 RestoreDialog Error Handling: Traps backend failures and renders warning Notice
  ✓ PASS: 3.5 Adversarial Engine Error Recovery: Corrupted restore failure leaves store operational
  ✓ PASS: 4.1 CSS Tokens Audit: OnboardingScreen.module.css uses standard tokens and steady 1px border
  ✓ PASS: 4.2 CSS Tokens Audit: RestoreDialog.module.css uses standard tokens and steady 1px border
  ✓ PASS: 4.3 CSS Tokens Audit: RotateKeyDialog.module.css uses typography & spacing tokens
  ✓ PASS: 4.4 Typography Audit: ConfirmDialog.module.css strictly enforces var(--font-sans)
  ✓ PASS: 4.5 Border Stability Audit: No dynamic border thickness changes causing layout shifts
  ✓ PASS: 5.1 End-to-End: Create workspace -> create recovery key -> export -> restore cycle

=================================================================
CHALLENGER 2 SUMMARY: 17 passed, 0 failed out of 17 tests.
=================================================================
```

#### Command 4: Desktop Production Build
```bash
$ pnpm desktop:build
vite v8.3.5 building client environment for production...
transforming (83) src/App.module.css...
✓ 122 modules transformed.
rendering chunks (1)...
rendering chunks (2)...
computing gzip size...
dist/index.html                    0.47 kB │ gzip:   0.30 kB
dist/assets/index-DdmKESpO.css    72.21 kB │ gzip:  11.53 kB
dist/assets/dist-js-B1TMAP68.js    0.28 kB │ gzip:   0.17 kB
dist/assets/index-B49p_KrV.js    459.29 kB │ gzip: 135.90 kB
✓ built in 279ms
# Exit code: 0
```

#### Command 5: Rust Desktop Test Suite
```bash
$ cargo test -p secwet-desktop
# Exit code: 0 (all tests passed across unit, command, lifecycle, clipboard, and concurrency suites)
```

---

## 2. Logic Chain

1. **First-run Onboarding & State Separation**:
   - By preserving `uninitialized` status in `store.init()` instead of auto-provisioning a dummy workspace, fresh app launches are directed into `OnboardingScreen` (Obs 1.1).
   - `OnboardingScreen` cleanly delineates the two user paths: clean creation via `store.createWorkspace()` or recovery via `RestoreDialog` (Obs 1.1). Both routes transition the application into an authenticated `unlocked` state and trigger entity loading via `reloadAll()`.

2. **Unlock Screen Disaster Recovery**:
   - Adding "Restore from backup" to `UnlockScreen.tsx` (Obs 1.2) ensures that a user whose local keystore was cleared or who needs to restore onto an existing machine from an offline export is never locked out without recovery options.
   - Restoring from the lock screen properly terminates previous database connections (`workspace_restore_impl` drops existing mutex guard, calls `old.lock()`, re-encrypts state into SQLite), updates the store status to `unlocked`, and transitions to the main app dashboard (Obs 1.2, Obs 1.5).

3. **Resilience to Corrupted Backups & Adversarial Input**:
   - Crockford Base32 normalization and validation (Obs 1.3) ensure that invalid input formats (e.g. truncated keys, invalid characters like `U`, whitespace, or lowercase variations) cannot trigger unexpected exceptions during cryptographic key derivation.
   - Form submission gating in `RestoreDialog` prevents premature or malformed API calls.
   - Cryptographic failures (e.g. envelope MAC authentication failure from corrupted bytes or incorrect recovery keys) are safely caught, formatted into clear user-facing notices, and do not crash or poison the store or database (Obs 1.3, Obs 1.5).

4. **Design Token & Typography Compliance**:
   - The removal of monospace declarations in `ConfirmDialog.module.css` (Obs 1.4) resolves the R1 audit finding.
   - The new CSS modules strictly utilize design tokens (`--color-*`, `--font-sans`, `--radius-*`, `--space-*`) with steady 1px borders, ensuring zero visual layout shifts or theme inconsistencies across light and dark modes (Obs 1.4).

---

## 3. Caveats

- End-to-end multi-device relay synchronization across restored devices will be validated during Milestone M3-4.
- In headless test environments where `@tauri-apps/plugin-dialog` is mocked, browser fallback `<input type="file">` and explicit path arguments are verified; native OS dialogs rely on Tauri runtime plugin bindings tested in Rust integration tests.

---

## 4. Conclusion

Milestone M3-3 successfully delivers all Desktop UI Integration requirements:
- The first-run onboarding vs restore flow is completely wired, tested, and reliable.
- The unlock screen provides seamless disaster recovery.
- Backup corruption and invalid keys are gracefully rejected without application lockup or state poisoning.
- Design tokens, typography rules, and steady borders comply 100% with `docs/ui-rules.md`.
- All automated suites (`pnpm typecheck`, `empirical_challenge.mjs`, `challenger_2_m3_3.mjs`, `pnpm desktop:build`, and `cargo test -p secwet-desktop`) pass with 0 failures and 0 warnings.

**Verdict: APPROVE**.

---

## 5. Verification Method

To independently verify this report, execute the following commands in `/Users/besaoct/Desktop/secwet`:

1. **TypeScript Typecheck**:
   ```bash
   pnpm typecheck
   ```
2. **Empirical Challenge Verification**:
   ```bash
   node apps/desktop/scripts/empirical_challenge.mjs
   ```
3. **Challenger 2 Adversarial Stress Suite**:
   ```bash
   node apps/desktop/scripts/challenger_2_m3_3.mjs
   ```
4. **Desktop Build**:
   ```bash
   pnpm desktop:build
   ```
5. **Rust Desktop Concurrency & Recovery Tests**:
   ```bash
   cargo test -p secwet-desktop
   ```

**Invalidation Conditions**:
- Any monospace font declaration in desktop CSS modules.
- Re-introduction of deleted `RecoveryScreen.tsx`.
- Auto-creation of workspaces on fresh installations bypassing `OnboardingScreen`.
- Failure to disable restore submission when recovery key or backup path is invalid.
- Store crash or deadlock when restoring over a locked state or handling corrupted backups.
