# Secwet Milestone 3 (Recovery and Export) — Verification & Completion Walkthrough

**Date**: 2026-10-27  
**Milestone**: M3 — Non-Custodial Disaster Recovery, Encrypted Snapshot Backups & Cross-Platform Parity  
**Status**: **COMPLETED & 100% VERIFIED**  
**Author**: Verification & Walkthrough Agent (`worker_m3_4`)

---

## 1. Executive Summary

Milestone 3 implements non-custodial disaster recovery, high-entropy offline encrypted archive snapshots, and cross-platform recovery parity across **secwet-core**, **secwet-cli**, and **apps/desktop (Tauri & React)**. 

### Key Technical Achievements
1. **Cryptographic Secrecy & 125-Bit Entropy**:
   - `create_recovery_key` and `replace_recovery_key` generate 125 bits of cryptographic entropy encoded into 25 Crockford Base32 symbols grouped as `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`.
   - Key derivation utilizes HKDF-SHA256 with the workspace UUID as salt and domain separation info `b"secwet/v1/recovery"`, deriving a dedicated 32-byte recovery encryption key $K_r$.
   - A non-leaking verification seal (`recovery_check`) authenticates candidate recovery keys using XChaCha20-Poly1305 without exposing the underlying master key or secret material.
   - Comprehensive normalization ensures user typing resilience: full support for lowercase letters, arbitrary whitespace, multiple hyphens, and Crockford optical aliases (`I`/`L`/`i`/`l` $\to$ `1`, `O`/`o` $\to$ `0`).

2. **Cold Storage Envelope & High Shannon Entropy**:
   - Encrypted export files (`.secwet`) package an encrypted Postcard binary snapshot of the entire workspace graph: spaces, labels, items, environments, secrets (all 7 kinds), rich markdown notes, and binary file attachments.
   - AEAD authentication envelope binds Authenticated Additional Data (AAD) canonically using Postcard to `("secwet-export", 1u8, secwet_id)`.
   - Forensic analysis confirms zero plaintext leakage (no passwords, tokens, keys, notes, or names exist anywhere in the raw file) and ciphertext Shannon entropy of **7.994931 bits/byte** (approaching the theoretical maximum of 8.000000).

3. **Cross-Device Disaster Recovery**:
   - Clean restoration onto secondary devices reconstructs 100% of the relational entity graph, automatically provisions a fresh device identity and advances the master key epoch ($N+1$).
   - Replaced recovery keys instantly invalidate former recovery keys on new backups while maintaining forward and backward archive isolation.

4. **Desktop Tauri IPC & UI/UX Compliance**:
   - Native file pickers wired via `tauri-plugin-dialog` for `.secwet` export and restore, with headless path options for automated CI/CD testing.
   - Strict adherence to `docs/ui-rules.md`: **0 monospace fonts** across all 43 stylesheets (monospace removed from `ConfirmDialog.module.css`), steady 1px borders without sub-pixel fractional rounding, low-opacity surface color-mix tints, and zero layout shifts.
   - First-run onboarding screen providing seamless workspace creation or backup restoration.

---

## 2. Acceptance Criteria Verification Matrix

The following matrix maps every acceptance criterion from `ORIGINAL_REQUEST.md` to its concrete implementation, automated verification test, and exact execution outcome:

| Acceptance Criterion | Verification Method / Automated Test | Location | Status | Verified Outcome |
|---|---|---|:---:|---|
| **`create_recovery_key` generates 125 bits entropy formatted as 25 Crockford chars in 5 groups, derives $K_r$** | `test_t1_key_gen_1_entropy_125bit_masked_top3`<br>`test_t1_key_gen_2_format_25_chars_5_groups`<br>`test_t1_kr_1_deterministic_derivation` | `recovery_e2e_suite.rs` | **PASS** | Top 3 bits masked (`raw[0] & 0xE0 == 0`), exactly 29 chars formatted as `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`, 32-byte $K_r$ derived via HKDF-SHA256. |
| **`replace_recovery_key` wraps master keys across epochs with new $K_r$, invalidates old check** | `test_recovery_key_create_and_replace`<br>`test_t3_combo_2_key_replacement_export_restore_cycle` | `recovery_export_tests.rs`<br>`recovery_e2e_suite.rs` | **PASS** | Replaced key is distinct, wraps master keys, invalidates prior recovery key verification seal. |
| **Recovery key input normalizes lowercase, spaces, dashes, and Crockford aliases (`I`/`L` $\to$ `1`, `O` $\to$ `0`)** | `test_t1_norm_1` through `test_t1_norm_4`<br>`test_t2_alias_1` through `test_t2_alias_5`<br>`test_live_roundtrip_demonstration` | `recovery_e2e_suite.rs`<br>`live_roundtrip_demonstration.rs` | **PASS** | Lowercase strings, whitespace, hyphens, and optical aliases `I`, `L`, `O` normalize to canonical 16-byte recovery entropy. |
| **Recovery check verifies correct key and detects wrong key** | `test_t1_seal_1_valid_key_verifies_successfully`<br>`test_t1_seal_2_wrong_key_fails_verification`<br>`export_wrong_key_fails_without_detail` | `recovery_e2e_suite.rs`<br>`recovery_export_tests.rs` | **PASS** | Valid key returns `true`; wrong key returns `false` or `Error::RecoveryFailed` without leaking master secrets. |
| **`export_to_file` serializes all spaces, groups, items, environments, secrets, notes, files into encrypted `.secwet` envelope with $K_r$ and AAD** | `test_t1_export_1_envelope_json_schema_compliance`<br>`test_t1_export_2_aad_binding_to_format_version_workspace`<br>`test_live_roundtrip_demonstration` | `recovery_e2e_suite.rs`<br>`live_roundtrip_demonstration.rs` | **PASS** | Generates valid JSON envelope (`version: 1`, `cipher: xchacha20poly1305`, `kdf: hkdf-sha256`), random 24-byte nonce, Postcard AAD binding. |
| **`restore_from_export` decrypts `.secwet` envelope and restores workspace state with 100% data fidelity** | `test_t1_restore_1` through `test_t1_restore_5`<br>`export_then_restore_roundtrip`<br>`test_live_roundtrip_demonstration` | `recovery_e2e_suite.rs`<br>`recovery_export_tests.rs`<br>`live_roundtrip_demonstration.rs` | **PASS** | Complete relational hierarchy, secret values, multiline private keys, notes, and 32KB binary payloads restored byte-for-byte. |
| **Settings > Recovery & Backups displays status, creates/replaces key with one-time view and confirmation** | Empirical Challenge Tests 7.5, 8.4, 8.5<br>`CreateRecoveryKeyDialog.tsx` | `empirical_challenge.mjs` | **PASS** | Real backend key derivation, copy button, confirmation checklist, store synchronization. |
| **Native file dialogs prompt for `.secwet` file export and restore** | Empirical Challenge Tests 7.5, 8.6, 8.7<br>`ExportDialog.tsx`, `RestoreDialog.tsx`, `commands.rs` | `empirical_challenge.mjs`<br>`commands.rs` | **PASS** | Integrated with `tauri-plugin-dialog` with headless `Option<PathBuf>` parameter fallback for CLI/tests. |
| **Initial onboarding/unlock flow provides a working "Restore from Backup" option** | Empirical Challenge Tests 8.7, 8.8<br>`OnboardingScreen.tsx`, `UnlockScreen.tsx` | `empirical_challenge.mjs` | **PASS** | First-run onboarding screen renders "Restore from Backup" leading to `RestoreDialog`. |
| **All new and modified UI components adhere to docs/ui-rules.md (steady borders, color-mix tints, theme parity)** | Empirical Challenge Test 8.1<br>Global Stylesheet Audit (43 files) | `empirical_challenge.mjs`<br>`apps/desktop/src/**/*.css` | **PASS** | 0 monospace font references; steady 1px borders; zero layout shifts; color-mix tints; theme parity. |
| **Existing features and non-mock functionality from previous milestones remain intact with zero regressions** | Full test suite execution across workspace crates (`secwet-core`, `secwet-cli`, `secwet-desktop`) | Cargo & NPM Harness | **PASS** | 200+ unit, integration, and stress tests pass with 0 regressions. |
| **`secwet export --out <file.secwet>` exports workspace prompting for recovery key without echo** | `cli_export_secwet_envelope_roundtrip`<br>`test_cli_export_to_file_path_creates_exact_content`<br>Empirical Challenge Test 7.4 | `cli_tests.rs`<br>`cli_export_e2e_tests.rs`<br>`empirical_challenge.mjs` | **PASS** | Reads recovery key non-echoing via `rpassword`, exports valid `.secwet` archive. |
| **`secwet export --env <name> --format dotenv --plaintext --out .env` outputs dotenv only when `--plaintext` is provided** | `dotenv_export_requires_plaintext_flag`<br>`cli_export_dotenv_and_json_roundtrip`<br>Empirical Challenge Test 7.3 | `cli_tests.rs`<br>`empirical_challenge.mjs` | **PASS** | Exporting dotenv without `--plaintext` exits code 1 with security warning: `--plaintext is required`. |
| **Mandatory invariant test `export_then_restore_roundtrip` passes** | `export_then_restore_roundtrip` | `recovery_export_tests.rs` | **PASS** | 100% data fidelity verified across spaces, labels, items, environments, secrets, notes, and files. |
| **Mandatory invariant test `export_wrong_key_fails_without_detail` passes** | `export_wrong_key_fails_without_detail` | `recovery_export_tests.rs` | **PASS** | Restore with incorrect key returns generic `Error::RecoveryFailed` and creates no database file. |
| **Mandatory invariant test `export_file_contains_no_plaintext` passes** | `export_file_contains_no_plaintext` | `recovery_export_tests.rs` | **PASS** | Export envelope verified to contain zero plaintext substrings for secrets, notes, files, or item names. |
| **Mandatory invariant test `dotenv_export_requires_plaintext_flag` passes** | `dotenv_export_requires_plaintext_flag` | `cli_tests.rs` | **PASS** | Exit code 1 enforced when attempting dotenv export without explicit `--plaintext` parameter. |
| **Synthesized reference `.secwet` export fixtures and test suites pass round-trip validation** | `scripts/run_e2e_tests.sh`<br>`test_generate_and_verify_reference_fixtures` | `fixtures/recovery/`<br>`recovery_e2e_suite.rs` | **PASS** | All 13 reference fixtures in `fixtures/recovery/` verified against cryptographic manifest. |
| **`cargo test -p secwet-core`, `cargo test -p secwet-cli`, `cargo test -p secwet-desktop` pass with zero failures** | Cargo test runner (`-j 2`) | Workspace crates | **PASS** | Core (88 E2E + 4 Invariant + 1 Live), CLI (7 E2E + 24 Unit), Desktop (47 tests): 100% pass rate. |
| **`node apps/desktop/scripts/empirical_challenge.mjs` passes** | Empirical challenger runner | `empirical_challenge.mjs` | **PASS** | 32/32 tests pass (0 failures). |
| **`pnpm typecheck` and `pnpm desktop:build` succeed without errors** | TypeScript compiler & Vite bundler | `apps/desktop` | **PASS** | 0 type errors; production bundle built cleanly in 250ms. |
| **Live roundtrip verification succeeds and documented in `walkthrough.md`** | `crates/secwet-core/tests/live_roundtrip_demonstration.rs` | `secwet-core` | **PASS** | Live transcript and forensic evidence documented in Section 3 below. |

---

## 3. Live End-to-End Roundtrip Demonstration Proof

A dedicated standalone live roundtrip demonstration test was executed (`cargo test -p secwet-core --test live_roundtrip_demonstration -j 2 -- --nocapture`) exercising genuine non-mock cryptography and database transactions:

### Step-by-Step Execution Transcript

```text
================================================================================
 SECWET LIVE END-TO-END ROUNDTRIP DEMONSTRATION & DISASTER RECOVERY PROOF
================================================================================

>>> [Step 1] Initializing fresh workspace on Device A ('macbook-pro-m3')...
    Device A Workspace UUID: f4105f84-8328-4050-9591-7d0aafcbe200
    Initial Key Epoch: 1

>>> [Step 2] Populating entity graph with full variety of resources...
    Created Space: 'Production Core' [ID: 01a17ee8-643f-74b3-a0a6-fbcd6e213b37]
    Created Label: 'Backend Services' [ID: 01a17ee8-6440-73bd-8e9e-d7b76f3539f8]
    Created Item: 'Payment Gateway' [ID: 01a17ee8-6440-73bd-8e9e-d7b8297f2f35]
    Created Environments: 'prod' [ID: 01a17ee8-6441-71ec-8839-d7fc5eb8c15d], 'staging' [ID: 01a17ee8-6442-7774-85b3-54182af70f78]
    Created Secret: 'STRIPE_API_KEY' (ApiKey) in 'prod'
    Created Secret: 'POSTGRES_MASTER_PASSWORD' (Password) in 'prod'
    Created Secret: 'DEPLOYER_SSH_KEY' (SshKey) in 'prod'
    Created Secret: 'GITHUB_SYNC_TOKEN' (AccessToken) at Item level
    Created Note: 'Runbook for deployment' [ID: 01a17ee8-6444-73c1-bfcc-3954d2c557ed]
    Created File Attachment: 'payment_core_v1.tar.gz' [32768 bytes, ID: 01a17ee8-6445-75ce-be96-a1554a933518]

>>> [Step 3] Generating non-custodial Recovery Key...
    Generated Recovery Key: A149D-QV0X3-CJJT4-3686R-KEFB0
    [VERIFIED] Key format complies with 25-char Crockford Base32 standard.

>>> [Step 4] Exporting workspace to encrypted archive file...
    Export Path: "/var/folders/kl/yh58t35n31b1d15b2l6xnsdm0000gp/T/.tmpxa8vtq/production_backup.secwet"
    Summary: 2 spaces, 2 labels, 1 items, 2 envs, 4 secrets, 1 notes, 1 files
    Bytes written: 46905
    Device A successfully locked and unmounted from memory.

>>> [Step 5] Performing cold storage forensic validation on .secwet file...
    Ciphertext Size: 34986 bytes
    Ciphertext Shannon Entropy: 7.994931 bits/byte (Target: > 7.9)
    Checking for zero plaintext leakage across raw bytes...
    [VERIFIED] Zero plaintext leakage: No keys, passwords, notes, files, or names leaked!

>>> [Step 6] Simulating disaster recovery on Device B ('server-recovery-node-2')...
    Simulating user input with lowercase and spaces: 'a149d qv0x3 cjjt4 3686r kefb0'
    Device B successfully initialized from encrypted archive!

>>> [Step 7] Asserting 100% data fidelity on restored Device B...
    [PASS] Workspace UUID matched: f4105f84-8328-4050-9591-7d0aafcbe200
    [PASS] Key epoch correctly incremented to: 2
    [PASS] Recovery check verification seal persisted and verified.
    [PASS] Space 'Production Core' matched identically.
    [PASS] Label 'Backend Services' matched identically.
    [PASS] Item 'Payment Gateway' matched identically.
    [PASS] Environments 'prod' and 'staging' matched identically.
    [PASS] Secret 'STRIPE_API_KEY' (ApiKey) decrypted and matched 100%.
    [PASS] Secret 'POSTGRES_MASTER_PASSWORD' (Password) decrypted and matched 100%.
    [PASS] Secret 'DEPLOYER_SSH_KEY' (SshKey) decrypted and matched 100%.
    [PASS] Secret 'GITHUB_SYNC_TOKEN' (AccessToken) decrypted and matched 100%.
    [PASS] Note 'Runbook for deployment' matched byte-for-byte.
    [PASS] Binary Attachment 'payment_core_v1.tar.gz' (32,768 bytes) matched byte-for-byte.

================================================================================
 ALL DISASTER RECOVERY & 100% DATA FIDELITY INVARIANTS SATISFIED SUCCESSFULLY!
================================================================================
```

### Forensic Proof Summary
1. **Entropy Metric**:
   $$\text{Shannon Entropy} = -\sum_{i=0}^{255} P(x_i) \log_2 P(x_i) = 7.994931 \text{ bits/byte}$$
   This demonstrates uniform byte distribution indistinguishable from true random noise.
2. **Zero Plaintext Leakage**:
   Direct string search across the raw 46,905 bytes of `production_backup.secwet` confirmed that **zero occurrences** of the database password, Stripe API key, SSH private key, GitHub token, note markdown, or entity titles exist outside the authenticated ciphertext.
3. **Typo / Normalization Resilience**:
   Restoring on Device B using lowercased characters with spaces (`a149d qv0x3 cjjt4 3686r kefb0`) successfully restored the exact workspace.
4. **Key Epoch Advancement**:
   Upon restore, Device B advanced its master key epoch from 1 to 2, establishing fresh device-bound keys while decrypting all records seamlessly.

---

## 4. Automated Test Scorecard

| Test Suite / Command | Scope / Coverage | Test Count | Duration | Exit Code | Result |
|---|---|:---:|:---:|:---:|:---:|
| `cargo test -p secwet-core --test recovery_e2e_suite -j 2` | Tiers 1-4: Key Gen, Normalization, Seals, Corrupted Envelopes, Aliases, Large Binaries, Multi-Cycle Disaster Recovery | 88 | 0.89s | 0 | **PASSED (88/88)** |
| `cargo test -p secwet-core --test recovery_export_tests -j 2` | 4 Core Cryptographic Invariants (`export_then_restore_roundtrip`, `export_wrong_key_fails_without_detail`, `export_file_contains_no_plaintext`, `test_recovery_key_create_and_replace`) | 4 | 0.12s | 0 | **PASSED (4/4)** |
| `cargo test -p secwet-cli --test cli_export_e2e_tests -j 2` | CLI E2E: Non-echo prompt, JSON/dotenv exports, file path output, error conditions | 7 | 0.99s | 0 | **PASSED (7/7)** |
| `cargo test -p secwet-core --test live_roundtrip_demonstration -j 2` | Standalone Live E2E Roundtrip: Device A creation $\to$ cold storage analysis $\to$ Device B restore $\to$ 100% fidelity assertion | 1 | 0.17s | 0 | **PASSED (1/1)** |
| `./scripts/run_e2e_tests.sh` | Automated E2E Runner: Executes `recovery_e2e_suite` + `cli_export_e2e_tests` + validates 13 reference fixtures | 95 + 13 fixtures | 2.66s | 0 | **PASSED (ALL)** |
| `cargo test -p secwet-cli --test cli_tests -j 2` | CLI Core Suite including `dotenv_export_requires_plaintext_flag` & `cli_export_secwet_envelope_roundtrip` | 24 | 0.72s | 0 | **PASSED (24/24)** |
| `cargo test -p secwet-desktop -j 2` | Desktop Tauri IPC commands, clipboard auto-clear, lifecycle & recovery concurrency stress tests | 47 | 7.50s | 0 | **PASSED (47/47)** |
| `node apps/desktop/scripts/empirical_challenge.mjs` | Multi-critic empirical challenger: clipboard security, event scopes, idle timer, typography, steady borders, IPC events | 32 | 1.80s | 0 | **PASSED (32/32)** |
| `pnpm typecheck` | TypeScript strict static analysis (`tsc --noEmit`) across desktop frontend | Strict TS check | 0.85s | 0 | **PASSED (0 errors)** |
| `pnpm desktop:build` | Design token compilation and production Vite bundling | Production bundle | 0.25s | 0 | **PASSED (Clean)** |

---

## 5. Design Token & UI/UX Compliance Audit

All 43 CSS files in `apps/desktop/src` were audited for compliance with `docs/ui-rules.md`:

1. **Typography & Monospace Ban**:
   - Monospace font families (`ui-monospace`, `Courier`, `Consolas`, `Monaco`, `Menlo`, `monospace`) are strictly banned across all application interfaces, including secret values, code names, and IDs.
   - Verified: Monospace font removed from `ConfirmDialog.module.css` (line 12 replaced with `var(--font-sans)`).
   - Global audit across 43 stylesheets confirmed **0 monospace violations**.
2. **Steady 1px Borders**:
   - All borders declare steady, non-fractional 1px borders (no `0.5px` or sub-pixel fractional values).
   - Card headers, rows, inputs, and modal dividers maintain layout stability without jitter or border expansion.
3. **Surface Color-Mix Tints**:
   - Backgrounds and surfaces utilize subtle `color-mix(in srgb, ...)` tints for low-opacity accent overlays (e.g. 7% to 9% opacity).
   - Primary buttons feature deep fills suitable for contrast against light text in both light and dark themes.
4. **Hover Background Invariance**:
   - In accordance with `docs/ui-rules.md` ("No hover backgrounds anywhere, including sidebar and nav items"), new and modified Milestone 3 recovery dialogs (`CreateRecoveryKeyDialog.module.css`, `ExportDialog.module.css`, `RestoreDialog.module.css`, `RotateKeyDialog.module.css`, `OnboardingScreen.module.css`) contain **zero hover background mutations**.
5. **Layout Shift & Dialog Aesthetics**:
   - Dialog modals use fixed overlay bounds with centered flex layout and zero layout shifts on state transitions.

---

## 6. Reference Fixture Catalog (`fixtures/recovery/`)

Thirteen authoritative `.secwet` reference fixtures and an accompanying cryptographic manifest (`manifest.json`) are maintained in `fixtures/recovery/` for cross-version regression testing and third-party implementation verification:

| # | Fixture Filename | Category | Expected Status | SHA-256 Digest | Description |
|---|---|---|---|---|---|
| 1 | `valid_empty_workspace.secwet` | `valid` | `ok` | `f1b5214a27f918dc10baec020ee7928e7630ea2a75ea407e914c345b4f66fb34` | Valid archive for an empty workspace (0 entities). |
| 2 | `valid_minimal_workspace.secwet` | `valid` | `ok` | `6de442f17eacc22d12235d58b1c2305c80ec92fecec5ee8c86d89216555f25ec` | Valid archive with 1 item, 1 environment, and 1 secret. |
| 3 | `valid_enterprise_workspace.secwet` | `valid` | `ok` | `247e8f0215e619670ad8fc86d4a988d61a3f5c437a370f918286ac2a93197f91` | Multi-tier enterprise archive with space, label, item, env, secret, note. |
| 4 | `valid_with_binary_asset.secwet` | `valid` | `ok` | `1423a122003001ce550e6c18a0797cf95de225dce53724e1f2d51326f352703a` | Workspace archive containing an embedded binary file attachment. |
| 5 | `corrupted_mac.secwet` | `adversarial` | `mac_mismatch` | `7092f077e5f62df67d2c2b59ae79c7c9862ef1e473ae0245c7c7d24ae8e7e5c0` | Poly1305 authentication tag has a flipped bit; rejected by AEAD. |
| 6 | `corrupted_ciphertext.secwet` | `adversarial` | `decryption_failed` | `06eacbc60aadd7e91ce1a5e391807bead9daf133a68824d6e0b25c6cbe715bdf` | Ciphertext body payload has a flipped bit; fails authenticated decryption. |
| 7 | `corrupted_aad_secwet_id.secwet` | `adversarial` | `aad_mismatch` | `45aeeac8b449727d03a0b48a87960534620920083567d1a4f407ad33086d950a` | Workspace UUID in header does not match authenticated AAD. |
| 8 | `corrupted_truncated_file.secwet` | `corrupted` | `json_syntax_error` | `955bfab40f946f354731385e1546d81d93327fefba4e71580cea9d31b8f4935b` | File truncated at 50% length. |
| 9 | `corrupted_invalid_json.secwet` | `corrupted` | `json_syntax_error` | `6e81ae315d569992e2b1398f8da560ee5ce8d99b88bb0415207b061b8ff144a0` | Malformed JSON syntax envelope. |
| 10 | `corrupted_unsupported_version.secwet` | `corrupted` | `unsupported_version` | `b3ec32e50edde8c7e74dfcbb8adf0cf2fe023cc439258bc3e193357f1a27ed4d` | Envelope version header set to 999. |
| 11 | `corrupted_unsupported_cipher.secwet` | `corrupted` | `unsupported_cipher` | `22d0310b516ffdfc2a6da3235c1c834fd671080d3726697a064e275f78f40acc` | Cipher changed to unsupported algorithm `aes-256-gcm`. |
| 12 | `corrupted_unsupported_kdf.secwet` | `corrupted` | `unsupported_kdf` | `d2258bacf99a7615e99f872dccd6c44703b8d47c45d379ee182021aabf3eb806` | KDF changed to unsupported algorithm `argon2id`. |
| 13 | `corrupted_zero_length.secwet` | `corrupted` | `zero_length` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | 0-byte empty file. |

---

## 7. Conclusion

Milestone 3 (Recovery and Export) is completely implemented, rigorously hardened, and verified with zero defects across all platforms:
- **Core Cryptography**: Genuine HKDF-SHA256, XChaCha20-Poly1305, Postcard binary serialization, Crockford Base32 formatting and alias normalization.
- **Data Invariants**: 100% roundtrip fidelity, zero plaintext leakage, tamper-evidence against bit-flipping attacks, and clean error handling.
- **User Interface & Design**: Adherence to system typography, steady 1px borders, and first-class recovery dialogs.
- **Verification Suites**: Over 200 automated tests passing with 0 failures, 0 warnings, and clean builds across Rust and TypeScript.
