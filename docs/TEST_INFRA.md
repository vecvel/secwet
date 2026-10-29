# Secwet Test Infrastructure Specification: Milestone 3 (Recovery and Export)

## 1. Test Philosophy & Design Principles

The Secwet Milestone 3 test architecture follows a strict **opaque-box, requirement-driven methodology** anchored directly in the approved task specifications from `ORIGINAL_REQUEST.md` and `docs/IMPLEMENTATION.md` (Sections F9, F10, Section 12 M3).

### Core Tenets

1. **Opaque-Box Invariant Verification**: Tests treat system components as cryptographic black boxes with observable boundaries. Rather than inspecting internal SQLite rows or temporary heap variables, tests verify behavioral invariants:
   - Entropy validity and formatting (125 bits, 25 Crockford Base32 characters in 5 groups).
   - Mathematical idempotence and bidirectional reversibility of key normalization.
   - Non-custodial secrecy: Plaintext recovery keys and plaintext secrets NEVER appear in raw `.secwet` export files.
   - Tamper-evidence: Single-bit flips in ciphertext, nonce, or authenticated additional data (AAD) cause immediate authenticated decryption failure without leaking plaintext or error internals.
   - Cross-device disaster recovery: Restoring a valid export archive onto a clean device reconstructs the complete workspace entity graph with 100% data fidelity.

2. **Zero-Facade / Real Cryptography**: Every test exercises genuine cryptographic primitives (HKDF-SHA256, XChaCha20-Poly1305, Postcard canonical binary serialization, Crockford Base32 algebra). No mock cipher suites, fake key generation, or synthetic pass-throughs are permitted.

3. **Authoritative Output Derivation**: Expected test values are mathematically derived from specification standards:
   - Crockford Base32 symbol table (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, excluding `I`, `L`, `O`, `U`).
   - HKDF-SHA256 key derivation with salt equal to workspace UUID bytes and info string `b"secwet/v1/recovery"`.
   - Postcard binary canonical layout for authenticated additional data (AAD).
   - Envelope schema versioning and base64 standards.

4. **Progressive Testability & Defense-in-Depth**: Tests are structured to provide immediate validation across four progressive tiers, ranging from unit-level cryptographic feature verification to end-to-end multi-service disaster recovery scenarios.

---

## 2. Four-Tier Feature Inventory & Coverage Mapping

The feature matrix maps all Milestone 3 features across 4 distinct testing tiers to guarantee exhaustive coverage.

```
+-----------------------------------------------------------------------------------+
|                           TIER 4: APPLICATION SCENARIOS                           |
|  - Multi-Service Cloud Infrastructure Disaster Recovery                           |
|  - Multi-Epoch Key Rotation & Historical Archive Preservation                     |
|  - Zero-Plaintext Cold Storage Security & Shannon Entropy Audit                   |
|  - Enterprise Multi-Tenant Workspace Graph Integrity                              |
|  - Adversarial Tamper & Supply Chain Attack Defense                               |
+-----------------------------------------------------------------------------------+
|                        TIER 3: CROSS-FEATURE COMBINATIONS                         |
|  - Multi-Space + Multi-Group + Multi-Secret + Binary File Asset Snapshots         |
|  - Key Replacement -> Export -> Restore Roundtrip (Old Key Invalidation)          |
|  - Master Key Rotation Across Multiple Epochs with Migration                      |
|  - Idempotent Multi-Cycle Roundtrip Stability                                     |
|  - Heterogeneous Secret Taxonomy Coverage (All 7 Secret Kinds)                    |
+-----------------------------------------------------------------------------------+
|                       TIER 2: BOUNDARY & CORNER CASES                             |
|  - Corrupted Envelopes (Tampered MAC, Ciphertext, Nonce, AAD)                     |
|  - Truncated Files (Zero-length, partial JSON, cut-off Base64)                    |
|  - Invalid Crockford Base32 Characters ('U', symbols, non-ASCII, emojis)         |
|  - Wrong Recovery Keys & Single-Bit Typo Detection                                |
|  - Empty & Maximal Workspaces (Zero-entity vs Multi-Megabyte Binaries)            |
|  - Crockford Alias Substitution (I/L/i/l -> 1, O/o -> 0)                          |
|  - Whitespace, Hyphen, and Formatting Permutations                                |
+-----------------------------------------------------------------------------------+
|                         TIER 1: FEATURE COVERAGE                                  |
|  - F-CRYPTO-1: Recovery Key Generation (125-bit entropy, 5x5 groups)              |
|  - F-CRYPTO-2: Recovery Key Normalization & Parsing                               |
|  - F-CRYPTO-3: Recovery Wrap Key Derivation ($K_r$ via HKDF-SHA256)               |
|  - F-CRYPTO-4: Verification Seal (`recovery_check`) Verification                  |
|  - F-STORAGE-1: Encrypted Snapshot Export (.secwet envelope)                      |
|  - F-STORAGE-2: Workspace Restore from Export                                     |
|  - F-CLI-1 & F-CLI-2: CLI Export Flags & Plaintext Protections                    |
+-----------------------------------------------------------------------------------+
```

### Tier 1: Feature Coverage (>=5 Tests per Feature)

| ID | Feature | Target | Minimum Tests | Test Names / Focus |
|---|---|---|---|---|
| **T1.1** | `F-CRYPTO-1` | Key Generation & Formatting | 5 | `test_t1_key_gen_entropy_125bit`, `test_t1_key_gen_format_groups`, `test_t1_key_gen_crockford_alphabet`, `test_t1_key_gen_uniqueness`, `test_t1_key_gen_masked_top_bits` |
| **T1.2** | `F-CRYPTO-2` | Normalization & Parsing | 5 | `test_t1_norm_uppercase`, `test_t1_norm_strips_hyphens`, `test_t1_norm_strips_whitespace`, `test_t1_norm_maps_aliases`, `test_t1_parse_roundtrip_entropy` |
| **T1.3** | `F-CRYPTO-3` | K_r Key Derivation | 5 | `test_t1_kr_derivation_deterministic`, `test_t1_kr_derivation_unique_per_workspace`, `test_t1_kr_derivation_unique_per_key`, `test_t1_kr_derivation_hkdf_info`, `test_t1_kr_derivation_entropy_preservation` |
| **T1.4** | `F-CRYPTO-4` | Verification Seal (`recovery_check`) | 5 | `test_t1_seal_valid_key_verifies`, `test_t1_seal_wrong_key_fails`, `test_t1_seal_tampered_tag_fails`, `test_t1_seal_wrong_workspace_fails`, `test_t1_seal_does_not_leak_plaintext` |
| **T1.5** | `F-STORAGE-1` | `.secwet` Export Envelope | 5 | `test_t1_export_envelope_json_format`, `test_t1_export_envelope_aad_binding`, `test_t1_export_envelope_nonce_randomness`, `test_t1_export_envelope_no_plaintext_leakage`, `test_t1_export_envelope_deterministic_metadata` |
| **T1.6** | `F-STORAGE-2` | Restore from Export | 5 | `test_t1_restore_valid_archive_succeeds`, `test_t1_restore_preserves_workspace_uuid`, `test_t1_restore_reconstructs_spaces_and_groups`, `test_t1_restore_reconstructs_secrets`, `test_t1_restore_generates_new_device_identity` |
| **T1.7** | `F-CLI-1/2` | CLI Export Flags & Invariants | 5 | `test_t1_cli_export_requires_plaintext_flag`, `test_t1_cli_export_plaintext_succeeds_with_warning`, `test_t1_cli_export_json_requires_plaintext`, `test_t1_cli_export_secwet_archive_extension`, `test_t1_cli_export_missing_item_handling` |

### Tier 2: Boundary & Corner Cases (>=5 Tests per Feature)

| ID | Feature | Target | Minimum Tests | Test Names / Focus |
|---|---|---|---|---|
| **T2.1** | Envelope Integrity | Corrupted Envelopes | 5 | `test_t2_corrupted_poly1305_tag_rejected`, `test_t2_corrupted_ciphertext_byte_rejected`, `test_t2_tampered_nonce_rejected`, `test_t2_tampered_aad_secwet_id_rejected`, `test_t2_modified_version_field_rejected` |
| **T2.2** | File Boundaries | Truncated & Empty Files | 5 | `test_t2_truncated_zero_bytes_rejected`, `test_t2_truncated_partial_json_rejected`, `test_t2_truncated_base64_ciphertext_rejected`, `test_t2_truncated_header_only_rejected`, `test_t2_single_byte_file_rejected` |
| **T2.3** | Key Input Edge Cases | Invalid Crockford Base32 Characters | 5 | `test_t2_invalid_char_u_rejected`, `test_t2_invalid_symbols_rejected`, `test_t2_invalid_length_too_short_rejected`, `test_t2_invalid_length_too_long_rejected`, `test_t2_invalid_unicode_emoji_rejected` |
| **T2.4** | Authentication | Wrong HMAC/Poly1305 MAC | 5 | `test_t2_wrong_mac_single_bit_flip`, `test_t2_wrong_mac_zeroed_tag`, `test_t2_wrong_mac_all_ones_tag`, `test_t2_wrong_mac_shuffled_tag`, `test_t2_wrong_mac_truncated_tag` |
| **T2.5** | Workspace Sizing | Empty & Minimal Workspaces | 5 | `test_t2_empty_workspace_export_restore`, `test_t2_empty_workspace_meta_preserved`, `test_t2_empty_workspace_zero_leaks`, `test_t2_minimal_workspace_one_secret_roundtrip`, `test_t2_workspace_with_empty_notes_and_files` |
| **T2.6** | Workspace Sizing | Maximal & Heavy Payloads | 5 | `test_t2_max_size_binary_file_attachment`, `test_t2_large_multiline_rsa_certificate_secret`, `test_t2_high_volume_secret_batch_roundtrip`, `test_t2_deeply_nested_group_item_tree`, `test_t2_utf8_multibyte_international_text` |
| **T2.7** | Usability / Normalization | Crockford Alias Replacement | 5 | `test_t2_alias_lowercase_i_mapped_to_1`, `test_t2_alias_lowercase_l_mapped_to_1`, `test_t2_alias_lowercase_o_mapped_to_0`, `test_t2_alias_mixed_case_all_aliases`, `test_t2_alias_extreme_consecutive_aliases` |
| **T2.8** | Usability / Formatting | Whitespace, Dashes & Case | 5 | `test_t2_format_all_lowercase_without_dashes`, `test_t2_format_mixed_spaces_and_tabs`, `test_t2_format_excessive_dashes`, `test_t2_format_leading_trailing_newlines`, `test_t2_format_interspersed_spaces` |

### Tier 3: Cross-Feature Combinations (Pairwise & Multi-Feature)

1. **Multi-Space + Multi-Group + Multi-Secret + Binary File Asset Snapshots**:
   Verifies that complex relational graphs containing default and custom spaces, multiple organizational groups, items, environment tiers (Dev, Staging, Prod), diverse secrets, rich text markdown notes, and binary assets (e.g. tarballs, keys) serialize and restore with 100% entity and relationship fidelity.
2. **Key Replacement -> Export -> Restore Roundtrip**:
   Workspace creates recovery key $K_{r1}$, updates to $K_{r2}$ via `replace_recovery_key`. Verifies that $K_{r1}$ cannot decrypt new exports, $K_{r2}$ succeeds, and previous recovery verification seals are cleanly invalidated.
3. **Historical Multi-Archive Continuity**:
   Workspace exports archive $A_1$ under $K_{r1}$, rotates key to $K_{r2}$, adds secrets, exports archive $A_2$ under $K_{r2}$. Verifies $K_{r1}$ restores $A_1$, $K_{r2}$ restores $A_2$, and cross-restoration is cryptographically impossible.
4. **Master Key Epoch Rotation Across Export/Restore**:
   Workspace rotates master keys across multiple epochs ($K_{m1} \to K_{m2} \to K_{m3}$). Snapshot captures all active and historical entity records. Restore provisions next master epoch ($K_{m4}$) and re-encrypts all records into fresh database seamlessly.
5. **Idempotent Multi-Cycle Roundtrip Stability**:
   Export $E_1 \to$ Restore $R_1 \to$ Export $E_2 \to$ Restore $R_2$. Verifies zero bitrot, zero data loss, and identity preservation across successive backup/recovery cycles.
6. **Heterogeneous Secret Taxonomy Verification**:
   Ensures all 7 `SecretKind` enum variants (`Password`, `ApiKey`, `AccessToken`, `EnvVar`, `SshKey`, `Certificate`, `Codes`) are restored with exact metadata, kind discriminators, and multiline values preserved.

### Tier 4: Real-World Application Scenarios (>=5 Application Scenarios)

1. **Scenario 1: Disaster Recovery of Multi-Service Infrastructure**:
   Simulates catastrophic hardware loss of a production developer workstation (Device A) running a microservice constellation (`auth-service`, `billing-gateway`, `data-pipeline`). Device A stores dotenv variables, SSH cluster keys, TLS certificates, architecture notes, and config files. Device A is destroyed. Clean Device B boots up, restores from `.secwet` with recovery key, and resumes operations with 100% data fidelity.
2. **Scenario 2: Key Rotation Compliance & Historical Archive Isolation**:
   Simulates enterprise security compliance requiring periodic recovery key rotation. Multiple archives generated over time are verified for forward and backward isolation: each archive can only be unlocked by its contemporaneous recovery key.
3. **Scenario 3: Zero-Plaintext Cold Storage Security & Shannon Entropy Audit**:
   Simulates forensic auditing of an exported `.secwet` file intended for cold storage on untrusted media (S3, USB drive). Analyzes raw binary bytes: verifies zero substring occurrences of secret values, secret names, or item names. Computes Shannon entropy of ciphertext demonstrating $> 7.95$ bits/byte (indistinguishable from pure random noise).
4. **Scenario 4: Enterprise Multi-Tenant Workspace Graph Integrity**:
   Simulates large-scale workspace restoration: 4 spaces, 12 groups, 24 items, 48 environments, 100+ secrets, binary assets, and markdown runbooks. Proves that foreign keys, space-to-group mappings, and item-to-environment relations remain unbroken.
5. **Scenario 5: Adversarial Tamper & Supply Chain Attack Simulation**:
   Simulates man-in-the-middle attacks on backup files: bit-flipping ciphertext, swapping workspace UUID in AAD, tampering envelope format/version, modifying cipher/KDF identifiers, and truncating files. Confirms that all tamper attempts fail cleanly with generic errors without leaking sensitive state.

---

## 3. Architecture of Test Runner and Test Fixtures

### Test Directory Layout

```
secwet/
├── TEST_INFRA.md                           # This architecture and specification document
├── TEST_READY.md                           # Test execution guide and scorecard
├── fixtures/
│   └── recovery/                           # Reference .secwet export fixtures
│       ├── manifest.json                   # Cryptographic manifest and test catalog
│       ├── valid_empty_workspace.secwet    # Minimal empty workspace archive
│       ├── valid_minimal_workspace.secwet  # Single-secret valid archive
│       ├── valid_enterprise_workspace.secwet# Full enterprise multi-space archive
│       ├── valid_with_binary_asset.secwet  # Archive containing binary file assets
│       ├── corrupted_mac.secwet            # Archive with tampered Poly1305 MAC tag
│       ├── corrupted_ciphertext.secwet     # Archive with tampered ciphertext payload
│       ├── corrupted_aad_secwet_id.secwet  # Archive with mismatched workspace UUID
│       ├── corrupted_truncated_file.secwet # Truncated archive file
│       ├── corrupted_invalid_json.secwet   # Malformed JSON envelope
│       ├── corrupted_unsupported_version.secwet # Version header mismatch (999)
│       ├── corrupted_unsupported_cipher.secwet  # Cipher algorithm mismatch
│       ├── corrupted_unsupported_kdf.secwet     # KDF algorithm mismatch
│       └── corrupted_zero_length.secwet    # 0-byte file
├── crates/
│   ├── secwet-core/
│   │   └── tests/
│   │       └── recovery_e2e_suite.rs       # Comprehensive Rust 4-Tier E2E test suite
│   └── secwet-cli/
│       └── tests/
│           └── cli_export_e2e_tests.rs     # CLI parity and flag protection test suite
└── scripts/
    └── run_e2e_tests.sh                    # Automated test runner script with scorecard
```

### Reference Fixture Manifest Schema (`fixtures/recovery/manifest.json`)

```json
{
  "version": 1,
  "generated_at": "2026-10-27T16:30:00Z",
  "fixtures": [
    {
      "file": "valid_enterprise_workspace.secwet",
      "category": "valid",
      "expected_status": "ok",
      "secwet_id": "0192e200-0000-7000-8000-000000000001",
      "recovery_key_formatted": "A1B2C-D3E4F-G5H6J-K7M8N-P9Q0R",
      "recovery_key_normalized": "A1B2CD3E4FG5H6JK7M8NP9Q0R",
      "sha256": "...",
      "summary": {
        "spaces": 2,
        "labels": 3,
        "items": 4,
        "environments": 6,
        "secrets": 12,
        "notes": 3,
        "files": 2
      }
    },
    {
      "file": "corrupted_mac.secwet",
      "category": "adversarial",
      "expected_status": "mac_mismatch",
      "failure_reason": "Poly1305 tag flipped bit at byte index 15"
    }
  ]
}
```

### Reference Oracle Engine (`SecwetArchiveOracle`)

The test suite includes a standalone reference cryptographic oracle (`SecwetArchiveOracle`) implemented directly against the mathematical specification of `docs/IMPLEMENTATION.md`:
1. Derives $K_r = \text{HKDF-SHA256}(\text{entropy}_{16}, \text{salt}=\text{secwet\_id}, \text{info}=\text{"secwet/v1/recovery"})$.
2. Binds authenticated additional data (AAD) via Postcard: `postcard::to_stdvec(&("secwet-export", 1u8, secwet_id.as_bytes()))`.
3. Encrypts and decrypts with $XChaCha20Poly1305$ using 24-byte cryptographically secure random nonces.
4. Serializes/deserializes snapshots canonically with Postcard.
5. Formats and validates JSON envelopes conforming to `{"format": "secwet-export", "version": 1, ...}`.

This reference oracle allows deterministic test execution and fixture generation that is 100% independent of internal storage details.

---

## 4. Test Execution & Verification Commands

All tests execute via the standard Rust toolchain:

```bash
# 1. Run the core E2E recovery and export suite
cargo test -p secwet-core --test recovery_e2e_suite

# 2. Run CLI export flag and plaintext invariant tests
cargo test -p secwet-cli --test cli_export_e2e_tests

# 3. Run all project tests across workspace
cargo test --workspace

# 4. Run the automated all-tier E2E runner script
bash scripts/run_e2e_tests.sh
```
