# Handoff Report: Milestone M3-1 (Core Cryptography and Storage - Requirement R2)

## 1. Observation
- **Assigned Scope**: Implementation of Milestone M3-1 in `crates/secwet-core` and `crates/secwet-proto` for non-custodial disaster recovery, recovery key lifecycle, and encrypted offline backup snapshots.
- **Source Files Modified**:
  - `crates/secwet-proto/src/lib.rs`: Added models `SnapshotSpace`, `SnapshotLabel`, `SnapshotItem`, `SnapshotEnvironment`, `SnapshotSecret`, `SnapshotNote`, `SnapshotFile`, `SnapshotSetting`, `SecwetSnapshot`, `ExportAad`, `SecwetExportEnvelope`, `ExportSummary`, and `RecoveryStatus`. Added unit test `test_snapshot_and_recovery_models_roundtrip`.
  - `crates/secwet-core/src/model.rs`: Re-exported snapshot, envelope, and recovery models.
  - `crates/secwet-core/src/lib.rs`: Re-exported snapshot, envelope, and recovery models under public interface.
  - `crates/secwet-core/src/crypto.rs`: Added `seal_raw_parts`, `open_raw_parts`, `seal_raw`, `open_raw`, and `derive_recovery_key_from_str`.
  - `crates/secwet-core/src/secwet.rs`: Implemented `create_recovery_key`, `replace_recovery_key`, `verify_recovery_key`, `recovery_status`, `collect_snapshot`, `export_encrypted`, `export_to_file`, `restore_from_export`, and `restore_from_export_str`.
- **Test Invariants Created**:
  - `crates/secwet-core/tests/recovery_export_tests.rs`: Implemented the 4 required invariant integration tests:
    - `test_recovery_key_create_and_replace`: Verifies recovery key creation, storage of check seal and wrapped master keys in SQLite meta, verification, and replacement.
    - `export_then_restore_roundtrip`: Populates spaces, labels, items, environments, multi-line secrets, notes, and binary attachments, exports to encrypted envelope, and restores into a clean secwet instance, asserting 100% data fidelity.
    - `export_wrong_key_fails_without_detail`: Tests export and restore attempts with corrupted or wrong recovery keys, ensuring atomic failure with `Error::RecoveryFailed` and no state corruption.
    - `export_file_contains_no_plaintext`: Exports an encrypted archive and scans raw bytes, validating that none of the plaintexts, secret values, notes, or file payloads appear unencrypted.
- **Verbatim Tool Verification Results**:
  - `cargo test -p secwet-proto`: 59 passed; 0 failed; 0 ignored; finished in 1.88s.
  - `cargo test -p secwet-core --test recovery_export_tests`: 4 passed; 0 failed; finished in 0.11s.
  - `cargo test -p secwet-core --test recovery_e2e_suite`: 88 passed; 0 failed; finished in 0.97s.
  - `cargo test -p secwet-core`: 15 test suites, all passed; 0 failed.
  - `cargo clippy -p secwet-core --test recovery_export_tests`: 0 warnings on target test and newly implemented code.

## 2. Logic Chain
- **Cryptographic Grounding**:
  - `crypto::generate_recovery_key()` generates 16 bytes of cryptographically secure random entropy with the top 3 bits masked `& 0x1F`, formatting it as 25 Crockford Base32 characters in 5 groups separated by hyphens.
  - `crypto::derive_recovery_key_from_str(key_str, secwet_id)` normalizes the string, handles Crockford character aliases (O/o -> 0, I/i/L/l -> 1), verifies length and character set, parses to 16 raw entropy bytes, and derives a 32-byte recovery encryption key $K_r$ using HKDF-SHA256 with salt = `secwet_id` and info = `"secwet-v1-recovery"`.
  - `crypto::seal_raw_parts` and `crypto::open_raw_parts` use XChaCha20Poly1305 with an explicit 24-byte random nonce and authenticated additional data (AAD).
- **Recovery Key Storage & Verification**:
  - When `create_recovery_key` or `replace_recovery_key` is called, a seal of constant plaintext `"secwet-recovery-check"` with AAD `("secwet-recovery-check", secwet_id)` is encrypted under $K_r$ and persisted in SQLite `meta` under key `"recovery_check"`.
  - For all active epochs $1 \le e \le \text{current\_key\_epoch}$, the master key $K_v^{(e)}$ is retrieved from the `KeyStore`, sealed under $K_r$ with AAD `("recovery-wrap", secwet_id, epoch)`, and saved as a JSON map under `"recovery_wrapped_master_keys"`.
  - `verify_recovery_key` attempts opening the stored seal in `recovery_check` using $K_r$. If decryption fails, it returns `Ok(false)` without leaking details.
- **Encrypted Offline Export**:
  - `export_encrypted` traverses all active spaces, labels, items, environments, secrets, notes, files, and settings, assembling a `SecwetSnapshot`.
  - The snapshot is serialized with `postcard`, generating an authenticated header `ExportAad` binding `format_version = 1`, `cipher = "xchacha20poly1305"`, `kdf = "hkdf-sha256"`, `secwet_id`, and `created_at`.
  - The ciphertext and Poly1305 tag are packaged into a JSON `SecwetExportEnvelope`.
- **Disaster Recovery Restore**:
  - `restore_from_export` decrypts and deserializes `SecwetSnapshot` from the envelope using $K_r$.
  - It provisions a new key epoch $e_{\text{new}} = \text{snapshot.key\_epoch} + 1$, generates a fresh master key $K_v^{(e_{\text{new}})}$, stores it into the target `KeyStore`, derives device Ed25519 and X25519 key pairs, and initializes the SQLite schema.
  - It sequentially restores and re-encrypts all spaces, labels, items, environments, secrets, notes, files, and settings under the new epoch with full relational fidelity and zero plaintext residue on disk.

## 3. Caveats
- `restore_from_export` requires that the target secwet instance has access to a working `KeyStore` (e.g. `MemoryKeyStore` in tests or OS platform keystore in CLI/desktop) to store the newly generated master key and device keys.
- If restoring into an existing database path, the destination SQLite database is overwritten cleanly to guarantee state isolation.

## 4. Conclusion
Milestone M3-1 is fully implemented and tested according to specification. The core cryptography, recovery key lifecycle, and encrypted offline export/restore systems satisfy all requirements of Requirement R2. Zero regressions were introduced into `crates/secwet-core` or `crates/secwet-proto`, and all invariant tests pass.

## 5. Verification Method
To independently verify Milestone M3-1:
1. Run the new invariant integration test suite:
   ```bash
   cargo test -p secwet-core --test recovery_export_tests
   ```
2. Run the end-to-end recovery test suite:
   ```bash
   cargo test -p secwet-core --test recovery_e2e_suite
   ```
3. Run the full core test suite:
   ```bash
   cargo test -p secwet-core
   ```
4. Verify code formatting and linting:
   ```bash
   cargo clippy -p secwet-core --test recovery_export_tests
   ```
