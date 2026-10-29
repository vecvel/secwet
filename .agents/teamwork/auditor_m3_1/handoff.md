# Forensic Audit Report: Milestone M3-1 (Core Cryptography and Storage)

**Work Product**: `crates/secwet-core` (`src/crypto.rs`, `src/secwet.rs`, `src/model.rs`, `tests/recovery_export_tests.rs`) and `crates/secwet-proto` (`src/lib.rs`)
**Profile**: General Project
**Integrity Mode**: Development (per `ORIGINAL_REQUEST.md`)
**Verdict**: **CLEAN**

---

### Phase Results
- **Hardcoded Output Detection**: PASS — No hardcoded test values, string matches, or constant bypasses found.
- **Facade Detection**: PASS — Genuine cryptographic implementations for recovery key lifecycle, postcard serialization, XChaCha20Poly1305 envelope sealing/opening, and SQLite state re-encryption.
- **Pre-populated Artifact Detection**: PASS — Zero pre-existing `.log`, `*result*`, or `*output*` files present in the workspace.
- **Randomness & Entropy Generation**: PASS — `crypto::generate_recovery_key()` samples 16 bytes via OS CSPRNG (`OsRng` wrapping `getrandom`), masks the top 3 bits (`& 0x1F`) to yield precisely 125 bits of random entropy, and formats it as 25 Crockford Base32 characters in 5 groups.
- **Decryption & Verification Logic**: PASS — `verify_recovery_key` never stores or string-compares plaintext keys; it executes authentic XChaCha20Poly1305 decryption of the SQLite `meta.recovery_check` seal using derived key $K_r$ and authenticated AAD.
- **Export Packaging & Sealing**: PASS — `export_encrypted` traverses and decrypts all 7 entity types (spaces, labels, items, environments, secrets, notes, files), serializes to postcard binary format, seals with XChaCha20Poly1305 under $K_r$ with authenticated `ExportAad` and a fresh 24-byte random nonce, and writes a valid `.secwet` JSON envelope.
- **Restore & Database Rebuilding**: PASS — `restore_from_export` validates envelope headers, decrypts and verifies Poly1305 MAC, provisions fresh Ed25519/X25519 device identities, increments key epoch to $N+1$, generates a fresh master key $K_v^{(N+1)}$ in the keystore, re-encrypts all entities, runs SQLite migrations, and creates a clean isolated database.
- **Test Suite Authenticity**: PASS — `tests/recovery_export_tests.rs` contains 4 invariant tests verifying real end-to-end roundtrips (with 64 KiB binary data, multi-line secrets, notes), wrong-key failure without leakage, and raw-disk absence of plaintext. `tests/recovery_e2e_suite.rs` executes 88 independent tests across Tiers 1-4.
- **Build and Test Verification**: PASS — All tests pass with zero failures.

---

## 1. Observation

1. **Source Code Inspection**:
   - `crates/secwet-core/src/crypto.rs` (lines 51–70): `OsRng` directly implements `TryRng` / `TryCryptoRng` using `getrandom::fill(dest).expect("OS CSPRNG failure")`.
   - `crates/secwet-core/src/crypto.rs` (lines 521–530):
     ```rust
     pub fn generate_recovery_key() -> (String, Zeroizing<[u8; 16]>) {
         let mut raw = Zeroizing::new([0u8; 16]);
         OsRng.fill_bytes(&mut *raw);
         raw[0] &= 0x1F;
         let formatted = format_recovery_key(&raw);
         (formatted, raw)
     }
     ```
   - `crates/secwet-core/src/crypto.rs` (lines 532–562): `normalize_recovery_key` strips whitespace and hyphens, maps `'I' | 'L' => '1'` and `'O' => '0'`, checks for valid Crockford Base32 characters, and strictly enforces 25 characters.
   - `crates/secwet-core/src/crypto.rs` (lines 591–601): `derive_recovery_key_from_str` normalizes and parses Crockford Base32 string to extract 125-bit entropy bytes, then derives 32-byte $K_r$ via HKDF-SHA256 with `salt = secwet_id` and `info = b"secwet/v1/recovery"`.
   - `crates/secwet-core/src/secwet.rs` (lines 3772–3803): `create_recovery_key` computes `recovery_check` seal with $K_r$ and AAD `("secwet-recovery-check", secwet_id)`, wraps master keys for all active epochs under $K_r$ with AAD `("recovery-wrap", secwet_id, epoch)`, and saves the encrypted seals into SQLite `meta`. The plaintext recovery key is never stored in SQLite or on disk.
   - `crates/secwet-core/src/secwet.rs` (lines 3815–3840): `verify_recovery_key` performs true decryption of the stored `recovery_check` blob using `open_raw(&k_r, &check_aad, &blob)` and confirms plaintext equality to `b"secwet-recovery-check"`.
   - `crates/secwet-core/src/secwet.rs` (lines 4117–4177): `export_encrypted` traverses all active spaces, labels, items, environments, secrets, notes, files, and settings, serializes the resulting `SecwetSnapshot` via `postcard::to_stdvec`, seals with `seal_raw_parts(&k_r, &aad_bytes, &snapshot_bytes)` using a 24-byte random nonce, and writes the JSON `.secwet` envelope.
   - `crates/secwet-core/src/secwet.rs` (lines 4189–4550): `restore_from_export` opens the JSON envelope, authenticates AAD and Poly1305 MAC via `open_raw_parts`, deserializes the postcard snapshot, generates new device keys via `OsRng`, increments epoch to `snapshot.key_epoch + 1`, stores fresh master key into keystore, creates a clean SQLite schema, re-encrypts all entities under the new epoch master key, and restores recovery seals.

2. **Empirical Test Verification**:
   - `cargo test -p secwet-core --test recovery_export_tests`:
     ```
     running 4 tests
     test test_recovery_key_create_and_replace ... ok
     test export_wrong_key_fails_without_detail ... ok
     test export_file_contains_no_plaintext ... ok
     test export_then_restore_roundtrip ... ok

     test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.15s
     ```
   - `cargo test -p secwet-core --test recovery_e2e_suite`:
     ```
     running 88 tests
     ...
     test result: ok. 88 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.10s
     ```
   - `cargo test -p secwet-proto`:
     ```
     test result: ok. 14 passed (unittests), 25 passed (adversarial_challenger), 12 passed (adversarial_verification), 8 passed (stress_tests); 0 failed; finished in 2.05s
     ```
   - `cargo test -p secwet-core`:
     ```
     15 test suites executed, all passed (108 total tests passed, 0 failed).
     ```
   - `cargo clippy -p secwet-core --test recovery_export_tests --test recovery_e2e_suite`:
     Finished with 0 errors.

---

## 2. Logic Chain

1. **Entropy & Randomness**:
   - Observation: `crypto::generate_recovery_key()` invokes `OsRng.fill_bytes(&mut *raw)`, masks `raw[0] &= 0x1F`, and passes it to `format_recovery_key()`.
   - Inference: 16 bytes equals 128 bits; clearing the top 3 bits leaves exactly $128 - 3 = 125$ bits of entropy. $25 \times 5$ Crockford Base32 digits represent 125 bits. `OsRng` uses the operating system's cryptographic random source (`getrandom`). No pseudo-random shortcuts or fixed seeds are used.

2. **Verification & Decryption Authenticity**:
   - Observation: `verify_recovery_key` decodes base64 `recovery_check` from the database `meta` table, derives $K_r$ using HKDF-SHA256, and invokes `crypto::open_raw(&k_r, &check_aad, &blob)`.
   - Inference: The plaintext candidate key is never compared against any stored string. The check succeeds only if Poly1305 MAC verification and ChaCha20 decryption succeed. If the recovery key is wrong, Poly1305 MAC verification fails, producing `CryptoError` which maps to `Ok(false)` without leaking details.

3. **Export & Restore Authenticity**:
   - Observation: `export_encrypted` gathers plaintext records by decrypting existing SQLite blobs with $K_{\text{rec}}$, constructs a structured `SecwetSnapshot`, serializes with postcard, and encrypts with XChaCha20Poly1305 using an authentic `ExportAad` bound to `secwet_id`.
   - Observation: `restore_from_export` decrypts the snapshot, generates new device keys and epoch $N+1$ master key, and re-encrypts every single entity into a clean SQLite database.
   - Observation: The `export_then_restore_roundtrip` test asserts exact byte-for-byte equality of 64 KiB binary file attachments, multi-line RSA certificates, JSON strings, and database relational hierarchy.
   - Inference: The export and restore system is completely genuine and functional, with 100% data fidelity and no mock bypasses.

---

## 3. Caveats

- Milestone M3-1 focuses strictly on core cryptography and storage (`crates/secwet-core` and `crates/secwet-proto`). Desktop Tauri IPC, CLI commands, and React UI components are in scope for Milestones M3-2, M3-3, and M3-4.
- In-memory keystore (`MemoryStore`) was used during unit and integration test suites, which is the standard testing pattern specified in `PROJECT.md`. Real OS platform keystores will be exercised in the CLI and desktop integration tests.

---

## 4. Conclusion

The code delivered for Milestone M3-1 strictly adheres to all requirements in `ORIGINAL_REQUEST.md` (R2) and `PROJECT.md`:
1. `create_recovery_key` generates genuine 125-bit random entropy via `OsRng` formatted as 25 Crockford Base32 characters in 5 groups.
2. `verify_recovery_key` executes authentic XChaCha20Poly1305 decryption of the stored seal.
3. `export_encrypted` and `restore_from_export` provide authentic, encrypted offline backups with 100% data fidelity.
4. No hardcoded results, facades, pre-populated artifacts, or test mocks exist.

**Final Verdict**: **CLEAN**.

---

## 5. Verification Method

To independently reproduce the forensic verification:

```bash
# 1. Run the core invariant integration tests
cargo test -p secwet-core --test recovery_export_tests

# 2. Run the 88-test end-to-end recovery suite
cargo test -p secwet-core --test recovery_e2e_suite

# 3. Run all unit and integration tests across secwet-proto and secwet-core
cargo test -p secwet-proto
cargo test -p secwet-core

# 4. Verify no compiler or clippy errors
cargo clippy -p secwet-core --test recovery_export_tests --test recovery_e2e_suite
```
