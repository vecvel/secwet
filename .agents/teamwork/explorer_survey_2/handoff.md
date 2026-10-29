# Milestone 3 Survey: Core Cryptography and Storage (Requirement R2)

## 1. Observation

### 1.1 Codebase Survey & Existing Primitives
- **Repository Location**: `/Users/besaoct/Desktop/secwet`
- **Specification Documents**:
  - `docs/IMPLEMENTATION.md`:
    - Section 4 (lines 101–176): Cryptographic specification (ChaCha20Poly1305, HKDF-SHA256, Ed25519, X25519, Crockford Base32, Key Derivations).
    - Section 5 (lines 177–284): Data model, records (`LabelBody`, `ItemBody`, `EnvironmentBody`, `SecretBody`, `AssetMetaBody`, `AssetPayload`, `NoteBody`), SQLite schema (`meta`, `labels`, `records`, `devices`, `outbox`, `settings`).
    - Section 6 (lines 347–352): Public API signatures for recovery and export.
    - Section 7 / F9 (lines 552–564): Recovery key specification, generation, normalization, verification seal (`recovery_check`), wrapped master keys.
    - Section 7 / F10 (lines 566–584): Encrypted export (`.secwet` envelope) and restore specification.
    - Section 12 / M3 (lines 1052–1055): Milestone 3 acceptance goals.
  - `ORIGINAL_REQUEST.md` (lines 17–19, 34–41, 53–57): Specific requirement R2 and acceptance criteria.

### 1.2 Status of Implemented vs Missing Components in `secwet-core`

| Component | Status | Existing Location | Details / Observations |
|---|---|---|---|
| **Crockford Base32 Alphabet & Value Mapping** | **Implemented** | `crates/secwet-core/src/crypto.rs:408-444` | Alphabet `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (32 chars, excludes I, L, O, U). |
| **Recovery Key Formatting (125-bit entropy in 5 groups)** | **Implemented** | `crates/secwet-core/src/crypto.rs:448-463` | `format_recovery_key(entropy_16: &[u8; 16]) -> String`. Top 3 bits masked `& 0x1F`, formats 25 chars in 5 groups: `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`. |
| **Recovery Key Generation** | **Implemented** | `crates/secwet-core/src/crypto.rs:468-474` | `generate_recovery_key() -> (String, Zeroizing<[u8; 16]>)` using `OsRng.fill_bytes`. |
| **Recovery Key Normalization** | **Implemented** | `crates/secwet-core/src/crypto.rs:484-506` | `normalize_recovery_key(input: &str) -> Result<String, CryptoError>`. Strips whitespace, hyphens, uppercases, maps `I`/`L` -> `1`, `O` -> `0`, validates length == 25 and character set. |
| **Recovery Key Parsing** | **Implemented** | `crates/secwet-core/src/crypto.rs:509-518` | `parse_recovery_key(input: &str) -> Result<Zeroizing<[u8; 16]>, CryptoError>`. Parses 25 Crockford chars to 16 bytes (top 3 bits 0). |
| **K_r Derivation (HKDF-SHA256)** | **Implemented** | `crates/secwet-core/src/crypto.rs:254-256` | `derive_recovery_key(recovery_secret: &[u8], secwet_id: &Uuid) -> Zeroizing<[u8; 32]>` with `salt = secwet_id.as_bytes()`, `info = b"secwet/v1/recovery"`. |
| **`create_recovery_key` in `Secwet`** | **Missing** | Needs to be added in `secwet.rs` | Does not exist in `Secwet`. Must generate key, derive $K_r$, compute `recovery_check`, wrap $K_m$ across epochs, store in `meta`. |
| **`recovery_check` Verification Seal** | **Missing** | Needs to be added in `secwet.rs` & `crypto.rs` | Must compute $XChaCha20Poly1305_{K_r}(\text{"secwet-recovery-check"})$ and store base64 in `meta`. |
| **`replace_recovery_key`** | **Missing** | Needs to be added in `secwet.rs` | Must generate new key, re-wrap all epochs of $K_m$, overwrite `recovery_check` & `recovery_wrapped_master_keys`, invalidate old key. |
| **`verify_recovery_key`** | **Missing** | Needs to be added in `secwet.rs` | Must verify candidate key against `recovery_check` seal without leaking details. |
| **`SecwetSnapshot` Data Model** | **Missing** | Needs to be added in `secwet-proto` / `secwet-core` | Snapshot structure capturing all spaces, labels, items, environments, secrets, notes, files, settings, and metadata. |
| **`SecwetExportEnvelope` & AAD** | **Missing** | Needs to be added in `secwet-proto` / `secwet-core` | JSON envelope (`format: "secwet-export"`, `version: 1`, `kdf: "hkdf-sha256"`, `cipher: "xchacha20poly1305"`, `nonce`, `ciphertext`) and authenticated AAD `postcard(("secwet-export", 1u8, secwet_id))`. |
| **`export_to_file` / `export_encrypted`** | **Missing** | Needs to be added in `secwet.rs` | Collects snapshot, postcard-serializes, seals with $K_r$ and AAD, writes JSON envelope to disk. |
| **`restore_from_export`** | **Missing** | Needs to be added in `secwet.rs` | Decrypts envelope, verifies AAD/MAC, deserializes snapshot, provisions new device keys and new master key epoch in keystore, re-encrypts and writes full SQLite database, returns active `Secwet`. |
| **Mandatory Invariant Test Suites** | **Missing** | Needs to be added in `tests/` | `export_then_restore_roundtrip`, `export_wrong_key_fails_without_detail`, `export_file_contains_no_plaintext`, `dotenv_export_requires_plaintext_flag`. |

### 1.3 Test Suite Baseline
- Executed `cargo test -p secwet-core`: 108 tests passed, 0 failed.
- Executed `cargo test -p secwet-cli`: 57 tests passed, 0 failed.

---

## 2. Logic Chain

### 2.1 Cryptographic Primitives & Derivations
1. **Entropy & Representation**:
   - `docs/IMPLEMENTATION.md §4.1` mandates: 125 bits of entropy, formatted as 25 Crockford Base32 characters in 5 groups of 5 separated by hyphens (e.g. `ABCDE-FGHIJ-KLMNP-QRSTV-WXYZ0`).
   - `crypto::generate_recovery_key()` generates 16 bytes from `OsRng`, masks top 3 bits (`raw[0] &= 0x1F`), giving $128 - 3 = 125$ bits.
   - `crypto::normalize_recovery_key()` ensures robust user input handling: uppercase mapping, stripping `-` and whitespace, converting `I`/`L` $\to 1$ and `O` $\to 0$.
   - Observation: These functions are already implemented and tested in `secwet-core/src/crypto.rs` (lines 446–534).

2. **Wrap Key Derivation ($K_r$)**:
   - `docs/IMPLEMENTATION.md §4.1` specifies:
     $$K_r = \text{HKDF-SHA256}(\text{ikm}=\text{recovery key entropy bytes}, \text{salt}=\text{secwet\_id bytes}, \text{info}=\text{"secwet/v1/recovery"})$$
   - `crypto::derive_recovery_key()` already implements this exact HKDF call.
   - Input to `derive_recovery_key` must be the 16 bytes of entropy (`Zeroizing<[u8; 16]>` from `parse_recovery_key`), not the formatted ASCII string.

3. **`recovery_check` Verification Seal**:
   - In `docs/IMPLEMENTATION.md §F9`:
     $$\text{recovery\_check} = \text{seal}(K_r, \text{"secwet-recovery-check"})$$
   - Encryption primitive: `XChaCha20Poly1305` using $K_r$, 24-byte random nonce from `OsRng`, and AAD `postcard(("secwet-recovery-check", secwet_id.as_bytes()))`.
   - Stored in `meta` table:
     - `recovery_created_at`: unix epoch timestamp string (ms).
     - `recovery_check`: base64 standard encoding of the sealed blob (`[0x01] || nonce(24) || ciphertext_with_tag`).
   - Verification mechanism: Decrypt `recovery_check` with candidate $K_r$. If decryption succeeds and plaintext equals `b"secwet-recovery-check"`, key is valid. If Poly1305 MAC check fails, return `Ok(false)` or `Err(Error::RecoveryFailed)` without panicking or leaking internal details.

4. **Master Key Wrapping Across Epochs (`replace_recovery_key`)**:
   - In `docs/IMPLEMENTATION.md §F9`:
     - Master encryption keys $K_m$ are stored per epoch in `keystore` at `secwet/{secwet_id}/master-key/{epoch}` for each epoch $1 \le e \le \text{current\_key\_epoch}$.
     - When `create_recovery_key` or `replace_recovery_key` executes:
       For each epoch $e \in [1, \text{current\_key\_epoch}]$, read $K_m(e)$ from `keystore`. Seal $K_m(e)$ under $K_r$ with AAD `postcard(("recovery-wrap", secwet_id.as_bytes(), e))`.
       Store in `meta` as `recovery_wrapped_master_keys = serde_json::to_string(&map)`.
     - When replacing: A new recovery key is generated, all epochs are re-wrapped under $K_{r,\text{new}}$, `recovery_check` is overwritten with the new seal, and old wrapped keys are deleted in a single SQLite transaction.

### 2.2 Export Envelope and Snapshot Serialization
1. **Envelope Specification** (`docs/IMPLEMENTATION.md §F10`):
   ```json
   {
     "format": "secwet-export",
     "version": 1,
     "secwet_id": "018d34b2-...",
     "created_at": 1730000000000,
     "kdf": "hkdf-sha256",
     "cipher": "xchacha20poly1305",
     "nonce": "<base64 standard>",
     "ciphertext": "<base64 standard>"
   }
   ```
2. **Authenticated Additional Data (AAD)**:
   - AAD bound to export ciphertext: `postcard::to_stdvec(&ExportAad { format: "secwet-export", version: 1, secwet_id: secwet_id.as_bytes() })`.
   - Prevents ciphertext splicing, format downgrades, or cross-workspace file substitutions.

3. **Complete Snapshot Structure (`SecwetSnapshot`)**:
   - Must capture 100% of workspace data:
     - `spaces`: ID, name, position, icon, is_default, timestamps, deleted.
     - `labels` (groups): ID, space_id, name, position, icon, timestamps, deleted.
     - `items` (projects): ID, label_id, name, description, position, timestamps, lamport, origin_device, deleted.
     - `environments`: ID, item_id, name, position, timestamps, lamport, origin_device, deleted.
     - `secrets`: ID, item_id, environment_id, name, kind, value (plaintext SecretString), note, timestamps, lamport, origin_device, deleted.
     - `notes`: ID, item_id, environment_id, title, content (plaintext rich text), position, timestamps, lamport, origin_device, deleted.
     - `files` (assets): ID, item_id, environment_id, name, size_bytes, mime_type, sha256, data (`Vec<u8>` raw decrypted payload), timestamps, lamport, origin_device, deleted.
     - `settings`: All key-value pairs from `settings` table.
     - Workspace metadata: `secwet_id`, `created_at`, `key_epoch`, `plan`, `relay_url`.
   - Serialized canonically using `postcard::to_stdvec(&snapshot)`.
   - Encrypted using $XChaCha20Poly1305_{K_r}$ with 24-byte random nonce and authenticated AAD.

### 2.3 Restore Workflow (`restore_from_export`)
1. **Decryption and Verification**:
   - Parses JSON envelope. Verifies format, version, KDF, cipher, and base64 fields.
   - Normalizes recovery key and derives $K_r$.
   - Authenticates and decrypts using $K_r$, `nonce`, and AAD. Any MAC or decoding failure immediately aborts with `Error::RecoveryFailed`.
   - Deserializes snapshot from postcard bytes. Any schema failure returns `Error::RecoveryFailed`.
2. **Workspace Provisioning**:
   - Generates fresh device keys (`Ed25519` identity signing key and `X25519` encryption key).
   - Generates next master key epoch $N+1 = \text{snapshot.key\_epoch} + 1$, generating fresh 32-byte $K_m$ from `OsRng`.
   - Writes device keys and new master key to `keystore`.
   - Initializes target SQLite database at `<data_dir>/secwet/<secwet_id>/secwet.sqlite3` with schema migrations (versions 1, 2, 3).
   - Re-encrypts all spaces, labels, items, environments, secrets, notes, and files under the new epoch $N+1$ and fresh record key $K_{\text{rec}}$, inserting into SQLite tables in an atomic transaction.
   - Restores settings and sets `meta` records.
   - Re-computes `recovery_check` and wraps the new epoch's master key under $K_r$ so recovery capabilities persist after restore.
   - Returns unlocked `Secwet` instance with 100% data fidelity.

---

## 3. Caveats

1. **Keystore Access for `create_recovery_key` and `replace_recovery_key`**:
   - `Secwet` struct does not currently retain a handle to `keystore`.
   - To read and wrap master keys across epochs ($K_m$), `create_recovery_key` and `replace_recovery_key` must receive `keystore: &dyn KeyStore` (matching `create(..., keystore)` and `unlock(..., keystore)`).
   - In Tauri, `AppState` already holds `pub keystore: Arc<dyn KeyStore>`. In CLI, `keystore` is already resolved via `resolve_keystore`. In unit tests, `MemoryStore` is used.
2. **File Size Consideration**:
   - File assets are limited to $\le 50\text{ MiB}$ per file as per `docs/IMPLEMENTATION.md §5.1`.
   - When snapshotting large workspaces with many file attachments, postcard serialization allocates the snapshot in memory. Memory limits should be documented (e.g. streaming export is not required for M3 since file limit is 50 MiB and desktop systems have sufficient RAM).
3. **Old Exports After Key Replacement**:
   - As documented in `docs/IMPLEMENTATION.md §F9`: Replacing a recovery key generates a new $K_r$. Old `.secwet` export files created before the replacement remain encrypted with the old recovery key and will still require the old recovery key to restore. The UI and documentation explicitly reflect this.

---

## 4. Conclusion

- The core cryptography foundations for recovery keys (125-bit entropy masking, Crockford Base32 formatting, normalization, parsing, and HKDF-SHA256 $K_r$ derivation) are already solidly implemented in `crates/secwet-core/src/crypto.rs`.
- The missing components required to fulfill Requirement R2 are:
  1. **Data Models** in `secwet-proto` / `secwet-core::model`:
     - `SecwetSnapshot`, `SnapshotSpace`, `SnapshotLabel`, `SnapshotItem`, `SnapshotEnvironment`, `SnapshotSecret`, `SnapshotNote`, `SnapshotFile`.
     - `SecwetExportEnvelope`, `ExportAad`, `ExportSummary`, `RecoveryStatus`.
  2. **Core Crypto Helpers** in `secwet-core::crypto`:
     - Generic `seal_raw` / `open_raw` or recovery seal helpers for arbitrary payloads with AAD.
     - `derive_recovery_key_from_str`.
  3. **Core Methods** in `secwet-core::secwet::Secwet`:
     - `create_recovery_key(&mut self, keystore: &dyn KeyStore) -> Result<SecretString>`
     - `replace_recovery_key(&mut self, keystore: &dyn KeyStore) -> Result<SecretString>`
     - `verify_recovery_key(&self, input: &str) -> Result<bool>`
     - `recovery_status(&self) -> Result<RecoveryStatus>`
     - `export_to_file(&self, recovery_key: &str, out: &Path) -> Result<ExportSummary>`
     - `export_encrypted(&self, recovery_key: &SecretString, out: &Path) -> Result<ExportSummary>`
     - `restore_from_export(data_dir: &Path, file: &Path, recovery_key: &str, device_name: &str, keystore: &dyn KeyStore) -> Result<Secwet>`
  4. **Test Suite** in `crates/secwet-core/tests/recovery_export_tests.rs`:
     - `test_recovery_key_create_and_verify`
     - `test_recovery_check_detects_wrong_key`
     - `test_replace_recovery_key_invalidates_old`
     - `test_export_then_restore_roundtrip` (100% data fidelity across spaces, groups, items, environments, secrets, notes, files, settings)
     - `test_export_wrong_key_fails_without_detail`
     - `test_export_file_contains_no_plaintext`

---

## 5. Verification Method

To verify these findings and subsequently validate the implementation:

1. **Verify Baseline Tests**:
   ```bash
   cargo test -p secwet-core
   cargo test -p secwet-cli
   ```
2. **Verify Recovery Cryptography Primitives**:
   Inspect `crates/secwet-core/src/crypto.rs` lines 446–534 and run:
   ```bash
   cargo test -p secwet-core --test crypto_tests test_recovery_key_format_and_normalization
   cargo test -p secwet-core --test crypto_adversarial challenge_recovery_key_adversarial_normalization_and_boundaries
   ```
3. **Verify Implementation of R2 (Post-Implementation)**:
   Execute the dedicated test suite:
   ```bash
   cargo test -p secwet-core --test recovery_export_tests
   ```
   Check that all mandatory invariant tests pass:
   - `export_then_restore_roundtrip`
   - `export_wrong_key_fails_without_detail`
   - `export_file_contains_no_plaintext`
   - `recovery_check_detects_wrong_key`
   - `replace_recovery_key_invalidates_old`
