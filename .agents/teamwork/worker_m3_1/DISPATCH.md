## 2026-10-27T16:30:38Z
[Message] timestamp=2026-10-27T16:30:38Z sender=1ebf4374-d237-49fe-9aa4-ecab43ee8aa1 priority=MESSAGE_PRIORITY_HIGH content=**Context**: Milestone M3-1: Core Cryptography and Storage (Requirement R2).
**Identity & Working Directory**:
- Type: teamwork_worker
- Working directory: /Users/besaoct/Desktop/secwet/.agents/teamwork/worker_m3_1
- Parent Conversation ID: 1ebf4374-d237-49fe-9aa4-ecab43ee8aa1

**Mandatory Task**:
Read the original user request at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/ORIGINAL_REQUEST.md`

Read the project scope and architecture at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/orchestrator/PROJECT.md`

Read the detailed findings and technical specifications in Explorer 2's handoff report at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/explorer_survey_2/handoff.md`

Implement Milestone M3-1 in `crates/secwet-core` (and `crates/secwet-proto` if needed):
1. Data Models:
   - Define `SecwetSnapshot` and its entity snapshots (`SnapshotSpace`, `SnapshotLabel`, `SnapshotItem`, `SnapshotEnvironment`, `SnapshotSecret`, `SnapshotNote`, `SnapshotFile`, `SnapshotSetting`, metadata) in `secwet-core::model` or `records.rs`.
   - Define `SecwetExportEnvelope`, `ExportAad`, `ExportSummary`, `RecoveryStatus` with postcard and serde serialization.
2. Cryptographic and Seal Helpers:
   - In `crypto.rs`: implement sealing/opening helpers using XChaCha20Poly1305 with authenticated AAD for `recovery_check` and the export envelope.
   - Implement `derive_recovery_key_from_str(recovery_key_str: &str, secwet_id: &Uuid) -> Result<Zeroizing<[u8; 32]>, CryptoError>` utilizing existing normalization, parsing, and `derive_recovery_key`.
3. `Secwet` Core Methods:
   - `create_recovery_key(&mut self, keystore: &dyn KeyStore) -> Result<SecretString, Error>`:
     - Generate 125-bit recovery key formatted as 25 Crockford base32 characters in 5 groups of 5.
     - Derive $K_r$.
     - Compute `recovery_check` seal ($XChaCha20Poly1305_{K_r}(\text{"secwet-recovery-check"})$) with AAD `("secwet-recovery-check", secwet_id)`.
     - Read and wrap all master keys $K_m(e)$ for epochs $1 \le e \le \text{current\_key\_epoch}$ under $K_r$ with AAD `("recovery-wrap", secwet_id, e)`.
     - Store `recovery_created_at`, `recovery_check`, and `recovery_wrapped_master_keys` in SQLite `meta` table in an atomic transaction.
   - `replace_recovery_key(&mut self, keystore: &dyn KeyStore) -> Result<SecretString, Error>`:
     - Generate new key, re-wrap all epochs of $K_m$ with new $K_r$, overwrite `recovery_check` and `recovery_wrapped_master_keys`, invalidating the old recovery key.
   - `verify_recovery_key(&self, input: &str) -> Result<bool, Error>`:
     - Normalize and parse candidate key, derive candidate $K_r$, verify against stored `recovery_check` seal. Returns false or error if invalid without leaking details.
   - `recovery_status(&self) -> Result<RecoveryStatus, Error>`:
     - Returns `{ created: bool, created_at: Option<u64> }` based on `meta` records.
   - `export_to_file(&self, recovery_key: &str, out: &Path) -> Result<ExportSummary, Error>` and `export_encrypted(&self, recovery_key: &SecretString, out: &Path) -> Result<ExportSummary, Error>`:
     - Collect full snapshot of all spaces, labels, items, environments, secrets, notes, and file payloads.
     - Canonical postcard serialization.
     - Encrypt using $XChaCha20Poly1305_{K_r}$ with random 24-byte nonce and authenticated AAD bound to `("secwet-export", 1u8, secwet_id)`.
     - Write `.secwet` JSON envelope to `out`.
   - `restore_from_export(data_dir: &Path, file: &Path, recovery_key: &SecretString, device_name: &str, keystore: &dyn KeyStore) -> Result<Secwet, Error>`:
     - Decrypt envelope, verify AAD and MAC.
     - Deserialized postcard snapshot.
     - Provision fresh device signing and encryption keys in keystore.
     - Provision next master key epoch $N+1$ in keystore.
     - Initialize clean SQLite database at target path, run schema migrations, and re-encrypt all entities into SQLite with 100% data fidelity.
     - Compute new recovery check and wrap new epoch under $K_r$.
     - Return active `Secwet` instance.
4. Invariant Tests:
   - Create `crates/secwet-core/tests/recovery_export_tests.rs`:
     - `export_then_restore_roundtrip`: Populates rich workspace with spaces, labels, items, environments, secrets, rich notes, and binary files; exports to `.secwet`; restores into a new data directory; verifies 100% exact equality and fidelity across all entities.
     - `export_wrong_key_fails_without_detail`: Verifies wrong key fails cleanly with generic error and zero data leakage.
     - `export_file_contains_no_plaintext`: Reads the exported `.secwet` file raw and verifies zero occurrences of plaintext secret values, notes, or file content.
     - `test_recovery_key_create_and_replace`: Verifies key creation, replacement, and invalidation of previous key.

**Write Ownership**:
You exclusively own:
- `crates/secwet-core/src/` (crypto.rs, model.rs, records.rs, secwet.rs, error.rs, etc.)
- `crates/secwet-core/tests/recovery_export_tests.rs`
- `crates/secwet-proto/` (if needed for shared DTOs)
