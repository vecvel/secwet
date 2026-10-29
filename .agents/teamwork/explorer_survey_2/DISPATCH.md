## 2026-10-27T16:14:33Z

**Context**: Milestone 3 Survey - Core Cryptography and Storage (Requirement R2).
**Identity & Working Directory**:
- Type: teamwork_explorer
- Working directory: /Users/besaoct/Desktop/secwet/.agents/teamwork/explorer_survey_2
- Parent Conversation ID: 1ebf4374-d237-49fe-9aa4-ecab43ee8aa1

**Mandatory Task**:
Read the original user request at:
`/Users/besaoct/Desktop/secwet/.agents/teamwork/ORIGINAL_REQUEST.md`

Read the specification documents:
- `docs/IMPLEMENTATION.md` (specifically Section 12 M3, Sections F9 & F10, Section 4 Cryptography, Section 5 Storage & Envelopes)

Investigate the core Rust codebase in `crates/secwet-core/` (and related crates like `crates/secwet-crypto/` or storage modules):
- Examine current implementations and requirements for:
  1. `create_recovery_key`: Generating 125-bit entropy formatted as 25-character Crockford base32 in 5 groups (e.g. `ABCDE-FGHIJ-...`), Crockford normalization (case insensitivity, spaces, hyphens, I/L -> 1, O -> 0).
  2. Deriving K_r from recovery key (Argon2id or HKDF or specified derivation).
  3. Computing `recovery_check` verification seal to verify correct key and detect wrong key.
  4. `replace_recovery_key`: Wrapping master keys across epochs with new K_r and invalidating old recovery check.
  5. `export_to_file`: Serializing all spaces, groups, items, environments, secrets, notes, and files into an encrypted `.secwet` envelope sealed with K_r and authenticated AAD (postcard snapshot serialized, encrypted envelope).
  6. `restore_from_export`: Decrypting `.secwet` envelope, verifying integrity/AAD, and restoring workspace state with 100% data fidelity.
  7. Invariants: `export_then_restore_roundtrip`, `export_wrong_key_fails_without_detail`, `export_file_contains_no_plaintext`.
- Identify what types, functions, tests already exist, what needs to be implemented or extended, and any cryptographic primitives/dependencies.

**Scope Boundaries**:
- This is a READ-ONLY exploration. Do NOT write or modify source code files.
- Produce your detailed findings and handoff report in:
  `/Users/besaoct/Desktop/secwet/.agents/teamwork/explorer_survey_2/handoff.md`
- Update `/Users/besaoct/Desktop/secwet/.agents/teamwork/explorer_survey_2/progress.md` with timestamps as you progress.
- Send a completion message back to parent when done referencing the handoff path.
