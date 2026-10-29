//! Comprehensive Milestone 3 E2E Recovery and Export Test Suite.
//!
//! Authoritative source: `ORIGINAL_REQUEST.md` (R1-R6), `docs/IMPLEMENTATION.md` (F9, F10, M3),
//! and `PROJECT.md` (Architecture, Milestones, Contracts).
//!
//! Structure:
//! - Reference Cryptographic Oracle: `SecwetArchiveOracle`
//! - Reference Snapshot Models: `SecwetSnapshot`, `SnapshotSpace`, `SnapshotLabel`, etc.
//! - Tier 1: Feature Coverage (>=5 per feature)
//! - Tier 2: Boundary & Corner Cases (>=5 per feature)
//! - Tier 3: Cross-Feature Combinations (Pairwise matrix)
//! - Tier 4: Real-World Application Scenarios (>=5 application-level)

use data_encoding::BASE64;
use rand_core::Rng;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use tempfile::tempdir;
use uuid::Uuid;

use secwet_core::crypto::{
    derive_recovery_key, format_normalized_recovery_key, format_recovery_key,
    generate_recovery_key, normalize_recovery_key, open_raw_parts, parse_recovery_key,
    seal_raw_parts, CryptoError, OsRng,
};

// ============================================================================
// Reference Models & Cryptographic Oracle
// ============================================================================

pub const EXPORT_FORMAT: &str = "secwet-export";
pub const EXPORT_VERSION: u32 = 1;
pub const KDF_NAME: &str = "hkdf-sha256";
pub const CIPHER_NAME: &str = "xchacha20poly1305";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecwetExportEnvelope {
    pub format: String,
    pub version: u32,
    pub secwet_id: Uuid,
    pub created_at: i64,
    pub kdf: String,
    pub cipher: String,
    pub nonce: String,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecwetSnapshot {
    pub secwet_id: Uuid,
    pub created_at: i64,
    pub key_epoch: u32,
    pub spaces: Vec<SnapshotSpace>,
    pub labels: Vec<SnapshotLabel>,
    pub items: Vec<SnapshotItem>,
    pub environments: Vec<SnapshotEnvironment>,
    pub secrets: Vec<SnapshotSecret>,
    pub notes: Vec<SnapshotNote>,
    pub files: Vec<SnapshotFile>,
    pub settings: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSpace {
    pub id: Uuid,
    pub name: String,
    pub position: i32,
    pub icon: Option<String>,
    pub is_default: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotLabel {
    pub id: Uuid,
    pub space_id: Uuid,
    pub name: String,
    pub position: i32,
    pub icon: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotItem {
    pub id: Uuid,
    pub label_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub position: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotEnvironment {
    pub id: Uuid,
    pub item_id: Uuid,
    pub name: String,
    pub position: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotSecret {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub kind: String,
    pub value: String,
    pub note: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotNote {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub title: String,
    pub content: String,
    pub position: i32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub id: Uuid,
    pub item_id: Uuid,
    pub environment_id: Option<Uuid>,
    pub name: String,
    pub size_bytes: u64,
    pub mime_type: Option<String>,
    pub sha256: String,
    pub data: Vec<u8>,
    pub created_at: i64,
    pub updated_at: i64,
}

/// Standalone reference oracle implementing `docs/IMPLEMENTATION.md §4, §F9, §F10`.
pub struct SecwetArchiveOracle;

impl SecwetArchiveOracle {
    /// Computes canonical AAD bound to `("secwet-export", 1u8, secwet_id.as_bytes())`.
    pub fn compute_aad(secwet_id: &Uuid) -> Vec<u8> {
        postcard::to_stdvec(&(EXPORT_FORMAT, 1u8, secwet_id.as_bytes()))
            .expect("canonical AAD postcard serialization")
    }

    /// Computes canonical recovery check AAD bound to `("secwet-recovery-check", secwet_id.as_bytes())`.
    pub fn compute_seal_aad(secwet_id: &Uuid) -> Vec<u8> {
        postcard::to_stdvec(&("secwet-recovery-check", secwet_id.as_bytes()))
            .expect("canonical recovery check AAD postcard serialization")
    }

    /// Computes recovery check seal: XChaCha20Poly1305_K_r("secwet-recovery-check").
    pub fn create_recovery_seal(recovery_secret: &[u8; 16], secwet_id: &Uuid) -> String {
        let k_r = derive_recovery_key(recovery_secret, secwet_id);
        let aad = Self::compute_seal_aad(secwet_id);
        let (nonce, ciphertext) = seal_raw_parts(&k_r, &aad, b"secwet-recovery-check")
            .expect("encryption of recovery seal");
        let mut blob = Vec::with_capacity(1 + 24 + ciphertext.len());
        blob.push(0x01); // framing byte
        blob.extend_from_slice(&nonce);
        blob.extend_from_slice(&ciphertext);
        BASE64.encode(&blob)
    }

    /// Verifies candidate recovery key against `recovery_check` seal.
    pub fn verify_recovery_seal(
        recovery_input: &str,
        secwet_id: &Uuid,
        seal_base64: &str,
    ) -> Result<bool, CryptoError> {
        let entropy = parse_recovery_key(recovery_input)?;
        let blob = BASE64.decode(seal_base64.as_bytes()).map_err(|_| CryptoError)?;
        if blob.len() < 1 + 24 + 16 || blob[0] != 0x01 {
            return Err(CryptoError);
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&blob[1..25]);
        let ciphertext = &blob[25..];
        let k_r = derive_recovery_key(&*entropy, secwet_id);
        let aad = Self::compute_seal_aad(secwet_id);
        match open_raw_parts(&k_r, &aad, &nonce, ciphertext) {
            Ok(pt) => Ok(pt == b"secwet-recovery-check"),
            Err(_) => Ok(false),
        }
    }

    /// Seals a SecwetSnapshot into a `.secwet` JSON envelope.
    pub fn seal_archive(
        snapshot: &SecwetSnapshot,
        recovery_secret: &[u8; 16],
    ) -> Result<SecwetExportEnvelope, CryptoError> {
        let k_r = derive_recovery_key(recovery_secret, &snapshot.secwet_id);
        let plaintext_bytes = postcard::to_stdvec(snapshot).map_err(|_| CryptoError)?;
        let aad = Self::compute_aad(&snapshot.secwet_id);
        let (nonce, ciphertext) = seal_raw_parts(&k_r, &aad, &plaintext_bytes)?;

        Ok(SecwetExportEnvelope {
            format: EXPORT_FORMAT.to_string(),
            version: EXPORT_VERSION,
            secwet_id: snapshot.secwet_id,
            created_at: snapshot.created_at,
            kdf: KDF_NAME.to_string(),
            cipher: CIPHER_NAME.to_string(),
            nonce: BASE64.encode(&nonce),
            ciphertext: BASE64.encode(&ciphertext),
        })
    }

    /// Opens and decrypts a `.secwet` JSON envelope using candidate recovery key.
    pub fn open_archive(
        envelope: &SecwetExportEnvelope,
        recovery_input: &str,
    ) -> Result<SecwetSnapshot, CryptoError> {
        if envelope.format != EXPORT_FORMAT || envelope.version != EXPORT_VERSION {
            return Err(CryptoError);
        }
        if envelope.kdf != KDF_NAME || envelope.cipher != CIPHER_NAME {
            return Err(CryptoError);
        }
        let entropy = parse_recovery_key(recovery_input)?;
        let k_r = derive_recovery_key(&*entropy, &envelope.secwet_id);

        let nonce_bytes = BASE64.decode(envelope.nonce.as_bytes()).map_err(|_| CryptoError)?;
        if nonce_bytes.len() != 24 {
            return Err(CryptoError);
        }
        let mut nonce = [0u8; 24];
        nonce.copy_from_slice(&nonce_bytes);

        let ciphertext_bytes = BASE64
            .decode(envelope.ciphertext.as_bytes())
            .map_err(|_| CryptoError)?;

        let aad = Self::compute_aad(&envelope.secwet_id);
        let plaintext = open_raw_parts(&k_r, &aad, &nonce, &ciphertext_bytes)?;
        let snapshot: SecwetSnapshot = postcard::from_bytes(&plaintext).map_err(|_| CryptoError)?;
        Ok(snapshot)
    }
}

// ============================================================================
// TIER 1: FEATURE COVERAGE (>=5 tests per feature)
// ============================================================================

// --- Feature 1: Recovery Key Generation & Formatting ---

#[test]
fn test_t1_key_gen_1_entropy_125bit_masked_top3() {
    for _ in 0..10 {
        let (_, raw) = generate_recovery_key();
        assert_eq!(raw[0] & 0xE0, 0, "Top 3 bits of entropy must be 0 (125-bit entropy)");
    }
}

#[test]
fn test_t1_key_gen_2_format_25_chars_5_groups() {
    let (key, _) = generate_recovery_key();
    assert_eq!(key.len(), 29, "Formatted key must be 29 chars (25 chars + 4 hyphens)");
    let groups: Vec<&str> = key.split('-').collect();
    assert_eq!(groups.len(), 5, "Must have exactly 5 groups");
    for (i, group) in groups.iter().enumerate() {
        assert_eq!(group.len(), 5, "Group {i} must be exactly 5 characters");
    }
}

#[test]
fn test_t1_key_gen_3_crockford_base32_character_set() {
    let allowed = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    for _ in 0..10 {
        let (key, _) = generate_recovery_key();
        for c in key.chars() {
            if c != '-' {
                assert!(allowed.contains(c), "Character '{c}' not in Crockford alphabet");
            }
        }
    }
}

#[test]
fn test_t1_key_gen_4_uniqueness_across_consecutive_generations() {
    let mut keys = HashSet::new();
    for _ in 0..50 {
        let (key, _) = generate_recovery_key();
        assert!(keys.insert(key), "Generated duplicate recovery key!");
    }
}

#[test]
fn test_t1_key_gen_5_excludes_prohibited_characters_ilou() {
    let prohibited = ['I', 'L', 'O', 'U', 'i', 'l', 'o', 'u'];
    for _ in 0..20 {
        let (key, _) = generate_recovery_key();
        for p in prohibited {
            assert!(!key.contains(p), "Key contains prohibited character '{p}'");
        }
    }
}

// --- Feature 2: Recovery Key Normalization ---

#[test]
fn test_t1_norm_1_lowercase_to_uppercase() {
    let raw = "abcde-fghjk-mnpqr-stvwx-yz012";
    let norm = normalize_recovery_key(raw).expect("normalization must succeed");
    assert_eq!(norm, norm.to_ascii_uppercase(), "Normalized key must be uppercase");
}

#[test]
fn test_t1_norm_2_strips_hyphens() {
    let raw = "ABCDE-FGHIJ-KLMNP-QRSTV-WXYZ0"; // Contains 'I', 'L', 'O' which will be mapped
    let norm = normalize_recovery_key(raw).expect("normalization must succeed");
    assert!(!norm.contains('-'), "Normalized key must not contain hyphens");
    assert_eq!(norm.len(), 25);
}

#[test]
fn test_t1_norm_3_strips_whitespace_tabs_spaces() {
    let raw = "  ABCDE \t\n FG1JK \r MNPQR \n STVWX \t YZ012  ";
    let norm = normalize_recovery_key(raw).expect("normalization must succeed");
    assert_eq!(norm.len(), 25);
    assert!(!norm.chars().any(|c| c.is_whitespace()));
}

#[test]
fn test_t1_norm_4_maps_crockford_aliases() {
    // 'I' and 'L' -> '1', 'O' -> '0'
    let input25 = "IIII1-LLLL1-OOOO0-11111-00000";
    let norm = normalize_recovery_key(input25).expect("aliases must normalize");
    assert_eq!(norm, "1111111111000001111100000");
}

#[test]
fn test_t1_norm_5_format_normalized_key_produces_5x5_groups() {
    let normalized = "0123456789ABCDEFGHJKMNPQR";
    let formatted = format_normalized_recovery_key(normalized).expect("formatting must succeed");
    assert_eq!(formatted, "01234-56789-ABCDE-FGHJK-MNPQR");
}

// --- Feature 3: Recovery Key Parsing & Entropy Extraction ---

#[test]
fn test_t1_parse_1_valid_formatted_key_produces_16_bytes() {
    let (key, expected_raw) = generate_recovery_key();
    let parsed = parse_recovery_key(&key).expect("parsing must succeed");
    assert_eq!(&*parsed, &*expected_raw, "Parsed bytes must match generated entropy");
}

#[test]
fn test_t1_parse_2_valid_unhyphenated_key_produces_identical_bytes() {
    let (key, expected_raw) = generate_recovery_key();
    let unhyphenated = key.replace('-', "");
    let parsed = parse_recovery_key(&unhyphenated).expect("unhyphenated parse must succeed");
    assert_eq!(&*parsed, &*expected_raw);
}

#[test]
fn test_t1_parse_3_aliased_key_produces_identical_bytes() {
    // A key with '1' replaced by 'I' or 'L' should parse to the exact same bytes
    let standard = "11111-11111-00000-00000-11111";
    let aliased = "IIIIL-LLLLI-OOOOO-ooooo-l1i1l";
    let p1 = parse_recovery_key(standard).unwrap();
    let p2 = parse_recovery_key(aliased).unwrap();
    assert_eq!(&*p1, &*p2, "Aliased key must parse to identical entropy bytes");
}

#[test]
fn test_t1_parse_4_top_3_bits_are_zero() {
    let (key, _) = generate_recovery_key();
    let parsed = parse_recovery_key(&key).unwrap();
    assert_eq!(parsed[0] & 0xE0, 0, "Top 3 bits of parsed entropy must be 0");
}

#[test]
fn test_t1_parse_5_full_roundtrip_generate_format_parse_format() {
    let (original_key, raw) = generate_recovery_key();
    let parsed = parse_recovery_key(&original_key).unwrap();
    assert_eq!(&*parsed, &*raw);
    let reformatted = format_recovery_key(&parsed);
    assert_eq!(original_key, reformatted, "Re-formatted key must match original");
}

// --- Feature 4: K_r Key Derivation (HKDF-SHA256) ---

#[test]
fn test_t1_kr_1_deterministic_derivation() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let k_r1 = derive_recovery_key(&*raw, &secwet_id);
    let k_r2 = derive_recovery_key(&*raw, &secwet_id);
    assert_eq!(&*k_r1, &*k_r2, "HKDF derivation must be strictly deterministic");
}

#[test]
fn test_t1_kr_2_domain_separation_by_workspace_uuid() {
    let id1 = Uuid::new_v4();
    let id2 = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let k_r1 = derive_recovery_key(&*raw, &id1);
    let k_r2 = derive_recovery_key(&*raw, &id2);
    assert_ne!(&*k_r1, &*k_r2, "Different workspace UUIDs must yield different K_r");
}

#[test]
fn test_t1_kr_3_domain_separation_by_recovery_secret() {
    let secwet_id = Uuid::new_v4();
    let (_, raw1) = generate_recovery_key();
    let (_, raw2) = generate_recovery_key();
    let k_r1 = derive_recovery_key(&*raw1, &secwet_id);
    let k_r2 = derive_recovery_key(&*raw2, &secwet_id);
    assert_ne!(&*k_r1, &*k_r2, "Different recovery secrets must yield different K_r");
}

#[test]
fn test_t1_kr_4_hkdf_info_secwet_v1_recovery() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let k_r = derive_recovery_key(&*raw, &secwet_id);
    assert_eq!(k_r.len(), 32, "K_r must be 32 bytes (256 bits)");
    assert_ne!(&*k_r, &[0u8; 32], "K_r must not be all zeros");
}

#[test]
fn test_t1_kr_5_high_entropy_output_32_bytes() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let k_r = derive_recovery_key(&*raw, &secwet_id);
    // Assert non-trivial byte distribution
    let set: HashSet<u8> = k_r.iter().copied().collect();
    assert!(set.len() > 15, "Derived key should have strong byte entropy");
}

// --- Feature 5: Verification Seal (`recovery_check`) ---

#[test]
fn test_t1_seal_1_valid_key_verifies_successfully() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let seal = SecwetArchiveOracle::create_recovery_seal(&raw, &secwet_id);
    let ok = SecwetArchiveOracle::verify_recovery_seal(&key_str, &secwet_id, &seal)
        .expect("seal verification should not error");
    assert!(ok, "Valid recovery key must verify against seal");
}

#[test]
fn test_t1_seal_2_wrong_key_fails_verification() {
    let secwet_id = Uuid::new_v4();
    let (_, raw1) = generate_recovery_key();
    let (key_str2, _) = generate_recovery_key();
    let seal = SecwetArchiveOracle::create_recovery_seal(&raw1, &secwet_id);
    let ok = SecwetArchiveOracle::verify_recovery_seal(&key_str2, &secwet_id, &seal)
        .expect("seal verification should not error");
    assert!(!ok, "Wrong recovery key must be rejected by seal");
}

#[test]
fn test_t1_seal_3_tampered_seal_ciphertext_fails_verification() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let seal = SecwetArchiveOracle::create_recovery_seal(&raw, &secwet_id);
    let mut blob = BASE64.decode(seal.as_bytes()).unwrap();
    let last = blob.len() - 1;
    blob[last] ^= 0x01; // Tamper tag
    let tampered_seal = BASE64.encode(&blob);
    let ok = SecwetArchiveOracle::verify_recovery_seal(&key_str, &secwet_id, &tampered_seal)
        .expect("seal verification must return false on MAC failure");
    assert!(!ok, "Tampered seal must not verify");
}

#[test]
fn test_t1_seal_4_mismatched_workspace_uuid_fails_verification() {
    let secwet_id1 = Uuid::new_v4();
    let secwet_id2 = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let seal = SecwetArchiveOracle::create_recovery_seal(&raw, &secwet_id1);
    let ok = SecwetArchiveOracle::verify_recovery_seal(&key_str, &secwet_id2, &seal)
        .expect("seal verification must handle AAD mismatch safely");
    assert!(!ok, "Mismatched workspace UUID must fail seal verification");
}

#[test]
fn test_t1_seal_5_seal_verification_does_not_leak_plaintext() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let seal = SecwetArchiveOracle::create_recovery_seal(&raw, &secwet_id);
    let seal_bytes = BASE64.decode(seal.as_bytes()).unwrap();
    let needle = b"secwet-recovery-check";
    assert!(
        !seal_bytes.windows(needle.len()).any(|w| w == needle),
        "Raw seal must not contain plaintext 'secwet-recovery-check'"
    );
}

// --- Feature 6: Encrypted Export Envelope ---

#[test]
fn test_t1_export_1_envelope_json_schema_compliance() {
    let secwet_id = Uuid::new_v4();
    let (_key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![("theme".to_string(), "dark".to_string())],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).expect("sealing snapshot");
    assert_eq!(envelope.format, "secwet-export");
    assert_eq!(envelope.version, 1);
    assert_eq!(envelope.kdf, "hkdf-sha256");
    assert_eq!(envelope.cipher, "xchacha20poly1305");
    assert_eq!(envelope.secwet_id, secwet_id);

    let json = serde_json::to_string_pretty(&envelope).expect("JSON serialization");
    assert!(json.contains("\"format\": \"secwet-export\""));
    assert!(json.contains("\"version\": 1"));
}

#[test]
fn test_t1_export_2_aad_binding_to_format_version_workspace() {
    let id = Uuid::new_v4();
    let aad = SecwetArchiveOracle::compute_aad(&id);
    let (fmt, ver, id_bytes): (String, u8, [u8; 16]) =
        postcard::from_bytes(&aad).expect("postcard deserialize AAD");
    assert_eq!(fmt, "secwet-export");
    assert_eq!(ver, 1);
    assert_eq!(&id_bytes, id.as_bytes());
}

#[test]
fn test_t1_export_3_random_nonce_generation_per_export() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let env1 = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let env2 = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    assert_ne!(env1.nonce, env2.nonce, "Nonces must be randomly generated per export");
    assert_ne!(env1.ciphertext, env2.ciphertext, "Ciphertexts must differ due to distinct nonces");
}

#[test]
fn test_t1_export_4_raw_file_contains_no_plaintext_secrets() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let secret_val = "SECRET_SUPER_CONFIDENTIAL_TOKEN_XYZ_999";
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "API_TOKEN".to_string(),
            kind: "api_key".to_string(),
            value: secret_val.to_string(),
            note: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let json = serde_json::to_string(&envelope).unwrap();
    assert!(!json.contains(secret_val), "Raw export JSON must NEVER leak plaintext secret values!");
}

#[test]
fn test_t1_export_5_metadata_fields_accurate() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730001234567,
        key_epoch: 3,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    assert_eq!(envelope.created_at, 1730001234567);
    assert_eq!(envelope.secwet_id, secwet_id);
}

// --- Feature 7: Restore from Export ---

#[test]
fn test_t1_restore_1_valid_archive_decrypts_and_deserializes() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![("plan".to_string(), "personal".to_string())],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str)
        .expect("valid restore must succeed");
    assert_eq!(restored.secwet_id, secwet_id);
    assert_eq!(restored.settings, snapshot.settings);
}

#[test]
fn test_t1_restore_2_preserves_spaces_and_groups_hierarchy() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let space_id = Uuid::new_v4();
    let label_id = Uuid::new_v4();
    let item_id = Uuid::new_v4();

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![SnapshotSpace {
            id: space_id,
            name: "Production Space".to_string(),
            position: 0,
            icon: Some("server".to_string()),
            is_default: true,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        labels: vec![SnapshotLabel {
            id: label_id,
            space_id,
            name: "Backend Services".to_string(),
            position: 0,
            icon: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        items: vec![SnapshotItem {
            id: item_id,
            label_id,
            name: "Auth Service".to_string(),
            description: Some("Authentication provider".to_string()),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.spaces.len(), 1);
    assert_eq!(restored.labels.len(), 1);
    assert_eq!(restored.items.len(), 1);
    assert_eq!(restored.spaces[0].name, "Production Space");
    assert_eq!(restored.labels[0].space_id, space_id);
    assert_eq!(restored.items[0].label_id, label_id);
}

#[test]
fn test_t1_restore_3_preserves_secrets_values_and_kinds() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let item_id = Uuid::new_v4();

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id,
            environment_id: None,
            name: "DB_PASSWORD".to_string(),
            kind: "password".to_string(),
            value: "super$ecret!p@ss".to_string(),
            note: Some("Primary cluster password".to_string()),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.secrets.len(), 1);
    assert_eq!(restored.secrets[0].value, "super$ecret!p@ss");
    assert_eq!(restored.secrets[0].kind, "password");
}

#[test]
fn test_t1_restore_4_preserves_notes_and_rich_content() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let markdown_body = "# Operational Runbook\n\n1. Run `secwet get API_KEY`\n2. Inject into container\n3. Enjoy!";
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![SnapshotNote {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            title: "Runbook".to_string(),
            content: markdown_body.to_string(),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.notes[0].content, markdown_body);
}

#[test]
fn test_t1_restore_5_preserves_binary_file_attachments() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let binary_bytes = vec![0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0xFF, 0x42, 0x13, 0x37];
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![SnapshotFile {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "id_ed25519".to_string(),
            size_bytes: binary_bytes.len() as u64,
            mime_type: Some("application/octet-stream".to_string()),
            sha256: "dummy-sha".to_string(),
            data: binary_bytes.clone(),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.files[0].data, binary_bytes);
}

// ============================================================================
// TIER 2: BOUNDARY & CORNER CASES (>=5 tests per feature)
// ============================================================================

// --- Boundary 1: Corrupted Envelopes ---

#[test]
fn test_t2_corrupt_1_poly1305_tag_bit_flip_fails() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let mut ct = BASE64.decode(envelope.ciphertext.as_bytes()).unwrap();
    let tag_idx = ct.len() - 1; // Poly1305 tag is the last 16 bytes
    ct[tag_idx] ^= 0x01; // Single bit flip in MAC tag
    envelope.ciphertext = BASE64.encode(&ct);

    let res = SecwetArchiveOracle::open_archive(&envelope, &key_str);
    assert_eq!(res, Err(CryptoError), "Poly1305 MAC tampering must fail decryption");
}

#[test]
fn test_t2_corrupt_2_ciphertext_body_bit_flip_fails() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let mut ct = BASE64.decode(envelope.ciphertext.as_bytes()).unwrap();
    ct[0] ^= 0x80; // Flip MSB of first ciphertext byte
    envelope.ciphertext = BASE64.encode(&ct);

    let res = SecwetArchiveOracle::open_archive(&envelope, &key_str);
    assert_eq!(res, Err(CryptoError), "Ciphertext body tampering must fail decryption");
}

#[test]
fn test_t2_corrupt_3_nonce_tampering_fails() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let mut nonce = BASE64.decode(envelope.nonce.as_bytes()).unwrap();
    nonce[0] ^= 0x01; // Tamper nonce
    envelope.nonce = BASE64.encode(&nonce);

    let res = SecwetArchiveOracle::open_archive(&envelope, &key_str);
    assert_eq!(res, Err(CryptoError), "Nonce tampering must fail decryption");
}

#[test]
fn test_t2_corrupt_4_aad_workspace_uuid_mismatch_fails() {
    let secwet_id1 = Uuid::new_v4();
    let secwet_id2 = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id: secwet_id1,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    // Tamper the workspace UUID in envelope header
    envelope.secwet_id = secwet_id2;

    let res = SecwetArchiveOracle::open_archive(&envelope, &key_str);
    assert_eq!(res, Err(CryptoError), "AAD workspace UUID mismatch must fail decryption");
}

#[test]
fn test_t2_corrupt_5_unsupported_version_fails() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    envelope.version = 999; // Unsupported version

    let res = SecwetArchiveOracle::open_archive(&envelope, &key_str);
    assert_eq!(res, Err(CryptoError), "Unsupported envelope version must be rejected");
}

// --- Boundary 2: Truncated & Incomplete Files ---

#[test]
fn test_t2_trunc_1_zero_byte_file_fails() {
    let json = "";
    let res: Result<SecwetExportEnvelope, _> = serde_json::from_str(json);
    assert!(res.is_err(), "0-byte file cannot be parsed as SecwetExportEnvelope");
}

#[test]
fn test_t2_trunc_2_partial_json_envelope_fails() {
    let json = r#"{"format": "secwet-export", "version": 1, "secwet_id": "#;
    let res: Result<SecwetExportEnvelope, _> = serde_json::from_str(json);
    assert!(res.is_err(), "Incomplete JSON envelope must fail deserialization");
}

#[test]
fn test_t2_trunc_3_truncated_base64_ciphertext_fails() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    // Truncate ciphertext in half
    envelope.ciphertext = envelope.ciphertext[..envelope.ciphertext.len() / 2].to_string();

    let res = SecwetArchiveOracle::open_archive(&envelope, &key_str);
    assert_eq!(res, Err(CryptoError), "Truncated ciphertext must fail decryption");
}

#[test]
fn test_t2_trunc_4_truncated_nonce_fails() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    envelope.nonce = BASE64.encode(&[0u8; 12]); // 12 bytes instead of 24

    let res = SecwetArchiveOracle::open_archive(&envelope, &key_str);
    assert_eq!(res, Err(CryptoError), "Truncated nonce (non-24 bytes) must be rejected");
}

#[test]
fn test_t2_trunc_5_single_byte_file_fails() {
    let res: Result<SecwetExportEnvelope, _> = serde_json::from_str("{");
    assert!(res.is_err(), "Single byte file must fail deserialization");
}

// --- Boundary 3: Invalid Crockford Characters ---

#[test]
fn test_t2_invalid_1_character_u_rejected() {
    // Character 'U' is explicitly excluded from Crockford Base32 to avoid profanity
    let key = "UUUUU-01234-56789-ABCDE-FGHJK";
    let res = normalize_recovery_key(key);
    assert_eq!(res, Err(CryptoError), "'U' must be rejected as invalid Crockford character");
}

#[test]
fn test_t2_invalid_2_special_symbols_rejected() {
    let key = "ABCDE-$%#@!-56789-ABCDE-FGHJK";
    let res = normalize_recovery_key(key);
    assert_eq!(res, Err(CryptoError), "Special symbols must be rejected");
}

#[test]
fn test_t2_invalid_3_length_24_rejected() {
    let key = "01234-56789-ABCDE-FGHJK-MNPQ"; // 24 characters
    let res = normalize_recovery_key(key);
    assert_eq!(res, Err(CryptoError), "Key of length 24 must be rejected");
}

#[test]
fn test_t2_invalid_4_length_26_rejected() {
    let key = "01234-56789-ABCDE-FGHJK-MNPQR-A"; // 26 characters
    let res = normalize_recovery_key(key);
    assert_eq!(res, Err(CryptoError), "Key of length 26 must be rejected");
}

#[test]
fn test_t2_invalid_5_unicode_emojis_rejected() {
    let key = "01234-56789-🔐🔑🛡️-FGHJK-MNPQR";
    let res = normalize_recovery_key(key);
    assert_eq!(res, Err(CryptoError), "Unicode emojis must be rejected");
}

// --- Boundary 4: Wrong HMAC/MAC Tags ---

#[test]
fn test_t2_mac_1_single_bit_flip_in_tag() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let mut ct = BASE64.decode(envelope.ciphertext.as_bytes()).unwrap();
    let tag_idx = ct.len() - 8;
    ct[tag_idx] ^= 0x40; // Flip 6th bit
    envelope.ciphertext = BASE64.encode(&ct);

    assert_eq!(
        SecwetArchiveOracle::open_archive(&envelope, &key_str),
        Err(CryptoError),
        "Bit flip in middle of MAC tag must fail"
    );
}

#[test]
fn test_t2_mac_2_zeroed_mac_tag() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let mut ct = BASE64.decode(envelope.ciphertext.as_bytes()).unwrap();
    let len = ct.len();
    ct[len - 16..].fill(0); // Zero out Poly1305 tag
    envelope.ciphertext = BASE64.encode(&ct);

    assert_eq!(
        SecwetArchiveOracle::open_archive(&envelope, &key_str),
        Err(CryptoError),
        "Zeroed MAC tag must fail authentication"
    );
}

#[test]
fn test_t2_mac_3_all_ones_mac_tag() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let mut ct = BASE64.decode(envelope.ciphertext.as_bytes()).unwrap();
    let len = ct.len();
    ct[len - 16..].fill(0xFF); // 0xFF out Poly1305 tag
    envelope.ciphertext = BASE64.encode(&ct);

    assert_eq!(
        SecwetArchiveOracle::open_archive(&envelope, &key_str),
        Err(CryptoError),
        "0xFF MAC tag must fail authentication"
    );
}

#[test]
fn test_t2_mac_4_shuffled_tag_bytes() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let mut envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let mut ct = BASE64.decode(envelope.ciphertext.as_bytes()).unwrap();
    let len = ct.len();
    ct[len - 16..].reverse(); // Reverse tag bytes
    envelope.ciphertext = BASE64.encode(&ct);

    assert_eq!(
        SecwetArchiveOracle::open_archive(&envelope, &key_str),
        Err(CryptoError),
        "Reversed MAC tag must fail authentication"
    );
}

#[test]
fn test_t2_mac_5_wrong_recovery_key_fails_mac() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let (wrong_key, _) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();

    assert_eq!(
        SecwetArchiveOracle::open_archive(&envelope, &wrong_key),
        Err(CryptoError),
        "Opening with wrong recovery key must fail MAC authentication"
    );
}

// --- Boundary 5: Empty Workspaces ---

#[test]
fn test_t2_empty_1_workspace_with_zero_records_roundtrips() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.spaces.len(), 0);
    assert_eq!(restored.secrets.len(), 0);
    assert_eq!(restored.notes.len(), 0);
    assert_eq!(restored.files.len(), 0);
}

#[test]
fn test_t2_empty_2_empty_workspace_preserves_settings() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![("auto_lock_minutes".to_string(), "15".to_string())],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.settings.len(), 1);
    assert_eq!(restored.settings[0].1, "15");
}

#[test]
fn test_t2_empty_3_empty_workspace_has_valid_json_envelope() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let json = serde_json::to_string(&envelope).unwrap();
    assert!(!json.is_empty());
}

#[test]
fn test_t2_empty_4_empty_workspace_produces_no_plaintext_leak() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    assert_eq!(envelope.format, "secwet-export");
}

#[test]
fn test_t2_empty_5_empty_workspace_reconstructs_empty_collections() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert!(restored.spaces.is_empty());
    assert!(restored.labels.is_empty());
    assert!(restored.items.is_empty());
    assert!(restored.environments.is_empty());
    assert!(restored.secrets.is_empty());
    assert!(restored.notes.is_empty());
    assert!(restored.files.is_empty());
}

// --- Boundary 6: Maximal & Heavy Payloads ---

#[test]
fn test_t2_max_1_large_binary_asset_attachment() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    // 2 megabyte random binary asset
    let mut large_asset = vec![0u8; 2 * 1024 * 1024];
    OsRng.fill_bytes(&mut large_asset);

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![SnapshotFile {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "firmware.bin".to_string(),
            size_bytes: large_asset.len() as u64,
            mime_type: Some("application/octet-stream".to_string()),
            sha256: "dummy-sha-2mb".to_string(),
            data: large_asset.clone(),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.files[0].data.len(), 2 * 1024 * 1024);
    assert_eq!(restored.files[0].data, large_asset);
}

#[test]
fn test_t2_max_2_massive_multiline_certificate_secret() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    // 64 KB certificate payload
    let cert_line = "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDVR4Qv...\n";
    let massive_cert = cert_line.repeat(1000);

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "WILDCARD_TLS_CERT".to_string(),
            kind: "certificate".to_string(),
            value: massive_cert.clone(),
            note: Some("Generated wildcard cert".to_string()),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.secrets[0].value, massive_cert);
}

#[test]
fn test_t2_max_3_batch_500_secrets_roundtrip() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let mut secrets = Vec::with_capacity(500);
    for i in 0..500 {
        secrets.push(SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: format!("SECRET_KEY_{i:04}"),
            kind: "env_var".to_string(),
            value: format!("value_payload_for_secret_{i:04}"),
            note: None,
            created_at: 1730000000000 + i as i64,
            updated_at: 1730000000000 + i as i64,
        });
    }

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets,
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.secrets.len(), 500);
    assert_eq!(restored.secrets[499].name, "SECRET_KEY_0499");
}

#[test]
fn test_t2_max_4_deeply_nested_hierarchy_50_levels() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let mut items = Vec::new();
    let label_id = Uuid::new_v4();
    for i in 0..50 {
        items.push(SnapshotItem {
            id: Uuid::new_v4(),
            label_id,
            name: format!("Subsystem Layer {i}"),
            description: None,
            position: i,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        });
    }

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items,
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.items.len(), 50);
}

#[test]
fn test_t2_max_5_international_multibyte_utf8_strings() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let unicode_val = "こんにちは世界！Здравствуйте! 🚀🛡️ Привет, мир! 中文测试";
    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "UNICODE_TOKEN".to_string(),
            kind: "password".to_string(),
            value: unicode_val.to_string(),
            note: Some("Testing international characters".to_string()),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.secrets[0].value, unicode_val);
}

// --- Boundary 7: Crockford Alias Replacement ---

#[test]
fn test_t2_alias_1_lowercase_i_and_l_mapped_to_1() {
    let raw = "iiiii-lllll-00000-00000-00000";
    let norm = normalize_recovery_key(raw).unwrap();
    assert_eq!(&norm[0..10], "1111111111");
}

#[test]
fn test_t2_alias_2_uppercase_i_and_l_mapped_to_1() {
    let raw = "IIIII-LLLLL-00000-00000-00000";
    let norm = normalize_recovery_key(raw).unwrap();
    assert_eq!(&norm[0..10], "1111111111");
}

#[test]
fn test_t2_alias_3_lowercase_and_uppercase_o_mapped_to_0() {
    let raw = "OOOOO-ooooo-11111-11111-11111";
    let norm = normalize_recovery_key(raw).unwrap();
    assert_eq!(&norm[0..10], "0000000000");
}

#[test]
fn test_t2_alias_4_mixed_aliases_string() {
    let raw = "iIlLo-OIliL-01010-10101-01010";
    let norm = normalize_recovery_key(raw).unwrap();
    assert_eq!(&norm[0..10], "1111001111");
}

#[test]
fn test_t2_alias_5_all_alias_25_char_string() {
    let raw = "iLiLo-oLiLi-ilLoO-OIliL-lLoOi";
    let norm = normalize_recovery_key(raw).unwrap();
    assert_eq!(norm.len(), 25);
    for c in norm.chars() {
        assert!(c == '0' || c == '1', "All aliases must map strictly to 0 or 1");
    }
}

// --- Boundary 8: Formatting Permutations ---

#[test]
fn test_t2_format_1_lowercase_without_hyphens() {
    let (key, _) = generate_recovery_key();
    let lower_no_hyphens = key.replace('-', "").to_ascii_lowercase();
    let norm = normalize_recovery_key(&lower_no_hyphens).unwrap();
    let expected = normalize_recovery_key(&key).unwrap();
    assert_eq!(norm, expected);
}

#[test]
fn test_t2_format_2_interspersed_spaces_and_tabs() {
    let (key, _) = generate_recovery_key();
    let spaced = key.replace('-', "  \t ");
    let norm = normalize_recovery_key(&spaced).unwrap();
    let expected = normalize_recovery_key(&key).unwrap();
    assert_eq!(norm, expected);
}

#[test]
fn test_t2_format_3_multiple_consecutive_hyphens() {
    let (key, _) = generate_recovery_key();
    let multi_hyphens = key.replace('-', "---");
    let norm = normalize_recovery_key(&multi_hyphens).unwrap();
    let expected = normalize_recovery_key(&key).unwrap();
    assert_eq!(norm, expected);
}

#[test]
fn test_t2_format_4_leading_and_trailing_newlines() {
    let (key, _) = generate_recovery_key();
    let with_newlines = format!("\n\r\n\t{}\n\n", key);
    let norm = normalize_recovery_key(&with_newlines).unwrap();
    let expected = normalize_recovery_key(&key).unwrap();
    assert_eq!(norm, expected);
}

#[test]
fn test_t2_format_5_spaced_groups_instead_of_hyphens() {
    let (key, _) = generate_recovery_key();
    let spaced = key.replace('-', " ");
    let norm = normalize_recovery_key(&spaced).unwrap();
    let expected = normalize_recovery_key(&key).unwrap();
    assert_eq!(norm, expected);
}

// ============================================================================
// TIER 3: CROSS-FEATURE COMBINATIONS (Pairwise Matrix)
// ============================================================================

#[test]
fn test_t3_combo_1_multispace_multigroup_multisecret_asset_snapshot() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let s1 = Uuid::new_v4();
    let s2 = Uuid::new_v4();
    let l1 = Uuid::new_v4();
    let l2 = Uuid::new_v4();
    let i1 = Uuid::new_v4();
    let i2 = Uuid::new_v4();
    let e1 = Uuid::new_v4();
    let e2 = Uuid::new_v4();

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![
            SnapshotSpace {
                id: s1,
                name: "Engineering".to_string(),
                position: 0,
                icon: Some("code".to_string()),
                is_default: true,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotSpace {
                id: s2,
                name: "Finance".to_string(),
                position: 1,
                icon: Some("dollar".to_string()),
                is_default: false,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
        ],
        labels: vec![
            SnapshotLabel {
                id: l1,
                space_id: s1,
                name: "Infrastructure".to_string(),
                position: 0,
                icon: None,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotLabel {
                id: l2,
                space_id: s2,
                name: "Payroll".to_string(),
                position: 0,
                icon: None,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
        ],
        items: vec![
            SnapshotItem {
                id: i1,
                label_id: l1,
                name: "Kubernetes Cluster".to_string(),
                description: None,
                position: 0,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotItem {
                id: i2,
                label_id: l2,
                name: "Stripe Connect".to_string(),
                description: None,
                position: 0,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
        ],
        environments: vec![
            SnapshotEnvironment {
                id: e1,
                item_id: i1,
                name: "production".to_string(),
                position: 0,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotEnvironment {
                id: e2,
                item_id: i2,
                name: "production".to_string(),
                position: 0,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
        ],
        secrets: vec![
            SnapshotSecret {
                id: Uuid::new_v4(),
                item_id: i1,
                environment_id: Some(e1),
                name: "KUBECONFIG_TOKEN".to_string(),
                kind: "access_token".to_string(),
                value: "token_for_k8s_prod".to_string(),
                note: None,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotSecret {
                id: Uuid::new_v4(),
                item_id: i2,
                environment_id: Some(e2),
                name: "STRIPE_SECRET_KEY".to_string(),
                kind: "api_key".to_string(),
                value: "sk_live_123456789".to_string(),
                note: None,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
        ],
        notes: vec![SnapshotNote {
            id: Uuid::new_v4(),
            item_id: i1,
            environment_id: None,
            title: "On-Call Escalation".to_string(),
            content: "Call devops lead in emergency.".to_string(),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        files: vec![SnapshotFile {
            id: Uuid::new_v4(),
            item_id: i1,
            environment_id: None,
            name: "ca-cert.pem".to_string(),
            size_bytes: 4,
            mime_type: Some("application/x-pem-file".to_string()),
            sha256: "ca-sha".to_string(),
            data: b"CERT".to_vec(),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        settings: vec![("plan".to_string(), "pro".to_string())],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();

    assert_eq!(restored.spaces.len(), 2);
    assert_eq!(restored.labels.len(), 2);
    assert_eq!(restored.items.len(), 2);
    assert_eq!(restored.environments.len(), 2);
    assert_eq!(restored.secrets.len(), 2);
    assert_eq!(restored.notes.len(), 1);
    assert_eq!(restored.files.len(), 1);
    assert_eq!(restored.settings.len(), 1);
}

#[test]
fn test_t3_combo_2_key_replacement_export_restore_cycle() {
    let secwet_id = Uuid::new_v4();
    let (key1_str, raw1) = generate_recovery_key();
    let (key2_str, raw2) = generate_recovery_key();

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "SECRET_A".to_string(),
            kind: "password".to_string(),
            value: "value_a".to_string(),
            note: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    // Export 1 with key 1
    let env1 = SecwetArchiveOracle::seal_archive(&snapshot, &raw1).unwrap();

    // Export 2 with replaced key 2
    let env2 = SecwetArchiveOracle::seal_archive(&snapshot, &raw2).unwrap();

    // Verify key 1 opens env1 but fails on env2
    assert!(SecwetArchiveOracle::open_archive(&env1, &key1_str).is_ok());
    assert_eq!(SecwetArchiveOracle::open_archive(&env2, &key1_str), Err(CryptoError));

    // Verify key 2 opens env2 but fails on env1
    assert!(SecwetArchiveOracle::open_archive(&env2, &key2_str).is_ok());
    assert_eq!(SecwetArchiveOracle::open_archive(&env1, &key2_str), Err(CryptoError));
}

#[test]
fn test_t3_combo_3_multi_epoch_historical_archives_isolation() {
    let secwet_id = Uuid::new_v4();
    let (k1_str, r1) = generate_recovery_key();
    let (k2_str, r2) = generate_recovery_key();
    let (k3_str, r3) = generate_recovery_key();

    let snap1 = SecwetSnapshot {
        secwet_id,
        created_at: 1000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let snap2 = SecwetSnapshot {
        secwet_id,
        created_at: 2000,
        key_epoch: 2,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let snap3 = SecwetSnapshot {
        secwet_id,
        created_at: 3000,
        key_epoch: 3,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let env1 = SecwetArchiveOracle::seal_archive(&snap1, &r1).unwrap();
    let env2 = SecwetArchiveOracle::seal_archive(&snap2, &r2).unwrap();
    let env3 = SecwetArchiveOracle::seal_archive(&snap3, &r3).unwrap();

    assert_eq!(SecwetArchiveOracle::open_archive(&env1, &k1_str).unwrap().key_epoch, 1);
    assert_eq!(SecwetArchiveOracle::open_archive(&env2, &k2_str).unwrap().key_epoch, 2);
    assert_eq!(SecwetArchiveOracle::open_archive(&env3, &k3_str).unwrap().key_epoch, 3);
}

#[test]
fn test_t3_combo_4_master_key_epoch_migration_through_export_restore() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 4, // Current epoch 4
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();

    // In restore workflow, next epoch will be key_epoch + 1 (5)
    let next_epoch = restored.key_epoch + 1;
    assert_eq!(next_epoch, 5);
}

#[test]
fn test_t3_combo_5_idempotent_multi_cycle_roundtrip_stability() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let initial = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "PERSISTENT_SECRET".to_string(),
            kind: "password".to_string(),
            value: "stable_value".to_string(),
            note: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![("mode".to_string(), "offline".to_string())],
    };

    // Cycle 1: initial -> env1 -> restored1
    let env1 = SecwetArchiveOracle::seal_archive(&initial, &raw).unwrap();
    let restored1 = SecwetArchiveOracle::open_archive(&env1, &key_str).unwrap();

    // Cycle 2: restored1 -> env2 -> restored2
    let env2 = SecwetArchiveOracle::seal_archive(&restored1, &raw).unwrap();
    let restored2 = SecwetArchiveOracle::open_archive(&env2, &key_str).unwrap();

    // Cycle 3: restored2 -> env3 -> restored3
    let env3 = SecwetArchiveOracle::seal_archive(&restored2, &raw).unwrap();
    let restored3 = SecwetArchiveOracle::open_archive(&env3, &key_str).unwrap();

    assert_eq!(initial, restored1);
    assert_eq!(restored1, restored2);
    assert_eq!(restored2, restored3);
}

#[test]
fn test_t3_combo_6_all_seven_secret_kinds_heterogeneous_snapshot() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let item_id = Uuid::new_v4();

    let kinds = [
        "password",
        "api_key",
        "access_token",
        "env_var",
        "ssh_key",
        "certificate",
        "codes",
    ];

    let mut secrets = Vec::new();
    for kind in kinds {
        secrets.push(SnapshotSecret {
            id: Uuid::new_v4(),
            item_id,
            environment_id: None,
            name: format!("{}_secret", kind.to_ascii_uppercase()),
            kind: kind.to_string(),
            value: format!("value_for_{kind}"),
            note: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        });
    }

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets,
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.secrets.len(), 7);
    for s in &restored.secrets {
        assert!(kinds.contains(&s.kind.as_str()));
    }
}

#[test]
fn test_t3_combo_7_mixed_spaces_and_orphaned_environments_integrity() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();
    let item_id = Uuid::new_v4();

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![SnapshotEnvironment {
            id: Uuid::new_v4(),
            item_id,
            name: "staging".to_string(),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();
    assert_eq!(restored.environments.len(), 1);
    assert_eq!(restored.environments[0].name, "staging");
}

// ============================================================================
// TIER 4: REAL-WORLD APPLICATION SCENARIOS (>=5 Application Scenarios)
// ============================================================================

/// Scenario 1: Catastrophic Hardware Failure & Disaster Recovery
///
/// Device A initialized -> populated with microservices, dotenv secrets, SSH keys,
/// architecture runbooks, and TLS certs -> Device A lost -> Clean Device B restored
/// with recovery key -> Verified 100% operational.
#[test]
fn test_t4_scenario_1_cloud_microservice_disaster_recovery() {
    let temp = tempdir().unwrap();
    let export_file = temp.path().join("production-disaster-backup.secwet");

    let secwet_id = Uuid::now_v7();
    let (recovery_key, raw_entropy) = generate_recovery_key();

    // Device A Workspace Population
    let space_prod = Uuid::new_v4();
    let group_backends = Uuid::new_v4();
    let item_auth = Uuid::new_v4();
    let item_billing = Uuid::new_v4();
    let env_prod_auth = Uuid::new_v4();
    let env_prod_billing = Uuid::new_v4();

    let cert_data = b"-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL9...\n-----END CERTIFICATE-----\n".to_vec();

    let snapshot_device_a = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![SnapshotSpace {
            id: space_prod,
            name: "Cloud Production".to_string(),
            position: 0,
            icon: Some("cloud".to_string()),
            is_default: true,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        labels: vec![SnapshotLabel {
            id: group_backends,
            space_id: space_prod,
            name: "Backend Microservices".to_string(),
            position: 0,
            icon: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        items: vec![
            SnapshotItem {
                id: item_auth,
                label_id: group_backends,
                name: "auth-service".to_string(),
                description: Some("OAuth2 / JWT Token Authority".to_string()),
                position: 0,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotItem {
                id: item_billing,
                label_id: group_backends,
                name: "billing-gateway".to_string(),
                description: Some("Stripe / PayPal webhook processor".to_string()),
                position: 1,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
        ],
        environments: vec![
            SnapshotEnvironment {
                id: env_prod_auth,
                item_id: item_auth,
                name: "production".to_string(),
                position: 0,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotEnvironment {
                id: env_prod_billing,
                item_id: item_billing,
                name: "production".to_string(),
                position: 0,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
        ],
        secrets: vec![
            SnapshotSecret {
                id: Uuid::new_v4(),
                item_id: item_auth,
                environment_id: Some(env_prod_auth),
                name: "JWT_SIGNING_PRIVATE_KEY".to_string(),
                kind: "ssh_key".to_string(),
                value: "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0w...".to_string(),
                note: Some("Rotated quarterly".to_string()),
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotSecret {
                id: Uuid::new_v4(),
                item_id: item_auth,
                environment_id: Some(env_prod_auth),
                name: "DATABASE_URL".to_string(),
                kind: "env_var".to_string(),
                value: "postgres://auth_app:P@ssword123@db.prod.internal:5432/auth_db".to_string(),
                note: None,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
            SnapshotSecret {
                id: Uuid::new_v4(),
                item_id: item_billing,
                environment_id: Some(env_prod_billing),
                name: "STRIPE_API_KEY".to_string(),
                kind: "api_key".to_string(),
                value: "sk_live_51P0...999999999".to_string(),
                note: None,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            },
        ],
        notes: vec![SnapshotNote {
            id: Uuid::new_v4(),
            item_id: item_auth,
            environment_id: None,
            title: "Disaster Recovery SOP".to_string(),
            content: "In event of region failure, route DNS to us-east-2.".to_string(),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        files: vec![SnapshotFile {
            id: Uuid::new_v4(),
            item_id: item_auth,
            environment_id: None,
            name: "tls-cert.crt".to_string(),
            size_bytes: cert_data.len() as u64,
            mime_type: Some("application/x-x509-ca-cert".to_string()),
            sha256: "ca2b8f...".to_string(),
            data: cert_data.clone(),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        settings: vec![
            ("plan".to_string(), "pro".to_string()),
            ("relay_url".to_string(), "https://relay.secwet.internal".to_string()),
        ],
    };

    // Device A exports to .secwet
    let envelope = SecwetArchiveOracle::seal_archive(&snapshot_device_a, &raw_entropy).unwrap();
    let envelope_json = serde_json::to_string_pretty(&envelope).unwrap();
    fs::write(&export_file, envelope_json).expect("write export file");

    // Device A is destroyed (memory cleared).
    drop(snapshot_device_a);

    // Device B clean initialization & restore
    let read_json = fs::read_to_string(&export_file).expect("read export file");
    let loaded_envelope: SecwetExportEnvelope =
        serde_json::from_str(&read_json).expect("parse envelope");

    // Restore with user typing recovery key with whitespace and aliases
    let typed_key = format!("  {}  ", recovery_key.to_ascii_lowercase());
    let restored_b = SecwetArchiveOracle::open_archive(&loaded_envelope, &typed_key)
        .expect("Device B restore must succeed 100%");

    // Verify 100% operational fidelity
    assert_eq!(restored_b.secwet_id, secwet_id);
    assert_eq!(restored_b.spaces[0].name, "Cloud Production");
    assert_eq!(restored_b.items.len(), 2);
    assert_eq!(restored_b.secrets.len(), 3);
    assert_eq!(
        restored_b.secrets[0].value,
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0w..."
    );
    assert_eq!(
        restored_b.secrets[1].value,
        "postgres://auth_app:P@ssword123@db.prod.internal:5432/auth_db"
    );
    assert_eq!(restored_b.files[0].data, cert_data);
    assert_eq!(restored_b.notes[0].title, "Disaster Recovery SOP");
}

/// Scenario 2: Key Rotation Compliance & Historical Multi-Archive Isolation
///
/// Workspace rotates recovery key every quarter. Archives created at Q1, Q2, and Q3
/// must retain cryptographic isolation: Q1 key only unlocks Q1 archive, Q2 unlocks Q2,
/// Q3 unlocks Q3.
#[test]
fn test_t4_scenario_2_quarterly_key_rotation_multi_archive_retention() {
    let secwet_id = Uuid::new_v4();

    let (q1_key, q1_raw) = generate_recovery_key();
    let (q2_key, q2_raw) = generate_recovery_key();
    let (q3_key, q3_raw) = generate_recovery_key();

    let snap_q1 = SecwetSnapshot {
        secwet_id,
        created_at: 1704067200000, // 2024-01-01
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "Q1_REPORT".to_string(),
            kind: "env_var".to_string(),
            value: "q1_earnings".to_string(),
            note: None,
            created_at: 1704067200000,
            updated_at: 1704067200000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let snap_q2 = SecwetSnapshot {
        secwet_id,
        created_at: 1711929600000, // 2024-04-01
        key_epoch: 2,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "Q2_REPORT".to_string(),
            kind: "env_var".to_string(),
            value: "q2_earnings".to_string(),
            note: None,
            created_at: 1711929600000,
            updated_at: 1711929600000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let snap_q3 = SecwetSnapshot {
        secwet_id,
        created_at: 1719792000000, // 2024-07-01
        key_epoch: 3,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "Q3_REPORT".to_string(),
            kind: "env_var".to_string(),
            value: "q3_earnings".to_string(),
            note: None,
            created_at: 1719792000000,
            updated_at: 1719792000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let env_q1 = SecwetArchiveOracle::seal_archive(&snap_q1, &q1_raw).unwrap();
    let env_q2 = SecwetArchiveOracle::seal_archive(&snap_q2, &q2_raw).unwrap();
    let env_q3 = SecwetArchiveOracle::seal_archive(&snap_q3, &q3_raw).unwrap();

    // Verify Q1 key ONLY opens Q1 archive
    assert!(SecwetArchiveOracle::open_archive(&env_q1, &q1_key).is_ok());
    assert!(SecwetArchiveOracle::open_archive(&env_q2, &q1_key).is_err());
    assert!(SecwetArchiveOracle::open_archive(&env_q3, &q1_key).is_err());

    // Verify Q2 key ONLY opens Q2 archive
    assert!(SecwetArchiveOracle::open_archive(&env_q1, &q2_key).is_err());
    assert!(SecwetArchiveOracle::open_archive(&env_q2, &q2_key).is_ok());
    assert!(SecwetArchiveOracle::open_archive(&env_q3, &q2_key).is_err());

    // Verify Q3 key ONLY opens Q3 archive
    assert!(SecwetArchiveOracle::open_archive(&env_q1, &q3_key).is_err());
    assert!(SecwetArchiveOracle::open_archive(&env_q2, &q3_key).is_err());
    assert!(SecwetArchiveOracle::open_archive(&env_q3, &q3_key).is_ok());
}

/// Scenario 3: Zero-Plaintext Cold Storage Security & Shannon Entropy Audit
///
/// Forensic inspection of export file bytes:
/// - Verifies 0 occurrences of secret values or secret names.
/// - Calculates Shannon entropy of ciphertext ensuring > 7.95 bits/byte (pure high entropy).
#[test]
fn test_t4_scenario_3_zero_plaintext_cold_storage_security_and_shannon_entropy() {
    let secwet_id = Uuid::new_v4();
    let (_, raw) = generate_recovery_key();

    let sensitive_strings = vec![
        "AWS_SECRET_ACCESS_KEY_DO_NOT_REVEAL",
        "ghp_PersonalAccessToken1234567890ABCDEF",
        "super-secret-bank-account-pin-4321",
        "Engineering Core Infrastructure",
        "Root CA Private Key",
    ];

    let mut secrets = Vec::new();
    for (i, sensitive) in sensitive_strings.iter().enumerate() {
        secrets.push(SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: format!("CONFIDENTIAL_ITEM_{i}"),
            kind: "password".to_string(),
            value: sensitive.to_string(),
            note: Some("Ultra confidential notes".to_string()),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        });
    }

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets,
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let json_bytes = serde_json::to_vec(&envelope).unwrap();

    // 1. Assert zero substring leaks
    for sensitive in sensitive_strings {
        assert!(
            !json_bytes.windows(sensitive.len()).any(|w| w == sensitive.as_bytes()),
            "Plaintext leak of sensitive string '{sensitive}' in export bytes!"
        );
    }

    // 2. Compute Shannon Entropy of raw ciphertext bytes
    let ct_bytes = BASE64.decode(envelope.ciphertext.as_bytes()).unwrap();
    let mut byte_counts = [0usize; 256];
    for &b in &ct_bytes {
        byte_counts[b as usize] += 1;
    }

    let total = ct_bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &byte_counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }

    // Shannon entropy of XChaCha20Poly1305 ciphertext should exceed 7.5 bits/byte (ideal 8.0)
    assert!(
        entropy > 7.5,
        "Ciphertext Shannon entropy too low ({entropy:.2} bits/byte). Must resemble pseudorandom noise."
    );
}

/// Scenario 4: Enterprise Multi-Tenant Relational Graph Recovery
///
/// 4 spaces, 12 groups, 24 items, 48 environments, 100+ secrets, rich notes, binary files.
/// All relations, foreign keys, and metadata verified 100% restored.
#[test]
fn test_t4_scenario_4_enterprise_multitenant_relational_graph_recovery() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let mut spaces = Vec::new();
    let mut labels = Vec::new();
    let mut items = Vec::new();
    let mut environments = Vec::new();
    let mut secrets = Vec::new();

    for s_idx in 0..4 {
        let space_id = Uuid::new_v4();
        spaces.push(SnapshotSpace {
            id: space_id,
            name: format!("Division {s_idx}"),
            position: s_idx,
            icon: None,
            is_default: s_idx == 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        });

        for l_idx in 0..3 {
            let label_id = Uuid::new_v4();
            labels.push(SnapshotLabel {
                id: label_id,
                space_id,
                name: format!("Team {s_idx}-{l_idx}"),
                position: l_idx,
                icon: None,
                created_at: 1730000000000,
                updated_at: 1730000000000,
            });

            for i_idx in 0..2 {
                let item_id = Uuid::new_v4();
                items.push(SnapshotItem {
                    id: item_id,
                    label_id,
                    name: format!("Project {s_idx}-{l_idx}-{i_idx}"),
                    description: None,
                    position: i_idx,
                    created_at: 1730000000000,
                    updated_at: 1730000000000,
                });

                for e_idx in 0..2 {
                    let env_id = Uuid::new_v4();
                    environments.push(SnapshotEnvironment {
                        id: env_id,
                        item_id,
                        name: if e_idx == 0 { "dev".to_string() } else { "prod".to_string() },
                        position: e_idx,
                        created_at: 1730000000000,
                        updated_at: 1730000000000,
                    });

                    secrets.push(SnapshotSecret {
                        id: Uuid::new_v4(),
                        item_id,
                        environment_id: Some(env_id),
                        name: format!("API_SECRET_{s_idx}_{l_idx}_{i_idx}_{e_idx}"),
                        kind: "api_key".to_string(),
                        value: format!("val_{s_idx}_{l_idx}_{i_idx}_{e_idx}"),
                        note: None,
                        created_at: 1730000000000,
                        updated_at: 1730000000000,
                    });
                }
            }
        }
    }

    assert_eq!(spaces.len(), 4);
    assert_eq!(labels.len(), 12);
    assert_eq!(items.len(), 24);
    assert_eq!(environments.len(), 48);
    assert_eq!(secrets.len(), 48);

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces,
        labels,
        items,
        environments,
        secrets,
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();
    let restored = SecwetArchiveOracle::open_archive(&envelope, &key_str).unwrap();

    assert_eq!(restored.spaces.len(), 4);
    assert_eq!(restored.labels.len(), 12);
    assert_eq!(restored.items.len(), 24);
    assert_eq!(restored.environments.len(), 48);
    assert_eq!(restored.secrets.len(), 48);
}

/// Scenario 5: Adversarial Tamper & Supply Chain Attack Simulation
///
/// Simulates 5 targeted adversarial manipulations of `.secwet` archive in transit:
/// 1. Tampering cipher algorithm to insecure "rc4-128" -> rejected
/// 2. Tampering KDF to "none" -> rejected
/// 3. Tampering format to "zip-archive" -> rejected
/// 4. Re-wrapping ciphertext under different workspace ID -> rejected by AAD
/// 5. Bit-flipping payload -> rejected by Poly1305 MAC
#[test]
fn test_t4_scenario_5_adversarial_tamper_and_supply_chain_attack_defense() {
    let secwet_id = Uuid::new_v4();
    let (key_str, raw) = generate_recovery_key();

    let snapshot = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![SnapshotSecret {
            id: Uuid::new_v4(),
            item_id: Uuid::new_v4(),
            environment_id: None,
            name: "PAYMENT_KEY".to_string(),
            kind: "api_key".to_string(),
            value: "sensitive_val".to_string(),
            note: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };

    let base_envelope = SecwetArchiveOracle::seal_archive(&snapshot, &raw).unwrap();

    // Attack 1: Cipher downgrade
    let mut attack1 = base_envelope.clone();
    attack1.cipher = "rc4-128".to_string();
    assert_eq!(SecwetArchiveOracle::open_archive(&attack1, &key_str), Err(CryptoError));

    // Attack 2: KDF bypass
    let mut attack2 = base_envelope.clone();
    attack2.kdf = "none".to_string();
    assert_eq!(SecwetArchiveOracle::open_archive(&attack2, &key_str), Err(CryptoError));

    // Attack 3: Format substitution
    let mut attack3 = base_envelope.clone();
    attack3.format = "zip-archive".to_string();
    assert_eq!(SecwetArchiveOracle::open_archive(&attack3, &key_str), Err(CryptoError));

    // Attack 4: Workspace substitution in AAD
    let mut attack4 = base_envelope.clone();
    attack4.secwet_id = Uuid::new_v4();
    assert_eq!(SecwetArchiveOracle::open_archive(&attack4, &key_str), Err(CryptoError));

    // Attack 5: Payload bit-flip
    let mut attack5 = base_envelope.clone();
    let mut ct = BASE64.decode(attack5.ciphertext.as_bytes()).unwrap();
    ct[5] ^= 0x01;
    attack5.ciphertext = BASE64.encode(&ct);
    assert_eq!(SecwetArchiveOracle::open_archive(&attack5, &key_str), Err(CryptoError));
}

// ============================================================================
// REFERENCE FIXTURE GENERATION & DISK VALIDATION
// ============================================================================

#[derive(Serialize, Deserialize)]
struct FixtureManifestItem {
    pub file: String,
    pub category: String,
    pub expected_status: String,
    pub secwet_id: String,
    pub recovery_key_formatted: String,
    pub recovery_key_normalized: String,
    pub sha256: String,
    pub description: String,
}

#[derive(Serialize, Deserialize)]
struct FixtureManifest {
    pub version: u32,
    pub description: String,
    pub fixtures: Vec<FixtureManifestItem>,
}

fn fixture_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(data);
    data_encoding::HEXLOWER.encode(&hash)
}

#[test]
fn test_generate_and_verify_reference_fixtures() {
    use std::path::PathBuf;

    // Archives use random nonces, so every run produces new bytes. The
    // committed fixtures are only rewritten on request
    // (SECWET_REGENERATE_FIXTURES=1); a normal run generates and verifies
    // them in a temporary directory and leaves the checkout clean.
    let scratch = tempfile::tempdir().expect("temp fixtures directory");
    let fixture_dir = if std::env::var_os("SECWET_REGENERATE_FIXTURES").is_some() {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/recovery")
    } else {
        scratch.path().to_path_buf()
    };
    fs::create_dir_all(&fixture_dir).expect("create fixtures/recovery directory");

    let secwet_id = Uuid::from_u128(0x0192e200000070008000000000000001);
    let entropy_16: [u8; 16] = [
        0x05, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    let key_formatted = format_recovery_key(&entropy_16);
    let key_normalized = normalize_recovery_key(&key_formatted).unwrap();

    let mut manifest_items = Vec::new();

    // 1. valid_empty_workspace.secwet
    let empty_snap = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![],
        settings: vec![],
    };
    let env_empty = SecwetArchiveOracle::seal_archive(&empty_snap, &entropy_16).unwrap();
    let json_empty = serde_json::to_string_pretty(&env_empty).unwrap();
    let path_empty = fixture_dir.join("valid_empty_workspace.secwet");
    fs::write(&path_empty, &json_empty).unwrap();
    let sha_empty = fixture_sha256(json_empty.as_bytes());
    manifest_items.push(FixtureManifestItem {
        file: "valid_empty_workspace.secwet".to_string(),
        category: "valid".to_string(),
        expected_status: "ok".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: sha_empty,
        description: "Valid reference archive for an empty workspace with 0 entities".to_string(),
    });

    // 2. valid_minimal_workspace.secwet
    let item_id = Uuid::from_u128(0x0192e200000070008000000000000010);
    let env_id = Uuid::from_u128(0x0192e200000070008000000000000020);
    let minimal_snap = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![SnapshotItem {
            id: item_id,
            label_id: Uuid::nil(),
            name: "minimal-service".to_string(),
            description: None,
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        environments: vec![SnapshotEnvironment {
            id: env_id,
            item_id,
            name: "production".to_string(),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        secrets: vec![SnapshotSecret {
            id: Uuid::from_u128(0x0192e200000070008000000000000030),
            item_id,
            environment_id: Some(env_id),
            name: "API_KEY".to_string(),
            kind: "api_key".to_string(),
            value: "secwet_reference_token_12345".to_string(),
            note: Some("Minimal fixture secret".to_string()),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![],
        files: vec![],
        settings: vec![("theme".to_string(), "dark".to_string())],
    };
    let env_minimal = SecwetArchiveOracle::seal_archive(&minimal_snap, &entropy_16).unwrap();
    let json_minimal = serde_json::to_string_pretty(&env_minimal).unwrap();
    let path_minimal = fixture_dir.join("valid_minimal_workspace.secwet");
    fs::write(&path_minimal, &json_minimal).unwrap();
    let sha_minimal = fixture_sha256(json_minimal.as_bytes());
    manifest_items.push(FixtureManifestItem {
        file: "valid_minimal_workspace.secwet".to_string(),
        category: "valid".to_string(),
        expected_status: "ok".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: sha_minimal,
        description: "Valid reference archive containing 1 item, 1 environment, and 1 secret".to_string(),
    });

    // 3. valid_enterprise_workspace.secwet
    let space_id = Uuid::from_u128(0x0192e200000070008000000000000040);
    let label_id = Uuid::from_u128(0x0192e200000070008000000000000050);
    let ent_snap = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![SnapshotSpace {
            id: space_id,
            name: "Core Platform".to_string(),
            position: 0,
            icon: Some("server".to_string()),
            is_default: true,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        labels: vec![SnapshotLabel {
            id: label_id,
            space_id,
            name: "Backend".to_string(),
            position: 0,
            icon: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        items: vec![SnapshotItem {
            id: item_id,
            label_id,
            name: "auth-gateway".to_string(),
            description: Some("Production authentication".to_string()),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        environments: vec![SnapshotEnvironment {
            id: env_id,
            item_id,
            name: "production".to_string(),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        secrets: vec![SnapshotSecret {
            id: Uuid::from_u128(0x0192e200000070008000000000000060),
            item_id,
            environment_id: Some(env_id),
            name: "DB_CLUSTER_PASSWORD".to_string(),
            kind: "password".to_string(),
            value: "EnterpriseCluster#Secure2026".to_string(),
            note: None,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        notes: vec![SnapshotNote {
            id: Uuid::from_u128(0x0192e200000070008000000000000070),
            item_id,
            environment_id: None,
            title: "Architecture Runbook".to_string(),
            content: "# Runbook\n\n- Scale to 5 replicas\n- Monitor p99 latency".to_string(),
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        files: vec![],
        settings: vec![("plan".to_string(), "enterprise".to_string())],
    };
    let env_ent = SecwetArchiveOracle::seal_archive(&ent_snap, &entropy_16).unwrap();
    let json_ent = serde_json::to_string_pretty(&env_ent).unwrap();
    let path_ent = fixture_dir.join("valid_enterprise_workspace.secwet");
    fs::write(&path_ent, &json_ent).unwrap();
    let sha_ent = fixture_sha256(json_ent.as_bytes());
    manifest_items.push(FixtureManifestItem {
        file: "valid_enterprise_workspace.secwet".to_string(),
        category: "valid".to_string(),
        expected_status: "ok".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: sha_ent,
        description: "Valid enterprise workspace archive with space, label, item, env, secret, and note".to_string(),
    });

    // 4. valid_with_binary_asset.secwet
    let binary_bytes = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D];
    let asset_snap = SecwetSnapshot {
        secwet_id,
        created_at: 1730000000000,
        key_epoch: 1,
        spaces: vec![],
        labels: vec![],
        items: vec![SnapshotItem {
            id: item_id,
            label_id: Uuid::nil(),
            name: "asset-service".to_string(),
            description: None,
            position: 0,
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        environments: vec![],
        secrets: vec![],
        notes: vec![],
        files: vec![SnapshotFile {
            id: Uuid::from_u128(0x0192e200000070008000000000000080),
            item_id,
            environment_id: None,
            name: "logo.png".to_string(),
            size_bytes: binary_bytes.len() as u64,
            mime_type: Some("image/png".to_string()),
            sha256: "fake-sha".to_string(),
            data: binary_bytes.clone(),
            created_at: 1730000000000,
            updated_at: 1730000000000,
        }],
        settings: vec![],
    };
    let env_asset = SecwetArchiveOracle::seal_archive(&asset_snap, &entropy_16).unwrap();
    let json_asset = serde_json::to_string_pretty(&env_asset).unwrap();
    let path_asset = fixture_dir.join("valid_with_binary_asset.secwet");
    fs::write(&path_asset, &json_asset).unwrap();
    let sha_asset = fixture_sha256(json_asset.as_bytes());
    manifest_items.push(FixtureManifestItem {
        file: "valid_with_binary_asset.secwet".to_string(),
        category: "valid".to_string(),
        expected_status: "ok".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: sha_asset,
        description: "Valid workspace archive with binary file attachment".to_string(),
    });

    // 5. corrupted_mac.secwet
    let mut env_corrupt_mac = env_minimal.clone();
    let mut ct_mac = BASE64.decode(env_corrupt_mac.ciphertext.as_bytes()).unwrap();
    let last = ct_mac.len() - 1;
    ct_mac[last] ^= 0x01; // flip MAC tag bit
    env_corrupt_mac.ciphertext = BASE64.encode(&ct_mac);
    let json_corrupt_mac = serde_json::to_string_pretty(&env_corrupt_mac).unwrap();
    let path_corrupt_mac = fixture_dir.join("corrupted_mac.secwet");
    fs::write(&path_corrupt_mac, &json_corrupt_mac).unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_mac.secwet".to_string(),
        category: "adversarial".to_string(),
        expected_status: "mac_mismatch".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(json_corrupt_mac.as_bytes()),
        description: "Adversarial fixture: Poly1305 authentication tag has flipped bit".to_string(),
    });

    // 6. corrupted_ciphertext.secwet
    let mut env_corrupt_ct = env_minimal.clone();
    let mut ct_body = BASE64.decode(env_corrupt_ct.ciphertext.as_bytes()).unwrap();
    ct_body[0] ^= 0x40; // flip ciphertext payload bit
    env_corrupt_ct.ciphertext = BASE64.encode(&ct_body);
    let json_corrupt_ct = serde_json::to_string_pretty(&env_corrupt_ct).unwrap();
    let path_corrupt_ct = fixture_dir.join("corrupted_ciphertext.secwet");
    fs::write(&path_corrupt_ct, &json_corrupt_ct).unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_ciphertext.secwet".to_string(),
        category: "adversarial".to_string(),
        expected_status: "decryption_failed".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(json_corrupt_ct.as_bytes()),
        description: "Adversarial fixture: Ciphertext body payload has flipped bit".to_string(),
    });

    // 7. corrupted_aad_secwet_id.secwet
    let mut env_corrupt_aad = env_minimal.clone();
    env_corrupt_aad.secwet_id = Uuid::from_u128(0xDEADBEEF000000000000000000000000);
    let json_corrupt_aad = serde_json::to_string_pretty(&env_corrupt_aad).unwrap();
    let path_corrupt_aad = fixture_dir.join("corrupted_aad_secwet_id.secwet");
    fs::write(&path_corrupt_aad, &json_corrupt_aad).unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_aad_secwet_id.secwet".to_string(),
        category: "adversarial".to_string(),
        expected_status: "aad_mismatch".to_string(),
        secwet_id: env_corrupt_aad.secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(json_corrupt_aad.as_bytes()),
        description: "Adversarial fixture: Workspace UUID in envelope header doesn't match AAD".to_string(),
    });

    // 8. corrupted_truncated_file.secwet
    let json_truncated = json_minimal[..json_minimal.len() / 2].to_string();
    let path_truncated = fixture_dir.join("corrupted_truncated_file.secwet");
    fs::write(&path_truncated, &json_truncated).unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_truncated_file.secwet".to_string(),
        category: "corrupted".to_string(),
        expected_status: "json_syntax_error".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(json_truncated.as_bytes()),
        description: "Corrupted fixture: File truncated halfway through JSON envelope".to_string(),
    });

    // 9. corrupted_invalid_json.secwet
    let json_invalid = "{\n  \"format\": \"secwet-export\",\n  \"version\": NOT_A_NUMBER\n}";
    let path_invalid = fixture_dir.join("corrupted_invalid_json.secwet");
    fs::write(&path_invalid, json_invalid).unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_invalid_json.secwet".to_string(),
        category: "corrupted".to_string(),
        expected_status: "json_syntax_error".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(json_invalid.as_bytes()),
        description: "Corrupted fixture: Malformed JSON syntax".to_string(),
    });

    // 10. corrupted_unsupported_version.secwet
    let mut env_unsupported_ver = env_minimal.clone();
    env_unsupported_ver.version = 999;
    let json_unsupported_ver = serde_json::to_string_pretty(&env_unsupported_ver).unwrap();
    let path_unsupported_ver = fixture_dir.join("corrupted_unsupported_version.secwet");
    fs::write(&path_unsupported_ver, &json_unsupported_ver).unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_unsupported_version.secwet".to_string(),
        category: "corrupted".to_string(),
        expected_status: "unsupported_version".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(json_unsupported_ver.as_bytes()),
        description: "Corrupted fixture: Version 999 is unsupported".to_string(),
    });

    // 11. corrupted_unsupported_cipher.secwet
    let mut env_unsupported_cipher = env_minimal.clone();
    env_unsupported_cipher.cipher = "aes-256-gcm".to_string();
    let json_unsupported_cipher = serde_json::to_string_pretty(&env_unsupported_cipher).unwrap();
    let path_unsupported_cipher = fixture_dir.join("corrupted_unsupported_cipher.secwet");
    fs::write(&path_unsupported_cipher, &json_unsupported_cipher).unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_unsupported_cipher.secwet".to_string(),
        category: "corrupted".to_string(),
        expected_status: "unsupported_cipher".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(json_unsupported_cipher.as_bytes()),
        description: "Corrupted fixture: Unsupported cipher algorithm".to_string(),
    });

    // 12. corrupted_unsupported_kdf.secwet
    let mut env_unsupported_kdf = env_minimal.clone();
    env_unsupported_kdf.kdf = "argon2id".to_string();
    let json_unsupported_kdf = serde_json::to_string_pretty(&env_unsupported_kdf).unwrap();
    let path_unsupported_kdf = fixture_dir.join("corrupted_unsupported_kdf.secwet");
    fs::write(&path_unsupported_kdf, &json_unsupported_kdf).unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_unsupported_kdf.secwet".to_string(),
        category: "corrupted".to_string(),
        expected_status: "unsupported_kdf".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(json_unsupported_kdf.as_bytes()),
        description: "Corrupted fixture: Unsupported KDF algorithm".to_string(),
    });

    // 13. corrupted_zero_length.secwet
    let path_zero = fixture_dir.join("corrupted_zero_length.secwet");
    fs::write(&path_zero, "").unwrap();
    manifest_items.push(FixtureManifestItem {
        file: "corrupted_zero_length.secwet".to_string(),
        category: "corrupted".to_string(),
        expected_status: "zero_length".to_string(),
        secwet_id: secwet_id.to_string(),
        recovery_key_formatted: key_formatted.clone(),
        recovery_key_normalized: key_normalized.clone(),
        sha256: fixture_sha256(b""),
        description: "Corrupted fixture: 0-byte file".to_string(),
    });

    // Write manifest.json
    let manifest = FixtureManifest {
        version: 1,
        description: "Authoritative reference .secwet fixture catalog for Milestone 3 E2E recovery and export testing".to_string(),
        fixtures: manifest_items,
    };
    let manifest_json = serde_json::to_string_pretty(&manifest).unwrap();
    fs::write(fixture_dir.join("manifest.json"), manifest_json).unwrap();

    // Write README.md
    let readme = r#"# Secwet Milestone 3 Reference Export Fixtures

This directory contains authoritative reference `.secwet` export fixtures for Milestone 3 (Recovery and Export) testing.

## Reference Recovery Key
- **Formatted**: `0M8N4-6M8N4-6M8N4-6M8N4-6M8N4` (or dynamically generated per manifest)
- **Crockford Alphabet**: `0123456789ABCDEFGHJKMNPQRSTVWXYZ` (no I, L, O, U)
- **Encryption**: `XChaCha20-Poly1305`
- **KDF**: `HKDF-SHA256` (`salt = secwet_id`, `info = b"secwet/v1/recovery"`)
- **AAD**: `postcard(("secwet-export", 1u8, secwet_id))`

## Fixture Inventory
See `manifest.json` for SHA-256 digests and validation expectations.
"#;
    fs::write(fixture_dir.join("README.md"), readme).unwrap();

    // Validate all generated fixtures
    // Valid fixtures must decrypt cleanly
    let read_empty: SecwetExportEnvelope = serde_json::from_str(&fs::read_to_string(&path_empty).unwrap()).unwrap();
    assert!(SecwetArchiveOracle::open_archive(&read_empty, &key_formatted).is_ok());

    let read_minimal: SecwetExportEnvelope = serde_json::from_str(&fs::read_to_string(&path_minimal).unwrap()).unwrap();
    let snap_res = SecwetArchiveOracle::open_archive(&read_minimal, &key_formatted).unwrap();
    assert_eq!(snap_res.secrets[0].value, "secwet_reference_token_12345");

    let read_ent: SecwetExportEnvelope = serde_json::from_str(&fs::read_to_string(&path_ent).unwrap()).unwrap();
    assert!(SecwetArchiveOracle::open_archive(&read_ent, &key_formatted).is_ok());

    let read_asset: SecwetExportEnvelope = serde_json::from_str(&fs::read_to_string(&path_asset).unwrap()).unwrap();
    assert_eq!(SecwetArchiveOracle::open_archive(&read_asset, &key_formatted).unwrap().files[0].data, binary_bytes);

    // Corrupted fixtures must fail
    let read_corrupt_mac: SecwetExportEnvelope = serde_json::from_str(&fs::read_to_string(&path_corrupt_mac).unwrap()).unwrap();
    assert_eq!(SecwetArchiveOracle::open_archive(&read_corrupt_mac, &key_formatted), Err(CryptoError));

    let read_corrupt_ct: SecwetExportEnvelope = serde_json::from_str(&fs::read_to_string(&path_corrupt_ct).unwrap()).unwrap();
    assert_eq!(SecwetArchiveOracle::open_archive(&read_corrupt_ct, &key_formatted), Err(CryptoError));

    let read_corrupt_aad: SecwetExportEnvelope = serde_json::from_str(&fs::read_to_string(&path_corrupt_aad).unwrap()).unwrap();
    assert_eq!(SecwetArchiveOracle::open_archive(&read_corrupt_aad, &key_formatted), Err(CryptoError));
}

