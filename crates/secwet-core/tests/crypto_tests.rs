use ed25519_dalek::SigningKey;
use rand_core::Rng;
use secwet_core::crypto::{
    compute_device_id, compute_fingerprint, decode_record_blob, derive_event_key, derive_keys,
    derive_record_key, derive_recovery_key, encode_record_blob, format_normalized_recovery_key,
    format_recovery_key, generate_recovery_key, normalize_recovery_key, open_record,
    open_record_parts, parse_recovery_key, seal_record, seal_record_parts, sign_payload,
    unwrap_for_me, verify_signature_strict, verify_signature_strict_bytes, wrap_for_device,
    CryptoError, OsRng,
};
use secwet_core::keys::{KeyStore, MemoryStore};
use secwet_proto::{RecordAad, RecordType};
use uuid::Uuid;
use x25519_dalek::StaticSecret;

// ============================================================================
// Acceptance Test 1: tampered_blob_fails_to_open
// ============================================================================

#[test]
fn tampered_blob_fails_to_open() {
    let k_rec = [42u8; 32];
    let secwet_id = Uuid::new_v4();
    let record_id = Uuid::now_v7();
    let aad = RecordAad::new(
        secwet_id.as_bytes(),
        record_id.as_bytes(),
        RecordType::Secret,
        1,
    );
    let plaintext = b"super_sensitive_api_token_value_999";

    // Seal the record
    let blob = seal_record(&k_rec, &aad, plaintext).expect("sealing valid payload must succeed");
    assert!(
        blob.len() >= 41,
        "blob must be at least 41 bytes (1 + 24 + 16)"
    );

    // Verify valid open works first
    let opened = open_record(&k_rec, &aad, &blob).expect("unmodified blob must open cleanly");
    assert_eq!(opened, plaintext);

    // Exhaustively flip every byte in the blob and ensure decryption strictly fails
    for i in 0..blob.len() {
        // Test single bit flip (LSB)
        let mut tampered_lsb = blob.clone();
        tampered_lsb[i] ^= 0x01;
        let res_lsb = open_record(&k_rec, &aad, &tampered_lsb);
        assert_eq!(
            res_lsb,
            Err(CryptoError),
            "Flipping LSB at byte {i} must return generic CryptoError"
        );

        // Test multi-bit flip (0xFF)
        let mut tampered_all = blob.clone();
        tampered_all[i] ^= 0xFF;
        let res_all = open_record(&k_rec, &aad, &tampered_all);
        assert_eq!(
            res_all,
            Err(CryptoError),
            "Flipping all bits at byte {i} must return generic CryptoError"
        );
    }

    // Truncated blob (less than 41 bytes)
    let truncated = &blob[..40];
    assert_eq!(
        open_record(&k_rec, &aad, truncated),
        Err(CryptoError),
        "Truncated blob must return generic CryptoError"
    );

    // Empty blob
    assert_eq!(
        open_record(&k_rec, &aad, &[]),
        Err(CryptoError),
        "Empty blob must return generic CryptoError"
    );

    // Unsupported version byte
    let mut bad_version = blob.clone();
    bad_version[0] = 0x02;
    assert_eq!(
        open_record(&k_rec, &aad, &bad_version),
        Err(CryptoError),
        "Unsupported version must return generic CryptoError"
    );
}

// ============================================================================
// Acceptance Test 2: blob_moved_to_other_record_fails
// ============================================================================

#[test]
fn blob_moved_to_other_record_fails() {
    let k_rec = [0x5Au8; 32];
    let secwet_id_1 = Uuid::new_v4();
    let record_id_1 = Uuid::now_v7();
    let epoch_1 = 1u32;
    let aad_1 = RecordAad::new(
        secwet_id_1.as_bytes(),
        record_id_1.as_bytes(),
        RecordType::Project,
        epoch_1,
    );
    let payload = b"{\"name\":\"Project Alpha\"}";

    let blob = seal_record(&k_rec, &aad_1, payload).expect("sealing must succeed");

    // 1. Same payload, but different record_id in AAD (e.g. copied to another record row)
    let record_id_2 = Uuid::now_v7();
    let aad_different_record = RecordAad::new(
        secwet_id_1.as_bytes(),
        record_id_2.as_bytes(),
        RecordType::Project,
        epoch_1,
    );
    assert_eq!(
        open_record(&k_rec, &aad_different_record, &blob),
        Err(CryptoError),
        "Opening with mismatched record_id must fail authentication"
    );

    // 2. Same payload, but different secwet_id in AAD (e.g. copied across secwets)
    let secwet_id_2 = Uuid::new_v4();
    let aad_different_secwet = RecordAad::new(
        secwet_id_2.as_bytes(),
        record_id_1.as_bytes(),
        RecordType::Project,
        epoch_1,
    );
    assert_eq!(
        open_record(&k_rec, &aad_different_secwet, &blob),
        Err(CryptoError),
        "Opening with mismatched secwet_id must fail authentication"
    );

    // 3. Same payload, but different record_type in AAD (type confusion: Project vs Environment)
    let aad_different_type = RecordAad::new(
        secwet_id_1.as_bytes(),
        record_id_1.as_bytes(),
        RecordType::Environment,
        epoch_1,
    );
    assert_eq!(
        open_record(&k_rec, &aad_different_type, &blob),
        Err(CryptoError),
        "Opening with mismatched record_type must fail authentication"
    );

    // 4. Same payload, but different key epoch in AAD (epoch mismatch)
    let aad_different_epoch = RecordAad::new(
        secwet_id_1.as_bytes(),
        record_id_1.as_bytes(),
        RecordType::Project,
        epoch_1 + 1,
    );
    assert_eq!(
        open_record(&k_rec, &aad_different_epoch, &blob),
        Err(CryptoError),
        "Opening with mismatched key_epoch must fail authentication"
    );

    // 5. Different format in AAD
    let mut aad_bad_format = aad_1;
    aad_bad_format.format = 2;
    assert_eq!(
        open_record(&k_rec, &aad_bad_format, &blob),
        Err(CryptoError),
        "Opening with mismatched format must fail authentication"
    );
}

// ============================================================================
// Sealing & Opening Roundtrip Tests
// ============================================================================

#[test]
fn test_sealing_and_opening_roundtrips() {
    let k_rec = [0x77u8; 32];
    let secwet_id = Uuid::new_v4();
    let record_id = Uuid::now_v7();
    let aad = RecordAad::new(
        secwet_id.as_bytes(),
        record_id.as_bytes(),
        RecordType::Secret,
        1,
    );

    // Empty payload
    let blob_empty = seal_record(&k_rec, &aad, b"").unwrap();
    let opened_empty = open_record(&k_rec, &aad, &blob_empty).unwrap();
    assert_eq!(opened_empty, b"");

    // Small payload
    let msg = b"database_password_123456789";
    let blob = seal_record(&k_rec, &aad, msg).unwrap();
    let opened = open_record(&k_rec, &aad, &blob).unwrap();
    assert_eq!(opened, msg);

    // 64 KiB multi-line payload
    let mut large = Vec::with_capacity(65_536);
    while large.len() < 65_536 {
        large.extend_from_slice(b"-----BEGIN CERTIFICATE-----\r\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\r\n-----END CERTIFICATE-----\r\n");
    }
    large.truncate(65_536);
    let blob_large = seal_record(&k_rec, &aad, &large).unwrap();
    let opened_large = open_record(&k_rec, &aad, &blob_large).unwrap();
    assert_eq!(opened_large, large);

    // Nonce uniqueness: sealing identical plaintext twice produces distinct ciphertexts
    let blob_1 = seal_record(&k_rec, &aad, msg).unwrap();
    let blob_2 = seal_record(&k_rec, &aad, msg).unwrap();
    assert_ne!(blob_1, blob_2);
    assert_ne!(&blob_1[1..25], &blob_2[1..25]); // Nonces differ

    // Parts helpers roundtrip
    let sealed_parts = seal_record_parts(&k_rec, &aad, msg).unwrap();
    let opened_parts = open_record_parts(&k_rec, &aad, &sealed_parts).unwrap();
    assert_eq!(opened_parts, msg);

    // Blob encode/decode roundtrip
    let encoded = encode_record_blob(&sealed_parts.nonce, &sealed_parts.ciphertext);
    let (decoded_nonce, decoded_cipher) = decode_record_blob(&encoded).unwrap();
    assert_eq!(decoded_nonce, sealed_parts.nonce);
    assert_eq!(decoded_cipher, sealed_parts.ciphertext.as_slice());
}

// ============================================================================
// HKDF Key Derivation & Domain Separation Tests
// ============================================================================

#[test]
fn test_hkdf_key_derivations_and_domain_separation() {
    let k_v = [0x11u8; 32];
    let secwet_id = Uuid::new_v4();

    let k_rec = derive_record_key(&k_v, &secwet_id);
    let k_evt = derive_event_key(&k_v, &secwet_id);
    let (k_rec_tuple, k_evt_tuple) = derive_keys(&k_v, &secwet_id);

    // Consistency
    assert_eq!(*k_rec, *k_rec_tuple);
    assert_eq!(*k_evt, *k_evt_tuple);

    // Domain separation: record key and event key derived from same k_v and secwet_id must differ
    assert_ne!(*k_rec, *k_evt);

    // Secwet separation: different secwet_id produces distinct keys
    let secwet_id_2 = Uuid::new_v4();
    let k_rec_secwet_2 = derive_record_key(&k_v, &secwet_id_2);
    let k_evt_secwet_2 = derive_event_key(&k_v, &secwet_id_2);
    assert_ne!(*k_rec, *k_rec_secwet_2);
    assert_ne!(*k_evt, *k_evt_secwet_2);

    // Recovery key derivation
    let recovery_secret = [0x99u8; 16];
    let k_recovery = derive_recovery_key(&recovery_secret, &secwet_id);
    assert_ne!(*k_recovery, *k_rec);
    assert_ne!(*k_recovery, *k_evt);

    // Wrong recovery secret produces different recovery key
    let k_recovery_diff = derive_recovery_key(&[0x98u8; 16], &secwet_id);
    assert_ne!(*k_recovery, *k_recovery_diff);
}

// ============================================================================
// HPKE RFC 9180 Wrap & Unwrap Tests
// ============================================================================

#[test]
fn test_hpke_wrap_and_unwrap_roundtrip() {
    // Generate recipient X25519 secret and public key
    let mut sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut sk_bytes);
    let recipient_sk = StaticSecret::from(sk_bytes);
    let recipient_pk = x25519_dalek::PublicKey::from(&recipient_sk);

    let info = b"secwet/v1/pair/master-key";
    let plaintext_key = [0x33u8; 32];

    // Wrap for device
    let wrapped = wrap_for_device(recipient_pk.as_bytes(), info, &plaintext_key)
        .expect("wrapping key for device must succeed");

    assert_eq!(wrapped.enc.len(), 32);
    assert_eq!(wrapped.ciphertext.len(), 32 + 16); // 32-byte key + 16-byte Poly1305 tag

    // Unwrap for recipient
    let unwrapped = unwrap_for_me(&recipient_sk, info, &wrapped)
        .expect("unwrapping key for device must succeed");
    assert_eq!(*unwrapped, plaintext_key);

    // Unwrap with mismatched info fails
    let bad_info = b"secwet/v1/wrong-info";
    assert_eq!(
        unwrap_for_me(&recipient_sk, bad_info, &wrapped),
        Err(CryptoError)
    );

    // Unwrap with wrong secret fails
    let mut wrong_sk_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut wrong_sk_bytes);
    let wrong_sk = StaticSecret::from(wrong_sk_bytes);
    assert_eq!(unwrap_for_me(&wrong_sk, info, &wrapped), Err(CryptoError));

    // Tampered ciphertext fails Poly1305 authentication
    let mut tampered_wrapped = wrapped.clone();
    tampered_wrapped.ciphertext[0] ^= 0x01;
    assert_eq!(
        unwrap_for_me(&recipient_sk, info, &tampered_wrapped),
        Err(CryptoError)
    );

    // Tampered ephemeral public key `enc` fails decapsulation
    let mut bad_enc = wrapped.clone();
    bad_enc.enc[0] ^= 0x01;
    assert_eq!(
        unwrap_for_me(&recipient_sk, info, &bad_enc),
        Err(CryptoError)
    );
}

// ============================================================================
// Ed25519 Signing & Strict Verification Tests
// ============================================================================

#[test]
fn test_ed25519_signing_and_strict_verification() {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let message = b"secwet-sync-event-v1-mutation-bytes";

    // Sign payload
    let sig = sign_payload(&signing_key, message);

    // Strict verification succeeds
    verify_signature_strict(&verifying_key, message, &sig).expect("signature must verify strictly");

    // Byte helper succeeds
    verify_signature_strict_bytes(verifying_key.as_bytes(), message, &sig.to_bytes())
        .expect("signature bytes must verify strictly");

    // Tampered message fails
    assert_eq!(
        verify_signature_strict(&verifying_key, b"different message", &sig),
        Err(CryptoError)
    );

    // Tampered signature fails
    let mut tampered_sig_bytes = sig.to_bytes();
    tampered_sig_bytes[0] ^= 0x01;
    let tampered_sig = ed25519_dalek::Signature::from_bytes(&tampered_sig_bytes);
    assert_eq!(
        verify_signature_strict(&verifying_key, message, &tampered_sig),
        Err(CryptoError)
    );

    // Verification against different key fails
    let mut seed2 = [0u8; 32];
    OsRng.fill_bytes(&mut seed2);
    let signing_key_2 = SigningKey::from_bytes(&seed2);
    let verifying_key_2 = signing_key_2.verifying_key();
    assert_eq!(
        verify_signature_strict(&verifying_key_2, message, &sig),
        Err(CryptoError)
    );
}

// ============================================================================
// Device ID & UI Key Fingerprint Tests
// ============================================================================

#[test]
fn test_device_id_and_fingerprint() {
    let ed25519_pub = [0x44u8; 32];
    let x25519_pub = [0x88u8; 32];

    // Device ID
    let device_id = compute_device_id(&ed25519_pub);
    assert_eq!(device_id.len(), 26, "device ID must be exactly 26 chars");
    assert!(
        device_id.chars().all(|c| c.is_ascii_alphanumeric()),
        "device ID must be alphanumeric Crockford base32"
    );

    // Deterministic check
    assert_eq!(device_id, compute_device_id(&ed25519_pub));

    // Different key produces different device ID
    let ed25519_pub_diff = [0x45u8; 32];
    assert_ne!(device_id, compute_device_id(&ed25519_pub_diff));

    // Fingerprint
    let fp = compute_fingerprint(&ed25519_pub, &x25519_pub);
    assert_eq!(
        fp.len(),
        14,
        "fingerprint length must be 14 (XXXX XXXX XXXX)"
    );

    let parts: Vec<&str> = fp.split(' ').collect();
    assert_eq!(parts.len(), 3, "fingerprint must contain 3 groups");
    for group in parts {
        assert_eq!(group.len(), 4, "each group must be 4 characters");
        assert!(
            group
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase()),
            "each char must be uppercase hex"
        );
    }

    // Deterministic check
    assert_eq!(fp, compute_fingerprint(&ed25519_pub, &x25519_pub));

    // Different keys produce different fingerprints
    assert_ne!(fp, compute_fingerprint(&ed25519_pub_diff, &x25519_pub));
}

// ============================================================================
// Recovery Key Generation & Normalization Tests
// ============================================================================

#[test]
fn test_recovery_key_format_and_normalization() {
    // Generation
    let (formatted, raw) = generate_recovery_key();

    // Check format: XXXXX-XXXXX-XXXXX-XXXXX-XXXXX (29 chars)
    assert_eq!(formatted.len(), 29);
    let groups: Vec<&str> = formatted.split('-').collect();
    assert_eq!(groups.len(), 5);
    for group in &groups {
        assert_eq!(group.len(), 5);
    }

    // Parse back
    let parsed = parse_recovery_key(&formatted).expect("parsing formatted key must succeed");
    assert_eq!(*parsed, *raw);

    // Normalization rules:
    // 1. Lowercase letters
    let lower = formatted.to_ascii_lowercase();
    let parsed_lower = parse_recovery_key(&lower).expect("lowercase must parse cleanly");
    assert_eq!(*parsed_lower, *raw);

    // 2. Spaces instead of dashes
    let spaces = formatted.replace('-', " ");
    let parsed_spaces = parse_recovery_key(&spaces).expect("spaces must parse cleanly");
    assert_eq!(*parsed_spaces, *raw);

    // 3. Leading and trailing whitespace
    let messy = format!("   {}   \n", formatted);
    let parsed_messy = parse_recovery_key(&messy).expect("padded whitespace must parse cleanly");
    assert_eq!(*parsed_messy, *raw);

    // 4. Character substitutions: I, L -> 1 and O -> 0
    let with_ilo = "IIIII-LLLLL-OOOOO-00000-11111";
    let normalized = normalize_recovery_key(with_ilo).expect("substitution must succeed");
    assert_eq!(normalized, "1111111111000000000011111");

    let formatted_normalized = format_normalized_recovery_key(&normalized).unwrap();
    assert_eq!(formatted_normalized, "11111-11111-00000-00000-11111");

    // 5. Length verification: too short
    assert_eq!(
        normalize_recovery_key("12345-12345-12345-12345"),
        Err(CryptoError)
    );

    // 6. Length verification: too long
    assert_eq!(
        normalize_recovery_key("12345-12345-12345-12345-12345-1"),
        Err(CryptoError)
    );

    // 7. Invalid characters (e.g. U is excluded in Crockford Base32)
    assert_eq!(
        normalize_recovery_key("UUUUU-12345-12345-12345-12345"),
        Err(CryptoError)
    );

    // 8. Custom format_recovery_key roundtrip
    let custom_entropy = [
        0x1Fu8, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99,
    ];
    let custom_str = format_recovery_key(&custom_entropy);
    let custom_parsed = parse_recovery_key(&custom_str).unwrap();
    assert_eq!(*custom_parsed, custom_entropy);
}

// ============================================================================
// KeyStore Trait & MemoryStore Tests
// ============================================================================

#[test]
fn test_memory_keystore() {
    use secrecy::ExposeSecret;

    let store = MemoryStore::new();

    let entry = "secwet/test-secwet/device-sign";
    let value = b"super-secret-signing-seed-material";

    // Initially absent
    assert_eq!(store.get(entry).unwrap(), None);

    // Set
    store.set(entry, value).expect("set must succeed");

    // Get
    let retrieved = store.get(entry).unwrap().expect("must find stored item");
    assert_eq!(retrieved.expose_secret(), value);
    assert_eq!(retrieved.as_slice(), value);

    // Delete
    store.delete(entry).expect("delete must succeed");
    assert_eq!(store.get(entry).unwrap(), None);

    // Repeated delete is idempotent
    store.delete(entry).expect("repeated delete must succeed");
}
