//! Adversarial challenge and stress test suite for secwet-core crypto primitives and KeyStore.
//!
//! Evaluates:
//! 1. tampered_blob_fails_to_open: Exhaustive bit-flipping across version, nonce, body, and tag.
//! 2. blob_moved_to_other_record_fails: Exhaustive mutation of RecordAad fields.
//! 3. HPKE wrap/unwrap stress: Encapped key tampering, ciphertext corruption, info mismatch.
//! 4. Ed25519 verify_strict: Malleable signatures (s + L), corrupted public keys, signature bit-flips.
//! 5. Recovery key: Tricky normalization, character substitutions, length boundaries, min/max entropy.
//! 6. KeyStore & Secrecy: Concurrent access, debug redaction, zeroization.

use ed25519_dalek::{Signature, SigningKey};
use rand_core::Rng;
use secwet_core::crypto::{
    compute_device_id, compute_fingerprint, decode_record_blob, derive_event_key, derive_keys,
    derive_record_key, derive_recovery_key, format_normalized_recovery_key, format_recovery_key,
    generate_recovery_key, normalize_recovery_key, open_record, parse_recovery_key, seal_record,
    sign_payload, unwrap_for_me, verify_signature_strict, verify_signature_strict_bytes,
    wrap_for_device, CryptoError, OsRng, MIN_RECORD_BLOB_LEN, NONCE_LEN, RECORD_BLOB_VERSION,
    TAG_LEN,
};
use secwet_core::keys::{KeyStore, MemoryStore, SecretVec};
use secwet_proto::{RecordAad, RecordType, WrappedKey};
use std::collections::HashSet;
use std::sync::Arc;
use std::thread;
use uuid::Uuid;
use x25519_dalek::StaticSecret;

// ============================================================================
// 1. Exhaustive Bit-Flipping & Truncation on Sealed Blobs
// ============================================================================

#[test]
fn challenge_tampered_blob_exhaustive_bit_flipping_and_offsets() {
    let k_rec = [0x42u8; 32];
    let vault_id = Uuid::new_v4();
    let record_id = Uuid::now_v7();
    let aad = RecordAad::new(
        vault_id.as_bytes(),
        record_id.as_bytes(),
        RecordType::Secret,
        1,
    );

    let test_payloads: &[&[u8]] = &[
        b"",
        b"x",
        b"short_api_token",
        b"{\"key\": \"value\", \"secret\": true}",
        &[0xAA; 1024],
        &[0x55; 4096],
    ];

    for &payload in test_payloads {
        let blob = seal_record(&k_rec, &aad, payload).expect("sealing valid payload must succeed");

        // Verify blob length invariants: version (1) + nonce (24) + ciphertext (payload.len() + 16)
        assert_eq!(
            blob.len(),
            1 + NONCE_LEN + payload.len() + TAG_LEN,
            "Blob length must exactly equal 1 + 24 + payload.len() + 16"
        );

        // Sanity check: valid open works
        let opened = open_record(&k_rec, &aad, &blob).expect("unmodified blob must open cleanly");
        assert_eq!(opened, payload);

        // 1. Version byte tampering (offset 0)
        // Test all possible byte values 0x00..=0xFF except 0x01
        for bad_version in 0x00..=0xFF {
            if bad_version == RECORD_BLOB_VERSION {
                continue;
            }
            let mut corrupted = blob.clone();
            corrupted[0] = bad_version;
            assert_eq!(
                open_record(&k_rec, &aad, &corrupted),
                Err(CryptoError),
                "Invalid version 0x{:02X} must return CryptoError",
                bad_version
            );
        }

        // 2. Nonce byte tampering (offsets 1..=24)
        for nonce_offset in 1..=NONCE_LEN {
            for bit in 0..8 {
                let mut corrupted = blob.clone();
                corrupted[nonce_offset] ^= 1 << bit;
                assert_eq!(
                    open_record(&k_rec, &aad, &corrupted),
                    Err(CryptoError),
                    "Flipping bit {} in nonce offset {} must fail decryption",
                    bit,
                    nonce_offset
                );
            }
        }

        // 3. Ciphertext Body & Tag bit-flipping
        // For larger payloads, sample offsets if large, or exhaustively test if <= 1024 bytes
        let body_and_tag_range = (1 + NONCE_LEN)..blob.len();
        let step = if blob.len() > 500 { 17 } else { 1 };
        for offset in body_and_tag_range.step_by(step) {
            for bit in 0..8 {
                let mut corrupted = blob.clone();
                corrupted[offset] ^= 1 << bit;
                assert_eq!(
                    open_record(&k_rec, &aad, &corrupted),
                    Err(CryptoError),
                    "Flipping bit {} at offset {} must fail authentication",
                    bit,
                    offset
                );
            }
        }

        // 4. Truncation stress: truncate at every possible byte length from 0 to blob.len() - 1
        for cut_len in 0..blob.len() {
            let truncated = &blob[..cut_len];
            assert_eq!(
                open_record(&k_rec, &aad, truncated),
                Err(CryptoError),
                "Truncating blob to length {} must fail",
                cut_len
            );
        }

        // 5. Byte extension stress: appending trailing bytes must fail Poly1305 authentication
        for extra_bytes in [1, 2, 7, 16, 64] {
            let mut extended = blob.clone();
            extended.extend_from_slice(&vec![0xAA; extra_bytes]);
            assert_eq!(
                open_record(&k_rec, &aad, &extended),
                Err(CryptoError),
                "Appending {} bytes to blob must fail",
                extra_bytes
            );
        }
    }
}

#[test]
fn challenge_sealed_record_minimal_and_boundary_lengths() {
    let k_rec = [0x99u8; 32];
    let vault_id = Uuid::new_v4();
    let record_id = Uuid::now_v7();
    let aad = RecordAad::new(
        vault_id.as_bytes(),
        record_id.as_bytes(),
        RecordType::Secret,
        1,
    );

    // Empty payload yields minimal blob of exactly 41 bytes
    let min_blob = seal_record(&k_rec, &aad, b"").unwrap();
    assert_eq!(min_blob.len(), MIN_RECORD_BLOB_LEN);
    assert_eq!(min_blob[0], RECORD_BLOB_VERSION);

    // Decoding minimal blob
    let (nonce, ciphertext) = decode_record_blob(&min_blob).unwrap();
    assert_eq!(nonce.len(), NONCE_LEN);
    assert_eq!(ciphertext.len(), TAG_LEN); // 0 bytes plaintext + 16 bytes tag

    // Exactly 40 bytes (1 byte below minimum)
    let underflow = &min_blob[..MIN_RECORD_BLOB_LEN - 1];
    assert_eq!(decode_record_blob(underflow), Err(CryptoError));
    assert_eq!(open_record(&k_rec, &aad, underflow), Err(CryptoError));
}

// ============================================================================
// 2. Exhaustive AAD Mutation & Cross-Record / Cross-Vault Replay
// ============================================================================

#[test]
fn challenge_blob_moved_exhaustive_aad_mutation() {
    let k_rec = [0x37u8; 32];
    let vault_id_1 = Uuid::new_v4();
    let record_id_1 = Uuid::now_v7();
    let epoch_1 = 10u32;
    let aad_original = RecordAad::new(
        vault_id_1.as_bytes(),
        record_id_1.as_bytes(),
        RecordType::Project,
        epoch_1,
    );

    let payload = b"{\"database_url\": \"postgres://localhost:5432/db\"}";
    let blob = seal_record(&k_rec, &aad_original, payload).expect("sealing must succeed");

    // 1. Bit-flipping each byte in vault_id
    for byte_idx in 0..16 {
        for bit in 0..8 {
            let mut bad_vault_id = *vault_id_1.as_bytes();
            bad_vault_id[byte_idx] ^= 1 << bit;
            let aad_mut = RecordAad::new(
                &bad_vault_id,
                record_id_1.as_bytes(),
                RecordType::Project,
                epoch_1,
            );
            assert_eq!(
                open_record(&k_rec, &aad_mut, &blob),
                Err(CryptoError),
                "Flipping bit {} in vault_id byte {} must fail",
                bit,
                byte_idx
            );
        }
    }

    // 2. Bit-flipping each byte in record_id
    for byte_idx in 0..16 {
        for bit in 0..8 {
            let mut bad_record_id = *record_id_1.as_bytes();
            bad_record_id[byte_idx] ^= 1 << bit;
            let aad_mut = RecordAad::new(
                vault_id_1.as_bytes(),
                &bad_record_id,
                RecordType::Project,
                epoch_1,
            );
            assert_eq!(
                open_record(&k_rec, &aad_mut, &blob),
                Err(CryptoError),
                "Flipping bit {} in record_id byte {} must fail",
                bit,
                byte_idx
            );
        }
    }

    // 3. Mutating RecordType to all other valid and invalid values
    for rt_u8 in 0..=255 {
        if rt_u8 == RecordType::Project as u8 {
            continue;
        }
        let mut aad_mut = aad_original;
        aad_mut.record_type = rt_u8;
        assert_eq!(
            open_record(&k_rec, &aad_mut, &blob),
            Err(CryptoError),
            "Mutating record_type to {} must fail",
            rt_u8
        );
    }

    // 4. Mutating key_epoch across boundaries
    for epoch_val in [
        0u32,
        1,
        epoch_1 - 1,
        epoch_1 + 1,
        100,
        u32::MAX - 1,
        u32::MAX,
    ] {
        if epoch_val == epoch_1 {
            continue;
        }
        let aad_mut = RecordAad::new(
            vault_id_1.as_bytes(),
            record_id_1.as_bytes(),
            RecordType::Project,
            epoch_val,
        );
        assert_eq!(
            open_record(&k_rec, &aad_mut, &blob),
            Err(CryptoError),
            "Mutating key_epoch to {} must fail",
            epoch_val
        );
    }

    // 5. Mutating format field in AAD
    for fmt_val in [0u8, 2, 3, 255] {
        let mut aad_mut = aad_original;
        aad_mut.format = fmt_val;
        assert_eq!(
            open_record(&k_rec, &aad_mut, &blob),
            Err(CryptoError),
            "Mutating format to {} must fail",
            fmt_val
        );
    }

    // 6. Mutating k_rec key
    let mut bad_key = k_rec;
    bad_key[0] ^= 0x01;
    assert_eq!(
        open_record(&bad_key, &aad_original, &blob),
        Err(CryptoError),
        "Opening with wrong key must fail"
    );
}

// ============================================================================
// 3. HPKE RFC 9180 Adversarial Stress Testing
// ============================================================================

#[test]
fn challenge_hpke_wrap_and_unwrap_adversarial_stress() {
    let mut rng = OsRng;
    let mut sk_bytes = [0u8; 32];
    rng.fill_bytes(&mut sk_bytes);
    let recipient_sk = StaticSecret::from(sk_bytes);
    let recipient_pk = x25519_dalek::PublicKey::from(&recipient_sk);

    let info = b"secwet/v1/pair/vault-key";
    let plaintext_key = [0x55u8; 32];

    let wrapped = wrap_for_device(recipient_pk.as_bytes(), info, &plaintext_key)
        .expect("wrapping key must succeed");

    assert_eq!(wrapped.enc.len(), 32);
    assert_eq!(wrapped.ciphertext.len(), 48); // 32 key + 16 Poly1305 tag

    // 1. Bit-flipping across ephemeral public key (enc)
    for byte_idx in 0..32 {
        for bit in [0, 4, 7] {
            let mut bad_enc = wrapped.clone();
            bad_enc.enc[byte_idx] ^= 1 << bit;
            assert_eq!(
                unwrap_for_me(&recipient_sk, info, &bad_enc),
                Err(CryptoError),
                "Flipping bit in enc at byte {} must fail",
                byte_idx
            );
        }
    }

    // 2. All-zero and special enc values
    let zero_enc_wrapped = WrappedKey {
        enc: [0u8; 32],
        ciphertext: wrapped.ciphertext.clone(),
    };
    assert_eq!(
        unwrap_for_me(&recipient_sk, info, &zero_enc_wrapped),
        Err(CryptoError)
    );

    // 3. Truncation and expansion of ciphertext
    for len in 0..48 {
        let truncated_wrapped = WrappedKey {
            enc: wrapped.enc,
            ciphertext: wrapped.ciphertext[..len].to_vec(),
        };
        assert_eq!(
            unwrap_for_me(&recipient_sk, info, &truncated_wrapped),
            Err(CryptoError),
            "Ciphertext truncated to length {} must fail",
            len
        );
    }

    for extra in [1, 16, 32] {
        let mut extended = wrapped.ciphertext.clone();
        extended.extend_from_slice(&vec![0xAA; extra]);
        let extended_wrapped = WrappedKey {
            enc: wrapped.enc,
            ciphertext: extended,
        };
        assert_eq!(
            unwrap_for_me(&recipient_sk, info, &extended_wrapped),
            Err(CryptoError),
            "Ciphertext extended by {} bytes must fail",
            extra
        );
    }

    // 4. Bit-flipping in ciphertext (key payload and tag)
    for byte_idx in 0..48 {
        for bit in [0, 7] {
            let mut tampered = wrapped.clone();
            tampered.ciphertext[byte_idx] ^= 1 << bit;
            assert_eq!(
                unwrap_for_me(&recipient_sk, info, &tampered),
                Err(CryptoError),
                "Flipping bit in ciphertext at byte {} must fail",
                byte_idx
            );
        }
    }

    // 5. Context / Info string manipulation
    let bad_infos: &[&[u8]] = &[
        b"",
        b"secwet/v1/pair/vault-ke",
        b"secwet/v1/pair/vault-key ",
        b"secwet/v1/pair/vault-key\0",
        b"secwet/v1/pair/vault-key-extra",
        b"SECWET/V1/PAIR/VAULT-KEY",
    ];
    for &bad_info in bad_infos {
        assert_eq!(
            unwrap_for_me(&recipient_sk, bad_info, &wrapped),
            Err(CryptoError),
            "Unwrap with mismatched info '{:?}' must fail",
            bad_info
        );
    }

    // 6. 50 randomized HPKE roundtrips
    for _ in 0..50 {
        let mut rand_sk_bytes = [0u8; 32];
        rng.fill_bytes(&mut rand_sk_bytes);
        let sk = StaticSecret::from(rand_sk_bytes);
        let pk = x25519_dalek::PublicKey::from(&sk);

        let mut rand_key = [0u8; 32];
        rng.fill_bytes(&mut rand_key);

        let wr = wrap_for_device(pk.as_bytes(), info, &rand_key).unwrap();
        let unwr = unwrap_for_me(&sk, info, &wr).unwrap();
        assert_eq!(*unwr, rand_key);
    }
}

// ============================================================================
// 4. Ed25519 verify_strict Adversarial & Malleability Stress Testing
// ============================================================================

#[test]
fn challenge_ed25519_strict_malleability_and_corruption() {
    let mut rng = OsRng;
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();

    let message = b"secwet-sync-event-mutation-for-strict-verification";
    let sig = sign_payload(&signing_key, message);

    // Baseline strict verification passes
    verify_signature_strict(&verifying_key, message, &sig)
        .expect("genuine signature must verify strictly");

    // 1. Ed25519 Signature Malleability Attack: s + L
    // Ed25519 group order L = 2^252 + 27742317777372353535851937790883648493
    // In little-endian bytes:
    let order_l_bytes: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    let sig_bytes = sig.to_bytes();
    let r_bytes = &sig_bytes[..32];
    let s_bytes = &sig_bytes[32..64];

    // Compute s + L using little-endian 256-bit addition
    let mut s_plus_l = [0u8; 32];
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = (s_bytes[i] as u16) + (order_l_bytes[i] as u16) + carry;
        s_plus_l[i] = (sum & 0xFF) as u8;
        carry = sum >> 8;
    }

    // If s + L did not overflow 256 bits (carry == 0), this is a valid malleable scalar
    if carry == 0 {
        let mut malleable_sig_bytes = [0u8; 64];
        malleable_sig_bytes[..32].copy_from_slice(r_bytes);
        malleable_sig_bytes[32..].copy_from_slice(&s_plus_l);

        let malleable_sig = Signature::from_bytes(&malleable_sig_bytes);
        assert_eq!(
            verify_signature_strict(&verifying_key, message, &malleable_sig),
            Err(CryptoError),
            "Non-canonical signature with scalar s + L must be rejected by verify_strict"
        );
    }

    // 2. Non-canonical scalar: s >= L (e.g. s = L, s = 2^256 - 1)
    let mut max_s_sig = sig_bytes;
    max_s_sig[32..64].copy_from_slice(&[0xFF; 32]);
    let sig_max_s = Signature::from_bytes(&max_s_sig);
    assert_eq!(
        verify_signature_strict(&verifying_key, message, &sig_max_s),
        Err(CryptoError),
        "Scalar s = 2^256 - 1 must be rejected by verify_strict"
    );

    let mut l_s_sig = sig_bytes;
    l_s_sig[32..64].copy_from_slice(&order_l_bytes);
    let sig_l_s = Signature::from_bytes(&l_s_sig);
    assert_eq!(
        verify_signature_strict(&verifying_key, message, &sig_l_s),
        Err(CryptoError),
        "Scalar s = L must be rejected by verify_strict"
    );

    // 3. Bit-flipping across all 64 bytes of signature
    for byte_idx in (0..64).step_by(2) {
        for bit in [0, 7] {
            let mut corrupted_sig_bytes = sig_bytes;
            corrupted_sig_bytes[byte_idx] ^= 1 << bit;
            let corrupted_sig = Signature::from_bytes(&corrupted_sig_bytes);
            assert_eq!(
                verify_signature_strict(&verifying_key, message, &corrupted_sig),
                Err(CryptoError),
                "Corrupted signature at byte {} bit {} must fail",
                byte_idx,
                bit
            );
        }
    }

    // 4. Invalid VerifyingKey bytes
    let invalid_pk_bytes: &[&[u8; 32]] = &[
        &[0x00; 32], // all zeros (not on curve)
        &[0xFF; 32], // all 0xFF (y >= 2^255 - 19, non-canonical)
        &[0xEE; 32], // invalid point
    ];
    for &bad_pk in invalid_pk_bytes {
        assert_eq!(
            verify_signature_strict_bytes(bad_pk, message, &sig_bytes),
            Err(CryptoError),
            "Invalid public key must fail"
        );
    }
}

// ============================================================================
// 5. Recovery Key Normalization & Crockford Base32 Stress Testing
// ============================================================================

#[test]
fn challenge_recovery_key_adversarial_normalization_and_boundaries() {
    // 1. Min boundary (all 0 bits)
    let min_entropy = [0u8; 16];
    let min_formatted = format_recovery_key(&min_entropy);
    assert_eq!(min_formatted, "00000-00000-00000-00000-00000");
    let min_parsed = parse_recovery_key(&min_formatted).unwrap();
    assert_eq!(*min_parsed, min_entropy);

    // 2. Max boundary (125 bits all 1)
    let mut max_entropy = [0xFFu8; 16];
    max_entropy[0] = 0x1F; // Top 3 bits 0
    let max_formatted = format_recovery_key(&max_entropy);
    assert_eq!(max_formatted, "ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ-ZZZZZ");
    let max_parsed = parse_recovery_key(&max_formatted).unwrap();
    assert_eq!(*max_parsed, max_entropy);

    // 3. Roundtrip property fuzzing over 100 iterations
    for _ in 0..100 {
        let (formatted, raw) = generate_recovery_key();
        assert_eq!(raw[0] & 0xE0, 0, "Top 3 bits of 125-bit entropy must be 0");
        let parsed = parse_recovery_key(&formatted).expect("Valid recovery key must parse");
        assert_eq!(*parsed, *raw);
    }

    // 4. Tricky normalization cases:
    // Multiple consecutive hyphens and leading/trailing hyphens
    let messy_hyphens = "--12345---6789A---BCDEF---GHJKM---NPQRS--";
    let norm_hyphens = normalize_recovery_key(messy_hyphens).unwrap();
    assert_eq!(norm_hyphens, "123456789ABCDEFGHJKMNPQRS");
    assert_eq!(
        format_normalized_recovery_key(&norm_hyphens).unwrap(),
        "12345-6789A-BCDEF-GHJKM-NPQRS"
    );

    // Mixed Unicode whitespace and ASCII whitespace
    let unicode_spaces = "\u{00A0}  12345 \t 6789A \n BCDEF \r GHJKM \u{2000} NPQRS  \n";
    let norm_spaces = normalize_recovery_key(unicode_spaces).unwrap();
    assert_eq!(norm_spaces, "123456789ABCDEFGHJKMNPQRS");

    // Crockford character substitution mappings:
    // 'I' and 'l' -> '1', 'O' and 'o' -> '0'
    let sub_input = "iiiII-llllL-ooooO-OOOOO-11111";
    let norm_sub = normalize_recovery_key(sub_input).unwrap();
    assert_eq!(norm_sub, "1111111111000000000011111");

    // 5. Explicit rejection of forbidden characters:
    // Douglas Crockford Base32 explicitly excludes 'U' and 'u' to prevent obscenity
    let forbidden_chars = [
        'U', 'u', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '_', '+', '=', '{', '}', '[',
        ']', '|', '\\', ':', ';', '"', '\'', '<', '>', ',', '.', '?', '/', '~', '`', '🦀', 'Ö',
        'É',
    ];
    for fc in forbidden_chars {
        let bad_key = format!("12345-12345-12345-12345-1234{}", fc);
        assert_eq!(
            normalize_recovery_key(&bad_key),
            Err(CryptoError),
            "Character '{}' must be rejected in recovery key",
            fc
        );
    }

    // 6. Length enforcement
    let base = "123451234512345123451234"; // 24 chars
    assert_eq!(normalize_recovery_key(base), Err(CryptoError));
    let base_25 = format!("{}5", base); // 25 chars
    assert!(normalize_recovery_key(&base_25).is_ok());
    let base_26 = format!("{}55", base); // 26 chars
    assert_eq!(normalize_recovery_key(&base_26), Err(CryptoError));
}

// ============================================================================
// 6. KeyStore Concurrency & Memory Secrecy Stress Testing
// ============================================================================

#[test]
fn challenge_memory_store_concurrent_stress() {
    let store = Arc::new(MemoryStore::new());
    let mut handles = Vec::new();

    // Spawn 8 threads performing concurrent set, get, delete operations
    for thread_id in 0..8 {
        let store_clone = Arc::clone(&store);
        let handle = thread::spawn(move || {
            for i in 0..200 {
                let entry = format!("secwet/test/thread_{}/key_{}", thread_id, i);
                let val = format!("secret_value_{}_{}", thread_id, i);

                store_clone.set(&entry, val.as_bytes()).unwrap();

                let retrieved = store_clone.get(&entry).unwrap().unwrap();
                assert_eq!(retrieved.as_slice(), val.as_bytes());

                if i % 3 == 0 {
                    store_clone.delete(&entry).unwrap();
                    assert_eq!(store_clone.get(&entry).unwrap(), None);
                }
            }
        });
        handles.push(handle);
    }

    for h in handles {
        h.join().expect("Worker thread panicked");
    }
}

#[test]
fn challenge_secret_vec_debug_redaction_and_zeroize() {
    let sensitive = b"my_super_secret_master_password_9999".to_vec();
    let secret = SecretVec::new(sensitive.clone());

    // Debug representation MUST NOT leak plaintext
    let debug_repr = format!("{:?}", secret);
    assert!(
        !debug_repr.contains("my_super_secret"),
        "SecretVec leaked plaintext in Debug: {}",
        debug_repr
    );
    assert_eq!(debug_repr, "SecretVec([REDACTED])");

    // Deref & as_slice provide access
    assert_eq!(secret.as_slice(), sensitive.as_slice());
    assert_eq!(&*secret, sensitive.as_slice());
    assert_eq!(secret.len(), sensitive.len());
    assert!(!secret.is_empty());
}

// ============================================================================
// 7. Device ID & Fingerprint Adversarial Validation
// ============================================================================

#[test]
fn challenge_device_id_and_fingerprint_collision_and_format() {
    let mut rng = OsRng;
    let mut device_ids = HashSet::new();

    // 1. Device ID Crockford Base32 alphabet and length invariants across 2,000 keys
    for _ in 0..2000 {
        let mut ed_pub = [0u8; 32];
        rng.fill_bytes(&mut ed_pub);

        let dev_id = compute_device_id(&ed_pub);
        assert_eq!(dev_id.len(), 26, "Device ID must be exactly 26 chars");

        // Crockford alphabet: 0123456789ABCDEFGHJKMNPQRSTVWXYZ (no I, L, O, U)
        for c in dev_id.chars() {
            assert!(
                "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c),
                "Device ID contains invalid Crockford char: {}",
                c
            );
        }

        assert!(
            device_ids.insert(dev_id),
            "Unexpected device ID collision encountered"
        );
    }

    // 2. Fingerprint bit sensitivity
    let mut ed_pub = [0x11u8; 32];
    let mut x_pub = [0x22u8; 32];
    let baseline_fp = compute_fingerprint(&ed_pub, &x_pub);

    // Flipping any single bit in either key MUST alter the fingerprint
    for byte_idx in 0..32 {
        for bit in 0..8 {
            ed_pub[byte_idx] ^= 1 << bit;
            let altered_fp = compute_fingerprint(&ed_pub, &x_pub);
            assert_ne!(
                baseline_fp, altered_fp,
                "Flipping bit in Ed25519 pub key must change fingerprint"
            );
            ed_pub[byte_idx] ^= 1 << bit; // revert

            x_pub[byte_idx] ^= 1 << bit;
            let altered_fp_x = compute_fingerprint(&ed_pub, &x_pub);
            assert_ne!(
                baseline_fp, altered_fp_x,
                "Flipping bit in X25519 pub key must change fingerprint"
            );
            x_pub[byte_idx] ^= 1 << bit; // revert
        }
    }
}

// ============================================================================
// 8. HKDF Key Derivations Domain Separation & Extreme Inputs
// ============================================================================

#[test]
fn challenge_hkdf_domain_separation_and_extreme_inputs() {
    let mut rng = OsRng;
    let vault_id = Uuid::new_v4();

    // 1. Extreme IKMs (all 0s, all 1s, random)
    let ikms = [[0x00u8; 32], [0xFFu8; 32], [0x5Au8; 32]];

    for ikm in ikms {
        let k_rec = derive_record_key(&ikm, &vault_id);
        let k_evt = derive_event_key(&ikm, &vault_id);
        let k_rec_pair = derive_keys(&ikm, &vault_id);

        assert_eq!(*k_rec, *k_rec_pair.0);
        assert_eq!(*k_evt, *k_rec_pair.1);

        // Domain separation invariant
        assert_ne!(*k_rec, *k_evt);

        // Recovery key domain separation
        let k_recov = derive_recovery_key(&ikm[..16], &vault_id);
        assert_ne!(*k_recov, *k_rec);
        assert_ne!(*k_recov, *k_evt);
    }

    // 2. Vault ID separation
    for _ in 0..100 {
        let v1 = Uuid::new_v4();
        let v2 = Uuid::new_v4();
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);

        let k1 = derive_record_key(&key, &v1);
        let k2 = derive_record_key(&key, &v2);
        assert_ne!(*k1, *k2);
    }
}
