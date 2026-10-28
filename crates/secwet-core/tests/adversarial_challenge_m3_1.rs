//! Empirical Adversarial Verification Suite for Milestone M3-1:
//! Core Cryptography, Recovery Key Lifecycle, and Encrypted Export/Restore.
//!
//! Mandatory Verification Invariants:
//! 1. Envelope corruption: tampered JSON, ciphertext, nonce, tag, AAD, or metadata fields
//!    MUST cause `restore_from_export` to fail cleanly with `Error::RecoveryFailed` and ZERO database corruption.
//! 2. Wrong recovery keys: off-by-one characters at all positions, transposed characters,
//!    prohibited Crockford characters ('U'), symbols, emojis, and length anomalies MUST be rejected atomically.
//! 3. Zero plaintext leakage: exported `.secwet` archives MUST contain zero plaintext strings of secrets,
//!    notes, file payloads, or entity names, and ciphertext must exhibit high Shannon entropy (>7.95 bits/byte).

use secrecy::{ExposeSecret, SecretString};
use secwet_core::crypto::{self, OsRng};
use secwet_core::keys::MemoryStore;
use secwet_core::model::{SecwetExportEnvelope, SecretDraft, SecretKind};
use secwet_core::{Error, KeyStore, Secwet};
use rand_core::Rng;
use tempfile::tempdir;
use uuid::Uuid;

/// Helper to create and populate a rich workspace with sensitive data.
fn create_test_workspace_and_export() -> (
    tempfile::TempDir,
    tempfile::TempDir,
    SecretString,
    std::path::PathBuf,
    Uuid,
    Vec<String>,
) {
    let dir_orig = tempdir().expect("tempdir orig");
    let dir_export = tempdir().expect("tempdir export");
    let keystore = MemoryStore::new();

    let mut secwet =
        Secwet::create(dir_orig.path(), "adversarial-laptop", &keystore).expect("create secwet");
    let secwet_id = secwet.secwet_id();

    // Populate spaces, labels, items, environments
    let space = secwet
        .create_space("Production Infrastructure", Some("cloud".to_string()))
        .expect("create space");
    let label = secwet
        .create_label_in_space("Core Services", Some("server".to_string()), Some(space.id))
        .expect("create label");
    let item = secwet
        .create_item(
            label.id,
            "Auth Microservice",
            Some("OAuth2 & OpenID Connect provider".to_string()),
        )
        .expect("create item");
    let env_prod = secwet
        .add_environment(item.id, "Production")
        .expect("add env prod");
    let env_stage = secwet
        .add_environment(item.id, "Staging")
        .expect("add env stage");

    // Populate secrets with distinctive markers
    let secrets = vec![
        "SUPER_CONFIDENTIAL_DB_PASSWORD_XYZZY_998877",
        "ghp_ADVERSARIAL_GITHUB_PAT_TOKEN_1122334455",
        "AKIA_AWS_ACCESS_KEY_ADVERSARIAL_CHALLENGE_99",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Y8v+KxV5XWvjXhPZ3Q1b1m2n3p4q5r6s7t8u9v0w1x2y3z4\n-----END RSA PRIVATE KEY-----",
    ];

    secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(env_prod.id),
            "DATABASE_PASSWORD",
            SecretKind::Password,
            secrets[0],
            Some("Primary PostgreSQL password".to_string()),
        ))
        .expect("create secret 0");

    secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(env_prod.id),
            "GITHUB_PAT",
            SecretKind::AccessToken,
            secrets[1],
            Some("Deployment GitHub PAT".to_string()),
        ))
        .expect("create secret 1");

    secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(env_stage.id),
            "AWS_SECRET",
            SecretKind::ApiKey,
            secrets[2],
            Some("Staging AWS key".to_string()),
        ))
        .expect("create secret 2");

    secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "JWT_SIGNING_KEY",
            SecretKind::Certificate,
            secrets[3],
            Some("Item level global certificate".to_string()),
        ))
        .expect("create secret 3");

    // Rich-text note
    let note_content = "# Disaster Recovery Plan\n\n1. Rotate credentials\n2. Notify security team\n3. Restore from .secwet snapshot";
    secwet
        .create_note(
            item.id,
            Some(env_prod.id),
            "Disaster Recovery Runbook",
            note_content,
        )
        .expect("create note");

    // File payload
    let mut file_payload = vec![0u8; 8192];
    OsRng.fill_bytes(&mut file_payload);
    secwet
        .upload_file(
            item.id,
            Some(env_prod.id),
            "cluster_config.bin",
            &file_payload,
            Some("application/octet-stream"),
        )
        .expect("upload file");

    let recovery_key = secwet
        .create_recovery_key(&keystore)
        .expect("create recovery key");

    let export_path = dir_export.path().join("backup.secwet");
    secwet
        .export_encrypted(&recovery_key, &export_path)
        .expect("export encrypted");

    let mut leak_markers = Vec::new();
    for s in &secrets {
        leak_markers.push(s.to_string());
    }
    leak_markers.push(note_content.to_string());
    leak_markers.push("Production Infrastructure".to_string());
    leak_markers.push("Auth Microservice".to_string());
    leak_markers.push("Primary PostgreSQL password".to_string());
    leak_markers.push("cluster_config.bin".to_string());

    secwet.lock();

    (
        dir_orig,
        dir_export,
        recovery_key,
        export_path,
        secwet_id,
        leak_markers,
    )
}

// ============================================================================
// 1. Envelope Tampering & Atomic Rollback Tests
// ============================================================================

#[test]
fn test_adversarial_envelope_corruption_and_atomicity() {
    let (_dir_orig, _dir_export, recovery_key, export_path, secwet_id, _markers) =
        create_test_workspace_and_export();

    let valid_envelope_bytes = std::fs::read(&export_path).expect("read export");
    let valid_envelope: SecwetExportEnvelope =
        serde_json::from_slice(&valid_envelope_bytes).expect("parse envelope");

    let raw_nonce = data_encoding::BASE64
        .decode(valid_envelope.nonce.as_bytes())
        .expect("decode nonce");
    let raw_ciphertext = data_encoding::BASE64
        .decode(valid_envelope.ciphertext.as_bytes())
        .expect("decode ciphertext");

    let test_restore_rejection = |tampered_json: &[u8], scenario: &str| {
        let dir_target = tempdir().expect("tempdir target");
        let tampered_file = dir_target.path().join("tampered.secwet");
        std::fs::write(&tampered_file, tampered_json).expect("write tampered");

        let keystore = MemoryStore::new();
        let result = Secwet::restore_from_export(
            dir_target.path(),
            &tampered_file,
            &recovery_key,
            "target-device",
            &keystore,
        );

        assert!(
            result.is_err(),
            "Scenario [{}] MUST fail restore, but succeeded!",
            scenario
        );
        match result.unwrap_err() {
            Error::RecoveryFailed => {}
            other => panic!(
                "Scenario [{}] expected Error::RecoveryFailed, got {:?}",
                scenario, other
            ),
        }

        // ATOMICITY: No database file or directory should be created or left behind!
        let db_path = dir_target
            .path()
            .join("secwet")
            .join(secwet_id.to_string())
            .join("secwet.sqlite3");
        assert!(
            !db_path.exists(),
            "Scenario [{}] violated atomicity: database file exists at {:?}",
            scenario,
            db_path
        );

        // Keystore must remain empty (no leaked master keys or device identities)
        assert!(
            keystore.get(&format!("secwet/{}/device-sign", secwet_id)).unwrap().is_none(),
            "Scenario [{}] leaked device keys into keystore on failure",
            scenario
        );
        assert!(
            keystore.get(&format!("secwet/{}/master-key/2", secwet_id)).unwrap().is_none(),
            "Scenario [{}] leaked master key into keystore on failure",
            scenario
        );
    };

    // Attack 1.1: Malformed JSON syntax (truncated JSON)
    let truncated_json = &valid_envelope_bytes[..valid_envelope_bytes.len() / 2];
    test_restore_rejection(truncated_json, "truncated JSON syntax");

    // Attack 1.2: Random garbage bytes
    test_restore_rejection(b"THIS_IS_NOT_A_VALID_JSON_PAYLOAD_AT_ALL", "raw garbage bytes");

    // Attack 1.3: Empty 0-byte file
    test_restore_rejection(b"", "empty 0-byte envelope");

    // Attack 1.4: Invalid envelope format field
    {
        let mut tampered = valid_envelope.clone();
        tampered.format = "secwet-tampered-format".to_string();
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, "invalid format identifier");
    }

    // Attack 1.5: Unsupported version (version = 2, 0, 999)
    for bad_ver in [0, 2, 999] {
        let mut tampered = valid_envelope.clone();
        tampered.version = bad_ver;
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, &format!("unsupported version {}", bad_ver));
    }

    // Attack 1.6: Downgraded/invalid KDF algorithm
    for bad_kdf in ["none", "scrypt", "argon2id", "pbkdf2", ""] {
        let mut tampered = valid_envelope.clone();
        tampered.kdf = bad_kdf.to_string();
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, &format!("invalid KDF '{}'", bad_kdf));
    }

    // Attack 1.7: Downgraded/invalid cipher algorithm
    for bad_cipher in ["aes-256-gcm", "plaintext", "none", "chacha20", ""] {
        let mut tampered = valid_envelope.clone();
        tampered.cipher = bad_cipher.to_string();
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, &format!("invalid cipher '{}'", bad_cipher));
    }

    // Attack 1.8: Nonce length != 24 bytes
    for bad_nonce_len in [0, 8, 12, 16, 23, 25, 32, 64] {
        let mut tampered = valid_envelope.clone();
        let bad_nonce = vec![0x42u8; bad_nonce_len];
        tampered.nonce = data_encoding::BASE64.encode(&bad_nonce);
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, &format!("nonce length {}", bad_nonce_len));
    }

    // Attack 1.9: Nonce invalid base64
    {
        let mut tampered = valid_envelope.clone();
        tampered.nonce = "!@#NOT_VALID_BASE64#@!".to_string();
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, "nonce invalid base64");
    }

    // Attack 1.10: Single bit flip in Nonce (test across all 24 bytes)
    for i in 0..24 {
        let mut corrupted_nonce = raw_nonce.clone();
        corrupted_nonce[i] ^= 0x01; // flip lowest bit
        let mut tampered = valid_envelope.clone();
        tampered.nonce = data_encoding::BASE64.encode(&corrupted_nonce);
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, &format!("nonce bit flip at byte {}", i));
    }

    // Attack 1.11: Ciphertext invalid base64
    {
        let mut tampered = valid_envelope.clone();
        tampered.ciphertext = "===NOT_VALID_BASE64_CIPHERTEXT===".to_string();
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, "ciphertext invalid base64");
    }

    // Attack 1.12: Truncated ciphertext (< 16-byte Poly1305 tag)
    for bad_ct_len in [0, 1, 8, 15] {
        let mut tampered = valid_envelope.clone();
        let bad_ct = vec![0xAAu8; bad_ct_len];
        tampered.ciphertext = data_encoding::BASE64.encode(&bad_ct);
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, &format!("ciphertext truncated to {} bytes", bad_ct_len));
    }

    // Attack 1.13: Bit flip in ciphertext body (start, 25%, 50%, 75%)
    let ct_len = raw_ciphertext.len();
    assert!(ct_len > 32);
    for pos in [0, ct_len / 4, ct_len / 2, (ct_len * 3) / 4] {
        let mut corrupted_ct = raw_ciphertext.clone();
        corrupted_ct[pos] ^= 0x80; // flip highest bit
        let mut tampered = valid_envelope.clone();
        tampered.ciphertext = data_encoding::BASE64.encode(&corrupted_ct);
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, &format!("ciphertext body bit flip at byte {}", pos));
    }

    // Attack 1.14: Bit flip in Poly1305 MAC tag (last 16 bytes)
    for tag_idx in 0..16 {
        let pos = ct_len - 16 + tag_idx;
        let mut corrupted_ct = raw_ciphertext.clone();
        corrupted_ct[pos] ^= 0x01;
        let mut tampered = valid_envelope.clone();
        tampered.ciphertext = data_encoding::BASE64.encode(&corrupted_ct);
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, &format!("Poly1305 MAC tag bit flip at offset {}", tag_idx));
    }

    // Attack 1.15: AAD Tampering - Workspace UUID substitution in envelope header
    {
        let mut tampered = valid_envelope.clone();
        tampered.secwet_id = Uuid::new_v4(); // different UUID
        let json = serde_json::to_vec(&tampered).unwrap();
        test_restore_rejection(&json, "AAD workspace UUID substitution attack");
    }
}

// ============================================================================
// 2. Wrong Recovery Keys & Fuzzing
// ============================================================================

#[test]
fn test_adversarial_wrong_recovery_keys_and_fuzzing() {
    let (_dir_orig, _dir_export, recovery_key, export_path, secwet_id, _markers) =
        create_test_workspace_and_export();

    let key_str = recovery_key.expose_secret();
    let normalized = crypto::normalize_recovery_key(key_str).expect("normalize valid key");
    assert_eq!(normalized.len(), 25);

    // Crockford characters table
    let crockford_chars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".chars().collect::<Vec<_>>();

    // 2.1: Systematic Off-By-One Mutation at Every Single Character Position (0..25)
    for pos in 0..25 {
        let orig_char = normalized.chars().nth(pos).unwrap();
        // Pick a replacement crockford character that is different
        let mut mutated_chars: Vec<char> = normalized.chars().collect();
        let replacement = crockford_chars
            .iter()
            .find(|&&c| c != orig_char)
            .copied()
            .unwrap();
        mutated_chars[pos] = replacement;
        let mutated_str: String = mutated_chars.into_iter().collect();

        // 1. verify_recovery_key on Secwet instance MUST reject (return Ok(false))
        let dir_orig = tempdir().expect("tempdir");
        let ks = MemoryStore::new();
        let mut secwet = Secwet::create(dir_orig.path(), "test", &ks).expect("create");
        let _k = secwet.create_recovery_key(&ks).expect("create key");
        assert!(
            !secwet.verify_recovery_key(&mutated_str).unwrap(),
            "verify_recovery_key accepted mutated key at pos {}: {}",
            pos,
            mutated_str
        );

        // 2. restore_from_export with mutated key MUST fail atomically
        let dir_target = tempdir().expect("tempdir");
        let keystore = MemoryStore::new();
        let restore_res = Secwet::restore_from_export(
            dir_target.path(),
            &export_path,
            &SecretString::from(mutated_str.clone()),
            "dev",
            &keystore,
        );

        assert!(
            restore_res.is_err(),
            "restore_from_export must reject mutated key at pos {}: {}",
            pos,
            mutated_str
        );
        match restore_res.unwrap_err() {
            Error::RecoveryFailed => {}
            other => panic!("Expected RecoveryFailed for mutated key, got {:?}", other),
        }

        // Verify zero database file created
        let db_path = dir_target
            .path()
            .join("secwet")
            .join(secwet_id.to_string())
            .join("secwet.sqlite3");
        assert!(!db_path.exists());
    }

    // 2.2: Transposed Adjacent Characters Mutation across all positions (0..24)
    for pos in 0..24 {
        let chars: Vec<char> = normalized.chars().collect();
        if chars[pos] == chars[pos + 1] {
            continue; // Skip if adjacent characters are identical
        }
        let mut transposed_chars = chars.clone();
        transposed_chars.swap(pos, pos + 1);
        let transposed_str: String = transposed_chars.into_iter().collect();

        let dir_target = tempdir().expect("tempdir");
        let keystore = MemoryStore::new();
        let restore_res = Secwet::restore_from_export(
            dir_target.path(),
            &export_path,
            &SecretString::from(transposed_str.clone()),
            "dev",
            &keystore,
        );

        assert!(
            restore_res.is_err(),
            "restore_from_export must reject transposed key at ({}, {}): {}",
            pos,
            pos + 1,
            transposed_str
        );
        assert!(!dir_target.path().join("secwet").exists());
    }

    // 2.3: Prohibited Crockford Character 'U' / 'u'
    for u_char in ['U', 'u'] {
        let mut chars: Vec<char> = normalized.chars().collect();
        chars[12] = u_char;
        let key_with_u: String = chars.into_iter().collect();

        let dir_target = tempdir().expect("tempdir");
        let keystore = MemoryStore::new();
        let restore_res = Secwet::restore_from_export(
            dir_target.path(),
            &export_path,
            &SecretString::from(key_with_u),
            "dev",
            &keystore,
        );
        assert!(matches!(restore_res, Err(Error::RecoveryFailed)));
    }

    // 2.4: Special Symbols, Punctuation, and Emojis
    let long_string = "X".repeat(10_000);
    let adversarial_strings = vec![
        "!@#$%^&*()-+=_{}[]|:;<>?,./~`",
        "A1B2C-D3E4F-G5H6J-K7M8N-P9Q0!", // symbol at end
        "@1B2C-D3E4F-G5H6J-K7M8N-P9Q0R", // symbol at start
        "A1B2C-D3E4F-🦀🦀🦀-K7M8N-P9Q0R", // emoji in middle
        "A1B2C\0D3E4FG5H6JK7M8NP9Q0R",   // null byte
        "A1B2C\u{200B}D3E4FG5H6JK7M8NP9Q0R", // zero-width space
        "",                              // empty string
        "A",                             // 1 char
        "A1B2C-D3E4F-G5H6J-K7M8N-P9Q0",  // 24 chars (1 char too short)
        "A1B2C-D3E4F-G5H6J-K7M8N-P9Q0RR", // 26 chars (1 char too long)
        &long_string,                    // 10,000 characters
    ];

    for adv_input in adversarial_strings {
        let dir_target = tempdir().expect("tempdir");
        let keystore = MemoryStore::new();
        let restore_res = Secwet::restore_from_export(
            dir_target.path(),
            &export_path,
            &SecretString::from(adv_input.to_string()),
            "dev",
            &keystore,
        );
        assert!(
            matches!(restore_res, Err(Error::RecoveryFailed)),
            "Adversarial key '{}' must fail with RecoveryFailed",
            adv_input
        );
        assert!(!dir_target.path().join("secwet").exists());
    }

    // 2.5: Valid Crockford Aliases and Normalization (Must Succeed)
    // Crockford rules: 'I', 'i', 'L', 'l' -> '1'; 'O', 'o' -> '0'.
    // Test that a key containing aliases decrypts successfully!
    {
        // Form a valid key that contains '1' and '0'
        let mut aliased = normalized.clone();
        aliased = aliased.replace('1', "I");
        aliased = aliased.replace('0', "O");

        // Format with arbitrary whitespace, tabs, and lowercase
        let mut formatted_alias = String::new();
        for (idx, ch) in aliased.chars().enumerate() {
            if idx > 0 && idx % 5 == 0 {
                formatted_alias.push_str("   -   ");
            }
            if idx % 2 == 0 {
                formatted_alias.push(ch.to_ascii_lowercase());
            } else {
                formatted_alias.push(ch);
            }
        }

        let dir_target = tempdir().expect("tempdir");
        let keystore = MemoryStore::new();
        let restore_res = Secwet::restore_from_export(
            dir_target.path(),
            &export_path,
            &SecretString::from(formatted_alias),
            "restored-aliased",
            &keystore,
        );

        assert!(
            restore_res.is_ok(),
            "Valid key with Crockford aliases and whitespace MUST succeed restore, but failed: {:?}",
            restore_res.err()
        );
        let restored = restore_res.unwrap();
        assert_eq!(restored.secwet_id(), secwet_id);
        restored.lock();
    }
}

// ============================================================================
// 3. Zero Plaintext Leakage & Shannon Entropy Audit
// ============================================================================

#[test]
fn test_adversarial_zero_plaintext_leakage_and_entropy() {
    let (_dir_orig, _dir_export, _key, export_path, _secwet_id, leak_markers) =
        create_test_workspace_and_export();

    let raw_bytes = std::fs::read(&export_path).expect("read export");
    let raw_string = String::from_utf8_lossy(&raw_bytes);

    // 3.1: Zero Substring Leaks
    for marker in &leak_markers {
        assert!(
            !raw_string.contains(marker),
            "FORENSIC VIOLATION: Export archive leaked plaintext marker: '{}'",
            marker
        );
        assert!(
            !raw_bytes.windows(marker.len()).any(|w| w == marker.as_bytes()),
            "FORENSIC VIOLATION: Byte sequence leaked in raw archive: '{}'",
            marker
        );
    }

    // 3.2: Shannon Entropy Analysis of Ciphertext Payload
    let envelope: SecwetExportEnvelope =
        serde_json::from_slice(&raw_bytes).expect("parse envelope");
    let ciphertext = data_encoding::BASE64
        .decode(envelope.ciphertext.as_bytes())
        .expect("decode ciphertext");

    assert!(ciphertext.len() >= 1024, "Ciphertext must be non-trivial");

    let mut byte_counts = [0usize; 256];
    for &b in &ciphertext {
        byte_counts[b as usize] += 1;
    }

    let total = ciphertext.len() as f64;
    let mut shannon_entropy = 0.0f64;
    for &count in &byte_counts {
        if count > 0 {
            let p = count as f64 / total;
            shannon_entropy -= p * p.log2();
        }
    }

    // Maximum possible entropy is 8.00 bits/byte (uniform random noise).
    // Genuine XChaCha20Poly1305 ciphertext with Postcard canonical payload
    // MUST achieve > 7.95 bits/byte on payloads >= 1KB.
    println!("Measured Shannon entropy: {:.4} bits/byte", shannon_entropy);
    assert!(
        shannon_entropy > 7.95,
        "Ciphertext entropy ({:.4} bits/byte) too low! Expected > 7.95 bits/byte",
        shannon_entropy
    );
}

// ============================================================================
// 4. Repeated Recovery Key Replacement & Multi-Epoch Roll Forward
// ============================================================================

#[test]
fn test_adversarial_recovery_key_replacement_and_epoch_roll_forward() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    let mut secwet =
        Secwet::create(dir.path(), "epoch-laptop", &keystore).expect("create secwet");
    let secwet_id = secwet.secwet_id();
    assert_eq!(secwet.key_epoch(), 1);

    // Initial state: uncreated recovery key
    assert!(!secwet.recovery_status().unwrap().created);

    // Step 1: Create initial recovery key K1
    let k1 = secwet.create_recovery_key(&keystore).expect("create k1");
    assert!(secwet.recovery_status().unwrap().created);
    assert!(secwet.verify_recovery_key(k1.expose_secret()).unwrap());

    // Step 2: Replace with K2
    let k2 = secwet.replace_recovery_key(&keystore).expect("replace k2");
    assert_ne!(k1.expose_secret(), k2.expose_secret());
    assert!(secwet.verify_recovery_key(k2.expose_secret()).unwrap());
    // K1 must be immediately invalidated!
    assert!(!secwet.verify_recovery_key(k1.expose_secret()).unwrap());

    // Step 3: Replace with K3
    let k3 = secwet.replace_recovery_key(&keystore).expect("replace k3");
    assert_ne!(k2.expose_secret(), k3.expose_secret());
    assert!(secwet.verify_recovery_key(k3.expose_secret()).unwrap());
    // K1 and K2 must both fail!
    assert!(!secwet.verify_recovery_key(k1.expose_secret()).unwrap());
    assert!(!secwet.verify_recovery_key(k2.expose_secret()).unwrap());

    // Step 4: Export with K3
    let export_dir = tempdir().expect("tempdir");
    let export_file_1 = export_dir.path().join("epoch1.secwet");
    secwet.export_encrypted(&k3, &export_file_1).expect("export k3");
    secwet.lock();

    // Step 5: Restore on new device B with K3 -> should advance to epoch 2
    let restore_dir_b = tempdir().expect("tempdir");
    let keystore_b = MemoryStore::new();
    let restored_b = Secwet::restore_from_export(
        restore_dir_b.path(),
        &export_file_1,
        &k3,
        "device-b",
        &keystore_b,
    )
    .expect("restore b");

    assert_eq!(restored_b.secwet_id(), secwet_id);
    assert_eq!(
        restored_b.key_epoch(),
        2,
        "First restore must increment epoch from 1 to 2"
    );
    assert!(restored_b.verify_recovery_key(k3.expose_secret()).unwrap());

    // Step 6: Export from device B and restore on device C -> should advance to epoch 3
    let export_file_2 = export_dir.path().join("epoch2.secwet");
    restored_b
        .export_encrypted(&k3, &export_file_2)
        .expect("export b");
    restored_b.lock();

    let restore_dir_c = tempdir().expect("tempdir");
    let keystore_c = MemoryStore::new();
    let restored_c = Secwet::restore_from_export(
        restore_dir_c.path(),
        &export_file_2,
        &k3,
        "device-c",
        &keystore_c,
    )
    .expect("restore c");

    assert_eq!(restored_c.secwet_id(), secwet_id);
    assert_eq!(
        restored_c.key_epoch(),
        3,
        "Second restore must increment epoch from 2 to 3"
    );
    assert!(restored_c.verify_recovery_key(k3.expose_secret()).unwrap());
    restored_c.lock();
}

// ============================================================================
// 5. Existing Workspace State Immunity Under Failed Restore Attempts
// ============================================================================

#[test]
fn test_adversarial_existing_workspace_not_corrupted_on_failed_restore() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    // 1. Create a production workspace with sensitive data
    let mut secwet = Secwet::create(dir.path(), "laptop-prod", &keystore).expect("create");
    let space = secwet.create_space("Production", None).expect("create space");
    let label = secwet
        .create_label_in_space("Critical", None, Some(space.id))
        .expect("create label");
    let item = secwet
        .create_item(label.id, "Prod DB", None)
        .expect("create item");
    let env = secwet
        .add_environment(item.id, "Live")
        .expect("add env");
    let sec = secwet
        .create_secret(SecretDraft::new(
            item.id,
            Some(env.id),
            "ROOT_KEY",
            SecretKind::Password,
            "HIGHLY_CONFIDENTIAL_ROOT_KEY_99999",
            None,
        ))
        .expect("create secret");
    let orig_id = secwet.secwet_id();
    secwet.lock();

    // 2. Prepare a malformed export archive
    let bad_export_file = dir.path().join("corrupted.secwet");
    std::fs::write(&bad_export_file, b"MALFORMED_CORRUPTED_EXPORT_ENVELOPE").unwrap();

    // 3. Attempt restoring the bad archive into the SAME data directory
    let keystore_attacker = MemoryStore::new();
    let bad_key = SecretString::from("00000-00000-00000-00000-00000");
    let restore_res = Secwet::restore_from_export(
        dir.path(),
        &bad_export_file,
        &bad_key,
        "attacker-device",
        &keystore_attacker,
    );

    assert!(restore_res.is_err());
    match restore_res.unwrap_err() {
        Error::RecoveryFailed => {}
        other => panic!("Expected RecoveryFailed, got {:?}", other),
    }

    // 4. Verify that the original workspace was NOT wiped or corrupted
    let unlocked = Secwet::unlock(dir.path(), &keystore).expect("original workspace must unlock");
    assert_eq!(unlocked.secwet_id(), orig_id);
    let rev = unlocked.reveal_secret(sec.id).expect("reveal secret");
    assert_eq!(rev.expose_secret(), "HIGHLY_CONFIDENTIAL_ROOT_KEY_99999");
    unlocked.lock();
}

// ============================================================================
// 6. Export Encrypted With Mismatched Key Fails Without Writing Output
// ============================================================================

#[test]
fn test_adversarial_export_with_wrong_key_rejected() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "laptop-export", &keystore).expect("create");
    let _real_key = secwet.create_recovery_key(&keystore).expect("create real key");

    // Attempt export using a completely different recovery key
    let wrong_key = SecretString::from("ABCDE-FGHIJ-KLMNP-QRSTV-WXYZ0");
    let out_file = dir.path().join("unauthorized_export.secwet");

    let export_res = secwet.export_encrypted(&wrong_key, &out_file);
    assert!(
        export_res.is_err(),
        "Export with wrong recovery key must be rejected"
    );
    match export_res.unwrap_err() {
        Error::RecoveryFailed => {}
        other => panic!("Expected Error::RecoveryFailed, got {:?}", other),
    }

    // Output file must NOT be created
    assert!(
        !out_file.exists(),
        "No output file should be written when export is rejected"
    );

    secwet.lock();
}

