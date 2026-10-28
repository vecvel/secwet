//! Empirical Challenger 2 Adversarial Stress Test Suite for Milestone 3-1.
//!
//! Scope:
//! 1. Multi-epoch key replacement:
//!    - Multiple `replace_recovery_key` cycles across multiple master key rotations.
//!    - Verification that previous recovery keys cannot unlock or restore workspaces, while
//!      the latest key restores 100% of data across all epochs.
//!    - Direct verification of `recovery_wrapped_master_keys` re-wrapping all epochs.
//! 2. Large payloads and boundaries:
//!    - Export and restore with 0-byte, 1-byte, 512 KiB low-entropy, and 1 MiB high-entropy binary files.
//!    - Multi-line secrets with mixed line endings, RSA/SSH keys, complex formatting.
//!    - Special characters: Full international Unicode (CJK, Cyrillic, Arabic RTL, Emojis, symbols).
//!    - Empty containers: Empty spaces, empty labels, empty items, empty environments.
//! 3. Cryptographic Shannon Entropy:
//!    - High-precision Shannon entropy calculation over decoded ciphertext from `.secwet` envelope.
//!    - Verification that even when plaintexts consist of 100% low-entropy zero bytes, ciphertext
//!      exceeds 7.95 bits/byte Shannon entropy.
//!    - Adversarial single-bit tamper resistance across nonce, tag, and ciphertext body.
//!    - Extreme Crockford Base32 normalization and alias testing.

use data_encoding::BASE64;
use rand_core::Rng;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use secwet_core::crypto::{self, OsRng};
use secwet_core::keys::MemoryStore;
use secwet_core::model::SecwetExportEnvelope;
use secwet_core::{Error, KeyStore, SecretDraft, SecretKind, Secwet};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tempfile::tempdir;
use uuid::Uuid;

/// Helper to calculate the Shannon entropy in bits per byte of a slice.
/// Formula: H(X) = - sum(p(x) * log2(p(x))) for p(x) > 0.
fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &counts {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

// ============================================================================
// 1. Multi-Epoch Key Replacement Across Master Key Rotations
// ============================================================================

#[test]
fn test_stress_multi_epoch_rotation_and_recovery_replacement() {
    let base_dir = tempdir().expect("tempdir");
    let keystore_dev1 = MemoryStore::new();

    // ------------------------------------------------------------------------
    // Epoch 1: Initial Creation & Population
    // ------------------------------------------------------------------------
    let dir_dev1 = base_dir.path().join("dev1");
    let mut secwet = Secwet::create(&dir_dev1, "device-1", &keystore_dev1)
        .expect("Secwet create must succeed");
    assert_eq!(secwet.key_epoch(), 1);

    // Populate Epoch 1 entities
    let space_e1 = secwet
        .create_space("Epoch 1 Space", Some("folder".to_string()))
        .expect("create_space");
    let label_e1 = secwet
        .create_label_in_space("Epoch 1 Label", None, Some(space_e1.id))
        .expect("create_label");
    let item_e1 = secwet
        .create_item(label_e1.id, "Epoch 1 Service", Some("Service in epoch 1".to_string()))
        .expect("create_item");
    let env_e1 = secwet
        .add_environment(item_e1.id, "Production")
        .expect("add_environment");
    let sec_e1 = secwet
        .create_secret(SecretDraft::new(
            item_e1.id,
            Some(env_e1.id),
            "EPOCH_1_KEY",
            SecretKind::ApiKey,
            "secret-from-epoch-1-original-state",
            Some("Epoch 1 secret note".to_string()),
        ))
        .expect("create_secret");

    // Perform multiple replace_recovery_key cycles in Epoch 1
    let k_r1_init = secwet
        .create_recovery_key(&keystore_dev1)
        .expect("create_recovery_key");
    let k_r1_str = k_r1_init.expose_secret().to_string();

    assert!(secwet.verify_recovery_key(&k_r1_str).expect("verify"));

    // Cycle 1.1 replacement
    let k_r1_rep1 = secwet
        .replace_recovery_key(&keystore_dev1)
        .expect("replace_recovery_key cycle 1");
    let k_r1_rep1_str = k_r1_rep1.expose_secret().to_string();
    assert_ne!(k_r1_str, k_r1_rep1_str);
    assert!(!secwet.verify_recovery_key(&k_r1_str).expect("verify old key"));
    assert!(secwet.verify_recovery_key(&k_r1_rep1_str).expect("verify rep1 key"));

    // Cycle 1.2 replacement
    let k_r1_rep2 = secwet
        .replace_recovery_key(&keystore_dev1)
        .expect("replace_recovery_key cycle 2");
    let k_r1_rep2_str = k_r1_rep2.expose_secret().to_string();
    assert_ne!(k_r1_rep1_str, k_r1_rep2_str);
    assert!(!secwet.verify_recovery_key(&k_r1_str).expect("verify initial"));
    assert!(!secwet.verify_recovery_key(&k_r1_rep1_str).expect("verify rep1"));
    assert!(secwet.verify_recovery_key(&k_r1_rep2_str).expect("verify rep2"));

    // Export Epoch 1 archive with active recovery key k_r1_rep2
    let export_e1_path = base_dir.path().join("export_epoch1.secwet");
    secwet
        .export_encrypted(&k_r1_rep2, &export_e1_path)
        .expect("export_encrypted epoch 1");

    // Negative verification: Previous recovery keys CANNOT export or restore
    let export_bad_path = base_dir.path().join("bad_export.secwet");
    let bad_export_res = secwet.export_encrypted(&SecretString::from(k_r1_str.clone()), &export_bad_path);
    assert!(bad_export_res.is_err(), "Export with replaced recovery key must fail");

    secwet.lock();

    // Verify previous keys CANNOT restore the exported archive
    let keystore_dev2 = MemoryStore::new();
    let dir_dev2 = base_dir.path().join("dev2");

    let bad_restore_1 = Secwet::restore_from_export(
        &dir_dev2,
        &export_e1_path,
        &SecretString::from(k_r1_str.clone()),
        "device-2",
        &keystore_dev2,
    );
    assert!(bad_restore_1.is_err(), "Initial replaced key must not restore archive");

    let bad_restore_2 = Secwet::restore_from_export(
        &dir_dev2,
        &export_e1_path,
        &SecretString::from(k_r1_rep1_str.clone()),
        "device-2",
        &keystore_dev2,
    );
    assert!(bad_restore_2.is_err(), "Intermediate replaced key must not restore archive");

    // ------------------------------------------------------------------------
    // Epoch 2: Restore from Epoch 1 Archive -> Key Epoch advances to 2
    // ------------------------------------------------------------------------
    let mut secwet_dev2 = Secwet::restore_from_export(
        &dir_dev2,
        &export_e1_path,
        &k_r1_rep2,
        "device-2",
        &keystore_dev2,
    )
    .expect("Restore with latest valid key must succeed");

    assert_eq!(secwet_dev2.key_epoch(), 2, "Epoch must advance to 2 upon restore");

    // Verify Epoch 1 data restored with 100% fidelity
    let rev_sec_e1 = secwet_dev2
        .reveal_secret(sec_e1.id)
        .expect("reveal Epoch 1 secret");
    assert_eq!(rev_sec_e1.expose_secret(), "secret-from-epoch-1-original-state");

    // Add Epoch 2 entities
    let space_e2 = secwet_dev2
        .create_space("Epoch 2 Space", None)
        .expect("create_space e2");
    let label_e2 = secwet_dev2
        .create_label_in_space("Epoch 2 Label", None, Some(space_e2.id))
        .expect("create_label e2");
    let item_e2 = secwet_dev2
        .create_item(label_e2.id, "Epoch 2 Gateway", None)
        .expect("create_item e2");
    let sec_e2 = secwet_dev2
        .create_secret(SecretDraft::new(
            item_e2.id,
            None,
            "EPOCH_2_TOKEN",
            SecretKind::AccessToken,
            "bearer-token-epoch-2-operational",
            None,
        ))
        .expect("create_secret e2");

    // Perform multiple replace_recovery_key cycles in Epoch 2
    let k_r2_init = secwet_dev2
        .replace_recovery_key(&keystore_dev2)
        .expect("replace_recovery_key in epoch 2 (init)");
    let k_r2_init_str = k_r2_init.expose_secret().to_string();

    let k_r2_rep = secwet_dev2
        .replace_recovery_key(&keystore_dev2)
        .expect("replace_recovery_key in epoch 2 (rep)");
    let k_r2_rep_str = k_r2_rep.expose_secret().to_string();

    // Confirm that Epoch 1 recovery keys and previous Epoch 2 keys are all rejected
    assert!(!secwet_dev2.verify_recovery_key(&k_r1_str).expect("verify"));
    assert!(!secwet_dev2.verify_recovery_key(&k_r1_rep1_str).expect("verify"));
    assert!(!secwet_dev2.verify_recovery_key(&k_r1_rep2_str).expect("verify"));
    assert!(!secwet_dev2.verify_recovery_key(&k_r2_init_str).expect("verify"));
    assert!(secwet_dev2.verify_recovery_key(&k_r2_rep_str).expect("verify"));

    // Export Epoch 2 archive
    let export_e2_path = base_dir.path().join("export_epoch2.secwet");
    secwet_dev2
        .export_encrypted(&k_r2_rep, &export_e2_path)
        .expect("export_encrypted epoch 2");

    secwet_dev2.lock();

    // ------------------------------------------------------------------------
    // Epoch 3: Restore from Epoch 2 Archive -> Key Epoch advances to 3
    // ------------------------------------------------------------------------
    let keystore_dev3 = MemoryStore::new();
    let dir_dev3 = base_dir.path().join("dev3");

    // All old keys fail to restore Epoch 2 archive
    for old_key in &[&k_r1_str, &k_r1_rep1_str, &k_r1_rep2_str, &k_r2_init_str] {
        let r = Secwet::restore_from_export(
            &dir_dev3,
            &export_e2_path,
            &SecretString::from((*old_key).clone()),
            "device-3",
            &keystore_dev3,
        );
        assert!(r.is_err(), "Old key {old_key} must fail to restore archive");
    }

    let mut secwet_dev3 = Secwet::restore_from_export(
        &dir_dev3,
        &export_e2_path,
        &k_r2_rep,
        "device-3",
        &keystore_dev3,
    )
    .expect("Restore epoch 2 archive with active key must succeed");

    assert_eq!(secwet_dev3.key_epoch(), 3, "Epoch must advance to 3 upon restore");

    // Verify BOTH Epoch 1 and Epoch 2 secrets exist
    let rev_e1_in_e3 = secwet_dev3
        .reveal_secret(sec_e1.id)
        .expect("reveal e1 in e3");
    assert_eq!(rev_e1_in_e3.expose_secret(), "secret-from-epoch-1-original-state");

    let rev_e2_in_e3 = secwet_dev3
        .reveal_secret(sec_e2.id)
        .expect("reveal e2 in e3");
    assert_eq!(rev_e2_in_e3.expose_secret(), "bearer-token-epoch-2-operational");

    // Add Epoch 3 entities
    let sec_e3 = secwet_dev3
        .create_secret(SecretDraft::new(
            item_e2.id,
            None,
            "EPOCH_3_PASSWORD",
            SecretKind::Password,
            "ultra-secure-epoch-3-master-secret",
            None,
        ))
        .expect("create_secret e3");

    // Cycle replace_recovery_key in Epoch 3
    let k_r3_final = secwet_dev3
        .replace_recovery_key(&keystore_dev3)
        .expect("replace_recovery_key in epoch 3");

    let export_e3_path = base_dir.path().join("export_epoch3.secwet");
    secwet_dev3
        .export_encrypted(&k_r3_final, &export_e3_path)
        .expect("export_encrypted epoch 3");

    secwet_dev3.lock();

    // ------------------------------------------------------------------------
    // Epoch 4: Restore Epoch 3 Archive -> Key Epoch advances to 4
    // ------------------------------------------------------------------------
    let keystore_dev4 = MemoryStore::new();
    let dir_dev4 = base_dir.path().join("dev4");

    let restored_final = Secwet::restore_from_export(
        &dir_dev4,
        &export_e3_path,
        &k_r3_final,
        "device-4",
        &keystore_dev4,
    )
    .expect("Final restore into epoch 4 must succeed");

    assert_eq!(restored_final.key_epoch(), 4, "Key epoch must be 4");

    // Assert 100% fidelity across all 3 historical epochs!
    assert_eq!(
        restored_final.reveal_secret(sec_e1.id).unwrap().expose_secret(),
        "secret-from-epoch-1-original-state",
        "Epoch 1 secret must survive all 4 epochs intact"
    );
    assert_eq!(
        restored_final.reveal_secret(sec_e2.id).unwrap().expose_secret(),
        "bearer-token-epoch-2-operational",
        "Epoch 2 secret must survive all epochs intact"
    );
    assert_eq!(
        restored_final.reveal_secret(sec_e3.id).unwrap().expose_secret(),
        "ultra-secure-epoch-3-master-secret",
        "Epoch 3 secret must survive all epochs intact"
    );

    restored_final.lock();
}

#[test]
fn test_stress_in_place_master_key_epochs_wrapping() {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    let secwet = Secwet::create(dir.path(), "laptop", &keystore)
        .expect("create workspace");
    let secwet_id = secwet.secwet_id();

    // Simulate multi-epoch master keys in the keystore: epochs 1, 2, 3, 4
    let mut original_master_keys: HashMap<u32, Vec<u8>> = HashMap::new();
    let k_v1 = keystore
        .get(&format!("secwet/{secwet_id}/master-key/1"))
        .unwrap()
        .unwrap();
    original_master_keys.insert(1u32, k_v1.as_slice().to_vec());

    for epoch in 2..=4u32 {
        let mut kv = [0u8; 32];
        OsRng.fill_bytes(&mut kv);
        keystore
            .set(&format!("secwet/{secwet_id}/master-key/{epoch}"), &kv)
            .unwrap();
        original_master_keys.insert(epoch, kv.to_vec());
    }

    let db_path = dir.path().join("secwet").join(secwet_id.to_string()).join("secwet.sqlite3");
    secwet.lock();

    // Update current_key_epoch in SQLite to 4
    {
        let conn = secwet_core::records::open_connection(&db_path).unwrap();
        secwet_core::records::set_meta(&conn, "current_key_epoch", "4").unwrap();
    }

    // Unlock secwet at epoch 4
    let mut secwet_ep4 = Secwet::unlock(dir.path(), &keystore).expect("unlock at epoch 4");
    assert_eq!(secwet_ep4.key_epoch(), 4);

    // Initial recovery key creation
    let key1 = secwet_ep4
        .create_recovery_key(&keystore)
        .expect("create_recovery_key");
    let key1_str = key1.expose_secret();

    // Inspect stored wrapped master keys in SQLite meta
    let check_b64_1 = {
        let conn = secwet_core::records::open_connection(&db_path).unwrap();
        secwet_core::records::get_meta(&conn, "recovery_check").unwrap().unwrap()
    };
    let wrapped_json_1 = {
        let conn = secwet_core::records::open_connection(&db_path).unwrap();
        secwet_core::records::get_meta(&conn, "recovery_wrapped_master_keys").unwrap().unwrap()
    };

    let wrapped_map_1: HashMap<u32, String> = serde_json::from_str(&wrapped_json_1).unwrap();
    assert_eq!(wrapped_map_1.len(), 4, "Must have wrapped master keys for all 4 epochs");

    // Derive K_r1 and verify each epoch can be opened and matches original master key
    let k_r1 = crypto::derive_recovery_key_from_str(key1_str, &secwet_id).unwrap();
    for epoch in 1..=4u32 {
        let wrapped_b64 = wrapped_map_1.get(&epoch).expect("epoch must be present");
        let blob = BASE64.decode(wrapped_b64.as_bytes()).unwrap();
        let wrap_aad = postcard::to_stdvec(&("recovery-wrap", secwet_id, epoch)).unwrap();
        let opened_km = crypto::open_raw(&k_r1, &wrap_aad, &blob).expect("unwrapping must succeed");
        assert_eq!(
            opened_km,
            original_master_keys[&epoch],
            "Unwrapped master key for epoch {epoch} must match original"
        );
    }

    // Now replace recovery key: cycle 2
    let key2 = secwet_ep4
        .replace_recovery_key(&keystore)
        .expect("replace_recovery_key");
    let key2_str = key2.expose_secret();
    assert_ne!(key1_str, key2_str);

    let check_b64_2 = {
        let conn = secwet_core::records::open_connection(&db_path).unwrap();
        secwet_core::records::get_meta(&conn, "recovery_check").unwrap().unwrap()
    };
    let wrapped_json_2 = {
        let conn = secwet_core::records::open_connection(&db_path).unwrap();
        secwet_core::records::get_meta(&conn, "recovery_wrapped_master_keys").unwrap().unwrap()
    };

    // Seals must be overwritten and distinct
    assert_ne!(check_b64_1, check_b64_2);
    assert_ne!(wrapped_json_1, wrapped_json_2);

    // K_r1 CANNOT decrypt the new recovery check seal
    let k_r1_check_aad = postcard::to_stdvec(&("secwet-recovery-check", secwet_id)).unwrap();
    let new_check_blob = BASE64.decode(check_b64_2.as_bytes()).unwrap();
    assert!(
        crypto::open_raw(&k_r1, &k_r1_check_aad, &new_check_blob).is_err(),
        "Old recovery key K_r1 must fail opening new recovery check seal"
    );

    // K_r1 CANNOT decrypt any of the newly wrapped master keys
    let wrapped_map_2: HashMap<u32, String> = serde_json::from_str(&wrapped_json_2).unwrap();
    assert_eq!(wrapped_map_2.len(), 4);
    for epoch in 1..=4u32 {
        let wrapped_b64 = &wrapped_map_2[&epoch];
        let blob = BASE64.decode(wrapped_b64.as_bytes()).unwrap();
        let wrap_aad = postcard::to_stdvec(&("recovery-wrap", secwet_id, epoch)).unwrap();
        assert!(
            crypto::open_raw(&k_r1, &wrap_aad, &blob).is_err(),
            "Old recovery key K_r1 must fail unwrapping epoch {epoch}"
        );
    }

    // K_r2 decrypts ALL epochs cleanly
    let k_r2 = crypto::derive_recovery_key_from_str(key2_str, &secwet_id).unwrap();
    for epoch in 1..=4u32 {
        let wrapped_b64 = &wrapped_map_2[&epoch];
        let blob = BASE64.decode(wrapped_b64.as_bytes()).unwrap();
        let wrap_aad = postcard::to_stdvec(&("recovery-wrap", secwet_id, epoch)).unwrap();
        let opened_km = crypto::open_raw(&k_r2, &wrap_aad, &blob).expect("K_r2 unwrapping");
        assert_eq!(
            opened_km,
            original_master_keys[&epoch],
            "Unwrapped master key with K_r2 for epoch {epoch} must match original"
        );
    }

    secwet_ep4.lock();
}

// ============================================================================
// 2. Large Payloads, Boundaries, Special Characters & Empty Containers
// ============================================================================

#[test]
fn test_stress_large_and_boundary_payloads_roundtrip() {
    let dir_orig = tempdir().expect("tempdir");
    let dir_restore = tempdir().expect("tempdir");
    let dir_export = tempdir().expect("tempdir");
    let keystore_orig = MemoryStore::new();

    let mut secwet = Secwet::create(dir_orig.path(), "laptop-stress", &keystore_orig)
        .expect("create workspace");

    // 2.1 Empty Containers:
    // a) Empty Space with 0 labels
    let empty_space = secwet
        .create_space("Empty Space Void", Some("inbox".to_string()))
        .expect("empty space");

    // b) Populated Space with an Empty Label
    let active_space = secwet
        .create_space("Active Multi-Tier Space", Some("cloud".to_string()))
        .expect("active space");
    let empty_label = secwet
        .create_label_in_space("Empty Label Zero Items", None, Some(active_space.id))
        .expect("empty label");

    // c) Item with Empty Environment (0 secrets, 0 notes, 0 files)
    let populated_label = secwet
        .create_label_in_space("Payloads Container", None, Some(active_space.id))
        .expect("populated label");
    let item_with_empty_env = secwet
        .create_item(populated_label.id, "Container Item", Some("Holds empty and populated envs".to_string()))
        .expect("item with empty env");
    let empty_env = secwet
        .add_environment(item_with_empty_env.id, "Completely Empty Env")
        .expect("empty env");

    // d) Completely Empty Item (0 environments, 0 secrets, 0 files, 0 notes)
    let empty_item = secwet
        .create_item(populated_label.id, "Ghost Item", Some("No children at all".to_string()))
        .expect("empty item");

    // 2.2 Boundary Files:
    // a) 0-byte binary file
    let file_0byte = secwet
        .upload_file(
            item_with_empty_env.id,
            None,
            "empty_zero.bin",
            &[],
            Some("application/octet-stream"),
        )
        .expect("upload 0-byte file");

    // b) 1-byte file
    let file_1byte = secwet
        .upload_file(
            item_with_empty_env.id,
            None,
            "single_byte.bin",
            &[0x42],
            Some("application/octet-stream"),
        )
        .expect("upload 1-byte file");

    // c) 1 MiB High-Entropy Random Payload
    let mut high_entropy_data = vec![0u8; 1024 * 1024]; // 1 MiB
    OsRng.fill_bytes(&mut high_entropy_data);
    let high_entropy_sha = {
        let mut hasher = Sha256::new();
        hasher.update(&high_entropy_data);
        data_encoding::HEXLOWER.encode(&hasher.finalize())
    };
    let file_1mib = secwet
        .upload_file(
            item_with_empty_env.id,
            None,
            "high_entropy_1mib.bin",
            &high_entropy_data,
            Some("application/octet-stream"),
        )
        .expect("upload 1 MiB high entropy file");

    // d) 512 KiB Low-Entropy Payload (all 0xAA repeating pattern)
    let low_entropy_data = vec![0xAAu8; 512 * 1024]; // 512 KiB
    let low_entropy_sha = {
        let mut hasher = Sha256::new();
        hasher.update(&low_entropy_data);
        data_encoding::HEXLOWER.encode(&hasher.finalize())
    };
    let file_512k_low = secwet
        .upload_file(
            item_with_empty_env.id,
            None,
            "low_entropy_512k.bin",
            &low_entropy_data,
            Some("application/octet-stream"),
        )
        .expect("upload 512 KiB low entropy file");

    // 2.3 Special Characters, Extreme Multiline, and Unicode Secrets:
    // a) Multiline RSA 4096-bit private key with mixed CR-LF and trailing spaces
    let mut multiline_rsa = String::from("-----BEGIN RSA PRIVATE KEY-----\r\n");
    for i in 0..64 {
        multiline_rsa.push_str(&format!("MIIJKQIBAAKCAQEA{:04x}LineOfBase64PaddedDataForAdversarialTest==  \r\n", i));
    }
    multiline_rsa.push_str("-----END RSA PRIVATE KEY-----\n");

    let sec_rsa = secwet
        .create_secret(SecretDraft::new(
            item_with_empty_env.id,
            None,
            "RSA_4096_MIXED_NEWLINES",
            SecretKind::Certificate,
            &multiline_rsa,
            Some("Multiline with CRLF and spaces".to_string()),
        ))
        .expect("create multiline rsa");

    // b) International Unicode & Emoji stress payload
    let unicode_secret_val = "\
        Japanese: 吾輩は猫である。名前はまだ無い。\n\
        Cyrillic: Съешь же ещё этих мягких французских булок, да выпей чаю.\n\
        Arabic RTL: لوريم إيبسوم هو ببساطة نص شكلي يستخدم في صناعة الطباعة\n\
        Special Characters: <>&'\"`\\/|?*~^$#@!%()[]{}:;,\n\
        Zero Width Space: \u{200B}\u{200C}\u{200D}\n\
        Emojis: 🚀🛡️🔐💥⚡🦀🧪💎✨";

    let sec_unicode = secwet
        .create_secret(SecretDraft::new(
            item_with_empty_env.id,
            None,
            "UNICODE_EMOJI_SPECIAL_CHARS",
            SecretKind::Password,
            unicode_secret_val,
            Some("Complete international Unicode character set".to_string()),
        ))
        .expect("create unicode secret");

    // c) Rich Markdown Note with complex HTML, tables, code blocks
    let note_complex = secwet
        .create_note(
            item_with_empty_env.id,
            None,
            "Adversarial Complex Runbook 🛡️",
            "# Heading 1\n\n```python\ndef test():\n    return 'Hello \\n\\t World'\n```\n\n| Col 1 | Col 2 |\n|---|---|\n| `Val <1>` | **Bold & Italic** |\n\n<script>alert('xss_attempt')</script>",
        )
        .expect("create complex note");

    // Export with recovery key
    let recovery_key = secwet
        .create_recovery_key(&keystore_orig)
        .expect("create_recovery_key");
    let export_file = dir_export.path().join("boundary_stress.secwet");

    let summary = secwet
        .export_encrypted(&recovery_key, &export_file)
        .expect("export_encrypted");

    assert!(export_file.is_file());
    assert!(summary.spaces_count >= 3);
    assert!(summary.labels_count >= 3);
    assert!(summary.items_count >= 2);
    assert!(summary.environments_count >= 1);
    assert!(summary.secrets_count >= 2);
    assert!(summary.notes_count >= 1);
    assert!(summary.files_count >= 4);

    secwet.lock();

    // ------------------------------------------------------------------------
    // Restore into clean environment and verify 100% fidelity
    // ------------------------------------------------------------------------
    let keystore_restore = MemoryStore::new();
    let restored = Secwet::restore_from_export(
        dir_restore.path(),
        &export_file,
        &recovery_key,
        "restored-stress",
        &keystore_restore,
    )
    .expect("restore_from_export boundary stress");

    // 1. Verify Empty Space is preserved
    let spaces = restored.list_spaces().expect("list_spaces");
    let found_empty_space = spaces.iter().find(|s| s.id == empty_space.id).expect("empty space must exist");
    assert_eq!(found_empty_space.name, "Empty Space Void");

    // 2. Verify Empty Label is preserved
    let labels = restored.list_labels().expect("list_labels");
    let found_empty_label = labels.iter().find(|l| l.id == empty_label.id).expect("empty label must exist");
    assert_eq!(found_empty_label.name, "Empty Label Zero Items");

    // 3. Verify Empty Environment is preserved
    let envs = restored.list_environments(item_with_empty_env.id).expect("list_environments");
    let found_empty_env = envs.iter().find(|e| e.id == empty_env.id).expect("empty env must exist");
    assert_eq!(found_empty_env.name, "Completely Empty Env");

    // 4. Verify Empty Item is preserved
    let items = restored.list_items(populated_label.id).expect("list_items");
    let found_empty_item = items.iter().find(|i| i.id == empty_item.id).expect("empty item must exist");
    assert_eq!(found_empty_item.name, "Ghost Item");
    assert_eq!(found_empty_item.description, Some("No children at all".to_string()));

    // 5. Verify 0-byte file
    let (meta_0, data_0) = restored.download_file(file_0byte.id).expect("download 0-byte");
    assert_eq!(meta_0.name, "empty_zero.bin");
    assert_eq!(meta_0.size_bytes, 0);
    assert_eq!(data_0.len(), 0);

    // 6. Verify 1-byte file
    let (meta_1, data_1) = restored.download_file(file_1byte.id).expect("download 1-byte");
    assert_eq!(meta_1.name, "single_byte.bin");
    assert_eq!(meta_1.size_bytes, 1);
    assert_eq!(data_1, vec![0x42]);

    // 7. Verify 1 MiB High Entropy File byte-for-byte and SHA-256
    let (meta_1mib, data_1mib) = restored.download_file(file_1mib.id).expect("download 1 MiB file");
    assert_eq!(meta_1mib.name, "high_entropy_1mib.bin");
    assert_eq!(meta_1mib.size_bytes, 1024 * 1024);
    assert_eq!(data_1mib.len(), 1024 * 1024);
    assert_eq!(meta_1mib.sha256, high_entropy_sha);
    assert_eq!(data_1mib, high_entropy_data);

    // 8. Verify 512 KiB Low Entropy File byte-for-byte and SHA-256
    let (meta_512k, data_512k) = restored.download_file(file_512k_low.id).expect("download 512 KiB file");
    assert_eq!(meta_512k.name, "low_entropy_512k.bin");
    assert_eq!(meta_512k.size_bytes, 512 * 1024);
    assert_eq!(meta_512k.sha256, low_entropy_sha);
    assert_eq!(data_512k, low_entropy_data);

    // 9. Verify Multiline Secret exact string with CRLF and trailing spaces
    let rev_rsa = restored.reveal_secret(sec_rsa.id).expect("reveal rsa");
    assert_eq!(
        rev_rsa.expose_secret(),
        &multiline_rsa,
        "Multiline secret must match exactly byte-for-byte with CRLF preserved"
    );

    // 10. Verify International Unicode & Emoji secret
    let rev_unicode = restored.reveal_secret(sec_unicode.id).expect("reveal unicode");
    assert_eq!(
        rev_unicode.expose_secret(),
        unicode_secret_val,
        "Unicode and emoji strings must match 100%"
    );

    // 11. Verify Complex Markdown Note
    let r_note = restored.get_note(note_complex.id).expect("get complex note");
    assert_eq!(r_note.title, "Adversarial Complex Runbook 🛡️");
    assert_eq!(
        r_note.content,
        "# Heading 1\n\n```python\ndef test():\n    return 'Hello \\n\\t World'\n```\n\n| Col 1 | Col 2 |\n|---|---|\n| `Val <1>` | **Bold & Italic** |\n\n<script>alert('xss_attempt')</script>"
    );

    restored.lock();
}

// ============================================================================
// 3. Shannon Entropy of Ciphertext & Cryptographic Tamper Defense
// ============================================================================

#[test]
fn test_stress_shannon_entropy_of_ciphertext() {
    let dir = tempdir().expect("tempdir");
    let export_dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "entropy-test", &keystore)
        .expect("create workspace");

    // ------------------------------------------------------------------------
    // Part A: Workspace packed with 100% LOW-ENTROPY data (Zero Bytes)
    // Even when plaintext consists entirely of repeated zeroes, the ciphertext
    // must achieve Shannon entropy > 7.95 bits/byte.
    // ------------------------------------------------------------------------
    let space = secwet.create_space("ZeroSpace", None).unwrap();
    let label = secwet.create_label_in_space("ZeroLabel", None, Some(space.id)).unwrap();
    let item = secwet.create_item(label.id, "ZeroItem", None).unwrap();

    // 256 KiB of pure zero bytes in a file
    let zero_payload = vec![0u8; 256 * 1024];
    secwet.upload_file(item.id, None, "zero.bin", &zero_payload, None).unwrap();

    // 10 repeated zero-value secrets
    for i in 0..10 {
        secwet.create_secret(SecretDraft::new(
            item.id,
            None,
            format!("ZERO_SECRET_{i}"),
            SecretKind::Password,
            "0".repeat(500),
            None,
        )).unwrap();
    }

    let recovery_key = secwet.create_recovery_key(&keystore).unwrap();
    let export_file = export_dir.path().join("low_entropy_plaintext.secwet");
    secwet.export_encrypted(&recovery_key, &export_file).unwrap();

    let envelope_json = std::fs::read_to_string(&export_file).expect("read export");
    let envelope: SecwetExportEnvelope = serde_json::from_str(&envelope_json).expect("parse envelope");

    let ciphertext_bytes = BASE64.decode(envelope.ciphertext.as_bytes()).expect("decode b64 ciphertext");
    assert!(
        ciphertext_bytes.len() >= 256 * 1024,
        "Ciphertext must include encrypted payload"
    );

    let entropy = calculate_shannon_entropy(&ciphertext_bytes);
    println!("Shannon entropy of ciphertext (with 100% zero plaintext): {:.6} bits/byte", entropy);

    // Cryptographic assertion: Shannon entropy must be > 7.95 (maximum theoretical is 8.0)
    assert!(
        entropy > 7.95,
        "XChaCha20Poly1305 ciphertext entropy ({:.6}) must exceed 7.95 bits/byte, proving strong encryption even on zero plaintexts",
        entropy
    );

    // Plaintext non-leakage assertion: raw file must NOT contain zero-value patterns or secrets
    assert!(!envelope_json.contains(&"0".repeat(500)));

    secwet.lock();
}

#[test]
fn test_stress_adversarial_bit_flips_and_tamper_attacks() {
    let dir = tempdir().expect("tempdir");
    let export_dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "tamper-test", &keystore).unwrap();
    let space = secwet.create_space("TamperSpace", None).unwrap();
    let label = secwet.create_label_in_space("TamperLabel", None, Some(space.id)).unwrap();
    let item = secwet.create_item(label.id, "TamperItem", None).unwrap();
    secwet.create_secret(SecretDraft::new(
        item.id,
        None,
        "TAMPER_SECRET",
        SecretKind::Password,
        "secret-to-be-tampered-with-adversarially",
        None,
    )).unwrap();

    let recovery_key = secwet.create_recovery_key(&keystore).unwrap();
    let export_file = export_dir.path().join("original.secwet");
    secwet.export_encrypted(&recovery_key, &export_file).unwrap();
    secwet.lock();

    let envelope_json = std::fs::read_to_string(&export_file).unwrap();
    let envelope_orig: SecwetExportEnvelope = serde_json::from_str(&envelope_json).unwrap();

    let restore_keystore = MemoryStore::new();

    // 1. Bit flip at byte 0 of ciphertext
    {
        let mut tampered = envelope_orig.clone();
        let mut ct = BASE64.decode(tampered.ciphertext.as_bytes()).unwrap();
        ct[0] ^= 0x01;
        tampered.ciphertext = BASE64.encode(&ct);

        let tampered_path = export_dir.path().join("tamper_ct_byte0.secwet");
        std::fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();

        let r = Secwet::restore_from_export(
            &dir.path().join("r1"),
            &tampered_path,
            &recovery_key,
            "dev",
            &restore_keystore,
        );
        assert!(matches!(r, Err(Error::RecoveryFailed)));
    }

    // 2. Bit flip at the LAST byte of ciphertext (which is part of the Poly1305 MAC tag)
    {
        let mut tampered = envelope_orig.clone();
        let mut ct = BASE64.decode(tampered.ciphertext.as_bytes()).unwrap();
        let last = ct.len() - 1;
        ct[last] ^= 0x80;
        tampered.ciphertext = BASE64.encode(&ct);

        let tampered_path = export_dir.path().join("tamper_tag_last.secwet");
        std::fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();

        let r = Secwet::restore_from_export(
            &dir.path().join("r2"),
            &tampered_path,
            &recovery_key,
            "dev",
            &restore_keystore,
        );
        assert!(matches!(r, Err(Error::RecoveryFailed)));
    }

    // 3. Bit flip in Nonce (24-byte nonce)
    {
        let mut tampered = envelope_orig.clone();
        let mut nonce = BASE64.decode(tampered.nonce.as_bytes()).unwrap();
        nonce[12] ^= 0x55;
        tampered.nonce = BASE64.encode(&nonce);

        let tampered_path = export_dir.path().join("tamper_nonce.secwet");
        std::fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();

        let r = Secwet::restore_from_export(
            &dir.path().join("r3"),
            &tampered_path,
            &recovery_key,
            "dev",
            &restore_keystore,
        );
        assert!(matches!(r, Err(Error::RecoveryFailed)));
    }

    // 4. AAD substitution attack: Change workspace secwet_id in envelope metadata
    {
        let mut tampered = envelope_orig.clone();
        tampered.secwet_id = Uuid::new_v4(); // different workspace ID

        let tampered_path = export_dir.path().join("tamper_secwet_id.secwet");
        std::fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();

        let r = Secwet::restore_from_export(
            &dir.path().join("r4"),
            &tampered_path,
            &recovery_key,
            "dev",
            &restore_keystore,
        );
        assert!(matches!(r, Err(Error::RecoveryFailed)));
    }

    // 5. Version downgrade attack: version = 0 or 2
    {
        let mut tampered = envelope_orig.clone();
        tampered.version = 2;

        let tampered_path = export_dir.path().join("tamper_version.secwet");
        std::fs::write(&tampered_path, serde_json::to_vec(&tampered).unwrap()).unwrap();

        let r = Secwet::restore_from_export(
            &dir.path().join("r5"),
            &tampered_path,
            &recovery_key,
            "dev",
            &restore_keystore,
        );
        assert!(matches!(r, Err(Error::RecoveryFailed)));
    }
}

#[test]
fn test_stress_crockford_normalization_extreme() {
    let dir = tempdir().expect("tempdir");
    let export_dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();

    let mut secwet = Secwet::create(dir.path(), "laptop-norm", &keystore).unwrap();
    let key = secwet.create_recovery_key(&keystore).unwrap();
    let key_str = key.expose_secret();

    // 1. Extreme formatting permutations
    // All lowercase
    let lower = key_str.to_lowercase();
    assert!(secwet.verify_recovery_key(&lower).unwrap());

    // Hyphens replaced with spaces, tabs, mixed whitespace
    let mixed_ws = format!("  \t\n{}\r\n  ", key_str.replace('-', "  \t "));
    assert!(secwet.verify_recovery_key(&mixed_ws).unwrap());

    // Multiple hyphens
    let multi_hyphens = key_str.replace('-', "---");
    assert!(secwet.verify_recovery_key(&multi_hyphens).unwrap());

    // Crockford alias permutations:
    // 'O' / 'o' -> '0'
    // 'I' / 'i' / 'L' / 'l' -> '1'
    let mut aliased = key_str.to_string();
    aliased = aliased.replace('0', "O");
    aliased = aliased.replace('1', "L");
    assert!(secwet.verify_recovery_key(&aliased).unwrap());

    let mut aliased_lower = key_str.to_string();
    aliased_lower = aliased_lower.replace('0', "o");
    aliased_lower = aliased_lower.replace('1', "i");
    assert!(secwet.verify_recovery_key(&aliased_lower).unwrap());

    // 2. Illegal Crockford characters must fail cleanly without panic
    let illegal_chars = ["U", "u", "*", "?", "!", "@", "é", "🔐"];
    for bad in &illegal_chars {
        let mut bad_key = key_str.to_string();
        bad_key.replace_range(0..1, bad);
        assert!(!secwet.verify_recovery_key(&bad_key).unwrap_or(false));
    }

    // 3. Export with canonical key and restore using heavily aliased/whitespace key
    let export_path = export_dir.path().join("norm_test.secwet");
    secwet.export_encrypted(&key, &export_path).unwrap();
    secwet.lock();

    let restore_ks = MemoryStore::new();
    let restored = Secwet::restore_from_export(
        &dir.path().join("restored"),
        &export_path,
        &SecretString::from(aliased_lower),
        "restored-laptop",
        &restore_ks,
    );
    assert!(restored.is_ok(), "Restoring with aliased lowercase key must succeed");
}
