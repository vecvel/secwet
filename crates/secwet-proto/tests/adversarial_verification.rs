//! Adversarial test harness and stress suite for secwet-proto.
//!
//! Validates:
//! 1. SecretBody Debug formatting plaintext leakage resistance.
//! 2. Postcard corrupted and truncated buffer handling for all wire/storage types.
//! 3. SecretMeta::compute_value_tail edge cases (length < 4, whitespace patterns, Unicode, large inputs).
//! 4. Field validation boundary conditions.

use secwet_proto::*;
use uuid::Uuid;

// ============================================================================
// 1. SecretBody Debug Formatting Verification
// ============================================================================

#[test]
fn challenge_secret_body_debug_never_leaks_plaintext() {
    // PRNG using simple xorshift64 for reproducible canary generation
    let mut state: u64 = 0xDEADBEEFCAFE;
    let mut next_u64 = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };

    let kinds = [
        SecretKind::Password,
        SecretKind::ApiKey,
        SecretKind::AccessToken,
        SecretKind::EnvVar,
        SecretKind::SshKey,
        SecretKind::Certificate,
    ];

    for i in 0..500 {
        let rand_val = next_u64();
        let secret_canary = format!("SUPER_SECRET_TOKEN_{:016x}_{}", rand_val, i);
        let project_id = Uuid::new_v4();
        let env_id = Uuid::new_v4();
        let name = format!("SECRET_KEY_{}", i);
        let note = Some("Non-sensitive metadata note".to_string());
        let kind = kinds[i % kinds.len()];

        let body = SecretBody::new(
            project_id,
            env_id,
            &name,
            kind,
            &secret_canary,
            note.clone(),
        );

        // 1. Standard {:?} formatting
        let debug_compact = format!("{:?}", body);
        assert!(
            !debug_compact.contains(&secret_canary),
            "Compact Debug output leaked secret value: {}",
            debug_compact
        );
        assert!(
            debug_compact.contains("[redacted]"),
            "Compact Debug output must contain [redacted]"
        );

        // 2. Pretty-print {:#?} formatting
        let debug_pretty = format!("{:#?}", body);
        assert!(
            !debug_pretty.contains(&secret_canary),
            "Pretty Debug output leaked secret value: {}",
            debug_pretty
        );
        assert!(
            debug_pretty.contains("[redacted]"),
            "Pretty Debug output must contain [redacted]"
        );

        // 3. Wrapped in RecordPayload
        let payload = RecordPayload::Secret(body.clone());
        let payload_compact = format!("{:?}", payload);
        assert!(
            !payload_compact.contains(&secret_canary),
            "RecordPayload compact Debug leaked secret value"
        );
        assert!(payload_compact.contains("[redacted]"));

        let payload_pretty = format!("{:#?}", payload);
        assert!(
            !payload_pretty.contains(&secret_canary),
            "RecordPayload pretty Debug leaked secret value"
        );
        assert!(payload_pretty.contains("[redacted]"));

        // 4. Wrapped in collections / options
        let vec_debug = format!("{:?}", vec![body.clone()]);
        assert!(!vec_debug.contains(&secret_canary));
        assert!(vec_debug.contains("[redacted]"));

        let opt_debug = format!("{:?}", Some(body.clone()));
        assert!(!opt_debug.contains(&secret_canary));
        assert!(opt_debug.contains("[redacted]"));
    }
}

#[test]
fn challenge_secret_body_debug_special_secret_values() {
    let special_values = [
        "",                                      // empty
        "   ",                                   // spaces only
        "\n\r\t",                                // whitespace controls
        "\"quotes\" and \\backslashes\\",        // escaping chars
        "format_{}_and_{:?}_and_{#?}",           // format specifiers
        "null\0byte\0injection",                 // null bytes
        "🦀🔑🔒🛡️⚡️",                            // unicode emojis
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE", // multiline certificates
        "SELECT * FROM secrets WHERE 1=1;",      // SQL-like syntax
        "<script>alert('xss')</script>",         // HTML/script
        &"A".repeat(65_536),                     // 64 KiB maximal value
    ];

    for val in special_values {
        let body = SecretBody::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "DB_SECRET",
            SecretKind::Password,
            val,
            None,
        );

        let debug_str = format!("{:?}", body);
        let debug_pretty = format!("{:#?}", body);

        // Even with special characters, value field is strictly "[redacted]"
        assert!(debug_str.contains("value: \"[redacted]\""));
        assert!(debug_pretty.contains("\"[redacted]\""));

        if !val.is_empty() && val.len() > 10 {
            assert!(
                !debug_str.contains(val),
                "Debug output leaked non-trivial secret value: {:?}",
                val
            );
        }
    }
}

// ============================================================================
// 2. Postcard Corrupted & Truncated Buffer Verification
// ============================================================================

#[test]
fn challenge_record_envelope_framing_corruptions() {
    // 1. Buffer shorter than MIN_BLOB_LEN (41 bytes)
    for len in 0..RecordEnvelope::MIN_BLOB_LEN {
        let short_buffer = vec![1u8; len];
        let res = RecordEnvelope::from_blob(&short_buffer);
        assert!(
            matches!(res, Err(EnvelopeError::BlobTooShort(l)) if l == len),
            "Expected BlobTooShort for len {}",
            len
        );
    }

    // 2. Unsupported version
    for v in [0u8, 2, 3, 42, 255] {
        let buffer = vec![v; 50];
        let res = RecordEnvelope::from_blob(&buffer);
        assert!(
            matches!(res, Err(EnvelopeError::UnsupportedVersion(bad_v)) if bad_v == v),
            "Expected UnsupportedVersion for version {}",
            v
        );
    }

    // 3. Minimum valid blob (version 1 + 24 bytes nonce + 16 bytes tag)
    let mut min_blob = vec![0u8; 41];
    min_blob[0] = RecordEnvelope::VERSION_V1;
    let parsed = RecordEnvelope::from_blob(&min_blob).expect("41 byte blob must parse");
    assert_eq!(parsed.version, 1);
    assert_eq!(parsed.nonce, [0u8; 24]);
    assert_eq!(parsed.ciphertext.len(), 16);
}

#[test]
fn challenge_postcard_truncation_fuzzing_all_types() {
    let project_body = ProjectBody::new("production-cluster");
    let env_body = EnvironmentBody::new(Uuid::new_v4(), "Staging", 1);
    let secret_body = SecretBody::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "API_TOKEN",
        SecretKind::ApiKey,
        "super-secret-token",
        Some("Production key".to_string()),
    );
    let aad_owned = RecordAadOwned::new([1u8; 16], [2u8; 16], RecordType::Secret, 5);
    let envelope = RecordEnvelope {
        version: 1,
        nonce: [3u8; 24],
        ciphertext: vec![4u8; 32],
    };
    let event_aad = EventAadOwned {
        event_id: [10u8; 16],
        vault_id: [11u8; 16],
        device_id: "DEVICE_X".to_string(),
        device_seq: 100,
        key_epoch: 2,
    };
    let signed_event = SignedEvent {
        envelope: EventEnvelope {
            event_id: [20u8; 16],
            vault_id: [21u8; 16],
            device_id: "DEVICE_Y".to_string(),
            device_seq: 42,
            key_epoch: 1,
            nonce: [22u8; 24],
            ciphertext: vec![99u8; 48],
        },
        signature: [77u8; 64],
    };
    let key_wrap = KeyWrapInfoOwned {
        purpose: "vault-key".to_string(),
        vault_id: [30u8; 16],
        key_epoch: 1,
        recipient_device_id: "DEV_RECIPIENT".to_string(),
    };
    let wrapped_key = WrappedKey {
        enc: [40u8; 32],
        ciphertext: vec![41u8; 48],
    };
    let pairing = PairingApproval {
        vault_id: [50u8; 16],
        session_id: [51u8; 16],
        device_id: "DEV_APPROVED".to_string(),
        sign_pub: [52u8; 32],
        enc_pub: [53u8; 32],
        approved_at: 1700000000,
    };
    let relay_err = RelayError {
        error: RelayErrorDetail {
            code: RelayErrorCode::DeviceLimit,
            message: "Limit reached".to_string(),
        },
    };

    // Helper macro to verify every prefix of an encoded message returns an Err, never panics
    macro_rules! test_truncation {
        ($val:expr, $type:ty) => {{
            let encoded = postcard::to_stdvec(&$val).expect("Serialization must succeed");
            for len in 0..encoded.len() {
                let truncated = &encoded[..len];
                let res: Result<$type, _> = postcard::from_bytes(truncated);
                assert!(
                    res.is_err(),
                    "Expected truncation at length {}/{} to fail for {}",
                    len,
                    encoded.len(),
                    stringify!($type)
                );
            }
        }};
    }

    test_truncation!(project_body, ProjectBody);
    test_truncation!(env_body, EnvironmentBody);
    test_truncation!(secret_body, SecretBody);
    test_truncation!(aad_owned, RecordAadOwned);
    test_truncation!(envelope, RecordEnvelope);
    test_truncation!(event_aad, EventAadOwned);
    test_truncation!(signed_event, SignedEvent);
    test_truncation!(key_wrap, KeyWrapInfoOwned);
    test_truncation!(wrapped_key, WrappedKey);
    test_truncation!(pairing, PairingApproval);
    test_truncation!(relay_err, RelayError);
}

#[test]
fn challenge_record_payload_from_bytes_corrupted_inputs() {
    let mut state: u64 = 0xCAFEBABE1234;
    let mut next_u8 = || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        (state & 0xFF) as u8
    };

    let record_types = [
        RecordType::Project,
        RecordType::Environment,
        RecordType::Secret,
    ];

    // 1. Completely empty slice
    for rt in record_types {
        assert!(
            RecordPayload::from_bytes(rt, &[]).is_err(),
            "Empty slice must fail"
        );
    }

    // 2. Fuzz with random byte slices of lengths 1..128
    for rt in record_types {
        for len in 1..=64 {
            let garbage: Vec<u8> = (0..len).map(|_| next_u8()).collect();
            // It either safely fails with Err, or if by astronomically rare chance it deserializes, it must not panic
            let _ = RecordPayload::from_bytes(rt, &garbage);
        }
    }
}

#[test]
fn challenge_signed_event_signature_bytes_visitor_robustness() {
    // Test custom signature_bytes visitor with invalid lengths
    let envelope = EventEnvelope {
        event_id: [1u8; 16],
        vault_id: [2u8; 16],
        device_id: "DEV_TEST".to_string(),
        device_seq: 1,
        key_epoch: 1,
        nonce: [3u8; 24],
        ciphertext: vec![4u8; 16],
    };

    let valid_event = SignedEvent {
        envelope: envelope.clone(),
        signature: [9u8; 64],
    };
    let encoded = postcard::to_stdvec(&valid_event).unwrap();

    // Verify valid decode
    let decoded: SignedEvent = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(decoded, valid_event);

    // Corrupt the signature length / byte stream at various points
    for i in (encoded.len() - 70)..encoded.len() {
        let mut corrupted = encoded.clone();
        corrupted[i] ^= 0xFF;
        // Should not panic, should return Err or parsed (if only signature contents changed)
        let _ = postcard::from_bytes::<SignedEvent>(&corrupted);
    }
}

// ============================================================================
// 3. SecretMeta::compute_value_tail Edge Cases
// ============================================================================

#[test]
fn challenge_value_tail_less_than_4_chars() {
    // 0 characters
    assert_eq!(SecretMeta::compute_value_tail(""), "");

    // 1 character
    assert_eq!(SecretMeta::compute_value_tail("a"), "a");
    assert_eq!(SecretMeta::compute_value_tail(" 1 "), "1");
    assert_eq!(SecretMeta::compute_value_tail("\t\n\r x \r\n"), "x");

    // 2 characters
    assert_eq!(SecretMeta::compute_value_tail("ab"), "ab");
    assert_eq!(SecretMeta::compute_value_tail("  a  b  "), "ab");

    // 3 characters
    assert_eq!(SecretMeta::compute_value_tail("abc"), "abc");
    assert_eq!(SecretMeta::compute_value_tail(" a b c "), "abc");
}

#[test]
fn challenge_value_tail_whitespace_variations() {
    // Whitespace only
    assert_eq!(SecretMeta::compute_value_tail("    "), "");
    assert_eq!(SecretMeta::compute_value_tail("\t\t\t"), "");
    assert_eq!(SecretMeta::compute_value_tail("\r\n\r\n"), "");
    assert_eq!(SecretMeta::compute_value_tail("  \t \n \r  "), "");

    // Unicode whitespace
    let unicode_spaces = "\u{00A0}\u{2000}\u{2001}\u{2002}\u{2003}\u{2004}\u{2005}\u{2006}\u{2007}\u{2008}\u{2009}\u{200A}\u{202F}\u{205F}\u{3000}";
    assert_eq!(
        SecretMeta::compute_value_tail(unicode_spaces),
        "",
        "All Unicode whitespace characters must be stripped"
    );

    let unicode_wrapped = format!("{}1234{}", unicode_spaces, unicode_spaces);
    assert_eq!(SecretMeta::compute_value_tail(&unicode_wrapped), "1234");
}

#[test]
fn challenge_value_tail_trailing_and_interleaved_whitespace() {
    // Trailing whitespace
    assert_eq!(
        SecretMeta::compute_value_tail("secret_token_1234   "),
        "1234"
    );
    assert_eq!(SecretMeta::compute_value_tail("1234\n\n\n"), "1234");
    assert_eq!(SecretMeta::compute_value_tail("1234\t\t"), "1234");

    // Interleaved whitespace
    assert_eq!(
        SecretMeta::compute_value_tail("s e c r e t 1 2 3 4"),
        "1234"
    );
    assert_eq!(SecretMeta::compute_value_tail("1 2 3 4 5"), "2345");
}

#[test]
fn challenge_value_tail_unicode_multibyte_safety() {
    // Greek/Cyrillic (2-byte UTF-8 per char)
    // 5 chars -> should retain last 4
    assert_eq!(SecretMeta::compute_value_tail("αβγδε"), "βγδε");
    assert_eq!(SecretMeta::compute_value_tail("абвгде"), "вгде");

    // Emojis (4-byte UTF-8 per codepoint)
    // 5 emojis -> should retain last 4 emojis without slicing mid-codepoint
    assert_eq!(SecretMeta::compute_value_tail("😀😃😄😁😆"), "😃😄😁😆");

    // Mixed ASCII, multibyte, and whitespace
    let mixed = "  🦀 key: 🗝️ 1234  ";
    assert_eq!(SecretMeta::compute_value_tail(mixed), "1234");
}

#[test]
fn challenge_value_tail_maximum_length_pressure() {
    // 64 KiB of spaces
    let huge_spaces = " ".repeat(65_536);
    assert_eq!(SecretMeta::compute_value_tail(&huge_spaces), "");

    // 64 KiB of 'x'
    let huge_x = "x".repeat(65_536);
    assert_eq!(SecretMeta::compute_value_tail(&huge_x), "xxxx");

    // 65,532 spaces followed by 'abcd'
    let leading_spaces = format!("{}abcd", " ".repeat(65_532));
    assert_eq!(SecretMeta::compute_value_tail(&leading_spaces), "abcd");

    // 'abcd' followed by 65,532 spaces
    let trailing_spaces = format!("abcd{}", " ".repeat(65_532));
    assert_eq!(SecretMeta::compute_value_tail(&trailing_spaces), "abcd");
}

// ============================================================================
// 4. Boundary Validation Stress Tests
// ============================================================================

#[test]
fn challenge_field_validation_boundaries() {
    // Project Name: 1..=64 chars after trim
    assert!(validate_project_name("").is_err());
    assert!(validate_project_name("   ").is_err());
    assert!(validate_project_name(&"a".repeat(64)).is_ok());
    assert!(validate_project_name(&"a".repeat(65)).is_err());
    // Unicode multi-byte chars count as characters, not bytes
    let unicode_64 = "α".repeat(64); // 64 chars, 128 bytes
    assert_eq!(validate_project_name(&unicode_64).unwrap(), unicode_64);
    let unicode_65 = "α".repeat(65);
    assert!(validate_project_name(&unicode_65).is_err());

    // Secret Name: ^[A-Za-z_][A-Za-z0-9_.@-]*$, 1..=128 chars
    assert!(validate_secret_name("").is_err());
    assert!(validate_secret_name("a").is_ok());
    assert!(validate_secret_name("_").is_ok());
    assert!(validate_secret_name("1").is_err());
    assert!(validate_secret_name(".leading_dot").is_err());
    assert!(validate_secret_name("-leading_dash").is_err());
    assert!(validate_secret_name("@leading_at").is_err());
    assert!(validate_secret_name("valid.name-with@all_symbols.123").is_ok());
    assert!(validate_secret_name(&format!("A{}", "0".repeat(127))).is_ok()); // 128 chars
    assert!(validate_secret_name(&format!("A{}", "0".repeat(128))).is_err()); // 129 chars

    // Disallowed characters
    for forbidden in [
        " ", "\t", "/", "\\", ":", ";", "=", "+", "*", "!", "?", "#", "$", "%",
    ] {
        assert!(
            validate_secret_name(&format!("SECRET_{}_NAME", forbidden)).is_err(),
            "Forbidden character '{}' should fail",
            forbidden
        );
    }

    // Secret Value: 0..=65,536 bytes
    assert!(validate_secret_value("").is_ok());
    assert!(validate_secret_value(&"v".repeat(65_536)).is_ok());
    assert!(validate_secret_value(&"v".repeat(65_537)).is_err());

    // Secret Note: 0..=500 chars
    assert!(validate_secret_note(None).is_ok());
    assert!(validate_secret_note(Some("")).is_ok());
    assert!(validate_secret_note(Some(&"n".repeat(500))).is_ok());
    assert!(validate_secret_note(Some(&"n".repeat(501))).is_err());
    let unicode_note_500 = "🦀".repeat(500); // 500 chars, 2000 bytes
    assert!(validate_secret_note(Some(&unicode_note_500)).is_ok());
    let unicode_note_501 = "🦀".repeat(501);
    assert!(validate_secret_note(Some(&unicode_note_501)).is_err());
}
