//! Adversarial stress test harness for `secwet-proto`.
//!
//! Evaluates serialization, deserialization, determinism, and boundary invariants
//! across all secwet-proto data types with edge cases.

use secwet_proto::*;
use uuid::Uuid;

#[test]
fn test_stress_64kib_secret_value() {
    let project_id = Uuid::new_v4();
    let env_id = Uuid::new_v4();

    // 1. Exact 64 KiB ASCII payload (65,536 bytes)
    let ascii_64kib = "A".repeat(65_536);
    assert_eq!(ascii_64kib.len(), 65_536);
    assert!(validate_secret_value(&ascii_64kib).is_ok());

    let body_ascii = SecretBody::new(
        project_id,
        env_id,
        "MAX_ASCII_SECRET",
        SecretKind::EnvVar,
        &ascii_64kib,
        Some("64KiB ASCII test".to_string()),
    );

    let encoded_ascii = postcard::to_stdvec(&body_ascii).expect("postcard serialize 64KiB ASCII");
    let decoded_ascii: SecretBody =
        postcard::from_bytes(&encoded_ascii).expect("postcard deserialize 64KiB ASCII");
    assert_eq!(decoded_ascii, body_ascii);
    assert_eq!(decoded_ascii.value, ascii_64kib);

    // 2. Exact 64 KiB multi-byte UTF-8 payload (16,384 4-byte emojis = 65,536 bytes)
    let crab = "🦀"; // 4 bytes in UTF-8
    assert_eq!(crab.len(), 4);
    let emoji_64kib = crab.repeat(16_384);
    assert_eq!(emoji_64kib.len(), 65_536);
    assert!(validate_secret_value(&emoji_64kib).is_ok());

    let body_emoji = SecretBody::new(
        project_id,
        env_id,
        "MAX_EMOJI_SECRET",
        SecretKind::Password,
        &emoji_64kib,
        None,
    );

    let encoded_emoji = postcard::to_stdvec(&body_emoji).expect("postcard serialize 64KiB UTF-8");
    let decoded_emoji: SecretBody =
        postcard::from_bytes(&encoded_emoji).expect("postcard deserialize 64KiB UTF-8");
    assert_eq!(decoded_emoji, body_emoji);
    assert_eq!(decoded_emoji.value, emoji_64kib);

    // 3. Boundary failure: 65,537 bytes (1 byte above limit)
    let too_large = "B".repeat(65_537);
    match validate_secret_value(&too_large) {
        Err(ValidationError::TooLong { field, max, actual }) => {
            assert_eq!(field, "secret_value");
            assert_eq!(max, 65_536);
            assert_eq!(actual, 65_537);
        }
        other => panic!("Expected ValidationError::TooLong, got {:?}", other),
    }

    // 4. RecordPayload roundtrip with 64 KiB body
    let payload = RecordPayload::Secret(body_ascii);
    let payload_bytes = payload.to_bytes().expect("RecordPayload to_bytes 64KiB");
    let decoded_payload = RecordPayload::from_bytes(RecordType::Secret, &payload_bytes)
        .expect("RecordPayload from_bytes 64KiB");
    assert_eq!(decoded_payload, payload);

    // 5. RecordEnvelope with 64 KiB ciphertext
    let ciphertext_64kib = vec![0x42u8; 65_536];
    let envelope = RecordEnvelope {
        version: RecordEnvelope::VERSION_V1,
        nonce: [0x77u8; 24],
        ciphertext: ciphertext_64kib.clone(),
    };
    let blob = envelope.to_blob();
    assert_eq!(blob.len(), 1 + 24 + 65_536);
    let decoded_envelope =
        RecordEnvelope::from_blob(&blob).expect("RecordEnvelope from_blob 64KiB");
    assert_eq!(decoded_envelope, envelope);

    // 6. WrappedKey with 64 KiB ciphertext
    let wrapped = WrappedKey {
        enc: [0xAA; 32],
        ciphertext: ciphertext_64kib.clone(),
    };
    let enc_wrapped = postcard::to_stdvec(&wrapped).expect("WrappedKey serialize 64KiB");
    let dec_wrapped: WrappedKey =
        postcard::from_bytes(&enc_wrapped).expect("WrappedKey deserialize 64KiB");
    assert_eq!(dec_wrapped, wrapped);

    // 7. EventEnvelope with 64 KiB ciphertext
    let event_env = EventEnvelope {
        event_id: [1u8; 16],
        secwet_id: [2u8; 16],
        device_id: "DEVICE_TEST".to_string(),
        device_seq: 100,
        key_epoch: 1,
        nonce: [0x55u8; 24],
        ciphertext: ciphertext_64kib,
        scope: None,
    };
    let enc_event_env = postcard::to_stdvec(&event_env).expect("EventEnvelope serialize 64KiB");
    let dec_event_env: EventEnvelope =
        postcard::from_bytes(&enc_event_env).expect("EventEnvelope deserialize 64KiB");
    assert_eq!(dec_event_env, event_env);
}

#[test]
fn test_stress_multiline_strings() {
    let project_id = Uuid::new_v4();
    let env_id = Uuid::new_v4();

    // 1. SSH Private Key PEM with Unix LF (\n)
    let ssh_key = "-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n\
NhAAAAAwEAAQAAAYEAuV3eZ...fake...key...content...==\n\
-----END OPENSSH PRIVATE KEY-----\n";

    // 2. Certificate chain with Windows CRLF (\r\n) and trailing blank lines
    let cert_chain = "-----BEGIN CERTIFICATE-----\r\n\
MIIDdzCCAl+gAwIBAgIET...cert1...\r\n\
-----END CERTIFICATE-----\r\n\
\r\n\
-----BEGIN CERTIFICATE-----\r\n\
MIIDfzCCAm+gAwIBAgIEU...cert2...\r\n\
-----END CERTIFICATE-----\r\n\r\n";

    // 3. Mixed weird whitespace: tabs, form-feeds, embedded NUL bytes
    let mixed_whitespace = "ENV_VAR_1=value1\r\n\tENV_VAR_2=value2\x0C\n\x00NULL_BYTE\n";

    let test_cases = [
        ("SSH_KEY", SecretKind::SshKey, ssh_key),
        ("TLS_CERT", SecretKind::Certificate, cert_chain),
        ("MIXED_WS", SecretKind::EnvVar, mixed_whitespace),
    ];

    for (name, kind, value) in test_cases {
        let body = SecretBody::new(
            project_id,
            env_id,
            name,
            kind,
            value,
            Some("multiline test".to_string()),
        );

        let encoded = postcard::to_stdvec(&body).expect("serialize multiline SecretBody");
        let decoded: SecretBody =
            postcard::from_bytes(&encoded).expect("deserialize multiline SecretBody");

        // Exact byte-for-byte fidelity without line ending normalization
        assert_eq!(decoded.value, value);
        assert_eq!(decoded.value.as_bytes(), value.as_bytes());

        let computed = SecretMeta::compute_value_tail(value);
        let non_ws: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        let expected_tail: String = if non_ws.chars().count() <= 4 {
            non_ws
        } else {
            let count = non_ws.chars().count();
            non_ws.chars().skip(count - 4).collect()
        };
        assert_eq!(computed, expected_tail);
        assert!(computed.chars().count() <= 4);
    }
}

#[test]
fn test_stress_notes_empty_and_boundaries() {
    let project_id = Uuid::new_v4();
    let env_id = Uuid::new_v4();

    // 1. None note
    assert!(validate_secret_note(None).is_ok());
    let body_none = SecretBody::new(
        project_id,
        env_id,
        "NONE_NOTE",
        SecretKind::Password,
        "val",
        None,
    );
    let enc_none = postcard::to_stdvec(&body_none).unwrap();
    let dec_none: SecretBody = postcard::from_bytes(&enc_none).unwrap();
    assert_eq!(dec_none.note, None);

    // 2. Empty string note Some("")
    assert!(validate_secret_note(Some("")).is_ok());
    let body_empty = SecretBody::new(
        project_id,
        env_id,
        "EMPTY_NOTE",
        SecretKind::Password,
        "val",
        Some("".to_string()),
    );
    let enc_empty = postcard::to_stdvec(&body_empty).unwrap();
    let dec_empty: SecretBody = postcard::from_bytes(&enc_empty).unwrap();
    assert_eq!(dec_empty.note, Some("".to_string()));

    // 3. Exactly 500 characters ASCII
    let note_500 = "x".repeat(500);
    assert_eq!(note_500.chars().count(), 500);
    assert!(validate_secret_note(Some(&note_500)).is_ok());

    // 4. Exactly 500 characters multi-byte Unicode (500 emojis = 2,000 bytes)
    let note_500_emoji = "🦀".repeat(500);
    assert_eq!(note_500_emoji.chars().count(), 500);
    assert_eq!(note_500_emoji.len(), 2000);
    assert!(validate_secret_note(Some(&note_500_emoji)).is_ok());

    let body_500_emoji = SecretBody::new(
        project_id,
        env_id,
        "EMOJI_NOTE",
        SecretKind::Password,
        "val",
        Some(note_500_emoji.clone()),
    );
    let enc_500 = postcard::to_stdvec(&body_500_emoji).unwrap();
    let dec_500: SecretBody = postcard::from_bytes(&enc_500).unwrap();
    assert_eq!(dec_500.note, Some(note_500_emoji));

    // 5. 501 characters ASCII -> rejected
    let note_501 = "x".repeat(501);
    match validate_secret_note(Some(&note_501)) {
        Err(ValidationError::TooLong { field, max, actual }) => {
            assert_eq!(field, "secret_note");
            assert_eq!(max, 500);
            assert_eq!(actual, 501);
        }
        other => panic!("Expected ValidationError::TooLong, got {:?}", other),
    }

    // 6. 501 characters emoji -> rejected
    let note_501_emoji = "🦀".repeat(501);
    match validate_secret_note(Some(&note_501_emoji)) {
        Err(ValidationError::TooLong { field, max, actual }) => {
            assert_eq!(field, "secret_note");
            assert_eq!(max, 500);
            assert_eq!(actual, 501);
        }
        other => panic!("Expected ValidationError::TooLong, got {:?}", other),
    }
}

#[test]
fn test_stress_boundary_numbers() {
    let boundary_u32s = [0u32, 1, 2, 255, 65535, u32::MAX - 1, u32::MAX];
    let boundary_u64s = [
        0u64,
        1,
        2,
        255,
        65535,
        u32::MAX as u64,
        u64::MAX - 1,
        u64::MAX,
    ];
    let boundary_i64s = [i64::MIN, i64::MIN + 1, -1, 0, 1, i64::MAX - 1, i64::MAX];

    let secwet_id = [0xFFu8; 16];
    let record_id = [0x00u8; 16];

    // Test RecordAad with extreme u32 key_epoch
    for &epoch in &boundary_u32s {
        let aad = RecordAad::new(&secwet_id, &record_id, RecordType::Secret, epoch);
        let bytes = aad
            .to_bytes()
            .expect("serialize RecordAad with boundary epoch");
        let owned = RecordAadOwned::new(secwet_id, record_id, RecordType::Secret, epoch);
        let owned_bytes = owned.as_borrowed().to_bytes().unwrap();
        assert_eq!(bytes, owned_bytes);

        let decoded_owned: RecordAadOwned =
            postcard::from_bytes(&bytes).expect("deserialize RecordAadOwned");
        assert_eq!(decoded_owned, owned);
        assert_eq!(decoded_owned.key_epoch, epoch);
    }

    // Test RecordMeta with extreme u64 lamport and i64 updated_at
    for &lamport in &boundary_u64s {
        for &updated_at in &boundary_i64s {
            let meta = RecordMeta {
                id: Uuid::nil(),
                lamport,
                origin_device: "DEV_01".to_string(),
                updated_at,
                deleted: true,
            };
            let encoded = postcard::to_stdvec(&meta).expect("serialize RecordMeta");
            let decoded: RecordMeta =
                postcard::from_bytes(&encoded).expect("deserialize RecordMeta");
            assert_eq!(decoded, meta);
        }
    }

    // Test EventEnvelope with boundary device_seq and key_epoch
    for &seq in &boundary_u64s {
        for &epoch in &boundary_u32s {
            let env = EventEnvelope {
                event_id: [0x11; 16],
                secwet_id: [0x22; 16],
                device_id: "DEV_EDGE".to_string(),
                device_seq: seq,
                key_epoch: epoch,
                nonce: [0x33; 24],
                ciphertext: vec![1, 2, 3],
                scope: None,
            };
            let encoded = postcard::to_stdvec(&env).expect("serialize EventEnvelope");
            let decoded: EventEnvelope =
                postcard::from_bytes(&encoded).expect("deserialize EventEnvelope");
            assert_eq!(decoded, env);
        }
    }

    // Test EnvironmentBody with boundary position
    for &pos in &boundary_u32s {
        let env_body = EnvironmentBody::new(Uuid::new_v4(), "staging", pos);
        let encoded = postcard::to_stdvec(&env_body).unwrap();
        let decoded: EnvironmentBody = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, env_body);
        assert_eq!(decoded.position, pos);
    }

    // Test PairingApproval with boundary approved_at
    for &ts in &boundary_i64s {
        let approval = PairingApproval {
            secwet_id: [1u8; 16],
            session_id: [2u8; 16],
            device_id: "DEVICE_PAIR".to_string(),
            sign_pub: [3u8; 32],
            enc_pub: [4u8; 32],
            approved_at: ts,
        };
        let encoded = postcard::to_stdvec(&approval).unwrap();
        let decoded: PairingApproval = postcard::from_bytes(&encoded).unwrap();
        assert_eq!(decoded, approval);
        assert_eq!(decoded.approved_at, ts);
    }
}

#[test]
fn test_stress_utf8_strings_and_validation() {
    // 1. Project name: Non-ASCII UTF-8 trimming and char count boundaries
    let valid_unicode_name = "  🚀 Secwet 安全 🔐  ";
    let trimmed = validate_project_name(valid_unicode_name).expect("valid Unicode project name");
    assert_eq!(trimmed, "🚀 Secwet 安全 🔐");

    // Exact 64 chars of emojis (64 * 4 = 256 bytes)
    let project_64_chars = "🦀".repeat(64);
    assert_eq!(project_64_chars.chars().count(), 64);
    assert_eq!(project_64_chars.len(), 256);
    assert!(validate_project_name(&project_64_chars).is_ok());

    // 65 chars -> rejected
    let project_65_chars = "🦀".repeat(65);
    assert!(validate_project_name(&project_65_chars).is_err());

    // Only whitespace project name
    assert!(validate_project_name(" \t\r\n\u{3000} ").is_err()); // u{3000} is ideographic space

    // 2. Secret name regex validation: ^[A-Za-z_][A-Za-z0-9_.@-]*$
    // Valid cases
    assert!(validate_secret_name("_").is_ok());
    assert!(validate_secret_name("A").is_ok());
    assert!(validate_secret_name("a").is_ok());
    assert!(validate_secret_name("AWS_SECRET_ACCESS_KEY").is_ok());
    assert!(validate_secret_name("db.host-name@service_1").is_ok());
    let max_secret_name = "A".repeat(128);
    assert!(validate_secret_name(&max_secret_name).is_ok());

    // Invalid cases
    assert!(validate_secret_name("").is_err());
    assert!(validate_secret_name("0STARTS_WITH_DIGIT").is_err());
    assert!(validate_secret_name("-STARTS_WITH_DASH").is_err());
    assert!(validate_secret_name(".STARTS_WITH_DOT").is_err());
    assert!(validate_secret_name("@STARTS_WITH_AT").is_err());
    assert!(validate_secret_name("HAS SPACE").is_err());
    assert!(validate_secret_name("HAS$DOLLAR").is_err());
    assert!(validate_secret_name("HAS/SLASH").is_err());
    assert!(validate_secret_name("HAS:COLON").is_err());
    assert!(validate_secret_name("Unicode_🦀").is_err()); // Non-ASCII must be rejected
    assert!(validate_secret_name("Accented_é").is_err()); // Non-ASCII must be rejected
    let too_long_secret_name = "A".repeat(129);
    assert!(validate_secret_name(&too_long_secret_name).is_err());

    // 3. Secret values: ANY UTF-8 is allowed up to 64 KiB
    let complex_utf8_value =
        "Hello 世界! مرحبا بالعالم! 🌍 Здравствуй, мир! \u{200B}\u{FEFF}\0\t\r\n";
    assert!(validate_secret_value(complex_utf8_value).is_ok());
    let body = SecretBody::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "COMPLEX_UTF8",
        SecretKind::Password,
        complex_utf8_value,
        None,
    );
    let encoded = postcard::to_stdvec(&body).unwrap();
    let decoded: SecretBody = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(decoded.value, complex_utf8_value);
}

#[test]
fn test_postcard_determinism_and_canonical_aad() {
    let secwet_id = [0x55u8; 16];
    let record_id = [0xAAu8; 16];

    // RecordAad determinism
    let aad = RecordAad::new(&secwet_id, &record_id, RecordType::Secret, 42);
    let baseline = aad.to_bytes().expect("serialize baseline");

    for _ in 0..500 {
        let repeated = aad.to_bytes().expect("serialize repeated");
        assert_eq!(
            repeated, baseline,
            "RecordAad serialization must be 100% deterministic"
        );
    }

    // RecordAadOwned vs borrowed RecordAad equivalence
    let owned = RecordAadOwned::new(secwet_id, record_id, RecordType::Secret, 42);
    assert_eq!(
        owned.as_borrowed().to_bytes().unwrap(),
        baseline,
        "RecordAadOwned borrowed bytes must match RecordAad bytes"
    );

    // Tampering any field produces different postcard bytes
    let tampered_type = RecordAad::new(&secwet_id, &record_id, RecordType::Project, 42)
        .to_bytes()
        .unwrap();
    assert_ne!(tampered_type, baseline);

    let tampered_epoch = RecordAad::new(&secwet_id, &record_id, RecordType::Secret, 43)
        .to_bytes()
        .unwrap();
    assert_ne!(tampered_epoch, baseline);

    let mut tampered_secwet_id = secwet_id;
    tampered_secwet_id[0] ^= 0x01;
    let tampered_secwet = RecordAad::new(&tampered_secwet_id, &record_id, RecordType::Secret, 42)
        .to_bytes()
        .unwrap();
    assert_ne!(tampered_secwet, baseline);

    // EventAad determinism & equivalence
    let event_id = [0x12u8; 16];
    let event_aad = EventAad {
        event_id: &event_id,
        secwet_id: &secwet_id,
        device_id: "DEVICE_CANONICAL",
        device_seq: 999,
        key_epoch: 5,
    };
    let event_baseline = postcard::to_stdvec(&event_aad).expect("serialize event_aad");
    for _ in 0..500 {
        let repeated = postcard::to_stdvec(&event_aad).expect("serialize event_aad repeated");
        assert_eq!(repeated, event_baseline);
    }

    let event_owned = EventAadOwned {
        event_id,
        secwet_id,
        device_id: "DEVICE_CANONICAL".to_string(),
        device_seq: 999,
        key_epoch: 5,
    };
    let event_owned_bytes = postcard::to_stdvec(&event_owned.as_borrowed()).unwrap();
    assert_eq!(event_owned_bytes, event_baseline);

    // KeyWrapInfo determinism & equivalence
    let wrap_info = KeyWrapInfo {
        purpose: "master-key",
        secwet_id: &secwet_id,
        key_epoch: 1,
        recipient_device_id: "DEVICE_RECIPIENT",
    };
    let wrap_baseline = postcard::to_stdvec(&wrap_info).expect("serialize wrap_info");
    for _ in 0..500 {
        let repeated = postcard::to_stdvec(&wrap_info).expect("serialize wrap_info repeated");
        assert_eq!(repeated, wrap_baseline);
    }

    let wrap_owned = KeyWrapInfoOwned {
        purpose: "master-key".to_string(),
        secwet_id,
        key_epoch: 1,
        recipient_device_id: "DEVICE_RECIPIENT".to_string(),
    };
    let wrap_owned_bytes = postcard::to_stdvec(&wrap_owned.as_borrowed()).unwrap();
    assert_eq!(wrap_owned_bytes, wrap_baseline);
}

#[test]
fn test_all_secwet_proto_structs_roundtrip() {
    // 1. RecordType try_from exhaustive check
    for b in 0u8..=255 {
        match b {
            1 => assert_eq!(RecordType::try_from(b), Ok(RecordType::Label)),
            2 => assert_eq!(RecordType::try_from(b), Ok(RecordType::Item)),
            3 => assert_eq!(RecordType::try_from(b), Ok(RecordType::Environment)),
            4 => assert_eq!(RecordType::try_from(b), Ok(RecordType::Secret)),
            5 => assert_eq!(RecordType::try_from(b), Ok(RecordType::File)),
            6 => assert_eq!(RecordType::try_from(b), Ok(RecordType::Note)),
            7 => assert_eq!(RecordType::try_from(b), Ok(RecordType::Space)),
            other => assert_eq!(RecordType::try_from(other), Err(other)),
        }
    }

    // 2. SecretKind parsing and serialization
    let all_kinds = [
        ("password", SecretKind::Password),
        ("api_key", SecretKind::ApiKey),
        ("access_token", SecretKind::AccessToken),
        ("env_var", SecretKind::EnvVar),
        ("ssh_key", SecretKind::SshKey),
        ("certificate", SecretKind::Certificate),
        ("codes", SecretKind::Codes),
    ];
    for (s, kind) in all_kinds {
        assert_eq!(kind.as_str(), s);
        assert_eq!(s.parse::<SecretKind>().unwrap(), kind);
        assert_eq!(format!("{}", kind), s);
        let enc = postcard::to_stdvec(&kind).unwrap();
        let dec: SecretKind = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, kind);
    }
    assert!("not_a_kind".parse::<SecretKind>().is_err());

    // 3. ProjectBody & EnvironmentBody & New Bodies
    let proj = ProjectBody::new("my-project");
    let enc_proj = postcard::to_stdvec(&proj).unwrap();
    let dec_proj: ProjectBody = postcard::from_bytes(&enc_proj).unwrap();
    assert_eq!(dec_proj, proj);

    let env = EnvironmentBody::new(Uuid::new_v4(), "production", 1);
    let enc_env = postcard::to_stdvec(&env).unwrap();
    let dec_env: EnvironmentBody = postcard::from_bytes(&enc_env).unwrap();
    assert_eq!(dec_env, env);

    let label_body = LabelBody::new("Work", 0, None);
    let item_body = ItemBody::new(Uuid::new_v4(), "Item A", None, 0);
    let file_meta = FileMetaBody::new(
        Uuid::new_v4(),
        None,
        "test.txt",
        100,
        "text/plain",
        [0u8; 32],
    );
    let file_payload = FilePayload::new(file_meta, vec![1, 2, 3]);
    let note_body = NoteBody::new(Uuid::new_v4(), None, "Note Title", "Note Content", 0);

    // 4. RecordPayload all variants
    let payload_label = RecordPayload::Label(label_body.clone());
    let payload_item = RecordPayload::Item(item_body.clone());
    let _payload_proj = RecordPayload::Project(proj.clone());
    let payload_env = RecordPayload::Environment(env.clone());
    let sec_body = SecretBody::new(
        Uuid::new_v4(),
        Some(Uuid::new_v4()),
        "KEY",
        SecretKind::ApiKey,
        "secret-value",
        None,
    );
    let payload_sec = RecordPayload::Secret(sec_body.clone());
    let payload_file = RecordPayload::File(file_payload.clone());
    let payload_note = RecordPayload::Note(note_body.clone());

    for (p, expected_type) in [
        (payload_label, RecordType::Label),
        (payload_item, RecordType::Item),
        (payload_env, RecordType::Environment),
        (payload_sec, RecordType::Secret),
        (payload_file, RecordType::File),
        (payload_note, RecordType::Note),
    ] {
        assert_eq!(p.record_type(), expected_type);
        let b = p.to_bytes().unwrap();
        let decoded = RecordPayload::from_bytes(expected_type, &b).unwrap();
        assert_eq!(decoded, p);
    }

    // 5. SignedEvent with full 64-byte signature test
    let signature_patterns = [[0x00u8; 64], [0xFFu8; 64], {
        let mut arr = [0u8; 64];
        for (i, item) in arr.iter_mut().enumerate() {
            *item = i as u8;
        }
        arr
    }];

    for sig in signature_patterns {
        let signed_event = SignedEvent {
            envelope: EventEnvelope {
                event_id: [1u8; 16],
                secwet_id: [2u8; 16],
                device_id: "DEV_TEST".to_string(),
                device_seq: 42,
                key_epoch: 1,
                nonce: [3u8; 24],
                ciphertext: vec![10, 20, 30],
                scope: None,
            },
            signature: sig,
        };

        let enc = postcard::to_stdvec(&signed_event).unwrap();
        let dec: SignedEvent = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, signed_event);
        assert_eq!(dec.signature, sig);
    }

    // 6. EventBody all variants
    let event_upsert = EventBody::Upsert {
        record_id: Uuid::new_v4(),
        record_type: RecordType::Secret as u8,
        lamport: 1234,
        body: vec![1, 2, 3, 4],
    };
    let enc_upsert = postcard::to_stdvec(&event_upsert).unwrap();
    let dec_upsert: EventBody = postcard::from_bytes(&enc_upsert).unwrap();
    assert_eq!(dec_upsert, event_upsert);

    let event_delete = EventBody::Delete {
        record_id: Uuid::new_v4(),
        record_type: RecordType::Project as u8,
        lamport: 1235,
    };
    let enc_delete = postcard::to_stdvec(&event_delete).unwrap();
    let dec_delete: EventBody = postcard::from_bytes(&enc_delete).unwrap();
    assert_eq!(dec_delete, event_delete);

    let event_rename = EventBody::DeviceRenamed {
        device_id: "DEV_X".to_string(),
        name: "MacBook Pro".to_string(),
    };
    let enc_rename = postcard::to_stdvec(&event_rename).unwrap();
    let dec_rename: EventBody = postcard::from_bytes(&enc_rename).unwrap();
    assert_eq!(dec_rename, event_rename);

    // 7. RelayErrorCode all variants
    let all_relay_codes = [
        RelayErrorCode::Exists,
        RelayErrorCode::NotEntitled,
        RelayErrorCode::Expired,
        RelayErrorCode::AlreadyJoined,
        RelayErrorCode::DeviceLimit,
        RelayErrorCode::BadSignature,
        RelayErrorCode::Pending,
        RelayErrorCode::CannotRevokeSelf,
        RelayErrorCode::EpochConflict,
        RelayErrorCode::SeqGap,
        RelayErrorCode::Revoked,
        RelayErrorCode::CursorExpired,
        RelayErrorCode::NotFound,
        RelayErrorCode::Internal,
        RelayErrorCode::ReusedNonce,
        RelayErrorCode::ExpiredTimestamp,
        RelayErrorCode::Unauthorized,
        RelayErrorCode::RateLimited,
    ];

    for code in all_relay_codes {
        let err = RelayError {
            error: RelayErrorDetail {
                code,
                message: format!("Error code test: {:?}", code),
            },
            revocation: None,
        };
        let enc = postcard::to_stdvec(&err).unwrap();
        let dec: RelayError = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, err);
        assert_eq!(dec.error.code, code);
    }

    // 8. SecwetStatus variants
    let id = Uuid::new_v4();
    for st in [
        SecwetStatus::Uninitialized,
        SecwetStatus::Locked { secwet_id: id },
        SecwetStatus::Unlocked { secwet_id: id },
    ] {
        let enc = postcard::to_stdvec(&st).unwrap();
        let dec: SecwetStatus = postcard::from_bytes(&enc).unwrap();
        assert_eq!(dec, st);
    }

    // 9. EnvironmentView & ProjectView
    let env_view = EnvironmentView {
        id: Uuid::new_v4(),
        project_id: id,
        name: "Production".to_string(),
        position: 0,
        secret_count: 42,
    };
    let proj_view = ProjectView {
        id,
        name: "Main".to_string(),
        environments: vec![env_view],
    };
    let enc_proj_view = postcard::to_stdvec(&proj_view).unwrap();
    let dec_proj_view: ProjectView = postcard::from_bytes(&enc_proj_view).unwrap();
    assert_eq!(dec_proj_view, proj_view);
}

#[test]
fn test_security_redaction_and_tail_adversarial() {
    let sensitive_value = "SUPER_SECRET_TOKEN_XYZ_9999";
    let body = SecretBody::new(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "SECRET_KEY",
        SecretKind::ApiKey,
        sensitive_value,
        Some("sensitive note".to_string()),
    );

    // Standard Debug formatting
    let debug_normal = format!("{:?}", body);
    assert!(debug_normal.contains("[redacted]"));
    assert!(!debug_normal.contains(sensitive_value));

    // Alternate pretty-printed Debug formatting
    let debug_pretty = format!("{:#?}", body);
    assert!(debug_pretty.contains("[redacted]"));
    assert!(!debug_pretty.contains(sensitive_value));

    // Inside RecordPayload
    let payload = RecordPayload::Secret(body);
    let debug_payload = format!("{:?}", payload);
    assert!(debug_payload.contains("[redacted]"));
    assert!(!debug_payload.contains(sensitive_value));

    // SecretMeta value tail calculation edge cases
    // Edge case 1: pure whitespace
    assert_eq!(SecretMeta::compute_value_tail("    \n\t   "), "");
    // Edge case 2: less than 4 characters
    assert_eq!(SecretMeta::compute_value_tail("ab"), "ab");
    // Edge case 3: exactly 4 characters
    assert_eq!(SecretMeta::compute_value_tail("abcd"), "abcd");
    // Edge case 4: characters interspersed with whitespace
    assert_eq!(SecretMeta::compute_value_tail(" a  b  c  d  e "), "bcde");
    // Edge case 5: Unicode emojis
    assert_eq!(SecretMeta::compute_value_tail("🌟🔥🚀🦀🎉"), "🔥🚀🦀🎉");
}
