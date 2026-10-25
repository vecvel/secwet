//! Empirical Adversarial Challenger Test Suite for `secwet-proto`.
//!
//! Written by M1 Challenger 1: Adversarial Bug Finder (Protocol & Serialization).
//!
//! Objectives:
//! 1. Fuzz / test invalid discriminators (`RecordType::try_from(0)`, `7`, `255`, and exhaustive 0..=255).
//! 2. Postcard serialization roundtrip with extreme payloads:
//!    - 0-byte strings
//!    - 64 KiB secrets
//!    - multi-line secrets
//!    - multibyte UTF-8 (emojis, CJK, RTL, ZWJ)
//!    - null characters ('\0')
//!    - 50 MiB file limits
//! 3. `RecordAad` canonical Postcard serialization:
//!    - Bit-level tampering of every single byte
//!    - Truncation fuzzing
//!    - Trailing bytes injection
//!    - Canonical determinism
//! 4. Text helpers (`extract_plain_text`, `snippet_from_content`):
//!    - Malicious HTML & XSS strings
//!    - Deeply nested tags
//!    - Unclosed / malformed tags
//!    - Attribute variants (<p class="x">, <br />, <li class="y">)
//!    - HTML entities, entity nesting, incomplete entities
//!    - Boundary conditions for snippet_from_content (max_chars = 0, 1, multibyte)

use secwet_proto::*;
use uuid::Uuid;

// ============================================================================
// 1. Invalid Discriminators & Taxonomy Fuzzing
// ============================================================================

#[test]
fn test_record_type_exhaustive_u8_space() {
    let valid_discriminators: std::collections::HashMap<u8, RecordType> = [
        (1u8, RecordType::Label),
        (2, RecordType::Item),
        (3, RecordType::Environment),
        (4, RecordType::Secret),
        (5, RecordType::File),
        (6, RecordType::Note),
    ]
    .into_iter()
    .collect();

    for b in 0u8..=255 {
        if let Some(&expected) = valid_discriminators.get(&b) {
            let res = RecordType::try_from(b);
            assert_eq!(
                res,
                Ok(expected),
                "Valid discriminator {} failed to parse",
                b
            );
            assert_eq!(u8::from(expected), b);
        } else {
            let res = RecordType::try_from(b);
            assert_eq!(
                res,
                Err(b),
                "Invalid discriminator {} unexpectedly succeeded: {:?}",
                b,
                res
            );
        }
    }

    // Explicitly assert on prompt's highlighted edge cases: 0, 7, 255
    assert_eq!(RecordType::try_from(0), Err(0));
    assert_eq!(RecordType::try_from(7), Err(7));
    assert_eq!(RecordType::try_from(255), Err(255));
}

#[test]
fn test_record_type_postcard_wire_representation() {
    // Postcard serializes unit enums by variant index (0..5)
    for (rt, expected_name) in [
        (RecordType::Label, "label"),
        (RecordType::Item, "item"),
        (RecordType::Environment, "environment"),
        (RecordType::Secret, "secret"),
        (RecordType::File, "file"),
        (RecordType::Note, "note"),
    ] {
        assert_eq!(rt.as_str(), expected_name);
        let enc = postcard::to_stdvec(&rt).expect("serialize RecordType");
        let dec: RecordType = postcard::from_bytes(&enc).expect("deserialize RecordType");
        assert_eq!(dec, rt);
    }

    // Deserializing invalid variant indices (>= 6) via postcard must fail cleanly without panics
    for invalid_var_idx in 6u8..=255 {
        let bad_bytes = [invalid_var_idx];
        let res: Result<RecordType, _> = postcard::from_bytes(&bad_bytes);
        assert!(
            res.is_err(),
            "Postcard must reject invalid enum variant index {}",
            invalid_var_idx
        );
    }

    // Empty buffer must fail
    assert!(postcard::from_bytes::<RecordType>(&[]).is_err());
}

#[test]
fn test_record_aad_from_raw_type_invariants() {
    let vault_id = [0x11u8; 16];
    let record_id = [0x22u8; 16];

    // Verify raw types for legacy and future discriminators
    for raw in [0u8, 1, 2, 3, 4, 5, 6, 7, 42, 255] {
        let aad = RecordAad::from_raw_type(&vault_id, &record_id, raw, 1);
        assert_eq!(aad.format, RecordAad::FORMAT_V1);
        assert_eq!(aad.record_type, raw);
        assert_eq!(aad.key_epoch, 1);

        let bytes = aad.to_bytes().expect("serialize raw AAD");
        assert_eq!(bytes[0], 1); // format
        assert_eq!(bytes[1..17], vault_id);
        assert_eq!(bytes[17..33], record_id);
        assert_eq!(bytes[33], raw); // record_type byte

        let owned = RecordAadOwned::from_raw_type(vault_id, record_id, raw, 1);
        let owned_bytes = owned.as_borrowed().to_bytes().expect("serialize owned AAD");
        assert_eq!(bytes, owned_bytes);

        // Deserializing back into RecordAadOwned
        let dec_owned: RecordAadOwned = postcard::from_bytes(&bytes).expect("deserialize AAD");
        assert_eq!(dec_owned, owned);
        assert_eq!(dec_owned.record_type, raw);
    }
}

#[test]
fn test_secret_kind_fuzzing() {
    let valid_strings = [
        "password",
        "api_key",
        "access_token",
        "env_var",
        "ssh_key",
        "certificate",
    ];

    for s in valid_strings {
        let kind: SecretKind = s.parse().expect("parse valid kind");
        assert_eq!(kind.as_str(), s);
        assert_eq!(format!("{}", kind), s);
    }

    // Fuzz invalid kinds
    let invalid_strings = [
        "",
        "PASSWORD",
        "Password",
        "api-key",
        "ssh",
        "secret",
        "unknown",
        "password\0",
        " password",
        "password ",
    ];

    for inv in invalid_strings {
        assert!(
            inv.parse::<SecretKind>().is_err(),
            "Invalid kind string '{}' unexpectedly succeeded",
            inv
        );
    }

    // Postcard deserialization of invalid SecretKind index
    for b in 6u8..=255 {
        assert!(postcard::from_bytes::<SecretKind>(&[b]).is_err());
    }
}

// ============================================================================
// 2. Extreme Payloads Roundtrip Verification
// ============================================================================

#[test]
fn test_extreme_payload_0_byte_strings() {
    let item_id = Uuid::new_v4();
    let env_id = Uuid::new_v4();

    // 0-byte strings in LabelBody
    let label = LabelBody::new("", 0, Some("".to_string()));
    let enc_label = postcard::to_stdvec(&label).expect("serialize empty LabelBody");
    let dec_label: LabelBody =
        postcard::from_bytes(&enc_label).expect("deserialize empty LabelBody");
    assert_eq!(dec_label, label);
    assert_eq!(dec_label.name, "");
    assert_eq!(dec_label.icon, Some("".to_string()));

    // 0-byte strings in ItemBody
    let item = ItemBody::new(Uuid::nil(), "", Some("".to_string()), 0);
    let enc_item = postcard::to_stdvec(&item).expect("serialize empty ItemBody");
    let dec_item: ItemBody = postcard::from_bytes(&enc_item).expect("deserialize empty ItemBody");
    assert_eq!(dec_item, item);
    assert_eq!(dec_item.name, "");

    // 0-byte strings in EnvironmentBody
    let env = EnvironmentBody::new(item_id, "", 0);
    let enc_env = postcard::to_stdvec(&env).expect("serialize empty EnvironmentBody");
    let dec_env: EnvironmentBody =
        postcard::from_bytes(&enc_env).expect("deserialize empty EnvironmentBody");
    assert_eq!(dec_env, env);

    // 0-byte strings in SecretBody
    let secret = SecretBody::new(
        item_id,
        Some(env_id),
        "",
        SecretKind::Password,
        "",
        Some("".to_string()),
    );
    let enc_secret = postcard::to_stdvec(&secret).expect("serialize empty SecretBody");
    let dec_secret: SecretBody =
        postcard::from_bytes(&enc_secret).expect("deserialize empty SecretBody");
    assert_eq!(dec_secret, secret);
    assert_eq!(dec_secret.name, "");
    assert_eq!(dec_secret.value, "");
    assert_eq!(dec_secret.note, Some("".to_string()));

    // 0-byte FilePayload data
    let file_meta = FileMetaBody::new(item_id, None, "", 0, "", [0u8; 32]);
    let file_payload = FilePayload::new(file_meta, Vec::new());
    let enc_file = postcard::to_stdvec(&file_payload).expect("serialize 0-byte FilePayload");
    let dec_file: FilePayload =
        postcard::from_bytes(&enc_file).expect("deserialize 0-byte FilePayload");
    assert_eq!(dec_file, file_payload);
    assert!(dec_file.data.is_empty());

    // 0-byte NoteBody
    let note = NoteBody::new(item_id, None, "", "", 0);
    let enc_note = postcard::to_stdvec(&note).expect("serialize 0-byte NoteBody");
    let dec_note: NoteBody = postcard::from_bytes(&enc_note).expect("deserialize 0-byte NoteBody");
    assert_eq!(dec_note, note);
    assert_eq!(dec_note.title, "");
    assert_eq!(dec_note.content, "");
}

#[test]
fn test_extreme_payload_64kib_secret() {
    let item_id = Uuid::new_v4();

    // 1. ASCII 64 KiB (exact 65,536 bytes)
    let payload_64k = "A".repeat(65_536);
    assert_eq!(payload_64k.len(), 65_536);
    assert!(validate_secret_value(&payload_64k).is_ok());

    let body = SecretBody::new(
        item_id,
        None,
        "SEC_64K",
        SecretKind::EnvVar,
        &payload_64k,
        None,
    );
    let enc = postcard::to_stdvec(&body).expect("serialize 64 KiB SecretBody");
    let dec: SecretBody = postcard::from_bytes(&enc).expect("deserialize 64 KiB SecretBody");
    assert_eq!(dec.value, payload_64k);

    // 2. SecretMeta value tail on 64 KiB secret
    let tail = SecretMeta::compute_value_tail(&payload_64k);
    assert_eq!(tail, "AAAA");

    // 3. Overflow boundary: 65,537 bytes
    let overflow_64k = "A".repeat(65_537);
    assert!(validate_secret_value(&overflow_64k).is_err());
}

#[test]
fn test_extreme_payload_multiline_secrets() {
    let item_id = Uuid::new_v4();

    // Complex real-world multi-line payload: SSH Private Key + TLS Cert + Docker compose
    let multiline_data = "Line 1\nLine 2\r\nLine 3\rLine 4\n\n\n\n\nLine 5\tWith\tTabs\n";
    let body = SecretBody::new(
        item_id,
        None,
        "MULTILINE_SECRET",
        SecretKind::SshKey,
        multiline_data,
        Some("Multi-line note\nSecond note line".to_string()),
    );

    let enc = postcard::to_stdvec(&body).expect("serialize multiline SecretBody");
    let dec: SecretBody = postcard::from_bytes(&enc).expect("deserialize multiline SecretBody");
    assert_eq!(dec.value, multiline_data);
    assert_eq!(
        dec.note,
        Some("Multi-line note\nSecond note line".to_string())
    );

    // Verify 10,000 lines string
    let mut large_multiline = String::with_capacity(70_000);
    for i in 0..10_000 {
        large_multiline.push_str(&format!("K_{}={}\n", i, i * 2));
    }
    // Postcard handles any length string without internal line-normalization
    let note = NoteBody::new(item_id, None, "10K Lines", &large_multiline, 0);
    let enc_note = postcard::to_stdvec(&note).expect("serialize 10k lines note");
    let dec_note: NoteBody = postcard::from_bytes(&enc_note).expect("deserialize 10k lines note");
    assert_eq!(dec_note.content, large_multiline);
}

#[test]
fn test_extreme_payload_multibyte_utf8() {
    let item_id = Uuid::new_v4();

    let multibyte_samples = [
        "🦀🔑🔒🛡️⚡️",                       // Emojis (4-byte)
        "漢字・日本語・한국어・中文",       // CJK (3-byte)
        "العربية / فارسی / עברית",          // RTL scripts
        "αβγδεζηθικλμνξοπρστυφχψω",         // Greek (2-byte)
        "👨‍👩‍👧‍👦",                               // Zero-width joiner family sequence
        "e\u{0301} vs \u{00E9}",            // Combining accents
        "\u{200B}\u{200C}\u{200D}\u{FEFF}", // Zero-width spaces & BOM
    ];

    for sample in multibyte_samples {
        let body = SecretBody::new(
            item_id,
            None,
            "MULTIBYTE",
            SecretKind::Password,
            sample,
            Some(sample.to_string()),
        );

        let enc = postcard::to_stdvec(&body).expect("serialize multibyte SecretBody");
        let dec: SecretBody = postcard::from_bytes(&enc).expect("deserialize multibyte SecretBody");
        assert_eq!(dec.value, sample);
        assert_eq!(dec.note, Some(sample.to_string()));
    }
}

#[test]
fn test_extreme_payload_null_characters() {
    let item_id = Uuid::new_v4();

    // Embedded and surrounding null characters
    let null_secret = "prefix\0middle\0\0\0suffix\0";
    let body = SecretBody::new(
        item_id,
        None,
        "NULL_SECRET",
        SecretKind::Password,
        null_secret,
        Some("note\0with\0nulls".to_string()),
    );

    let enc = postcard::to_stdvec(&body).expect("serialize null bytes SecretBody");
    let dec: SecretBody = postcard::from_bytes(&enc).expect("deserialize null bytes SecretBody");
    assert_eq!(dec.value, null_secret);
    assert_eq!(dec.note, Some("note\0with\0nulls".to_string()));

    // compute_value_tail with null characters
    // Note: '\0' is NOT whitespace according to char::is_whitespace()
    let tail = SecretMeta::compute_value_tail(null_secret);
    assert_eq!(tail, "fix\0");
}

#[test]
fn test_extreme_payload_50mib_file_limit() {
    const FIFTY_MIB: usize = 50 * 1024 * 1024; // 52,428,800 bytes

    // 1. Validate file size boundary checks
    assert!(validate_file_size(0).is_ok());
    assert!(validate_file_size(FIFTY_MIB as u64).is_ok());
    assert!(validate_file_size((FIFTY_MIB + 1) as u64).is_err());
    assert!(validate_file_size(u64::MAX).is_err());

    // 2. Allocate exactly 50 MiB data buffer
    let mut large_buffer = vec![0x7A; FIFTY_MIB];
    large_buffer[0] = 0xAA;
    large_buffer[FIFTY_MIB - 1] = 0xBB;

    let meta = FileMetaBody::new(
        Uuid::new_v4(),
        None,
        "large_firmware.bin",
        FIFTY_MIB as u64,
        "application/octet-stream",
        [0x42u8; 32],
    );

    let file_payload = FilePayload::new(meta, large_buffer);

    // 3. Postcard roundtrip of full 50 MiB payload
    let enc = postcard::to_stdvec(&file_payload).expect("serialize 50 MiB FilePayload");
    assert!(enc.len() >= FIFTY_MIB);

    let dec: FilePayload = postcard::from_bytes(&enc).expect("deserialize 50 MiB FilePayload");
    assert_eq!(dec.meta.size_bytes, FIFTY_MIB as u64);
    assert_eq!(dec.data.len(), FIFTY_MIB);
    assert_eq!(dec.data[0], 0xAA);
    assert_eq!(dec.data[FIFTY_MIB - 1], 0xBB);
}

// ============================================================================
// 3. RecordAad Canonical Serialization & Bit Tampering
// ============================================================================

#[test]
fn test_record_aad_canonical_determinism_and_bit_tampering() {
    let vault_id = [0x33u8; 16];
    let record_id = [0x44u8; 16];
    let record_type = RecordType::Secret;
    let key_epoch = 1u32;

    let aad = RecordAad::new(&vault_id, &record_id, record_type, key_epoch);
    let canonical_bytes = aad.to_bytes().expect("serialize RecordAad");

    // Layout: format(1) + vault_id(16) + record_id(16) + record_type(1) + varint(key_epoch)
    assert_eq!(canonical_bytes.len(), 1 + 16 + 16 + 1 + 1); // 35 bytes

    // 1. Bit-level tampering: flip each bit of each byte in canonical_bytes
    for byte_idx in 0..canonical_bytes.len() {
        for bit in 0..8 {
            let mut tampered = canonical_bytes.clone();
            tampered[byte_idx] ^= 1 << bit;

            // Property A: Tampered bytes must never equal canonical bytes
            assert_ne!(
                tampered, canonical_bytes,
                "Tampering byte {} bit {} produced identical bytes",
                byte_idx, bit
            );

            // Property B: If it deserializes as RecordAadOwned, it must NOT match the original AAD
            if let Ok(dec) = postcard::from_bytes::<RecordAadOwned>(&tampered) {
                assert_ne!(
                    dec,
                    RecordAadOwned::new(vault_id, record_id, record_type, key_epoch),
                    "Tampered AAD at byte {} bit {} unexpectedly deserialized to original AAD",
                    byte_idx,
                    bit
                );
            }
        }
    }

    // 2. Truncation testing: any truncated slice [0..len] must fail deserialization
    for len in 0..canonical_bytes.len() {
        let truncated = &canonical_bytes[..len];
        let res: Result<RecordAadOwned, _> = postcard::from_bytes(truncated);
        assert!(
            res.is_err(),
            "Truncation to len {} unexpectedly deserialized successfully",
            len
        );
    }

    // 3. Extra trailing bytes: postcard::take_from_bytes reports unconsumed trailing bytes
    for extra_len in 1..=10 {
        let mut with_trailing = canonical_bytes.clone();
        with_trailing.extend(vec![0xFF; extra_len]);
        let (_aad, remaining) = postcard::take_from_bytes::<RecordAadOwned>(&with_trailing)
            .expect("take_from_bytes succeeds");
        assert_eq!(
            remaining.len(),
            extra_len,
            "take_from_bytes must leave exactly trailing bytes unconsumed"
        );
    }

    // 4. Varint corruption in key_epoch (continuation bit set with no next byte)
    let mut bad_varint = canonical_bytes.clone();
    let last = bad_varint.len() - 1;
    bad_varint[last] = 0x80; // Set MSB (continuation bit) without subsequent byte
    assert!(postcard::from_bytes::<RecordAadOwned>(&bad_varint).is_err());
}

#[test]
fn test_record_aad_every_field_tampering_different_bytes() {
    let vault_id = [0x55u8; 16];
    let record_id = [0x66u8; 16];
    let epoch = 10u32;

    let base = RecordAad::new(&vault_id, &record_id, RecordType::Item, epoch)
        .to_bytes()
        .unwrap();

    // 1. Changing vault_id
    for i in 0..16 {
        let mut other_vault = vault_id;
        other_vault[i] ^= 0x01;
        let bytes = RecordAad::new(&other_vault, &record_id, RecordType::Item, epoch)
            .to_bytes()
            .unwrap();
        assert_ne!(bytes, base);
    }

    // 2. Changing record_id
    for i in 0..16 {
        let mut other_rec = record_id;
        other_rec[i] ^= 0x01;
        let bytes = RecordAad::new(&vault_id, &other_rec, RecordType::Item, epoch)
            .to_bytes()
            .unwrap();
        assert_ne!(bytes, base);
    }

    // 3. Changing record_type across all variants
    for rt in [
        RecordType::Label,
        RecordType::Environment,
        RecordType::Secret,
        RecordType::File,
        RecordType::Note,
    ] {
        let bytes = RecordAad::new(&vault_id, &record_id, rt, epoch)
            .to_bytes()
            .unwrap();
        assert_ne!(bytes, base);
    }

    // 4. Changing key_epoch
    for other_epoch in [0u32, 9, 11, 100, 1000, u32::MAX] {
        let bytes = RecordAad::new(&vault_id, &record_id, RecordType::Item, other_epoch)
            .to_bytes()
            .unwrap();
        assert_ne!(bytes, base);
    }
}

// ============================================================================
// 4. Text Helpers & Rich-Text Adversarial Attacks
// ============================================================================

#[test]
fn test_text_helpers_xss_and_malicious_tags() {
    let xss_payloads = [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=\"javascript:alert('xss')\">",
        "<iframe src=\"javascript:alert(1)\"></iframe>",
        "<body onload=alert('test')>",
        "<style>body { background: red; }</style>",
        "<a href=\"javascript:alert(1)\">Click me</a>",
        "<input type=\"text\" autofocus onfocus=\"alert(1)\">",
        "<<SCRIPT>alert('XSS');//<</SCRIPT>",
        "<script src=\"https://evil.com/payload.js\"></script>",
    ];

    for payload in xss_payloads {
        let plain = extract_plain_text(payload);
        // Ensure no HTML tags survive in the output
        assert!(
            !plain.contains("<script"),
            "Tag '<script' survived in '{}' -> '{}'",
            payload,
            plain
        );
        assert!(
            !plain.contains("<img"),
            "Tag '<img' survived in '{}' -> '{}'",
            payload,
            plain
        );
        assert!(
            !plain.contains("<svg"),
            "Tag '<svg' survived in '{}' -> '{}'",
            payload,
            plain
        );
        assert!(
            !plain.contains("<iframe"),
            "Tag '<iframe' survived in '{}' -> '{}'",
            payload,
            plain
        );
        assert!(
            !plain.contains("<a href"),
            "Tag '<a href' survived in '{}' -> '{}'",
            payload,
            plain
        );

        let snippet = snippet_from_content(payload, 30);
        assert!(!snippet.contains("<script"));
        assert!(!snippet.contains("<img"));
    }
}

#[test]
fn test_text_helpers_deeply_nested_tags() {
    // 1,000 deeply nested tags: <div><div>...<p>Hello World</p>...</div></div>
    let open_tags = "<div><section><article><span>".repeat(250);
    let close_tags = "</span></article></section></div>".repeat(250);
    let nested_html = format!("{}<p>Deep Content</p>{}", open_tags, close_tags);

    let plain = extract_plain_text(&nested_html);
    assert_eq!(plain, "Deep Content");

    let snippet = snippet_from_content(&nested_html, 10);
    assert_eq!(snippet, "Deep Conte...");
}

#[test]
fn test_text_helpers_unclosed_and_malformed_tags() {
    // 1. Unclosed tag: text continues after '<'
    let unclosed = "Text before <unclosed tag Text inside tag";
    let plain = extract_plain_text(unclosed);
    // Since '<' was never closed, everything after '<' is discarded as tag content
    assert_eq!(plain, "Text before");

    // 2. Unopened closing tag: '>' without '<'
    let unopened = "Text before > and text after";
    let plain_unopened = extract_plain_text(unopened);
    assert_eq!(plain_unopened, "Text before > and text after");

    // 3. Double angle brackets
    let double_brackets = "<<div>>Content<<//div>>";
    let plain_double = extract_plain_text(double_brackets);
    assert!(plain_double.contains("Content"));

    // 4. Empty tag
    let empty_tag = "Start <> Middle < > End";
    let plain_empty = extract_plain_text(empty_tag);
    assert_eq!(plain_empty, "Start  Middle  End");
}

#[test]
fn test_text_helpers_html_entities() {
    // Basic entity decoding
    let html = "&lt;div&gt; &amp; &quot;Hello&#39;s World&quot; &nbsp;&lt;/div&gt;";
    let plain = extract_plain_text(html);
    assert_eq!(plain, "<div> & \"Hello's World\"  </div>");

    // Incomplete / trailing entities
    let incomplete = "Value: &amp &lt &gt &quot &#39 &nbsp &";
    let plain_inc = extract_plain_text(incomplete);
    assert_eq!(plain_inc, "Value: &amp &lt &gt &quot &#39 &nbsp &");

    // Entity injection (single-pass decode prevents recursive injection)
    let injected = "&amp;lt;script&amp;gt;";
    let plain_inj = extract_plain_text(injected);
    assert_eq!(plain_inj, "&lt;script&gt;");
}

#[test]
fn test_text_helpers_attributes_on_tags() {
    // Tags with style, class, id attributes
    let html = "<h1 class=\"title\" id=\"main\">Heading</h1>\
                <p style=\"color: red;\">First paragraph.</p>\
                <ul class=\"list-group\">\
                  <li class=\"list-item\">Item A</li>\
                  <li class=\"list-item\">Item B</li>\
                </ul>";
    let plain = extract_plain_text(html);
    assert!(plain.contains("Heading"));
    assert!(plain.contains("First paragraph."));
    assert!(plain.contains("Item A"));
    assert!(plain.contains("Item B"));
}

#[test]
fn test_snippet_boundary_conditions() {
    let content = "<p>Hello <b>World</b>!</p>";

    // max_chars = 0
    assert_eq!(snippet_from_content(content, 0), "...");

    // max_chars = 1
    assert_eq!(snippet_from_content(content, 1), "H...");

    // max_chars exact match with plain text length ("Hello World!" is 12 chars)
    assert_eq!(snippet_from_content(content, 12), "Hello World!");

    // max_chars exceeding plain text length
    assert_eq!(snippet_from_content(content, 50), "Hello World!");

    // Multibyte Unicode in snippet
    let unicode_content = "<p>🦀 🔑 🔒 🛡️ ⚡️</p>";
    // Slicing at 2 chars ("🦀 ")
    let snippet_uni = snippet_from_content(unicode_content, 2);
    assert_eq!(snippet_uni, "🦀...");
}

// ============================================================================
// 5. Cross-Type Deserialization & Postcard UTF-8 Invariants
// ============================================================================

#[test]
fn test_cross_record_type_deserialization_safety() {
    let item_id = Uuid::new_v4();
    let env_id = Uuid::new_v4();

    let secret = SecretBody::new(
        item_id,
        Some(env_id),
        "DB_PASS",
        SecretKind::Password,
        "very_secret_pass_123456",
        Some("Production database password".to_string()),
    );
    let secret_bytes = postcard::to_stdvec(&secret).expect("serialize SecretBody");

    // Deserializing SecretBody bytes as Label, Item, Environment, File, Note
    // Must either return Err (expected because fields and tags mismatch) or never panic
    let types = [
        RecordType::Label,
        RecordType::Item,
        RecordType::Environment,
        RecordType::File,
        RecordType::Note,
    ];

    for rt in types {
        let res = RecordPayload::from_bytes(rt, &secret_bytes);
        // We verify that cross-deserialization safely returns an error or handled Result
        if let Ok(payload) = res {
            // In the unlikely event structural framing coincidentally matched, its record_type must match rt
            assert_eq!(payload.record_type(), rt);
        }
    }
}

#[test]
fn test_postcard_invalid_utf8_rejection() {
    // Postcard encodes String as: varint length prefix + raw bytes.
    // Construct a byte slice claiming a 2-byte string with invalid UTF-8 bytes 0xFF, 0xFF.
    let invalid_utf8_postcard = [
        2u8,  // varint len = 2
        0xFF, // invalid UTF-8 start byte
        0xFF,
    ];

    let res: Result<String, _> = postcard::from_bytes(&invalid_utf8_postcard);
    assert!(
        res.is_err(),
        "Postcard must reject invalid UTF-8 byte sequences"
    );

    // Test with invalid UTF-8 in LabelBody
    let invalid_label_bytes = [
        2u8, 0xFF, 0xFF, // name: invalid utf8
        0u8,  // position: 0
        0u8,  // icon: None
    ];
    let res_label: Result<LabelBody, _> = postcard::from_bytes(&invalid_label_bytes);
    assert!(res_label.is_err());
}

#[test]
fn test_extract_plain_text_extreme_fuzzing() {
    // 1. Extreme string of '<' characters without closing '>'
    let many_open = "<".repeat(50_000);
    let plain_open = extract_plain_text(&many_open);
    assert_eq!(plain_open, "");

    // 2. Extreme string of '>' characters without opening '<'
    let many_close = ">".repeat(50_000);
    let plain_close = extract_plain_text(&many_close);
    assert_eq!(plain_close, many_close);

    // 3. Alternating angle brackets
    let alternating = "<>".repeat(10_000);
    let plain_alt = extract_plain_text(&alternating);
    assert_eq!(plain_alt, "");

    // 4. Incomplete entities at the end of string buffer (index out-of-bounds safety check)
    for tail in ["&", "&a", "&am", "&amp", "&amp;", "&l", "&lt", "&lt;"] {
        let input = format!("content{}", tail);
        let plain = extract_plain_text(&input);
        assert!(!plain.is_empty());
    }

    // 5. Embedded null bytes in HTML
    let null_html = "<p>Hello\0World</p><script>\0evil()</script>";
    let plain_null = extract_plain_text(null_html);
    assert!(plain_null.contains("Hello\0World"));
    assert!(!plain_null.contains("<script"));

    // 6. Multiple consecutive <br> tags: collapses to max 2 blank lines (i.e. 3 newlines between text)
    let br_100 = "<br>".repeat(100);
    let plain_br = extract_plain_text(&br_100);
    assert_eq!(plain_br, ""); // Leading/trailing newlines are trimmed

    let text_with_br = format!("Start{}End", "<br>".repeat(50));
    let plain_text_br = extract_plain_text(&text_with_br);
    // Algorithm permits at most 2 blank lines, which corresponds to 3 newlines
    assert_eq!(plain_text_br, "Start\n\n\nEnd");
}

#[test]
fn test_extract_plain_text_defects_and_limitations() {
    // Remediation 1: `<br />` (standard XHTML self-closing with space) inserts newline without gluing
    let br_space = extract_plain_text("Line 1<br />Line 2");
    assert_eq!(br_space, "Line 1\nLine 2");

    // Remediation 2: `<li class="...">` inserts bullet "• " even with attributes
    let li_attr = extract_plain_text("<li class=\"task-item\">Buy milk</li>");
    assert_eq!(li_attr, "• Buy milk");

    // Remediation 3: `<script>` and `<style>` tag content is stripped entirely
    let script_content = extract_plain_text("<script>alert('xss')</script>");
    assert_eq!(script_content, "");

    let style_content = extract_plain_text("<style>body { color: red; }</style>");
    assert_eq!(style_content, "");

    // Remediation 4: Mathematical comparisons like "5 < 10 and 10 > 5" preserve inner content
    let math = extract_plain_text("5 < 10 and 10 > 5");
    assert_eq!(math, "5 < 10 and 10 > 5");
}

#[test]
fn test_nested_list_indentation_and_validation() {
    let nested_html =
        "<ul><li>Parent 1<ul><li>Child 1.1</li><li>Child 1.2</li></ul></li><li>Parent 2</li></ul>";
    let plain = extract_plain_text(nested_html);
    assert_eq!(
        plain,
        "• Parent 1\n  • Child 1.1\n  • Child 1.2\n• Parent 2"
    );

    assert!(validate_note_content("Valid note content").is_ok());
    assert!(validate_note_content("").is_ok());
    let too_large = "x".repeat(1_000_001);
    assert!(validate_note_content(&too_large).is_err());
}

#[test]
fn test_note_content_validation_stress_and_adversarial() {
    // Verify fast path vs slow path consistency
    let short_content = "Short note";
    assert!(validate_note_content(short_content).is_ok());

    // Test with mixed scripts (CJK, Arabic, Latin, Math, Emoji)
    let mixed_script = "Hello 世界 مرحبا 🌍 ∑(n=1..∞) 1/n² = π²/6 ";
    let repeated_mixed = mixed_script.repeat(10_000);
    assert!(validate_note_content(&repeated_mixed).is_ok());

    // Test NoteBody::try_new rejecting empty title while accepting empty content
    let item_id = Uuid::new_v4();
    assert!(NoteBody::try_new(item_id, None, "", "Valid content", 0).is_err());
    assert!(NoteBody::try_new(item_id, None, "Valid Title", "", 0).is_ok());

    // Test NoteBody::validate
    let mut note = NoteBody::new(item_id, None, "Valid Title", "Valid Content", 0);
    assert!(note.validate().is_ok());
    note.title = "".to_string();
    assert!(note.validate().is_err());
    note.title = "Valid Title".to_string();
    note.content = "c".repeat(1_000_001);
    assert!(note.validate().is_err());
}

#[test]
fn test_reverification_challenger_adversarial_suite() {
    // 1. <br /> with spaces and attribute variants
    assert_eq!(extract_plain_text("Line 1<br />Line 2"), "Line 1\nLine 2");
    assert_eq!(extract_plain_text("Line 1<br   />Line 2"), "Line 1\nLine 2");
    assert_eq!(extract_plain_text("Line 1<br/ >Line 2"), "Line 1\nLine 2");
    assert_eq!(extract_plain_text("Line 1<br>Line 2"), "Line 1\nLine 2");
    assert_eq!(extract_plain_text("Line 1<BR />Line 2"), "Line 1\nLine 2");
    assert_eq!(
        extract_plain_text("Line 1<br class=\"clear\" />Line 2"),
        "Line 1\nLine 2"
    );
    assert_eq!(
        extract_plain_text("Line 1<br style=\"mso-special-format:line-break\" />Line 2"),
        "Line 1\nLine 2"
    );
    assert_eq!(extract_plain_text("Line 1<br\t/>Line 2"), "Line 1\nLine 2");
    assert_eq!(extract_plain_text("Line 1<br\n/>Line 2"), "Line 1\nLine 2");

    // 2. Attributes on HTML tags
    assert_eq!(
        extract_plain_text("<li class=\"task-item\">Buy milk</li>"),
        "• Buy milk"
    );
    assert_eq!(
        extract_plain_text("<li id=\"item1\" class=\"task-item\" style=\"color:red\">Test</li>"),
        "• Test"
    );
    let nested_lists = "<ul class=\"root\"><li class=\"p1\">Parent 1<ul class=\"sub\"><li class=\"c1\">Child 1.1</li><li class=\"c2\">Child 1.2</li></ul></li><li class=\"p2\">Parent 2</li></ul>";
    assert_eq!(
        extract_plain_text(nested_lists),
        "• Parent 1\n  • Child 1.1\n  • Child 1.2\n• Parent 2"
    );

    let block_elements = "<h1 id=\"header\" class=\"main\">Main Title</h1><p class=\"lead\" style=\"color: blue\">First paragraph.</p><p id=\"p2\">Second paragraph.</p>";
    assert_eq!(
        extract_plain_text(block_elements),
        "Main Title\n\nFirst paragraph.\n\nSecond paragraph."
    );

    let complex_blocks = "<div class=\"box\"><h2 data-id=\"1\">Heading 2</h2><blockquote cite=\"https://example.com\">A quote</blockquote><pre>code block</pre></div>";
    assert_eq!(
        extract_plain_text(complex_blocks),
        "Heading 2\n\nA quote\n\ncode block"
    );

    // 3. <script> and <style> content blocks stripped completely
    assert_eq!(extract_plain_text("<script>alert('xss')</script>"), "");
    assert_eq!(
        extract_plain_text("<style>body { color: red; }</style>"),
        ""
    );
    assert_eq!(extract_plain_text("<script type=\"text/javascript\" src=\"evil.js\">const x = 10; function run() { return true; }</script>"), "");
    assert_eq!(
        extract_plain_text(
            "<STYLE type=\"text/css\">.hidden { display: none !important; }</STYLE>"
        ),
        ""
    );
    assert_eq!(
        extract_plain_text("<p>Safe text</p><script>evil()</script><p>More safe text</p>"),
        "Safe text\n\nMore safe text"
    );
    // Script with internal '<' comparisons and quotes
    assert_eq!(
        extract_plain_text("<script>for (var i = 0; i < 10; i++) { if (i > 5) break; }</script>"),
        ""
    );

    // 4. Mathematical comparisons preserved
    assert_eq!(extract_plain_text("5 < 10 and 10 > 5"), "5 < 10 and 10 > 5");
    assert_eq!(extract_plain_text("3 < 4 < 5"), "3 < 4 < 5");
    assert_eq!(
        extract_plain_text("Formula: x < 5 and y > 3"),
        "Formula: x < 5 and y > 3"
    );
    assert_eq!(
        extract_plain_text("Comparing: a < b and b > c"),
        "Comparing: a < b and b > c"
    );

    // 5. validate_note_content 1,000,000 character limit enforcement
    assert!(validate_note_content("").is_ok());
    assert!(validate_note_content("Small note").is_ok());
    let exact_1m_ascii = "a".repeat(1_000_000);
    assert!(validate_note_content(&exact_1m_ascii).is_ok());
    let overflow_1m_ascii = "a".repeat(1_000_001);
    match validate_note_content(&overflow_1m_ascii) {
        Err(ValidationError::TooLong { field, max, actual }) => {
            assert_eq!(field, "note_content");
            assert_eq!(max, 1_000_000);
            assert_eq!(actual, 1_000_001);
        }
        other => panic!("Expected ValidationError::TooLong, got {:?}", other),
    }

    // Multibyte characters at boundary
    let exact_1m_multibyte = "🦀".repeat(1_000_000); // 4 MB byte length, 1M characters
    assert_eq!(exact_1m_multibyte.len(), 4_000_000);
    assert!(validate_note_content(&exact_1m_multibyte).is_ok());

    let overflow_1m_multibyte = "🦀".repeat(1_000_001); // 4,000,004 byte length, 1,000,001 characters
    match validate_note_content(&overflow_1m_multibyte) {
        Err(ValidationError::TooLong { field, max, actual }) => {
            assert_eq!(field, "note_content");
            assert_eq!(max, 1_000_000);
            assert_eq!(actual, 1_000_001);
        }
        other => panic!("Expected ValidationError::TooLong, got {:?}", other),
    }

    // validate_note combined validator
    assert!(validate_note("Title", &exact_1m_ascii).is_ok());
    assert!(validate_note("Title", &overflow_1m_ascii).is_err());
    assert!(validate_note("", &exact_1m_ascii).is_err());
}
