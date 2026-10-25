//! Empirical Challenger 1 Adversarial Test Suite for Milestone 2.
//!
//! Scope:
//! 1. File upload boundary: 50 MiB (52,428,800 bytes allowed), 50 MiB + 1 byte (rejected),
//!    empty file (0 bytes allowed), invalid names (empty, whitespace, >255 chars, duplicate siblings,
//!    path traversal sanitization).
//! 2. SHA-256 integrity and bit flip attacks on file ciphertext in SQLite (must fail Poly1305 MAC).
//! 3. Rich-text note boundary: title > 128 chars (rejected), content > 1,000,000 chars (rejected),
//!    HTML stripping in `list_notes` vs raw markup preservation in `get_note`.
//! 4. Deleting the only environment on an item with `preserve_content: true` (verify child items
//!    reparent to item_id) vs `preserve_content: false` (verify cascade deletion).
//! 5. Single environment legacy `delete_environment` behavior vs `delete_environment_with_options`.

use secrecy::ExposeSecret;
use secwet_core::keys::MemoryStore;
use secwet_core::records::open_connection;
use secwet_core::{Error, SecretDraft, SecretKind, Vault};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use uuid::Uuid;

fn create_challenge_vault() -> (tempfile::TempDir, Vault, MemoryStore, Uuid, Uuid) {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let mut vault =
        Vault::create(dir.path(), "challenger-device", &keystore).expect("vault create");

    let labels = vault.list_labels().expect("list labels");
    let default_label_id = labels[0].id;

    let item = vault
        .create_item(
            default_label_id,
            "Challenger Test Item",
            Some("Adversarial test harness item".to_string()),
        )
        .expect("create item");

    (dir, vault, keystore, default_label_id, item.id)
}

// ============================================================================
// 1. File Upload Boundary & Name Validation
// ============================================================================

#[test]
fn test_adversarial_file_upload_boundary_and_names() {
    let (_dir, mut vault, _ks, _label_id, item_id) = create_challenge_vault();

    // --- 1.1: 50 MiB Boundary (52,428,800 bytes) ---
    // Exact 50 MiB must succeed
    let fifty_mib = 50 * 1024 * 1024;
    let valid_50mib_data = vec![0xA5u8; fifty_mib];
    let expected_50mib_sha = {
        let mut hasher = Sha256::new();
        hasher.update(&valid_50mib_data);
        data_encoding::HEXLOWER.encode(&hasher.finalize())
    };

    let meta_50 = vault
        .upload_file(
            item_id,
            None,
            "max_exact_50mib.bin",
            &valid_50mib_data,
            Some("application/octet-stream"),
        )
        .expect("50 MiB file upload must succeed");

    assert_eq!(meta_50.size_bytes, fifty_mib as u64);
    assert_eq!(meta_50.sha256, expected_50mib_sha);
    assert_eq!(meta_50.name, "max_exact_50mib.bin");

    // Download and verify exact length and byte content
    let (dl_meta, dl_data) = vault
        .download_file(meta_50.id)
        .expect("download 50 MiB file");
    assert_eq!(dl_meta.id, meta_50.id);
    assert_eq!(dl_data.len(), fifty_mib);
    assert_eq!(dl_data[0], 0xA5);
    assert_eq!(dl_data[fifty_mib - 1], 0xA5);

    // --- 1.2: 50 MiB + 1 Byte Boundary (52,428,801 bytes) ---
    // Must be rejected with Error::Invalid { field: "size" }
    let oversized_data = vec![0x5Au8; fifty_mib + 1];
    let err_oversized = vault.upload_file(
        item_id,
        None,
        "oversized_50mib_plus_1.bin",
        &oversized_data,
        None,
    );
    match err_oversized {
        Err(Error::Invalid { field, message }) => {
            assert_eq!(field, "size");
            assert!(
                message.contains("50 MiB"),
                "Error message should mention 50 MiB: {}",
                message
            );
        }
        other => panic!("Expected Error::Invalid for size, got: {:?}", other),
    }

    // --- 1.3: Empty File (0 Bytes) ---
    // Uploading a 0-byte file must succeed with standard empty SHA-256
    let empty_data = b"";
    let empty_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    let meta_empty = vault
        .upload_file(
            item_id,
            None,
            "empty_payload.dat",
            empty_data,
            Some("application/x-empty"),
        )
        .expect("Empty 0-byte file upload must succeed");

    assert_eq!(meta_empty.size_bytes, 0);
    assert_eq!(meta_empty.sha256, empty_sha256);

    let (dl_empty_meta, dl_empty_data) = vault
        .download_file(meta_empty.id)
        .expect("download empty file");
    assert_eq!(dl_empty_meta.size_bytes, 0);
    assert!(dl_empty_data.is_empty());

    // --- 1.4: Invalid File Names ---
    // A) Empty filename
    let err_empty = vault.upload_file(item_id, None, "", b"some bytes", None);
    assert!(matches!(
        err_empty,
        Err(Error::Invalid { field: "name", .. })
    ));

    // B) Whitespace-only filename
    let err_ws = vault.upload_file(item_id, None, "   \t \r\n   ", b"some bytes", None);
    assert!(matches!(err_ws, Err(Error::Invalid { field: "name", .. })));

    // C) Filename > 255 characters (256 chars)
    let name_256 = "f".repeat(256);
    let err_len = vault.upload_file(item_id, None, &name_256, b"some bytes", None);
    assert!(matches!(err_len, Err(Error::Invalid { field: "name", .. })));

    // D) Filename exactly 255 characters must succeed
    let name_255 = format!("{}.txt", "a".repeat(251));
    assert_eq!(name_255.chars().count(), 255);
    let meta_255 = vault
        .upload_file(item_id, None, &name_255, b"valid content", None)
        .expect("255-character filename must succeed");
    assert_eq!(meta_255.name, name_255);

    // E) Sibling filename collision (case-insensitive in same container)
    let err_dup = vault.upload_file(
        item_id,
        None,
        "MAX_EXACT_50MIB.BIN",
        b"collision payload",
        None,
    );
    assert!(matches!(err_dup, Err(Error::Duplicate { field: "name" })));

    // F) Path traversal in filename: path is sanitized to file_name() component
    let traversal_meta = vault
        .upload_file(
            item_id,
            None,
            "../../../../etc/passwd",
            b"traversal test",
            None,
        )
        .expect("Path traversal filename is sanitized");
    assert_eq!(traversal_meta.name, "passwd");

    // G) Sibling in a DIFFERENT container (e.g. inside an environment) is allowed!
    let env = vault.add_environment(item_id, "staging").expect("add env");
    let env_file = vault
        .upload_file(
            item_id,
            Some(env.id),
            "max_exact_50mib.bin", // Same name as item-level file
            b"scoped to staging",
            None,
        )
        .expect("Same filename in different environment container must succeed");
    assert_eq!(env_file.environment_id, Some(env.id));
    assert_eq!(env_file.name, "max_exact_50mib.bin");

    // H) Rename validation
    let err_rename_empty = vault.rename_file(meta_empty.id, "   ");
    assert!(matches!(
        err_rename_empty,
        Err(Error::Invalid { field: "name", .. })
    ));

    let err_rename_256 = vault.rename_file(meta_empty.id, &"x".repeat(256));
    assert!(matches!(
        err_rename_256,
        Err(Error::Invalid { field: "name", .. })
    ));

    let err_rename_dup = vault.rename_file(meta_empty.id, "max_exact_50mib.bin");
    assert!(matches!(
        err_rename_dup,
        Err(Error::Duplicate { field: "name" })
    ));
}

// ============================================================================
// 2. SHA-256 Integrity & Bit Flip Attacks on File Ciphertext in SQLite
// ============================================================================

#[test]
fn test_adversarial_file_sha256_and_sqlite_bit_flips() {
    let (dir, mut vault, ks, _label_id, item_id) = create_challenge_vault();

    // Prepare known payload
    let mut payload = Vec::with_capacity(65536);
    for i in 0..65536 {
        payload.push((i % 256) as u8);
    }
    let expected_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&payload);
        data_encoding::HEXLOWER.encode(&hasher.finalize())
    };

    let meta = vault
        .upload_file(
            item_id,
            None,
            "firmware_image.bin",
            &payload,
            Some("application/octet-stream"),
        )
        .expect("upload firmware");

    assert_eq!(meta.sha256, expected_sha256);

    let vault_id = vault.vault_id();
    let db_path = dir
        .path()
        .join("vaults")
        .join(vault_id.to_string())
        .join("vault.sqlite3");

    // Lock vault to release any exclusive write handles
    vault.lock();

    // Query clean blob
    let clean_blob: Vec<u8> = {
        let conn = open_connection(&db_path).expect("open SQLite");
        conn.query_row(
            "SELECT blob FROM records WHERE id = ?1",
            rusqlite::params![meta.id.as_bytes().as_slice()],
            |r| r.get(0),
        )
        .expect("fetch clean blob")
    };

    // Helper closure to write a blob
    let write_blob = |b: &[u8]| {
        let conn = open_connection(&db_path).expect("open SQLite");
        conn.execute(
            "UPDATE records SET blob = ?1 WHERE id = ?2",
            rusqlite::params![b, meta.id.as_bytes().as_slice()],
        )
        .expect("write blob");
    };

    // --- Attack 2.1: Bit flip at index 0 (nonce / ciphertext start) ---
    {
        let mut tampered = clean_blob.clone();
        tampered[0] ^= 0x01; // Flip lowest bit of byte 0
        write_blob(&tampered);

        let unlocked = Vault::unlock(dir.path(), &ks).expect("unlock after tamper 0");
        let dl_result = unlocked.download_file(meta.id);
        assert!(
            matches!(dl_result, Err(Error::Crypto)),
            "Bit flip at byte 0 must trigger Error::Crypto, got: {:?}",
            dl_result
        );
        unlocked.lock();
        write_blob(&clean_blob); // Restore clean blob
    }

    // --- Attack 2.2: Bit flip in ciphertext body (middle of blob) ---
    {
        let mut tampered = clean_blob.clone();
        let mid = tampered.len() / 2;
        tampered[mid] ^= 0x80; // Flip highest bit of middle byte
        write_blob(&tampered);

        let unlocked = Vault::unlock(dir.path(), &ks).expect("unlock after tamper mid");
        let dl_result = unlocked.download_file(meta.id);
        assert!(
            matches!(dl_result, Err(Error::Crypto)),
            "Bit flip in middle of ciphertext body must trigger Error::Crypto, got: {:?}",
            dl_result
        );
        unlocked.lock();
        write_blob(&clean_blob); // Restore clean blob
    }

    // --- Attack 2.3: Bit flip in last byte (Poly1305 MAC tag) ---
    {
        let mut tampered = clean_blob.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x40; // Flip bit in MAC tag
        write_blob(&tampered);

        let unlocked = Vault::unlock(dir.path(), &ks).expect("unlock after tamper MAC tag");
        let dl_result = unlocked.download_file(meta.id);
        assert!(
            matches!(dl_result, Err(Error::Crypto)),
            "Bit flip in Poly1305 MAC tag must trigger Error::Crypto, got: {:?}",
            dl_result
        );
        unlocked.lock();
        write_blob(&clean_blob); // Restore clean blob
    }

    // --- Attack 2.4: AAD Mismatch by swapping key_epoch in SQLite ---
    {
        let conn = open_connection(&db_path).expect("open SQLite");
        conn.execute(
            "UPDATE records SET key_epoch = 99 WHERE id = ?1",
            rusqlite::params![meta.id.as_bytes().as_slice()],
        )
        .expect("tamper key_epoch");

        let unlocked = Vault::unlock(dir.path(), &ks).expect("unlock after epoch tamper");
        let dl_result = unlocked.download_file(meta.id);
        assert!(
            matches!(dl_result, Err(Error::Crypto)),
            "Key epoch tamper causing AAD mismatch must trigger Error::Crypto, got: {:?}",
            dl_result
        );
        unlocked.lock();

        // Restore clean key_epoch
        let conn = open_connection(&db_path).expect("open SQLite");
        conn.execute(
            "UPDATE records SET key_epoch = 1 WHERE id = ?1",
            rusqlite::params![meta.id.as_bytes().as_slice()],
        )
        .expect("restore key_epoch");
    }

    // --- Attack 2.5: AAD Mismatch by swapping blobs between two distinct records ---
    {
        let mut unlocked = Vault::unlock(dir.path(), &ks).expect("unlock");
        let file2 = unlocked
            .upload_file(
                item_id,
                None,
                "second_file.bin",
                b"file 2 distinct content",
                None,
            )
            .expect("upload file2");
        unlocked.lock();

        let conn = open_connection(&db_path).expect("open SQLite");
        let file2_blob: Vec<u8> = conn
            .query_row(
                "SELECT blob FROM records WHERE id = ?1",
                rusqlite::params![file2.id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .expect("fetch file2 blob");

        // Put file2's blob into meta (file1)'s record
        conn.execute(
            "UPDATE records SET blob = ?1 WHERE id = ?2",
            rusqlite::params![file2_blob, meta.id.as_bytes().as_slice()],
        )
        .expect("swap blob");

        let unlocked = Vault::unlock(dir.path(), &ks).expect("unlock after swap");
        let dl_result = unlocked.download_file(meta.id);
        assert!(
            matches!(dl_result, Err(Error::Crypto)),
            "Record ID mismatch in RecordAad must trigger Error::Crypto when swapping blobs, got: {:?}",
            dl_result
        );
        unlocked.lock();

        // Restore meta blob
        write_blob(&clean_blob);
    }

    // --- Verify Clean State Restored ---
    {
        let unlocked = Vault::unlock(dir.path(), &ks).expect("unlock clean");
        let (dl_meta, dl_data) = unlocked
            .download_file(meta.id)
            .expect("download clean file");
        assert_eq!(dl_meta.id, meta.id);
        assert_eq!(dl_data, payload);
    }
}

// ============================================================================
// 3. Rich-Text Note Boundary & HTML Stripping Validation
// ============================================================================

#[test]
fn test_adversarial_rich_text_note_boundaries_and_html_stripping() {
    let (dir, mut vault, ks, _label_id, item_id) = create_challenge_vault();

    // --- 3.1: Title Boundary Testing ---
    // A) Empty title
    let err_empty_title = vault.create_note(item_id, None, "", "Valid content");
    assert!(matches!(
        err_empty_title,
        Err(Error::Invalid { field: "title", .. })
    ));

    let err_ws_title = vault.create_note(item_id, None, "   \t\n  ", "Valid content");
    assert!(matches!(
        err_ws_title,
        Err(Error::Invalid { field: "title", .. })
    ));

    // B) Exact 128 characters title must succeed
    let title_128 = "A".repeat(128);
    let note_128 = vault
        .create_note(item_id, None, &title_128, "Content for note 128")
        .expect("128-char title must succeed");
    assert_eq!(note_128.title, title_128);

    // C) 129 characters title must be rejected
    let title_129 = "A".repeat(129);
    let err_title_129 = vault.create_note(item_id, None, &title_129, "Content for note 129");
    assert!(matches!(
        err_title_129,
        Err(Error::Invalid { field: "title", .. })
    ));

    // D) Unicode title character boundary (128 unicode code points vs 129 code points)
    let uni_title_128 = "🦀".repeat(128);
    assert_eq!(uni_title_128.chars().count(), 128);
    let note_uni = vault
        .create_note(item_id, None, &uni_title_128, "Emoji title content")
        .expect("128 emoji title must succeed");
    assert_eq!(note_uni.title, uni_title_128);

    let uni_title_129 = "🦀".repeat(129);
    assert_eq!(uni_title_129.chars().count(), 129);
    let err_uni_129 = vault.create_note(item_id, None, &uni_title_129, "Too many emojis");
    assert!(matches!(
        err_uni_129,
        Err(Error::Invalid { field: "title", .. })
    ));

    // --- 3.2: Content Boundary Testing ---
    // A) Empty content is allowed
    let note_empty_content = vault
        .create_note(item_id, None, "Empty Content Note", "")
        .expect("Empty note content is valid");
    assert_eq!(note_empty_content.content, "");

    // B) Content exactly 1,000,000 characters must succeed
    let content_1m: String = "X".repeat(1_000_000);
    let note_1m = vault
        .create_note(item_id, None, "Million Char Note", &content_1m)
        .expect("1,000,000 char note content must succeed");
    assert_eq!(note_1m.content.len(), 1_000_000);

    // C) Content exceeding 1,000,000 characters (1,000,001 chars) must be rejected
    let content_1m_plus = "X".repeat(1_000_001);
    let err_1m_plus = vault.create_note(item_id, None, "Oversized Note", &content_1m_plus);
    assert!(matches!(
        err_1m_plus,
        Err(Error::Invalid {
            field: "content",
            ..
        })
    ));

    // --- 3.3: HTML Stripping in list_notes vs Raw Markup in get_note ---
    let complex_markup = r#"
<div class="container">
    <h1>System Architecture &amp; Security</h1>
    <p>All sensitive records <strong>MUST</strong> be sealed with <code>XChaCha20-Poly1305</code>.</p>
    <script type="text/javascript">
        alert("XSS attempt should be stripped");
    </script>
    <table border="1">
        <tr><th>Key</th><th>Type</th></tr>
        <tr><td>k_rec</td><td>SecretBox&lt;[u8; 32]&gt;</td></tr>
    </table>
    <a href="https://example.com?query=1&amp;test=2">Link with &quot;quotes&quot;</a>
</div>
"#;

    let rich_note = vault
        .create_note(item_id, None, "Architecture Note", complex_markup)
        .expect("create rich note");

    // 1. Verify list_notes generates clean plain-text snippet without HTML tags
    let notes_list = vault.list_notes(item_id, None).expect("list notes");
    let target_meta = notes_list
        .into_iter()
        .find(|n| n.id == rich_note.id)
        .expect("note in listing");

    let snippet = target_meta.snippet;
    assert!(
        !snippet.contains("<h1>") && !snippet.contains("</h1>"),
        "Snippet must strip <h1> tags: {}",
        snippet
    );
    assert!(
        !snippet.contains("<script>") && !snippet.contains("</script>"),
        "Snippet must strip <script> tags: {}",
        snippet
    );
    assert!(
        !snippet.contains("<div") && !snippet.contains("<strong>"),
        "Snippet must strip <div> and <strong> tags: {}",
        snippet
    );
    assert!(
        snippet.contains('&'),
        "Snippet should decode &amp; into &: {}",
        snippet
    );
    assert!(
        snippet.len() <= 125, // 120 chars + potential "..."
        "Snippet length must be bounded: len={}",
        snippet.len()
    );

    // 2. Verify get_note returns RAW markup byte-for-byte intact
    let fetched = vault.get_note(rich_note.id).expect("get full note");
    assert_eq!(
        fetched.content, complex_markup,
        "get_note MUST preserve raw HTML markup exactly without alterations"
    );

    // --- 3.4: Note Ciphertext Tampering Attack ---
    let vault_id = vault.vault_id();
    let db_path = dir
        .path()
        .join("vaults")
        .join(vault_id.to_string())
        .join("vault.sqlite3");
    vault.lock();

    {
        let conn = open_connection(&db_path).expect("open SQLite");
        let mut blob: Vec<u8> = conn
            .query_row(
                "SELECT blob FROM records WHERE id = ?1",
                rusqlite::params![rich_note.id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .expect("fetch note blob");

        // Flip byte in ciphertext body
        let idx = blob.len() / 2;
        blob[idx] ^= 0xFF;

        conn.execute(
            "UPDATE records SET blob = ?1 WHERE id = ?2",
            rusqlite::params![blob, rich_note.id.as_bytes().as_slice()],
        )
        .expect("tamper note blob");
    }

    {
        let unlocked = Vault::unlock(dir.path(), &ks).expect("unlock after note tamper");
        let get_res = unlocked.get_note(rich_note.id);
        assert!(
            matches!(get_res, Err(Error::Crypto)),
            "Tampered note blob must fail get_note with Error::Crypto"
        );

        let list_res = unlocked.list_notes(item_id, None);
        assert!(
            matches!(list_res, Err(Error::Crypto)),
            "Tampered note blob must fail list_notes with Error::Crypto"
        );
    }
}

// ============================================================================
// 4. Deleting the Only Environment: preserve_content true vs false
// ============================================================================

#[test]
fn test_adversarial_delete_only_environment_preserve_content_true() {
    let (dir, mut vault, _ks, label_id, _orig_item_id) = create_challenge_vault();

    // Create a dedicated item
    let item = vault
        .create_item(label_id, "Preserve Test Item", None)
        .expect("create item");

    // Add exactly ONE environment
    let only_env = vault
        .add_environment(item.id, "isolated_env")
        .expect("add only environment");

    // Verify item has exactly 1 environment
    let envs_before = vault.list_environments(item.id).expect("list envs");
    assert_eq!(envs_before.len(), 1);
    assert_eq!(envs_before[0].id, only_env.id);

    // Create child Secret under only_env
    let secret = vault
        .create_secret(SecretDraft::new(
            item.id,
            Some(only_env.id),
            "DATABASE_PASSWORD",
            SecretKind::Password,
            "super_secret_db_pass_9988",
            Some("Database master password".to_string()),
        ))
        .expect("create secret in env");

    // Upload child File under only_env
    let file_data = b"%PDF-1.7 Confidential Engineering Spec".to_vec();
    let file = vault
        .upload_file(
            item.id,
            Some(only_env.id),
            "spec.pdf",
            &file_data,
            Some("application/pdf"),
        )
        .expect("upload file in env");

    // Create child Note under only_env
    let note = vault
        .create_note(
            item.id,
            Some(only_env.id),
            "Deployment Runbook",
            "<p>Runbook steps: 1. Deploy 2. Verify</p>",
        )
        .expect("create note in env");

    // Pre-condition check: item level (environment_id = None) has 0 secrets, files, notes
    assert!(vault
        .list_secrets(item.id, None)
        .expect("item secrets")
        .is_empty());
    assert!(vault
        .list_files(item.id, None)
        .expect("item files")
        .is_empty());
    assert!(vault
        .list_notes(item.id, None)
        .expect("item notes")
        .is_empty());

    // Environment-level listings contain the records
    assert_eq!(
        vault
            .list_secrets(item.id, Some(only_env.id))
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        vault.list_files(item.id, Some(only_env.id)).unwrap().len(),
        1
    );
    assert_eq!(
        vault.list_notes(item.id, Some(only_env.id)).unwrap().len(),
        1
    );

    // --- ACTION: Delete the ONLY environment with preserve_content: true ---
    vault
        .delete_environment_with_options(only_env.id, true)
        .expect(
            "delete_environment_with_options must succeed even for the only environment on an item",
        );

    // --- Post-condition 1: Environment is deleted; item now has 0 environments ---
    let envs_after = vault.list_environments(item.id).expect("list envs after");
    assert!(
        envs_after.is_empty(),
        "Item must have 0 environments after deleting the only environment"
    );

    // --- Post-condition 2: SQLite database verification ---
    let vault_id = vault.vault_id();
    let db_path = dir
        .path()
        .join("vaults")
        .join(vault_id.to_string())
        .join("vault.sqlite3");

    {
        let conn = open_connection(&db_path).expect("open SQLite");

        // Environment record: deleted = 1, blob IS NULL
        let (env_deleted, env_blob): (bool, Option<Vec<u8>>) = conn
            .query_row(
                "SELECT deleted, blob FROM records WHERE id = ?1",
                rusqlite::params![only_env.id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query env record");
        assert!(env_deleted, "Environment record must be marked deleted = 1");
        assert!(
            env_blob.is_none(),
            "Environment record blob must be cleared to NULL"
        );

        // Secret record: parent_id MUST be reparented to item.id, deleted = 0
        let (s_parent, s_deleted): (Vec<u8>, bool) = conn
            .query_row(
                "SELECT parent_id, deleted FROM records WHERE id = ?1",
                rusqlite::params![secret.id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query secret record");
        assert_eq!(
            Uuid::from_slice(&s_parent).unwrap(),
            item.id,
            "Secret parent_id must reparent to item.id"
        );
        assert!(!s_deleted, "Secret must remain active (deleted = 0)");

        // File record: parent_id MUST be reparented to item.id, deleted = 0
        let (f_parent, f_deleted): (Vec<u8>, bool) = conn
            .query_row(
                "SELECT parent_id, deleted FROM records WHERE id = ?1",
                rusqlite::params![file.id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query file record");
        assert_eq!(
            Uuid::from_slice(&f_parent).unwrap(),
            item.id,
            "File parent_id must reparent to item.id"
        );
        assert!(!f_deleted, "File must remain active (deleted = 0)");

        // Note record: parent_id MUST be reparented to item.id, deleted = 0
        let (n_parent, n_deleted): (Vec<u8>, bool) = conn
            .query_row(
                "SELECT parent_id, deleted FROM records WHERE id = ?1",
                rusqlite::params![note.id.as_bytes().as_slice()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .expect("query note record");
        assert_eq!(
            Uuid::from_slice(&n_parent).unwrap(),
            item.id,
            "Note parent_id must reparent to item.id"
        );
        assert!(!n_deleted, "Note must remain active (deleted = 0)");
    }

    // --- Post-condition 3: Secret accessible at item level ---
    let item_secrets = vault
        .list_secrets(item.id, None)
        .expect("list item secrets");
    assert_eq!(item_secrets.len(), 1);
    assert_eq!(item_secrets[0].id, secret.id);
    assert_eq!(item_secrets[0].name, "DATABASE_PASSWORD");
    let revealed = vault
        .reveal_secret(secret.id)
        .expect("reveal preserved secret");
    assert_eq!(revealed.expose_secret(), "super_secret_db_pass_9988");

    // --- Post-condition 4: File accessible at item level ---
    let item_files = vault.list_files(item.id, None).expect("list item files");
    assert_eq!(item_files.len(), 1);
    assert_eq!(item_files[0].id, file.id);
    assert_eq!(item_files[0].name, "spec.pdf");
    let (dl_meta, dl_data) = vault
        .download_file(file.id)
        .expect("download preserved file");
    assert_eq!(dl_meta.id, file.id);
    assert_eq!(dl_data, file_data);

    // --- Post-condition 5: Note accessible at item level ---
    let item_notes = vault.list_notes(item.id, None).expect("list item notes");
    assert_eq!(item_notes.len(), 1);
    assert_eq!(item_notes[0].id, note.id);
    assert_eq!(item_notes[0].title, "Deployment Runbook");
    let fetched_note = vault.get_note(note.id).expect("get preserved note");
    assert_eq!(
        fetched_note.content,
        "<p>Runbook steps: 1. Deploy 2. Verify</p>"
    );

    // Querying with old environment_id now returns NotFound
    assert!(matches!(
        vault.list_secrets(item.id, Some(only_env.id)),
        Err(Error::NotFound)
    ));
}

#[test]
fn test_adversarial_delete_only_environment_preserve_content_false() {
    let (dir, mut vault, _ks, label_id, _orig_item_id) = create_challenge_vault();

    // Create item with 1 environment
    let item = vault
        .create_item(label_id, "Cascade Delete Test Item", None)
        .expect("create item");

    let only_env = vault
        .add_environment(item.id, "to_be_purged")
        .expect("add env");

    let secret = vault
        .create_secret(SecretDraft::new(
            item.id,
            Some(only_env.id),
            "DISPOSABLE_SECRET",
            SecretKind::ApiKey,
            "temp_key_xyz",
            None,
        ))
        .expect("create secret");

    let file = vault
        .upload_file(
            item.id,
            Some(only_env.id),
            "temp_cache.tmp",
            b"temporary file data",
            None,
        )
        .expect("upload file");

    let note = vault
        .create_note(
            item.id,
            Some(only_env.id),
            "Scratchpad",
            "This will be deleted",
        )
        .expect("create note");

    // --- ACTION: Delete the ONLY environment with preserve_content: false ---
    vault
        .delete_environment_with_options(only_env.id, false)
        .expect("delete with preserve_content: false must succeed");

    // Item has 0 environments
    let envs = vault.list_environments(item.id).expect("list envs");
    assert!(envs.is_empty());

    // In SQLite: all records must have deleted = 1 and blob IS NULL
    let vault_id = vault.vault_id();
    let db_path = dir
        .path()
        .join("vaults")
        .join(vault_id.to_string())
        .join("vault.sqlite3");

    {
        let conn = open_connection(&db_path).expect("open SQLite");
        for (name, id) in [
            ("env", only_env.id),
            ("secret", secret.id),
            ("file", file.id),
            ("note", note.id),
        ] {
            let (deleted, blob): (bool, Option<Vec<u8>>) = conn
                .query_row(
                    "SELECT deleted, blob FROM records WHERE id = ?1",
                    rusqlite::params![id.as_bytes().as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap_or_else(|e| panic!("query {} failed: {:?}", name, e));

            assert!(deleted, "Record {} ({}) must have deleted = 1", name, id);
            assert!(
                blob.is_none(),
                "Record {} ({}) blob must be cleared to NULL",
                name,
                id
            );
        }
    }

    // Vault listings at item level are empty
    assert!(vault
        .list_secrets(item.id, None)
        .expect("secrets")
        .is_empty());
    assert!(vault.list_files(item.id, None).expect("files").is_empty());
    assert!(vault.list_notes(item.id, None).expect("notes").is_empty());

    // Direct fetches fail with NotFound
    assert!(matches!(
        vault.reveal_secret(secret.id),
        Err(Error::NotFound)
    ));
    assert!(matches!(vault.download_file(file.id), Err(Error::NotFound)));
    assert!(matches!(vault.get_note(note.id), Err(Error::NotFound)));
}

// ============================================================================
// 5. Single Environment Legacy Delete Protection Comparison
// ============================================================================

#[test]
fn test_adversarial_single_environment_legacy_delete_protection() {
    let (_dir, mut vault, _ks, label_id, _orig_item_id) = create_challenge_vault();

    let item = vault
        .create_item(label_id, "Legacy Env Delete Test Item", None)
        .expect("create item");

    let single_env = vault
        .add_environment(item.id, "lone_env")
        .expect("add single env");

    // Calling legacy delete_environment (which enforces last-environment protection)
    // MUST return Error::LastEnvironment
    let err_legacy = vault.delete_environment(single_env.id);
    assert!(
        matches!(err_legacy, Err(Error::LastEnvironment)),
        "Legacy delete_environment on the only environment must return Error::LastEnvironment, got: {:?}",
        err_legacy
    );

    // But delete_environment_with_options succeeds!
    let res_options = vault.delete_environment_with_options(single_env.id, true);
    assert!(
        res_options.is_ok(),
        "delete_environment_with_options must succeed where legacy delete_environment is protected"
    );
}
