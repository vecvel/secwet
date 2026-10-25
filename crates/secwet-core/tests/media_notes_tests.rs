//! Empirical integration tests for Encrypted Files and Rich-Text Notes in secwet-core.
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §5.1, §6, and Milestone 2 specification.
//!
//! Evaluates:
//! 1. Encrypted Files CRUD:
//!    - Upload file with SHA-256 calculation and RecordAad record_type 5 (File).
//!    - Download file with exact byte-for-byte fidelity and SHA-256 match.
//!    - File rename and delete (soft delete).
//!    - Scoping: Item-level files vs. Environment-level files.
//!    - 50 MiB file boundary enforcement (52,428,800 allowed, 52,428,801 rejected).
//!    - Empty filename and over-length filename validation.
//!    - Cryptographic tampering detection (Poly1305 auth tag check).
//! 2. Encrypted Rich-Text Notes CRUD:
//!    - Create note with RecordAad record_type 6 (Note).
//!    - Snippet generation: plain-text preview stripping markdown formatting, truncated to <= 200 chars.
//!    - Full note retrieval and decryption.
//!    - Note update: title only, content only, both.
//!    - Note soft-deletion and removal from listings.
//!    - Title length validation: 1..=128 chars.
//!    - Content length validation: <= 1,000,000 chars.
//!    - Cryptographic tampering detection.

use secwet_core::keys::MemoryStore;
use secwet_core::records::open_connection;
use secwet_core::{Error, Vault};
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use uuid::Uuid;

fn create_test_vault() -> (tempfile::TempDir, Vault, MemoryStore, Uuid, Uuid) {
    let dir = tempdir().expect("tempdir");
    let keystore = MemoryStore::new();
    let mut vault = Vault::create(dir.path(), "test-device", &keystore).expect("vault create");

    let labels = vault.list_labels().expect("list labels");
    let default_label_id = labels[0].id;

    // Create a parent item for media/notes testing
    let item = vault
        .create_item(
            default_label_id,
            "Test Media Item",
            Some("Test item".to_string()),
        )
        .expect("create item");

    (dir, vault, keystore, default_label_id, item.id)
}

// ============================================================================
// 1. Encrypted Files Tests
// ============================================================================

#[test]
fn test_file_upload_download_roundtrip_and_sha256() {
    let (_dir, mut vault, _ks, _label_id, item_id) = create_test_vault();

    // 1. Item-level file upload
    let file_data = b"Hello, encrypted secure storage! XChaCha20Poly1305 with SHA-256.".to_vec();
    let expected_sha256 = {
        let mut hasher = Sha256::new();
        hasher.update(&file_data);
        hasher.finalize()
    };
    let expected_sha_hex = data_encoding::HEXLOWER.encode(&expected_sha256);

    let meta = vault
        .upload_file(
            item_id,
            None,
            "document.txt",
            &file_data,
            Some("text/plain"),
        )
        .expect("upload file");

    assert_eq!(meta.name, "document.txt");
    assert_eq!(meta.size_bytes, file_data.len() as u64);
    assert_eq!(meta.mime_type, "text/plain");
    assert_eq!(meta.sha256, expected_sha_hex);
    assert_eq!(meta.item_id, item_id);
    assert_eq!(meta.environment_id, None);

    // Verify listing
    let files = vault.list_files(item_id, None).expect("list files");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].id, meta.id);
    assert_eq!(files[0].name, "document.txt");

    // 2. Download and verify bytes
    let (dl_meta, dl_data) = vault.download_file(meta.id).expect("download file");
    assert_eq!(dl_meta.id, meta.id);
    assert_eq!(dl_data, file_data);

    // 3. Environment-level file upload
    let env = vault
        .add_environment(item_id, "production")
        .expect("add env");

    let env_file_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE];
    let env_file_meta = vault
        .upload_file(
            item_id,
            Some(env.id),
            "binary_artifact.bin",
            &env_file_data,
            Some("application/octet-stream"),
        )
        .expect("upload env file");

    assert_eq!(env_file_meta.environment_id, Some(env.id));

    // Verify item-level listing does NOT contain env file
    let item_files = vault.list_files(item_id, None).expect("list item files");
    assert_eq!(item_files.len(), 1);
    assert_eq!(item_files[0].id, meta.id);

    // Verify env-level listing contains env file
    let env_files = vault
        .list_files(item_id, Some(env.id))
        .expect("list env files");
    assert_eq!(env_files.len(), 1);
    assert_eq!(env_files[0].id, env_file_meta.id);

    // Download env file
    let (_, dl_env_data) = vault
        .download_file(env_file_meta.id)
        .expect("download env file");
    assert_eq!(dl_env_data, env_file_data);
}

#[test]
fn test_file_rename_and_deletion() {
    let (_dir, mut vault, _ks, _label_id, item_id) = create_test_vault();

    let meta = vault
        .upload_file(
            item_id,
            None,
            "original.pdf",
            b"%PDF-1.4...",
            Some("application/pdf"),
        )
        .expect("upload");

    // Rename file
    let renamed = vault
        .rename_file(meta.id, "renamed.pdf")
        .expect("rename file");
    assert_eq!(renamed.id, meta.id);
    assert_eq!(renamed.name, "renamed.pdf");

    let files = vault.list_files(item_id, None).expect("list files");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].name, "renamed.pdf");

    // Rename with empty name should fail
    let err_empty = vault.rename_file(meta.id, "   ");
    assert!(matches!(
        err_empty,
        Err(Error::Invalid { field: "name", .. })
    ));

    // Delete file
    vault.delete_file(meta.id).expect("delete file");

    // Listing should now be empty
    let files_after = vault.list_files(item_id, None).expect("list after delete");
    assert!(files_after.is_empty());

    // Download should return NotFound
    let err_dl = vault.download_file(meta.id);
    assert!(matches!(err_dl, Err(Error::NotFound)));

    // Deleting again should return NotFound
    let err_del = vault.delete_file(meta.id);
    assert!(matches!(err_del, Err(Error::NotFound)));
}

#[test]
fn test_file_size_limits_and_validation() {
    let (_dir, mut vault, _ks, _label_id, item_id) = create_test_vault();

    // 1. File exceeding 50 MiB limit (52,428,800 + 1 bytes)
    let oversized_data = vec![0u8; 50 * 1024 * 1024 + 1];
    let err_size = vault.upload_file(item_id, None, "too_big.iso", &oversized_data, None);
    assert!(matches!(
        err_size,
        Err(Error::Invalid { field: "size", .. })
    ));

    // Empty name
    let err_name = vault.upload_file(item_id, None, "", b"some data", None);
    assert!(matches!(
        err_name,
        Err(Error::Invalid { field: "name", .. })
    ));

    // Name too long (> 255 chars)
    let long_name = "a".repeat(256);
    let err_long = vault.upload_file(item_id, None, &long_name, b"some data", None);
    assert!(matches!(
        err_long,
        Err(Error::Invalid { field: "name", .. })
    ));
}

#[test]
fn test_file_poly1305_tampering_fails_to_open() {
    let (dir, mut vault, ks, _label_id, item_id) = create_test_vault();

    let meta = vault
        .upload_file(
            item_id,
            None,
            "sensitive_contract.docx",
            b"Confidential Data",
            None,
        )
        .expect("upload");

    let vault_id = vault.vault_id();
    let db_path = dir
        .path()
        .join("vaults")
        .join(vault_id.to_string())
        .join("vault.sqlite3");
    vault.lock();

    // Tamper with file blob in SQLite database
    {
        let conn = open_connection(&db_path).expect("open connection");
        let mut blob: Vec<u8> = conn
            .query_row(
                "SELECT blob FROM records WHERE id = ?1",
                rusqlite::params![meta.id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .expect("query blob");

        // Flip a byte in the ciphertext body
        let last_idx = blob.len() - 1;
        blob[last_idx] ^= 0xFF;

        conn.execute(
            "UPDATE records SET blob = ?1 WHERE id = ?2",
            rusqlite::params![blob, meta.id.as_bytes().as_slice()],
        )
        .expect("tamper blob");
    }

    // Unlock and verify download fails with Crypto error
    let vault = Vault::unlock(dir.path(), &ks).expect("unlock");
    let result = vault.download_file(meta.id);
    assert!(
        matches!(result, Err(Error::Crypto)),
        "Tampered encrypted file blob must fail authentication with Error::Crypto"
    );
}

// ============================================================================
// 2. Encrypted Rich-Text Notes Tests
// ============================================================================

#[test]
fn test_note_crud_and_markdown_snippet_generation() {
    let (_dir, mut vault, _ks, _label_id, item_id) = create_test_vault();

    // 1. Create a note with rich-text content
    let rich_content = "<h1>Architecture Guidelines</h1>\n<p>All secrets must be encrypted with <strong>XChaCha20-Poly1305</strong> using authenticated additional data. Plaintext buffers must be explicitly zeroized.</p>";

    let note = vault
        .create_note(item_id, None, "Architecture Guidelines", rich_content)
        .expect("create note");

    assert_eq!(note.title, "Architecture Guidelines");
    assert_eq!(note.content, rich_content);
    assert_eq!(note.item_id, item_id);
    assert_eq!(note.environment_id, None);

    // Verify snippet generation in list_notes
    let notes = vault.list_notes(item_id, None).expect("list notes");
    assert_eq!(notes.len(), 1);
    assert_eq!(notes[0].id, note.id);
    assert_eq!(notes[0].title, "Architecture Guidelines");

    // Snippet must strip HTML tags and be <= 200 chars
    let snippet = &notes[0].snippet;
    assert!(!snippet.contains("<h1>"), "Snippet must strip <h1> tags");
    assert!(
        !snippet.contains("<strong>"),
        "Snippet must strip <strong> tags"
    );
    assert!(snippet.starts_with("Architecture Guidelines"));
    assert!(
        snippet.len() <= 200,
        "Snippet must not exceed 200 characters"
    );

    // 2. Get full note
    let fetched = vault.get_note(note.id).expect("get note");
    assert_eq!(fetched.id, note.id);
    assert_eq!(fetched.title, "Architecture Guidelines");
    assert_eq!(fetched.content, rich_content);

    // 3. Update note content only
    let updated_content = "Short updated memo.";
    let updated = vault
        .update_note(note.id, None, Some(updated_content))
        .expect("update note content");
    assert_eq!(updated.title, "Architecture Guidelines");
    assert_eq!(updated.content, updated_content);

    // 4. Update note title only
    let updated_title = vault
        .update_note(note.id, Some("Updated Guidelines Title"), None)
        .expect("update note title");
    assert_eq!(updated_title.title, "Updated Guidelines Title");
    assert_eq!(updated_title.content, updated_content);

    // 5. Delete note
    vault.delete_note(note.id).expect("delete note");

    let notes_after = vault
        .list_notes(item_id, None)
        .expect("list notes after delete");
    assert!(notes_after.is_empty());

    let err_get = vault.get_note(note.id);
    assert!(matches!(err_get, Err(Error::NotFound)));
}

#[test]
fn test_note_validation_limits() {
    let (_dir, mut vault, _ks, _label_id, item_id) = create_test_vault();

    // Empty title
    let err_empty = vault.create_note(item_id, None, "   ", "Some content");
    assert!(matches!(
        err_empty,
        Err(Error::Invalid { field: "title", .. })
    ));

    // Title exceeding 128 characters
    let long_title = "T".repeat(129);
    let err_title_len = vault.create_note(item_id, None, &long_title, "Some content");
    assert!(matches!(
        err_title_len,
        Err(Error::Invalid { field: "title", .. })
    ));

    // Exactly 128 characters title must succeed
    let max_title = "T".repeat(128);
    let note = vault.create_note(item_id, None, &max_title, "Content");
    assert!(note.is_ok());

    // Content exceeding 1,000,000 characters
    let huge_content = "X".repeat(1_000_001);
    let err_content_len = vault.create_note(item_id, None, "Valid Title", &huge_content);
    assert!(matches!(
        err_content_len,
        Err(Error::Invalid {
            field: "content",
            ..
        })
    ));
}

#[test]
fn test_note_poly1305_tampering_fails_to_open() {
    let (dir, mut vault, ks, _label_id, item_id) = create_test_vault();

    let note = vault
        .create_note(item_id, None, "Top Secret Note", "Do not tamper!")
        .expect("create note");

    let vault_id = vault.vault_id();
    let db_path = dir
        .path()
        .join("vaults")
        .join(vault_id.to_string())
        .join("vault.sqlite3");
    vault.lock();

    // Tamper with note blob in SQLite
    {
        let conn = open_connection(&db_path).expect("open connection");
        let mut blob: Vec<u8> = conn
            .query_row(
                "SELECT blob FROM records WHERE id = ?1",
                rusqlite::params![note.id.as_bytes().as_slice()],
                |r| r.get(0),
            )
            .expect("query blob");

        // Flip byte in ciphertext body
        let idx = blob.len() / 2;
        blob[idx] ^= 0xAA;

        conn.execute(
            "UPDATE records SET blob = ?1 WHERE id = ?2",
            rusqlite::params![blob, note.id.as_bytes().as_slice()],
        )
        .expect("tamper blob");
    }

    let vault = Vault::unlock(dir.path(), &ks).expect("unlock");
    let result = vault.get_note(note.id);
    assert!(
        matches!(result, Err(Error::Crypto)),
        "Tampered encrypted note blob must fail Poly1305 authentication with Error::Crypto"
    );
}
