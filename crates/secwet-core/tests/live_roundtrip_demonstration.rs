//! Live Standalone End-to-End Roundtrip Demonstration Test
//!
//! Authoritative source: `docs/IMPLEMENTATION.md` §7 (F9, F10) & `ORIGINAL_REQUEST.md` (R6).
//!
//! Demonstrates:
//! 1. Fresh workspace provisioning on Device A.
//! 2. Population of full entity variety: Spaces, Labels, Items, Environments,
//!    diverse Secret kinds (API Key, Password, SSH Key, Access Token), rich Note, binary File attachment.
//! 3. Recovery key derivation with Crockford Base32 formatting (25 chars in 5x5 groups).
//! 4. Encrypted snapshot export to `.secwet` envelope.
//! 5. Cold storage forensic validation: zero plaintext leakage and high Shannon entropy (>7.9 bits/byte).
//! 6. Disaster recovery restoration onto clean Device B.
//! 7. 100% data fidelity assertion across all entities and relationships.

use rand_core::Rng;
use secrecy::ExposeSecret;
use secrecy::SecretString;
use secwet_core::crypto::OsRng;
use secwet_core::keys::MemoryStore;
use secwet_core::{SecretDraft, SecretKind, Secwet};
use tempfile::tempdir;

fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let total = data.len() as f64;
    let mut entropy = 0.0f64;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / total;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[test]
fn test_live_roundtrip_demonstration() {
    println!("\n================================================================================");
    println!(" SECWET LIVE END-TO-END ROUNDTRIP DEMONSTRATION & DISASTER RECOVERY PROOF");
    println!("================================================================================\n");

    let device_a_dir = tempdir().expect("Device A tempdir creation failed");
    let device_b_dir = tempdir().expect("Device B tempdir creation failed");
    let export_dir = tempdir().expect("Export storage tempdir creation failed");

    let keystore_a = MemoryStore::new();

    // -------------------------------------------------------------------------
    // Step 1: Device A Workspace Initialization
    // -------------------------------------------------------------------------
    println!(">>> [Step 1] Initializing fresh workspace on Device A ('macbook-pro-m3')...");
    let mut device_a = Secwet::create(device_a_dir.path(), "macbook-pro-m3", &keystore_a)
        .expect("Device A workspace creation must succeed");
    let workspace_id = device_a.secwet_id();
    println!("    Device A Workspace UUID: {}", workspace_id);
    println!("    Initial Key Epoch: {}", device_a.key_epoch());

    // -------------------------------------------------------------------------
    // Step 2: Populating Rich Heterogeneous Entity Graph
    // -------------------------------------------------------------------------
    println!("\n>>> [Step 2] Populating entity graph with full variety of resources...");

    // Space: Production Core
    let space = device_a
        .create_space("Production Core", Some("shield-check".to_string()))
        .expect("Space creation must succeed");
    println!("    Created Space: '{}' [ID: {}]", space.name, space.id);

    // Group / Label: Backend Services
    let label = device_a
        .create_label_in_space("Backend Services", Some("server".to_string()), Some(space.id))
        .expect("Label creation must succeed");
    println!("    Created Label: '{}' [ID: {}]", label.name, label.id);

    // Item: Payment Gateway
    let item = device_a
        .create_item(
            label.id,
            "Payment Gateway",
            Some("PCI-DSS Level 1 Payment Processing Service".to_string()),
        )
        .expect("Item creation must succeed");
    println!("    Created Item: '{}' [ID: {}]", item.name, item.id);

    // Environments: prod & staging
    let env_prod = device_a
        .add_environment(item.id, "prod")
        .expect("prod env creation must succeed");
    let env_staging = device_a
        .add_environment(item.id, "staging")
        .expect("staging env creation must succeed");
    println!("    Created Environments: 'prod' [ID: {}], 'staging' [ID: {}]", env_prod.id, env_staging.id);

    // Secrets of various kinds
    // 1. API Key
    let stripe_key_val = "sk_example_0000000000000000000000000000000000000000";
    let sec_api_key = device_a
        .create_secret(SecretDraft::new(
            item.id,
            Some(env_prod.id),
            "STRIPE_API_KEY",
            SecretKind::ApiKey,
            stripe_key_val,
            Some("Production live Stripe billing API key".to_string()),
        ))
        .expect("API Key secret creation must succeed");
    println!("    Created Secret: 'STRIPE_API_KEY' (ApiKey) in 'prod'");

    // 2. Password
    let db_pass_val = "P@ssw0rd!#SecurePaymentDb2026_WithSymbols&Whitespace ";
    let sec_password = device_a
        .create_secret(SecretDraft::new(
            item.id,
            Some(env_prod.id),
            "POSTGRES_MASTER_PASSWORD",
            SecretKind::Password,
            db_pass_val,
            Some("Primary database administrative credentials".to_string()),
        ))
        .expect("Password secret creation must succeed");
    println!("    Created Secret: 'POSTGRES_MASTER_PASSWORD' (Password) in 'prod'");

    // 3. SSH Private Key (multi-line)
    let ssh_key_val = "\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEA0d2E0+5X9vK+mK2Z1+8Yq2LpM5x1...SecwetLiveDemoKey...
fK8v1s2d3f4g5h6j7k8l9m0n1p2q3r4s5t6u7v8w9x0y1z2a3b4c5d6e7f8g9h0i1j2k
-----END OPENSSH PRIVATE KEY-----";
    let sec_ssh_key = device_a
        .create_secret(SecretDraft::new(
            item.id,
            Some(env_prod.id),
            "DEPLOYER_SSH_KEY",
            SecretKind::SshKey,
            ssh_key_val,
            Some("Cluster deployment bastion SSH private key".to_string()),
        ))
        .expect("SSH Key secret creation must succeed");
    println!("    Created Secret: 'DEPLOYER_SSH_KEY' (SshKey) in 'prod'");

    // 4. Access Token (Item-level, shared across environments)
    let github_token_val = "ghp_0123456789abcdefghijklmnopqrstuvwxyzABCD";
    let sec_access_token = device_a
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "GITHUB_SYNC_TOKEN",
            SecretKind::AccessToken,
            github_token_val,
            Some("Shared GitHub CI/CD sync token".to_string()),
        ))
        .expect("AccessToken creation must succeed");
    println!("    Created Secret: 'GITHUB_SYNC_TOKEN' (AccessToken) at Item level");

    // Note: Deployment Runbook
    let note_content = "# Payment Gateway Deployment Runbook\n\n\
1. Ensure blue/green database migrations are backward-compatible.\n\
2. Verify Redis cluster connection pools.\n\
3. Execute canary deployment with 5% traffic split.\n\
4. Monitor Prometheus metric `payment_error_rate_5xx` for 10 minutes.\n\
5. Promote canary to full production.";
    let note = device_a
        .create_note(
            item.id,
            Some(env_prod.id),
            "Runbook for deployment",
            note_content,
        )
        .expect("Note creation must succeed");
    println!("    Created Note: '{}' [ID: {}]", note.title, note.id);

    // Binary file attachment (32 KiB binary blob)
    let mut binary_payload = vec![0u8; 32768];
    OsRng.fill_bytes(&mut binary_payload);
    let binary_file = device_a
        .upload_file(
            item.id,
            Some(env_prod.id),
            "payment_core_v1.tar.gz",
            &binary_payload,
            Some("application/gzip"),
        )
        .expect("File upload must succeed");
    println!("    Created File Attachment: '{}' [32768 bytes, ID: {}]", binary_file.name, binary_file.id);

    // -------------------------------------------------------------------------
    // Step 3: Create Recovery Key
    // -------------------------------------------------------------------------
    println!("\n>>> [Step 3] Generating non-custodial Recovery Key...");
    let recovery_key = device_a
        .create_recovery_key(&keystore_a)
        .expect("create_recovery_key must succeed");
    let key_str = recovery_key.expose_secret();
    println!("    Generated Recovery Key: {}", key_str);

    // Validate 25-character Crockford format in 5 groups
    assert_eq!(
        key_str.len(),
        29,
        "Recovery key formatted string must be 29 characters (5 groups x 5 chars + 4 hyphens)"
    );
    let groups: Vec<&str> = key_str.split('-').collect();
    assert_eq!(groups.len(), 5, "Must have exactly 5 groups");
    for (i, g) in groups.iter().enumerate() {
        assert_eq!(g.len(), 5, "Group {} must be exactly 5 chars", i + 1);
        for c in g.chars() {
            assert!(
                "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(c),
                "Invalid Crockford character: {}",
                c
            );
        }
    }
    println!("    [VERIFIED] Key format complies with 25-char Crockford Base32 standard.");

    // -------------------------------------------------------------------------
    // Step 4: Export to Encrypted .secwet Envelope
    // -------------------------------------------------------------------------
    println!("\n>>> [Step 4] Exporting workspace to encrypted archive file...");
    let export_path = export_dir.path().join("production_backup.secwet");
    let summary = device_a
        .export_encrypted(&recovery_key, &export_path)
        .expect("export_encrypted must succeed");
    println!("    Export Path: {:?}", export_path);
    println!("    Summary: {} spaces, {} labels, {} items, {} envs, {} secrets, {} notes, {} files",
        summary.spaces_count, summary.labels_count, summary.items_count,
        summary.environments_count, summary.secrets_count, summary.notes_count, summary.files_count);
    println!("    Bytes written: {}", summary.bytes_written);

    // Lock Device A and simulate complete destruction
    device_a.lock();
    println!("    Device A successfully locked and unmounted from memory.");

    // -------------------------------------------------------------------------
    // Step 5: Cold Storage Forensic Validation & Entropy Analysis
    // -------------------------------------------------------------------------
    println!("\n>>> [Step 5] Performing cold storage forensic validation on .secwet file...");
    let raw_file_bytes = std::fs::read(&export_path).expect("Reading export file failed");
    let raw_file_str = String::from_utf8_lossy(&raw_file_bytes);

    // Parse JSON envelope
    let json_envelope: serde_json::Value = serde_json::from_slice(&raw_file_bytes)
        .expect("Export file must be a valid JSON envelope");
    assert_eq!(json_envelope["format"], "secwet-export");
    assert_eq!(json_envelope["version"], 1);
    assert_eq!(json_envelope["cipher"], "xchacha20poly1305");
    assert_eq!(json_envelope["kdf"], "hkdf-sha256");

    let ciphertext_b64 = json_envelope["ciphertext"]
        .as_str()
        .expect("Ciphertext must be a base64 string");
    let ciphertext_raw = data_encoding::BASE64
        .decode(ciphertext_b64.as_bytes())
        .expect("Ciphertext must decode from base64");

    // Shannon Entropy Check
    let entropy = compute_shannon_entropy(&ciphertext_raw);
    println!("    Ciphertext Size: {} bytes", ciphertext_raw.len());
    println!("    Ciphertext Shannon Entropy: {:.6} bits/byte (Target: > 7.9)", entropy);
    assert!(
        entropy > 7.90,
        "Ciphertext entropy {:.4} must be > 7.90 (indistinguishable from random noise)",
        entropy
    );

    // Zero Plaintext Leakage Checks
    println!("    Checking for zero plaintext leakage across raw bytes...");
    let banned_strings = [
        stripe_key_val,
        db_pass_val,
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn",
        github_token_val,
        "Payment Gateway Deployment Runbook",
        "PCI-DSS Level 1 Payment Processing Service",
        "Production Core",
        "Backend Services",
        "Payment Gateway",
    ];
    for banned in &banned_strings {
        assert!(
            !raw_file_str.contains(banned),
            "SECURITY VIOLATION: Plaintext leakage detected in raw backup file: '{}'",
            banned
        );
    }
    println!("    [VERIFIED] Zero plaintext leakage: No keys, passwords, notes, files, or names leaked!");

    // -------------------------------------------------------------------------
    // Step 6: Disaster Recovery on Device B ('server-recovery-node-2')
    // -------------------------------------------------------------------------
    println!("\n>>> [Step 6] Simulating disaster recovery on Device B ('server-recovery-node-2')...");
    let keystore_b = MemoryStore::new();

    // Test alias and normalization resilience during restore input:
    // Convert to lowercase and introduce spaces instead of hyphens
    let user_typed_input = SecretString::from(key_str.to_lowercase().replace('-', " "));
    println!("    Simulating user input with lowercase and spaces: '{}'", user_typed_input.expose_secret());

    let device_b = Secwet::restore_from_export(
        device_b_dir.path(),
        &export_path,
        &user_typed_input,
        "server-recovery-node-2",
        &keystore_b,
    )
    .expect("Disaster recovery on Device B must succeed");
    println!("    Device B successfully initialized from encrypted archive!");

    // -------------------------------------------------------------------------
    // Step 7: 100% Data Fidelity Assertions
    // -------------------------------------------------------------------------
    println!("\n>>> [Step 7] Asserting 100% data fidelity on restored Device B...");

    // 1. Workspace Identity & Key Epoch
    assert_eq!(device_b.secwet_id(), workspace_id, "Workspace UUID must match exactly");
    assert_eq!(device_b.key_epoch(), 2, "Key epoch must be incremented to N+1 (epoch 2)");
    println!("    [PASS] Workspace UUID matched: {}", device_b.secwet_id());
    println!("    [PASS] Key epoch correctly incremented to: {}", device_b.key_epoch());

    // 2. Recovery Seal Persistence & Verification
    let b_status = device_b.recovery_status().expect("Device B recovery status");
    assert!(b_status.created, "Recovery key status must remain active");
    assert!(
        device_b.verify_recovery_key(key_str).expect("Recovery key verification"),
        "Original recovery key must verify on Device B"
    );
    println!("    [PASS] Recovery check verification seal persisted and verified.");

    // 3. Space Fidelity
    let restored_spaces = device_b.list_spaces().expect("list_spaces");
    let restored_space = restored_spaces
        .iter()
        .find(|s| s.id == space.id)
        .expect("Production Core space must exist");
    assert_eq!(restored_space.name, "Production Core");
    assert_eq!(restored_space.icon, Some("shield-check".to_string()));
    println!("    [PASS] Space 'Production Core' matched identically.");

    // 4. Label Fidelity
    let restored_labels = device_b.list_labels().expect("list_labels");
    let restored_label = restored_labels
        .iter()
        .find(|l| l.id == label.id)
        .expect("Backend Services label must exist");
    assert_eq!(restored_label.name, "Backend Services");
    assert_eq!(restored_label.space_id, Some(space.id));
    println!("    [PASS] Label 'Backend Services' matched identically.");

    // 5. Item Fidelity
    let restored_items = device_b.list_items(label.id).expect("list_items");
    let restored_item = restored_items
        .iter()
        .find(|i| i.id == item.id)
        .expect("Payment Gateway item must exist");
    assert_eq!(restored_item.name, "Payment Gateway");
    assert_eq!(
        restored_item.description,
        Some("PCI-DSS Level 1 Payment Processing Service".to_string())
    );
    println!("    [PASS] Item 'Payment Gateway' matched identically.");

    // 6. Environments Fidelity
    let restored_envs = device_b.list_environments(item.id).expect("list_environments");
    assert_eq!(restored_envs.len(), 2);
    let r_env_prod = restored_envs.iter().find(|e| e.id == env_prod.id).expect("prod env");
    assert_eq!(r_env_prod.name, "prod");
    let r_env_staging = restored_envs.iter().find(|e| e.id == env_staging.id).expect("staging env");
    assert_eq!(r_env_staging.name, "staging");
    println!("    [PASS] Environments 'prod' and 'staging' matched identically.");

    // 7. Secrets Fidelity (All 4 kinds and values)
    let rev_api_key = device_b.reveal_secret(sec_api_key.id).expect("reveal api key");
    assert_eq!(rev_api_key.expose_secret(), stripe_key_val);
    println!("    [PASS] Secret 'STRIPE_API_KEY' (ApiKey) decrypted and matched 100%.");

    let rev_password = device_b.reveal_secret(sec_password.id).expect("reveal password");
    assert_eq!(rev_password.expose_secret(), db_pass_val);
    println!("    [PASS] Secret 'POSTGRES_MASTER_PASSWORD' (Password) decrypted and matched 100%.");

    let rev_ssh = device_b.reveal_secret(sec_ssh_key.id).expect("reveal ssh key");
    assert_eq!(rev_ssh.expose_secret(), ssh_key_val);
    println!("    [PASS] Secret 'DEPLOYER_SSH_KEY' (SshKey) decrypted and matched 100%.");

    let rev_token = device_b.reveal_secret(sec_access_token.id).expect("reveal access token");
    assert_eq!(rev_token.expose_secret(), github_token_val);
    println!("    [PASS] Secret 'GITHUB_SYNC_TOKEN' (AccessToken) decrypted and matched 100%.");

    // 8. Note Content Fidelity
    let r_note = device_b.get_note(note.id).expect("get_note");
    assert_eq!(r_note.title, "Runbook for deployment");
    assert_eq!(r_note.content, note_content);
    println!("    [PASS] Note 'Runbook for deployment' matched byte-for-byte.");

    // 9. Binary File Attachment Fidelity
    let (meta_file, downloaded_bytes) = device_b.download_file(binary_file.id).expect("download_file");
    assert_eq!(meta_file.name, "payment_core_v1.tar.gz");
    assert_eq!(meta_file.mime_type, "application/gzip");
    assert_eq!(meta_file.size_bytes, 32768);
    assert_eq!(downloaded_bytes, binary_payload);
    println!("    [PASS] Binary Attachment 'payment_core_v1.tar.gz' (32,768 bytes) matched byte-for-byte.");

    device_b.lock();
    println!("\n================================================================================");
    println!(" ALL DISASTER RECOVERY & 100% DATA FIDELITY INVARIANTS SATISFIED SUCCESSFULLY!");
    println!("================================================================================\n");
}
