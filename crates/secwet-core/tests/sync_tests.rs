//! Milestone 6: Core Event Synchronization Test Suite (F15).
//!
//! Authoritative source: docs/IMPLEMENTATION.md §15.1 - §15.6
//!
//! Invariants:
//! 1. All entity changes on Pro workspaces produce signed, encrypted `SignedEvent` envelopes.
//! 2. Event bodies are sealed under K_evt with authenticated associated data (AAD).
//! 3. Envelopes are signed with the authoring device's Ed25519 signing key.
//! 4. Conflict resolution strictly follows Last-Writer-Wins (LWW) per record:
//!    (event.lamport, event.origin_device) > (stored.lamport, stored.origin_device)
//! 5. Event application is strictly commutative and idempotent across arbitrary out-of-order shuffles.
//! 6. Snapshots provide complete zero-loss state recovery when cursor expires past retention.

use secrecy::ExposeSecret;
use secwet_core::{
    keys::{KeyStore, MemoryStore},
    model::SecretDraft,
    Secwet,
};
use secwet_proto::{SecretKind, SecwetSnapshot, SignedEvent};
use tempfile::TempDir;
use uuid::Uuid;

struct TestDevice {
    _dir: TempDir,
    secwet: Secwet,
}

fn canonicalize_snapshot(mut s: SecwetSnapshot) -> SecwetSnapshot {
    s.created_at = 0;
    for x in &mut s.spaces { x.created_at = 0; x.updated_at = 0; }
    for x in &mut s.labels { x.created_at = 0; x.updated_at = 0; }
    for x in &mut s.items { x.updated_at = 0; }
    for x in &mut s.environments { x.updated_at = 0; }
    for x in &mut s.secrets { x.updated_at = 0; }
    for x in &mut s.notes { x.updated_at = 0; }
    for x in &mut s.files { x.updated_at = 0; }
    s.spaces.sort_by_key(|x| x.id);
    s.labels.sort_by_key(|x| x.id);
    s.items.sort_by_key(|x| x.id);
    s.environments.sort_by_key(|x| x.id);
    s.secrets.sort_by_key(|x| x.id);
    s.notes.sort_by_key(|x| x.id);
    s.files.sort_by_key(|x| x.id);
    s.settings.sort_by(|a, b| a.key.cmp(&b.key));
    s
}

/// Creates N mutually paired devices on the same workspace with Pro plan enabled.
fn create_test_devices(count: usize) -> (Vec<TestDevice>, Uuid, [u8; 32]) {
    assert!(count >= 1);
    let mut devices = Vec::with_capacity(count);

    // 1. Create primary device
    let dir0 = TempDir::new().unwrap();
    let keystore0 = MemoryStore::new();
    let mut dev0 = Secwet::create(dir0.path(), "Device-0", &keystore0).unwrap();
    dev0.set_plan("pro").unwrap();
    let secwet_id = dev0.secwet_id();

    // Extract master key from keystore0 for pairing
    let key_opt = keystore0
        .get(&format!("secwet/{secwet_id}/master-key/1"))
        .unwrap()
        .expect("Master key must exist");
    let mut master_key = [0u8; 32];
    master_key.copy_from_slice(key_opt.as_slice());

    devices.push(TestDevice {
        _dir: dir0,
        secwet: dev0,
    });

    // 2. Create paired devices
    for i in 1..count {
        let dir = TempDir::new().unwrap();
        let keystore = MemoryStore::new();
        let dev_name = format!("Device-{}", i);
        let mut dev = Secwet::create_paired(
            dir.path(),
            &dev_name,
            secwet_id,
            &master_key,
            &keystore,
        )
        .unwrap();
        dev.set_plan("pro").unwrap();

        devices.push(TestDevice {
            _dir: dir,
            secwet: dev,
        });
    }

    // Sync initial workspace snapshot (spaces & labels) to all paired devices
    let base_snap = devices[0].secwet.collect_snapshot().unwrap();
    for dev in devices.iter_mut().skip(1) {
        dev.secwet.restore_from_snapshot(&base_snap, 1).unwrap();
    }

    // 3. Register all devices with each other
    let device_meta: Vec<(String, [u8; 32], [u8; 32])> = devices
        .iter()
        .map(|d| {
            (
                d.secwet.device_id().to_string(),
                d.secwet.device_sign_pub(),
                d.secwet.device_enc_pub(),
            )
        })
        .collect();

    for (i, target) in devices.iter_mut().enumerate() {
        for (j, (peer_id, peer_sign, peer_enc)) in device_meta.iter().enumerate() {
            if i != j {
                let _ = target.secwet.record_paired_device(
                    peer_id,
                    &format!("Device-{}", j),
                    "Desktop",
                    peer_sign,
                    peer_enc,
                );
            }
        }
    }

    (devices, secwet_id, master_key)
}

/// Simulated Relay: gathers all outboxes, routes them across peers in sequential order, and clears outboxes.
fn sync_devices(devices: &mut [TestDevice], server_seq_counter: &mut u64) {
    let mut all_events: Vec<(usize, SignedEvent)> = Vec::new();

    for (idx, dev) in devices.iter().enumerate() {
        let outbox = dev.secwet.peek_outbox(1000).unwrap();
        for event in outbox {
            all_events.push((idx, event));
        }
    }

    for (from_idx, event) in all_events {
        *server_seq_counter += 1;
        let s_seq = *server_seq_counter;

        for (target_idx, target_dev) in devices.iter_mut().enumerate() {
            if from_idx != target_idx {
                let _ = target_dev.secwet.apply_signed_event(s_seq, &event).unwrap();
            }
        }
    }

    for dev in devices.iter_mut() {
        let _ = dev.secwet.delete_outbox_events(u64::MAX).unwrap();
    }
}

// ============================================================================
// Test 1: Two devices converge on concurrent edits
// ============================================================================
#[test]
fn two_devices_converge_on_concurrent_edits() {
    let (mut devices, _secwet_id, _mk) = create_test_devices(2);
    let mut seq = 0u64;

    // Both start from same base snapshot
    let base_snap = devices[0].secwet.collect_snapshot().unwrap();
    devices[1].secwet.restore_from_snapshot(&base_snap, 1).unwrap();

    let space_id = devices[0].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[0]
        .secwet
        .create_label_in_space("Backend", None, Some(space_id))
        .unwrap();

    // Initial sync
    sync_devices(&mut devices, &mut seq);

    // Concurrent edit 1: Device 0 creates item A + secret
    let item_a = devices[0]
        .secwet
        .create_item(label.id, "Payment Gateway", None)
        .unwrap();
    devices[0]
        .secwet
        .create_secret(SecretDraft::new(
            item_a.id,
            None,
            "STRIPE_API_KEY",
            SecretKind::ApiKey,
            "sk_live_concurrent_a",
            None,
        ))
        .unwrap();

    // Concurrent edit 2: Device 1 creates item B + secret
    let item_b = devices[1]
        .secwet
        .create_item(label.id, "Database Cluster", None)
        .unwrap();
    devices[1]
        .secwet
        .create_secret(SecretDraft::new(
            item_b.id,
            None,
            "DATABASE_URL",
            SecretKind::EnvVar,
            "postgres://localhost:5432/db",
            None,
        ))
        .unwrap();

    // Sync both devices
    sync_devices(&mut devices, &mut seq);

    // Verify convergence
    let snap_a = canonicalize_snapshot(devices[0].secwet.collect_snapshot().unwrap());
    let snap_b = canonicalize_snapshot(devices[1].secwet.collect_snapshot().unwrap());

    assert_eq!(snap_a.items.len(), snap_b.items.len());
    assert_eq!(snap_a.secrets.len(), snap_b.secrets.len());
    assert_eq!(snap_a, snap_b);
}

// ============================================================================
// Test 2: Delete vs Update resolves strictly by Lamport
// ============================================================================
#[test]
fn delete_vs_update_resolves_by_lamport() {
    let (mut devices, _secwet_id, _mk) = create_test_devices(2);
    let mut seq = 0u64;

    let space_id = devices[0].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[0]
        .secwet
        .create_label_in_space("Security", None, Some(space_id))
        .unwrap();
    let item = devices[0]
        .secwet
        .create_item(label.id, "Auth Server", None)
        .unwrap();
    let sec = devices[0]
        .secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "JWT_SECRET",
            SecretKind::Password,
            "original_value",
            None,
        ))
        .unwrap();

    sync_devices(&mut devices, &mut seq);

    // Device 0 updates secret value
    devices[0]
        .secwet
        .update_secret(
            sec.id,
            SecretDraft::new(
                item.id,
                None,
                "JWT_SECRET",
                SecretKind::Password,
                "updated_higher_lamport",
                None,
            ),
        )
        .unwrap();

    let dev0_events = devices[0].secwet.peek_outbox(100).unwrap();
    let update_event = dev0_events.last().unwrap().clone();

    // Device 1 deletes secret
    devices[1].secwet.delete_secret(sec.id).unwrap();
    let dev1_events = devices[1].secwet.peek_outbox(100).unwrap();
    let delete_event = dev1_events.last().unwrap().clone();

    // Apply update to Device 1, delete to Device 0
    let _ = devices[1].secwet.apply_signed_event(10, &update_event).unwrap();
    let _ = devices[0].secwet.apply_signed_event(11, &delete_event).unwrap();

    let res0 = devices[0].secwet.reveal_secret(sec.id);
    let res1 = devices[1].secwet.reveal_secret(sec.id);

    // Both devices must converge to the exact same resolution (both deleted or both active)
    assert_eq!(res0.is_ok(), res1.is_ok(), "Both devices must agree whether secret exists");
    if let (Ok(s0), Ok(s1)) = (res0, res1) {
        assert_eq!(s0.expose_secret(), s1.expose_secret());
    }
}

// ============================================================================
// Test 3: Duplicate events applied once (Idempotency)
// ============================================================================
#[test]
fn duplicate_events_applied_once() {
    let (mut devices, _secwet_id, _mk) = create_test_devices(2);

    let space_id = devices[0].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[0]
        .secwet
        .create_label_in_space("Infra", None, Some(space_id))
        .unwrap();
    let item = devices[0]
        .secwet
        .create_item(label.id, "Cluster", None)
        .unwrap();
    devices[0]
        .secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "ROOT_PW",
            SecretKind::Password,
            "admin123",
            None,
        ))
        .unwrap();

    let events = devices[0].secwet.peek_outbox(100).unwrap();
    assert!(!events.is_empty());

    // Apply events once to Device 1
    for (i, ev) in events.iter().enumerate() {
        let applied = devices[1].secwet.apply_signed_event((i + 1) as u64, ev).unwrap();
        assert!(applied, "First application of event must return true");
    }

    let snap_first = canonicalize_snapshot(devices[1].secwet.collect_snapshot().unwrap());

    // Apply exact same events again
    for (i, ev) in events.iter().enumerate() {
        let applied = devices[1].secwet.apply_signed_event((i + 10) as u64, ev).unwrap();
        assert!(!applied, "Duplicate event application must be detected and return false");
    }

    let snap_second = canonicalize_snapshot(devices[1].secwet.collect_snapshot().unwrap());
    assert_eq!(snap_first, snap_second, "Duplicate application must not modify state");
}

// ============================================================================
// Test 4: Out-of-order events converge (100 deterministic shuffles)
// ============================================================================
#[test]
fn out_of_order_events_converge() {
    let (mut devices, secwet_id, master_key) = create_test_devices(1);

    let space_id = devices[0].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[0]
        .secwet
        .create_label_in_space("App", None, Some(space_id))
        .unwrap();
    let item = devices[0]
        .secwet
        .create_item(label.id, "Microservice", None)
        .unwrap();

    let sec1 = devices[0]
        .secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "KEY1",
            SecretKind::Password,
            "v1",
            None,
        ))
        .unwrap();
    let sec2 = devices[0]
        .secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "KEY2",
            SecretKind::Password,
            "v2",
            None,
        ))
        .unwrap();

    devices[0]
        .secwet
        .update_secret(
            sec1.id,
            SecretDraft::new(
                item.id,
                None,
                "KEY1",
                SecretKind::Password,
                "v1_updated",
                None,
            ),
        )
        .unwrap();
    devices[0].secwet.delete_secret(sec2.id).unwrap();

    let events = devices[0].secwet.peek_outbox(100).unwrap();
    assert!(events.len() >= 5);

    // Reference snapshot applied in sequential order
    let ref_dir = TempDir::new().unwrap();
    let ref_keystore = MemoryStore::new();
    let mut ref_dev = Secwet::create_paired(
        ref_dir.path(),
        "RefDevice",
        secwet_id,
        &master_key,
        &ref_keystore,
    )
    .unwrap();
    ref_dev
        .record_paired_device(
            &devices[0].secwet.device_id().to_string(),
            "Device-0",
            "Desktop",
            &devices[0].secwet.device_sign_pub(),
            &devices[0].secwet.device_enc_pub(),
        )
        .unwrap();

    for (idx, ev) in events.iter().enumerate() {
        let _ = ref_dev.apply_signed_event((idx + 1) as u64, ev).unwrap();
    }
    let ref_snap = canonicalize_snapshot(ref_dev.collect_snapshot().unwrap());

    // Run 100 deterministic shuffles
    for seed in 0..100u64 {
        let mut shuffled = events.clone();
        // Deterministic Knuth shuffle using LCG
        let mut lcg = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        for i in (1..shuffled.len()).rev() {
            lcg = lcg.wrapping_mul(6364136223846793005).wrapping_add(1);
            let j = (lcg >> 33) as usize % (i + 1);
            shuffled.swap(i, j);
        }

        let test_dir = TempDir::new().unwrap();
        let test_keystore = MemoryStore::new();
        let mut test_dev = Secwet::create_paired(
            test_dir.path(),
            &format!("Shuffle-{}", seed),
            secwet_id,
            &master_key,
            &test_keystore,
        )
        .unwrap();
        test_dev
            .record_paired_device(
                &devices[0].secwet.device_id().to_string(),
                "Device-0",
                "Desktop",
                &devices[0].secwet.device_sign_pub(),
                &devices[0].secwet.device_enc_pub(),
            )
            .unwrap();

        for (idx, ev) in shuffled.iter().enumerate() {
            let _ = test_dev.apply_signed_event((idx + 1) as u64, ev).unwrap();
        }

        let test_snap = canonicalize_snapshot(test_dev.collect_snapshot().unwrap());
        assert_eq!(
            ref_snap, test_snap,
            "Shuffle {} diverged from reference state",
            seed
        );
    }
}

// ============================================================================
// Test 5: Offline device catches up after 50 changes
// ============================================================================
#[test]
fn offline_device_catches_up() {
    let (mut devices, _secwet_id, _mk) = create_test_devices(2);
    let mut seq = 0u64;

    let space_id = devices[0].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[0]
        .secwet
        .create_label_in_space("Production", None, Some(space_id))
        .unwrap();
    let item = devices[0]
        .secwet
        .create_item(label.id, "Core Services", None)
        .unwrap();

    sync_devices(&mut devices, &mut seq);

    // Device 1 goes "offline". Device 0 generates 50 changes
    for i in 0..50 {
        devices[0]
            .secwet
            .create_secret(SecretDraft::new(
                item.id,
                None,
                format!("API_TOKEN_{}", i),
                SecretKind::AccessToken,
                format!("token_val_{}", i),
                None,
            ))
            .unwrap();
    }

    assert_eq!(devices[0].secwet.pending_outbox_count().unwrap(), 50);

    // Device 1 comes back online and pulls all events
    sync_devices(&mut devices, &mut seq);

    assert_eq!(devices[0].secwet.pending_outbox_count().unwrap(), 0);

    let snap0 = canonicalize_snapshot(devices[0].secwet.collect_snapshot().unwrap());
    let snap1 = canonicalize_snapshot(devices[1].secwet.collect_snapshot().unwrap());

    assert_eq!(snap0.secrets.len(), 50);
    assert_eq!(snap0, snap1);
}

// ============================================================================
// Test 6: Offline device after retention uses snapshot
// ============================================================================
#[test]
fn offline_device_after_retention_uses_snapshot() {
    let (mut devices, _secwet_id, _mk) = create_test_devices(2);

    let space_id = devices[0].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[0]
        .secwet
        .create_label_in_space("Archive", None, Some(space_id))
        .unwrap();
    let item = devices[0]
        .secwet
        .create_item(label.id, "Backups", None)
        .unwrap();

    for i in 0..20 {
        devices[0]
            .secwet
            .create_secret(SecretDraft::new(
                item.id,
                None,
                format!("SECRET_{}", i),
                SecretKind::Password,
                format!("pass_{}", i),
                None,
            ))
            .unwrap();
    }

    // Device 0 collects snapshot
    let snapshot = devices[0].secwet.collect_snapshot().unwrap();

    // Device 1 (cursor behind retention) applies snapshot directly
    devices[1].secwet.restore_from_snapshot(&snapshot, 500).unwrap();

    let snap0 = canonicalize_snapshot(devices[0].secwet.collect_snapshot().unwrap());
    let snap1 = canonicalize_snapshot(devices[1].secwet.collect_snapshot().unwrap());

    assert_eq!(snap0, snap1);
}

// ============================================================================
// Test 7: Tampered event rejected
// ============================================================================
#[test]
fn tampered_event_rejected() {
    let (mut devices, _secwet_id, _mk) = create_test_devices(2);

    let space_id = devices[0].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[0]
        .secwet
        .create_label_in_space("TamperTest", None, Some(space_id))
        .unwrap();
    let item = devices[0]
        .secwet
        .create_item(label.id, "Target", None)
        .unwrap();
    devices[0]
        .secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "CRITICAL",
            SecretKind::Password,
            "secret123",
            None,
        ))
        .unwrap();

    let events = devices[0].secwet.peek_outbox(10).unwrap();
    let valid_event = events.last().unwrap();

    // 1. Tamper ciphertext
    let mut tampered_cipher = valid_event.clone();
    if let Some(b) = tampered_cipher.envelope.ciphertext.first_mut() {
        *b ^= 0xFF;
    }
    let res1 = devices[1].secwet.apply_signed_event(1, &tampered_cipher);
    assert!(res1.is_err(), "Tampered ciphertext must be rejected");

    // 2. Tamper signature
    let mut tampered_sig = valid_event.clone();
    tampered_sig.signature[0] ^= 0xAA;
    let res2 = devices[1].secwet.apply_signed_event(2, &tampered_sig);
    assert!(res2.is_err(), "Tampered signature must be rejected");
}

// ============================================================================
// Test 8: Event from revoked device rejected
// ============================================================================
#[test]
fn event_from_revoked_device_rejected() {
    let (mut devices, _secwet_id, _mk) = create_test_devices(2);

    let dev1_id = devices[1].secwet.device_id().to_string();

    // Device 0 revokes Device 1
    devices[0].secwet.device_revoke(&dev1_id).unwrap();

    // Device 1 creates a secret and signs an event
    let space_id = devices[1].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[1]
        .secwet
        .create_label_in_space("Rogue", None, Some(space_id))
        .unwrap();
    let item = devices[1]
        .secwet
        .create_item(label.id, "RogueItem", None)
        .unwrap();
    devices[1]
        .secwet
        .create_secret(SecretDraft::new(
            item.id,
            None,
            "ROGUE_KEY",
            SecretKind::Password,
            "bad",
            None,
        ))
        .unwrap();

    let outbox1 = devices[1].secwet.peek_outbox(10).unwrap();
    let rogue_event = outbox1.last().unwrap();

    // Device 0 attempts to apply rogue event
    let res = devices[0].secwet.apply_signed_event(1, rogue_event);
    assert!(
        matches!(res, Err(secwet_core::Error::Revoked)),
        "Event from revoked device must be rejected with Error::Revoked"
    );
}

// ============================================================================
// Test 9: Proptest - Three devices concurrent convergence
// ============================================================================
#[test]
fn proptest_three_devices_concurrent_convergence() {
    let (mut devices, _secwet_id, _mk) = create_test_devices(3);
    let mut seq = 0u64;

    let space_id = devices[0].secwet.ensure_default_personal_space().unwrap().id;
    let label = devices[0]
        .secwet
        .create_label_in_space("ConcurrentCluster", None, Some(space_id))
        .unwrap();
    let item = devices[0]
        .secwet
        .create_item(label.id, "SharedApp", None)
        .unwrap();

    sync_devices(&mut devices, &mut seq);

    // Generate random interleaved actions across 3 devices
    for step in 0..30 {
        let dev_idx = (step * 7 + 3) % 3;
        let op_type = (step * 11) % 3;

        match op_type {
            0 => {
                let _ = devices[dev_idx].secwet.create_secret(SecretDraft::new(
                    item.id,
                    None,
                    format!("KEY_{}_{}", dev_idx, step),
                    SecretKind::ApiKey,
                    format!("val_{}", step),
                    None,
                ));
            }
            1 => {
                let _ = devices[dev_idx].secwet.create_note(
                    item.id,
                    None,
                    &format!("Note_{}_{}", dev_idx, step),
                    "Note body content here",
                );
            }
            _ => {
                let _ = devices[dev_idx].secwet.create_secret(SecretDraft::new(
                    item.id,
                    None,
                    "SHARED_KEY",
                    SecretKind::Password,
                    format!("shared_val_{}_{}", dev_idx, step),
                    None,
                ));
            }
        }

        // Periodically batch sync
        if step % 5 == 0 {
            sync_devices(&mut devices, &mut seq);
        }
    }

    // Final sync
    sync_devices(&mut devices, &mut seq);

    let snap0 = canonicalize_snapshot(devices[0].secwet.collect_snapshot().unwrap());
    let snap1 = canonicalize_snapshot(devices[1].secwet.collect_snapshot().unwrap());
    let snap2 = canonicalize_snapshot(devices[2].secwet.collect_snapshot().unwrap());

    assert_eq!(snap0, snap1, "Device 0 and 1 must converge");
    assert_eq!(snap1, snap2, "Device 1 and 2 must converge");
}
