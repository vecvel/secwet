//! Zero-Knowledge Event-Driven Synchronization Engine.
//!
//! Architectural Invariants:
//! 1. All entity changes on Pro workspaces produce signed, encrypted `SignedEvent` envelopes.
//! 2. Event bodies are sealed under $K_{\text{evt}}$ with authenticated associated data (AAD).
//! 3. Envelopes are signed with the authoring device's Ed25519 signing key.
//! 4. Conflict resolution strictly follows Last-Writer-Wins (LWW) per record:
//!    `(event.lamport, event.origin_device) > (stored.lamport, stored.origin_device)`
//! 5. Event application is strictly commutative and idempotent. Duplicate or out-of-order
//!    events converge to the exact same state across all devices.

use ed25519_dalek::SigningKey;
use rusqlite::{params, Connection, OptionalExtension};
use secwet_proto::{
    EventAad, EventBody, EventEnvelope, EventScope, RecordAad, RecordPayload, RecordType,
    SignedEvent,
};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::{
    crypto::{self, open_raw_parts, seal_raw_parts, sign_payload, verify_signature_strict_bytes},
    Error,
};

fn current_time_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ============================================================================
// 1. Event Construction & Cryptographic Verification
// ============================================================================

/// Creates and signs an encrypted event envelope for a mutation.
pub fn create_signed_event(
    secwet_id: Uuid,
    device_id: &str,
    device_seq: u64,
    key_epoch: u32,
    k_evt: &[u8; 32],
    signing_key: &SigningKey,
    event_body: &EventBody,
) -> Result<SignedEvent, Error> {
    create_signed_event_scoped(
        secwet_id,
        device_id,
        device_seq,
        key_epoch,
        k_evt,
        signing_key,
        event_body,
        None,
    )
}

/// Creates and signs an event. `scope` is set for events in collaborative
/// spaces; `k_evt` is then the branch key named by the scope and
/// `key_epoch` the branch epoch.
#[allow(clippy::too_many_arguments)]
pub fn create_signed_event_scoped(
    secwet_id: Uuid,
    device_id: &str,
    device_seq: u64,
    key_epoch: u32,
    k_evt: &[u8; 32],
    signing_key: &SigningKey,
    event_body: &EventBody,
    scope: Option<EventScope>,
) -> Result<SignedEvent, Error> {
    let event_id = *Uuid::now_v7().as_bytes();
    let secwet_id_bytes = *secwet_id.as_bytes();

    // 1. Postcard-serialize authenticated associated data
    let aad = EventAad {
        event_id: &event_id,
        secwet_id: &secwet_id_bytes,
        device_id,
        device_seq,
        key_epoch,
    };
    let aad_bytes = postcard::to_stdvec(&aad).map_err(|_| Error::Crypto)?;

    // 2. Postcard-serialize event body
    let body_bytes = postcard::to_stdvec(event_body).map_err(|_| Error::Crypto)?;

    // 3. Encrypt event body under K_evt with authenticated AAD
    let (nonce, ciphertext) = seal_raw_parts(k_evt, &aad_bytes, &body_bytes)?;

    // 4. Construct envelope
    let envelope = EventEnvelope {
        event_id,
        secwet_id: secwet_id_bytes,
        device_id: device_id.to_string(),
        device_seq,
        key_epoch,
        nonce,
        ciphertext,
        scope,
    };

    // 5. Sign envelope with device Ed25519 signing key
    let envelope_bytes = envelope.signing_bytes().map_err(|_| Error::Crypto)?;
    let sig = sign_payload(signing_key, &envelope_bytes);

    Ok(SignedEvent {
        envelope,
        signature: sig.to_bytes(),
    })
}

/// Re-encrypts an existing event under another epoch's key, keeping its
/// event id, device sequence and scope, and signs it again.
pub fn reseal_signed_event(
    ev: &SignedEvent,
    key_epoch: u32,
    k_evt: &[u8; 32],
    signing_key: &SigningKey,
    body: &EventBody,
) -> Result<SignedEvent, Error> {
    reseal_with_scope(ev, key_epoch, k_evt, signing_key, body, ev.envelope.scope.clone())
}

/// Like `reseal_signed_event` but drops the scope (owner no-op replacement).
pub fn reseal_signed_event_unscoped(
    ev: &SignedEvent,
    key_epoch: u32,
    k_evt: &[u8; 32],
    signing_key: &SigningKey,
    body: &EventBody,
) -> Result<SignedEvent, Error> {
    reseal_with_scope(ev, key_epoch, k_evt, signing_key, body, None)
}

fn reseal_with_scope(
    ev: &SignedEvent,
    key_epoch: u32,
    k_evt: &[u8; 32],
    signing_key: &SigningKey,
    body: &EventBody,
    scope: Option<EventScope>,
) -> Result<SignedEvent, Error> {
    let e = &ev.envelope;
    let aad = EventAad {
        event_id: &e.event_id,
        secwet_id: &e.secwet_id,
        device_id: &e.device_id,
        device_seq: e.device_seq,
        key_epoch,
    };
    let aad_bytes = postcard::to_stdvec(&aad).map_err(|_| Error::Crypto)?;
    let body_bytes = postcard::to_stdvec(body).map_err(|_| Error::Crypto)?;
    let (nonce, ciphertext) = seal_raw_parts(k_evt, &aad_bytes, &body_bytes)?;
    let envelope = EventEnvelope {
        event_id: e.event_id,
        secwet_id: e.secwet_id,
        device_id: e.device_id.clone(),
        device_seq: e.device_seq,
        key_epoch,
        nonce,
        ciphertext,
        scope,
    };
    let sig = sign_payload(signing_key, &envelope.signing_bytes().map_err(|_| Error::Crypto)?);
    Ok(SignedEvent { envelope, signature: sig.to_bytes() })
}

/// Strictly verifies an event's cryptographic signature and decrypts its body under $K_{\text{evt}}$.
pub fn verify_and_decrypt_event(
    signed_event: &SignedEvent,
    sender_sign_pub: &[u8; 32],
    k_evt: &[u8; 32],
) -> Result<EventBody, Error> {
    verify_event_signature(signed_event, sender_sign_pub)?;
    decrypt_event_body(signed_event, k_evt)
}

/// Verifies the Ed25519 signature over the envelope's signing bytes.
pub fn verify_event_signature(signed_event: &SignedEvent, sender_sign_pub: &[u8; 32]) -> Result<(), Error> {
    let envelope_bytes = signed_event
        .envelope
        .signing_bytes()
        .map_err(|_| Error::Crypto)?;
    verify_signature_strict_bytes(sender_sign_pub, &envelope_bytes, &signed_event.signature)
        .map_err(|_| Error::Relay {
            code: "bad_signature".into(),
        })
}

/// Decrypts an event body whose signature was already verified.
pub fn decrypt_event_body(signed_event: &SignedEvent, k_evt: &[u8; 32]) -> Result<EventBody, Error> {
    // Build AAD matching encryption
    let aad = EventAad {
        event_id: &signed_event.envelope.event_id,
        secwet_id: &signed_event.envelope.secwet_id,
        device_id: &signed_event.envelope.device_id,
        device_seq: signed_event.envelope.device_seq,
        key_epoch: signed_event.envelope.key_epoch,
    };
    let aad_bytes = postcard::to_stdvec(&aad).map_err(|_| Error::Crypto)?;

    // 3. Decrypt ciphertext under K_evt
    let plaintext = open_raw_parts(
        k_evt,
        &aad_bytes,
        &signed_event.envelope.nonce,
        &signed_event.envelope.ciphertext,
    )?;

    // 4. Postcard-deserialize EventBody
    postcard::from_bytes(&plaintext).map_err(|_| Error::Crypto)
}

// ============================================================================
// 2. Outbox Management
// ============================================================================

/// Enqueues a signed event into the local `outbox` table.
pub fn enqueue_outbox(conn: &Connection, event: &SignedEvent) -> Result<(), Error> {
    let envelope_bytes = postcard::to_stdvec(event).map_err(|_| Error::Storage)?;
    conn.execute(
        "INSERT INTO outbox (event_id, device_seq, envelope) VALUES (?1, ?2, ?3)",
        params![
            &event.envelope.event_id[..],
            event.envelope.device_seq as i64,
            &envelope_bytes,
        ],
    )
    .map_err(|e| {
        eprintln!("OUTBOX INSERT RUSQLITE ERROR: {:?}", e);
        Error::Storage
    })?;

    // Also persist monotonic device sequence counter
    conn.execute(
        "INSERT INTO sync_state (key, value) VALUES ('next_device_seq', ?1)
         ON CONFLICT(key) DO UPDATE SET value = ?1",
        params![(event.envelope.device_seq + 1).to_string()],
    )
    .map_err(|e| {
        eprintln!("SYNC STATE INSERT RUSQLITE ERROR: {:?}", e);
        Error::Storage
    })?;

    Ok(())
}

/// Reads unacknowledged events from `outbox` in strictly increasing `device_seq` order.
pub fn peek_outbox(conn: &Connection, limit: usize) -> Result<Vec<SignedEvent>, Error> {
    let mut stmt = conn
        .prepare("SELECT envelope FROM outbox ORDER BY device_seq ASC LIMIT ?1")
        .map_err(|_| Error::Storage)?;

    let rows = stmt
        .query_map(params![limit as i64], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|_| Error::Storage)?;

    let mut events = Vec::new();
    for row in rows {
        let bytes = row.map_err(|_| Error::Storage)?;
        let event = SignedEvent::from_postcard_compat(&bytes).map_err(|_| Error::Storage)?;
        events.push(event);
    }

    Ok(events)
}

/// Deletes acknowledged events from `outbox` up to a given `device_seq`.
pub fn delete_outbox_events(conn: &Connection, up_to_device_seq: u64) -> Result<usize, Error> {
    let bound = if up_to_device_seq > i64::MAX as u64 {
        i64::MAX
    } else {
        up_to_device_seq as i64
    };
    let affected = conn
        .execute(
            "DELETE FROM outbox WHERE device_seq <= ?1",
            params![bound],
        )
        .map_err(|_| Error::Storage)?;
    Ok(affected)
}

/// Returns the next monotonic `device_seq` for this device (starts at 1).
pub fn next_device_seq(conn: &Connection, _device_id: &str) -> Result<u64, Error> {
    let stored_val: Option<String> = conn
        .query_row(
            "SELECT value FROM sync_state WHERE key = 'next_device_seq'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|e| {
            eprintln!("next_device_seq sync_state error: {:?}", e);
            Error::Storage
        })?;

    if let Some(val) = stored_val {
        if let Ok(seq) = val.parse::<u64>() {
            return Ok(seq);
        }
    }

    let max_outbox: i64 = conn
        .query_row("SELECT COALESCE(MAX(device_seq), 0) FROM outbox", [], |row| row.get(0))
        .map_err(|e| {
            eprintln!("next_device_seq outbox error: {:?}", e);
            Error::Storage
        })?;

    let current = max_outbox.max(0) as u64;
    Ok(current + 1)
}

// ============================================================================
// 3. Deduplication, Cursor & Conflict Resolution
// ============================================================================

/// Returns true if an `event_id` has already been applied locally.
pub fn is_event_applied(conn: &Connection, event_id: &[u8; 16]) -> Result<bool, Error> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM applied_events WHERE event_id = ?1",
            params![&event_id[..]],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::Storage)?;

    Ok(exists.is_some())
}

/// Records an applied event in `applied_events` for deduplication.
pub fn record_event_applied(
    conn: &Connection,
    event_id: &[u8; 16],
    server_seq: u64,
) -> Result<(), Error> {
    conn.execute(
        "INSERT OR IGNORE INTO applied_events (event_id, server_seq) VALUES (?1, ?2)",
        params![&event_id[..], server_seq as i64],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

/// Gets the local sync cursor (`server_seq`).
pub fn get_sync_cursor(conn: &Connection) -> Result<u64, Error> {
    let val: Option<String> = conn
        .query_row(
            "SELECT value FROM sync_state WHERE key = 'cursor'",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|_| Error::Storage)?;

    match val {
        Some(v) => Ok(v.parse::<u64>().unwrap_or(0)),
        None => Ok(0),
    }
}

/// Sets the local sync cursor (`server_seq`).
pub fn set_sync_cursor(conn: &Connection, cursor: u64) -> Result<(), Error> {
    conn.execute(
        "INSERT INTO sync_state (key, value) VALUES ('cursor', ?1)
         ON CONFLICT(key) DO UPDATE SET value = ?1",
        params![cursor.to_string()],
    )
    .map_err(|_| Error::Storage)?;
    Ok(())
}

/// Applies a verified and decrypted event mutation with Last-Writer-Wins (LWW) conflict resolution.
///
/// Invariant:
/// Stored record is replaced ONLY if `(event.lamport, event.origin_device) > (stored.lamport, stored.origin_device)`
/// lexicographically.
///
/// `key_epoch` is the epoch of the local store key `k_rec` the record is
/// re-sealed under, not the epoch the event was encrypted with.
pub fn apply_event_mutation(
    conn: &Connection,
    secwet_id: Uuid,
    origin_device: &str,
    key_epoch: u32,
    k_rec: &[u8; 32],
    event_body: &EventBody,
) -> Result<(), Error> {
    match event_body {
        EventBody::Upsert {
            record_id,
            record_type,
            lamport,
            body,
        } => {
            let rec_type = RecordType::try_from(*record_type).map_err(|_| Error::Invalid {
                field: "record_type",
                message: "Unknown record type discriminator".into(),
            })?;

            // 1. Check existing record
            let existing: Option<(u64, String, bool, i64)> = conn
                .query_row(
                    "SELECT lamport, origin_device, deleted, record_type FROM records WHERE id = ?1",
                    params![record_id.as_bytes().as_slice()],
                    |row| {
                        let l: i64 = row.get(0)?;
                        let d: String = row.get(1)?;
                        let del: i64 = row.get(2)?;
                        Ok((l as u64, d, del != 0, row.get(3)?))
                    },
                )
                .optional()
                .map_err(|_| Error::Storage)?;

            if let Some((stored_lamport, stored_device, _, stored_type)) = existing {
                // A record never changes type: an id reused for another type
                // would let a writer replace a container it cannot touch.
                if stored_type as u8 != rec_type as u8 {
                    return Ok(());
                }
                // Strict lexicographical comparison: (event.lamport, origin_device) > (stored.lamport, stored.origin_device)
                if (*lamport, origin_device) <= (stored_lamport, stored_device.as_str()) {
                    // Local record wins; ignore incoming mutation
                    return Ok(());
                }
            }

            // 2. Decode payload to determine parent_id
            let payload = RecordPayload::from_bytes(rec_type, body).map_err(|_| Error::Crypto)?;
            let parent_id = match &payload {
                RecordPayload::Label(b) => b.space_id,
                RecordPayload::Item(b) => Some(b.label_id),
                RecordPayload::Environment(b) => Some(b.item_id),
                RecordPayload::Secret(b) => b.environment_id.or(Some(b.item_id)),
                RecordPayload::File(b) => b.meta.environment_id.or(Some(b.meta.item_id)),
                RecordPayload::Note(b) => b.environment_id.or(Some(b.item_id)),
                RecordPayload::Project(_) => None,
                RecordPayload::Space(_) => None,
            };

            // 3. Seal record under local K_rec with authentic AAD
            let aad = RecordAad::new(secwet_id.as_bytes(), record_id.as_bytes(), rec_type, key_epoch);
            let blob = crypto::seal_record(k_rec, &aad, body)?;

            let now_ms = current_time_ms();
            let parent_bytes = parent_id.map(|p| p.as_bytes().to_vec());

            // 4. Upsert into records table
            conn.execute(
                "INSERT INTO records (
                    id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0)
                ON CONFLICT(id) DO UPDATE SET
                    record_type = ?2,
                    parent_id = ?3,
                    key_epoch = ?4,
                    blob = ?5,
                    lamport = ?6,
                    origin_device = ?7,
                    updated_at = ?8,
                    deleted = 0",
                params![
                    record_id.as_bytes().as_slice(),
                    rec_type as u8,
                    parent_bytes,
                    key_epoch as i64,
                    &blob,
                    *lamport as i64,
                    origin_device,
                    now_ms,
                ],
            )
            .map_err(|_| Error::Storage)?;

            if rec_type == RecordType::Label {
                if let RecordPayload::Label(b) = &payload {
                    conn.execute(
                        "INSERT INTO labels (id, name_blob, position, space_id, created_at, updated_at, deleted)
                         VALUES (?1, ?2, ?3, ?4, ?5, ?5, 0)
                         ON CONFLICT(id) DO UPDATE SET
                             name_blob = ?2,
                             position = ?3,
                             space_id = ?4,
                             updated_at = ?5,
                             deleted = 0",
                        params![
                            record_id.as_bytes().as_slice(),
                            &blob,
                            b.position as i64,
                            b.space_id.map(|s| s.as_bytes().to_vec()),
                            now_ms,
                        ],
                    )
                    .map_err(|_| Error::Storage)?;
                }
            }

            if rec_type == RecordType::Space {
                if let RecordPayload::Space(b) = &payload {
                    // Local storage seals spaces with the Label discriminator.
                    let space_aad =
                        RecordAad::new(secwet_id.as_bytes(), record_id.as_bytes(), RecordType::Label, key_epoch);
                    let space_blob = crypto::seal_record(k_rec, &space_aad, body)?;
                    conn.execute(
                        "INSERT INTO spaces (id, name_blob, position, created_at, updated_at, deleted)
                         VALUES (?1, ?2, ?3, ?4, ?4, 0)
                         ON CONFLICT(id) DO UPDATE SET
                             name_blob = ?2,
                             position = ?3,
                             updated_at = ?4,
                             deleted = 0",
                        params![
                            record_id.as_bytes().as_slice(),
                            &space_blob,
                            b.position as i64,
                            now_ms,
                        ],
                    )
                    .map_err(|_| Error::Storage)?;
                }
            }
        }
        EventBody::Delete {
            record_id,
            record_type,
            lamport,
        } => {
            let rec_type = RecordType::try_from(*record_type).map_err(|_| Error::Invalid {
                field: "record_type",
                message: "Unknown record type discriminator".into(),
            })?;

            let existing: Option<(u64, String, i64)> = conn
                .query_row(
                    "SELECT lamport, origin_device, record_type FROM records WHERE id = ?1",
                    params![record_id.as_bytes().as_slice()],
                    |row| {
                        let l: i64 = row.get(0)?;
                        let d: String = row.get(1)?;
                        Ok((l as u64, d, row.get(2)?))
                    },
                )
                .optional()
                .map_err(|_| Error::Storage)?;

            if let Some((stored_lamport, stored_device, stored_type)) = existing {
                if stored_type as u8 != rec_type as u8 {
                    return Ok(());
                }
                if (*lamport, origin_device) <= (stored_lamport, stored_device.as_str()) {
                    return Ok(());
                }
            }

            let now_ms = current_time_ms();
            // Upsert tombstone (blob = NULL, deleted = 1)
            conn.execute(
                "INSERT INTO records (
                    id, record_type, parent_id, key_epoch, blob, lamport, origin_device, updated_at, deleted
                ) VALUES (?1, ?2, NULL, ?3, NULL, ?4, ?5, ?6, 1)
                ON CONFLICT(id) DO UPDATE SET
                    blob = NULL,
                    lamport = ?4,
                    origin_device = ?5,
                    updated_at = ?6,
                    deleted = 1",
                params![
                    record_id.as_bytes().as_slice(),
                    rec_type as u8,
                    key_epoch as i64,
                    *lamport as i64,
                    origin_device,
                    now_ms,
                ],
            )
            .map_err(|_| Error::Storage)?;

            if rec_type == RecordType::Label {
                conn.execute(
                    "UPDATE labels SET deleted = 1, updated_at = ?1 WHERE id = ?2",
                    params![now_ms, record_id.as_bytes().as_slice()],
                )
                .map_err(|_| Error::Storage)?;
            }
            if rec_type == RecordType::Space {
                conn.execute(
                    "UPDATE spaces SET deleted = 1, updated_at = ?1 WHERE id = ?2",
                    params![now_ms, record_id.as_bytes().as_slice()],
                )
                .map_err(|_| Error::Storage)?;
            }
        }
        EventBody::Seed {
            record_id,
            record_type,
            lamport,
            origin_device: seed_origin,
            body,
        } => {
            // Seeds only fill in records the receiver does not have yet.
            let present: Option<i64> = conn
                .query_row(
                    "SELECT 1 FROM records WHERE id = ?1
                     UNION ALL SELECT 1 FROM labels WHERE id = ?1
                     UNION ALL SELECT 1 FROM spaces WHERE id = ?1 LIMIT 1",
                    params![record_id.as_bytes().as_slice()],
                    |r| r.get(0),
                )
                .optional()
                .map_err(|_| Error::Storage)?;
            if present.is_none() {
                apply_event_mutation(
                    conn,
                    secwet_id,
                    seed_origin,
                    key_epoch,
                    k_rec,
                    &EventBody::Upsert {
                        record_id: *record_id,
                        record_type: *record_type,
                        lamport: *lamport,
                        body: body.clone(),
                    },
                )?;
            }
        }
        EventBody::DeviceCertified {
            device_id,
            sign_pub,
            enc_pub,
            member_id,
        } => {
            apply_device_certificate(conn, k_rec, device_id, sign_pub, enc_pub, *member_id)?;
        }
        EventBody::DeviceRenamed { device_id, name } if device_id.is_empty() && name.is_empty() => {
            // No-op placeholder that kept the device sequence contiguous.
        }
        EventBody::DeviceRenamed { device_id, name } => {
            // Seal new device name with K_rec and update devices table
            let nil_uuid = Uuid::nil();
            let aad = RecordAad::new(secwet_id.as_bytes(), nil_uuid.as_bytes(), RecordType::Item, key_epoch);
            let name_blob = crypto::seal_record(k_rec, &aad, name.as_bytes())?;

            conn.execute(
                "UPDATE devices SET name_blob = ?2 WHERE device_id = ?1",
                params![device_id, &name_blob],
            )
            .map_err(|_| Error::Storage)?;
        }
    }

    Ok(())
}

/// Result of applying one event pulled from the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// Mutation applied (it may still lose last-writer-wins to local state).
    Applied,
    /// Already applied earlier.
    Duplicate,
    /// This device may never read or accept it (another branch it has no
    /// access to, or an author without the role); the event is done.
    Skipped,
    /// Not readable or attributable yet (key or device certificate still on
    /// its way). Kept in `collab_deferred` and retried later; the cursor
    /// moves on so one event cannot stall sync.
    Deferred,
}

/// How a resolver answers a key lookup.
pub enum KeyLookup {
    Key(zeroize::Zeroizing<[u8; 32]>),
    /// The key may still arrive (new branch, newer epoch).
    Defer,
    /// This device will never hold the key.
    Skip,
}

/// How a resolver answers an authorization check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization {
    Allow,
    Deny,
    /// The author's identity or grants are not known yet.
    Defer,
}

/// Key and authorization lookups the caller provides to `apply_signed_event_with`.
pub trait EventKeyResolver {
    fn event_key(&mut self, envelope: &EventEnvelope) -> Result<KeyLookup, Error>;
    fn authorize(&mut self, envelope: &EventEnvelope, body: &EventBody, server_seq: u64) -> Authorization;
}

/// Records a certificate from an owner device (decryptable with the workspace
/// event key, so the relay cannot forge it). Only adds trust: an existing row
/// whose keys differ is left alone.
pub fn apply_device_certificate(
    conn: &Connection,
    k_rec: &[u8; 32],
    device_id: &str,
    sign_pub: &[u8; 32],
    enc_pub: &[u8; 32],
    member_id: Option<Uuid>,
) -> Result<(), Error> {
    if crypto::compute_device_id(sign_pub) != device_id {
        return Ok(());
    }
    let existing: Option<(Vec<u8>, Vec<u8>, String)> = conn
        .query_row(
            "SELECT sign_pub, enc_pub, trust FROM devices WHERE device_id = ?1",
            params![device_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|_| Error::Storage)?;
    let member = member_id.map(|m| m.as_bytes().to_vec());
    match existing {
        Some((sp, ep, trust)) => {
            if sp != sign_pub.as_slice() || ep != enc_pub.as_slice() || trust == "self" || trust == "certified" {
                return Ok(());
            }
            conn.execute(
                "UPDATE devices SET trust = 'certified', member_id = ?2 WHERE device_id = ?1",
                params![device_id, member],
            )
            .map_err(|_| Error::Storage)?;
        }
        None => {
            let name_blob = crate::secwet::seal_device_name(k_rec, device_id, "Device")?;
            conn.execute(
                "INSERT INTO devices (device_id, name_blob, sign_pub, enc_pub, added_at, revoked_at, last_seen_at, member_id, trust)
                 VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?5, ?6, 'certified')",
                params![device_id, name_blob, sign_pub.as_slice(), enc_pub.as_slice(), current_time_ms(), member],
            )
            .map_err(|_| Error::Storage)?;
        }
    }
    Ok(())
}

fn advance_sync_cursor(conn: &Connection, server_seq: u64) -> Result<(), Error> {
    if server_seq > get_sync_cursor(conn)? {
        set_sync_cursor(conn, server_seq)?;
    }
    Ok(())
}

fn defer_event(conn: &Connection, server_seq: u64, event: &SignedEvent) -> Result<(), Error> {
    let bytes = postcard::to_stdvec(event).map_err(|_| Error::Storage)?;
    conn.execute(
        "INSERT OR REPLACE INTO collab_deferred (server_seq, envelope, deferred_at) VALUES (?1, ?2, ?3)",
        params![server_seq as i64, bytes, current_time_ms()],
    )
    .map_err(|_| Error::Storage)?;
    advance_sync_cursor(conn, server_seq)
}

/// Applies a signed event from the relay, handling deduplication, signature verification,
/// decryption, authorization, LWW mutation, and cursor progression.
///
/// `local_epoch` / `k_rec` are the local store key the record is re-sealed under.
pub fn apply_signed_event_with(
    conn: &Connection,
    secwet_id: Uuid,
    server_seq: u64,
    signed_event: &SignedEvent,
    local_epoch: u32,
    k_rec: &[u8; 32],
    resolver: &mut dyn EventKeyResolver,
) -> Result<ApplyOutcome, Error> {
    // 1. Skip if already applied
    if is_event_applied(conn, &signed_event.envelope.event_id)? {
        advance_sync_cursor(conn, server_seq)?;
        return Ok(ApplyOutcome::Duplicate);
    }

    if signed_event.envelope.secwet_id != *secwet_id.as_bytes() {
        return Err(Error::Crypto);
    }

    // 2. Fetch sender public key from devices table
    let device_row: Option<(Vec<u8>, Option<i64>, Option<i64>)> = conn
        .query_row(
            "SELECT sign_pub, revoked_at, revoked_seq FROM devices WHERE device_id = ?1",
            params![&signed_event.envelope.device_id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()
        .map_err(|_| Error::Storage)?;

    let (sign_pub_bytes, revoked_at, revoked_seq) = match device_row {
        Some(row) => row,
        None => {
            // Sender not known yet: its certificate or relay listing may
            // still arrive.
            defer_event(conn, server_seq, signed_event)?;
            return Ok(ApplyOutcome::Deferred);
        }
    };

    // Writes accepted by the relay before the revocation stay valid.
    if revoked_at.is_some() && !revoked_seq.is_some_and(|r| server_seq <= r as u64) {
        return Err(Error::Revoked);
    }

    if sign_pub_bytes.len() != 32 {
        return Err(Error::Crypto);
    }
    let mut sign_pub = [0u8; 32];
    sign_pub.copy_from_slice(&sign_pub_bytes);

    // 3. Verify signature, then decrypt with the key named by scope and epoch
    verify_event_signature(signed_event, &sign_pub)?;
    if let Some(scope) = &signed_event.envelope.scope {
        if !scope.is_well_formed() {
            return Err(Error::Crypto);
        }
    }
    let key = match resolver.event_key(&signed_event.envelope)? {
        KeyLookup::Key(k) => k,
        KeyLookup::Defer => {
            defer_event(conn, server_seq, signed_event)?;
            return Ok(ApplyOutcome::Deferred);
        }
        KeyLookup::Skip => {
            record_event_applied(conn, &signed_event.envelope.event_id, server_seq)?;
            advance_sync_cursor(conn, server_seq)?;
            return Ok(ApplyOutcome::Skipped);
        }
    };
    let body = decrypt_event_body(signed_event, &key)?;

    // 4. Role and identity check
    match resolver.authorize(&signed_event.envelope, &body, server_seq) {
        Authorization::Allow => {}
        Authorization::Defer => {
            defer_event(conn, server_seq, signed_event)?;
            return Ok(ApplyOutcome::Deferred);
        }
        Authorization::Deny => {
            record_event_applied(conn, &signed_event.envelope.event_id, server_seq)?;
            advance_sync_cursor(conn, server_seq)?;
            return Ok(ApplyOutcome::Skipped);
        }
    }

    // 5. Apply mutation with LWW
    apply_event_mutation(
        conn,
        secwet_id,
        &signed_event.envelope.device_id,
        local_epoch,
        k_rec,
        &body,
    )?;

    // 6. Record event in applied_events and advance cursor
    record_event_applied(conn, &signed_event.envelope.event_id, server_seq)?;
    advance_sync_cursor(conn, server_seq)?;
    conn.execute("DELETE FROM collab_deferred WHERE server_seq = ?1", params![server_seq as i64])
        .map_err(|_| Error::Storage)?;

    Ok(ApplyOutcome::Applied)
}
