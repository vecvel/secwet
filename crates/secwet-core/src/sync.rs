use serde::{Deserialize, Serialize};

/// One encrypted change sent through the relay. The relay can read the
/// envelope fields for routing and replay protection, never the payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncEvent {
    /// Unique id, used to drop duplicates.
    pub id: String,
    pub vault_id: String,
    pub device_id: String,
    /// Per-device monotonic counter for ordering and replay protection.
    pub revision: u64,
    /// Authenticated ciphertext of the change.
    pub payload: Vec<u8>,
    /// Device signature over the envelope and payload.
    pub signature: Vec<u8>,
}
