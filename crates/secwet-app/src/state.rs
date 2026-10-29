//! Application state shared by every host, and access helpers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use secwet_core::keys::KeyStore;
use secwet_core::{Secwet, SecwetStatus};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::UiError;
use crate::events::{AppEvent, EventSink};

/// Discriminated status DTO for frontend consumption.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SecwetStatusDto {
    Uninitialized,
    Locked {
        secwet_id: Uuid,
    },
    Unlocked {
        secwet_id: Uuid,
    },
}

impl From<SecwetStatus> for SecwetStatusDto {
    fn from(s: SecwetStatus) -> Self {
        match s {
            SecwetStatus::Uninitialized => SecwetStatusDto::Uninitialized,
            SecwetStatus::Locked { secwet_id } => SecwetStatusDto::Locked { secwet_id },
            SecwetStatus::Unlocked { secwet_id } => SecwetStatusDto::Unlocked { secwet_id },
        }
    }
}

/// Cached information about a peer that has joined an active pairing session.
pub struct ActivePairingPeer {
    pub join_req: secwet_proto::PairingJoinRequest,
    pub profile: secwet_proto::PairingProfile,
    pub sas: String,
    pub fingerprint: String,
    pub device_id: String,
}

/// Active in-memory pairing session state held on the approving device.
pub struct ActivePairingSession {
    pub session_id: Uuid,
    pub a_eph_secret: x25519_dalek::StaticSecret,
    pub a_eph_pub: [u8; 32],
    pub expires_at: String,
    pub qr_payload: String,
    pub cached_peer: Option<ActivePairingPeer>,
}

/// Application state. One per process; hosts keep it for the app's lifetime
/// and call the command methods on it.
pub struct AppState {
    pub secwet: Mutex<Option<Secwet>>,
    pub active_pairing: Mutex<Option<ActivePairingSession>>,
    pub data_dir: PathBuf,
    pub keystore: Arc<dyn KeyStore>,
    pub clipboard_generation: Arc<AtomicU64>,
    pub clear_duration: Duration,
    /// Invite links created in this session, so they can be copied through
    /// the auto-clearing clipboard instead of the webview (they carry the
    /// invite token). Cleared on lock.
    pub invite_links: Mutex<HashMap<Uuid, secrecy::SecretString>>,
    /// Bumped on every lock, so a store taken out for a network call is not
    /// put back after the user locked the app meanwhile.
    pub lock_generation: Arc<AtomicU64>,
    /// Number of commands holding the store across a network call.
    pub in_flight: Arc<AtomicU64>,
    events: RwLock<Arc<dyn EventSink>>,
    /// The host's biometric check, if it has one (see `crate::biometric`).
    pub(crate) presence: RwLock<Option<Arc<dyn crate::biometric::PresenceVerifier>>>,
    /// A pairing this new device joined and is waiting to be approved
    /// (see `crate::pairing_join`).
    pub(crate) pairing_join: Mutex<Option<secwet_core::pairing_join::PairingJoin>>,
}

impl AppState {
    pub fn new(data_dir: PathBuf, keystore: Arc<dyn KeyStore>) -> Self {
        let clear_duration = std::env::var("SECWET_TEST_CLIPBOARD_CLEAR_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_millis)
            .unwrap_or_else(|| Duration::from_secs(30));

        // Finish key deletions left by an interrupted remote wipe.
        let _ = Secwet::finish_pending_wipes(&data_dir, keystore.as_ref());

        Self {
            secwet: Mutex::new(None),
            active_pairing: Mutex::new(None),
            data_dir,
            keystore,
            clipboard_generation: Arc::new(AtomicU64::new(0)),
            clear_duration,
            invite_links: Mutex::new(HashMap::new()),
            lock_generation: Arc::new(AtomicU64::new(0)),
            in_flight: Arc::new(AtomicU64::new(0)),
            events: RwLock::new(crate::events::no_events()),
            presence: RwLock::new(None),
            pairing_join: Mutex::new(None),
        }
    }

    /// Discovers the standard platform data_dir and the OS keychain.
    #[cfg(feature = "os-keyring")]
    pub fn default_state() -> Self {
        let data_dir = Self::resolve_data_dir();
        let keystore = Self::resolve_keystore();
        Self::new(data_dir, keystore)
    }

    /// Discovers data_dir: SECWET_DATA_DIR env override -> ProjectDirs -> .secwet fallback.
    pub fn resolve_data_dir() -> PathBuf {
        std::env::var_os("SECWET_DATA_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                directories::ProjectDirs::from("app", "secwet", "Secwet")
                    .map(|dirs| dirs.data_dir().to_path_buf())
                    .unwrap_or_else(|| PathBuf::from(".secwet"))
            })
    }

    /// Discovers keystore: MemoryStore if SECWET_TEST_KEYSTORE=memory; otherwise KeyringStore.
    #[cfg(feature = "os-keyring")]
    pub fn resolve_keystore() -> Arc<dyn KeyStore> {
        if std::env::var("SECWET_TEST_KEYSTORE").as_deref() == Ok("memory") {
            return Arc::new(secwet_core::keys::MemoryStore::new());
        }
        Arc::new(secwet_core::keys::KeyringStore::new())
    }

    /// Routes UI notifications to `sink` from now on.
    pub fn set_event_sink(&self, sink: Arc<dyn EventSink>) {
        if let Ok(mut events) = self.events.write() {
            *events = sink;
        }
    }

    /// Sends `event` to the installed sink.
    pub fn emit(&self, event: AppEvent) {
        let sink = match self.events.read() {
            Ok(events) => Arc::clone(&events),
            Err(_) => return,
        };
        sink.emit(event);
    }

    pub(crate) fn emit_changed(&self, scope: &'static str) {
        self.emit(AppEvent::changed(scope));
    }

    /// Executes a read-only closure with the unlocked secwet.
    pub fn with_secwet<T, F>(&self, f: F) -> Result<T, UiError>
    where
        F: FnOnce(&Secwet) -> Result<T, secwet_core::Error>,
    {
        let guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = guard.as_ref().ok_or_else(|| self.locked_or_busy())?;
        f(secwet).map_err(UiError::from)
    }

    /// `busy` while a command holds the store for a network call, else `locked`.
    pub fn locked_or_busy(&self) -> UiError {
        if self.in_flight.load(Ordering::SeqCst) > 0 {
            UiError::new("busy", None, "Secwet is syncing. Try again in a moment.")
        } else {
            UiError::locked()
        }
    }

    /// Executes a mutating closure with the unlocked secwet.
    pub fn with_secwet_mut<T, F>(&self, f: F) -> Result<T, UiError>
    where
        F: FnOnce(&mut Secwet) -> Result<T, secwet_core::Error>,
    {
        let mut guard = self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))?;
        let secwet = guard.as_mut().ok_or_else(|| self.locked_or_busy())?;
        f(secwet).map_err(UiError::from)
    }
}
