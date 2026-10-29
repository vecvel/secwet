//! Joining a Secwet from another device's pairing code (F14), on a device
//! that has no Secwet yet. The approving side is `pairing_start` /
//! `pairing_poll` / `pairing_approve` in `commands.rs`.
//!
//! 1. `pairing_join_start` with the scanned `secwet://pair?...` link: joins
//!    the relay session and returns the 6-digit code to compare.
//! 2. `pairing_join_poll` until the other device approves: the store is
//!    created with the received keys, opened, and synced once.

use secwet_core::pairing_join::{PairingJoin, PairingPoller};
use serde::Serialize;

use crate::error::UiError;
use crate::state::{AppState, SecwetStatusDto};

/// What the new device shows while waiting for approval.
#[derive(Debug, Clone, Serialize)]
pub struct PairingJoinInfo {
    /// The code both screens must show.
    pub code: String,
    /// This device's new key fingerprint, as the approver sees it.
    pub fingerprint: String,
}

/// Result of polling a joined pairing session.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PairingJoinPoll {
    Waiting,
    Expired,
    /// Approved: the store exists and is open. `synced` is false when the
    /// first sync failed (it runs again on the next sync).
    Approved { secwet: SecwetStatusDto, synced: bool },
}

impl AppState {
    fn ensure_no_store(&self) -> Result<(), UiError> {
        match self.secwet_status()? {
            SecwetStatusDto::Uninitialized => Ok(()),
            _ => Err(UiError::already_initialized()),
        }
    }

    fn joins(&self) -> Result<std::sync::MutexGuard<'_, Option<PairingJoin>>, UiError> {
        self.pairing_join
            .lock()
            .map_err(|_| UiError::internal("Pairing mutex poisoned"))
    }

    /// Joins the pairing session in `link` as a new device.
    pub async fn pairing_join_start(
        &self,
        link: String,
        device_name: String,
        platform: String,
    ) -> Result<PairingJoinInfo, UiError> {
        self.ensure_no_store()?;
        let join = PairingJoin::start(&link, &device_name, &platform).await?;
        let info = PairingJoinInfo {
            code: join.code().to_string(),
            fingerprint: join.fingerprint(),
        };
        *self.joins()? = Some(join);
        Ok(info)
    }

    /// Checks whether the other device approved; on approval creates and
    /// opens the store, then pulls the data once.
    pub async fn pairing_join_poll(&self) -> Result<PairingJoinPoll, UiError> {
        let Some(poller) = self.joins()?.as_ref().map(PairingJoin::poller) else {
            return Ok(PairingJoinPoll::Expired);
        };
        let result = match poller.poll().await {
            Ok(Some(result)) => result,
            Ok(None) | Err(secwet_core::Error::Offline) => return Ok(PairingJoinPoll::Waiting),
            Err(secwet_core::Error::Relay { code }) if code == "expired" || code == "not_found" => {
                self.drop_join(&poller)?;
                return Ok(PairingJoinPoll::Expired);
            }
            Err(e) => return Err(e.into()),
        };

        // Cancelled or restarted while the request ran: this approval is stale.
        let join = {
            let mut guard = self.joins()?;
            match guard.as_ref() {
                Some(j) if j.session_id() == poller.session_id() => guard.take(),
                _ => None,
            }
        };
        let Some(join) = join else {
            return Ok(PairingJoinPoll::Expired);
        };
        self.ensure_no_store()?;
        let secwet = join.finish(&self.data_dir, &result, self.keystore.as_ref())?;
        let status = SecwetStatusDto::from(secwet.current_status());
        *self
            .secwet
            .lock()
            .map_err(|_| UiError::internal("Secwet mutex poisoned"))? = Some(secwet);
        let synced = self.sync_round().await.is_ok();
        self.emit_changed("all");
        Ok(PairingJoinPoll::Approved { secwet: status, synced })
    }

    /// Forgets a pending join; nothing was stored for it.
    pub fn pairing_join_cancel(&self) -> Result<(), UiError> {
        *self.joins()? = None;
        Ok(())
    }

    fn drop_join(&self, poller: &PairingPoller) -> Result<(), UiError> {
        let mut guard = self.joins()?;
        if guard.as_ref().is_some_and(|j| j.session_id() == poller.session_id()) {
            *guard = None;
        }
        Ok(())
    }
}
