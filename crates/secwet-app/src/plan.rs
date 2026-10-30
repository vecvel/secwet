//! Plan commands, shared by every host.
//!
//! The plan lives in `secwet_core::plan`; this module exposes it to the UI.
//! Free never contacts the relay: `plan_status` and `plan_refresh` read the
//! cached plan, and only `plan_activate` (an explicit user action) may call
//! the relay from Free.

use secwet_core::{PlanInfo, PlanState};
use serde::Serialize;
use uuid::Uuid;

use crate::error::UiError;
use crate::state::AppState;

/// The plan as Settings, Devices and the sharing dialogs show it.
#[derive(Debug, Clone, Serialize)]
pub struct PlanStatusDto {
    /// `free`, `pro` or `paused` (Pro ended: sync paused, data untouched).
    pub plan: String,
    pub device_limit: u32,
    pub active_devices: u32,
    /// RFC 3339 end of the Pro entitlement, if it has one.
    pub expires_at: Option<String>,
    /// Unix ms of the last entitlement check on the relay.
    pub checked_at: Option<i64>,
    pub relay_configured: bool,
    /// Sync, pairing and sharing run only on an active Pro plan.
    pub sync_enabled: bool,
    /// Revocation and key rotation over the relay (Pro, and Pro that ended).
    pub relay_security: bool,
    /// The Secwet id an operator grants Pro to.
    pub secwet_id: Uuid,
}

fn dto(info: PlanInfo, active_devices: u32, secwet_id: Uuid) -> PlanStatusDto {
    PlanStatusDto {
        plan: info.state.as_str().to_string(),
        device_limit: info.device_limit,
        active_devices,
        expires_at: info.expires_at,
        checked_at: info.checked_at,
        relay_configured: info.relay_configured,
        sync_enabled: info.state == PlanState::Pro,
        relay_security: info.state != PlanState::Free,
        secwet_id,
    }
}

impl AppState {
    /// The cached plan. Never contacts the relay.
    pub fn plan_status(&self) -> Result<PlanStatusDto, UiError> {
        self.with_secwet(|s| {
            let active = s.active_devices_count().unwrap_or(1);
            Ok(dto(s.plan_info()?, active, s.secwet_id()))
        })
    }

    /// Re-reads the entitlement from the relay on Pro and paused stores. On
    /// Free it returns the cached plan without any network call.
    pub async fn plan_refresh(&self) -> Result<PlanStatusDto, UiError> {
        let stored = self.with_secwet(|s| s.plan_state())?;
        if stored == PlanState::Free || !self.plan_status()?.relay_configured {
            return self.plan_status();
        }
        let (mut secwet, client, ticket) = self.take()?;
        let res = secwet.refresh_plan(&client).await;
        self.finish_plan(secwet, ticket, res)?;
        self.emit_changed("plan");
        self.plan_status()
    }

    /// Asks the relay which plan this Secwet has, registering it first if
    /// needed. Started by the user ("Check for Pro"); the one relay call a
    /// Free store makes.
    pub async fn plan_activate(&self) -> Result<PlanStatusDto, UiError> {
        let (mut secwet, client, ticket) = self.take_unchecked()?;
        let res = secwet.activate_plan(&client).await;
        self.finish_plan(secwet, ticket, res)?;
        self.emit_changed("plan");
        self.plan_status()
    }
}
