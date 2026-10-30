//! Plans and entitlements.
//!
//! The relay owns the entitlement. The store caches it in
//! `meta` and refreshes it on every sync round:
//!
//! | meta key             | value                                          |
//! |----------------------|------------------------------------------------|
//! | `plan`               | `free`, `pro` or `paused` (Pro that ended)     |
//! | `plan_device_limit`  | device limit from the entitlement              |
//! | `plan_expires_at`    | RFC 3339 end of the entitlement, empty if none |
//! | `plan_checked_at`    | unix ms of the last successful relay check     |
//!
//! Free never contacts the relay: every network path checks
//! [`Secwet::ensure_relay_allowed`] first. The only exception is
//! [`Secwet::activate_plan`], which the user starts explicitly to move a
//! Free store to Pro. When Pro ends the store becomes `paused`: sync stops,
//! local data stays fully usable and exportable, nothing is deleted or locked.

use serde::{Deserialize, Serialize};

use crate::records::{get_meta, set_meta};
use crate::relay_client::RelayClient;
use crate::{Error, Result, Secwet};

/// Device limit on the Free plan: this device only.
pub const FREE_DEVICE_LIMIT: u32 = 1;
/// Pro device limit when the entitlement does not say otherwise.
pub const DEFAULT_PRO_DEVICE_LIMIT: u32 = 5;

/// Where the store stands with its plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanState {
    /// One device, local only, no relay contact.
    Free,
    /// Active entitlement: pairing, sync, revocation, rotation, collaboration.
    Pro,
    /// Pro ended: sync is paused, local data is untouched.
    Paused,
}

impl PlanState {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanState::Free => "free",
            PlanState::Pro => "pro",
            PlanState::Paused => "paused",
        }
    }

    /// Unknown values read as Free, the plan that never contacts the relay.
    pub fn parse(s: &str) -> PlanState {
        match s.trim() {
            "pro" => PlanState::Pro,
            "paused" => PlanState::Paused,
            _ => PlanState::Free,
        }
    }
}

/// What a store may do over the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayOp {
    /// Entitlement check only (resumes a paused store once Pro is renewed).
    Entitlement,
    /// Push, pull, snapshots, pairing, invitations: needs an active Pro plan.
    Sync,
    /// Revocation and key rotation: allowed while paused, because security
    /// actions must never be locked behind a plan.
    Security,
}

/// Cached plan of a store, as shown in Settings and the CLI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanInfo {
    pub state: PlanState,
    pub device_limit: u32,
    /// RFC 3339 end of the Pro entitlement, if it has one.
    pub expires_at: Option<String>,
    /// Unix ms of the last successful entitlement check on the relay.
    pub checked_at: Option<i64>,
    pub relay_configured: bool,
}

impl PlanInfo {
    pub fn plan(&self) -> &'static str {
        self.state.as_str()
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Parses an RFC 3339 timestamp (`2027-01-01T00:00:00Z`,
/// `2027-01-01T00:00:00.123+02:00`) or a plain date (`2027-01-01`, midnight
/// UTC) into unix ms. Returns `None` for anything else.
pub fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    let b = s.as_bytes();
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let part = s.get(r)?;
        if part.is_empty() || !part.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        part.parse().ok()
    };
    if b.len() < 10 || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (year, month, day) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    let mut ms = days_from_civil(year, month, day) * 86_400_000;
    if b.len() == 10 {
        return Some(ms);
    }
    if !matches!(b[10], b'T' | b't' | b' ') || b.len() < 19 || b[13] != b':' || b[16] != b':' {
        return None;
    }
    let (hour, minute, second) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    ms += (hour * 3600 + minute * 60 + second) * 1000;
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return None;
        }
        let frac = &s[start..i.min(start + 3)];
        let scale = 10i64.pow(3 - frac.len() as u32);
        ms += frac.parse::<i64>().ok()? * scale;
    }
    match b.get(i) {
        Some(b'Z' | b'z') if i + 1 == b.len() => Some(ms),
        Some(sign @ (b'+' | b'-')) if b.len() == i + 6 && b[i + 3] == b':' => {
            let offset = (num(i + 1..i + 3)? * 60 + num(i + 4..i + 6)?) * 60_000;
            Some(if *sign == b'+' { ms - offset } else { ms + offset })
        }
        _ => None,
    }
}

/// Whether an entitlement end has passed. Unparseable values count as
/// passed, so a damaged expiry can never extend Pro.
fn is_past(expires_at: Option<&str>, now: i64) -> bool {
    match expires_at {
        Some(t) if !t.trim().is_empty() => parse_rfc3339_ms(t).is_none_or(|end| end <= now),
        _ => false,
    }
}

impl Secwet {
    /// The stored plan, before the local expiry check.
    fn stored_plan_state(&self) -> Result<PlanState> {
        Ok(PlanState::parse(&get_meta(&self.db, "plan")?.unwrap_or_default()))
    }

    /// The cached plan. A Pro entitlement whose end has passed reads as
    /// paused right away, without waiting for the next relay check.
    pub fn plan_info(&self) -> Result<PlanInfo> {
        let stored = self.stored_plan_state()?;
        let expires_at = get_meta(&self.db, "plan_expires_at")?.filter(|v| !v.trim().is_empty());
        let state = if stored == PlanState::Pro && is_past(expires_at.as_deref(), now_ms()) {
            PlanState::Paused
        } else {
            stored
        };
        let device_limit = match state {
            PlanState::Free => FREE_DEVICE_LIMIT,
            _ => get_meta(&self.db, "plan_device_limit")?
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_PRO_DEVICE_LIMIT),
        };
        let checked_at = get_meta(&self.db, "plan_checked_at")?.and_then(|v| v.parse().ok());
        let relay_configured = get_meta(&self.db, "relay_url")?.is_some_and(|u| !u.trim().is_empty());
        Ok(PlanInfo { state, device_limit, expires_at, checked_at, relay_configured })
    }

    /// The effective plan state.
    pub fn plan_state(&self) -> Result<PlanState> {
        Ok(self.plan_info()?.state)
    }

    /// The effective plan as a string: `free`, `pro` or `paused`.
    pub fn plan(&self) -> Result<String> {
        Ok(self.plan_state()?.as_str().to_string())
    }

    /// Sets the cached plan directly (tests and stores created by pairing or
    /// an invitation, which join an already entitled workspace).
    pub fn set_plan(&mut self, plan: &str) -> Result<()> {
        set_meta(&self.db, "plan", PlanState::parse(plan).as_str())?;
        Ok(())
    }

    /// Fails without touching the network when the plan does not allow `op`.
    pub fn ensure_relay_allowed(&self, op: RelayOp) -> Result<()> {
        match (self.plan_state()?, op) {
            (PlanState::Free, _) => Err(Error::NeedsPro),
            (PlanState::Paused, RelayOp::Sync) => Err(Error::SyncPaused),
            _ => Ok(()),
        }
    }

    /// Stores a relay entitlement and returns the resulting plan.
    ///
    /// An active Pro entitlement makes the store Pro. Anything else pauses a
    /// store that had Pro (or whose entitlement visibly ended) and leaves a
    /// Free store Free.
    pub fn apply_entitlement(&mut self, ent: &secwet_proto::EntitlementResponse) -> Result<PlanInfo> {
        let now = now_ms();
        let expires_at = ent.expires_at.clone().filter(|v| !v.trim().is_empty());
        let ended = is_past(expires_at.as_deref(), now);
        let state = if ent.plan == "pro" && !ended {
            PlanState::Pro
        } else if self.stored_plan_state()? != PlanState::Free || (ent.plan == "pro" && ended) {
            PlanState::Paused
        } else {
            PlanState::Free
        };
        let limit = if ent.device_limit == 0 { DEFAULT_PRO_DEVICE_LIMIT } else { ent.device_limit };
        set_meta(&self.db, "plan", state.as_str())?;
        set_meta(&self.db, "plan_device_limit", &limit.to_string())?;
        set_meta(&self.db, "plan_expires_at", expires_at.as_deref().unwrap_or(""))?;
        set_meta(&self.db, "plan_checked_at", &now.to_string())?;
        self.plan_info()
    }

    /// Re-reads the entitlement from the relay. A Free store returns its
    /// cached plan and never contacts the relay.
    pub async fn refresh_plan(&mut self, client: &RelayClient) -> Result<PlanInfo> {
        if self.stored_plan_state()? == PlanState::Free {
            return self.plan_info();
        }
        let ent = client.get_entitlement(self.secwet_id, &self.device_sign_key).await?;
        self.apply_entitlement(&ent)
    }

    /// Moves a store to the plan its relay entitlement grants. Started by the
    /// user (Settings > Plan > Check for Pro): this is the one relay
    /// call a Free store makes. Registers the workspace and this device on
    /// the relay first if it is not registered yet.
    pub async fn activate_plan(&mut self, client: &RelayClient) -> Result<PlanInfo> {
        self.relay_url()?;
        if self.is_owner() {
            // Borrow only fields across the await, so the future stays `Send`.
            let (id, sign_pub, enc_pub) = (self.secwet_id, self.device_sign_pub, self.device_enc_pub);
            match client.register(id, sign_pub, enc_pub, &self.device_sign_key).await {
                Ok(_) => {}
                Err(Error::Relay { code }) if code == "exists" => {}
                Err(e) => return Err(e),
            }
        }
        let ent = client.get_entitlement(self.secwet_id, &self.device_sign_key).await?;
        self.apply_entitlement(&ent)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_rfc3339_forms() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_ms("2027-01-01"), Some(1_798_761_600_000));
        assert_eq!(parse_rfc3339_ms("2027-01-01T00:00:00+00:00"), Some(1_798_761_600_000));
        assert_eq!(parse_rfc3339_ms("2027-01-01T02:00:00+02:00"), Some(1_798_761_600_000));
        assert_eq!(parse_rfc3339_ms("2026-12-31T19:00:00-05:00"), Some(1_798_761_600_000));
        assert_eq!(parse_rfc3339_ms("2027-01-01T00:00:00.5Z"), Some(1_798_761_600_500));
        assert_eq!(parse_rfc3339_ms("2027-01-01T00:00:00.123456789Z"), Some(1_798_761_600_123));
        assert_eq!(parse_rfc3339_ms("2000-02-29T12:00:00Z"), Some(951_825_600_000));
        for bad in ["", "never", "2027-13-01", "2027-01-01T25:00:00Z", "2027-01-01T00:00:00", "2027-01-01T00:00:00+0200"] {
            assert_eq!(parse_rfc3339_ms(bad), None, "{bad}");
        }
    }

    #[test]
    fn expiry_is_strict_and_damaged_values_count_as_ended() {
        let now = 1_798_761_600_000;
        assert!(!is_past(None, now));
        assert!(!is_past(Some(""), now));
        assert!(!is_past(Some("2027-01-01T00:00:01Z"), now));
        assert!(is_past(Some("2027-01-01T00:00:00Z"), now));
        assert!(is_past(Some("garbage"), now));
    }

    #[test]
    fn plan_state_round_trips() {
        for s in [PlanState::Free, PlanState::Pro, PlanState::Paused] {
            assert_eq!(PlanState::parse(s.as_str()), s);
        }
        assert_eq!(PlanState::parse("enterprise"), PlanState::Free);
    }
}
