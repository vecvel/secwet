use secwet_core::{PlanState, Secwet};

pub fn execute_status(secwet: &Secwet, json_output: bool) -> Result<(), String> {
    let secwet_id = secwet.secwet_id();
    let settings = secwet.settings().map_err(|e| format!("{e}"))?;
    let device_name = settings.device_name;

    // The cached plan; status never contacts the relay.
    let info = secwet.plan_info().map_err(|e| format!("{e}"))?;
    // `sync_state` keeps its machine values for scripts; `sync_line` is for people.
    let (sync_state, sync_line) = match info.state {
        PlanState::Free => ("offline", "Local only (Free never contacts the relay)"),
        PlanState::Paused => ("paused", "Paused until Pro is renewed"),
        PlanState::Pro if info.relay_configured => ("online", "On"),
        PlanState::Pro => ("offline", "Not set up (no relay address)"),
    };
    let until = info.expires_at.as_deref().map(|t| t.get(..10).unwrap_or(t));
    let plan_line = match (info.state, until) {
        (PlanState::Free, _) => "Free (this device only)".to_string(),
        (PlanState::Pro, Some(u)) => format!("Pro, {} devices, until {u}", info.device_limit),
        (PlanState::Pro, None) => format!("Pro, {} devices", info.device_limit),
        (PlanState::Paused, Some(u)) => format!("Pro ended {u}. Sync is paused; local data stays available"),
        (PlanState::Paused, None) => "Pro ended. Sync is paused; local data stays available".to_string(),
    };

    if json_output {
        let json_val = serde_json::json!({
            "secwet_id": secwet_id.to_string(),
            "device_name": device_name,
            "plan": info.plan(),
            "device_limit": info.device_limit,
            "expires_at": info.expires_at,
            "sync_state": sync_state,
        });
        println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
    } else {
        println!("{:<14} {}", "Secwet ID:", secwet_id);
        println!("{:<14} {}", "Device:", device_name);
        println!("{:<14} {}", "Plan:", plan_line);
        println!("{:<14} {}", "Sync:", sync_line);
    }

    Ok(())
}
