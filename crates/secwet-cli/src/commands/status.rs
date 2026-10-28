use secwet_core::Secwet;

pub fn execute_status(secwet: &Secwet, json_output: bool) -> Result<(), String> {
    let secwet_id = secwet.secwet_id();
    let settings = secwet.settings().map_err(|e| format!("{e}"))?;
    let device_name = settings.device_name;

    let plan = secwet_core::records::get_meta(secwet.db_connection(), "plan")
        .map_err(|e| format!("{e}"))?
        .unwrap_or_else(|| "free".to_string());

    let relay_url = secwet_core::records::get_meta(secwet.db_connection(), "relay_url")
        .map_err(|e| format!("{e}"))?
        .unwrap_or_default();

    let sync_state = if relay_url.trim().is_empty() {
        "offline"
    } else {
        "online"
    };

    if json_output {
        let json_val = serde_json::json!({
            "secwet_id": secwet_id.to_string(),
            "device_name": device_name,
            "plan": plan,
            "sync_state": sync_state,
        });
        println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
    } else {
        println!("{:<14} {}", "Secwet ID:", secwet_id);
        println!("{:<14} {}", "Device:", device_name);
        println!("{:<14} {}", "Plan:", plan);
        println!("{:<14} {}", "Sync State:", sync_state);
    }

    Ok(())
}
