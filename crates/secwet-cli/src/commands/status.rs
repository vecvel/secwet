use secwet_core::Vault;

pub fn execute_status(vault: &Vault, json_output: bool) -> Result<(), String> {
    let vault_id = vault.vault_id();
    let settings = vault.settings().map_err(|e| format!("{e}"))?;
    let device_name = settings.device_name;

    let plan = secwet_core::records::get_meta(vault.db_connection(), "plan")
        .map_err(|e| format!("{e}"))?
        .unwrap_or_else(|| "free".to_string());

    let relay_url = secwet_core::records::get_meta(vault.db_connection(), "relay_url")
        .map_err(|e| format!("{e}"))?
        .unwrap_or_default();

    let sync_state = if relay_url.trim().is_empty() {
        "offline"
    } else {
        "online"
    };

    if json_output {
        let json_val = serde_json::json!({
            "vault_id": vault_id.to_string(),
            "device_name": device_name,
            "plan": plan,
            "sync_state": sync_state,
        });
        println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
    } else {
        println!("{:<14} {}", "Vault ID:", vault_id);
        println!("{:<14} {}", "Device:", device_name);
        println!("{:<14} {}", "Plan:", plan);
        println!("{:<14} {}", "Sync State:", sync_state);
    }

    Ok(())
}
