use crate::resolver::format_timestamp_ms;
use secwet_core::Vault;
use std::io::IsTerminal;
use uuid::Uuid;

pub fn execute_list(vault: &Vault, item_id: Uuid, env_id: Option<Uuid>) -> Result<(), String> {
    let mut secrets = vault
        .list_secrets(item_id, env_id)
        .map_err(|e| format!("{e}"))?;
    secrets.sort_by(|a, b| a.name.cmp(&b.name));

    if std::io::stdout().is_terminal() {
        println!("{:<24} {:<16} UPDATED", "NAME", "KIND");
        println!("{:-<24} {:-<16} {:-<24}", "", "", "");
        for s in &secrets {
            let updated = format_timestamp_ms(s.updated_at);
            println!("{:<24} {:<16} {}", s.name, s.kind.as_str(), updated);
        }
    } else {
        for s in &secrets {
            let updated = format_timestamp_ms(s.updated_at);
            println!("{}\t{}\t{}", s.name, s.kind.as_str(), updated);
        }
    }

    Ok(())
}
