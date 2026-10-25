use crate::dotenv::parse_dotenv;
use secwet_core::{SecretDraft, Vault};
use secwet_proto::SecretKind;
use std::path::Path;
use uuid::Uuid;

pub fn execute_import(
    vault: &mut Vault,
    item_id: Uuid,
    item_name: &str,
    env_id: Option<Uuid>,
    env_name: Option<&str>,
    file_path: &Path,
) -> Result<(), String> {
    let content = std::fs::read_to_string(file_path)
        .map_err(|e| format!("cannot read file '{}': {e}", file_path.display()))?;

    let pairs = parse_dotenv(&content)?;
    if pairs.is_empty() {
        eprintln!("No secrets found in '{}'", file_path.display());
        return Ok(());
    }

    let existing_secrets = vault
        .list_secrets(item_id, env_id)
        .map_err(|e| format!("{e}"))?;
    let mut existing_map = std::collections::HashMap::new();
    for s in existing_secrets {
        existing_map.insert(s.name, s.id);
    }

    let mut created = 0usize;
    let mut updated = 0usize;

    for (key, val) in pairs {
        let draft = SecretDraft::new(item_id, env_id, &key, SecretKind::EnvVar, val, None);

        if let Some(&id) = existing_map.get(&key) {
            vault.update_secret(id, draft).map_err(|e| format!("{e}"))?;
            updated += 1;
        } else {
            let meta = vault.create_secret(draft).map_err(|e| format!("{e}"))?;
            existing_map.insert(key, meta.id);
            created += 1;
        }
    }

    let location = match env_name {
        Some(e) => format!("{item_name}/{e}"),
        None => item_name.to_string(),
    };

    eprintln!(
        "Imported {} secret(s) ({} created, {} updated) into {}",
        created + updated,
        created,
        updated,
        location
    );

    Ok(())
}
