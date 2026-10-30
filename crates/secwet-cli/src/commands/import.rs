use crate::dotenv::parse_dotenv;
use secwet_core::{SecretDraft, Secwet};
use secwet_proto::SecretKind;
use std::path::Path;
use uuid::Uuid;

pub fn execute_import(
    secwet: &mut Secwet,
    item_id: Uuid,
    item_name: &str,
    env_id: Option<Uuid>,
    env_name: Option<&str>,
    file_path: &Path,
) -> Result<(), String> {
    let content = if file_path == Path::new("-") {
        use std::io::Read;
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|e| format!("cannot read from stdin: {e}"))?;
        buffer
    } else {
        std::fs::read_to_string(file_path)
            .map_err(|e| format!("cannot read file '{}': {e}", file_path.display()))?
    };

    let pairs = parse_dotenv(&content)?;
    if pairs.is_empty() {
        let source = if file_path == Path::new("-") {
            "stdin".to_string()
        } else {
            format!("'{}'", file_path.display())
        };
        eprintln!("No secrets found in {source}");
        return Ok(());
    }

    let existing_secrets = secwet
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
            secwet.update_secret(id, draft).map_err(|e| format!("{e}"))?;
            updated += 1;
        } else {
            let meta = secwet.create_secret(draft).map_err(|e| format!("{e}"))?;
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
