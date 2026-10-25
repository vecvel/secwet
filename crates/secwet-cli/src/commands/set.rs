use secwet_core::{SecretDraft, Vault};
use secwet_proto::SecretKind;
use std::io::{IsTerminal, Read, Write};
use uuid::Uuid;

#[allow(clippy::too_many_arguments)]
pub fn execute_set(
    vault: &mut Vault,
    item_id: Uuid,
    item_name: &str,
    env_id: Option<Uuid>,
    env_name: Option<&str>,
    name: &str,
    kind_str: Option<&str>,
    note: Option<String>,
) -> Result<(), String> {
    secwet_proto::validate_secret_name(name)
        .map_err(|e| format!("invalid secret name '{name}': {e}"))?;

    let kind = match kind_str {
        Some(s) => s
            .parse::<SecretKind>()
            .map_err(|_| format!("invalid secret kind '{s}'"))?,
        None => SecretKind::EnvVar,
    };

    secwet_proto::validate_secret_note(note.as_deref())
        .map_err(|e| format!("invalid note: {e}"))?;

    let mut input = String::new();
    if std::io::stdin().is_terminal() {
        eprint!("Enter secret value: ");
        let _ = std::io::stderr().flush();
        std::io::stdin()
            .read_line(&mut input)
            .map_err(|e| format!("failed to read from stdin: {e}"))?;
        if input.ends_with('\n') {
            input.pop();
            if input.ends_with('\r') {
                input.pop();
            }
        }
    } else {
        std::io::stdin()
            .read_to_string(&mut input)
            .map_err(|e| format!("failed to read from stdin: {e}"))?;
    }

    secwet_proto::validate_secret_value(&input)
        .map_err(|e| format!("invalid secret value for '{name}': {e}"))?;

    let secrets = vault
        .list_secrets(item_id, env_id)
        .map_err(|e| format!("{e}"))?;
    let existing = secrets.into_iter().find(|s| s.name == name);

    let draft = SecretDraft::new(item_id, env_id, name, kind, input, note);

    let location = match env_name {
        Some(e) => format!("{item_name}/{e}"),
        None => item_name.to_string(),
    };

    if let Some(s) = existing {
        vault
            .update_secret(s.id, draft)
            .map_err(|e| format!("{e}"))?;
        eprintln!("Updated secret '{name}' in {location}");
    } else {
        vault.create_secret(draft).map_err(|e| format!("{e}"))?;
        eprintln!("Created secret '{name}' in {location}");
    }

    Ok(())
}
