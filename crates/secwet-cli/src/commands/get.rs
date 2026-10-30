use secrecy::ExposeSecret;
use secwet_core::Secwet;
use std::io::{IsTerminal, Write};
use uuid::Uuid;

pub fn execute_get(
    secwet: &Secwet,
    item_id: Uuid,
    env_id: Option<Uuid>,
    name: &str,
) -> Result<(), String> {
    let secret_meta = match env_id {
        Some(e) => {
            let env_secrets = secwet.list_secrets(item_id, Some(e)).map_err(|err| format!("{err}"))?;
            if let Some(s) = env_secrets.into_iter().find(|s| s.name == name) {
                s
            } else {
                let item_secrets = secwet.list_secrets(item_id, None).map_err(|err| format!("{err}"))?;
                item_secrets
                    .into_iter()
                    .find(|s| s.name == name)
                    .ok_or_else(|| format!("secret '{name}' not found"))?
            }
        }
        None => {
            let item_secrets = secwet.list_secrets(item_id, None).map_err(|err| format!("{err}"))?;
            item_secrets
                .into_iter()
                .find(|s| s.name == name)
                .ok_or_else(|| format!("secret '{name}' not found"))?
        }
    };

    let secret_val = secwet
        .reveal_secret(secret_meta.id)
        .map_err(|e| format!("{e}"))?;
    let exposed = secret_val.expose_secret();

    if std::io::stdout().is_terminal() {
        println!("{exposed}");
    } else {
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle
            .write_all(exposed.as_bytes())
            .map_err(|e| format!("failed to write to stdout: {e}"))?;
        handle
            .flush()
            .map_err(|e| format!("failed to flush stdout: {e}"))?;
    }

    Ok(())
}
