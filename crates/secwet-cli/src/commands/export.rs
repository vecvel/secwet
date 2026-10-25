use secrecy::ExposeSecret;
use secwet_core::Vault;
use std::path::Path;
use uuid::Uuid;

pub fn execute_export(
    vault: &Vault,
    item_id: Uuid,
    env_id: Option<Uuid>,
    out_path: Option<&Path>,
    format: &str,
) -> Result<(), String> {
    let mut secrets = vault
        .env_for(item_id, env_id)
        .map_err(|e| format!("{e}"))?;
    secrets.sort_by(|a, b| a.0.cmp(&b.0));

    let output_str = match format.to_ascii_lowercase().as_str() {
        "dotenv" => {
            let mut out = String::new();
            for (k, v) in secrets {
                let val = v.expose_secret();
                let escaped = val
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n")
                    .replace('\r', "\\r");
                out.push_str(&format!("{k}=\"{escaped}\"\n"));
            }
            out
        }
        "json" => {
            let mut map = std::collections::BTreeMap::new();
            for (k, v) in secrets {
                map.insert(k, v.expose_secret().to_string());
            }
            serde_json::to_string_pretty(&map)
                .map_err(|e| format!("failed to format JSON: {e}"))?
                + "\n"
        }
        other => {
            return Err(format!(
                "unsupported export format '{other}': must be 'dotenv' or 'json'"
            ))
        }
    };

    if let Some(p) = out_path {
        std::fs::write(p, &output_str)
            .map_err(|e| format!("failed to write export to '{}': {e}", p.display()))?;
    } else {
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        handle
            .write_all(output_str.as_bytes())
            .map_err(|e| format!("failed to write to stdout: {e}"))?;
        handle
            .flush()
            .map_err(|e| format!("failed to flush stdout: {e}"))?;
    }

    Ok(())
}
