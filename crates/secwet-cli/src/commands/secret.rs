//! Secret management commands for secwet-cli.

use crate::commands::get::execute_get;
use crate::commands::set::parse_kind_cli;
use crate::config::SecwetConfig;
use crate::resolver::resolve_item_and_env;
use clap::{Args, Subcommand};
use secrecy::ExposeSecret;
use secwet_core::model::SecretDraft;
use secwet_core::{Error, Result, Secwet};
use secwet_proto::SecretKind;
use std::io::{IsTerminal, Read, Write};

#[derive(Args, Debug)]
pub struct SecretArgs {
    #[command(subcommand)]
    pub command: SecretSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum SecretSubcommands {
    /// List secrets (never outputs plaintext values)
    List(SecretListArgs),
    /// Print a single secret value to stdout
    Get(SecretGetArgs),
    /// Create or update a secret
    Set(SecretSetArgs),
    /// Delete a secret
    Delete(SecretDeleteArgs),
    /// Copy a secret to another environment
    CopyToEnv(SecretCopyToEnvArgs),
}

#[derive(Args, Debug)]
pub struct SecretListArgs {
    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SecretGetArgs {
    /// The name of the secret
    pub name: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Output in JSON format (metadata + value)
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SecretSetArgs {
    /// The name of the secret
    pub name: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Secret kind (env_var, api_key, password, access_token, ssh_key, certificate, codes)
    #[arg(short = 'k', long)]
    pub kind: Option<String>,

    /// Optional note / comment
    #[arg(long)]
    pub note: Option<String>,

    /// Value for the secret (if omitted, reads from stdin)
    #[arg(long)]
    pub value: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SecretDeleteArgs {
    /// The name of the secret
    pub name: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SecretCopyToEnvArgs {
    /// Name of the secret to copy
    pub name: String,

    /// Target environment name or UUID (use "general" for item root)
    #[arg(long = "target-env", required = true)]
    pub target_env: String,

    /// Source item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Source environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub fn execute_secret(
    secwet: &mut Secwet,
    args: SecretArgs,
    config: Option<&SecwetConfig>,
    global_item: Option<&str>,
    global_env: Option<&str>,
) -> Result<()> {
    match args.command {
        SecretSubcommands::List(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, false)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);
            let secrets = secwet.list_secrets(item.id, env_id)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&secrets).map_err(|_| Error::Storage)?);
            } else if secrets.is_empty() {
                println!("No secrets found.");
            } else {
                println!("{:<32} {:<14} {:<6} {:<12}", "NAME", "KIND", "TAIL", "UPDATED");
                println!("{}", "-".repeat(68));
                for s in secrets {
                    println!(
                        "{:<32} {:<14} {:<6} {:<12}",
                        s.name,
                        s.kind.to_string(),
                        s.value_tail,
                        crate::resolver::format_timestamp(s.updated_at)
                    );
                }
            }
            Ok(())
        }
        SecretSubcommands::Get(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, false)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);

            if sub.json {
                let secrets = secwet.list_secrets(item.id, env_id)?;
                let meta = secrets.into_iter().find(|s| s.name == sub.name).ok_or(Error::NotFound)?;
                let val = secwet.reveal_secret(meta.id)?;
                println!(
                    "{}",
                    serde_json::json!({
                        "id": meta.id.to_string(),
                        "name": meta.name,
                        "kind": meta.kind.to_string(),
                        "value": val.expose_secret(),
                        "updated_at": meta.updated_at
                    })
                );
                Ok(())
            } else {
                execute_get(secwet, item.id, env_id, &sub.name).map_err(|_| Error::NotFound)
            }
        }
        SecretSubcommands::Set(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);

            secwet_proto::validate_secret_name(&sub.name)
                .map_err(|_| Error::Invalid { field: "name", message: "invalid secret name".into() })?;

            let kind = match sub.kind.as_deref() {
                Some(s) => parse_kind_cli(s).map_err(|e| Error::Invalid { field: "kind", message: e })?,
                None => SecretKind::EnvVar,
            };

            secwet_proto::validate_secret_note(sub.note.as_deref())
                .map_err(|_| Error::Invalid { field: "note", message: "invalid note".into() })?;

            let value = if let Some(val) = sub.value {
                val
            } else {
                let mut input = String::new();
                if std::io::stdin().is_terminal() {
                    eprint!("Enter secret value: ");
                    let _ = std::io::stderr().flush();
                    std::io::stdin()
                        .read_line(&mut input)
                        .map_err(|_| Error::Storage)?;
                    if input.ends_with('\n') {
                        input.pop();
                        if input.ends_with('\r') {
                            input.pop();
                        }
                    }
                } else {
                    std::io::stdin()
                        .read_to_string(&mut input)
                        .map_err(|_| Error::Storage)?;
                }
                input
            };

            secwet_proto::validate_secret_value(&value)
                .map_err(|_| Error::Invalid { field: "value", message: "invalid secret value".into() })?;

            let secrets = secwet.list_secrets(item.id, env_id)?;
            let existing = secrets.into_iter().find(|s| s.name == sub.name);

            let draft = SecretDraft::new(item.id, env_id, sub.name.clone(), kind, value, sub.note);

            let meta = if let Some(s) = existing {
                secwet.update_secret(s.id, draft)?
            } else {
                secwet.create_secret(draft)?
            };

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&meta).map_err(|_| Error::Storage)?);
            } else {
                let location = match env.as_ref() {
                    Some(e) => format!("{}/{}", item.name, e.name),
                    None => format!("{} (General)", item.name),
                };
                println!("Saved secret '{}' in {location}", meta.name);
            }
            Ok(())
        }
        SecretSubcommands::Delete(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, false)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);

            let secrets = secwet.list_secrets(item.id, env_id)?;
            let s = secrets.into_iter().find(|s| s.name == sub.name).ok_or(Error::NotFound)?;
            secwet.delete_secret(s.id)?;

            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": s.id.to_string(),
                        "name": s.name,
                        "status": "deleted"
                    })
                );
            } else {
                println!("Deleted secret '{}' ({})", s.name, s.id);
            }
            Ok(())
        }
        SecretSubcommands::CopyToEnv(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, false)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);

            let secrets = secwet.list_secrets(item.id, env_id)?;
            let s = secrets.into_iter().find(|s| s.name == sub.name).ok_or(Error::NotFound)?;

            let target_env_id = if sub.target_env.eq_ignore_ascii_case("general") || sub.target_env.eq_ignore_ascii_case("none") {
                None
            } else {
                let item_envs = secwet.list_environments(item.id)?;
                let target_e = item_envs
                    .into_iter()
                    .find(|e| e.name.eq_ignore_ascii_case(&sub.target_env) || e.id.to_string() == sub.target_env)
                    .ok_or(Error::NotFound)?;
                Some(target_e.id)
            };

            let copied = secwet.copy_secret_to_environment(s.id, target_env_id)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&copied).map_err(|_| Error::Storage)?);
            } else {
                println!("Copied secret '{}' to environment '{}'", s.name, sub.target_env);
            }
            Ok(())
        }
    }
}
