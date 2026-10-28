//! Environment management commands for secwet-cli.

use crate::config::SecwetConfig;
use crate::resolver::resolve_item;
use clap::{Args, Subcommand};
use secwet_core::model::EnvironmentView;
use secwet_core::{Error, Result, Secwet};
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct EnvArgs {
    #[command(subcommand)]
    pub command: EnvSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum EnvSubcommands {
    /// List environments within an item
    List(EnvListArgs),
    /// Create a new environment in an item
    Create(EnvCreateArgs),
    /// Rename an environment
    Rename(EnvRenameArgs),
    /// Delete an environment
    Delete(EnvDeleteArgs),
}

#[derive(Args, Debug)]
pub struct EnvListArgs {
    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct EnvCreateArgs {
    /// Environment name (e.g. development, staging, production)
    pub name: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct EnvRenameArgs {
    /// Target environment name or UUID
    pub target: String,

    /// New environment name
    pub new_name: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct EnvDeleteArgs {
    /// Target environment name or UUID
    pub target: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Also delete secrets in this environment (otherwise preserved)
    #[arg(long)]
    pub delete_secrets: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub fn resolve_env_view(secwet: &Secwet, item_id: Uuid, target: &str) -> Result<EnvironmentView> {
    let envs = secwet.list_environments(item_id)?;
    if let Ok(id) = Uuid::parse_str(target) {
        if let Some(e) = envs.into_iter().find(|e| e.id == id) {
            return Ok(e);
        }
    } else if let Some(e) = envs.into_iter().find(|e| e.name.eq_ignore_ascii_case(target)) {
        return Ok(e);
    }
    Err(Error::NotFound)
}

pub fn execute_env(
    secwet: &mut Secwet,
    args: EnvArgs,
    config: Option<&SecwetConfig>,
    global_item: Option<&str>,
) -> Result<()> {
    match args.command {
        EnvSubcommands::List(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let item = resolve_item(secwet, item_target, config)?;
            let envs = secwet.list_environments(item.id)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&envs).map_err(|_| Error::Storage)?);
            } else if envs.is_empty() {
                println!("No environments found in item '{}'.", item.name);
            } else {
                println!("{:<38} {:<24} {:<8}", "ID", "NAME", "SECRETS");
                println!("{}", "-".repeat(74));
                for e in envs {
                    println!("{:<38} {:<24} {:<8}", e.id, e.name, e.secret_count);
                }
            }
            Ok(())
        }
        EnvSubcommands::Create(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let item = resolve_item(secwet, item_target, config)?;
            let created = secwet.add_environment(item.id, &sub.name)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&created).map_err(|_| Error::Storage)?);
            } else {
                println!(
                    "Created environment '{}' ({}) in item '{}'",
                    created.name, created.id, item.name
                );
            }
            Ok(())
        }
        EnvSubcommands::Rename(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let item = resolve_item(secwet, item_target, config)?;
            let env = resolve_env_view(secwet, item.id, &sub.target)?;
            secwet.rename_environment(env.id, &sub.new_name)?;

            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": env.id.to_string(),
                        "name": sub.new_name,
                        "status": "renamed"
                    })
                );
            } else {
                println!("Renamed environment '{}' -> '{}'", env.name, sub.new_name);
            }
            Ok(())
        }
        EnvSubcommands::Delete(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let item = resolve_item(secwet, item_target, config)?;
            let env = resolve_env_view(secwet, item.id, &sub.target)?;
            let preserve = !sub.delete_secrets;
            secwet.delete_environment_with_options(env.id, preserve)?;

            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": env.id.to_string(),
                        "name": env.name,
                        "status": "deleted"
                    })
                );
            } else {
                println!("Deleted environment '{}' ({})", env.name, env.id);
            }
            Ok(())
        }
    }
}

