use clap::{Args, Parser, Subcommand};
use secwet_cli::commands;
use secwet_cli::config::{find_and_load_config, SecwetConfig};
use secwet_cli::keystore::resolve_keystore;
use secwet_cli::resolver::{resolve_data_dir, resolve_environment, resolve_item};
use secwet_core::{EnvironmentView, Error, ProjectView, Vault, VaultStatus};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "secwet",
    about = "Passwordless, end-to-end encrypted secrets manager for developers",
    version,
    long_about = None
)]
pub struct Cli {
    /// Override the vault data directory (or use SECWET_DATA_DIR)
    #[arg(long, global = true, env = "SECWET_DATA_DIR")]
    pub data_dir: Option<PathBuf>,

    /// Target item name or UUID (or --project for backwards compatibility)
    #[arg(
        short = 'i',
        long = "item",
        visible_alias = "project",
        short_alias = 'p',
        global = true
    )]
    pub item: Option<String>,

    /// Target environment name or UUID (optional)
    #[arg(short = 'e', long = "env", global = true)]
    pub env: Option<String>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// List secret names and types (never prints values)
    List,

    /// Print a single secret value to stdout
    Get(GetArgs),

    /// Run a command with secrets injected into its environment
    Run(RunArgs),

    /// Create or update a secret, reading the value from stdin
    Set(SetArgs),

    /// Import secrets from a dotenv (.env) file
    Import(ImportArgs),

    /// Display local vault status, device ID, epoch, and plan
    Status(StatusArgs),

    /// Export secrets to stdout or file
    Export(ExportArgs),
}

#[derive(Args, Debug)]
pub struct GetArgs {
    /// The name of the secret to retrieve
    pub name: String,
}

#[derive(Args, Debug)]
pub struct RunArgs {
    /// Command and arguments to execute with injected secrets
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

#[derive(Args, Debug)]
pub struct SetArgs {
    /// The name of the secret
    pub name: String,

    /// Secret kind (env_var, api_key, password, access_token, ssh_key, certificate)
    #[arg(short = 'k', long)]
    pub kind: Option<String>,

    /// Optional description or note (max 500 chars)
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Path to the .env file to import
    pub file: PathBuf,
}

#[derive(Args, Debug)]
pub struct StatusArgs {
    /// Output status as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ExportArgs {
    /// Output file path (defaults to stdout if omitted)
    #[arg(short = 'o', long = "out")]
    pub out: Option<PathBuf>,

    /// Export format: dotenv (default) or json
    #[arg(short = 'f', long = "format", default_value = "dotenv")]
    pub format: String,
}

fn resolve_item_and_env(
    vault: &Vault,
    item_flag: Option<&str>,
    env_flag: Option<&str>,
    config: Option<&SecwetConfig>,
) -> std::result::Result<(ProjectView, Option<EnvironmentView>), ExitCode> {
    let item = match resolve_item(vault, item_flag, config) {
        Ok(i) => i,
        Err(_) => {
            eprintln!("error: item not found");
            return Err(ExitCode::from(1));
        }
    };

    let env = match resolve_environment(&item, env_flag, config) {
        Ok(e) => e,
        Err(Error::Invalid { message, .. }) => {
            eprintln!("error: {message}");
            return Err(ExitCode::from(1));
        }
        Err(_) => {
            eprintln!("error: environment not found in item '{}'", item.name);
            return Err(ExitCode::from(1));
        }
    };

    Ok((item, env))
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(err) => {
            if err.kind() == clap::error::ErrorKind::DisplayHelp
                || err.kind() == clap::error::ErrorKind::DisplayVersion
            {
                print!("{err}");
                return ExitCode::SUCCESS;
            }
            eprint!("{err}");
            return ExitCode::from(64);
        }
    };

    // Load .secwet.toml if present
    let config = match find_and_load_config(None) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("error: configuration error: {e}");
            return ExitCode::from(64);
        }
    };

    // Resolve data directory
    let data_dir = match resolve_data_dir(cli.data_dir, config.as_ref()) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("error: failed to resolve data directory: {e}");
            return ExitCode::from(1);
        }
    };

    // Check vault status
    match Vault::status(&data_dir) {
        Ok(VaultStatus::Uninitialized) => {
            eprintln!("error: no vault on this device");
            return ExitCode::from(2);
        }
        Err(_) => {
            eprintln!("error: vault is locked or storage damaged");
            return ExitCode::from(2);
        }
        _ => {}
    }

    // Resolve keystore
    let keystore = resolve_keystore(&data_dir);

    // Unlock vault
    let mut vault = match Vault::unlock(&data_dir, &*keystore) {
        Ok(v) => v,
        Err(Error::Locked | Error::NoVault | Error::KeyStore) => {
            eprintln!("error: vault is locked");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("error: failed to unlock vault: {e}");
            return ExitCode::from(1);
        }
    };

    let exit_code = match cli.command {
        Commands::Status(args) => {
            if let Err(e) = commands::status::execute_status(&vault, args.json) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::List => {
            let (item, env) = match resolve_item_and_env(
                &vault,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            if let Err(e) = commands::list::execute_list(&vault, item.id, env_id) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Get(args) => {
            let (item, env) = match resolve_item_and_env(
                &vault,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            if let Err(e) = commands::get::execute_get(&vault, item.id, env_id, &args.name) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Run(args) => {
            let (item, env) = match resolve_item_and_env(
                &vault,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            match commands::run::execute_run(&vault, item.id, env_id, &args.command) {
                Ok(child_exit_code) => {
                    vault.lock();
                    std::process::exit(child_exit_code);
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::from(1)
                }
            }
        }
        Commands::Set(args) => {
            let (item, env) = match resolve_item_and_env(
                &vault,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            let env_name = env.as_ref().map(|e| e.name.as_str());
            if let Err(e) = commands::set::execute_set(
                &mut vault,
                item.id,
                &item.name,
                env_id,
                env_name,
                &args.name,
                args.kind.as_deref(),
                args.note,
            ) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Import(args) => {
            let (item, env) = match resolve_item_and_env(
                &vault,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            let env_name = env.as_ref().map(|e| e.name.as_str());
            if let Err(e) = commands::import::execute_import(
                &mut vault,
                item.id,
                &item.name,
                env_id,
                env_name,
                &args.file,
            ) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Export(args) => {
            let (item, env) = match resolve_item_and_env(
                &vault,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            if let Err(e) = commands::export::execute_export(
                &vault,
                item.id,
                env_id,
                args.out.as_deref(),
                &args.format,
            ) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    };

    vault.lock();
    exit_code
}
