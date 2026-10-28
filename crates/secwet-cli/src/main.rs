use clap::{Args, Parser, Subcommand};
use secwet_cli::commands;
use secwet_cli::config::{find_and_load_config, SecwetConfig};
use secwet_cli::keystore::resolve_keystore;
use secwet_cli::resolver::{
    resolve_data_dir, resolve_environment_with_default, resolve_item,
};
use secwet_core::{EnvironmentView, Error, ProjectView, Secwet, SecwetStatus};
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
    /// Override the secwet data directory (or use SECWET_DATA_DIR)
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

    /// Display local secwet status, device ID, epoch, and plan
    Status(StatusArgs),

    /// Export secrets to stdout or file
    Export(ExportArgs),

    /// Manage spaces (parent containers for groups)
    Space(commands::space::SpaceArgs),

    /// Manage groups (sections/labels)
    #[command(visible_alias = "section", visible_alias = "label")]
    Group(commands::group::GroupArgs),

    /// Manage items (entries/projects)
    #[command(visible_alias = "entry", visible_alias = "project")]
    Item(commands::item::ItemArgs),

    /// Manage environments
    #[command(visible_alias = "environment")]
    Env(commands::env::EnvArgs),

    /// Manage secrets (list, get, set, delete, copy-to-env)
    Secret(commands::secret::SecretArgs),

    /// Manage rich notes
    Note(commands::note::NoteArgs),

    /// Manage encrypted files/assets
    #[command(visible_alias = "asset")]
    File(commands::file::FileArgs),

    /// Manage active process sessions
    Session(commands::session::SessionArgs),

    /// Inspect complete workspace hierarchy tree (ASCII or JSON)
    Tree(commands::tree::TreeArgs),

    /// Manage registered devices (list, revoke)
    Device(commands::device::DeviceArgs),

    /// Pair a device (start pairing session or join an existing session)
    Pair(commands::pair::PairArgs),

    /// Synchronize local workspace changes with the relay server
    Sync(commands::sync::SyncArgs),

    /// Show or rotate the workspace encryption key
    Key(commands::collab::KeyArgs),

    /// Manage collaborators: list, invite, role, remove, join
    Member(commands::collab::MemberArgs),

    /// Initialize local .secwet.toml in repository
    Init(commands::init::InitArgs),
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

    /// Secret kind (env_var, api_key, password, access_token, ssh_key, certificate, codes)
    #[arg(short = 'k', long)]
    pub kind: Option<String>,

    /// Optional description or note (max 500 chars)
    #[arg(long)]
    pub note: Option<String>,
}

#[derive(Args, Debug)]
pub struct ImportArgs {
    /// Path to the .env file to import (use '-' to read from stdin)
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

    /// Explicitly allow exporting unencrypted plaintext secrets
    #[arg(long = "plaintext")]
    pub plaintext: bool,
}

fn resolve_item_and_env(
    secwet: &Secwet,
    item_flag: Option<&str>,
    env_flag: Option<&str>,
    config: Option<&SecwetConfig>,
    default_to_general: bool,
) -> std::result::Result<(ProjectView, Option<EnvironmentView>), ExitCode> {
    let item = match resolve_item(secwet, item_flag, config) {
        Ok(i) => i,
        Err(_) => {
            eprintln!("error: item not found");
            return Err(ExitCode::from(1));
        }
    };

    let env = match resolve_environment_with_default(&item, env_flag, config, default_to_general) {
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

    // `member join` creates the local store from an invite link.
    if let Commands::Member(commands::collab::MemberArgs {
        command: commands::collab::MemberSubcommand::Join { link, email, name },
    }) = &cli.command
    {
        let keystore = resolve_keystore(&data_dir);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime");
        return match rt.block_on(commands::collab::execute_join(&data_dir, keystore.as_ref(), link, email, name)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        };
    }

    // Check secwet status
    match Secwet::status(&data_dir) {
        Ok(SecwetStatus::Uninitialized) => {
            eprintln!("error: secwet not initialized on this device");
            return ExitCode::from(2);
        }
        Err(_) => {
            eprintln!("error: secwet is locked or storage damaged");
            return ExitCode::from(2);
        }
        _ => {}
    }

    // Resolve keystore
    let keystore = resolve_keystore(&data_dir);
    // Finish key deletions left by an interrupted remote wipe.
    let _ = Secwet::finish_pending_wipes(&data_dir, keystore.as_ref());

    // If command is pair join, allow joining before workspace is initialized locally
    if let Commands::Pair(commands::pair::PairArgs {
        command: commands::pair::PairSubcommand::Join { uri, name },
    }) = cli.command
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to build tokio runtime");
        let args = commands::pair::PairArgs {
            command: commands::pair::PairSubcommand::Join { uri, name },
        };
        return match rt.block_on(commands::pair::handle_pair(
            None,
            keystore.as_ref(),
            args,
        )) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e}");
                ExitCode::from(1)
            }
        };
    }

    // Unlock secwet
    let mut secwet = match Secwet::unlock(&data_dir, &*keystore) {
        Ok(v) => v,
        Err(Error::Locked | Error::NotInitialized | Error::KeyStore) => {
            eprintln!("error: secwet is locked");
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("error: failed to unlock secwet: {e}");
            return ExitCode::from(1);
        }
    };

    let exit_code = match cli.command {
        Commands::Status(args) => {
            if let Err(e) = commands::status::execute_status(&secwet, args.json) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::List => {
            let (item, env) = match resolve_item_and_env(
                &secwet,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
                false,
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            if let Err(e) = commands::list::execute_list(&secwet, item.id, env_id) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Get(args) => {
            let (item, env) = match resolve_item_and_env(
                &secwet,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
                false,
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            if let Err(e) = commands::get::execute_get(&secwet, item.id, env_id, &args.name) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Run(args) => {
            let (item, env) = match resolve_item_and_env(
                &secwet,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
                false,
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            match commands::run::execute_run(&secwet, item.id, env_id, &args.command) {
                Ok(child_exit_code) => {
                    secwet.lock();
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
                &secwet,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
                true,
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            let env_name = env.as_ref().map(|e| e.name.as_str());
            if let Err(e) = commands::set::execute_set(
                &mut secwet,
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
                &secwet,
                cli.item.as_deref(),
                cli.env.as_deref(),
                config.as_ref(),
                false,
            ) {
                Ok(pair) => pair,
                Err(code) => return code,
            };
            let env_id = env.as_ref().map(|e| e.id);
            let env_name = env.as_ref().map(|e| e.name.as_str());
            if let Err(e) = commands::import::execute_import(
                &mut secwet,
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
            let is_secwet = args
                .out
                .as_ref()
                .and_then(|p| p.extension())
                .and_then(|ext| ext.to_str())
                .map(|ext| ext.eq_ignore_ascii_case("secwet"))
                .unwrap_or(false);

            if is_secwet {
                let out_file = args.out.as_ref().unwrap();
                use std::io::{IsTerminal, Write};
                eprint!("Enter recovery key: ");
                let _ = std::io::stderr().flush();
                let raw_key = if std::io::stdin().is_terminal() {
                    rpassword::read_password()
                } else {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line).map(|_| line)
                };
                let raw_key = match raw_key {
                    Ok(k) => k,
                    Err(e) => {
                        eprintln!("error: failed to read recovery key: {e}");
                        return ExitCode::from(1);
                    }
                };
                let recovery_key_str = raw_key.trim();
                if recovery_key_str.is_empty() {
                    eprintln!("error: recovery key cannot be empty");
                    return ExitCode::from(1);
                }
                let recovery_secret = secrecy::SecretString::from(recovery_key_str.to_string());
                match secwet.export_encrypted(&recovery_secret, out_file) {
                    Ok(summary) => {
                        eprintln!(
                            "Exported {} secrets across {} items to {}",
                            summary.secrets_count,
                            summary.items_count,
                            out_file.display()
                        );
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        ExitCode::from(1)
                    }
                }
            } else {
                let (item, env) = match resolve_item_and_env(
                    &secwet,
                    cli.item.as_deref(),
                    cli.env.as_deref(),
                    config.as_ref(),
                    false,
                ) {
                    Ok(pair) => pair,
                    Err(code) => return code,
                };

                let format_lower = args.format.to_ascii_lowercase();
                if format_lower != "dotenv" && format_lower != "json" {
                    eprintln!(
                        "error: unsupported export format '{}': must be 'dotenv' or 'json'",
                        args.format
                    );
                    return ExitCode::from(1);
                }

                if !args.plaintext {
                    eprintln!("error: exporting plaintext secrets requires the explicit --plaintext flag");
                    return ExitCode::from(1);
                }

                eprintln!("warning: exporting unencrypted plaintext secrets");
                let env_id = env.as_ref().map(|e| e.id);
                if let Err(e) = commands::export::execute_export(
                    &secwet,
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
        }
        Commands::Space(commands::space::SpaceArgs {
            command: commands::space::SpaceSubcommands::Share(share),
        }) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime");
            if let Err(e) = rt.block_on(commands::collab::execute_space_share(&mut secwet, keystore.as_ref(), share)) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Space(args) => {
            if let Err(e) = commands::space::execute(&mut secwet, args) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Group(args) => {
            if let Err(e) = commands::group::execute_group(&mut secwet, args) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Item(args) => {
            if let Err(e) = commands::item::execute_item(&mut secwet, args) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Env(args) => {
            if let Err(e) = commands::env::execute_env(
                &mut secwet,
                args,
                config.as_ref(),
                cli.item.as_deref(),
            ) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Secret(args) => {
            if let Err(e) = commands::secret::execute_secret(
                &mut secwet,
                args,
                config.as_ref(),
                cli.item.as_deref(),
                cli.env.as_deref(),
            ) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Note(args) => {
            if let Err(e) = commands::note::execute_note(
                &mut secwet,
                args,
                config.as_ref(),
                cli.item.as_deref(),
                cli.env.as_deref(),
            ) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::File(args) => {
            if let Err(e) = commands::file::execute_file(
                &mut secwet,
                args,
                config.as_ref(),
                cli.item.as_deref(),
                cli.env.as_deref(),
            ) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Session(args) => {
            if let Err(e) = commands::session::execute_session(&secwet, args) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Tree(args) => {
            if let Err(e) = commands::tree::execute_tree(&secwet, args) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Init(args) => {
            if let Err(e) = commands::init::execute_init(&secwet, args, config.as_ref()) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Device(args) => {
            if let Err(e) = commands::device::handle_device(&mut secwet, args) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Pair(args) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime");
            if let Err(e) = rt.block_on(commands::pair::handle_pair(
                Some(&mut secwet),
                keystore.as_ref(),
                args,
            )) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Sync(args) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime");
            if let Err(e) = rt.block_on(commands::sync::run_sync(&mut secwet, keystore.as_ref(), args)) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Key(args) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime");
            if let Err(e) = rt.block_on(commands::collab::execute_key(&mut secwet, keystore.as_ref(), args)) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Commands::Member(args) => {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to build tokio runtime");
            if let Err(e) = rt.block_on(commands::collab::execute_member(&mut secwet, keystore.as_ref(), args)) {
                eprintln!("error: {e}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
    };

    secwet.lock();
    exit_code
}
