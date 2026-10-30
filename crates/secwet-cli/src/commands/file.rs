//! File (Asset) management commands for secwet-cli.

use crate::config::SecwetConfig;
use crate::resolver::resolve_item_and_env;
use clap::{Args, Subcommand};
use secwet_core::model::FileMetaView;
use secwet_core::{Error, Result, Secwet};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct FileArgs {
    #[command(subcommand)]
    pub command: FileSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum FileSubcommands {
    /// List files attached to an item
    List(FileListArgs),
    /// Upload and encrypt a local file
    Upload(FileUploadArgs),
    /// Download and decrypt a file
    Download(FileDownloadArgs),
    /// Delete an encrypted file
    Delete(FileDeleteArgs),
}

#[derive(Args, Debug)]
pub struct FileListArgs {
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
pub struct FileUploadArgs {
    /// Path to local file
    pub path: PathBuf,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Custom file name inside secwet (defaults to filename on disk)
    #[arg(long)]
    pub name: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct FileDownloadArgs {
    /// File name or UUID
    pub target: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Output file destination (defaults to current directory with original name)
    #[arg(short = 'o', long = "out")]
    pub out: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct FileDeleteArgs {
    /// File name or UUID
    pub target: String,

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

fn resolve_file_meta(
    secwet: &Secwet,
    item_id: Uuid,
    env_id: Option<Uuid>,
    target: &str,
) -> Result<FileMetaView> {
    let files = secwet.list_files(item_id, env_id)?;
    if let Ok(id) = Uuid::parse_str(target) {
        if let Some(f) = files.into_iter().find(|f| f.id == id) {
            return Ok(f);
        }
    } else if let Some(f) = files.into_iter().find(|f| f.name.eq_ignore_ascii_case(target)) {
        return Ok(f);
    }
    Err(Error::NotFound)
}

pub fn execute_file(
    secwet: &mut Secwet,
    args: FileArgs,
    config: Option<&SecwetConfig>,
    global_item: Option<&str>,
    global_env: Option<&str>,
) -> Result<()> {
    match args.command {
        FileSubcommands::List(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);
            let files = secwet.list_files(item.id, env_id)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&files).map_err(|_| Error::Storage)?);
            } else if files.is_empty() {
                println!("No files found.");
            } else {
                println!("{:<38} {:<28} {:<10} {:<12}", "ID", "NAME", "SIZE", "UPDATED");
                println!("{}", "-".repeat(92));
                for f in files {
                    println!(
                        "{:<38} {:<28} {:<10} {:<12}",
                        f.id,
                        f.name,
                        format_bytes(f.size_bytes),
                        crate::resolver::format_timestamp(f.updated_at)
                    );
                }
            }
            Ok(())
        }
        FileSubcommands::Upload(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);

            let data = std::fs::read(&sub.path).map_err(|_| Error::Storage)?;
            let file_name = sub.name.unwrap_or_else(|| {
                sub.path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file")
                    .to_string()
            });

            let mime = sub.path.extension().and_then(|ext| ext.to_str()).map(|ext| {
                match ext.to_ascii_lowercase().as_str() {
                    "txt" | "md" => "text/plain",
                    "json" => "application/json",
                    "png" => "image/png",
                    "jpg" | "jpeg" => "image/jpeg",
                    "pdf" => "application/pdf",
                    "pem" | "crt" | "key" => "application/x-pem-file",
                    _ => "application/octet-stream",
                }
            });

            let meta = secwet.upload_asset(item.id, env_id, &file_name, &data, mime)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&meta).map_err(|_| Error::Storage)?);
            } else {
                println!(
                    "Uploaded file '{}' ({}, {})",
                    meta.name,
                    meta.id,
                    format_bytes(meta.size_bytes)
                );
            }
            Ok(())
        }
        FileSubcommands::Download(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);
            let meta = resolve_file_meta(secwet, item.id, env_id, &sub.target)?;

            let (file_meta, data) = secwet.download_file(meta.id)?;
            let destination = sub.out.unwrap_or_else(|| PathBuf::from(&file_meta.name));

            std::fs::write(&destination, data).map_err(|_| Error::Storage)?;
            println!("Downloaded '{}' to {}", file_meta.name, destination.display());
            Ok(())
        }
        FileSubcommands::Delete(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);
            let meta = resolve_file_meta(secwet, item.id, env_id, &sub.target)?;
            secwet.delete_file(meta.id)?;

            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": meta.id.to_string(),
                        "name": meta.name,
                        "status": "deleted"
                    })
                );
            } else {
                println!("Deleted file '{}' ({})", meta.name, meta.id);
            }
            Ok(())
        }
    }
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}
