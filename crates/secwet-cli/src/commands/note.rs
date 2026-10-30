//! Note management commands for secwet-cli.

use crate::config::SecwetConfig;
use crate::resolver::resolve_item_and_env;
use clap::{Args, Subcommand};
use secwet_core::model::NoteMetaView;
use secwet_core::{Error, Result, Secwet};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct NoteArgs {
    #[command(subcommand)]
    pub command: NoteSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum NoteSubcommands {
    /// List notes for an item
    List(NoteListArgs),
    /// View full note content
    Get(NoteGetArgs),
    /// Create a new note
    Create(NoteCreateArgs),
    /// Update a note
    Update(NoteUpdateArgs),
    /// Delete a note
    Delete(NoteDeleteArgs),
}

#[derive(Args, Debug)]
pub struct NoteListArgs {
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
pub struct NoteGetArgs {
    /// Note title or UUID
    pub target: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Print raw note content only (no title header)
    #[arg(long)]
    pub raw: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct NoteCreateArgs {
    /// Note title
    pub title: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// Note content string
    #[arg(long)]
    pub content: Option<String>,

    /// Read note content from a file
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct NoteUpdateArgs {
    /// Note title or UUID
    pub target: String,

    /// Target item name or UUID
    #[arg(short = 'i', long = "item", visible_alias = "project")]
    pub item: Option<String>,

    /// Target environment name or UUID
    #[arg(short = 'e', long = "env")]
    pub env: Option<String>,

    /// New note title
    #[arg(long)]
    pub title: Option<String>,

    /// New note content string
    #[arg(long)]
    pub content: Option<String>,

    /// Read new note content from a file
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct NoteDeleteArgs {
    /// Note title or UUID
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

fn resolve_note_meta(
    secwet: &Secwet,
    item_id: Uuid,
    env_id: Option<Uuid>,
    target: &str,
) -> Result<NoteMetaView> {
    let notes = secwet.list_notes(item_id, env_id)?;
    if let Ok(id) = Uuid::parse_str(target) {
        if let Some(n) = notes.into_iter().find(|n| n.id == id) {
            return Ok(n);
        }
    } else if let Some(n) = notes.into_iter().find(|n| n.title.eq_ignore_ascii_case(target)) {
        return Ok(n);
    }
    Err(Error::NotFound)
}

pub fn execute_note(
    secwet: &mut Secwet,
    args: NoteArgs,
    config: Option<&SecwetConfig>,
    global_item: Option<&str>,
    global_env: Option<&str>,
) -> Result<()> {
    match args.command {
        NoteSubcommands::List(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);
            let notes = secwet.list_notes(item.id, env_id)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&notes).map_err(|_| Error::Storage)?);
            } else if notes.is_empty() {
                println!("No notes found.");
            } else {
                println!("{:<38} {:<28} {:<12}", "ID", "TITLE", "UPDATED");
                println!("{}", "-".repeat(82));
                for n in notes {
                    println!(
                        "{:<38} {:<28} {:<12}",
                        n.id,
                        n.title,
                        crate::resolver::format_timestamp(n.updated_at)
                    );
                }
            }
            Ok(())
        }
        NoteSubcommands::Get(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);
            let meta = resolve_note_meta(secwet, item.id, env_id, &sub.target)?;
            let note = secwet.get_note(meta.id)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&note).map_err(|_| Error::Storage)?);
            } else if sub.raw {
                print!("{}", note.content);
            } else {
                println!("# {}\n", note.title);
                println!("{}", note.content);
            }
            Ok(())
        }
        NoteSubcommands::Create(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);

            let content = if let Some(path) = sub.file {
                std::fs::read_to_string(&path).map_err(|_| Error::Storage)?
            } else {
                sub.content.unwrap_or_default()
            };

            let note = secwet.create_note(item.id, env_id, &sub.title, &content)?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&note).map_err(|_| Error::Storage)?);
            } else {
                println!("Created note '{}' ({})", note.title, note.id);
            }
            Ok(())
        }
        NoteSubcommands::Update(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);
            let meta = resolve_note_meta(secwet, item.id, env_id, &sub.target)?;

            let new_content = if let Some(path) = sub.file {
                Some(std::fs::read_to_string(&path).map_err(|_| Error::Storage)?)
            } else {
                sub.content
            };

            let note = secwet.update_note(
                meta.id,
                sub.title.as_deref(),
                new_content.as_deref(),
            )?;

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&note).map_err(|_| Error::Storage)?);
            } else {
                println!("Updated note '{}' ({})", note.title, note.id);
            }
            Ok(())
        }
        NoteSubcommands::Delete(sub) => {
            let item_target = sub.item.as_deref().or(global_item);
            let env_target = sub.env.as_deref().or(global_env);
            let (item, env) = resolve_item_and_env(secwet, item_target, env_target, config, true)
                .map_err(|_| Error::NotFound)?;
            let env_id = env.as_ref().map(|e| e.id);
            let meta = resolve_note_meta(secwet, item.id, env_id, &sub.target)?;
            secwet.delete_note(meta.id)?;

            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": meta.id.to_string(),
                        "title": meta.title,
                        "status": "deleted"
                    })
                );
            } else {
                println!("Deleted note '{}' ({})", meta.title, meta.id);
            }
            Ok(())
        }
    }
}

