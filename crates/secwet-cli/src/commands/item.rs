//! Item (Entry / Project) management commands for secwet-cli.

use super::group::resolve_group;
use clap::{Args, Subcommand};
use secwet_core::model::ItemView;
use secwet_core::{Error, Result, Secwet};
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct ItemArgs {
    #[command(subcommand)]
    pub command: ItemSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum ItemSubcommands {
    /// List items (optionally filtered by group)
    List(ItemListArgs),
    /// Get details of a single item
    Get(ItemGetArgs),
    /// Create a new item under a group
    Create(ItemCreateArgs),
    /// Update an item's name or description
    Update(ItemUpdateArgs),
    /// Delete an item and all its child secrets/notes/files
    Delete(ItemDeleteArgs),
}

#[derive(Args, Debug)]
pub struct ItemListArgs {
    /// Filter by group name or UUID
    #[arg(short = 'g', long = "group", visible_alias = "label")]
    pub group: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ItemGetArgs {
    /// Item name or UUID
    pub target: String,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ItemCreateArgs {
    /// Item name
    pub name: String,

    /// Target group name or UUID (defaults to first group if omitted)
    #[arg(short = 'g', long = "group", visible_alias = "label")]
    pub group: Option<String>,

    /// Optional description
    #[arg(short = 'd', long = "desc")]
    pub desc: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ItemUpdateArgs {
    /// Target item name or UUID
    pub target: String,

    /// New item name
    #[arg(long)]
    pub name: Option<String>,

    /// New description
    #[arg(short = 'd', long = "desc")]
    pub desc: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct ItemDeleteArgs {
    /// Target item name or UUID
    pub target: String,

    /// Force delete without prompt
    #[arg(long)]
    pub force: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub fn get_all_items(secwet: &Secwet) -> Result<Vec<ItemView>> {
    let labels = secwet.list_labels()?;
    let mut all = Vec::new();
    for l in labels {
        if let Ok(items) = secwet.list_items(l.id) {
            all.extend(items);
        }
    }
    Ok(all)
}

pub fn resolve_item_view(secwet: &Secwet, target: &str) -> Result<ItemView> {
    let items = get_all_items(secwet)?;
    if let Ok(id) = Uuid::parse_str(target) {
        if let Some(i) = items.into_iter().find(|i| i.id == id) {
            return Ok(i);
        }
    } else if let Some(i) = items.into_iter().find(|i| i.name.eq_ignore_ascii_case(target)) {
        return Ok(i);
    }
    Err(Error::NotFound)
}

pub fn execute_item(secwet: &mut Secwet, args: ItemArgs) -> Result<()> {
    match args.command {
        ItemSubcommands::List(sub) => {
            let items = if let Some(ref group_target) = sub.group {
                let group = resolve_group(secwet, group_target)?;
                secwet.list_items(group.id)?
            } else {
                get_all_items(secwet)?
            };

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&items).map_err(|_| Error::Storage)?);
            } else if items.is_empty() {
                println!("No items found.");
            } else {
                println!("{:<38} {:<24} {:<6} {:<8} {:<6}", "ID", "NAME", "ENVS", "SECRETS", "NOTES");
                println!("{}", "-".repeat(88));
                for it in items {
                    println!(
                        "{:<38} {:<24} {:<6} {:<8} {:<6}",
                        it.id, it.name, it.environments_count, it.secrets_count, it.notes_count
                    );
                }
            }
            Ok(())
        }
        ItemSubcommands::Get(sub) => {
            let item = resolve_item_view(secwet, &sub.target)?;
            let envs = secwet.list_environments(item.id).unwrap_or_default();
            if sub.json {
                let json_val = serde_json::json!({
                    "id": item.id.to_string(),
                    "group_id": item.label_id.to_string(),
                    "name": item.name,
                    "description": item.description,
                    "environments": envs,
                    "secrets_count": item.secrets_count,
                    "notes_count": item.notes_count,
                    "files_count": item.files_count,
                });
                println!("{}", serde_json::to_string_pretty(&json_val).map_err(|_| Error::Storage)?);
            } else {
                println!("Item: {} ({})", item.name, item.id);
                if let Some(d) = &item.description {
                    println!("Description: {d}");
                }
                println!("Environments ({}):", envs.len());
                for e in envs {
                    println!("  - {} (secrets: {})", e.name, e.secret_count);
                }
                println!("Secrets: {} | Notes: {} | Files: {}", item.secrets_count, item.notes_count, item.files_count);
            }
            Ok(())
        }
        ItemSubcommands::Create(sub) => {
            let group = if let Some(ref g_target) = sub.group {
                resolve_group(secwet, g_target)?
            } else {
                let labels = secwet.list_labels()?;
                labels.into_iter().next().ok_or(Error::NotFound)?
            };

            let created = secwet.create_item(group.id, &sub.name, sub.desc)?;
            if sub.json {
                println!("{}", serde_json::to_string_pretty(&created).map_err(|_| Error::Storage)?);
            } else {
                println!("Created item '{}' ({}) in group '{}'", created.name, created.id, group.name);
            }
            Ok(())
        }
        ItemSubcommands::Update(sub) => {
            let item = resolve_item_view(secwet, &sub.target)?;
            let new_name = sub.name.as_deref().unwrap_or(&item.name);
            let new_desc = sub.desc.or(item.description);
            secwet.rename_item(item.id, new_name, new_desc.clone())?;
            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": item.id.to_string(),
                        "name": new_name,
                        "description": new_desc,
                        "status": "updated"
                    })
                );
            } else {
                println!("Updated item '{}' ({})", new_name, item.id);
            }
            Ok(())
        }
        ItemSubcommands::Delete(sub) => {
            let item = resolve_item_view(secwet, &sub.target)?;
            secwet.delete_item(item.id)?;
            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": item.id.to_string(),
                        "name": item.name,
                        "status": "deleted"
                    })
                );
            } else {
                println!("Deleted item '{}' ({})", item.name, item.id);
            }
            Ok(())
        }
    }
}
