//! Group (Section / Label) management commands for secwet-cli.

use clap::{Args, Subcommand};
use secwet_core::model::LabelView;
use secwet_core::{Error, Result, Secwet};
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct GroupArgs {
    #[command(subcommand)]
    pub command: GroupSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum GroupSubcommands {
    /// List all groups
    List(GroupListArgs),
    /// Create a new group
    Create(GroupCreateArgs),
    /// Rename a group and optionally update its icon
    Rename(GroupRenameArgs),
    /// Delete a group
    Delete(GroupDeleteArgs),
    /// Move a group to another space
    Move(GroupMoveArgs),
    /// Reorder groups
    Reorder(GroupReorderArgs),
}

#[derive(Args, Debug)]
pub struct GroupListArgs {
    /// Filter groups by space name or UUID
    #[arg(long)]
    pub space: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GroupCreateArgs {
    /// The name of the group
    pub name: String,

    /// Parent space name or UUID (defaults to active or Personal space)
    #[arg(long)]
    pub space: Option<String>,

    /// Optional icon name (folder, server, lock, cloud, etc.)
    #[arg(long)]
    pub icon: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GroupRenameArgs {
    /// Target group name or UUID
    pub target: String,

    /// New group name
    pub new_name: String,

    /// Optional icon name
    #[arg(long)]
    pub icon: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GroupDeleteArgs {
    /// Target group name or UUID
    pub target: String,

    /// Force delete without prompt
    #[arg(long)]
    pub force: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GroupMoveArgs {
    /// Target group name or UUID
    pub target: String,

    /// Target space name or UUID to move the group to
    #[arg(long)]
    pub to: String,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct GroupReorderArgs {
    /// Ordered group names or UUIDs
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub fn resolve_group(secwet: &Secwet, target: &str) -> Result<LabelView> {
    let labels = secwet.list_labels()?;
    if let Ok(id) = Uuid::parse_str(target) {
        if let Some(l) = labels.into_iter().find(|l| l.id == id) {
            return Ok(l);
        }
    } else if let Some(l) = labels.into_iter().find(|l| l.name.eq_ignore_ascii_case(target)) {
        return Ok(l);
    }
    Err(Error::NotFound)
}

pub fn execute_group(secwet: &mut Secwet, args: GroupArgs) -> Result<()> {
    match args.command {
        GroupSubcommands::List(sub) => {
            let spaces = secwet.list_spaces().unwrap_or_default();
            let labels = if let Some(ref sp_target) = sub.space {
                let space = crate::commands::space::resolve_space(secwet, sp_target)?;
                secwet.list_labels_by_space(space.id)?
            } else {
                secwet.list_labels()?
            };

            if sub.json {
                println!("{}", serde_json::to_string_pretty(&labels).map_err(|_| Error::Storage)?);
            } else if labels.is_empty() {
                println!("No groups found.");
            } else {
                println!("{:<38} {:<24} {:<16} {:<10} {:<6}", "ID", "NAME", "SPACE", "ICON", "ITEMS");
                println!("{}", "-".repeat(98));
                for l in labels {
                    let space_name = l.space_id.and_then(|sid| spaces.iter().find(|s| s.id == sid)).map(|s| s.name.as_str()).unwrap_or("-");
                    println!(
                        "{:<38} {:<24} {:<16} {:<10} {:<6}",
                        l.id,
                        l.name,
                        space_name,
                        l.icon.as_deref().unwrap_or("-"),
                        l.items_count
                    );
                }
            }
            Ok(())
        }
        GroupSubcommands::Create(sub) => {
            let space_id = if let Some(ref sp_target) = sub.space {
                let space = crate::commands::space::resolve_space(secwet, sp_target)?;
                Some(space.id)
            } else {
                None
            };

            let created = secwet.create_label_in_space(&sub.name, sub.icon, space_id)?;
            if sub.json {
                println!("{}", serde_json::to_string_pretty(&created).map_err(|_| Error::Storage)?);
            } else {
                println!("Created group '{}' ({})", created.name, created.id);
            }
            Ok(())
        }
        GroupSubcommands::Rename(sub) => {
            let group = resolve_group(secwet, &sub.target)?;
            let icon = sub.icon.or(group.icon);
            secwet.update_label(group.id, &sub.new_name, icon)?;
            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": group.id.to_string(),
                        "name": sub.new_name,
                        "status": "renamed"
                    })
                );
            } else {
                println!("Renamed group '{}' -> '{}'", group.name, sub.new_name);
            }
            Ok(())
        }
        GroupSubcommands::Delete(sub) => {
            let group = resolve_group(secwet, &sub.target)?;
            secwet.delete_label(group.id)?;
            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": group.id.to_string(),
                        "name": group.name,
                        "status": "deleted"
                    })
                );
            } else {
                println!("Deleted group '{}' ({})", group.name, group.id);
            }
            Ok(())
        }
        GroupSubcommands::Move(sub) => {
            let group = resolve_group(secwet, &sub.target)?;
            let target_space = crate::commands::space::resolve_space(secwet, &sub.to)?;
            secwet.move_label_to_space(group.id, target_space.id)?;
            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "id": group.id.to_string(),
                        "name": group.name,
                        "space_id": target_space.id.to_string(),
                        "space_name": target_space.name,
                        "status": "moved"
                    })
                );
            } else {
                println!("Moved group '{}' to space '{}'", group.name, target_space.name);
            }
            Ok(())
        }
        GroupSubcommands::Reorder(sub) => {
            let mut ordered_ids = Vec::with_capacity(sub.targets.len());
            for t in &sub.targets {
                let g = resolve_group(secwet, t)?;
                ordered_ids.push(g.id);
            }
            secwet.reorder_labels(&ordered_ids)?;
            if sub.json {
                println!(
                    "{}",
                    serde_json::json!({
                        "ordered_ids": ordered_ids.iter().map(|id| id.to_string()).collect::<Vec<_>>(),
                        "status": "reordered"
                    })
                );
            } else {
                println!("Successfully reordered {} groups.", ordered_ids.len());
            }
            Ok(())
        }
    }
}
