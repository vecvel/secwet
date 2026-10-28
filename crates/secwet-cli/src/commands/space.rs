//! Space management commands for secwet-cli.

use clap::{Args, Subcommand};
use secwet_core::model::SpaceView;
use secwet_core::{Error, Result, Secwet};
use uuid::Uuid;

#[derive(Args, Debug)]
pub struct SpaceArgs {
    #[command(subcommand)]
    pub command: SpaceSubcommands,
}

#[derive(Subcommand, Debug)]
pub enum SpaceSubcommands {
    /// List all spaces
    List(SpaceListArgs),
    /// Create a new space
    Create(SpaceCreateArgs),
    /// Rename a space and optionally update its icon
    Rename(SpaceRenameArgs),
    /// Delete a space (groups are safely reassigned to Personal space)
    Delete(SpaceDeleteArgs),
    /// Reorder spaces
    Reorder(SpaceReorderArgs),
    /// Share a space with a collaborator by email (prints a one-time invite link)
    Share(crate::commands::collab::SpaceShareArgs),
}

#[derive(Args, Debug)]
pub struct SpaceListArgs {
    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SpaceCreateArgs {
    /// The name of the space
    pub name: String,

    /// Optional icon name (folder, briefcase, user, globe, etc.)
    #[arg(long)]
    pub icon: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SpaceRenameArgs {
    /// Target space name or UUID
    pub target: String,

    /// New space name
    pub new_name: String,

    /// Optional icon name
    #[arg(long)]
    pub icon: Option<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SpaceDeleteArgs {
    /// Target space name or UUID
    pub target: String,

    /// Force delete without prompt
    #[arg(long)]
    pub force: bool,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

#[derive(Args, Debug)]
pub struct SpaceReorderArgs {
    /// Ordered space names or UUIDs
    #[arg(required = true)]
    pub targets: Vec<String>,

    /// Output in JSON format
    #[arg(long)]
    pub json: bool,
}

pub fn resolve_space(secwet: &Secwet, target: &str) -> Result<SpaceView> {
    let spaces = secwet.list_spaces()?;
    if let Ok(id) = Uuid::parse_str(target) {
        if let Some(s) = spaces.into_iter().find(|s| s.id == id) {
            return Ok(s);
        }
    } else if let Some(s) = spaces.into_iter().find(|s| s.name.eq_ignore_ascii_case(target)) {
        return Ok(s);
    }
    Err(Error::NotFound)
}

pub fn execute(secwet: &mut Secwet, args: SpaceArgs) -> Result<()> {
    match args.command {
        // Needs the relay; dispatched from main before this function.
        SpaceSubcommands::Share(_) => return Err(Error::Unimplemented("space share without a relay")),
        SpaceSubcommands::List(cmd_args) => {
            let spaces = secwet.list_spaces()?;
            if cmd_args.json {
                let json = serde_json::to_string_pretty(&spaces).map_err(|_| Error::Storage)?;
                println!("{json}");
            } else if spaces.is_empty() {
                println!("No spaces found.");
            } else {
                println!("{:<38} {:<20} {:<10} {:<10} {:<10}", "ID", "NAME", "DEFAULT", "GROUPS", "ICON");
                println!("{:-<38} {:-<20} {:-<10} {:-<10} {:-<10}", "", "", "", "", "");
                for s in spaces {
                    let is_def = if s.is_default { "yes" } else { "no" };
                    let icon_str = s.icon.unwrap_or_else(|| "-".to_string());
                    println!("{:<38} {:<20} {:<10} {:<10} {:<10}", s.id, s.name, is_def, s.groups_count, icon_str);
                }
            }
        }
        SpaceSubcommands::Create(cmd_args) => {
            let space = secwet.create_space(&cmd_args.name, cmd_args.icon)?;
            if cmd_args.json {
                let json = serde_json::to_string_pretty(&space).map_err(|_| Error::Storage)?;
                println!("{json}");
            } else {
                println!("Created space '{}' ({})", space.name, space.id);
            }
        }
        SpaceSubcommands::Rename(cmd_args) => {
            let existing = resolve_space(secwet, &cmd_args.target)?;
            let space = secwet.rename_space(existing.id, &cmd_args.new_name, cmd_args.icon)?;
            if cmd_args.json {
                let json = serde_json::to_string_pretty(&space).map_err(|_| Error::Storage)?;
                println!("{json}");
            } else {
                println!("Renamed space to '{}' ({})", space.name, space.id);
            }
        }
        SpaceSubcommands::Delete(cmd_args) => {
            let space = resolve_space(secwet, &cmd_args.target)?;
            secwet.delete_space(space.id)?;
            if cmd_args.json {
                println!("{}", serde_json::json!({ "deleted": space.id, "name": space.name }));
            } else {
                println!("Deleted space '{}' (any groups were reassigned to Personal)", space.name);
            }
        }
        SpaceSubcommands::Reorder(cmd_args) => {
            let mut ids = Vec::new();
            for t in cmd_args.targets {
                let s = resolve_space(secwet, &t)?;
                ids.push(s.id);
            }
            secwet.reorder_spaces(&ids)?;
            if cmd_args.json {
                println!("{}", serde_json::json!({ "reordered": ids }));
            } else {
                println!("Reordered spaces successfully.");
            }
        }
    }
    Ok(())
}

