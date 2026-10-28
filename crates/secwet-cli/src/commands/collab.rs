//! CLI commands for key rotation (F16) and collaboration (F19):
//! `secwet key`, `secwet member`, `secwet space share`.

use clap::{Args, Subcommand};
use secwet_core::keys::KeyStore;
use secwet_core::{Error, RelayClient, Result, Secwet};
use secwet_proto::{TreeNode, TreeRole};
use uuid::Uuid;

fn client(secwet: &Secwet) -> Result<RelayClient> {
    Ok(RelayClient::new(secwet.relay_url()?, secwet.device_id().to_string()))
}

/// Parses `kind:id=role` (or `workspace=role`) into a grant.
pub fn parse_grant(spec: &str) -> Result<(TreeNode, TreeRole)> {
    let invalid = || Error::Invalid {
        field: "grant",
        message: format!(
            "'{spec}' is not a grant; use workspace=ROLE or KIND:ID=ROLE where KIND is space, group, item, general or env and ROLE is admin, editor, viewer or no_access"
        ),
    };
    let (node, role) = spec.rsplit_once('=').ok_or_else(invalid)?;
    let role = TreeRole::parse(role).ok_or_else(invalid)?;
    let node = if node.trim() == "workspace" {
        TreeNode::Workspace
    } else {
        let (kind, id) = node.split_once(':').ok_or_else(invalid)?;
        let id = Uuid::parse_str(id.trim()).map_err(|_| invalid())?;
        TreeNode::from_parts(kind.trim(), Some(id)).ok_or_else(invalid)?
    };
    Ok((node, role))
}

fn grants_text(secwet: &Secwet, grants: &[secwet_proto::MemberGrant]) -> String {
    grants
        .iter()
        .map(|g| format!("{} ({})", secwet.node_label(g.node), g.role.as_str()))
        .collect::<Vec<_>>()
        .join(", ")
}

// ============================================================================
// secwet key
// ============================================================================

#[derive(Args, Debug)]
pub struct KeyArgs {
    #[command(subcommand)]
    pub command: KeySubcommand,
}

#[derive(Subcommand, Debug)]
pub enum KeySubcommand {
    /// Show the current encryption key version and whether rotation is recommended
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Rotate the workspace encryption key for all active devices
    Rotate {
        #[arg(long)]
        json: bool,
    },
}

pub async fn execute_key(secwet: &mut Secwet, keystore: &dyn KeyStore, args: KeyArgs) -> Result<()> {
    match args.command {
        KeySubcommand::Status { json } => {
            let st = secwet.key_status()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&st).unwrap_or_default());
            } else {
                println!("Key version: {}", st.epoch);
                if let Some(at) = st.rotated_at {
                    println!("Last rotated: {}", crate::commands::collab::format_ms(at));
                }
                if st.rotation_recommended {
                    println!(
                        "Rotation recommended: {}",
                        st.pending_reason.unwrap_or_else(|| "a device was revoked.".into())
                    );
                }
            }
            Ok(())
        }
        KeySubcommand::Rotate { json } => {
            let c = client(secwet)?;
            let report = secwet.rotate_master_key(&c, keystore).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap_or_default());
            } else if report.adopted_from_conflict {
                println!(
                    "Another device rotated first. This device switched to key version {} and re-encrypted {} item(s).",
                    report.epoch, report.resealed
                );
            } else {
                println!(
                    "Rotated to key version {} for {} device(s). Re-encrypted {} item(s) on this device.",
                    report.epoch, report.recipients, report.resealed
                );
            }
            Ok(())
        }
    }
}

pub fn format_ms(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|d| d.format("%Y-%m-%d %H:%M UTC").to_string())
        .unwrap_or_else(|| ms.to_string())
}

// ============================================================================
// secwet member
// ============================================================================

#[derive(Args, Debug)]
pub struct MemberArgs {
    #[command(subcommand)]
    pub command: MemberSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum MemberSubcommand {
    /// List collaborators, their access and devices
    #[command(visible_alias = "ls")]
    List {
        #[arg(long)]
        json: bool,
    },
    /// Invite a collaborator by email and print the one-time invite link
    Invite {
        email: String,
        /// Access to grant, repeatable: workspace=ROLE or KIND:ID=ROLE
        /// (KIND: space, group, item, general, env; ROLE: admin, editor, viewer, no_access)
        #[arg(long = "grant", required = true)]
        grants: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Replace a collaborator's access (a downgrade rotates the branch keys)
    Role {
        member_id: Uuid,
        #[arg(long = "grant", required = true)]
        grants: Vec<String>,
    },
    /// Remove a collaborator, revoke their devices and rotate branch keys
    Remove {
        member_id: Uuid,
        /// Also make their devices erase the shared data
        #[arg(long)]
        wipe: bool,
    },
    /// Withdraw a pending invitation
    Uninvite { invitation_id: Uuid },
    /// Join a shared workspace with an invite link (on a device with no workspace yet)
    Join {
        link: String,
        #[arg(long)]
        email: String,
        #[arg(long, default_value = "CLI")]
        name: String,
    },
}

pub async fn execute_member(secwet: &mut Secwet, keystore: &dyn KeyStore, args: MemberArgs) -> Result<()> {
    let c = client(secwet)?;
    match args.command {
        MemberSubcommand::List { json } => {
            let members = secwet.members_list(&c).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&members).unwrap_or_default());
                return Ok(());
            }
            if members.is_empty() {
                println!("No collaborators yet.");
                return Ok(());
            }
            for m in members {
                println!(
                    "{}  {}  {}  devices: {}",
                    m.member_id,
                    m.email.as_deref().unwrap_or("Invited member"),
                    m.status,
                    m.devices.iter().filter(|d| !d.revoked).count()
                );
                println!("    access: {}", grants_text(secwet, &m.grants));
            }
            Ok(())
        }
        MemberSubcommand::Invite { email, grants, json } => {
            let grants = grants.iter().map(|g| parse_grant(g)).collect::<Result<Vec<_>>>()?;
            let r = secwet.invite_member(&c, keystore, &email, &grants).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&r).unwrap_or_default());
            } else {
                println!("Invite link for {email} (works once, expires {}):", format_ms(r.expires_at));
                println!("{}", r.link);
            }
            Ok(())
        }
        MemberSubcommand::Role { member_id, grants } => {
            let grants = grants.iter().map(|g| parse_grant(g)).collect::<Result<Vec<_>>>()?;
            secwet.set_member_grants(&c, keystore, member_id, &grants).await?;
            println!("Access updated for {member_id}.");
            Ok(())
        }
        MemberSubcommand::Remove { member_id, wipe } => {
            secwet.remove_member(&c, keystore, member_id, wipe).await?;
            println!("Removed {member_id}. Shared keys were rotated so they can't read new changes.");
            Ok(())
        }
        MemberSubcommand::Uninvite { invitation_id } => {
            secwet.revoke_invitation(&c, invitation_id).await?;
            println!("Invitation {invitation_id} withdrawn.");
            Ok(())
        }
        MemberSubcommand::Join { .. } => Err(Error::AlreadyInitialized),
    }
}

/// `secwet member join` runs before any store exists on this device.
pub async fn execute_join(data_dir: &std::path::Path, keystore: &dyn KeyStore, link: &str, email: &str, name: &str) -> Result<()> {
    let mut secwet = Secwet::accept_invitation(data_dir, link, email, name, keystore).await?;
    println!("Joined. Waiting for the admin's device to share access; run `secwet sync` in a moment.");
    let c = client(&secwet)?;
    match secwet.sync_round(&c, keystore).await {
        Ok((_, pulled)) if pulled > 0 => println!("Received {pulled} change(s)."),
        _ => {}
    }
    secwet.lock();
    Ok(())
}

// ============================================================================
// secwet space share
// ============================================================================

#[derive(Args, Debug)]
pub struct SpaceShareArgs {
    /// Space id
    pub space_id: Uuid,
    /// Collaborator email
    #[arg(long)]
    pub email: String,
    /// Role on the whole space: admin, editor or viewer
    #[arg(long, default_value = "viewer")]
    pub role: String,
}

pub async fn execute_space_share(secwet: &mut Secwet, keystore: &dyn KeyStore, args: SpaceShareArgs) -> Result<()> {
    let role = TreeRole::parse(&args.role).ok_or(Error::Invalid {
        field: "role",
        message: "Role must be admin, editor or viewer.".into(),
    })?;
    let c = client(secwet)?;
    let r = secwet
        .invite_member(&c, keystore, &args.email, &[(TreeNode::Space(args.space_id), role)])
        .await?;
    println!("Space shared. Send this link to {} (works once):", args.email);
    println!("{}", r.link);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_specs_parse() {
        let id = Uuid::new_v4();
        assert_eq!(parse_grant("workspace=viewer").unwrap(), (TreeNode::Workspace, TreeRole::Viewer));
        assert_eq!(parse_grant(&format!("env:{id}=no_access")).unwrap(), (TreeNode::Environment(id), TreeRole::NoAccess));
        assert_eq!(parse_grant(&format!("general:{id}=editor")).unwrap(), (TreeNode::General(id), TreeRole::Editor));
        assert!(parse_grant("space:nope=admin").is_err());
        assert!(parse_grant(&format!("item:{id}=owner")).is_err());
    }
}
