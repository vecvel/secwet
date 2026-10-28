//! Relay Admin CLI commands for managing workspace entitlements and devices.

use chrono::{DateTime, Utc};
use clap::{Args, Subcommand};
use crate::sqlx::PgPool;
use uuid::Uuid;

use crate::db;

#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// Grant or update plan entitlements for a workspace
    Grant(AdminGrantArgs),

    /// Check entitlement and device status for a workspace
    Status(AdminStatusArgs),

    /// Revoke a device directly
    Revoke(AdminRevokeArgs),
}

#[derive(Debug, Args)]
pub struct AdminGrantArgs {
    /// Workspace UUID
    #[arg(short, long)]
    pub secwet: Option<Uuid>,

    /// Positional workspace UUID if --secwet flag is omitted
    pub secwet_pos: Option<Uuid>,

    /// Plan tier: "free" or "pro"
    #[arg(short, long, default_value = "pro")]
    pub plan: String,

    /// Maximum active devices allowed
    #[arg(short, long, default_value = "5")]
    pub devices: u32,

    /// Optional expiration timestamp (RFC 3339, e.g. 2027-01-01T00:00:00Z)
    #[arg(short, long)]
    pub until: Option<String>,
}

#[derive(Debug, Args)]
pub struct AdminStatusArgs {
    /// Workspace UUID
    pub secwet_id: Uuid,
}

#[derive(Debug, Args)]
pub struct AdminRevokeArgs {
    /// Workspace UUID
    pub secwet_id: Uuid,

    /// Device ID to revoke
    pub device_id: String,
}

pub async fn run_admin_command(pool: &PgPool, cmd: AdminCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        AdminCommand::Grant(args) => {
            let secwet_id = args
                .secwet
                .or(args.secwet_pos)
                .ok_or("Workspace UUID is required (use --secwet <UUID> or positional argument)")?;

            let expires_at = if let Some(until_str) = args.until {
                let dt = DateTime::parse_from_rfc3339(&until_str)
                    .map(|d| d.with_timezone(&Utc))
                    .or_else(|_| {
                        // Support YYYY-MM-DD
                        chrono::NaiveDate::parse_from_str(&until_str, "%Y-%m-%d").map(|d| {
                            d.and_hms_opt(0, 0, 0)
                                .unwrap()
                                .and_local_timezone(Utc)
                                .unwrap()
                        })
                    })
                    .map_err(|e| format!("Invalid date format for --until: {}", e))?;
                Some(dt)
            } else {
                None
            };

            let res = db::grant_entitlement(pool, secwet_id, &args.plan, args.devices, expires_at).await?;
            println!("Successfully granted entitlement for workspace {}:", secwet_id);
            println!("  Plan: {}", res.plan);
            println!("  Device limit: {}", res.device_limit);
            println!(
                "  Expires at: {}",
                res.expires_at.as_deref().unwrap_or("never")
            );
        }
        AdminCommand::Status(args) => {
            match db::get_entitlement(pool, args.secwet_id).await {
                Ok(ent) => {
                    let active_devices = db::count_active_devices(pool, args.secwet_id).await?;
                    println!("Workspace: {}", args.secwet_id);
                    println!("  Plan: {}", ent.plan);
                    println!("  Device limit: {}", ent.device_limit);
                    println!("  Active devices: {}", active_devices);
                    println!(
                        "  Expires at: {}",
                        ent.expires_at.as_deref().unwrap_or("never")
                    );
                }
                Err(err) => {
                    println!("Failed to retrieve entitlement for {}: {}", args.secwet_id, err);
                }
            }
        }
        AdminCommand::Revoke(args) => {
            let revoked = db::revoke_device(pool, args.secwet_id, &args.device_id).await?;
            if revoked {
                println!(
                    "Device {} in workspace {} revoked successfully.",
                    args.device_id, args.secwet_id
                );
            } else {
                println!(
                    "Device {} not found or already revoked in workspace {}.",
                    args.device_id, args.secwet_id
                );
            }
        }
    }

    Ok(())
}
