//! CLI commands for device management.

use clap::{Args, Subcommand};
use secwet_core::secwet::Secwet;
use secwet_core::Error;

#[derive(Args, Debug)]
pub struct DeviceArgs {
    #[command(subcommand)]
    pub command: DeviceSubcommand,
}

#[derive(Subcommand, Debug)]
pub enum DeviceSubcommand {
    /// List all registered devices
    #[command(visible_alias = "ls")]
    List {
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },

    /// Revoke a registered device
    Revoke {
        /// The device ID to revoke
        device_id: String,
        /// Revoke and make the device crypto-shred its keys and erase its data (lost or stolen devices)
        #[arg(long, conflicts_with = "sync_only")]
        wipe: bool,
        /// Stop syncing only; the device keeps a read-only archive (default)
        #[arg(long)]
        sync_only: bool,
    },
}

pub fn handle_device(secwet: &mut Secwet, args: DeviceArgs) -> Result<(), Error> {
    match args.command {
        DeviceSubcommand::List { json } => {
            let devices = secwet.devices_list()?;
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&devices).unwrap_or_else(|_| "[]".into())
                );
                return Ok(());
            }

            if devices.is_empty() {
                println!("No devices registered.");
                return Ok(());
            }

            println!(
                "{:<28} {:<18} {:<10} {:<16} {:<10}",
                "DEVICE ID", "NAME", "PLATFORM", "FINGERPRINT", "STATUS"
            );
            println!("{}", "-".repeat(86));

            for d in devices {
                let status = if d.revoked_at.is_some() {
                    "Revoked"
                } else if d.is_current {
                    "Active (this)"
                } else {
                    "Active"
                };

                println!(
                    "{:<28} {:<18} {:<10} {:<16} {:<10}",
                    d.id, d.name, d.platform, d.fingerprint, status
                );
            }
            Ok(())
        }
        DeviceSubcommand::Revoke { device_id, wipe, .. } => {
            // Pro, and Pro that ended: revocation is never locked behind a plan.
            let pro = secwet.plan_state()? != secwet_core::PlanState::Free && secwet.relay_url().is_ok();
            if pro {
                let client = secwet_core::RelayClient::new(secwet.relay_url()?, secwet.device_id().to_string());
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|_| Error::Storage)?;
                rt.block_on(secwet.device_revoke_remote(&client, &device_id, wipe))?;
            } else {
                secwet.device_revoke(&device_id)?;
            }
            if wipe && pro {
                println!("Device {device_id} revoked. It will erase its keys and data when it next connects.");
            } else {
                println!("Device {device_id} revoked. It keeps a read-only copy of what it already had.");
            }
            println!("Run `secwet key rotate` so it can't read changes made from now on.");
            Ok(())
        }
    }
}

