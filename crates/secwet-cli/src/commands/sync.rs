//! `secwet sync` CLI command.
//!
//! Synchronizes local workspace changes with the relay server.

use clap::Args;
use secwet_core::{Error, RelayClient, Secwet};

#[derive(Debug, Args)]
pub struct SyncArgs {
    /// Output results as JSON
    #[arg(long)]
    pub json: bool,
}

pub async fn run_sync(
    secwet: &mut Secwet,
    keystore: &dyn secwet_core::keys::KeyStore,
    args: SyncArgs,
) -> Result<(), Error> {
    let relay_url = secwet.relay_url()?;
    let client = RelayClient::new(&relay_url, secwet.device_id().to_string());

    let (pushed, pulled) = match secwet.sync_round(&client, keystore).await {
        Ok(r) => r,
        Err(Error::RevocationNotice(notice)) => {
            if notice.directive.wipe {
                eprintln!("This device was revoked and erased its Secwet keys and data.");
            } else {
                eprintln!("This device was unlinked from Secwet. Sync is disabled.");
            }
            return Err(Error::Revoked);
        }
        Err(e) => return Err(e),
    };

    if args.json {
        let out = serde_json::json!({
            "pushed": pushed,
            "pulled": pulled,
            "pending_outbox": secwet.pending_outbox_count().unwrap_or(0),
            "cursor": secwet.sync_cursor().unwrap_or(0),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap());
    } else {
        println!("Sync complete: pushed {} event(s), pulled {} event(s).", pushed, pulled);
    }

    Ok(())
}
