//! Periodic background maintenance jobs.
//!
//! Section 8.5:
//! - Purge seen nonces older than 10 minutes (600s).
//! - Purge expired pairing sessions.

use crate::sqlx::PgPool;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info};

use crate::db::{cleanup_expired_pairing, cleanup_old_nonces, run_retention_job};

/// Spawns background maintenance task running every 60 seconds.
pub fn spawn_background_jobs(pool: PgPool) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(60));
        loop {
            ticker.tick().await;

            // 1. Purge nonces older than 10 minutes (600s)
            match cleanup_old_nonces(&pool, 600).await {
                Ok(count) => {
                    if count > 0 {
                        info!(purged_nonces = count, "Cleaned expired nonces");
                    }
                }
                Err(err) => {
                    error!(error = %err, "Failed to clean expired nonces");
                }
            }

            // 2. Purge expired pairing sessions
            match cleanup_expired_pairing(&pool).await {
                Ok(count) => {
                    if count > 0 {
                        info!(purged_sessions = count, "Cleaned expired pairing sessions");
                    }
                }
                Err(err) => {
                    error!(error = %err, "Failed to clean expired pairing sessions");
                }
            }

            // 3. Purge sync events past retention (30 days or acked by all active devices)
            match run_retention_job(&pool, 30).await {
                Ok(count) => {
                    if count > 0 {
                        info!(purged_events = count, "Cleaned sync events past retention");
                    }
                }
                Err(err) => {
                    error!(error = %err, "Failed to clean sync events past retention");
                }
            }
        }
    })
}
