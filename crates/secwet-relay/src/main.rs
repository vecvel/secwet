//! Relay entry point and CLI commands.

use clap::{Parser, Subcommand};
use secwet_relay::{
    admin::{run_admin_command, AdminCommand},
    config::RelayConfig,
    db::{create_pool, run_migrations},
    handlers::AppState,
    jobs::spawn_background_jobs,
    rate_limit::RateLimitManager,
    server::create_router,
};
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser, Debug)]
#[command(name = "secwet-relay", about = "Secwet Zero-Knowledge Relay Server & Admin Tool")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the relay HTTP server (default if no subcommand given)
    Serve,

    /// Relay administrative operations
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "secwet_relay=info,tower_http=info".into());
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = RelayConfig::from_env();
    let cli = Cli::parse();

    let pool = create_pool(&config.database_url).await?;

    match cli.command {
        Some(Commands::Admin { command }) => {
            run_admin_command(&pool, command).await?;
        }
        Some(Commands::Serve) | None => {
            info!("Running PostgreSQL schema migrations...");
            run_migrations(&pool).await?;

            info!("Starting background maintenance tasks...");
            spawn_background_jobs(pool.clone());

            let limiter = RateLimitManager::new();
            let state = Arc::new(AppState::new(pool, config.clone(), limiter));

            let app = create_router(state);
            let listener = tokio::net::TcpListener::bind(&config.addr)
                .await
                .map_err(|e| format!("Failed to bind to {}: {}", config.addr, e))?;

            info!("secwet-relay listening on http://{}", config.addr);
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
        }
    }

    Ok(())
}
