//! Secwet Relay Server Library.
//!
//! Hosted relay for zero-knowledge encrypted sync events and plan entitlements.
//! Never stores or sees plaintext, record names, or master encryption keys.

pub mod admin;
pub mod auth;
pub mod collab;
pub mod collab_db;
pub mod config;
pub mod db;
pub mod error;
pub mod handlers;
pub mod jobs;
pub mod rate_limit;
pub mod server;

// Re-export PostgreSQL-isolated sqlx primitives without bringing in conflicting SQLite dependencies
pub mod sqlx {
    pub use sqlx_core::{
        error::Error,
        executor::Executor,
        from_row::FromRow,
        pool::Pool,
        query::query,
        query_as::query_as,
        query_scalar::query_scalar,
        row::Row,
    };
    pub use sqlx_postgres::{PgPool, PgPoolOptions, PgRow, Postgres};

    pub mod postgres {
        pub use sqlx_postgres::*;
    }
}

pub use config::RelayConfig;
pub use error::RelayApiError;
pub use handlers::AppState;
pub use server::create_router;
