//! Relay configuration parsed from environment variables.

use std::net::SocketAddr;

#[derive(Debug, Clone)]
pub struct RelayConfig {
    pub database_url: String,
    pub addr: SocketAddr,
    pub retention_days: i64,
    pub public_url: String,
    pub default_device_limit: u32,
}

impl RelayConfig {
    pub fn from_env() -> Self {
        let database_url = std::env::var("DATABASE_URL")
            .unwrap_or_else(|_| "postgres://secwet:secwet@localhost:5432/secwet_relay".to_string());

        let addr_str = std::env::var("SECWET_RELAY_ADDR")
            .unwrap_or_else(|_| "127.0.0.1:8787".to_string());
        let addr: SocketAddr = addr_str
            .parse()
            .unwrap_or_else(|_| "127.0.0.1:8787".parse().unwrap());

        let retention_days: i64 = std::env::var("RETENTION_DAYS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        let public_url = std::env::var("PUBLIC_URL")
            .unwrap_or_else(|_| format!("http://{}", addr));

        let default_device_limit: u32 = std::env::var("DEFAULT_DEVICE_LIMIT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5);

        Self {
            database_url,
            addr,
            retention_days,
            public_url,
            default_device_limit,
        }
    }
}
