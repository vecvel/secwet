//! Target project, environment, and data directory resolution.

use crate::config::SecwetConfig;
use secwet_core::{EnvironmentView, Error, ProjectView, Result, Vault};
use std::path::PathBuf;
use uuid::Uuid;

/// Resolves the vault storage directory according to precedence:
/// 1. CLI flag `--data-dir`
/// 2. Environment variable `SECWET_DATA_DIR`
/// 3. Configuration file `.secwet.toml` `vault`
/// 4. Platform default: `app.secwet.Secwet` data directory.
pub fn resolve_data_dir(
    cli_flag: Option<PathBuf>,
    config: Option<&SecwetConfig>,
) -> Result<PathBuf> {
    if let Some(dir) = cli_flag {
        return Ok(dir);
    }

    if let Ok(dir) = std::env::var("SECWET_DATA_DIR") {
        if !dir.trim().is_empty() {
            return Ok(PathBuf::from(dir));
        }
    }

    if let Some(cfg) = config {
        if let Some(ref vault_path) = cfg.vault {
            return Ok(vault_path.clone());
        }
    }

    directories::ProjectDirs::from("app", "secwet", "Secwet")
        .map(|dirs| dirs.data_dir().to_path_buf())
        .ok_or(Error::Storage)
}

/// Resolves the target item from CLI flag, configuration file, or fallback to the first item.
pub fn resolve_item(
    vault: &Vault,
    cli_flag: Option<&str>,
    config: Option<&SecwetConfig>,
) -> Result<ProjectView> {
    let items = vault.list_projects()?;
    if items.is_empty() {
        return Err(Error::NotFound);
    }

    let target = cli_flag.or_else(|| config.and_then(|c| c.target_item()));

    match target {
        Some(t) => {
            if let Ok(id) = Uuid::parse_str(t) {
                if let Some(i) = items.into_iter().find(|i| i.id == id) {
                    return Ok(i);
                }
            } else if let Some(i) = items
                .into_iter()
                .find(|i| i.name.eq_ignore_ascii_case(t))
            {
                return Ok(i);
            }
            Err(Error::NotFound)
        }
        None => Ok(items.into_iter().next().unwrap()),
    }
}

/// Backwards compatibility alias for `resolve_item`.
#[inline]
pub fn resolve_project(
    vault: &Vault,
    cli_flag: Option<&str>,
    config: Option<&SecwetConfig>,
) -> Result<ProjectView> {
    resolve_item(vault, cli_flag, config)
}

/// Resolves the target environment within an item.
/// Returns `Ok(None)` if the item has no environments and `--env` was omitted.
/// Returns `Err(...)` if the item has no environments and `--env` was explicitly passed.
pub fn resolve_environment(
    item: &ProjectView,
    cli_flag: Option<&str>,
    config: Option<&SecwetConfig>,
) -> Result<Option<EnvironmentView>> {
    if item.environments.is_empty() {
        if cli_flag.is_some() {
            return Err(Error::Invalid {
                field: "env",
                message: format!("item '{}' has no environments", item.name),
            });
        }
        return Ok(None);
    }

    let target = cli_flag.or_else(|| config.and_then(|c| c.env.as_deref()));

    match target {
        Some(t) => {
            if let Ok(id) = Uuid::parse_str(t) {
                if let Some(env) = item.environments.iter().find(|e| e.id == id) {
                    return Ok(Some(env.clone()));
                }
            } else if let Some(env) = item
                .environments
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case(t))
            {
                return Ok(Some(env.clone()));
            }
            Err(Error::NotFound)
        }
        None => {
            if let Some(env) = item
                .environments
                .iter()
                .find(|e| e.name.eq_ignore_ascii_case("development"))
            {
                Ok(Some(env.clone()))
            } else {
                Ok(Some(item.environments[0].clone()))
            }
        }
    }
}

/// Formats a Unix timestamp in milliseconds to an ISO 8601 UTC string.
pub fn format_timestamp_ms(ms: i64) -> String {
    let secs = ms / 1000;
    let days = secs / 86400;
    let time_in_day = (secs % 86400 + 86400) % 86400;
    let hours = time_in_day / 3600;
    let minutes = (time_in_day % 3600) / 60;
    let seconds = time_in_day % 60;

    let (year, month, day) = days_to_ymd(days);
    format!("{year:04}-{month:02}-{day:02} {hours:02}:{minutes:02}:{seconds:02} UTC")
}

fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i32 + era as i32 * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_timestamp() {
        // 0 ms is 1970-01-01 00:00:00 UTC
        assert_eq!(format_timestamp_ms(0), "1970-01-01 00:00:00 UTC");
        // 1700000000_000 ms is 2023-11-14 22:13:20 UTC
        assert_eq!(
            format_timestamp_ms(1_700_000_000_000),
            "2023-11-14 22:13:20 UTC"
        );
    }
}
