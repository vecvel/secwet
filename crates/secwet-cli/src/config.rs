use serde::Deserialize;
use std::path::{Path, PathBuf};

/// Project-level configuration stored in `.secwet.toml`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecwetConfig {
    /// Target item name or UUID
    pub item: Option<String>,
    /// Target project name or UUID (alias for item)
    pub project: Option<String>,
    /// Target environment name or UUID
    pub env: Option<String>,
    /// Optional secwet data directory override
    pub data_dir: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Default)]
struct RawSecwetConfig {
    pub item: Option<String>,
    pub project: Option<String>,
    pub env: Option<String>,
    #[serde(alias = "secwet")]
    pub data_dir: Option<PathBuf>,
}

impl<'de> serde::Deserialize<'de> for SecwetConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let raw = RawSecwetConfig::deserialize(deserializer)?;
        let effective_item = raw.item.clone().or_else(|| raw.project.clone());
        let effective_project = raw.project.or(raw.item);
        let effective_data_dir = raw.data_dir;

        Ok(SecwetConfig {
            item: effective_item,
            project: effective_project,
            env: raw.env,
            data_dir: effective_data_dir,
        })
    }
}

impl SecwetConfig {
    /// Returns the target item identifier (checking `item` first, then `project`).
    pub fn target_item(&self) -> Option<&str> {
        self.item.as_deref().or(self.project.as_deref())
    }

    /// Returns the data directory override if specified.
    pub fn data_dir(&self) -> Option<&Path> {
        self.data_dir.as_deref()
    }
}

/// Discovers and loads `.secwet.toml` by traversing upwards from `start_dir` to the root.
/// Returns `Ok(Some(cfg))` if found and valid, `Ok(None)` if no config file exists,
/// or `Err(...)` if a config file is present but corrupted or invalid TOML.
pub fn find_and_load_config(start_dir: Option<&Path>) -> Result<Option<SecwetConfig>, String> {
    let mut current = match start_dir {
        Some(d) => d.to_path_buf(),
        None => {
            std::env::current_dir().map_err(|e| format!("cannot get current directory: {e}"))?
        }
    };

    loop {
        let candidate = current.join(".secwet.toml");
        if candidate.is_file() {
            let content = std::fs::read_to_string(&candidate)
                .map_err(|e| format!("failed to read {}: {e}", candidate.display()))?;
            let cfg: SecwetConfig = toml::from_str(&content)
                .map_err(|e| format!("failed to parse {}: {e}", candidate.display()))?;
            return Ok(Some(cfg));
        }

        if !current.pop() {
            break;
        }
    }

    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_discovery_in_parent() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let config_file = root.join(".secwet.toml");
        std::fs::write(
            &config_file,
            "project = \"payments-api\"\nenv = \"staging\"\n",
        )
        .unwrap();

        let nested = root.join("a").join("b").join("c");
        std::fs::create_dir_all(&nested).unwrap();

        let loaded = find_and_load_config(Some(&nested)).unwrap().unwrap();
        assert_eq!(loaded.project.as_deref(), Some("payments-api"));
        assert_eq!(loaded.env.as_deref(), Some("staging"));
    }

    #[test]
    fn test_config_corrupted_fails() {
        let temp = tempdir().unwrap();
        let root = temp.path();
        let config_file = root.join(".secwet.toml");
        std::fs::write(&config_file, "INVALID = [[[[TOML").unwrap();

        let res = find_and_load_config(Some(root));
        assert!(res.is_err());
    }

    #[test]
    fn test_config_not_found_returns_none() {
        let temp = tempdir().unwrap();
        let res = find_and_load_config(Some(temp.path())).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_config_item_and_project_precedence() {
        let toml_item = "item = \"item-service\"\nenv = \"prod\"\n";
        let cfg: SecwetConfig = toml::from_str(toml_item).unwrap();
        assert_eq!(cfg.item.as_deref(), Some("item-service"));
        assert_eq!(cfg.project.as_deref(), Some("item-service"));
        assert_eq!(cfg.target_item(), Some("item-service"));

        let toml_both = "item = \"item-priority\"\nproject = \"legacy-proj\"\n";
        let cfg2: SecwetConfig = toml::from_str(toml_both).unwrap();
        assert_eq!(cfg2.target_item(), Some("item-priority"));
    }
}
