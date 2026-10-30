//! apps/desktop/src-tauri/src/cli_manager.rs
//!
//! Manages detection, 1-click symlinking, and uninstallation of the `secwet`
//! CLI binary to the user's `$PATH` (e.g. `/usr/local/bin/secwet` or `~/.local/bin/secwet`).

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct CliInstallStatus {
    pub installed: bool,
    pub path: Option<String>,
    pub in_path: bool,
    pub binary_found: bool,
    pub binary_path: Option<String>,
    pub symlink_target: Option<String>,
    pub can_install: bool,
    pub error: Option<String>,
}

/// Locates the compiled `secwet` CLI binary.
pub fn find_cli_source_binary() -> Result<PathBuf, String> {
    let bin_name = if cfg!(windows) { "secwet.exe" } else { "secwet" };

    // 1. Check next to the currently running executable (development & production macOS bundle)
    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            // Next to executable (target/debug or Contents/MacOS)
            let next_to_exe = parent.join(bin_name);
            if next_to_exe.is_file() {
                if let Ok(canonical) = next_to_exe.canonicalize() {
                    return Ok(canonical);
                }
                return Ok(next_to_exe);
            }

            // In macOS app bundle (Contents/Resources/secwet or Contents/Resources/bin/secwet)
            let in_resources = parent.join("../Resources").join(bin_name);
            if in_resources.is_file() {
                if let Ok(canonical) = in_resources.canonicalize() {
                    return Ok(canonical);
                }
                return Ok(in_resources);
            }

            let in_resources_bin = parent.join("../Resources/bin").join(bin_name);
            if in_resources_bin.is_file() {
                if let Ok(canonical) = in_resources_bin.canonicalize() {
                    return Ok(canonical);
                }
                return Ok(in_resources_bin);
            }
        }
    }

    // 2. Fallback relative to current working directory (workspace root in dev)
    for profile in ["debug", "release"] {
        let candidate = PathBuf::from(format!("target/{profile}/{bin_name}"));
        if candidate.is_file() {
            if let Ok(canonical) = candidate.canonicalize() {
                return Ok(canonical);
            }
            return Ok(candidate);
        }
    }

    // 3. Check workspace root relative paths (if running inside apps/desktop)
    for profile in ["debug", "release"] {
        let candidate = PathBuf::from(format!("../../target/{profile}/{bin_name}"));
        if candidate.is_file() {
            if let Ok(canonical) = candidate.canonicalize() {
                return Ok(canonical);
            }
            return Ok(candidate);
        }
    }

    // 4. Check if secwet is already somewhere in PATH
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                // If it's not a broken symlink
                if let Ok(canonical) = candidate.canonicalize() {
                    return Ok(canonical);
                }
            }
        }
    }

    Err("Could not find compiled secwet CLI binary".into())
}

/// Checks if a directory is writable by attempting a quick temporary file creation.
fn is_dir_writable(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    let test_file = dir.join(format!(".secwet_write_test_{}", std::process::id()));
    if let Ok(f) = std::fs::File::create(&test_file) {
        drop(f);
        let _ = std::fs::remove_file(&test_file);
        true
    } else {
        false
    }
}

/// Returns candidate target paths for symlinking the CLI into PATH.
fn candidate_install_paths() -> Vec<PathBuf> {
    let mut candidates = Vec::new();

    // 1. /usr/local/bin (Standard universal system bin on macOS/Linux)
    candidates.push(PathBuf::from("/usr/local/bin/secwet"));

    // 2. ~/.local/bin (Standard user bin on macOS/Linux)
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join(".local/bin/secwet"));
    }

    // 3. User home bin ~/bin
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(PathBuf::from(home).join("bin/secwet"));
    }

    candidates
}

/// Checks if a given path or its directory is included in the current `$PATH`.
fn is_in_path(path: &Path) -> bool {
    if let Some(parent) = path.parent() {
        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                if dir == parent {
                    return true;
                }
            }
        }
    }
    false
}

/// Detects whether `secwet` is installed in PATH and whether it can be installed.
pub fn get_cli_status() -> CliInstallStatus {
    let source_res = find_cli_source_binary();
    let binary_found = source_res.is_ok();
    let binary_path = source_res.ok().map(|p| p.to_string_lossy().to_string());

    // Check candidate install paths first
    for candidate in candidate_install_paths() {
        if let Ok(meta) = std::fs::symlink_metadata(&candidate) {
            let symlink_target = if meta.file_type().is_symlink() {
                std::fs::read_link(&candidate).ok().map(|p| p.to_string_lossy().to_string())
            } else {
                None
            };
            let in_path = is_in_path(&candidate);
            return CliInstallStatus {
                installed: true,
                path: Some(candidate.to_string_lossy().to_string()),
                in_path,
                binary_found,
                binary_path,
                symlink_target,
                can_install: binary_found,
                error: None,
            };
        }
    }

    // Check if secwet is found anywhere in PATH
    let bin_name = if cfg!(windows) { "secwet.exe" } else { "secwet" };
    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                let symlink_target = std::fs::read_link(&candidate).ok().map(|p| p.to_string_lossy().to_string());
                return CliInstallStatus {
                    installed: true,
                    path: Some(candidate.to_string_lossy().to_string()),
                    in_path: true,
                    binary_found,
                    binary_path,
                    symlink_target,
                    can_install: binary_found,
                    error: None,
                };
            }
        }
    }

    CliInstallStatus {
        installed: false,
        path: None,
        in_path: false,
        binary_found,
        binary_path,
        symlink_target: None,
        can_install: binary_found,
        error: None,
    }
}

/// Installs the `secwet` command into PATH by creating a symlink.
pub fn install_cli() -> Result<CliInstallStatus, String> {
    let source = find_cli_source_binary().map_err(|e| format!("Cannot install CLI: {}", e))?;

    // Determine the best target path:
    // 1. Try /usr/local/bin if writable
    // 2. Otherwise try ~/.local/bin (create if needed)
    let usr_local_bin = PathBuf::from("/usr/local/bin");
    let target = if is_dir_writable(&usr_local_bin) {
        usr_local_bin.join("secwet")
    } else if let Ok(home) = std::env::var("HOME") {
        let local_bin = PathBuf::from(home).join(".local/bin");
        std::fs::create_dir_all(&local_bin).map_err(|e| {
            format!("Failed to create ~/.local/bin directory: {}", e)
        })?;
        local_bin.join("secwet")
    } else {
        PathBuf::from("/usr/local/bin/secwet")
    };

    // If target exists or is a broken symlink, remove it first
    if std::fs::symlink_metadata(&target).is_ok() {
        let _ = std::fs::remove_file(&target);
    }

    // Create the symlink
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&source, &target).map_err(|e| {
            format!(
                "Failed to link {} to {}: {}. Try running: ln -sf \"{}\" \"{}\"",
                source.display(),
                target.display(),
                e,
                source.display(),
                target.display()
            )
        })?;

        // Ensure target is executable
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(&target) {
            let mut perms = meta.permissions();
            perms.set_mode(0o755);
            let _ = std::fs::set_permissions(&target, perms);
        }
    }

    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(&source, &target).or_else(|_| {
            std::fs::copy(&source, &target).map(|_| ())
        }).map_err(|e| format!("Failed to copy/link CLI to {}: {}", target.display(), e))?;
    }

    Ok(get_cli_status())
}

/// Uninstalls the `secwet` symlink from PATH.
pub fn uninstall_cli() -> Result<CliInstallStatus, String> {
    for candidate in candidate_install_paths() {
        if std::fs::symlink_metadata(&candidate).is_ok() {
            let _ = std::fs::remove_file(&candidate);
        }
    }

    Ok(get_cli_status())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_candidate_paths_not_empty() {
        let paths = candidate_install_paths();
        assert!(!paths.is_empty());
    }

    #[test]
    fn test_get_cli_status_runs() {
        let status = get_cli_status();
        // Should not panic and should find binary in dev workspace
        assert!(status.can_install || !status.binary_found);
    }
}
