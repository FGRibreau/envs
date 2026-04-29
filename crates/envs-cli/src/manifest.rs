//! Project root detection and profile loading.

use crate::error::{CliError, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

const MARKER: &str = ".envs";

/// Walk up from `cwd`, find the nearest ancestor containing a `.envs/` directory.
/// Returns `None` if no marker is found before reaching the filesystem root.
pub fn find_project_root(cwd: &Path) -> Option<PathBuf> {
    for ancestor in cwd.ancestors() {
        let marker = ancestor.join(MARKER);
        if marker.is_dir() {
            return Some(ancestor.to_path_buf());
        }
    }
    None
}

/// Profile TOML schema (minimal v0.1).
#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)] // reserved for envs CLI side profile reading in v0.2 (currently the daemon does it)
pub struct Profile {
    #[serde(default)]
    pub schema: u32,
    #[serde(default)]
    pub binary: ProfileBinaryMeta,
    #[serde(default, rename = "binding")]
    pub bindings: Vec<Binding>,
    #[serde(default)]
    pub includes: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
pub struct ProfileBinaryMeta {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize, Clone)]
#[allow(dead_code)]
pub struct Binding {
    pub env: String,
    #[serde(alias = "src")]
    pub source: String,
}

/// Load a profile TOML from a path.
#[allow(dead_code)]
pub fn load_profile(path: &Path) -> Result<Profile> {
    let content = std::fs::read_to_string(path)?;
    let profile: Profile = toml::from_str(&content)?;
    Ok(profile)
}

/// Resolve a profile for `binary_name`. Order:
/// 1. project-local `<project_root>/.envs/<binary>.toml`
/// 2. global `~/.envs/profiles/<binary>.toml`
/// Returns the first found, or None if neither exists.
#[allow(dead_code)]
pub fn resolve_profile(binary_name: &str, project_root: Option<&Path>) -> Result<Option<Profile>> {
    if let Some(root) = project_root {
        let local = root.join(MARKER).join(format!("{binary_name}.toml"));
        if local.is_file() {
            return Ok(Some(load_profile(&local)?));
        }
    }

    let home = dirs::home_dir().ok_or_else(|| CliError::Internal("no home dir".into()))?;
    let global = home
        .join(MARKER)
        .join("profiles")
        .join(format!("{binary_name}.toml"));
    if global.is_file() {
        return Ok(Some(load_profile(&global)?));
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_root_detect_marker() {
        let tmp = tempdir_helper();
        std::fs::create_dir_all(tmp.join(".envs")).unwrap();
        let sub = tmp.join("src").join("module");
        std::fs::create_dir_all(&sub).unwrap();
        let root = find_project_root(&sub).unwrap();
        assert_eq!(root, tmp);
    }

    #[test]
    fn project_root_none_at_filesystem_root() {
        let result = find_project_root(Path::new("/"));
        assert!(result.is_none());
    }

    fn tempdir_helper() -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let p = std::env::temp_dir().join(format!("envs-test-{nanos}"));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
