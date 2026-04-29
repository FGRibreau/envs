//! Community registry: lookup TOML entries describing known binaries' env vars.
//!
//! Repo: github.com/fgribreau/envs-registry
//! Layout: `binaries/<name>.toml` per binary.
//! Local clone: `~/.envs/registry/`. Lazy `git pull` if last fetch > 7 days.

use crate::error::{DaemonError, Result};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::{Duration, SystemTime};
use tokio::process::Command;

const REGISTRY_REPO: &str = "https://github.com/fgribreau/envs-registry.git";
const SYNC_TTL: Duration = Duration::from_secs(7 * 24 * 3600);
const LAST_PULL_FILE: &str = ".last_pull";

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct RegistryEntry {
    #[serde(default = "default_schema")]
    pub schema: u32,
    pub binary: BinaryMeta,
    #[serde(default, rename = "env_var")]
    pub env_vars: Vec<EnvVarEntry>,
}

fn default_schema() -> u32 {
    1
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct BinaryMeta {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    #[serde(default)]
    pub codesign_team_ids: Vec<String>,
    #[serde(default)]
    pub brew_formula: Option<String>,
    #[serde(default)]
    pub suggested_paths: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct EnvVarEntry {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub recommended_source: Option<String>,
    #[serde(default)]
    pub deprecated: bool,
}

pub fn registry_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| DaemonError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("registry"))
}

/// Look up a binary's registry entry (if exists). Returns None on miss.
pub async fn lookup(binary_name: &str) -> Result<Option<RegistryEntry>> {
    let dir = registry_dir()?;
    let path = dir.join("binaries").join(format!("{binary_name}.toml"));
    if !path.is_file() {
        return Ok(None);
    }
    let content = match std::fs::read_to_string(&path) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    match toml::from_str::<RegistryEntry>(&content) {
        Ok(entry) => Ok(Some(entry)),
        Err(e) => {
            tracing::warn!(?e, path = %path.display(), "failed to parse registry entry");
            Ok(None)
        }
    }
}

/// Sync the registry via `git pull` (or `git clone` if absent). Idempotent.
/// Skip if last_pull is fresh (< 7 days), unless `force` is true.
pub async fn sync(force: bool) -> Result<SyncResult> {
    let dir = registry_dir()?;
    let parent = dir
        .parent()
        .ok_or_else(|| DaemonError::Internal("registry dir has no parent".into()))?;
    std::fs::create_dir_all(parent)?;

    if !force && is_fresh(&dir).await {
        return Ok(SyncResult::Skipped);
    }

    let result = if dir.join(".git").is_dir() {
        // Pull
        let output = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .arg("pull")
            .arg("--ff-only")
            .arg("--quiet")
            .output()
            .await
            .map_err(|e| DaemonError::Internal(format!("git pull failed: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DaemonError::Internal(format!(
                "git pull: {}",
                stderr.trim()
            )));
        }
        SyncResult::Pulled
    } else {
        // Clone
        let output = Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("--quiet")
            .arg(REGISTRY_REPO)
            .arg(&dir)
            .output()
            .await
            .map_err(|e| DaemonError::Internal(format!("git clone failed: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(DaemonError::Internal(format!(
                "git clone: {}",
                stderr.trim()
            )));
        }
        SyncResult::Cloned
    };

    touch_last_pull(&dir);
    Ok(result)
}

#[derive(Debug, Clone, Copy)]
pub enum SyncResult {
    Pulled,
    Cloned,
    Skipped,
}

async fn is_fresh(dir: &std::path::Path) -> bool {
    let marker = dir.join(LAST_PULL_FILE);
    let modified = match std::fs::metadata(&marker).and_then(|m| m.modified()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    SystemTime::now()
        .duration_since(modified)
        .map(|d| d < SYNC_TTL)
        .unwrap_or(false)
}

fn touch_last_pull(dir: &std::path::Path) {
    let marker = dir.join(LAST_PULL_FILE);
    let _ = std::fs::write(&marker, "");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_parses_minimal() {
        let toml = r#"
schema = 1
[binary]
name = "flarectl"
"#;
        let entry: RegistryEntry = toml::from_str(toml).unwrap();
        assert_eq!(entry.binary.name, "flarectl");
    }

    #[test]
    fn entry_parses_full() {
        let toml = r#"
schema = 1
[binary]
name = "flarectl"
description = "Cloudflare CLI"
codesign_team_ids = ["Software Signing"]

[[env_var]]
name = "CF_API_TOKEN"
required = true
recommended_source = "rbw://CF_API_TOKEN"

[[env_var]]
name = "CF_API_KEY"
deprecated = true
"#;
        let entry: RegistryEntry = toml::from_str(toml).unwrap();
        assert_eq!(entry.binary.name, "flarectl");
        assert_eq!(entry.env_vars.len(), 2);
        assert!(entry.env_vars[0].required);
        assert!(entry.env_vars[1].deprecated);
    }
}
