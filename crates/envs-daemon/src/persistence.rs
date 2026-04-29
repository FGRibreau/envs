//! Persistence of `Rule` metadata (no values) to `~/.envs/state/rules.toml`.

use crate::error::{DaemonError, Result};
use crate::rule::Rule;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Default)]
struct RulesFile {
    #[serde(default = "default_schema")]
    schema: u32,
    #[serde(default, rename = "rule")]
    rules: Vec<Rule>,
}

fn default_schema() -> u32 {
    1
}

pub fn rules_file_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| DaemonError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("state").join("rules.toml"))
}

/// Load rules from disk, filtering expired ones. Returns empty Vec if file does not exist.
pub fn load() -> Result<Vec<Rule>> {
    let path = rules_file_path()?;
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = std::fs::read_to_string(&path)?;
    if content.trim().is_empty() {
        return Ok(Vec::new());
    }
    let file: RulesFile = toml::from_str(&content)?;
    if file.schema != 1 {
        tracing::warn!(
            schema = file.schema,
            "unknown rules.toml schema version, ignoring"
        );
        return Ok(Vec::new());
    }
    let now = Utc::now();
    let alive: Vec<Rule> = file
        .rules
        .into_iter()
        .filter(|r| !r.is_expired(now))
        .collect();
    Ok(alive)
}

/// Atomically write the given rules snapshot to disk (write-tmp + rename).
pub fn save(rules: &[Rule]) -> Result<()> {
    let path = rules_file_path()?;
    let parent = path
        .parent()
        .ok_or_else(|| DaemonError::Internal("rules.toml has no parent dir".into()))?;
    std::fs::create_dir_all(parent)?;
    set_dir_perms(parent, 0o700)?;

    let file = RulesFile {
        schema: 1,
        rules: rules.to_vec(),
    };
    let content = toml::to_string_pretty(&file)?;

    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, content.as_bytes())?;
    set_file_perms(&tmp, 0o600)?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

#[cfg(unix)]
fn set_dir_perms(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_perms(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use envs_proto::ArgvMatch;

    #[test]
    fn roundtrip_empty() {
        let parsed: RulesFile = toml::from_str("schema = 1\n").unwrap();
        assert_eq!(parsed.schema, 1);
        assert!(parsed.rules.is_empty());
    }

    #[test]
    fn roundtrip_one_rule() {
        let now = Utc::now();
        let rule = Rule {
            id: "01ABC".into(),
            canon_path: "/opt/homebrew/bin/flarectl".into(),
            sha256: "9f3c".into(),
            codesign_team: Some("Cloudflare".into()),
            argv_match: ArgvMatch::Any,
            project_root: Some("/Users/test/proj".into()),
            env_keys: vec!["CF_API_TOKEN".into()],
            sources: vec!["rbw://CF_API_TOKEN".into()],
            profile_id: "flarectl".into(),
            created_at: now,
            expires_at: now + chrono::Duration::seconds(300),
            last_used_at: None,
        };
        let file = RulesFile {
            schema: 1,
            rules: vec![rule.clone()],
        };
        let s = toml::to_string_pretty(&file).unwrap();
        let parsed: RulesFile = toml::from_str(&s).unwrap();
        assert_eq!(parsed.rules.len(), 1);
        assert_eq!(parsed.rules[0].canon_path, rule.canon_path);
    }
}
