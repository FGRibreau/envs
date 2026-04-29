//! User configuration loaded from `~/.envs/config.toml`.

use serde::Deserialize;
use std::path::PathBuf;
use std::sync::OnceLock;

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Config {
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub audit: AuditConfig,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct LlmConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct AuditConfig {
    #[serde(default = "default_retention")]
    pub retention_days: u64,
}

fn default_retention() -> u64 {
    30
}

fn config_path() -> Option<PathBuf> {
    Some(dirs::home_dir()?.join(".envs").join("config.toml"))
}

fn load() -> Config {
    let Some(path) = config_path() else {
        return Config::default();
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return Config::default();
    };
    toml::from_str(&content).unwrap_or_default()
}

/// Returns the cached config snapshot, loading from disk on first call.
pub fn current() -> &'static Config {
    static CACHE: OnceLock<Config> = OnceLock::new();
    CACHE.get_or_init(load)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_llm_disabled() {
        let c = Config::default();
        assert!(!c.llm.enabled);
        assert_eq!(c.audit.retention_days, 0); // serde default for u64 is 0; only loaded value uses default_retention
    }

    #[test]
    fn parse_minimal() {
        let toml = r#"
[llm]
enabled = true

[audit]
retention_days = 60
"#;
        let c: Config = toml::from_str(toml).unwrap();
        assert!(c.llm.enabled);
        assert_eq!(c.audit.retention_days, 60);
    }
}
