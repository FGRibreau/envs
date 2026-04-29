//! Optional LLM-powered discovery for unknown binaries.
//!
//! v0.2 STATUS: scaffolding ready, HTTP call deliberately deferred.
//!
//! For binaries that aren't in the registry and don't expose useful `--help`,
//! we can ask an LLM "what env vars does <binary> read?". The response is
//! cached in `~/.envs/llm-cache.json` for 30 days.
//!
//! v0.2 ships the cache layer + opt-in plumbing. The actual Anthropic API call
//! is stubbed (returns empty Vec). v0.3 will wire `reqwest` + Claude API client.
//! Reason for the deferral: a robust API client (retry, rate-limit, streaming
//! error handling, cost guardrails) is an afternoon of careful work that
//! deserves its own iteration.
//!
//! To enable when implemented: set `ENVS_LLM_ENABLED=1` in the daemon env or
//! flip `[llm].enabled = true` in `~/.envs/config.toml`.

use chrono::{DateTime, Utc};
use envs_proto::{Confidence, SuggestedBinding};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

const CACHE_TTL_DAYS: i64 = 30;

#[derive(Debug, Serialize, Deserialize, Default)]
struct CacheFile {
    #[serde(default)]
    entries: HashMap<String, CacheEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CacheEntry {
    fetched_at: DateTime<Utc>,
    suggestions: Vec<CachedSuggestion>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct CachedSuggestion {
    env: String,
    source: String,
    reason: String,
}

pub fn is_enabled() -> bool {
    // Env var takes precedence (handy for one-off testing) over config.toml.
    if let Ok(v) = std::env::var("ENVS_LLM_ENABLED") {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    crate::config::current().llm.enabled
}

fn cache_path() -> Option<PathBuf> {
    let home = dirs::home_dir()?;
    Some(home.join(".envs").join("llm-cache.json"))
}

fn read_cache() -> CacheFile {
    let Some(path) = cache_path() else {
        return CacheFile::default();
    };
    let Ok(content) = std::fs::read_to_string(&path) else {
        return CacheFile::default();
    };
    serde_json::from_str(&content).unwrap_or_default()
}

fn write_cache(cache: &CacheFile) -> std::io::Result<()> {
    let Some(path) = cache_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(cache)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&path, json)
}

/// Look up suggestions for a binary, querying the LLM if cache miss + enabled.
pub async fn discover(binary_name: &str, _help_text: &str) -> Vec<SuggestedBinding> {
    if !is_enabled() {
        return Vec::new();
    }

    // Cache lookup
    let mut cache = read_cache();
    if let Some(entry) = cache.entries.get(binary_name) {
        let age = Utc::now() - entry.fetched_at;
        if age < chrono::Duration::days(CACHE_TTL_DAYS) {
            return entry
                .suggestions
                .iter()
                .map(|s| SuggestedBinding {
                    env: s.env.clone(),
                    source: s.source.clone(),
                    confidence: Confidence::Medium,
                    reason: s.reason.clone(),
                    deprecated: false,
                })
                .collect();
        }
    }

    // v0.2: stub. v0.3: real API call.
    let suggestions = query_llm_stub(binary_name).await;
    if !suggestions.is_empty() {
        let cached: Vec<CachedSuggestion> = suggestions
            .iter()
            .map(|s| CachedSuggestion {
                env: s.env.clone(),
                source: s.source.clone(),
                reason: s.reason.clone(),
            })
            .collect();
        cache.entries.insert(
            binary_name.to_string(),
            CacheEntry {
                fetched_at: Utc::now(),
                suggestions: cached,
            },
        );
        let _ = write_cache(&cache);
    }
    suggestions
}

/// v0.2 stub. v0.3 will replace with a real reqwest call to Anthropic API.
async fn query_llm_stub(_binary_name: &str) -> Vec<SuggestedBinding> {
    tracing::debug!(
        "LLM discovery is enabled but the API client is a v0.3 task; returning empty"
    );
    Vec::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_file_default_empty() {
        let c = CacheFile::default();
        assert!(c.entries.is_empty());
    }

    #[test]
    fn is_enabled_via_env() {
        std::env::set_var("ENVS_LLM_ENABLED", "1");
        assert!(is_enabled());
        std::env::remove_var("ENVS_LLM_ENABLED");
        assert!(!is_enabled());
    }
}
