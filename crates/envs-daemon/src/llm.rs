//! Optional LLM-powered discovery for unknown binaries.
//!
//! For binaries that aren't in the registry and don't expose useful `--help`,
//! we ask Claude "what env vars does <binary> read?". The response is cached
//! in `~/.envs/llm-cache.json` for 30 days.
//!
//! Opt-in. To enable: `[llm].enabled = true` in `~/.envs/config.toml`, or
//! `ENVS_LLM_ENABLED=1` in the daemon environment. An `ANTHROPIC_API_KEY`
//! env var is required when enabled — without it, discovery degrades back
//! to registry + `--help` parsing only and a warning is logged.

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
    let json = serde_json::to_string_pretty(cache).map_err(std::io::Error::other)?;
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

    let suggestions = query_anthropic(binary_name, _help_text).await;
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

/// Call the Anthropic Messages API. Returns empty Vec on any failure
/// (missing API key, network error, malformed response). Discovery degrades
/// to registry + `--help` parsing only — never blocks a resolve.
async fn query_anthropic(binary_name: &str, help_text: &str) -> Vec<SuggestedBinding> {
    let api_key = match std::env::var("ANTHROPIC_API_KEY") {
        Ok(k) if !k.trim().is_empty() => k,
        _ => {
            tracing::warn!(
                "LLM discovery is enabled but ANTHROPIC_API_KEY is not set; \
                 skipping (registry + --help still apply)"
            );
            return Vec::new();
        }
    };

    // Run the blocking ureq call on a separate thread so we don't stall the
    // tokio runtime. The API typically responds in 1-3s.
    let binary_name = binary_name.to_string();
    let help_excerpt: String = help_text.chars().take(4000).collect();
    let result =
        tokio::task::spawn_blocking(move || call_anthropic(&api_key, &binary_name, &help_excerpt))
            .await;
    match result {
        Ok(Ok(parsed)) => parsed,
        Ok(Err(e)) => {
            tracing::warn!(error = %e, "LLM discovery API call failed");
            Vec::new()
        }
        Err(join_err) => {
            tracing::warn!(error = %join_err, "LLM discovery task panicked");
            Vec::new()
        }
    }
}

/// Synchronous, blocking-thread Anthropic call. Kept tight: one POST,
/// one JSON parse, no streaming, no retries (cache absorbs retries via TTL).
fn call_anthropic(
    api_key: &str,
    binary_name: &str,
    help_text: &str,
) -> Result<Vec<SuggestedBinding>, String> {
    let user_msg = format!(
        "What environment variables does the CLI tool `{binary_name}` read?\n\n\
         Here is its --help output (may be truncated):\n```\n{help_text}\n```\n\n\
         Respond ONLY with a JSON object of the form:\n\
         {{\"env_vars\": [{{\"name\": \"FOO_TOKEN\", \"reason\": \"<why>\"}}]}}\n\
         If the tool reads no environment variables, respond with {{\"env_vars\": []}}.\n\
         No prose, no markdown fences."
    );
    let body = serde_json::json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": user_msg}
        ]
    });

    let response = ureq::post("https://api.anthropic.com/v1/messages")
        .set("x-api-key", api_key)
        .set("anthropic-version", "2023-06-01")
        .set("content-type", "application/json")
        .timeout(std::time::Duration::from_secs(15))
        .send_string(&body.to_string())
        .map_err(|e| format!("HTTP error: {e}"))?;

    let json: serde_json::Value = response
        .into_json()
        .map_err(|e| format!("response parse: {e}"))?;
    let text = json
        .pointer("/content/0/text")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "missing /content/0/text in response".to_string())?;
    let payload: serde_json::Value = serde_json::from_str(text.trim())
        .map_err(|e| format!("model returned non-JSON: {e}; raw='{text}'"))?;
    let env_vars = payload
        .get("env_vars")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "missing env_vars array".to_string())?;

    let mut out = Vec::with_capacity(env_vars.len());
    for entry in env_vars {
        let name = entry.get("name").and_then(|v| v.as_str()).unwrap_or("");
        let reason = entry
            .get("reason")
            .and_then(|v| v.as_str())
            .unwrap_or("Claude")
            .to_string();
        if name.is_empty()
            || !name
                .chars()
                .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        {
            // Skip anything that doesn't look like a real env var name.
            continue;
        }
        out.push(SuggestedBinding {
            env: name.to_string(),
            source: format!("rbw://{name}"),
            confidence: Confidence::Medium,
            reason: format!("LLM: {reason}"),
            deprecated: false,
        });
    }
    Ok(out)
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

    /// Enabled but ANTHROPIC_API_KEY missing → log warning and return empty.
    /// Discovery degrades gracefully so a missing key never blocks resolves.
    #[tokio::test]
    async fn enabled_without_api_key_returns_empty() {
        std::env::set_var("ENVS_LLM_ENABLED", "1");
        std::env::remove_var("ANTHROPIC_API_KEY");
        let out = discover("nonexistent-bin", "").await;
        std::env::remove_var("ENVS_LLM_ENABLED");
        assert!(
            out.is_empty(),
            "expected empty without API key, got {out:?}"
        );
    }
}
