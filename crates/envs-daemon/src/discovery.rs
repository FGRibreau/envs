//! Discovery pipeline: extract suggested env var bindings for a binary.
//!
//! Order:
//! 1. Registry lookup (curated community catalog)
//! 2. `<bin> --help` parsing (regex + prefix heuristics)
//! 3. (opt-in v0.2) LLM query for unknown tools
//!
//! Output: a list of `SuggestedBinding`s with confidence scores, used to
//! pre-fill the popup so the user doesn't have to type env var names from scratch.

use envs_proto::{Confidence, SuggestedBinding};
use std::collections::HashMap;
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;

/// Run the full discovery pipeline for a binary.
pub async fn discover(binary_path: &Path, binary_name: &str) -> Vec<SuggestedBinding> {
    let mut suggestions: HashMap<String, SuggestedBinding> = HashMap::new();

    // 1. Registry lookup
    if let Ok(Some(entry)) = crate::registry::lookup(binary_name).await {
        for ev in entry.env_vars {
            let env = ev.name.clone();
            let source = ev
                .recommended_source
                .unwrap_or_else(|| format!("rbw://{env}"));
            suggestions.insert(
                env.clone(),
                SuggestedBinding {
                    env,
                    source,
                    confidence: Confidence::High,
                    reason: format!("registry: {}", entry.binary.name),
                    deprecated: ev.deprecated,
                },
            );
        }
    }

    // 2. --help parsing (additive — fills gaps not covered by registry)
    let help_text = run_help(binary_path).await;
    let from_help = parse_help_for_env_vars(&help_text, binary_name);
    for sugg in from_help {
        suggestions.entry(sugg.env.clone()).or_insert(sugg);
    }

    // 3. LLM query (opt-in via ENVS_LLM_ENABLED=1; v0.2 ships scaffolding only)
    if crate::llm::is_enabled() && suggestions.is_empty() {
        for sugg in crate::llm::discover(binary_name, &help_text).await {
            suggestions.entry(sugg.env.clone()).or_insert(sugg);
        }
    }

    // Sort by confidence then alphabetical
    let mut out: Vec<SuggestedBinding> = suggestions.into_values().collect();
    out.sort_by(|a, b| {
        let order = |c: Confidence| match c {
            Confidence::High => 0,
            Confidence::Medium => 1,
            Confidence::Low => 2,
        };
        order(a.confidence)
            .cmp(&order(b.confidence))
            .then_with(|| a.env.cmp(&b.env))
    });
    out
}

/// Run `<bin> --help` and capture stdout+stderr. Failures yield empty string.
///
/// SAFETY: refuses to spawn the daemon's own executable to prevent self-recursion
/// (which can steal the UDS socket via server::run's "remove existing socket"
/// behavior). Daemons should never run `--help` against themselves.
async fn run_help(binary_path: &Path) -> String {
    if is_self(binary_path) {
        tracing::debug!(
            path = %binary_path.display(),
            "discovery: skipping --help on our own executable"
        );
        return String::new();
    }

    let output = match tokio::time::timeout(
        Duration::from_secs(3),
        Command::new(binary_path).arg("--help").output(),
    )
    .await
    {
        Ok(Ok(o)) => o,
        _ => {
            match tokio::time::timeout(
                Duration::from_secs(3),
                Command::new(binary_path).arg("-h").output(),
            )
            .await
            {
                Ok(Ok(o)) => o,
                _ => return String::new(),
            }
        }
    };
    let mut s = String::from_utf8_lossy(&output.stdout).to_string();
    s.push('\n');
    s.push_str(&String::from_utf8_lossy(&output.stderr));
    s
}

fn is_self(target: &Path) -> bool {
    let target_canon = match std::fs::canonicalize(target) {
        Ok(p) => p,
        Err(_) => return false,
    };
    if let Ok(self_path) = std::env::current_exe() {
        if let Ok(self_canon) = std::fs::canonicalize(&self_path) {
            return self_canon == target_canon;
        }
    }
    false
}

/// Parse `--help` text for env var mentions.
///
/// Strategy:
/// - Scan for tokens matching `[A-Z][A-Z0-9_]{2,}` (uppercase identifiers).
/// - Strong signals: line contains "env", "ENV:", "[$VAR]", "environment variable", "$VAR".
/// - Weak signal: just appears in --help.
/// - Filter out common false positives (option keywords like USAGE, OPTIONS, COMMANDS).
fn parse_help_for_env_vars(help: &str, binary_name: &str) -> Vec<SuggestedBinding> {
    if help.is_empty() {
        return Vec::new();
    }

    let mut found: HashMap<String, (Confidence, String)> = HashMap::new();
    let prefix_hint = guess_prefix(binary_name);

    for line in help.lines() {
        let lower = line.to_lowercase();
        let mentions_env = lower.contains("env")
            || lower.contains("[$")
            || lower.contains("variable")
            || line.contains("$");

        for token in extract_uppercase_tokens(line) {
            if is_blacklisted(&token) {
                continue;
            }
            if token.len() < 3 {
                continue;
            }

            let confidence = if mentions_env {
                Confidence::High
            } else if let Some(prefix) = prefix_hint.as_deref() {
                if token.starts_with(prefix) {
                    Confidence::Medium
                } else {
                    Confidence::Low
                }
            } else {
                Confidence::Low
            };

            let reason = if mentions_env {
                format!("--help mentions env var")
            } else {
                format!("--help contains uppercase identifier")
            };

            found
                .entry(token.clone())
                .and_modify(|(c, _)| {
                    if rank(*c) > rank(confidence) {
                        *c = confidence;
                    }
                })
                .or_insert((confidence, reason));
        }
    }

    found
        .into_iter()
        .filter(|(_, (c, _))| !matches!(c, Confidence::Low))
        .map(|(env, (confidence, reason))| SuggestedBinding {
            source: format!("rbw://{env}"),
            env,
            confidence,
            reason,
            deprecated: false,
        })
        .collect()
}

fn rank(c: Confidence) -> u8 {
    match c {
        Confidence::High => 0,
        Confidence::Medium => 1,
        Confidence::Low => 2,
    }
}

fn extract_uppercase_tokens(line: &str) -> Vec<String> {
    // Match `[A-Z][A-Z0-9_]{2,}`, allowing optional leading `$`.
    let mut tokens = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        // Skip leading `$` if followed by an uppercase letter; loop continues
        // so the next iteration handles the uppercase identifier.
        if bytes[i] == b'$' && i + 1 < bytes.len() && bytes[i + 1].is_ascii_uppercase() {
            i += 1;
            continue;
        }
        if bytes[i].is_ascii_uppercase() {
            let start = i;
            while i < bytes.len()
                && (bytes[i].is_ascii_uppercase() || bytes[i].is_ascii_digit() || bytes[i] == b'_')
            {
                i += 1;
            }
            if i - start >= 3 {
                tokens.push(line[start..i].to_string());
            }
        } else {
            i += 1;
        }
    }
    tokens
}

fn is_blacklisted(token: &str) -> bool {
    matches!(
        token,
        "USAGE"
            | "OPTIONS"
            | "COMMANDS"
            | "ARGS"
            | "ARGUMENTS"
            | "HELP"
            | "VERSION"
            | "INPUT"
            | "OUTPUT"
            | "FILE"
            | "PATH"
            | "DIR"
            | "VALUE"
            | "STRING"
            | "BOOL"
            | "INT"
            | "FLOAT"
            | "NAME"
            | "URL"
            | "TRUE"
            | "FALSE"
            | "NULL"
            | "DEBUG"
            | "INFO"
            | "WARN"
            | "ERROR"
            | "TRACE"
    )
}

/// Guess a likely env var prefix for the binary name (heuristic).
fn guess_prefix(binary_name: &str) -> Option<String> {
    let lower = binary_name.to_lowercase();
    let mapping: &[(&str, &str)] = &[
        ("flarectl", "CF_"),
        ("wrangler", "CLOUDFLARE_"),
        ("aws", "AWS_"),
        ("awscli", "AWS_"),
        ("gh", "GITHUB_"),
        ("hub", "GITHUB_"),
        ("kubectl", "KUBE"),
        ("docker", "DOCKER_"),
        ("gcloud", "GCLOUD_"),
        ("terraform", "TF_"),
        ("openai", "OPENAI_"),
        ("anthropic", "ANTHROPIC_"),
    ];
    for (k, v) in mapping {
        if lower.contains(k) {
            return Some((*v).to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_uppercase_tokens_basic() {
        let s = "Set the CF_API_TOKEN env var. See $CF_ACCOUNT_ID.";
        let tokens = extract_uppercase_tokens(s);
        assert!(tokens.contains(&"CF_API_TOKEN".to_string()));
        assert!(tokens.contains(&"CF_ACCOUNT_ID".to_string()));
    }

    #[test]
    fn extract_uppercase_tokens_min_length() {
        let s = "AB and ABC and AB12";
        let tokens = extract_uppercase_tokens(s);
        assert!(!tokens.contains(&"AB".to_string())); // too short
        assert!(tokens.contains(&"ABC".to_string()));
    }

    #[test]
    fn parse_help_high_confidence_when_env_mentioned() {
        let help = "Use $CF_API_TOKEN environment variable for auth.";
        let out = parse_help_for_env_vars(help, "flarectl");
        let cf = out.iter().find(|s| s.env == "CF_API_TOKEN").unwrap();
        assert!(matches!(cf.confidence, Confidence::High));
    }

    #[test]
    fn parse_help_blacklisted_filtered() {
        let help = "USAGE: flarectl [OPTIONS] COMMAND";
        let out = parse_help_for_env_vars(help, "flarectl");
        assert!(out.iter().all(|s| !["USAGE", "OPTIONS", "COMMAND"].contains(&s.env.as_str())));
    }

    #[test]
    fn guess_prefix_known_binary() {
        assert_eq!(guess_prefix("flarectl").as_deref(), Some("CF_"));
        assert_eq!(guess_prefix("aws").as_deref(), Some("AWS_"));
        assert_eq!(guess_prefix("unknown-tool"), None);
    }
}
