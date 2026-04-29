//! `envs audit` — view audit log.
//!
//! Filters supported by `show`:
//! - `--since 1h|30m|2d|...` (compound durations like `1h30m` are rejected for now)
//! - `--binary <name>` substring match against the `path` field
//! - `--event <name>` exact match against the `event` field
//! - `--project <path>` canonicalised match against the `project_root` field
//!
//! `verify` walks the HMAC-chained log and checks every line. The chain logic
//! is duplicated client-side here to keep `envs audit verify` daemon-free
//! (the daemon may be down when an operator audits the log).

use crate::error::{CliError, Result};
use chrono::{DateTime, Utc};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

pub async fn execute(action: super::super::AuditAction) -> Result<()> {
    use super::super::AuditAction;
    match action {
        AuditAction::Show {
            since,
            binary,
            event,
            project,
        } => show(since, binary, event, project).await,
        AuditAction::Export { path } => export(path).await,
        AuditAction::Verify => verify().await,
    }
}

async fn verify() -> Result<()> {
    // Verification is intentionally daemon-free: an operator may need to audit
    // the log when envsd is down (crashed, suspected tamper). The HMAC chain
    // primitives are simple enough that duplicating them here vs adding a UDS
    // round-trip is the simpler tradeoff.
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let home =
        dirs::home_dir().ok_or_else(|| crate::error::CliError::Internal("no home dir".into()))?;
    let log_path = home.join(".envs").join("logs").join("audit.jsonl");
    let key_path = home.join(".envs").join("state").join("audit.key");

    if !log_path.exists() {
        println!("(no audit log yet)");
        return Ok(());
    }
    if !key_path.exists() {
        println!("✗ audit.key missing — chain cannot be verified");
        return Ok(());
    }

    let key = std::fs::read(&key_path)?;
    if key.len() != 32 {
        println!("✗ audit.key has wrong length {}", key.len());
        return Ok(());
    }

    let file = std::fs::File::open(&log_path)?;
    let reader = std::io::BufReader::new(file);
    let mut prev = String::new();
    let mut verified = 0usize;
    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                println!("✗ line {}: parse error: {e}", idx + 1);
                println!("  ({verified} events verified before break)");
                return Ok(());
            }
        };
        let stored = value
            .as_object_mut()
            .and_then(|m| m.remove("_hmac"))
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default();
        if stored.len() != 64 {
            println!("✗ line {}: missing or malformed _hmac", idx + 1);
            println!("  ({verified} events verified before break)");
            return Ok(());
        }
        let payload = serde_json::to_vec(&value)?;
        let mut mac = HmacSha256::new_from_slice(&key).expect("hmac key");
        mac.update(prev.as_bytes());
        mac.update(&payload);
        let expected = hex::encode(mac.finalize().into_bytes());
        if expected != stored {
            println!("✗ line {}: HMAC mismatch", idx + 1);
            println!("  expected: {expected}");
            println!("  stored:   {stored}");
            println!("  ({verified} events verified before break)");
            return Ok(());
        }
        prev = stored;
        verified += 1;
    }
    println!("✓ chain verified: {verified} events");
    Ok(())
}

fn audit_log_path() -> Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| crate::error::CliError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("logs").join("audit.jsonl"))
}

async fn show(
    since: Option<String>,
    binary_filter: Option<String>,
    event_filter: Option<String>,
    project_filter: Option<PathBuf>,
) -> Result<()> {
    let cutoff = match since.as_deref() {
        Some(s) => Some(parse_since(s).map_err(|e| {
            CliError::BadArgs(format!(
                "--since {s:?}: {e}; use 30s/5m/2h/3d/1w (single unit)"
            ))
        })?),
        None => None,
    };

    let project_canon = project_filter.as_deref().map(canonicalize_or);

    let path = audit_log_path()?;
    if !path.exists() {
        println!("(no audit log yet)");
        return Ok(());
    }

    // Walk rotated logs first (oldest → newest), then today's file. Rotated logs
    // are named `audit.jsonl.YYYY-MM-DD`; we only include those still relevant
    // to the cutoff to avoid reading 30 days of history when --since 1h was asked.
    let dir = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let mut files = collect_relevant_logs(&dir, cutoff)?;
    files.push(path);

    let mut count = 0usize;
    for file_path in files {
        if !file_path.exists() {
            continue;
        }
        let file = std::fs::File::open(&file_path)?;
        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !matches_filters(
                &value,
                cutoff,
                event_filter.as_deref(),
                binary_filter.as_deref(),
                project_canon.as_deref(),
            ) {
                continue;
            }
            let ts = value.get("ts").and_then(|v| v.as_str()).unwrap_or("?");
            let ev = value.get("event").and_then(|v| v.as_str()).unwrap_or("?");
            let path_str = value.get("path").and_then(|v| v.as_str()).unwrap_or("");
            println!("{ts}  {ev:24} {path_str}");
            count += 1;
        }
    }
    if count == 0 {
        println!("(no matching events)");
    }
    Ok(())
}

async fn export(target: PathBuf) -> Result<()> {
    let src = audit_log_path()?;
    if !src.exists() {
        println!("(no audit log to export)");
        return Ok(());
    }
    std::fs::copy(&src, &target)?;
    println!("✓ exported {} → {}", src.display(), target.display());
    Ok(())
}

/// Parse a duration like `30s`, `5m`, `2h`, `3d`, `1w` (single unit).
/// Compound forms (`1h30m`) are intentionally rejected — keep the surface narrow.
fn parse_since(raw: &str) -> std::result::Result<chrono::Duration, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty value".into());
    }
    let split_at = trimmed
        .find(|c: char| !c.is_ascii_digit())
        .ok_or_else(|| "missing unit".to_string())?;
    if split_at == 0 {
        return Err("missing leading number".into());
    }
    let (num_str, unit) = trimmed.split_at(split_at);
    let n: i64 = num_str
        .parse()
        .map_err(|e| format!("invalid number {num_str:?}: {e}"))?;
    if n < 0 {
        return Err("negative duration".into());
    }
    let dur = match unit {
        "s" | "sec" | "secs" => chrono::Duration::seconds(n),
        "m" | "min" | "mins" => chrono::Duration::minutes(n),
        "h" | "hr" | "hrs" => chrono::Duration::hours(n),
        "d" | "day" | "days" => chrono::Duration::days(n),
        "w" | "wk" | "wks" | "week" | "weeks" => chrono::Duration::weeks(n),
        other => return Err(format!("unknown unit {other:?}")),
    };
    Ok(dur)
}

fn matches_filters(
    value: &serde_json::Value,
    cutoff: Option<chrono::Duration>,
    event: Option<&str>,
    binary: Option<&str>,
    project_canon: Option<&Path>,
) -> bool {
    if let Some(dur) = cutoff {
        let ts_str = match value.get("ts").and_then(|v| v.as_str()) {
            Some(s) => s,
            // Lines without a ts can't be filtered by time — drop them rather
            // than silently include them.
            None => return false,
        };
        let ts = match DateTime::parse_from_rfc3339(ts_str) {
            Ok(t) => t.with_timezone(&Utc),
            Err(_) => return false,
        };
        if Utc::now() - ts > dur {
            return false;
        }
    }
    if let Some(ev) = event {
        if value.get("event").and_then(|v| v.as_str()) != Some(ev) {
            return false;
        }
    }
    if let Some(b) = binary {
        let matches = value
            .get("path")
            .and_then(|v| v.as_str())
            .map(|p| p.contains(b))
            .unwrap_or(false);
        if !matches {
            return false;
        }
    }
    if let Some(want) = project_canon {
        let got = match value.get("project_root").and_then(|v| v.as_str()) {
            Some(s) => canonicalize_or(Path::new(s)),
            None => return false,
        };
        if got != want {
            return false;
        }
    }
    true
}

fn canonicalize_or(p: &Path) -> PathBuf {
    std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// Collect rotated log files (`audit.jsonl.YYYY-MM-DD`) sorted oldest → newest.
/// When `cutoff` is set, skip files whose date is strictly older than the cutoff
/// day so `--since 1h` doesn't tail 30 days of history.
fn collect_relevant_logs(dir: &Path, cutoff: Option<chrono::Duration>) -> Result<Vec<PathBuf>> {
    let cutoff_date = cutoff.map(|dur| (Utc::now() - dur).format("%Y-%m-%d").to_string());
    let mut rotated: Vec<(String, PathBuf)> = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(Vec::new()),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        let Some(date) = s.strip_prefix("audit.jsonl.") else {
            continue;
        };
        if let Some(ref cutoff_str) = cutoff_date {
            if date < cutoff_str.as_str() {
                continue;
            }
        }
        rotated.push((date.to_string(), entry.path()));
    }
    rotated.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(rotated.into_iter().map(|(_, p)| p).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_since_units() {
        assert_eq!(parse_since("30s").unwrap(), chrono::Duration::seconds(30));
        assert_eq!(parse_since("5m").unwrap(), chrono::Duration::minutes(5));
        assert_eq!(parse_since("2h").unwrap(), chrono::Duration::hours(2));
        assert_eq!(parse_since("3d").unwrap(), chrono::Duration::days(3));
        assert_eq!(parse_since("1w").unwrap(), chrono::Duration::weeks(1));
        assert_eq!(
            parse_since("  10mins ").unwrap(),
            chrono::Duration::minutes(10)
        );
    }

    #[test]
    fn parse_since_rejects_invalid() {
        assert!(parse_since("").is_err());
        assert!(parse_since("h").is_err()); // no number
        assert!(parse_since("10").is_err()); // no unit
        assert!(parse_since("10x").is_err()); // bad unit
        assert!(parse_since("-1h").is_err()); // negative — split puts '-' in unit slot
        assert!(parse_since("1h30m").is_err()); // compound rejected
    }

    #[test]
    fn matches_filters_event() {
        let line = json!({"ts":"2026-04-29T12:00:00Z","event":"grant","path":"/bin/x"});
        assert!(matches_filters(&line, None, Some("grant"), None, None));
        assert!(!matches_filters(&line, None, Some("revoke"), None, None));
    }

    #[test]
    fn matches_filters_binary_substring() {
        let line = json!({"ts":"2026-04-29T12:00:00Z","event":"grant","path":"/opt/homebrew/bin/flarectl"});
        assert!(matches_filters(&line, None, None, Some("flarectl"), None));
        assert!(matches_filters(&line, None, None, Some("homebrew"), None));
        assert!(!matches_filters(&line, None, None, Some("wrangler"), None));
    }

    #[test]
    fn matches_filters_project_root() {
        let tmp = tempfile::tempdir().expect("tmpdir");
        let project = tmp.path().to_path_buf();
        let canon_project = std::fs::canonicalize(&project).unwrap_or(project.clone());
        let line = json!({
            "ts":"2026-04-29T12:00:00Z",
            "event":"grant",
            "project_root": canon_project.to_string_lossy(),
        });
        assert!(matches_filters(
            &line,
            None,
            None,
            None,
            Some(&canon_project)
        ));

        let other = tempfile::tempdir().expect("other");
        let canon_other = std::fs::canonicalize(other.path()).unwrap_or(other.path().to_path_buf());
        assert!(!matches_filters(
            &line,
            None,
            None,
            None,
            Some(&canon_other)
        ));
    }

    #[test]
    fn matches_filters_project_missing_field_excludes() {
        let line = json!({"ts":"2026-04-29T12:00:00Z","event":"resolve"});
        let dummy = std::env::current_dir().expect("cwd");
        assert!(!matches_filters(&line, None, None, None, Some(&dummy)));
    }

    #[test]
    fn matches_filters_since_keeps_recent() {
        let recent = Utc::now() - chrono::Duration::seconds(30);
        let line = json!({
            "ts": recent.to_rfc3339(),
            "event":"resolve",
        });
        assert!(matches_filters(
            &line,
            Some(chrono::Duration::minutes(5)),
            None,
            None,
            None
        ));
    }

    #[test]
    fn matches_filters_since_drops_old() {
        let old = Utc::now() - chrono::Duration::hours(2);
        let line = json!({
            "ts": old.to_rfc3339(),
            "event":"resolve",
        });
        assert!(!matches_filters(
            &line,
            Some(chrono::Duration::minutes(5)),
            None,
            None,
            None
        ));
    }

    #[test]
    fn matches_filters_since_drops_missing_ts() {
        let line = json!({"event":"resolve"});
        assert!(!matches_filters(
            &line,
            Some(chrono::Duration::days(1)),
            None,
            None,
            None
        ));
    }

    #[test]
    fn collect_relevant_logs_skips_old_dates() {
        let tmp = tempfile::tempdir().expect("tmp");
        let dir = tmp.path();
        // Today and one week ago — only the recent one should pass a 1d cutoff.
        let today = Utc::now().format("%Y-%m-%d").to_string();
        let week_ago = (Utc::now() - chrono::Duration::days(7))
            .format("%Y-%m-%d")
            .to_string();
        std::fs::write(dir.join(format!("audit.jsonl.{today}")), b"").unwrap();
        std::fs::write(dir.join(format!("audit.jsonl.{week_ago}")), b"").unwrap();

        let kept = collect_relevant_logs(dir, Some(chrono::Duration::days(1))).unwrap();
        assert_eq!(kept.len(), 1, "only today's rotated log should be kept");
        assert!(kept[0].to_string_lossy().contains(&today));
    }
}
