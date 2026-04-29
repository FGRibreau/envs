//! Audit log: append-only JSON Lines, daily rotation, HMAC-chained.
//!
//! v0.2: each event includes a `_hmac` field equal to
//!     HMAC-SHA256(prev_hmac || serialized_event_without_hmac, key)
//! where `key` is a 32-byte random secret stored in `~/.envs/state/audit.key`
//! (mode 0600), generated on first use.
//!
//! `envs audit verify` walks the log and validates the chain. Insertions,
//! edits, or deletions break the chain.
//!
//! Never logs secret values.

use crate::error::{DaemonError, Result};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::Sha256;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;

const KEY_BYTES: usize = 32;
#[allow(dead_code)] // used in tests + verify_chain function (the latter is reserved for daemon-side verify)
const HMAC_HEX_LEN: usize = 64; // 32 bytes * 2

/// Cached HMAC chain state: the hex digest of the last event written.
/// Initialized lazily from disk on first event.
static CHAIN_STATE: Mutex<Option<ChainState>> = Mutex::new(None);

#[derive(Debug, Clone)]
struct ChainState {
    key: [u8; KEY_BYTES],
    last_hmac: String, // hex
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEvent {
    pub ts: DateTime<Utc>,
    pub event: String,
    #[serde(flatten)]
    pub fields: serde_json::Map<String, Value>,
    /// HMAC chain digest (hex). Empty for the genesis event.
    #[serde(rename = "_hmac", default, skip_serializing_if = "String::is_empty")]
    pub hmac: String,
}

pub fn log_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| DaemonError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("logs"))
}

pub fn current_log_file() -> Result<PathBuf> {
    let dir = log_dir()?;
    Ok(dir.join("audit.jsonl"))
}

fn key_file() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| DaemonError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("state").join("audit.key"))
}

/// Load or generate the HMAC key, and load the last hmac from the latest log line.
fn init_chain() -> Result<ChainState> {
    let path = key_file()?;
    let parent = path
        .parent()
        .ok_or_else(|| DaemonError::Internal("audit key has no parent".into()))?;
    std::fs::create_dir_all(parent)?;
    set_dir_perms(parent, 0o700)?;

    let key = if path.exists() {
        let bytes = std::fs::read(&path)?;
        if bytes.len() != KEY_BYTES {
            return Err(DaemonError::Internal(format!(
                "audit.key has wrong length {} (expected {KEY_BYTES})",
                bytes.len()
            )));
        }
        let mut k = [0u8; KEY_BYTES];
        k.copy_from_slice(&bytes);
        k
    } else {
        let mut k = [0u8; KEY_BYTES];
        rand::thread_rng().fill_bytes(&mut k);
        std::fs::write(&path, &k)?;
        set_file_perms(&path, 0o600)?;
        k
    };

    // Load last hmac from existing log file (tail).
    let last_hmac = read_last_hmac()?;
    Ok(ChainState { key, last_hmac })
}

fn read_last_hmac() -> Result<String> {
    let path = current_log_file()?;
    if !path.exists() {
        return Ok(String::new());
    }
    let file = std::fs::File::open(&path)?;
    let reader = BufReader::new(file);
    let mut last = String::new();
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<AuditEvent>(&line) {
            if !ev.hmac.is_empty() {
                last = ev.hmac;
            }
        }
    }
    Ok(last)
}

fn compute_hmac(key: &[u8; KEY_BYTES], prev: &str, payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key length is fixed");
    mac.update(prev.as_bytes());
    mac.update(payload);
    hex::encode(mac.finalize().into_bytes())
}

/// Append an event to the audit log with HMAC chaining + daily rotation.
///
/// Rotation: when the date changes, the current `audit.jsonl` is renamed to
/// `audit.jsonl.YYYY-MM-DD` and a fresh file is started. Old rotated files
/// older than `retention_days` (default 30) are purged on each rotation.
pub fn log(mut event: AuditEvent) -> Result<()> {
    let dir = log_dir()?;
    std::fs::create_dir_all(&dir)?;
    set_dir_perms(&dir, 0o700)?;

    // Lazy-init the chain state.
    let mut guard = CHAIN_STATE
        .lock()
        .map_err(|e| DaemonError::Internal(format!("audit lock: {e}")))?;
    if guard.is_none() {
        *guard = Some(init_chain()?);
    }
    let state = guard.as_mut().expect("just initialized");

    // Daily rotation: if today's date is newer than the file's last-modified date, rotate.
    let path = current_log_file()?;
    rotate_if_needed(&path)?;

    // Compute HMAC over (prev || event without hmac field).
    event.hmac.clear();
    let payload = serde_json::to_vec(&event)?;
    let new_hmac = compute_hmac(&state.key, &state.last_hmac, &payload);
    event.hmac = new_hmac.clone();
    state.last_hmac = new_hmac;

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    set_file_perms(&path, 0o600)?;

    let mut buf = serde_json::to_vec(&event)?;
    buf.push(b'\n');
    file.write_all(&buf)?;
    file.flush()?;
    Ok(())
}

fn retention_days() -> u64 {
    let cfg = crate::config::current();
    if cfg.audit.retention_days > 0 {
        cfg.audit.retention_days
    } else {
        30
    }
}

/// Rotate the active audit.jsonl if its mtime date differs from today.
/// Renames to `audit.jsonl.YYYY-MM-DD` (the previous day's date) and sweeps old files.
fn rotate_if_needed(path: &std::path::Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let meta = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };
    let modified = match meta.modified() {
        Ok(m) => m,
        Err(_) => return Ok(()),
    };

    let modified_date = chrono::DateTime::<Utc>::from(modified)
        .format("%Y-%m-%d")
        .to_string();
    let today = Utc::now().format("%Y-%m-%d").to_string();
    if modified_date == today {
        return Ok(());
    }

    // Rotate: rename to audit.jsonl.<modified_date>
    let parent = path.parent().unwrap_or_else(|| std::path::Path::new("."));
    let rotated = parent.join(format!("audit.jsonl.{modified_date}"));
    // If a file with that name already exists (e.g., daemon restarted), append to it.
    if rotated.exists() {
        let existing = std::fs::read_to_string(&rotated).unwrap_or_default();
        let new_content = std::fs::read_to_string(path).unwrap_or_default();
        std::fs::write(&rotated, format!("{existing}{new_content}"))?;
        std::fs::remove_file(path).ok();
    } else {
        std::fs::rename(path, &rotated)?;
    }
    set_file_perms(&rotated, 0o600)?;
    tracing::info!(rotated = %rotated.display(), "audit log rotated");

    // Sweep retention
    sweep_old_logs(parent, retention_days())?;
    Ok(())
}

fn sweep_old_logs(dir: &std::path::Path, retention_days: u64) -> Result<()> {
    let cutoff = Utc::now() - chrono::Duration::days(retention_days as i64);
    let cutoff_str = cutoff.format("%Y-%m-%d").to_string();

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let s = name.to_string_lossy();
        if let Some(date_part) = s.strip_prefix("audit.jsonl.") {
            if date_part < cutoff_str.as_str() {
                let _ = std::fs::remove_file(entry.path());
                tracing::debug!(file = %s, "audit: deleted old rotated log");
            }
        }
    }
    Ok(())
}

/// Verify the HMAC chain integrity. Returns Ok(events_verified) or Err on the
/// first broken line. (Daemon-side; CLI duplicates this logic for `envs audit verify`.)
#[allow(dead_code)]
pub fn verify_chain() -> Result<VerifyReport> {
    let path = current_log_file()?;
    if !path.exists() {
        return Ok(VerifyReport {
            verified: 0,
            broken_at: None,
        });
    }

    let path_key = key_file()?;
    if !path_key.exists() {
        return Err(DaemonError::Internal(
            "audit.key missing — cannot verify chain".into(),
        ));
    }
    let key_bytes = std::fs::read(&path_key)?;
    if key_bytes.len() != KEY_BYTES {
        return Err(DaemonError::Internal(format!(
            "audit.key has wrong length {}",
            key_bytes.len()
        )));
    }
    let mut key = [0u8; KEY_BYTES];
    key.copy_from_slice(&key_bytes);

    let file = std::fs::File::open(&path)?;
    let reader = BufReader::new(file);
    let mut prev = String::new();
    let mut verified = 0usize;
    for (idx, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let mut ev: AuditEvent = match serde_json::from_str(&line) {
            Ok(e) => e,
            Err(e) => {
                return Ok(VerifyReport {
                    verified,
                    broken_at: Some(format!("line {}: parse error: {e}", idx + 1)),
                })
            }
        };
        let stored = std::mem::take(&mut ev.hmac);
        if stored.len() != HMAC_HEX_LEN {
            return Ok(VerifyReport {
                verified,
                broken_at: Some(format!("line {}: missing or malformed _hmac", idx + 1)),
            });
        }
        let payload = serde_json::to_vec(&ev)?;
        let expected = compute_hmac(&key, &prev, &payload);
        if expected != stored {
            return Ok(VerifyReport {
                verified,
                broken_at: Some(format!(
                    "line {}: HMAC mismatch (expected {expected}, got {stored})",
                    idx + 1
                )),
            });
        }
        prev = stored;
        verified += 1;
    }

    Ok(VerifyReport {
        verified,
        broken_at: None,
    })
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct VerifyReport {
    pub verified: usize,
    pub broken_at: Option<String>,
}

/// Convenience builder.
pub fn event(event_name: &str) -> AuditBuilder {
    AuditBuilder {
        event: AuditEvent {
            ts: Utc::now(),
            event: event_name.to_string(),
            fields: serde_json::Map::new(),
            hmac: String::new(),
        },
    }
}

pub struct AuditBuilder {
    event: AuditEvent,
}

impl AuditBuilder {
    pub fn field<V: Serialize>(mut self, key: &str, value: V) -> Self {
        if let Ok(v) = serde_json::to_value(&value) {
            self.event.fields.insert(key.to_string(), v);
        }
        self
    }

    pub fn write(self) -> Result<()> {
        log(self.event)
    }
}

#[cfg(unix)]
fn set_dir_perms(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_perms(path: &std::path::Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_deterministic_with_same_inputs() {
        let key = [0x42u8; KEY_BYTES];
        let h1 = compute_hmac(&key, "abc", b"hello");
        let h2 = compute_hmac(&key, "abc", b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn hmac_changes_with_payload() {
        let key = [0x42u8; KEY_BYTES];
        let h1 = compute_hmac(&key, "abc", b"hello");
        let h2 = compute_hmac(&key, "abc", b"hellx");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hmac_changes_with_prev() {
        let key = [0x42u8; KEY_BYTES];
        let h1 = compute_hmac(&key, "abc", b"hello");
        let h2 = compute_hmac(&key, "abd", b"hello");
        assert_ne!(h1, h2);
    }

    #[test]
    fn build_event() {
        let e = event("test").field("foo", "bar").field("count", 42).event;
        assert_eq!(e.event, "test");
        assert_eq!(e.fields.get("foo").and_then(Value::as_str), Some("bar"));
        assert_eq!(e.fields.get("count").and_then(Value::as_i64), Some(42));
        assert!(e.hmac.is_empty());
    }
}
