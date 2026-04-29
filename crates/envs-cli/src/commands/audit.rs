//! `envs audit` — view audit log.

use crate::error::Result;
use std::io::{BufRead, BufReader};

pub async fn execute(action: super::super::AuditAction) -> Result<()> {
    use super::super::AuditAction;
    match action {
        AuditAction::Show {
            since: _,
            binary,
            event,
            project: _,
        } => show(binary, event).await,
        AuditAction::Export { path } => export(path).await,
        AuditAction::Verify => verify().await,
    }
}

async fn verify() -> Result<()> {
    // Verification needs the audit key + chain logic, which lives in envs-daemon.
    // For v0.2 we shell out to a hidden `envsd verify-audit` mode? Simpler: walk
    // the log here, but we need the key. Solution: copy the verify logic here
    // (it only needs hmac + sha2 + the key file). For minimal duplication, we
    // expose verify via a Request enum variant. v0.2 keeps it client-side using
    // the same primitives.
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
    use std::io::BufRead;
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

fn audit_log_path() -> Result<std::path::PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| crate::error::CliError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("logs").join("audit.jsonl"))
}

async fn show(binary_filter: Option<String>, event_filter: Option<String>) -> Result<()> {
    let path = audit_log_path()?;
    if !path.exists() {
        println!("(no audit log yet)");
        return Ok(());
    }
    let file = std::fs::File::open(&path)?;
    let reader = BufReader::new(file);
    let mut count = 0;
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(ref ev) = event_filter {
            if value.get("event").and_then(|v| v.as_str()) != Some(ev) {
                continue;
            }
        }
        if let Some(ref b) = binary_filter {
            let path_match = value
                .get("path")
                .and_then(|v| v.as_str())
                .map(|p| p.contains(b))
                .unwrap_or(false);
            if !path_match {
                continue;
            }
        }
        let ts = value.get("ts").and_then(|v| v.as_str()).unwrap_or("?");
        let ev = value.get("event").and_then(|v| v.as_str()).unwrap_or("?");
        let path_str = value.get("path").and_then(|v| v.as_str()).unwrap_or("");
        println!("{ts}  {ev:24} {path_str}");
        count += 1;
    }
    if count == 0 {
        println!("(no matching events)");
    }
    Ok(())
}

async fn export(target: std::path::PathBuf) -> Result<()> {
    let src = audit_log_path()?;
    if !src.exists() {
        println!("(no audit log to export)");
        return Ok(());
    }
    std::fs::copy(&src, &target)?;
    println!("✓ exported {} → {}", src.display(), target.display());
    Ok(())
}
