//! Async wrapper around the `rbw` CLI.
//!
//! URI scheme: `rbw://<item-name>/<field>` where `<field>` defaults to `password`.
//! Examples:
//!   - `rbw://CF_API_TOKEN`              → `rbw get "CF_API_TOKEN"` (password field)
//!   - `rbw://Cloudflare API/username`   → `rbw get "Cloudflare API" --field username`
//!   - `rbw://Cloudflare API/CF_TOKEN`   → `rbw get "Cloudflare API" --field CF_TOKEN`

use crate::error::{DaemonError, Result};
use secrecy::SecretString;
use tokio::process::Command;

/// Parsed components of an `rbw://` URI.
#[derive(Debug, Clone)]
pub struct RbwUri {
    pub item: String,
    pub field: String,
}

impl RbwUri {
    pub fn parse(uri: &str) -> Result<Self> {
        let rest = uri
            .strip_prefix("rbw://")
            .ok_or_else(|| DaemonError::BadRbwUri(format!("missing rbw:// prefix in {uri}")))?;
        if rest.is_empty() {
            return Err(DaemonError::BadRbwUri("empty URI".into()));
        }
        // First slash separates item from field. Item names may NOT contain `/`.
        match rest.split_once('/') {
            Some((item, field)) if !item.is_empty() && !field.is_empty() => Ok(Self {
                item: item.to_string(),
                field: field.to_string(),
            }),
            Some((item, _)) if !item.is_empty() => Ok(Self {
                item: item.to_string(),
                field: "password".to_string(),
            }),
            None => Ok(Self {
                item: rest.to_string(),
                field: "password".to_string(),
            }),
            _ => Err(DaemonError::BadRbwUri(format!("malformed: {uri}"))),
        }
    }
}

/// Fetch the value at a `rbw://` URI. Returns a `SecretString` that zeroizes on drop.
pub async fn get(uri: &str) -> Result<SecretString> {
    let parsed = RbwUri::parse(uri)?;
    let mut cmd = Command::new("rbw");
    cmd.arg("get").arg(&parsed.item);
    if parsed.field != "password" {
        cmd.arg("--field").arg(&parsed.field);
    }

    let output = cmd.output().await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            DaemonError::RbwNotInstalled
        } else {
            DaemonError::Io(e)
        }
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stderr_l = stderr.to_lowercase();
        if stderr_l.contains("locked") || stderr_l.contains("not unlocked") {
            return Err(DaemonError::RbwLocked);
        }
        return Err(DaemonError::RbwLookupFailed(format!(
            "rbw get {} failed: {}",
            parsed.item,
            stderr.trim()
        )));
    }

    // rbw appends a trailing newline.
    let mut value = String::from_utf8_lossy(&output.stdout).to_string();
    if value.ends_with('\n') {
        value.pop();
    }
    if value.ends_with('\r') {
        value.pop();
    }
    Ok(SecretString::new(value.into()))
}

/// Check that `rbw` is on PATH and the vault is unlocked.
pub async fn check_status() -> Result<bool> {
    let output = Command::new("rbw")
        .arg("unlocked")
        .output()
        .await
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                DaemonError::RbwNotInstalled
            } else {
                DaemonError::Io(e)
            }
        })?;
    // `rbw unlocked` exits 0 if unlocked, non-zero otherwise.
    Ok(output.status.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_short_uri_defaults_to_password() {
        let u = RbwUri::parse("rbw://CF_API_TOKEN").unwrap();
        assert_eq!(u.item, "CF_API_TOKEN");
        assert_eq!(u.field, "password");
    }

    #[test]
    fn parse_with_field() {
        let u = RbwUri::parse("rbw://Cloudflare API/username").unwrap();
        assert_eq!(u.item, "Cloudflare API");
        assert_eq!(u.field, "username");
    }

    #[test]
    fn parse_with_custom_field() {
        let u = RbwUri::parse("rbw://Cloudflare API/CF_TOKEN").unwrap();
        assert_eq!(u.item, "Cloudflare API");
        assert_eq!(u.field, "CF_TOKEN");
    }

    #[test]
    fn parse_rejects_missing_prefix() {
        assert!(RbwUri::parse("CF_API_TOKEN").is_err());
    }

    #[test]
    fn parse_rejects_empty() {
        assert!(RbwUri::parse("rbw://").is_err());
    }
}
