//! Helper-side `rbw` shell-out for the interactive item/field picker.
//!
//! Mirrors `envs-cli::picker` but lives in the helper because that's where
//! the modal popup runs. envsd auto-unlocks rbw before each resolve, so
//! `rbw list` and `rbw get --raw` succeed during the helper round-trip.

use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum RbwError {
    #[error("rbw is not on PATH")]
    Missing,
    #[error("rbw is locked")]
    Locked,
    #[error("rbw vault is empty")]
    Empty,
    #[error("rbw error: {0}")]
    Other(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, RbwError>;

/// `rbw list` → one item name per line, blank/garbage lines dropped.
pub fn list_items() -> Result<Vec<String>> {
    let out = match Command::new("rbw").arg("list").output() {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(RbwError::Missing),
        Err(e) => return Err(e.into()),
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.to_ascii_lowercase().contains("locked") {
            return Err(RbwError::Locked);
        }
        return Err(RbwError::Other(stderr.trim().to_string()));
    }
    let items: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    if items.is_empty() {
        return Err(RbwError::Empty);
    }
    Ok(items)
}

/// `rbw get --raw <item>` → field-name list. The list always exposes the
/// canonical login fields (`password`, `username`, `totp`) when set, plus
/// `notes` when non-empty, plus every custom field saved on the item.
pub fn get_fields(item: &str) -> Result<Vec<String>> {
    let out = match Command::new("rbw")
        .arg("get")
        .arg("--raw")
        .arg(item)
        .output()
    {
        Ok(o) => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(RbwError::Missing),
        Err(e) => return Err(e.into()),
    };
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.to_ascii_lowercase().contains("locked") {
            return Err(RbwError::Locked);
        }
        return Err(RbwError::Other(stderr.trim().to_string()));
    }
    parse_fields(&String::from_utf8_lossy(&out.stdout))
}

/// Pure parser, exposed for tests. See `envs-cli::picker::parse_fields` for
/// the input shape — both crates parse the same `rbw get --raw` JSON.
pub fn parse_fields(json: &str) -> Result<Vec<String>> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| RbwError::Other(format!("json parse: {e}")))?;
    let mut out: Vec<String> = Vec::new();

    if let Some(data) = v.get("data") {
        for k in &["password", "username", "totp"] {
            if data.get(*k).map(|x| !x.is_null()).unwrap_or(false) {
                out.push((*k).to_string());
            }
        }
    }
    if v.get("notes")
        .map(|n| !n.is_null() && n.as_str().map(|s| !s.is_empty()).unwrap_or(true))
        .unwrap_or(false)
    {
        out.push("notes".into());
    }
    if let Some(fields) = v.get("fields").and_then(|f| f.as_array()) {
        for f in fields {
            if let Some(name) = f.get("name").and_then(|n| n.as_str()) {
                if !name.trim().is_empty() {
                    out.push(name.to_string());
                }
            }
        }
    }
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_password_only() {
        let f = parse_fields(r#"{"name":"X","data":{"username":null,"password":"p","totp":null}}"#)
            .unwrap();
        assert_eq!(f, vec!["password"]);
    }

    #[test]
    fn parse_full_login_with_custom_fields() {
        let f = parse_fields(
            r#"{
                "name":"GitHub",
                "data":{"username":"u","password":"p","totp":"t"},
                "notes":"deploy",
                "fields":[{"name":"token","value":"v"}]
            }"#,
        )
        .unwrap();
        assert_eq!(f, vec!["password", "username", "totp", "notes", "token"]);
    }
}
