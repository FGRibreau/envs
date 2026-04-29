//! Binary integrity helpers: refuse system binaries in scope=Any, world-writable check.

use crate::error::{DaemonError, Result};
use std::path::Path;

/// Paths under these prefixes are "system" and cannot be granted scope=Any
/// (codesign and sha256 drift on every macOS softwareupdate; the binary is
/// shared with all tools, so a broad scope grant is too laxe).
///
/// They CAN be granted with scope=ExactArgv (locked to specific argv).
const SYSTEM_PREFIXES: &[&str] = &["/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/", "/System/"];

pub fn is_system_binary(path: &Path) -> bool {
    let s = path.to_string_lossy();
    SYSTEM_PREFIXES.iter().any(|p| s.starts_with(p))
}

/// Refuse if the binary file (or its dir) is world-writable. Anyone-can-write
/// = anyone-can-replace = bypass of the sha256 binding.
#[cfg(unix)]
pub fn ensure_not_world_writable(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode();
    // S_IWOTH = 0o002
    if mode & 0o002 != 0 {
        return Err(DaemonError::BadInput(format!(
            "{} is world-writable (mode {:o}); refusing to grant",
            path.display(),
            mode & 0o777
        )));
    }
    if let Some(parent) = path.parent() {
        if let Ok(meta) = std::fs::metadata(parent) {
            let pmode = meta.permissions().mode();
            if pmode & 0o002 != 0 {
                return Err(DaemonError::BadInput(format!(
                    "{} (parent of binary) is world-writable; refusing",
                    parent.display()
                )));
            }
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub fn ensure_not_world_writable(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn detects_system_binaries() {
        assert!(is_system_binary(&PathBuf::from("/usr/bin/curl")));
        assert!(is_system_binary(&PathBuf::from("/bin/sh")));
        assert!(is_system_binary(&PathBuf::from("/System/Library/Foo")));
        assert!(!is_system_binary(&PathBuf::from(
            "/opt/homebrew/bin/flarectl"
        )));
        assert!(!is_system_binary(&PathBuf::from("/Users/me/bin/cf-curl")));
    }
}
