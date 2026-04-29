//! `envs init` — bootstrap wizard. Idempotent: re-runs cleanly when everything
//! is already in place. Auto-installs missing prerequisites via Homebrew rather
//! than refusing to proceed (a wizard's job is to install, not to lecture).

use crate::error::{CliError, Result};
use std::process::Stdio;
use tokio::process::Command;

pub async fn execute(force: bool) -> Result<()> {
    println!("envs setup wizard\n");

    println!("[1/6] Checking Homebrew...");
    if !brew_available().await {
        return Err(CliError::BadArgs(
            "Homebrew is required to install rbw + pinentry-touchid. \
             Install brew first: https://brew.sh"
                .into(),
        ));
    }
    println!("  ✓ brew is available");

    println!("\n[2/6] rbw (Bitwarden CLI backend)...");
    ensure_brew_pkg("rbw", "rbw").await?;
    let rbw_version = Command::new("rbw")
        .arg("--version")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    println!("  ✓ {rbw_version}");

    println!("\n[3/6] pinentry-touchid (TouchID-gated unlock)...");
    let was_present = Command::new("pinentry-touchid")
        .arg("--version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    ensure_brew_pkg("pinentry-touchid", "jorgelbg/tap/pinentry-touchid").await?;
    let pinentry_version = Command::new("pinentry-touchid")
        .arg("--version")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "pinentry-touchid".into());
    println!("  ✓ {pinentry_version}");
    // First-run setup: pinentry-touchid wraps pinentry-mac and needs `-fix`
    // to wire the delegation. Without this, rbw login fails with
    // "error reading pinentry output: unexpected EOF". Idempotent — safe
    // to re-run.
    if !was_present || force {
        println!("  → Running `pinentry-touchid -fix` (one-time setup)...");
        let out = Command::new("pinentry-touchid")
            .arg("-fix")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await;
        match out {
            Ok(s) if s.success() => println!("  ✓ pinentry-touchid backend wired"),
            _ => println!(
                "  ! `pinentry-touchid -fix` exited non-zero — you may need to run it manually"
            ),
        }
    }
    println!("\n[4/6] rbw login state...");
    // Did login already happen? rbw stores the encrypted vault DB at
    // ~/.local/share/rbw/db.<email>.json after the first successful login.
    // `rbw config show` only proves the email is set — not that login worked.
    let already_logged_in = rbw_db_exists();
    let cfg = read_rbw_config().await;
    let email_configured = cfg.get("email").map(|e| e.contains('@')).unwrap_or(false);

    if already_logged_in && !force {
        println!("  ✓ rbw login state OK (vault DB present)");
    } else {
        if !email_configured || force {
            let email = prompt_line("  Bitwarden email > ")?;
            rbw_config_set("email", &email).await?;
            println!("  ✓ email set to {email}");

            // Server URL: empty (default) → Bitwarden cloud (api.bitwarden.com).
            // Anything else → self-hosted Vaultwarden / on-prem Bitwarden domain.
            let current_url = cfg.get("base_url").cloned().unwrap_or_default();
            let hint = if current_url.is_empty() {
                "  Server URL (Enter for Bitwarden cloud, or e.g. https://vault.example.com) > "
                    .to_string()
            } else {
                format!("  Server URL [{current_url}] > ")
            };
            let url = prompt_line_with_default(&hint, &current_url)?;
            if url.is_empty() {
                // Cloud — clear any prior self-hosted override.
                let _ = Command::new("rbw")
                    .arg("config")
                    .arg("unset")
                    .arg("base_url")
                    .output()
                    .await;
                println!("  ✓ using Bitwarden cloud (api.bitwarden.com)");
            } else {
                rbw_config_set("base_url", &url).await?;
                println!("  ✓ server set to {url}");
            }
        } else {
            println!("  ✓ rbw email already configured");
            if let Some(url) = cfg.get("base_url") {
                println!("  ✓ server: {url}");
            }
        }

        // CRITICAL: pinentry-touchid wraps pinentry-mac for Keychain-cached
        // unlocks AFTER a master password is known. On the very first login
        // (no Keychain entry yet), pinentry-touchid hands off to pinentry-mac
        // but its own EOF-handling has a known race that yields:
        //   "rbw login: failed to read password from pinentry: error reading
        //    pinentry output: unexpected EOF"
        // Workaround used by every rbw + TouchID setup in the wild: do the
        // initial login with pinentry-mac directly, then swap to pinentry-touchid
        // for subsequent unlocks (which is where the TouchID gating actually
        // matters). Override unconditionally — any prior partial run may have
        // left pinentry=pinentry-touchid in rbw config.
        let _ = Command::new("rbw")
            .arg("config")
            .arg("set")
            .arg("pinentry")
            .arg("pinentry-mac")
            .output()
            .await;
        println!("  → Running `rbw login` via pinentry-mac (one-time bootstrap)...");
        let status = Command::new("rbw")
            .arg("login")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .map_err(|e| CliError::Internal(format!("rbw login: {e}")))?;
        if !status.success() {
            // Restore pinentry-touchid so the next `envs init` retry doesn't
            // start from an inconsistent rbw config.
            let _ = Command::new("rbw")
                .arg("config")
                .arg("set")
                .arg("pinentry")
                .arg("pinentry-touchid")
                .output()
                .await;
            return Err(CliError::BadArgs(
                "rbw login failed — re-run `envs init` once you have your master password".into(),
            ));
        }
        println!("  ✓ rbw login successful");
    }

    // Login is done (or was already done). Now bind pinentry-touchid for the
    // hot path — `rbw unlock` from the daemon's auto-unlock will TouchID-gate
    // each unlock and cache the master password in macOS Keychain.
    let _ = Command::new("rbw")
        .arg("config")
        .arg("set")
        .arg("pinentry")
        .arg("pinentry-touchid")
        .output()
        .await;
    println!("  ✓ rbw bound to pinentry-touchid for unlocks");

    println!("\n[5/6] LaunchAgent for envsd...");
    match install_launch_agent(force).await {
        Ok(InstallResult::Installed(path)) => println!("  ✓ installed at {}", path.display()),
        Ok(InstallResult::AlreadyInstalled(path)) => {
            println!("  ✓ already installed at {}", path.display())
        }
        Ok(InstallResult::EnvsdNotFound) => {
            println!("  ! envsd binary not found on PATH");
            println!("    Run: cargo install --path crates/envs-daemon");
            println!("    Then re-run: envs init");
        }
        Err(e) => println!("  ✗ {e}"),
    }

    println!("\n[6/6] Registry sync...");
    match sync_registry().await {
        Ok(msg) => println!("  ✓ {msg}"),
        Err(e) => println!("  ! {e} (you can run `envs registry sync` later)"),
    }

    println!("\nSetup complete. envs auto-locks rbw between every resolve;");
    println!("the first cold call will trigger pinentry-touchid (TouchID).");
    println!("Try: envs daemon status");
    Ok(())
}

/// Probe `brew --version`. Network-free.
async fn brew_available() -> bool {
    Command::new("brew")
        .arg("--version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run `brew install <pkg>` if `<bin>` is not on PATH. Streams brew's output
/// directly so the user sees download progress.
async fn ensure_brew_pkg(bin: &str, brew_pkg: &str) -> Result<()> {
    let already = Command::new(bin)
        .arg("--version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if already {
        return Ok(());
    }
    println!("  → installing via `brew install {brew_pkg}`...");
    let status = Command::new("brew")
        .arg("install")
        .arg(brew_pkg)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .map_err(|e| CliError::Internal(format!("brew install: {e}")))?;
    if !status.success() {
        return Err(CliError::BadArgs(format!(
            "brew install {brew_pkg} failed — re-run `envs init` after fixing it"
        )));
    }
    Ok(())
}

fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    print!("{prompt}");
    std::io::stdout().flush()?;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim().to_string();
    if trimmed.is_empty() {
        return Err(CliError::BadArgs("empty input".into()));
    }
    Ok(trimmed)
}

/// Like `prompt_line`, but returns `default` when the user just presses Enter.
fn prompt_line_with_default(prompt: &str, default: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    print!("{prompt}");
    std::io::stdout().flush()?;
    let stdin = std::io::stdin();
    let mut line = String::new();
    stdin.lock().read_line(&mut line)?;
    let trimmed = line.trim();
    if trimmed.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(trimmed.to_string())
    }
}

/// Parse `rbw config show` into a key→value map. Output is loose `key: value`
/// lines, one per setting. Missing/unset fields are simply absent from the map.
async fn read_rbw_config() -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Ok(o) = Command::new("rbw").arg("config").arg("show").output().await else {
        return out;
    };
    if !o.status.success() {
        return out;
    }
    for line in String::from_utf8_lossy(&o.stdout).lines() {
        // rbw 1.x prints either `key: value` (toml-ish) or JSON depending on
        // version. Handle both: split on the first ':' for the loose form,
        // and try a JSON object parse as a fallback.
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().trim_matches('"').to_string();
            let val = v.trim().trim_matches(',').trim_matches('"').to_string();
            if !key.is_empty() && !val.is_empty() && val != "null" {
                out.insert(key, val);
            }
        }
    }
    out
}

/// Run `rbw config set <key> <value>`, mapping non-zero exit to a clear error.
async fn rbw_config_set(key: &str, value: &str) -> Result<()> {
    let out = Command::new("rbw")
        .arg("config")
        .arg("set")
        .arg(key)
        .arg(value)
        .output()
        .await
        .map_err(|e| CliError::Internal(format!("rbw config set {key}: {e}")))?;
    if !out.status.success() {
        return Err(CliError::Internal(format!(
            "rbw config set {key} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

enum InstallResult {
    Installed(std::path::PathBuf),
    AlreadyInstalled(std::path::PathBuf),
    EnvsdNotFound,
}

async fn install_launch_agent(force: bool) -> Result<InstallResult> {
    let envsd_path = match find_envsd_on_path().await {
        Some(p) => p,
        None => return Ok(InstallResult::EnvsdNotFound),
    };
    let home =
        dirs::home_dir().ok_or_else(|| crate::error::CliError::Internal("no home dir".into()))?;
    let agents_dir = home.join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&agents_dir)?;
    let plist_path = agents_dir.join("com.fgribreau.envsd.plist");

    if plist_path.exists() && !force {
        return Ok(InstallResult::AlreadyInstalled(plist_path));
    }

    let template = include_str!("../../../../packaging/com.fgribreau.envsd.plist.template");
    let plist = template
        .replace("{ENVSD_PATH}", &envsd_path.to_string_lossy())
        .replace("{HOME}", &home.to_string_lossy());
    std::fs::write(&plist_path, plist)?;

    // Bootstrap the LaunchAgent.
    let uid = unsafe { libc::getuid() };
    let _ = Command::new("launchctl")
        .arg("bootstrap")
        .arg(format!("gui/{uid}"))
        .arg(&plist_path)
        .output()
        .await;

    Ok(InstallResult::Installed(plist_path))
}

/// True if rbw's encrypted vault DB is on disk — proof that `rbw login`
/// completed at least once. The DB lives in
/// `$XDG_DATA_HOME/rbw/db.<email>.json` (default `~/.local/share/rbw/`).
fn rbw_db_exists() -> bool {
    let base = std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .or_else(|| dirs::home_dir().map(|h| h.join(".local").join("share")));
    let Some(dir) = base.map(|b| b.join("rbw")) else {
        return false;
    };
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    entries.flatten().any(|e| {
        let name = e.file_name();
        let s = name.to_string_lossy();
        s.starts_with("db.") && s.ends_with(".json")
    })
}

async fn find_envsd_on_path() -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("envsd");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

async fn sync_registry() -> std::result::Result<String, String> {
    // Delegate to envsd via UDS, OR run git directly here. For init wizard simplicity,
    // we run git directly (daemon may not be up yet).
    let home = dirs::home_dir().ok_or_else(|| "no home dir".to_string())?;
    let dir = home.join(".envs").join("registry");
    if dir.join(".git").is_dir() {
        let out = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .arg("pull")
            .arg("--ff-only")
            .arg("--quiet")
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "git pull: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(format!("registry up to date at {}", dir.display()))
    } else {
        let out = Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("--quiet")
            .arg("https://github.com/fgribreau/envs-registry.git")
            .arg(&dir)
            .output()
            .await
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            // Likely the repo doesn't exist yet (we're shipping v0.1). Just create the dir.
            std::fs::create_dir_all(&dir).ok();
            return Ok(format!(
                "registry repo not yet available; created empty {}",
                dir.display()
            ));
        }
        Ok(format!("registry cloned to {}", dir.display()))
    }
}
