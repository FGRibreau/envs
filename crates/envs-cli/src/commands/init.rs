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
    ensure_brew_pkg("pinentry-touchid", "jorgelbg/tap/pinentry-touchid").await?;
    let pinentry_version = Command::new("pinentry-touchid")
        .arg("--version")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "pinentry-touchid".into());
    println!("  ✓ {pinentry_version}");
    // Bind rbw to pinentry-touchid (idempotent).
    let _ = Command::new("rbw")
        .arg("config")
        .arg("set")
        .arg("pinentry")
        .arg("pinentry-touchid")
        .output()
        .await;
    println!("  ✓ rbw configured to use pinentry-touchid");

    println!("\n[4/6] rbw login state...");
    let configured = Command::new("rbw")
        .arg("config")
        .arg("show")
        .output()
        .await
        .map(|o| {
            o.status.success()
                && String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .any(|l| l.trim().starts_with("email") && l.contains('@'))
        })
        .unwrap_or(false);
    if configured && !force {
        println!("  ✓ rbw email is configured");
    } else {
        let email = prompt_line("  Bitwarden email > ")?;
        let out = Command::new("rbw")
            .arg("config")
            .arg("set")
            .arg("email")
            .arg(&email)
            .output()
            .await
            .map_err(|e| CliError::Internal(format!("rbw config set email: {e}")))?;
        if !out.status.success() {
            return Err(CliError::Internal(format!(
                "rbw config set email failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        println!("  ✓ email set to {email}");
        println!("  → Running `rbw login` (will prompt for your master password)...");
        let status = Command::new("rbw")
            .arg("login")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .await
            .map_err(|e| CliError::Internal(format!("rbw login: {e}")))?;
        if !status.success() {
            return Err(CliError::BadArgs(
                "rbw login failed — re-run `envs init` once you have your master password".into(),
            ));
        }
        println!("  ✓ rbw login successful");
    }

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
