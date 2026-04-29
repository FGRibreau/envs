//! `envs init` — bootstrap wizard (idempotent, rejouable).

use crate::error::{CliError, Result};
use tokio::process::Command;

pub async fn execute(force: bool) -> Result<()> {
    println!("envs setup wizard\n");

    println!("[1/6] Checking rbw...");
    let rbw_ok = Command::new("rbw")
        .arg("--version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if rbw_ok {
        println!("  ✓ rbw is installed");
    } else {
        println!("  ✗ rbw is not installed");
        println!("  → Run: brew install rbw");
        println!("  (This wizard does not auto-install brew packages — run the brew command yourself, then re-run `envs init`.)");
        return Ok(());
    }

    println!("\n[2/6] Checking rbw login state...");
    let logged_in = Command::new("rbw")
        .arg("config")
        .arg("show")
        .output()
        .await
        .map(|o| o.status.success() && !o.stdout.is_empty())
        .unwrap_or(false);
    if logged_in && !force {
        println!("  ✓ rbw is configured");
    } else {
        println!("  ! rbw is not configured (or --force was used)");
        println!("  → Run: rbw config set email <your-email>");
        println!("  → Then: rbw login");
    }

    println!("\n[3/6] Checking pinentry-touchid...");
    // pinentry-touchid is a hard prerequisite: envs auto-locks rbw between
    // resolves and re-unlocks it on demand. Without pinentry-touchid the user
    // would type their master password at every cold call — defeats the UX.
    let pinentry_ok = Command::new("pinentry-touchid")
        .arg("--version")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !pinentry_ok {
        println!("  ✗ pinentry-touchid is not installed");
        println!("  → Run: brew install jorgelbg/tap/pinentry-touchid");
        println!("  → Then: rbw config set pinentry pinentry-touchid");
        println!("  (envs auto-locks rbw between resolves; without pinentry-touchid every cold call asks for your master password)");
        return Err(CliError::BadArgs(
            "pinentry-touchid is required — install it then re-run `envs init`".into(),
        ));
    }
    println!("  ✓ pinentry-touchid is installed");
    let pinentry_configured = Command::new("rbw")
        .arg("config")
        .arg("show")
        .output()
        .await
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .any(|l| l.trim().starts_with("pinentry") && l.contains("pinentry-touchid"))
        })
        .unwrap_or(false);
    if pinentry_configured {
        println!("  ✓ rbw is configured to use pinentry-touchid");
    } else {
        println!("  ! rbw is not configured to use pinentry-touchid");
        println!("  → Run: rbw config set pinentry pinentry-touchid");
        return Err(CliError::BadArgs(
            "rbw must be configured to use pinentry-touchid — see `envs doctor`".into(),
        ));
    }

    println!("\n[4/6] Checking rbw unlock state...");
    let unlocked = Command::new("rbw")
        .arg("unlocked")
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false);
    if unlocked {
        println!("  ✓ vault is unlocked (envs will lock it again after each resolve)");
    } else {
        println!("  ! vault is locked (envs will auto-unlock on the first call)");
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

    println!("\nSetup complete. Next steps:");
    println!("  - The envsd daemon should be running (check: envs daemon status)");
    println!("  - Try: envs flarectl --help (or any tool you've authorized)");
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
