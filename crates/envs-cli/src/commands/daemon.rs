//! `envs daemon` — lifecycle commands.

use crate::client;
use crate::error::{CliError, Result};
use envs_proto::{Request, Response};
use std::path::PathBuf;
use tokio::process::Command;

pub async fn execute(action: super::super::DaemonAction) -> Result<()> {
    use super::super::DaemonAction;
    match action {
        DaemonAction::Start => start().await,
        DaemonAction::Stop => stop().await,
        DaemonAction::Restart => {
            stop().await.ok();
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            start().await
        }
        DaemonAction::Status => status().await,
        DaemonAction::Install => install_launch_agent(false).await,
        DaemonAction::Uninstall => uninstall_launch_agent().await,
    }
}

fn launch_agent_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| CliError::Internal("no home dir".into()))?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join("com.fgribreau.envsd.plist"))
}

fn pid_file_path() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| CliError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("envsd.pid"))
}

async fn find_envsd() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join("envsd");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

async fn start() -> Result<()> {
    // If LaunchAgent installed, prefer that path (it manages restarts).
    let plist = launch_agent_path()?;
    if plist.exists() {
        let uid = unsafe { libc::getuid() };
        let out = Command::new("launchctl")
            .arg("kickstart")
            .arg("-k")
            .arg(format!("gui/{uid}/com.fgribreau.envsd"))
            .output()
            .await?;
        if out.status.success() {
            println!("✓ envsd kickstarted via LaunchAgent");
            return Ok(());
        }
        println!("⚠ launchctl kickstart failed; falling back to direct spawn");
    }

    // Direct spawn
    let envsd = find_envsd().await.ok_or_else(|| {
        CliError::Internal("envsd not on PATH. Run: cargo install --path crates/envs-daemon".into())
    })?;
    let log_dir = dirs::home_dir()
        .ok_or_else(|| CliError::Internal("no home dir".into()))?
        .join(".envs")
        .join("logs");
    std::fs::create_dir_all(&log_dir).ok();

    use std::process::{Command as StdCommand, Stdio};
    let stdout_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("envsd.stdout.log"))?;
    let stderr_log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_dir.join("envsd.stderr.log"))?;
    let child = StdCommand::new(&envsd)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout_log))
        .stderr(Stdio::from(stderr_log))
        .spawn()
        .map_err(|e| CliError::Internal(format!("spawn envsd: {e}")))?;

    // Write PID for `envs daemon stop`.
    let pid_path = pid_file_path()?;
    if let Some(parent) = pid_path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&pid_path, child.id().to_string()).ok();

    println!("✓ envsd spawned (pid {})", child.id());
    println!("  logs: {}/envsd.{{stdout,stderr}}.log", log_dir.display());
    Ok(())
}

async fn stop() -> Result<()> {
    let plist = launch_agent_path()?;
    if plist.exists() {
        let uid = unsafe { libc::getuid() };
        let out = Command::new("launchctl")
            .arg("kill")
            .arg("SIGTERM")
            .arg(format!("gui/{uid}/com.fgribreau.envsd"))
            .output()
            .await?;
        if out.status.success() {
            println!("✓ envsd SIGTERM sent via LaunchAgent");
            return Ok(());
        }
    }

    // Direct: read pid file, send SIGTERM
    let pid_path = pid_file_path()?;
    if !pid_path.exists() {
        println!(
            "(no pid file at {} — daemon may not be running)",
            pid_path.display()
        );
        return Ok(());
    }
    let pid_str = std::fs::read_to_string(&pid_path)?;
    let pid: i32 = pid_str
        .trim()
        .parse()
        .map_err(|e| CliError::Internal(format!("bad pid file: {e}")))?;
    use nix::sys::signal::{kill, Signal};
    use nix::unistd::Pid;
    match kill(Pid::from_raw(pid), Signal::SIGTERM) {
        Ok(()) => {
            println!("✓ SIGTERM sent to envsd (pid {pid})");
            std::fs::remove_file(&pid_path).ok();
            Ok(())
        }
        Err(nix::errno::Errno::ESRCH) => {
            println!("(pid {pid} not running — clearing stale pid file)");
            std::fs::remove_file(&pid_path).ok();
            Ok(())
        }
        Err(e) => Err(CliError::Internal(format!("kill {pid}: {e}"))),
    }
}

async fn status() -> Result<()> {
    match client::send_request(&Request::Status).await {
        Ok(Response::Status {
            version,
            protocol,
            cache_entries,
            rules_count,
            rbw_unlocked,
            uptime_secs,
        }) => {
            println!("envsd status:");
            println!("  version:        {version}");
            println!("  protocol:       v{protocol}");
            println!("  rules active:   {rules_count}");
            println!("  cache entries:  {cache_entries}");
            println!("  rbw unlocked:   {rbw_unlocked}");
            println!("  uptime:         {uptime_secs}s");
            Ok(())
        }
        Ok(other) => {
            println!("(unexpected response: {other:?})");
            Ok(())
        }
        Err(CliError::DaemonNotRunning) => {
            println!("✗ daemon not running. Try `envs daemon start` or `envs init`.");
            Ok(())
        }
        Err(e) => {
            println!("✗ {e}");
            Ok(())
        }
    }
}

async fn install_launch_agent(force: bool) -> Result<()> {
    let envsd = find_envsd().await.ok_or_else(|| {
        CliError::Internal("envsd not on PATH. Run: cargo install --path crates/envs-daemon".into())
    })?;
    let home = dirs::home_dir().ok_or_else(|| CliError::Internal("no home dir".into()))?;
    let agents_dir = home.join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&agents_dir)?;
    let plist_path = agents_dir.join("com.fgribreau.envsd.plist");

    if plist_path.exists() && !force {
        println!("✓ already installed at {}", plist_path.display());
        return Ok(());
    }

    let template = include_str!("../../../../packaging/com.fgribreau.envsd.plist.template");
    let plist = template
        .replace("{ENVSD_PATH}", &envsd.to_string_lossy())
        .replace("{HOME}", &home.to_string_lossy());
    std::fs::write(&plist_path, plist)?;
    println!("✓ wrote {}", plist_path.display());

    let uid = unsafe { libc::getuid() };
    let out = Command::new("launchctl")
        .arg("bootstrap")
        .arg(format!("gui/{uid}"))
        .arg(&plist_path)
        .output()
        .await?;
    if out.status.success() {
        println!("✓ launchctl bootstrap succeeded — envsd will start at login + run now");
    } else {
        println!(
            "⚠ launchctl bootstrap exit={:?}; stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
        println!("  (it may already be loaded — try: envs daemon status)");
    }
    Ok(())
}

async fn uninstall_launch_agent() -> Result<()> {
    let plist_path = launch_agent_path()?;
    if !plist_path.exists() {
        println!("(no LaunchAgent installed at {})", plist_path.display());
        return Ok(());
    }

    let uid = unsafe { libc::getuid() };
    let _ = Command::new("launchctl")
        .arg("bootout")
        .arg(format!("gui/{uid}/com.fgribreau.envsd"))
        .output()
        .await;
    std::fs::remove_file(&plist_path).ok();
    println!("✓ uninstalled LaunchAgent + removed plist");
    Ok(())
}
