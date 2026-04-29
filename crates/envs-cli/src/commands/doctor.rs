//! `envs doctor` — non-modifying diagnostic checks.

use crate::client;
use crate::error::Result;
use envs_proto::{Request, Response};
use std::path::PathBuf;
use tokio::process::Command;

pub async fn execute() -> Result<()> {
    println!("envs doctor — diagnostics\n");

    print_check("rbw installed", check_rbw_installed().await);
    print_check("pinentry-touchid installed", check_pinentry_installed().await);
    print_check(
        "rbw uses pinentry-touchid",
        check_rbw_pinentry_configured().await,
    );
    print_check("rbw unlocked", check_rbw_unlocked().await);
    print_check("~/.envs/ exists", check_envs_dir());
    print_check("envsd socket present", check_socket_present().await);
    print_check("envsd reachable (Ping)", check_daemon_ping().await);
    print_check("Xcode CLI tools", check_xcode_cli().await);

    Ok(())
}

async fn check_pinentry_installed() -> std::result::Result<String, String> {
    let output = Command::new("pinentry-touchid").arg("--version").output().await;
    match output {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Ok(_) => Err("pinentry-touchid exited non-zero".into()),
        Err(_) => Err("pinentry-touchid not on PATH (try: brew install jorgelbg/tap/pinentry-touchid)".into()),
    }
}

async fn check_rbw_pinentry_configured() -> std::result::Result<String, String> {
    let output = Command::new("rbw").arg("config").arg("show").output().await;
    match output {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            let line = text
                .lines()
                .find(|l| l.trim().starts_with("pinentry"))
                .unwrap_or("");
            if line.contains("pinentry-touchid") {
                Ok(line.trim().to_string())
            } else {
                Err("pinentry not set to pinentry-touchid (try: rbw config set pinentry pinentry-touchid)".into())
            }
        }
        _ => Err("rbw config show failed".into()),
    }
}

async fn check_rbw_installed() -> std::result::Result<String, String> {
    let output = Command::new("rbw").arg("--version").output().await;
    match output {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
        Ok(_) => Err("rbw is on PATH but exited non-zero".into()),
        Err(_) => Err("rbw not found on PATH (try: brew install rbw)".into()),
    }
}

async fn check_rbw_unlocked() -> std::result::Result<String, String> {
    let status = Command::new("rbw").arg("unlocked").status().await;
    match status {
        Ok(s) if s.success() => Ok("vault is unlocked".into()),
        Ok(_) => Err("vault is locked — run `rbw unlock`".into()),
        Err(_) => Err("rbw not available".into()),
    }
}

fn check_envs_dir() -> std::result::Result<String, String> {
    let home = dirs::home_dir().ok_or_else(|| "no home dir".to_string())?;
    let dir = home.join(".envs");
    if !dir.is_dir() {
        return Err(format!("{} does not exist", dir.display()));
    }
    Ok(dir.display().to_string())
}

async fn check_socket_present() -> std::result::Result<String, String> {
    let path = socket_path().map_err(|e| e.to_string())?;
    if path.exists() {
        Ok(path.display().to_string())
    } else {
        Err(format!(
            "{} not found — daemon may not be running",
            path.display()
        ))
    }
}

async fn check_daemon_ping() -> std::result::Result<String, String> {
    match client::send_request(&Request::Ping).await {
        Ok(Response::Pong) => Ok("Pong received".into()),
        Ok(other) => Err(format!("unexpected response: {other:?}")),
        Err(e) => Err(format!("{e}")),
    }
}

async fn check_xcode_cli() -> std::result::Result<String, String> {
    let output = Command::new("xcode-select").arg("-p").output().await;
    match output {
        Ok(o) if o.status.success() => Ok(String::from_utf8_lossy(&o.stdout).trim().to_string()),
        _ => Err("xcode-select -p failed".into()),
    }
}

fn socket_path() -> Result<PathBuf> {
    client::socket_path()
}

fn print_check(label: &str, result: std::result::Result<String, String>) {
    match result {
        Ok(detail) => println!("  ✓ {label:30} {detail}"),
        Err(detail) => println!("  ✗ {label:30} {detail}"),
    }
}
