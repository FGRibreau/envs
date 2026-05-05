//! `envs doctor` — non-modifying diagnostic checks.

use crate::client;
use crate::error::Result;
use envs_proto::{Request, Response};
use std::path::PathBuf;
use tokio::process::Command;

pub async fn execute() -> Result<()> {
    println!("envs doctor — diagnostics\n");

    print_check("rbw installed", check_rbw_installed().await);
    print_check(
        "pinentry-touchid installed",
        check_pinentry_installed().await,
    );
    print_check(
        "rbw uses pinentry-touchid",
        check_rbw_pinentry_configured().await,
    );
    print_check("rbw vault state", check_rbw_state().await);
    print_check("~/.envs/ exists", check_envs_dir());
    print_check("envsd socket present", check_socket_present().await);
    print_check("envsd reachable (Ping)", check_daemon_ping().await);
    print_check("Xcode CLI tools", check_xcode_cli().await);

    Ok(())
}

async fn check_pinentry_installed() -> std::result::Result<String, String> {
    // pinentry-touchid (jorgelbg/tap, Go binary) doesn't implement `--version`;
    // it exits 2 with "flag provided but not defined: -version". Use the
    // self-test flag `-check` instead — it returns 0 when pinentry-mac
    // (the real prompter pinentry-touchid wraps) is reachable, which is
    // exactly what we want to verify.
    let probe = Command::new("pinentry-touchid")
        .arg("-check")
        .output()
        .await;
    match probe {
        Ok(o) if o.status.success() => {
            // Resolve the binary path for the friendly success line.
            let path = Command::new("which")
                .arg("pinentry-touchid")
                .output()
                .await
                .ok()
                .map(|w| String::from_utf8_lossy(&w.stdout).trim().to_string())
                .unwrap_or_else(|| "pinentry-touchid".into());
            Ok(path)
        }
        Ok(o) => Err(format!(
            "pinentry-touchid -check failed: {}",
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(_) => Err(
            "pinentry-touchid not on PATH (try: brew install jorgelbg/tap/pinentry-touchid)".into(),
        ),
    }
}

async fn check_rbw_pinentry_configured() -> std::result::Result<String, String> {
    // rbw 1.x emits its config as pretty-printed JSON, not toml-ish key=value
    // lines. Parse properly so `"pinentry": "pinentry-touchid"` matches.
    let output = Command::new("rbw").arg("config").arg("show").output().await;
    let stdout = match output {
        Ok(o) if o.status.success() => o.stdout,
        _ => return Err("rbw config show failed".into()),
    };
    let parsed: serde_json::Value = match serde_json::from_slice(&stdout) {
        Ok(v) => v,
        Err(e) => return Err(format!("rbw config show: not JSON ({e})")),
    };
    let pinentry = parsed
        .get("pinentry")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    if pinentry == "pinentry-touchid" {
        Ok(format!("pinentry = {pinentry}"))
    } else if pinentry.is_empty() {
        Err("pinentry field absent in rbw config".into())
    } else {
        Err(format!(
            "pinentry = {pinentry} (try: rbw config set pinentry pinentry-touchid)"
        ))
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

/// Vault state is informational: envsd auto-locks rbw between every resolve,
/// so "locked" is the expected steady state — flagging it as a failure would
/// scare users about a system working as designed. The only real failure
/// here is rbw being missing entirely (handled separately by `rbw installed`).
async fn check_rbw_state() -> std::result::Result<String, String> {
    let out = Command::new("rbw").arg("unlocked").output().await;
    match out {
        Ok(o) if o.status.success() => Ok("unlocked".into()),
        Ok(_) => Ok("locked (envsd will auto-unlock on the next resolve)".into()),
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
