//! `envs run` — resolve secrets via daemon and execvpe the target.

use crate::client;
use crate::error::{CliError, Result};
use crate::exec;
use crate::manifest;
use envs_proto::{Binding, Request, Response};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use tokio::process::Command;

pub async fn execute(argv: Vec<String>, profiles: &[String], binds: &[String]) -> Result<()> {
    if argv.is_empty() {
        return Err(CliError::NothingToRun);
    }

    // Parse `--bind KEY=rbw://item/field` flags into Binding structs.
    let extra_bindings = parse_bindings(binds)?;

    // Interactive session check (envs is interactive-only).
    if !is_interactive() {
        return Err(CliError::NonInteractive);
    }

    // Resolve binary path: absolute, relative, or PATH lookup.
    let cmd_arg = &argv[0];
    let bin_path = resolve_binary_path(cmd_arg)?;
    let canon_path = std::fs::canonicalize(&bin_path)
        .map_err(|e| CliError::Internal(format!("canonicalize {}: {e}", bin_path.display())))?;

    let sha256 = sha256_of_file(&canon_path)?;
    let codesign_team = extract_codesign_team(&canon_path).await;

    let cwd = std::env::current_dir()?;
    let project_root = manifest::find_project_root(&cwd);
    let pid = std::process::id() as i32;

    let req = Request::Resolve {
        canon_path: canon_path.clone(),
        sha256,
        codesign_team,
        argv: argv.clone(),
        cwd,
        project_root,
        client_pid: pid,
        profiles: profiles.to_vec(),
        extra_bindings,
    };

    let resp = client::send_request(&req).await?;
    let entries = match resp {
        Response::Resolved { entries, .. } => entries,
        other => {
            return Err(CliError::Internal(format!(
                "unexpected daemon response: {other:?}"
            )))
        }
    };

    let injected: Vec<(String, secrecy::SecretString)> = entries
        .into_iter()
        .map(|e| (e.key, secrecy::SecretString::new(e.value.into())))
        .collect();
    let env = exec::build_env(&injected);

    let argv0 =
        exec::cstring(canon_path.to_str().ok_or_else(|| {
            CliError::Internal(format!("non-utf8 path: {}", canon_path.display()))
        })?)?;
    let args = exec::cstrings(argv.iter().map(String::as_str))?;

    let _: std::convert::Infallible = exec::run(exec::ExecArgs { argv0, args, env })?;
    unreachable!("execve replaces the current process on success")
}

/// Parse `--bind KEY=rbw://item/field` strings into `Binding` structs.
/// Errors fail-fast — invalid syntax is a CliError::Internal.
fn parse_bindings(binds: &[String]) -> Result<Vec<Binding>> {
    binds
        .iter()
        .map(|s| {
            let (env, source) = s.split_once('=').ok_or_else(|| {
                CliError::Internal(format!(
                    "bad --bind syntax: '{s}' — expected KEY=rbw://item/field"
                ))
            })?;
            if env.is_empty() {
                return Err(CliError::Internal(format!(
                    "--bind has empty env var name: '{s}'"
                )));
            }
            if !source.starts_with("rbw://") {
                return Err(CliError::Internal(format!(
                    "--bind source must start with rbw://: '{s}'"
                )));
            }
            Ok(Binding {
                env: env.to_string(),
                source: source.to_string(),
            })
        })
        .collect()
}

fn is_interactive() -> bool {
    // Allow bypass for testing.
    if std::env::var_os("ENVS_NONINTERACTIVE_OK").is_some() {
        return true;
    }
    // Heuristic: stdin is a tty OR DISPLAY/SSH_TTY suggests an interactive context.
    use nix::unistd::isatty;
    if let Ok(true) = isatty(0) {
        return true;
    }
    // Fallback: if envsd is reachable AND we have a controlling terminal env,
    // accept. macOS GUI apps may not have isatty(0) but have a session.
    std::env::var_os("TERM").is_some()
}

fn resolve_binary_path(arg: &str) -> Result<PathBuf> {
    let p = Path::new(arg);
    if p.is_absolute() || arg.contains('/') {
        if !p.exists() {
            return Err(CliError::CommandNotFound(arg.into()));
        }
        return Ok(p.to_path_buf());
    }
    let path_var = std::env::var_os("PATH").unwrap_or_default();
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(arg);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }
    Err(CliError::CommandNotFound(arg.into()))
}

fn sha256_of_file(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

async fn extract_codesign_team(path: &Path) -> Option<String> {
    let output = Command::new("codesign")
        .arg("-dv")
        .arg("--verbose=4")
        .arg(path)
        .output()
        .await
        .ok()?;
    // codesign prints to stderr.
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Look for "TeamIdentifier=XXXXXXXXXX" or "Authority=Developer ID ... (TEAMID)"
    for line in combined.lines() {
        if let Some(rest) = line.strip_prefix("TeamIdentifier=") {
            let team = rest.trim();
            if !team.is_empty() && team != "not set" {
                return Some(team.to_string());
            }
        }
    }
    None
}
