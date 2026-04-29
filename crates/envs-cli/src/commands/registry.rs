//! `envs registry` — sync + lookup the community binary registry.
//!
//! Single source of truth: github.com/fgribreau/envs-registry. Cloned on
//! first sync into `~/.envs/registry/`, refreshed via fast-forward `git pull`
//! on subsequent syncs. The daemon also pulls lazily when the local clone is
//! older than 7 days, but `envs registry sync` lets the user force-refresh.

use crate::error::{CliError, Result};
use serde::Deserialize;
use std::path::PathBuf;
use tokio::process::Command;

const REGISTRY_REPO: &str = "https://github.com/fgribreau/envs-registry.git";

pub async fn execute(action: super::super::RegistryAction) -> Result<()> {
    use super::super::RegistryAction;
    match action {
        RegistryAction::Sync => sync().await,
        RegistryAction::Show { binary } => show(&binary).await,
    }
}

fn registry_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().ok_or_else(|| CliError::Internal("no home dir".into()))?;
    Ok(home.join(".envs").join("registry"))
}

async fn sync() -> Result<()> {
    let dir = registry_dir()?;
    if let Some(parent) = dir.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if dir.join(".git").is_dir() {
        let out = Command::new("git")
            .arg("-C")
            .arg(&dir)
            .arg("pull")
            .arg("--ff-only")
            .arg("--quiet")
            .output()
            .await
            .map_err(|e| CliError::Internal(format!("git pull: {e}")))?;
        if !out.status.success() {
            return Err(CliError::Internal(format!(
                "git pull failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        // Refresh the daemon's freshness marker so it doesn't re-pull on next resolve.
        let _ = std::fs::write(dir.join(".last_pull"), "");
        println!("✓ registry up to date at {}", dir.display());
    } else {
        let out = Command::new("git")
            .arg("clone")
            .arg("--depth")
            .arg("1")
            .arg("--quiet")
            .arg(REGISTRY_REPO)
            .arg(&dir)
            .output()
            .await
            .map_err(|e| CliError::Internal(format!("git clone: {e}")))?;
        if !out.status.success() {
            return Err(CliError::Internal(format!(
                "git clone failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        let _ = std::fs::write(dir.join(".last_pull"), "");
        println!("✓ registry cloned to {}", dir.display());
    }
    Ok(())
}

async fn show(binary: &str) -> Result<()> {
    let dir = registry_dir()?;
    let path = dir.join("binaries").join(format!("{binary}.toml"));
    if !path.is_file() {
        return Err(CliError::BadArgs(format!(
            "no registry entry for {binary} at {} — run `envs registry sync` first or check the spelling",
            path.display()
        )));
    }
    let content = std::fs::read_to_string(&path)?;
    let entry: RegistryEntry = toml::from_str(&content)?;

    println!("binary: {}", entry.binary.name);
    if let Some(d) = &entry.binary.description {
        println!("  description: {d}");
    }
    if let Some(h) = &entry.binary.homepage {
        println!("  homepage:    {h}");
    }
    if let Some(b) = &entry.binary.brew_formula {
        println!("  brew:        {b}");
    }
    if !entry.binary.codesign_team_ids.is_empty() {
        println!(
            "  codesign:    {}",
            entry.binary.codesign_team_ids.join(", ")
        );
    }
    if !entry.binary.suggested_paths.is_empty() {
        let paths: Vec<String> = entry
            .binary
            .suggested_paths
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        println!("  paths:       {}", paths.join(", "));
    }
    if entry.env_vars.is_empty() {
        println!("\nenv vars: (none declared)");
    } else {
        println!("\nenv vars:");
        for ev in &entry.env_vars {
            let req = if ev.required { " required" } else { "" };
            let dep = if ev.deprecated { " deprecated" } else { "" };
            print!("  - {}{req}{dep}", ev.name);
            if let Some(src) = &ev.recommended_source {
                print!(" ← {src}");
            }
            println!();
            if let Some(d) = &ev.description {
                println!("      {d}");
            }
        }
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
struct RegistryEntry {
    #[serde(default)]
    binary: BinaryMeta,
    #[serde(default, rename = "env_var")]
    env_vars: Vec<EnvVarEntry>,
}

#[derive(Debug, Deserialize, Default)]
struct BinaryMeta {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    homepage: Option<String>,
    #[serde(default)]
    codesign_team_ids: Vec<String>,
    #[serde(default)]
    brew_formula: Option<String>,
    #[serde(default)]
    suggested_paths: Vec<PathBuf>,
}

#[derive(Debug, Deserialize)]
struct EnvVarEntry {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    recommended_source: Option<String>,
    #[serde(default)]
    deprecated: bool,
}
