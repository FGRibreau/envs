//! `envs project` — manage project-local profiles in `.envs/`.

use crate::error::{CliError, Result};
use crate::manifest;
use std::io::Write;

pub async fn execute(action: super::super::ProjectAction) -> Result<()> {
    use super::super::ProjectAction;
    match action {
        ProjectAction::Init => init().await,
        ProjectAction::Show => show().await,
        ProjectAction::Link { global, binary } => link(global, binary).await,
    }
}

async fn link(to_global: bool, binary: String) -> Result<()> {
    use std::path::PathBuf;
    let cwd = std::env::current_dir()?;
    let project_root = manifest::find_project_root(&cwd);
    let home = dirs::home_dir().ok_or_else(|| CliError::Internal("no home dir".into()))?;

    let project_path = project_root
        .as_ref()
        .map(|r| r.join(".envs").join(format!("{binary}.toml")));
    let global_path: PathBuf = home
        .join(".envs")
        .join("profiles")
        .join(format!("{binary}.toml"));

    if to_global {
        // Promote project → global
        let pp = project_path.as_ref().ok_or_else(|| {
            CliError::BadArgs(
                "no project root detected (no .envs/ ancestor) — nothing to promote".into(),
            )
        })?;
        if !pp.is_file() {
            return Err(CliError::BadArgs(format!(
                "project profile not found at {}",
                pp.display()
            )));
        }
        if global_path.exists() {
            return Err(CliError::BadArgs(format!(
                "global profile already exists at {} — refusing to overwrite",
                global_path.display()
            )));
        }
        if let Some(parent) = global_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(pp, &global_path)?;
        println!("✓ promoted: {} → {}", pp.display(), global_path.display());
        Ok(())
    } else {
        // Demote global → project
        let pp = project_path.ok_or_else(|| {
            CliError::BadArgs(
                "no project root detected (no .envs/ ancestor) — run `envs project init` first"
                    .into(),
            )
        })?;
        if !global_path.is_file() {
            return Err(CliError::BadArgs(format!(
                "global profile not found at {}",
                global_path.display()
            )));
        }
        if pp.exists() {
            return Err(CliError::BadArgs(format!(
                "project profile already exists at {} — refusing to overwrite",
                pp.display()
            )));
        }
        if let Some(parent) = pp.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&global_path, &pp)?;
        println!("✓ demoted: {} → {}", global_path.display(), pp.display());
        Ok(())
    }
}

async fn init() -> Result<()> {
    let cwd = std::env::current_dir()?;
    let envs_dir = cwd.join(".envs");
    if envs_dir.exists() {
        println!("✓ .envs/ already exists at {}", envs_dir.display());
    } else {
        std::fs::create_dir_all(&envs_dir)?;
        let readme = envs_dir.join("README.md");
        std::fs::write(
            &readme,
            "# envs project profile\n\n\
             This directory holds per-binary profiles for `envs`. Each `<binary>.toml` declares which Bitwarden vault items map to which env vars for that binary, scoped to this project.\n\n\
             Files here only contain `rbw://` URIs (pointers to your Bitwarden items), never secret values. You can decide whether to commit them based on whether your team shares the same vault item naming convention.\n",
        )?;
        println!("✓ created {}", envs_dir.display());
    }

    // Offer to add to .gitignore
    let gitignore = cwd.join(".gitignore");
    let mut existing = String::new();
    if gitignore.exists() {
        existing = std::fs::read_to_string(&gitignore)?;
    }
    if existing.lines().any(|l| l.trim() == ".envs/") {
        println!("  (.envs/ already in .gitignore)");
    } else {
        print!("Add .envs/ to .gitignore? [y/N] ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer)?;
        if answer.trim().eq_ignore_ascii_case("y") || answer.trim().eq_ignore_ascii_case("yes") {
            let mut content = existing;
            if !content.is_empty() && !content.ends_with('\n') {
                content.push('\n');
            }
            content.push_str(".envs/\n");
            std::fs::write(&gitignore, content)?;
            println!("✓ added .envs/ to .gitignore");
        } else {
            println!("(skipped — your team can share vault item names if you commit .envs/)");
        }
    }

    Ok(())
}

async fn show() -> Result<()> {
    let cwd = std::env::current_dir()?;
    match manifest::find_project_root(&cwd) {
        Some(root) => {
            println!("project root: {}", root.display());
            let envs_dir = root.join(".envs");
            let mut profiles = Vec::new();
            for entry in std::fs::read_dir(&envs_dir)? {
                let e = entry?;
                let path = e.path();
                if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                    profiles.push(path);
                }
            }
            if profiles.is_empty() {
                println!("  (no profiles yet — run a binary via `envs` to create one)");
            } else {
                for p in profiles {
                    println!("  {}", p.display());
                }
            }
            Ok(())
        }
        None => {
            println!(
                "(no .envs/ found by walking up from {}); run `envs project init` to create one.",
                cwd.display()
            );
            Err(CliError::Internal("no project root".into())).or(Ok(())) // print is enough
        }
    }
}
