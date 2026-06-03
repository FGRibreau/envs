//! `envs` — CLI wrapper that injects Bitwarden secrets into a child process via TouchID-gated grants.

use clap::{Parser, Subcommand};

mod client;
mod commands;
mod error;
mod exec;
mod manifest;

use crate::error::Result;

#[derive(Parser, Debug)]
#[command(
    name = "envs",
    version,
    about = "Lulu-style firewall for environment variables (Bitwarden + TouchID)",
    long_about = "A TouchID-gated firewall for environment variables.\n\
        \n\
        Secrets stay encrypted in Bitwarden; this machine holds only rbw:// pointers.\n\
        `envs <cmd>` injects them into a single child process after a biometric approval,\n\
        scoped to that binary, that project, and a short TTL.\n\
        \n\
        Three pieces cooperate: the `envs` CLI (this), the `envsd` daemon (cache + vault +\n\
        audit) and a native popup (consent + TouchID). Run `envs init` once to set them up."
)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Use one or more named profiles (additive). Repeat to combine.
    #[arg(short = 'p', long = "profile", global = true)]
    profile: Vec<String>,

    /// Inline binding override: KEY=rbw://item/field (repeatable).
    #[arg(short = 'b', long = "bind", global = true)]
    bind: Vec<String>,

    /// Verbose logging (RUST_LOG=debug).
    #[arg(short = 'v', long, global = true)]
    verbose: bool,

    /// Trailing args interpreted as the command to wrap when no subcommand is given.
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    trailing: Vec<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run a command with secrets injected.
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        argv: Vec<String>,
    },

    /// Bootstrap wizard: install rbw, log in, install LaunchAgent, sync registry.
    Init {
        /// Re-run all steps even if already configured.
        #[arg(long)]
        force: bool,
    },

    /// Run diagnostic checks without modifying anything.
    Doctor,

    /// Manage active rules (cache).
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },

    /// Manage project-local profiles (.envs/ in CWD).
    Project {
        #[command(subcommand)]
        action: ProjectAction,
    },

    /// View audit log.
    Audit {
        #[command(subcommand)]
        action: AuditAction,
    },

    /// Manage the community registry.
    Registry {
        #[command(subcommand)]
        action: RegistryAction,
    },

    /// Daemon lifecycle.
    Daemon {
        #[command(subcommand)]
        action: DaemonAction,
    },

    /// Print shell completions.
    Completions { shell: clap_complete::Shell },
}

#[derive(Subcommand, Debug)]
enum RulesAction {
    List,
    Show { rule_id: String },
    Revoke { rule_id_or_all: String },
}

#[derive(Subcommand, Debug)]
enum ProjectAction {
    /// Create .envs/ in CWD.
    Init,
    /// Show detected project_root and profiles.
    Show,
    /// Promote a project profile to global.
    Link {
        #[arg(long)]
        global: bool,
        binary: String,
    },
}

#[derive(Subcommand, Debug)]
enum AuditAction {
    Show {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        binary: Option<String>,
        #[arg(long)]
        event: Option<String>,
        #[arg(long)]
        project: Option<std::path::PathBuf>,
    },
    Export {
        path: std::path::PathBuf,
    },
    /// Verify the HMAC chain integrity of the audit log.
    Verify,
}

#[derive(Subcommand, Debug)]
enum RegistryAction {
    Sync,
    Show { binary: String },
}

#[derive(Subcommand, Debug)]
enum DaemonAction {
    Start,
    Stop,
    Restart,
    Status,
    Install,
    Uninstall,
}

fn main() {
    let cli = Cli::parse();
    init_tracing(cli.verbose);

    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("envs: tokio init failed: {e}");
            std::process::exit(70);
        }
    };

    if let Err(e) = runtime.block_on(async move { dispatch(cli).await }) {
        // Friendly Display formatting (not Debug). Maps to the right exit code.
        eprintln!("{}", error::format_user_error(&e));
        std::process::exit(e.exit_code());
    }
}

async fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Some(Command::Run { argv }) => commands::run::execute(argv, &cli.profile, &cli.bind).await,
        Some(Command::Init { force }) => commands::init::execute(force).await,
        Some(Command::Doctor) => commands::doctor::execute().await,
        Some(Command::Rules { action }) => commands::rules::execute(action).await,
        Some(Command::Project { action }) => commands::project::execute(action).await,
        Some(Command::Audit { action }) => commands::audit::execute(action).await,
        Some(Command::Registry { action }) => commands::registry::execute(action).await,
        Some(Command::Daemon { action }) => commands::daemon::execute(action).await,
        Some(Command::Completions { shell }) => commands::completions::execute(shell),
        None => {
            // Bare invocation: `envs <bin> <args>` shorthand for `envs run -- <bin> <args>`
            if cli.trailing.is_empty() {
                return handle_no_command().await;
            }
            commands::run::execute(cli.trailing, &cli.profile, &cli.bind).await
        }
    }
}

/// Bare `envs` with no command and no trailing args.
///
/// If the daemon answers, there's simply nothing to run. If it doesn't, the
/// user almost certainly hasn't set envs up yet — so instead of a cryptic
/// one-liner, explain what envs is and why `envs init` is the next step, and
/// (on a TTY) offer to run it right now. The daemon is the engine: it caches
/// grants, talks to the vault and shows the TouchID popup, so "daemon
/// unreachable" is the most reliable first-run signal we have.
async fn handle_no_command() -> Result<()> {
    use std::io::Write;

    if client::daemon_reachable().await {
        // Set up and healthy — nothing to do without a command to wrap.
        return Err(error::CliError::NothingToRun);
    }

    eprintln!(
        "envs — a TouchID-gated firewall for your environment variables.\n\
         \n\
         Your secrets stay encrypted in Bitwarden; this machine only holds pointers.\n\
         `envs <cmd>` injects them into one command, after you approve with TouchID.\n\
         \n\
         You're not set up yet. `envs init` installs the pieces envs needs:\n\
         \x20 • rbw              — the Bitwarden client that decrypts your vault\n\
         \x20 • pinentry-touchid — puts each vault unlock behind TouchID\n\
         \x20 • envsd            — the background daemon that caches grants and shows the popup\n"
    );

    // Only offer the interactive prompt when we actually have a terminal —
    // otherwise (piped, CI, agent) print guidance and return without blocking.
    if !nix::unistd::isatty(0).unwrap_or(false) {
        eprintln!("Run `envs init` to get started.");
        return Ok(());
    }

    eprint!("Run `envs init` now? [Y/n] ");
    std::io::stderr().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    let trimmed = answer.trim();
    let yes = trimmed.is_empty()
        || trimmed.eq_ignore_ascii_case("y")
        || trimmed.eq_ignore_ascii_case("yes");
    if yes {
        commands::init::execute(false).await
    } else {
        eprintln!("No problem — run `envs init` when you're ready.");
        Ok(())
    }
}

fn init_tracing(verbose: bool) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        if verbose {
            tracing_subscriber::EnvFilter::new("envs=debug")
        } else {
            tracing_subscriber::EnvFilter::new("envs=info")
        }
    });
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}
