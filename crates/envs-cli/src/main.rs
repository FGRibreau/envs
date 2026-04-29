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
    about = "Lulu-style firewall for environment variables (Bitwarden + TouchID)"
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
                eprintln!("envs: nothing to run. Try `envs --help` or `envs init`.");
                std::process::exit(64); // EX_USAGE
            }
            commands::run::execute(cli.trailing, &cli.profile, &cli.bind).await
        }
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
