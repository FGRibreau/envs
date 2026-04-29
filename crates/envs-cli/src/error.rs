use envs_proto::ErrorCode;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, CliError>;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("proto: {0}")]
    Proto(#[from] envs_proto::ProtoError),

    #[error("daemon error ({code:?}): {message}")]
    Daemon { code: ErrorCode, message: String },

    #[error("daemon not running. Try `envs daemon start` or `envs init`.")]
    DaemonNotRunning,

    #[error("nothing to run")]
    NothingToRun,

    #[error("command not found: {0}")]
    CommandNotFound(String),

    #[error("non-interactive: envs requires an interactive macOS session for TouchID prompts")]
    NonInteractive,

    /// User-facing input/usage error (bad CLI args, missing prereqs the user must fix).
    /// Rendered without an "internal error:" prefix and exits 64 (EX_USAGE).
    #[error("{0}")]
    BadArgs(String),

    #[error("{0}")]
    Internal(String),
}

impl CliError {
    /// Translate this error into a process exit code following BSD sysexits.h conventions.
    pub fn exit_code(&self) -> i32 {
        match self {
            CliError::DaemonNotRunning => 75, // EX_TEMPFAIL
            CliError::NonInteractive => 75,
            CliError::CommandNotFound(_) => 127,
            CliError::NothingToRun => 64, // EX_USAGE
            CliError::BadArgs(_) => 64,   // EX_USAGE
            CliError::Daemon { code, .. } => match code {
                ErrorCode::NotAuthorized => 77, // EX_NOPERM (user cancelled)
                ErrorCode::SystemBinaryRefused => 77,
                ErrorCode::PeerVerificationFailed => 77,
                ErrorCode::RbwLocked | ErrorCode::RbwNotInstalled => 75,
                _ => 70, // EX_SOFTWARE
            },
            _ => 70,
        }
    }
}

/// User-facing one-liner for stderr. Friendly, prefixed with `envs:`, no Debug noise.
pub fn format_user_error(e: &CliError) -> String {
    match e {
        CliError::DaemonNotRunning => {
            "envs: daemon is not running. Try `envs init` or start `envsd` manually.".into()
        }
        CliError::NonInteractive => {
            "envs: requires an interactive macOS session for TouchID prompts (out of scope: SSH/CI/headless).".into()
        }
        CliError::CommandNotFound(cmd) => format!("envs: command not found: {cmd}"),
        CliError::NothingToRun => "envs: nothing to run. Try `envs --help`.".into(),
        CliError::Daemon { code, message } => match code {
            ErrorCode::SystemBinaryRefused => format!(
                "envs: refused — {message}\n  hint: wrap the binary with a personal script under ~/bin/, or use scope=ExactArgv"
            ),
            ErrorCode::RbwLocked => {
                "envs: vault locked and auto-unlock failed. Run `envs doctor` to verify pinentry-touchid is installed and configured (`rbw config set pinentry pinentry-touchid`).".into()
            }
            ErrorCode::RbwNotInstalled => {
                "envs: rbw is not installed. Run `brew install rbw`.".into()
            }
            ErrorCode::NotAuthorized => "envs: cancelled by user.".into(),
            ErrorCode::PeerVerificationFailed => {
                "envs: peer verification failed (caller identity mismatch).".into()
            }
            ErrorCode::BinaryNotInProfile => format!(
                "envs: no profile or registry entry for `{message}`, and `--help` parsing found no env vars.\n\
                 \n\
                 Pick one:\n\
                 \n\
                 1. Bind ad-hoc on the command line:\n\
                      envs --bind FOO=rbw://Foo --bind BAR=rbw://Bar/notes -- {message} <args>\n\
                 \n\
                 2. Save a project profile (committable — it only stores rbw:// pointers, never values):\n\
                      cat > .envs/{message}.toml <<EOF\n\
                      schema = 1\n\
                      [binary]\n\
                      name = \"{message}\"\n\
                      \n\
                      [[binding]]\n\
                      env = \"FOO\"\n\
                      src = \"rbw://Foo\"\n\
                      EOF\n\
                 \n\
                 3. Save a global profile in ~/.envs/profiles/{message}.toml (same format)."
            ),
            _ => format!("envs: {message}"),
        },
        CliError::BadArgs(msg) => format!("envs: {msg}"),
        CliError::Internal(msg) => format!("envs: internal error: {msg}"),
        _ => format!("envs: {e}"),
    }
}
