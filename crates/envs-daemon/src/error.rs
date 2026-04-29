use thiserror::Error;

pub type Result<T> = std::result::Result<T, DaemonError>;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml decode: {0}")]
    TomlDecode(#[from] toml::de::Error),

    #[error("toml encode: {0}")]
    TomlEncode(#[from] toml::ser::Error),

    #[error("proto: {0}")]
    Proto(#[from] envs_proto::ProtoError),

    #[error("rbw vault is locked; run `rbw unlock` first")]
    RbwLocked,

    #[error("rbw is not installed (or not in PATH)")]
    RbwNotInstalled,

    #[error("rbw lookup failed: {0}")]
    RbwLookupFailed(String),

    #[error("invalid rbw URI: {0}")]
    BadRbwUri(String),

    #[error("helper subprocess error: {0}")]
    Helper(String),

    #[error("rule not found: {0}")]
    #[allow(dead_code)] // reserved for v0.2 lookup-by-id flows
    RuleNotFound(String),

    #[error("bad input: {0}")]
    BadInput(String),

    #[error("system binary refused: {0}")]
    SystemBinaryRefused(String),

    #[error("no profile or registry entry for {0}")]
    NoProfile(String),

    #[error("internal: {0}")]
    Internal(String),
}
