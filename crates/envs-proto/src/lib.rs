//! Shared IPC types between `envs` CLI, `envsd` daemon, and `envs-prompt` helper.
//!
//! Wire protocol: newline-delimited JSON over Unix domain sockets (CLI ↔ daemon)
//! and stdin/stdout pipes (daemon ↔ helper).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

pub const PROTOCOL_VERSION: u32 = 1;

/// Unique identifier for a granted rule.
pub type RuleId = String; // Ulid as string for serde simplicity

/// Request from `envs` CLI to `envsd` daemon.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Request {
    /// Health check.
    Ping,

    /// Resolve secrets for a command invocation.
    /// CLI sends this just before `execve`.
    Resolve {
        canon_path: PathBuf,
        sha256: String, // hex
        codesign_team: Option<String>,
        argv: Vec<String>,
        cwd: PathBuf,
        project_root: Option<PathBuf>,
        client_pid: i32,
        /// Profile names requested via `--profile` (additive, see ProfileFile.includes).
        #[serde(default)]
        profiles: Vec<String>,
        /// Inline binding overrides via `--bind KEY=rbw://item/field`.
        /// Merged on top of profile bindings (override wins).
        #[serde(default)]
        extra_bindings: Vec<Binding>,
    },

    /// List active rules.
    ListRules,

    /// Get a single rule.
    GetRule { rule_id: RuleId },

    /// Revoke rule(s). `rule_id = None` revokes all.
    Revoke { rule_id: Option<RuleId> },

    /// Daemon status.
    Status,

    /// Force flush all caches.
    Flush,
}

/// Response from `envsd` daemon to `envs` CLI.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Pong,

    /// Resolved secrets to inject into the child process environ.
    Resolved {
        rule_id: RuleId,
        entries: Vec<EnvEntry>,
        cached: bool,
        expires_at: DateTime<Utc>,
    },

    Rules {
        rules: Vec<RuleSummary>,
    },

    Rule {
        rule: Option<RuleDetail>,
    },

    Status {
        version: String,
        protocol: u32,
        cache_entries: usize,
        rules_count: usize,
        rbw_unlocked: bool,
        uptime_secs: u64,
    },

    Ok,

    Error {
        code: ErrorCode,
        message: String,
    },
}

/// One env var entry to inject (key + value).
///
/// The value travels in plaintext over the UDS (same-UID local kernel memory).
/// Both ends wrap it in `secrecy::SecretString` immediately upon receipt for
/// in-process zeroize-on-drop hygiene.
#[derive(Debug, Serialize, Deserialize)]
pub struct EnvEntry {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleSummary {
    pub id: RuleId,
    pub canon_path: PathBuf,
    pub argv_match: ArgvMatch,
    pub project_root: Option<PathBuf>,
    pub env_keys: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RuleDetail {
    #[serde(flatten)]
    pub summary: RuleSummary,
    pub sha256: String,
    pub codesign_team: Option<String>,
    pub sources: Vec<String>,
    pub profile_id: String,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// Argv matching mode for a rule.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArgvMatch {
    /// Match any argv (i.e. any invocation of the binary).
    Any,
    /// Match only this exact argv.
    Exact { argv: Vec<String> },
}

impl ArgvMatch {
    pub fn matches(&self, argv: &[String]) -> bool {
        match self {
            ArgvMatch::Any => true,
            ArgvMatch::Exact { argv: expected } => argv == expected.as_slice(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    NotAuthorized,
    BinaryNotInProfile,
    KeyNotInProfile,
    BinaryHashMismatch,
    SystemBinaryRefused,
    RbwLocked,
    RbwNotInstalled,
    RbwLookupFailed,
    TouchIdUnavailable,
    PeerVerificationFailed,
    ProtocolMismatch,
    Internal,
}

// ─── daemon ↔ helper IPC ─────────────────────────────────────────────────────

/// Event sent from daemon to helper.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HelperEvent {
    /// New popup request (creates a new tab in the popup window).
    NewRequest(PromptRequest),

    /// Cancel a pending request (process killed, daemon revoked, etc.).
    /// Helper animates the tab disappearing.
    CancelRequest { request_id: String },

    /// Update pending count (for menubar badge).
    PendingCountChanged { count: usize },

    /// Daemon shutting down.
    Shutdown,
}

/// Reply from helper to daemon (user decision on a popup).
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum HelperReply {
    /// User authorized via TouchID.
    Authorized {
        request_id: String,
        bindings: Vec<Binding>,
        scope: GrantScope,
        ttl_secs: u64,
        save_as_profile: Option<ProfileTarget>,
    },

    /// User cancelled the popup.
    Cancelled { request_id: String },

    /// Helper detected error (TouchID unavailable, etc.).
    Error { request_id: String, message: String },
}

/// What the daemon shows to the user in the popup tab.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptRequest {
    pub request_id: String,
    pub canon_path: PathBuf,
    pub binary_name: String,
    pub argv: Vec<String>,
    pub cwd: PathBuf,
    pub project_root: Option<PathBuf>,
    pub suggested_bindings: Vec<SuggestedBinding>,
    pub available_vault_items: Vec<VaultItem>,
    pub current_profile: Option<ProfileSnapshot>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SuggestedBinding {
    pub env: String,
    pub source: String,
    pub confidence: Confidence,
    pub reason: String, // "registry", "--help parsing", "LLM", etc.
    pub deprecated: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VaultItem {
    pub name: String,
    pub fields: Vec<String>, // password, username, custom field names
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Binding {
    pub env: String,
    pub source: String, // rbw://item/field
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GrantScope {
    /// Any invocation of the binary in the project (or globally if no project).
    Any,
    /// Only this exact argv.
    ExactArgv { argv: Vec<String> },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProfileTarget {
    /// Save in `<project_root>/.envs/<binary>.toml`.
    Project,
    /// Save in `~/.envs/profiles/<binary>.toml`.
    Global,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProfileSnapshot {
    pub source: ProfileTarget,
    pub path: PathBuf,
    pub bindings: Vec<Binding>,
}

// ─── error type for proto-level errors ──────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol mismatch: expected {expected}, got {got}")]
    ProtocolMismatch { expected: u32, got: u32 },
}

/// Helper to write a newline-delimited JSON message to a writer.
pub fn write_msg<T: Serialize>(buf: &mut Vec<u8>, msg: &T) -> Result<(), ProtoError> {
    serde_json::to_writer(&mut *buf, msg)?;
    buf.push(b'\n');
    Ok(())
}

/// Helper to parse a newline-delimited JSON message.
pub fn parse_msg<T: for<'de> Deserialize<'de>>(line: &str) -> Result<T, ProtoError> {
    Ok(serde_json::from_str(line)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ping_pong_roundtrip() {
        let req = Request::Ping;
        let mut buf = Vec::new();
        write_msg(&mut buf, &req).unwrap();
        let s = std::str::from_utf8(&buf).unwrap().trim();
        let parsed: Request = parse_msg(s).unwrap();
        matches!(parsed, Request::Ping);
    }

    #[test]
    fn argv_match_any() {
        let m = ArgvMatch::Any;
        assert!(m.matches(&["a".into(), "b".into()]));
        assert!(m.matches(&[]));
    }

    #[test]
    fn argv_match_exact() {
        let m = ArgvMatch::Exact {
            argv: vec!["zone".into(), "list".into()],
        };
        assert!(m.matches(&["zone".into(), "list".into()]));
        assert!(!m.matches(&["zone".into(), "create".into()]));
        assert!(!m.matches(&[]));
    }

    #[test]
    fn ulid_serializes_as_string() {
        let id = ulid::Ulid::new().to_string();
        let json = serde_json::to_string(&id).unwrap();
        assert!(json.starts_with('"'));
    }
}
