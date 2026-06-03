//! Helper subprocess supervisor.
//!
//! Spawns `envs-prompt` at boot, communicates via stdin/stdout JSON pipes,
//! and respawns on unexpected exit (max 3 attempts before fail-closed mode).
//!
//! v0.1: in stub mode (`ENVS_HELPER_STUB=1`), bypasses subprocess entirely
//! and returns a deterministic Authorized reply directly.

use crate::error::{DaemonError, Result};
use envs_proto::{Binding, GrantScope, HelperEvent, HelperReply, ProfileTarget, PromptRequest};
use std::collections::HashMap;
use std::ffi::OsString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{oneshot, Mutex};

/// Helper binary name. Resolved next to `envsd` first (see `resolve_helper_path`).
const HELPER_BIN: &str = "envs-prompt";

/// User-facing message when the helper pipeline is permanently down. Covers both
/// "couldn't be started" (the common case: not found next to envsd / not on
/// PATH) and "started but kept crashing".
const HELPER_UNAVAILABLE: &str =
    "could not run the envs-prompt helper — ensure it is installed next to envsd \
     (same directory, e.g. `cargo install envs-prompt`) and is not crashing";

/// Resolve the `envs-prompt` helper binary.
///
/// `envsd` and `envs-prompt` are always installed together — same `cargo install`
/// bin directory, same release tarball — so prefer the copy sitting next to the
/// running daemon. This is what makes the helper findable when `envsd` runs under
/// launchd, whose PATH (`/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`) does
/// NOT include `~/.cargo/bin`. Fall back to a bare PATH lookup for unusual
/// layouts or development.
fn resolve_helper_path(self_exe: Option<&Path>) -> OsString {
    if let Some(dir) = self_exe.and_then(Path::parent) {
        let sibling = dir.join(HELPER_BIN);
        if sibling.is_file() {
            return sibling.into_os_string();
        }
    }
    OsString::from(HELPER_BIN)
}

pub struct HelperHandle {
    /// Pending requests, keyed by request_id, awaiting helper reply.
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<HelperReply>>>>,
    /// Channel to the helper subprocess stdin (None in stub mode).
    sender: Option<tokio::sync::mpsc::UnboundedSender<HelperEvent>>,
    /// Stub mode: skip subprocess, auto-authorize.
    stub: bool,
    /// Set to true when the supervisor exhausts respawn attempts. New requests
    /// fail-fast instead of hanging forever on a dead pipeline.
    degraded: Arc<AtomicBool>,
}

impl HelperHandle {
    /// Whether this handle is the auto-authorize stub (no real popup/UI).
    /// Used to skip GUI-session gating in tests and on non-macOS.
    pub fn is_stub(&self) -> bool {
        self.stub
    }

    /// Create a stub helper that auto-authorizes every request.
    pub fn stub() -> Self {
        Self {
            pending: Arc::new(Mutex::new(HashMap::new())),
            sender: None,
            stub: true,
            degraded: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Spawn the real `envs-prompt` subprocess with respawn-on-crash supervision.
    ///
    /// Per spec section "Helper UI lifecycle":
    /// - exit unexpected → respawn (max 3 retries within 30s, then degrade to stub mode)
    /// - daemon stop → kill helper proprement (SIGTERM via tokio kill_on_drop)
    pub async fn spawn_real() -> Result<Self> {
        let pending: Arc<Mutex<HashMap<String, oneshot::Sender<HelperReply>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<HelperEvent>();

        // Respawn supervisor: keeps the helper alive, retrying with exponential backoff
        // up to 3 times in any 30s window.
        let pending_for_supervisor = pending.clone();
        let degraded = Arc::new(AtomicBool::new(false));
        let degraded_for_supervisor = degraded.clone();
        let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        // Resolve the helper once, next to our own binary, so a restricted
        // launchd PATH can't hide it.
        let helper_bin = resolve_helper_path(std::env::current_exe().ok().as_deref());
        tokio::spawn(async move {
            let mut retry_window: Vec<std::time::Instant> = Vec::new();
            loop {
                // Trim retry window to the last 30s
                let now = std::time::Instant::now();
                retry_window.retain(|t| now.duration_since(*t) < Duration::from_secs(30));
                if retry_window.len() >= 3 {
                    tracing::error!(
                        "envs-prompt has crashed 3 times in 30s — failing pending requests"
                    );
                    // Mark the helper as permanently degraded so future request()
                    // calls fail-fast instead of waiting on a dead pipeline (we
                    // removed the per-request timeout for Co5).
                    degraded_for_supervisor.store(true, Ordering::SeqCst);
                    // Drain in-flight requests with an explicit Error so callers
                    // do not hang forever.
                    let mut guard = pending_for_supervisor.lock().await;
                    let entries: Vec<(String, oneshot::Sender<HelperReply>)> =
                        guard.drain().collect();
                    drop(guard);
                    for (request_id, tx) in entries {
                        let _ = tx.send(HelperReply::Error {
                            request_id,
                            message: HELPER_UNAVAILABLE.into(),
                        });
                    }
                    break;
                }
                retry_window.push(now);

                tracing::info!(
                    bin = %helper_bin.to_string_lossy(),
                    "spawning envs-prompt (retry {}/3 in 30s window)",
                    retry_window.len()
                );
                let child = match Command::new(&helper_bin)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::inherit())
                    .kill_on_drop(true)
                    .spawn()
                {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::warn!(
                            ?e,
                            bin = %helper_bin.to_string_lossy(),
                            "failed to spawn envs-prompt; retrying in 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

                if let Err(e) =
                    run_one_helper_session(child, &pending_for_supervisor, &mut stdin_rx).await
                {
                    tracing::warn!(?e, "envs-prompt session ended");
                }
                // Brief pause before respawn
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        });

        // Forward HelperEvent → bytes for the supervisor to feed to the active child.
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Ok(mut buf) = serde_json::to_vec(&event) {
                    buf.push(b'\n');
                    if stdin_tx.send(buf).is_err() {
                        break;
                    }
                }
            }
        });

        Ok(Self {
            pending,
            sender: Some(tx),
            stub: false,
            degraded,
        })
    }

    /// Internal stub-spawn variant retained for backward compat with old call sites.
    /// Same signature kept for tests; logic now in spawn_real with respawn.
    #[allow(dead_code)]
    async fn _legacy_spawn_real() -> Result<Self> {
        let helper_bin = resolve_helper_path(std::env::current_exe().ok().as_deref());
        let mut child = Command::new(&helper_bin)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| DaemonError::Helper(format!("spawn envs-prompt: {e}")))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| DaemonError::Helper("no stdin pipe".into()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| DaemonError::Helper("no stdout pipe".into()))?;

        let pending: Arc<Mutex<HashMap<String, oneshot::Sender<HelperReply>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<HelperEvent>();

        // Writer task: events → helper stdin
        let mut stdin_writer = stdin;
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Ok(mut buf) = serde_json::to_vec(&event) {
                    buf.push(b'\n');
                    if stdin_writer.write_all(&buf).await.is_err() {
                        tracing::warn!("helper stdin write failed");
                        break;
                    }
                    let _ = stdin_writer.flush().await;
                }
            }
        });

        // Reader task: helper stdout → pending oneshots
        let pending_reader = pending.clone();
        tokio::spawn(async move {
            let mut reader = BufReader::new(stdout).lines();
            loop {
                match reader.next_line().await {
                    Ok(Some(line)) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        let reply: HelperReply = match serde_json::from_str(&line) {
                            Ok(r) => r,
                            Err(err) => {
                                tracing::warn!(?err, line = %line, "helper reply parse failed");
                                continue;
                            }
                        };
                        let id = match &reply {
                            HelperReply::Authorized { request_id, .. } => request_id.clone(),
                            HelperReply::Cancelled { request_id } => request_id.clone(),
                            HelperReply::Error { request_id, .. } => request_id.clone(),
                        };
                        let mut guard = pending_reader.lock().await;
                        if let Some(tx) = guard.remove(&id) {
                            let _ = tx.send(reply);
                        } else {
                            tracing::debug!(%id, "stray helper reply");
                        }
                    }
                    Ok(None) => {
                        tracing::warn!("helper stdout EOF");
                        break;
                    }
                    Err(e) => {
                        tracing::warn!(?e, "helper stdout read error");
                        break;
                    }
                }
            }
        });

        // Reaper task: detect helper exit (we don't auto-respawn here for v0.1 simplicity)
        tokio::spawn(reap_child(child));

        Ok(Self {
            pending,
            sender: Some(tx),
            stub: false,
            degraded: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Submit a request to the helper. Awaits the user decision.
    ///
    /// Per spec section "Concurrence": no timeout, cancel explicite uniquement.
    /// The user may take arbitrarily long to respond — the consent popup is
    /// human-driven, so blocking is acceptable. The CLI side has its own
    /// connection lifecycle. Callers reach this only after a GUI session has
    /// been confirmed (see `create_via_helper`), so the popup will be shown.
    /// `_timeout` is kept in the signature for backwards compatibility but ignored.
    pub async fn request(&self, req: PromptRequest, _timeout: Duration) -> Result<HelperReply> {
        if self.stub {
            return Ok(stub_reply(req));
        }

        if self.degraded.load(Ordering::SeqCst) {
            return Err(DaemonError::Helper(HELPER_UNAVAILABLE.into()));
        }

        let id = req.request_id.clone();
        let (tx, rx) = oneshot::channel();
        {
            let mut guard = self.pending.lock().await;
            guard.insert(id.clone(), tx);
        }

        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| DaemonError::Helper("no sender".into()))?;
        sender
            .send(HelperEvent::NewRequest(req))
            .map_err(|e| DaemonError::Helper(format!("send: {e}")))?;

        // No timeout — wait until the helper responds (cancel-only model).
        match rx.await {
            Ok(reply) => Ok(reply),
            Err(_) => {
                self.pending.lock().await.remove(&id);
                Err(DaemonError::Helper(
                    "helper channel dropped — likely subprocess crashed".into(),
                ))
            }
        }
    }
}

/// Build a deterministic stub reply. The user's saved profile is authoritative
/// when present; discovery suggestions are only fallback when nothing is yet
/// configured. (Real popup shows both and lets the human pick.)
fn stub_reply(req: PromptRequest) -> HelperReply {
    let bindings: Vec<Binding> = if let Some(profile) = &req.current_profile {
        profile.bindings.clone()
    } else if !req.suggested_bindings.is_empty() {
        req.suggested_bindings
            .iter()
            .map(|s| Binding {
                env: s.env.clone(),
                source: s.source.clone(),
            })
            .collect()
    } else {
        Vec::new()
    };

    let scope = if crate::binary::is_system_binary(&req.canon_path) {
        GrantScope::ExactArgv {
            argv: req.argv.clone(),
        }
    } else {
        GrantScope::Any
    };

    HelperReply::Authorized {
        request_id: req.request_id,
        bindings,
        scope,
        ttl_secs: 300,
        save_as_profile: req
            .project_root
            .as_ref()
            .map(|_| ProfileTarget::Project)
            .or(Some(ProfileTarget::Global)),
    }
}

async fn reap_child(mut child: Child) {
    match child.wait().await {
        Ok(status) => tracing::info!(?status, "envs-prompt subprocess exited"),
        Err(e) => tracing::warn!(?e, "envs-prompt wait failed"),
    }
}

/// Run a single helper session: pipe stdin/stdout, await child exit.
/// Returns when the child exits (whatever the reason). Caller's loop
/// implements the respawn policy.
async fn run_one_helper_session(
    mut child: Child,
    pending: &Arc<Mutex<HashMap<String, oneshot::Sender<HelperReply>>>>,
    stdin_rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
) -> Result<()> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| DaemonError::Helper("no stdin pipe".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| DaemonError::Helper("no stdout pipe".into()))?;

    // Reader task: parse helper stdout → resolve pending oneshots
    let pending_reader = pending.clone();
    let read_handle = tokio::spawn(async move {
        let mut reader = BufReader::new(stdout).lines();
        loop {
            match reader.next_line().await {
                Ok(Some(line)) => {
                    if line.trim().is_empty() {
                        continue;
                    }
                    let reply: HelperReply = match serde_json::from_str(&line) {
                        Ok(r) => r,
                        Err(err) => {
                            tracing::warn!(?err, line = %line, "helper reply parse failed");
                            continue;
                        }
                    };
                    let id = match &reply {
                        HelperReply::Authorized { request_id, .. } => request_id.clone(),
                        HelperReply::Cancelled { request_id } => request_id.clone(),
                        HelperReply::Error { request_id, .. } => request_id.clone(),
                    };
                    let mut guard = pending_reader.lock().await;
                    if let Some(tx) = guard.remove(&id) {
                        let _ = tx.send(reply);
                    } else {
                        tracing::debug!(%id, "stray helper reply");
                    }
                }
                Ok(None) => {
                    tracing::debug!("helper stdout EOF");
                    break;
                }
                Err(e) => {
                    tracing::warn!(?e, "helper stdout read error");
                    break;
                }
            }
        }
    });

    // Writer loop: drain stdin_rx → write to helper stdin
    // Stops when either: stdin_rx closes (daemon shutting down) OR child exits.
    loop {
        tokio::select! {
            maybe_msg = stdin_rx.recv() => {
                match maybe_msg {
                    Some(buf) => {
                        if stdin.write_all(&buf).await.is_err() {
                            break;
                        }
                        let _ = stdin.flush().await;
                    }
                    None => break,
                }
            }
            status = child.wait() => {
                match status {
                    Ok(status) => tracing::info!(?status, "envs-prompt exited"),
                    Err(e) => tracing::warn!(?e, "envs-prompt wait failed"),
                }
                break;
            }
        }
    }

    // Drop stdin to signal EOF, ensure child has exited.
    drop(stdin);
    let _ = child.kill().await;
    let _ = read_handle.await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_path_prefers_sibling_of_daemon() {
        // envsd and envs-prompt installed together → resolve the sibling,
        // independent of PATH (the launchd-restricted-PATH bug).
        let dir = tempfile::tempdir().unwrap();
        let envsd = dir.path().join("envsd");
        let helper = dir.path().join(HELPER_BIN);
        std::fs::write(&envsd, b"x").unwrap();
        std::fs::write(&helper, b"x").unwrap();
        assert_eq!(resolve_helper_path(Some(&envsd)), helper.into_os_string());
    }

    #[test]
    fn helper_path_falls_back_to_bare_name_when_no_sibling() {
        let dir = tempfile::tempdir().unwrap();
        let envsd = dir.path().join("envsd"); // no sibling helper created
        std::fs::write(&envsd, b"x").unwrap();
        assert_eq!(
            resolve_helper_path(Some(&envsd)),
            OsString::from(HELPER_BIN)
        );
    }

    #[test]
    fn helper_path_falls_back_to_bare_name_when_self_exe_unknown() {
        assert_eq!(resolve_helper_path(None), OsString::from(HELPER_BIN));
    }
}
