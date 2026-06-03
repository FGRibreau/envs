//! Black-box onboarding tests: drive the real `envs` binary with an isolated
//! HOME and a dead socket, and assert the first-run guidance.
//!
//! These cover the "why vs how" onboarding surfaces that don't need a live
//! daemon or TouchID:
//!   - bare `envs` on a fresh machine → welcome + `envs init` guidance,
//!     and (critically) it must NOT block waiting on stdin when there's no TTY;
//!   - `envs <cmd>` before setup → "not set up yet … envs init";
//!   - `envs <cmd>` with the LaunchAgent installed but the daemon down →
//!     "daemon isn't running … envs daemon start".
//!
//! The interactive Y/n prompt and the TouchID popup can't be automated; they're
//! verified manually.

use std::path::Path;
use std::process::{Command, Stdio};

/// Run `envs` with an isolated HOME and a socket path that points at nothing,
/// so every daemon probe fails fast. stdin is closed (no TTY) so the binary
/// must take its non-interactive branches and never block.
fn run_envs(home: &Path, args: &[&str]) -> std::process::Output {
    let dead_socket = home.join("envsd.sock"); // never created
    Command::new(env!("CARGO_BIN_EXE_envs"))
        .args(args)
        .env("HOME", home)
        .env("ENVS_SOCKET", &dead_socket)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn envs")
}

#[test]
fn bare_envs_first_run_explains_why_and_does_not_block() {
    let home = tempfile::tempdir().expect("tmp home");
    let out = run_envs(home.path(), &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // Explains what envs is + why init is next (the WHY, not just the HOW).
    assert!(
        stderr.contains("firewall for your environment variables"),
        "missing value-prop line; stderr was:\n{stderr}"
    );
    assert!(
        stderr.contains("You're not set up yet"),
        "missing first-run framing; stderr was:\n{stderr}"
    );
    // No TTY → must print guidance and exit, never hang on the Y/n prompt.
    assert!(
        stderr.contains("Run `envs init` to get started."),
        "missing non-interactive guidance; stderr was:\n{stderr}"
    );
    assert!(out.status.success(), "bare first-run should exit 0");
}

#[test]
fn run_before_setup_points_to_envs_init() {
    let home = tempfile::tempdir().expect("tmp home");
    // No LaunchAgent plist under HOME → "never set up" branch.
    let out = run_envs(home.path(), &["/bin/echo", "hi"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("not set up yet") && stderr.contains("envs init"),
        "expected the not-set-up message; stderr was:\n{stderr}"
    );
    assert_eq!(out.status.code(), Some(75), "EX_TEMPFAIL expected");
}

#[test]
fn run_with_launchagent_but_daemon_down_points_to_daemon_start() {
    let home = tempfile::tempdir().expect("tmp home");
    // Simulate "set up, but daemon stopped": the LaunchAgent plist exists.
    let agents = home.path().join("Library").join("LaunchAgents");
    std::fs::create_dir_all(&agents).expect("mk LaunchAgents");
    std::fs::write(agents.join("com.fgribreau.envsd.plist"), "<plist/>").expect("write plist");

    let out = run_envs(home.path(), &["/bin/echo", "hi"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stderr.contains("isn't running") && stderr.contains("envs daemon start"),
        "expected the daemon-stopped message; stderr was:\n{stderr}"
    );
    assert_eq!(out.status.code(), Some(75), "EX_TEMPFAIL expected");
}
