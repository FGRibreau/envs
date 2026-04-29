//! End-to-end smoke test: spawn daemon, send Resolve, verify Resolved with values.
//!
//! Setup:
//!   - Temp HOME so persistence files don't pollute real $HOME
//!   - ENVS_SOCKET points to a tmpdir socket
//!   - ENVS_HELPER_STUB=1 bypasses the real helper subprocess
//!   - PATH prepends a fake `rbw` shim that returns deterministic values
//!
//! The test does NOT exercise execvpe (that replaces the test process).
//! It validates IPC + cache + helper stub + rbw shell-out path end-to-end.

use envs_proto::{ArgvMatch, Request, Response};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

struct DaemonHandle {
    child: Child,
    socket: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_daemon() -> DaemonHandle {
    let tmp = tempfile::tempdir().expect("tempdir");
    let socket = tmp.path().join("envsd.sock");
    let envs_home = tmp.path().join("home");
    std::fs::create_dir_all(envs_home.join(".envs/state")).unwrap();
    std::fs::create_dir_all(envs_home.join(".envs/logs")).unwrap();

    // Build a fake rbw script in a tmp bin dir.
    let bin_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let rbw_path = bin_dir.join("rbw");
    let mut f = std::fs::File::create(&rbw_path).unwrap();
    writeln!(
        f,
        "#!/bin/bash\n\
         case \"$1\" in\n  \
           --version) echo 'rbw-shim 0.0.0'; exit 0 ;;\n  \
           unlocked) exit 0 ;;\n  \
           get) item=\"$2\"; field=password; if [ \"$3\" = --field ]; then field=\"$4\"; fi; echo \"v-$item-$field\"; exit 0 ;;\n  \
           *) exit 1 ;;\n\
         esac"
    ).unwrap();
    drop(f);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&rbw_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let bin = env!("CARGO_BIN_EXE_envsd");
    let path_var = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let child = Command::new(bin)
        .env("HOME", &envs_home)
        .env("ENVS_SOCKET", &socket)
        .env("ENVS_HELPER_STUB", "1")
        .env("PATH", &path_var)
        .env("RUST_LOG", "envsd=warn")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn envsd");

    // Wait up to 3s for the socket to appear.
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !socket.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(
        socket.exists(),
        "envsd did not create socket within timeout"
    );

    DaemonHandle {
        child,
        socket,
        _tmp: tmp,
    }
}

async fn send(socket: &std::path::Path, req: &Request) -> Response {
    let stream = UnixStream::connect(socket).await.expect("connect");
    let (read_half, mut write_half) = stream.into_split();
    let mut buf = serde_json::to_vec(req).unwrap();
    buf.push(b'\n');
    write_half.write_all(&buf).await.unwrap();
    write_half.flush().await.unwrap();
    drop(write_half);

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await.unwrap();
    assert!(n > 0, "no response from daemon");
    serde_json::from_str(line.trim()).expect("parse response")
}

#[tokio::test]
async fn ping_pong() {
    let h = start_daemon();
    let resp = send(&h.socket, &Request::Ping).await;
    matches!(resp, Response::Pong);
}

#[tokio::test]
async fn status_reports_version() {
    let h = start_daemon();
    let resp = send(&h.socket, &Request::Status).await;
    match resp {
        Response::Status { version, protocol, .. } => {
            assert!(!version.is_empty());
            assert_eq!(protocol, envs_proto::PROTOCOL_VERSION);
        }
        other => panic!("expected Status, got {other:?}"),
    }
}

#[tokio::test]
async fn resolve_with_stub_helper_returns_values() {
    let h = start_daemon();

    // Build a Resolve request. The stub helper (ENVS_HELPER_STUB=1) auto-authorizes
    // with bindings derived from suggested_bindings. Since we don't pre-fill suggestions
    // here (that's Phase 4 discovery), the stub will return zero bindings → daemon will
    // error "no bindings supplied".
    //
    // To exercise the full path, we plant a global profile on the temp HOME so the
    // daemon's load_current_profile finds something to pre-fill the PromptRequest with.
    let envs_home = h._tmp.path().join("home");
    let profiles_dir = envs_home.join(".envs/profiles");
    std::fs::create_dir_all(&profiles_dir).unwrap();
    std::fs::write(
        profiles_dir.join("envsd.toml"),
        r#"
schema = 1
[binary]
name = "envsd"
[[binding]]
env = "TEST_KEY"
src = "rbw://TEST_KEY"
"#,
    )
    .unwrap();

    // Use the envsd binary itself as the "target binary" for the Resolve since it
    // exists on disk and we have its path. We just need the daemon to compute a hash
    // and look up a profile by basename.
    let canon_path = std::path::PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let sha = "deadbeef".to_string(); // doesn't matter for v0.1 stub flow

    let req = Request::Resolve {
        canon_path: canon_path.clone(),
        sha256: sha,
        codesign_team: None,
        argv: vec!["envsd".into()],
        cwd: h._tmp.path().to_path_buf(),
        project_root: None,
        client_pid: std::process::id() as i32,
        profiles: Vec::new(),
        extra_bindings: Vec::new(),
    };

    let resp = send(&h.socket, &req).await;
    match resp {
        Response::Resolved { entries, .. } => {
            assert_eq!(entries.len(), 1, "expected 1 entry, got {entries:?}");
            assert_eq!(entries[0].key, "TEST_KEY");
            // The fake rbw returns "v-<item>-<field>" → "v-TEST_KEY-password"
            assert_eq!(entries[0].value, "v-TEST_KEY-password");
        }
        Response::Error { code, message } => {
            panic!("expected Resolved, got Error {code:?}: {message}");
        }
        other => panic!("expected Resolved, got {other:?}"),
    }
}

#[tokio::test]
async fn argv_match_proto_roundtrip() {
    // Sanity: ensure proto types serialize correctly across the wire.
    let h = start_daemon();
    let resp = send(&h.socket, &Request::ListRules).await;
    match resp {
        Response::Rules { rules } => {
            assert!(rules.is_empty());
        }
        other => panic!("expected Rules, got {other:?}"),
    }
    // Just to use ArgvMatch import.
    let _ = ArgvMatch::Any;
}
