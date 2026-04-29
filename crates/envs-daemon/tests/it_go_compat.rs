//! Cross-language compatibility test: env vars injected by `envs run` must
//! reach a Go binary, which bypasses libc `getenv` and reads `runtime.envs` at
//! startup. This is the primary use case (flarectl/wrangler are Go binaries).
//!
//! The test:
//!   1. Compiles `tests/fixtures/printenv-go/main.go` if `go` is on PATH.
//!   2. Spawns the daemon + stub helper + fake rbw shim.
//!   3. Sends a Resolve request for the Go binary.
//!   4. Spawns the Go binary directly with the resolved env, asserts it prints
//!      the expected value (proving `os.Getenv` reads what we injected).
//!
//! Skipped (not failed) if `go` is not installed.

use envs_proto::{Request, Response};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

fn go_available() -> bool {
    Command::new("go")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

#[tokio::test]
async fn go_binary_sees_injected_env() {
    if !go_available() {
        eprintln!("skipping: `go` not on PATH");
        return;
    }

    // 1. Compile the Go fixture in a tempdir.
    let tmp = tempfile::tempdir().expect("tempdir");
    let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let go_src = workspace_root.join("tests/fixtures/printenv-go/main.go");
    let go_bin = tmp.path().join("printenv-go");
    let build = Command::new("go")
        .args(["build", "-o"])
        .arg(&go_bin)
        .arg(&go_src)
        .output()
        .expect("go build");
    assert!(
        build.status.success(),
        "go build failed: {}",
        String::from_utf8_lossy(&build.stderr)
    );
    assert!(go_bin.exists(), "go binary missing");

    // 2. Setup daemon + fake rbw + stub helper
    let socket = tmp.path().join("envsd.sock");
    let envs_home = tmp.path().join("home");
    std::fs::create_dir_all(envs_home.join(".envs/state")).unwrap();
    std::fs::create_dir_all(envs_home.join(".envs/logs")).unwrap();
    std::fs::create_dir_all(envs_home.join(".envs/profiles")).unwrap();

    // Profile that maps GO_TOKEN to rbw
    let bin_name = go_bin.file_name().unwrap().to_string_lossy().to_string();
    let profile_path = envs_home
        .join(".envs/profiles")
        .join(format!("{bin_name}.toml"));
    std::fs::write(
        &profile_path,
        r#"
schema = 1
[binary]
name = "printenv-go"
[[binding]]
env = "GO_TOKEN"
src = "rbw://GO_TOKEN"
"#,
    )
    .unwrap();

    // Fake rbw shim
    let bin_dir = tmp.path().join("bin");
    std::fs::create_dir_all(&bin_dir).unwrap();
    let rbw_path = bin_dir.join("rbw");
    let mut f = std::fs::File::create(&rbw_path).unwrap();
    writeln!(
        f,
        "#!/bin/bash\n\
         case \"$1\" in\n  \
           --version) echo 'rbw-shim'; exit 0 ;;\n  \
           unlocked) exit 0 ;;\n  \
           get) item=\"$2\"; field=password; if [ \"$3\" = --field ]; then field=\"$4\"; fi; echo \"go-secret-$item-$field\"; exit 0 ;;\n  \
           *) exit 1 ;;\n\
         esac"
    )
    .unwrap();
    drop(f);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&rbw_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    // 3. Spawn daemon
    let envsd_bin = env!("CARGO_BIN_EXE_envsd");
    let path_var = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );

    let mut child = Command::new(envsd_bin)
        .env("HOME", &envs_home)
        .env("ENVS_SOCKET", &socket)
        .env("ENVS_HELPER_STUB", "1")
        .env("ENVS_SKIP_REGISTRY_SYNC", "1")
        .env("PATH", &path_var)
        .env("RUST_LOG", "envs_daemon=warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn envsd");

    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && !socket.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(socket.exists());

    // 4. Send Resolve to daemon
    let stream = UnixStream::connect(&socket).await.unwrap();
    let (read_half, mut write_half) = stream.into_split();
    let req = Request::Resolve {
        canon_path: go_bin.clone(),
        sha256: "deadbeef".into(),
        codesign_team: None,
        argv: vec![bin_name.clone(), "GO_TOKEN".into()],
        cwd: tmp.path().to_path_buf(),
        project_root: None,
        client_pid: std::process::id() as i32,
        profiles: vec![],
        extra_bindings: vec![],
    };
    let mut buf = serde_json::to_vec(&req).unwrap();
    buf.push(b'\n');
    write_half.write_all(&buf).await.unwrap();
    write_half.flush().await.unwrap();
    drop(write_half);

    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let n = reader.read_line(&mut line).await.unwrap();
    assert!(n > 0);
    let resp: Response = serde_json::from_str(line.trim()).expect("parse");
    let entries = match resp {
        Response::Resolved { entries, .. } => entries,
        other => panic!("expected Resolved, got {other:?}"),
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, "GO_TOKEN");
    assert_eq!(entries[0].value, "go-secret-GO_TOKEN-password");

    // 5. Spawn the Go binary with the injected env, assert it sees the value
    let go_output = Command::new(&go_bin)
        .arg("GO_TOKEN")
        .env("GO_TOKEN", &entries[0].value)
        .output()
        .expect("run printenv-go");
    assert!(
        go_output.status.success(),
        "Go binary exited non-zero: {}",
        String::from_utf8_lossy(&go_output.stderr)
    );
    let stdout = String::from_utf8_lossy(&go_output.stdout);
    assert_eq!(
        stdout.trim(),
        "GO_TOKEN=go-secret-GO_TOKEN-password",
        "Go binary did not see injected env: stdout='{stdout}'"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// Smoke test: confirm the workspace fixture file exists.
#[test]
fn go_fixture_source_exists() {
    let workspace_root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let go_src: PathBuf = workspace_root.join("tests/fixtures/printenv-go/main.go");
    assert!(
        go_src.exists(),
        "Go fixture source missing at {}",
        go_src.display()
    );
}
