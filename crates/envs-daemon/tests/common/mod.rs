//! Black-box test fixtures: real Vaultwarden + real rbw + real envsd.
//!
//! Spins up a Vaultwarden container per test (testcontainers), registers a
//! fresh account via the Bitwarden HTTP signup endpoint (KDF + AES + HMAC
//! computed in Rust, no `bw` CLI), bootstraps `rbw` against that vault, and
//! returns helpers that drive `envsd` end-to-end.
//!
//! No bash rbw shim. No mocks. The whole pipeline runs.

#![allow(dead_code)] // each test file uses a subset

use aes::cipher::{block_padding::Pkcs7, generic_array::GenericArray, BlockEncryptMut, KeyIvInit};
use base64::Engine;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use testcontainers::core::{IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

const KDF_ITERATIONS: u32 = 600_000;
pub const TEST_PASSWORD: &str = "test-master-password-123";

/// One-shot probe — fail fast if Docker isn't reachable.
fn require_docker() {
    let ok = Command::new("docker")
        .arg("info")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !ok {
        panic!(
            "Docker daemon not reachable. Black-box integration tests require docker; \
             start Docker Desktop or set up a remote DOCKER_HOST."
        );
    }
}

/// Per-test fixture: a Vaultwarden container, a registered account, an
/// initialised `rbw` profile and helper binaries on PATH that an `envsd` child
/// can find.
pub struct VaultFixture {
    _container: ContainerAsync<GenericImage>,
    pub url: String,
    pub email: String,
    pub home: tempfile::TempDir,
    pub rbw_path: PathBuf,
    pub envs_prompt_path: PathBuf,
    pub pinentry_path: PathBuf,
}

impl VaultFixture {
    /// Spin up a fresh vaultwarden, register a unique account, configure rbw,
    /// log in + unlock. Async because testcontainers' AsyncRunner is the only
    /// runner usable from inside `#[tokio::test]`.
    pub async fn start() -> Self {
        require_docker();

        let container = GenericImage::new("vaultwarden/server", "1.35.8-alpine")
            .with_exposed_port(80.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Rocket has launched"))
            .with_env_var("ROCKET_ADDRESS", "0.0.0.0")
            .with_env_var("ROCKET_PORT", "80")
            .with_env_var("SIGNUPS_ALLOWED", "true")
            .with_env_var("I_REALLY_WANT_VOLATILE_STORAGE", "true")
            .with_env_var("WEB_VAULT_ENABLED", "false")
            .start()
            .await
            .expect("vaultwarden start");
        let port = container
            .get_host_port_ipv4(80)
            .await
            .expect("vaultwarden port mapping");
        let url = format!("http://127.0.0.1:{port}");

        let email = format!("envs-test-{}@local", uuid::Uuid::new_v4());
        register_account(&url, &email, TEST_PASSWORD).expect("register account");

        let home = tempfile::tempdir().expect("home tempdir");
        let envs_home = home.path().join("home");
        std::fs::create_dir_all(envs_home.join(".envs/state")).unwrap();
        std::fs::create_dir_all(envs_home.join(".envs/logs")).unwrap();
        std::fs::create_dir_all(envs_home.join(".envs/profiles")).unwrap();
        // rbw-agent needs $XDG_RUNTIME_DIR to exist for its socket. We create
        // a per-test one with mode 0700 so concurrent tests can each spawn
        // their own agent without colliding.
        let xdg_runtime = envs_home.join(".xdg-runtime");
        std::fs::create_dir_all(&xdg_runtime).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&xdg_runtime, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Resolve real binaries we need.
        let rbw_path =
            which("rbw").expect("rbw must be installed (brew install rbw / cargo install rbw)");
        let _rbw_agent = which("rbw-agent").expect("rbw-agent must be installed alongside rbw");
        // envs-prompt isn't in this crate, so CARGO_BIN_EXE_envs-prompt isn't set.
        // The daemon spawns envs-prompt via PATH in non-stub mode; in stub mode
        // (ENVS_HELPER_STUB=1) it's never invoked. We still surface the path for
        // tests that want to put it on PATH explicitly.
        let envs_prompt_path =
            workspace_target_release_or_debug("envs-prompt").unwrap_or_else(|| {
                // Fallback: rely on system PATH.
                which("envs-prompt").unwrap_or_else(|| PathBuf::from("envs-prompt"))
            });

        // Custom pinentry stub that emits TEST_PASSWORD — replaces TouchID.
        let pinentry_path = home.path().join("pinentry-stub");
        std::fs::write(
            &pinentry_path,
            format!(
                "#!/usr/bin/env bash\n\
                 set -eu\n\
                 echo 'OK Pleased to meet you'\n\
                 while IFS= read -r line; do\n  \
                   case \"$line\" in\n    \
                     GETPIN*) printf 'D %s\\n' '{password}'; printf 'OK\\n' ;;\n    \
                     BYE*)    printf 'OK closing\\n'; exit 0 ;;\n    \
                     *)       printf 'OK\\n' ;;\n  \
                   esac\n\
                 done\n",
                password = TEST_PASSWORD
            ),
        )
        .unwrap();
        std::fs::set_permissions(&pinentry_path, std::fs::Permissions::from_mode(0o755)).unwrap();

        // Configure rbw with isolated HOME, point it at the vaultwarden +
        // pinentry stub.
        rbw_run(&rbw_path, &envs_home, &["config", "set", "base_url", &url]);
        rbw_run(&rbw_path, &envs_home, &["config", "set", "email", &email]);
        rbw_run(
            &rbw_path,
            &envs_home,
            &["config", "set", "pinentry", pinentry_path.to_str().unwrap()],
        );
        rbw_run(&rbw_path, &envs_home, &["login"]);
        rbw_run(&rbw_path, &envs_home, &["unlock"]);

        Self {
            _container: container,
            url,
            email,
            home,
            rbw_path,
            envs_prompt_path,
            pinentry_path,
        }
    }

    pub fn envs_home(&self) -> PathBuf {
        self.home.path().join("home")
    }

    /// Add a Bitwarden item via real rbw (the daemon's `rbw get` will see it).
    pub fn rbw_add(&self, name: &str, password: &str) {
        let mut cmd = Command::new(&self.rbw_path);
        cmd.env("HOME", self.envs_home())
            .env("XDG_RUNTIME_DIR", self.envs_home().join(".xdg-runtime"))
            .arg("add")
            .arg(name)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().expect("rbw add spawn");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(password.as_bytes())
            .unwrap();
        let out = child.wait_with_output().expect("rbw add wait");
        assert!(
            out.status.success(),
            "rbw add {name} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    /// Lock the vault (so subsequent envsd resolve must auto-unlock).
    pub fn rbw_lock(&self) {
        // `rbw lock` exits non-zero if no agent is running — tolerate that.
        let _ = Command::new(&self.rbw_path)
            .env("HOME", self.envs_home())
            .env("XDG_RUNTIME_DIR", self.envs_home().join(".xdg-runtime"))
            .arg("lock")
            .output();
    }

    /// Plant a `~/.envs/profiles/<binary>.toml` for the daemon.
    pub fn write_profile(&self, binary: &str, bindings: &[(&str, &str)]) {
        let mut s = format!("schema = 1\n[binary]\nname = \"{binary}\"\n");
        for (env, src) in bindings {
            s.push_str(&format!("[[binding]]\nenv = \"{env}\"\nsrc = \"{src}\"\n"));
        }
        let p = self
            .envs_home()
            .join(".envs/profiles")
            .join(format!("{binary}.toml"));
        std::fs::write(p, s).unwrap();
    }

    /// Plant `<project_root>/.envs/<binary>.toml` (project-local profile).
    pub fn write_project_profile(
        &self,
        project_root: &Path,
        binary: &str,
        bindings: &[(&str, &str)],
    ) {
        let envs_dir = project_root.join(".envs");
        std::fs::create_dir_all(&envs_dir).unwrap();
        let mut s = format!("schema = 1\n[binary]\nname = \"{binary}\"\n");
        for (env, src) in bindings {
            s.push_str(&format!("[[binding]]\nenv = \"{env}\"\nsrc = \"{src}\"\n"));
        }
        std::fs::write(envs_dir.join(format!("{binary}.toml")), s).unwrap();
    }

    /// Replace the pinentry stub with one that ALWAYS fails, so any
    /// `rbw unlock` triggered by envsd's auto-unlock will return non-zero
    /// and the daemon must surface RbwLocked. Useful for the
    /// vault-locked-error test path.
    pub fn break_pinentry(&self) {
        std::fs::write(
            &self.pinentry_path,
            "#!/usr/bin/env bash\necho 'OK'\nwhile read -r line; do\n  case \"$line\" in\n    GETPIN*) printf 'ERR 83886179 wrong password\\n' ;;\n    BYE*) exit 1 ;;\n    *) printf 'OK\\n' ;;\n  esac\ndone\nexit 1\n",
        )
        .unwrap();
    }
}

fn rbw_run(rbw: &Path, envs_home: &Path, args: &[&str]) {
    let out = Command::new(rbw)
        .env("HOME", envs_home)
        // Per-test rbw-agent socket so parallel tests don't collide.
        .env("XDG_RUNTIME_DIR", envs_home.join(".xdg-runtime"))
        .args(args)
        .output()
        .expect("rbw spawn");
    assert!(
        out.status.success(),
        "rbw {} failed:\nstdout:{}\nstderr:{}",
        args.join(" "),
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn which(bin: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(bin);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// Look for a sibling binary in the workspace's target dir. cargo test sets
/// `CARGO_TARGET_TMPDIR` and we know the binary is built one level up.
fn workspace_target_release_or_debug(bin: &str) -> Option<PathBuf> {
    // CARGO_BIN_EXE_envsd points at <target>/<profile>/deps/envsd-<hash>?
    // No — it points at <target>/<profile>/envsd. Strip filename, sibling lookup.
    let envsd = PathBuf::from(env!("CARGO_BIN_EXE_envsd"));
    let dir = envsd.parent()?;
    let candidate = dir.join(bin);
    if candidate.is_file() {
        Some(candidate)
    } else {
        None
    }
}

/// Bitwarden / Vaultwarden account registration via raw HTTP. Implements the
/// PBKDF2 + AES-CBC + HMAC dance the official `bw` CLI no longer exposes.
fn register_account(base_url: &str, email: &str, password: &str) -> Result<(), String> {
    let email_lower = email.to_lowercase();

    // PBKDF2(password, email, 600_000) → masterKey (32 bytes)
    let mut master_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        email_lower.as_bytes(),
        KDF_ITERATIONS,
        &mut master_key,
    );

    // PBKDF2(masterKey, password, 1) → masterPasswordHash → base64
    let mut master_pw_hash = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(&master_key, password.as_bytes(), 1, &mut master_pw_hash);
    let master_pw_hash_b64 = base64::engine::general_purpose::STANDARD.encode(master_pw_hash);

    // HKDF-Expand → enc + mac stretched keys (Bitwarden style: HMAC-SHA256
    // with single-byte counter, taking the full 32-byte digest each time).
    let enc_key = hkdf_expand_one_block(&master_key, b"enc");
    let mac_key = hkdf_expand_one_block(&master_key, b"mac");

    // Random user symmetric key (64 bytes)
    let mut user_key = [0u8; 64];
    rand::thread_rng().fill_bytes(&mut user_key);

    // AES-256-CBC encrypt(userKey) with enc_key + iv
    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);
    // user_key is 64 bytes; PKCS7 pads to next 16-byte boundary → 80 bytes.
    let mut buf = vec![0u8; user_key.len() + 16];
    buf[..user_key.len()].copy_from_slice(&user_key);
    let key_arr: GenericArray<u8, _> = GenericArray::clone_from_slice(&enc_key);
    let iv_arr: GenericArray<u8, _> = GenericArray::clone_from_slice(&iv);
    let ct_len = Aes256CbcEnc::new(&key_arr, &iv_arr)
        .encrypt_padded_mut::<Pkcs7>(&mut buf, user_key.len())
        .expect("AES-CBC encrypt")
        .len();
    let ciphertext = buf[..ct_len].to_vec();

    // HMAC-SHA256(iv || ciphertext) with mac_key
    let mut hmac = HmacSha256::new_from_slice(&mac_key).unwrap();
    hmac.update(&iv);
    hmac.update(&ciphertext);
    let mac = hmac.finalize().into_bytes();

    // Bitwarden EncString type 2: "2.<iv_b64>|<ct_b64>|<mac_b64>"
    let b64 = base64::engine::general_purpose::STANDARD;
    let protected_key = format!(
        "2.{}|{}|{}",
        b64.encode(iv),
        b64.encode(&ciphertext),
        b64.encode(mac)
    );

    // RSA-2048 keypair: Bitwarden requires a publicKey + encryptedPrivateKey
    // pair. The private key is wrapped by the user symmetric key.
    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let mut rng = rand::thread_rng();
    let priv_key = rsa::RsaPrivateKey::new(&mut rng, 2048).expect("rsa keygen");
    let pub_key = rsa::RsaPublicKey::from(&priv_key);
    let priv_der = priv_key
        .to_pkcs8_der()
        .expect("priv DER")
        .as_bytes()
        .to_vec();
    let pub_der = pub_key
        .to_public_key_der()
        .expect("pub DER")
        .as_bytes()
        .to_vec();

    // Encrypt PKCS8 private key DER with user_key (enc half + mac half).
    let user_enc = &user_key[..32];
    let user_mac = &user_key[32..];
    let mut iv2 = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv2);
    let mut buf2 = vec![0u8; priv_der.len() + 16];
    buf2[..priv_der.len()].copy_from_slice(&priv_der);
    let key2_arr: GenericArray<u8, _> = GenericArray::clone_from_slice(user_enc);
    let iv2_arr: GenericArray<u8, _> = GenericArray::clone_from_slice(&iv2);
    let priv_ct_len = Aes256CbcEnc::new(&key2_arr, &iv2_arr)
        .encrypt_padded_mut::<Pkcs7>(&mut buf2, priv_der.len())
        .expect("AES-CBC encrypt private")
        .len();
    let priv_ct = buf2[..priv_ct_len].to_vec();
    let mut hmac2 = HmacSha256::new_from_slice(user_mac).unwrap();
    hmac2.update(&iv2);
    hmac2.update(&priv_ct);
    let priv_mac = hmac2.finalize().into_bytes();
    let encrypted_private_key = format!(
        "2.{}|{}|{}",
        b64.encode(iv2),
        b64.encode(&priv_ct),
        b64.encode(priv_mac)
    );

    let body = serde_json::json!({
        "email": email,
        "name": "envs-test",
        "masterPasswordHash": master_pw_hash_b64,
        "masterPasswordHint": null,
        "key": protected_key,
        "keys": {
            "publicKey": b64.encode(&pub_der),
            "encryptedPrivateKey": encrypted_private_key,
        },
        "kdf": 0,
        "kdfIterations": KDF_ITERATIONS,
    });

    let url = format!("{base_url}/identity/accounts/register");
    let response = ureq::post(&url)
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|e| format!("register POST: {e}"))?;
    if response.status() != 200 && response.status() != 204 {
        return Err(format!(
            "register failed: {} {}",
            response.status(),
            response.into_string().unwrap_or_default()
        ));
    }
    Ok(())
}

fn hkdf_expand_one_block(prk: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let mut hmac = HmacSha256::new_from_slice(prk).unwrap();
    hmac.update(info);
    hmac.update(&[1]);
    hmac.finalize().into_bytes().into()
}

// ─── envsd handle ───────────────────────────────────────────────────────────

pub struct DaemonHandle {
    pub child: Child,
    pub socket: PathBuf,
    pub envs_home: PathBuf,
    /// Keep the fixture alive for the duration of the test (the rbw vault
    /// lives in tmp inside the fixture's home).
    pub _fixture: VaultFixture,
}

impl DaemonHandle {
    /// Probe the real rbw vault's lock state (used by tests asserting the
    /// auto-lock / auto-unlock cycle without log-file inspection).
    pub fn rbw_unlocked(&self) -> bool {
        Command::new(&self._fixture.rbw_path)
            .env("HOME", &self.envs_home)
            .env("XDG_RUNTIME_DIR", self.envs_home.join(".xdg-runtime"))
            .arg("unlocked")
            .status()
            .expect("rbw unlocked")
            .success()
    }
}

impl Drop for DaemonHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Spin up a daemon child with PATH including the real rbw + envs-prompt, the
/// fixture's HOME, and the helper-stub mode (so we don't need a real popup).
pub fn start_daemon(fx: VaultFixture) -> DaemonHandle {
    let socket = fx.home.path().join("envsd.sock");
    let envs_home = fx.envs_home();

    let envsd = env!("CARGO_BIN_EXE_envsd");
    let path_var = std::env::var("PATH").unwrap_or_default();
    let extra_path = format!(
        "{}:{}:{path_var}",
        fx.rbw_path.parent().unwrap().display(),
        fx.envs_prompt_path.parent().unwrap().display(),
    );

    let xdg_runtime = envs_home.join(".xdg-runtime");
    let child = Command::new(envsd)
        .env("HOME", &envs_home)
        .env("XDG_RUNTIME_DIR", &xdg_runtime)
        .env("ENVS_SOCKET", &socket)
        .env("ENVS_HELPER_STUB", "1")
        .env("ENVS_SKIP_REGISTRY_SYNC", "1")
        .env("PATH", &extra_path)
        .env("RUST_LOG", "envsd=warn")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn envsd");

    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline && !socket.exists() {
        std::thread::sleep(Duration::from_millis(50));
    }
    assert!(socket.exists(), "envsd never created its socket");

    DaemonHandle {
        child,
        socket,
        envs_home,
        _fixture: fx,
    }
}

/// Roundtrip a request through the daemon's UDS.
pub async fn send(socket: &Path, req: &envs_proto::Request) -> envs_proto::Response {
    let stream = UnixStream::connect(socket).await.expect("connect uds");
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

/// Convenience: a Resolve request targeting `/usr/bin/env` (or whatever
/// `binary` is) — most tests just need a syntactically valid request.
pub fn resolve_request_for(binary: impl Into<PathBuf>, argv: Vec<String>) -> envs_proto::Request {
    envs_proto::Request::Resolve {
        canon_path: binary.into(),
        sha256: "deadbeef".into(),
        codesign_team: None,
        argv,
        cwd: std::env::temp_dir(),
        project_root: None,
        client_pid: std::process::id() as i32,
        profiles: Vec::new(),
        extra_bindings: Vec::new(),
    }
}
