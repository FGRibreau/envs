# Development

How to build, test, and contribute to `envs`.

## Architecture

3 Rust binaries that talk to each other over Unix domain sockets and stdin/stdout pipes:

- **`envs`** — the CLI wrapper. Short-lived process, one per command invocation. Resolves binary path + sha256, sends a `Resolve` request to `envsd`, then `execvpe`s the target with the merged environ.
- **`envsd`** — the long-running daemon. Owns the rule cache (in memory + persisted metadata), spawns the helper, talks to Bitwarden via `rbw`, writes the audit log.
- **`envs-prompt`** — the native macOS popup helper (`objc2-app-kit` + `LAContext`). Spawned by `envsd` and supervised with crash-respawn.

Backend: Bitwarden personal vault via [`rbw`](https://github.com/doy/rbw) shell-out.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design and [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md) for what `envs` does and does not defend against.

## Build from source

```bash
git clone https://github.com/fgribreau/envs.git
cd envs
cargo build --release --workspace
```

Produces three binaries in `target/release/`:

| Binary | Size (approx) | Role |
|---|---|---|
| `envs` | ~2 MB | CLI wrapper |
| `envsd` | ~2 MB | daemon |
| `envs-prompt` | ~1.3 MB | popup helper |

To install them on your `PATH`:

```bash
cargo install --path crates/envs-cli
cargo install --path crates/envs-daemon
cargo install --path crates/envs-prompt
```

## Run the test suite

```bash
cargo test --workspace            # unit + integration tests (no TouchID required)
bash scripts/smoke.sh release     # 24 black-box CLI smoke tests
```

The Go cross-language compatibility test (`tests/it_go_compat.rs`) is skipped automatically if `go` is not on `PATH`.

The TouchID prompt and the native NSWindow can't be tested programmatically on macOS — there is no biometric simulator. Tests run with `ENVS_HELPER_STUB=1` (daemon side) or `ENVS_PROMPT_AUTO_GRANT=1` (helper side) which bypass the UI.

## Code layout

```
envs/
├── crates/
│   ├── envs-proto/           # IPC types shared by CLI ↔ daemon ↔ helper
│   ├── envs-cli/             # binary `envs`
│   ├── envs-daemon/          # binary `envsd` + integration tests
│   └── envs-prompt/          # binary `envs-prompt`
├── tests/fixtures/
│   └── printenv-go/          # Go program used by the cross-language test
├── packaging/
│   └── com.fgribreau.envsd.plist.template
├── scripts/
│   ├── smoke.sh              # CLI smoke tests
│   └── codesign.sh           # optional: codesign + notarize for distribution
├── specs/
│   └── spec.md               # full design + decision log
└── docs/
    ├── ARCHITECTURE.md
    ├── THREAT-MODEL.md
    ├── RELEASE.md            # distribution paths + notarization
    └── V03-V04-ROADMAP.md
```

## Release & distribution

See [docs/RELEASE.md](docs/RELEASE.md) for:

- Three distribution paths (`cargo install`, Homebrew tap, signed `.tar.gz`)
- One-time notarization setup with `xcrun notarytool store-credentials`
- The `scripts/codesign.sh` helper that codesigns + notarizes the release binaries

```bash
# Skip codesign (default — fine for cargo install / brew install paths):
scripts/codesign.sh

# Codesign + notarize (requires Apple Developer ID):
ENVS_APPLE_TEAM_ID=ABC1234567 ENVS_NOTARIZE=1 scripts/codesign.sh
```

## Conventions

The project follows the conventions documented in `CLAUDE.md` at the repo root and the personal one in `~/.claude/CLAUDE.md`. Highlights:

- All scripts are written in Rust (or Bash for shell glue like `smoke.sh`/`codesign.sh`)
- No `.unwrap()` / `.expect()` in business logic; functions that can fail return `Result<T, E>` and propagate with `?`
- `.expect()` is acceptable only for startup-time invariants (env reads, regex compilation)
- Tests are black-box; no mocks of internal services
- Errors carry friendly user-facing messages (`format_user_error` in `crates/envs-cli/src/error.rs`)

## Contributing

1. Fork the repo and create a feature branch
2. Ensure `cargo test --workspace` and `bash scripts/smoke.sh release` are green
3. Open a PR with a description of the change and which spec section it touches

Bug reports and feature requests welcome on [GitHub Issues](https://github.com/fgribreau/envs/issues).
