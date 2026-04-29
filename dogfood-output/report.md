# envs CLI — Dogfood Report

**Target**: envs CLI v0.1.0 (release build at `~/www/labs/envs/target/release/`)
**Session**: envs-cli-dogfood
**Date**: 2026-04-29
**Methodology**: CLI tool dogfooding (per /dogfood skill, adapted from web app workflow)

## Summary

| Severity | Count |
|---|---|
| Critical | 0 |
| High | 1 |
| Medium | 4 |
| Low | 2 |

**Most critical**: ISSUE-001 — daemon error responses leak Rust Debug formatting into user-facing stderr (high impact on UX, agent IA parsing).

## Test Strategy

24 shell-based test cases covering: `--help`, `--version`, no-args, error paths, all subcommands (run/init/doctor/rules/project/audit/registry/daemon/completions), live daemon e2e (status/list/resolve), system binary refusal, project profile flow.

## Findings

---

### ISSUE-001 — Daemon error responses leak Rust `Debug` format into stderr [HIGH]

**Repro**: T22 + T23 in transcripts.

```
$ ENVS_NONINTERACTIVE_OK=1 envs run -- /bin/echo hello
Error: Daemon { code: Internal, message: "bad input: scope=Any refused for system binary /bin/echo — use scope=ExactArgv or wrap with a personal script" }
```

**Expected**:
```
envs: scope=Any refused for system binary /bin/echo
hint: wrap /bin/echo with a personal script under ~/bin/, or use scope=ExactArgv
```

**Cause**: `crates/envs-cli/src/main.rs` returns `Result<(), CliError>` which `anyhow` formats with `{:?}` (Debug). The `CliError::Daemon { code, message }` Debug impl produces `Daemon { code: Internal, message: "..." }`.

**Fix**: implement custom `Display` formatting in main() instead of relying on anyhow's default. Map error to friendly stderr line + appropriate exit code.

**Severity rationale**: every error path is affected. AI agents parsing stderr will see confusing `Daemon { code: ...}` prefix. UX impact on every failure case.

---

### ISSUE-002 — Daemon code wrong for system binary refusal [MEDIUM]

**Repro**: T22 stderr.

The handler returns `DaemonError::BadInput("scope=Any refused...")` which maps to `ErrorCode::Internal` in `handlers.rs:dispatch`. There's already a `ErrorCode::SystemBinaryRefused` variant in `envs-proto` but it's never used.

**Fix**: in `handlers.rs`, add a specific `DaemonError::SystemBinaryRefused` variant or change the mapping for system-binary-refusal so it surfaces as `ErrorCode::SystemBinaryRefused` (which CLI maps to exit 77 `EX_NOPERM`).

---

### ISSUE-003 — `envs rules list` (no daemon) error inconsistent with `envs daemon status` [MEDIUM]

**Repro**:
```
$ envs rules list           # T09: exits 1, stderr "Error: DaemonNotRunning"
$ envs daemon status        # T10: exits 0, stdout "✗ daemon not running. Try ..."
```

Both should behave the same way. Pick one:
- (a) Both exit non-zero with consistent friendly stderr line
- (b) Both exit 0 with friendly stdout/stderr

Recommendation: (a) with exit 75 (EX_TEMPFAIL) — daemon down is a transient failure, not user error.

---

### ISSUE-004 — Helper stub silently authorizes scope=Any for system binaries [MEDIUM]

**Repro**: T22 — running `envs run -- /bin/echo hello` produces an error AT THE DAEMON because the stub helper grants scope=Any, then the daemon refuses scope=Any for system binaries. The user/agent sees a confusing path: "I asked, popup auto-granted, then daemon rejected".

**Expected**: the helper should know about system binaries and propose scope=ExactArgv by default. OR: the popup logic should propose scope=ExactArgv as the default for system binaries (visible in UI).

**Fix**: in `envs-prompt/src/main.rs::handle_request`, check `is_system_binary(canon_path)` (port the function from daemon to a shared place like envs-proto) and override `scope=Any` → `scope=ExactArgv { argv: req.argv.clone() }` when matched.

---

### ISSUE-005 — Stub helper authorization with empty bindings produces unhelpful error [MEDIUM]

**Repro**: T23 — running an unprofiled binary gets `Error: Daemon { code: Internal, message: "no bindings supplied (helper authorized empty grant)" }`.

**Expected**: friendly message: `envs: no profile or registry entry for <binary>. Run `envs project init` or create a profile manually.`

**Fix**: combine with ISSUE-001 (better Display) + add a hint about profile creation.

---

### ISSUE-006 — `(not yet implemented)` stubs exit 0 [LOW]

**Repro**: T13 — `envs registry sync` prints `(envs registry sync is not yet implemented in v0.1)` to stdout and exits 0.

**Expected**: print to stderr and exit 64 (EX_USAGE) or 70 (EX_SOFTWARE). Exit 0 means success — wrong signal for "feature unavailable".

Affected commands: `envs registry sync`, `envs registry show`, `envs daemon start/install/uninstall`, `envs project link`, `envs completions` partial (now real in v0.2).

---

### ISSUE-007 — `audit show` and `audit verify` empty-state messages diverge [LOW]

**Repro**:
```
$ envs audit show         # T08: "(no audit log yet — daemon hasn't started or no events recorded)"
$ envs audit verify       # T07: "(no audit log yet)"
```

Cosmetic but inconsistent. Both should print the same empty-state line.

---

## What's working well

- `envs --help` is comprehensive and well-formatted
- `envs doctor` correctly diagnoses missing rbw + missing daemon + Xcode present
- `envs completions zsh|bash|fish` produces valid shell completion scripts
- `envs project init` is clear, prompts for `.gitignore` choice idempotently
- Daemon start-up + IPC ping/status/list works under mtmpdir+stub conditions (T20-T21)
- Audit log writes daemon_start + daemon_stop with valid HMAC chain entries
- File permissions on `~/.envs/state/audit.key` and `~/.envs/state/rules.toml` correctly set to 0600
- Directory permissions on `~/.envs/logs/` and `~/.envs/state/` correctly set to 0700

## Recommended fix order

1. **ISSUE-001** (high) — block on this for next ship; affects every failure path
2. **ISSUE-002** + **ISSUE-005** (medium) — clean error codes + helpful hints
3. **ISSUE-004** (medium) — system-binary-aware helper to avoid the round-trip
4. **ISSUE-003** (medium) — consistent daemon-down behavior
5. **ISSUE-006** (low) — stub commands exit non-zero
6. **ISSUE-007** (low) — message consistency
