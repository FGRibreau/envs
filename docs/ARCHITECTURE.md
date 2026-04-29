# Architecture — `envs`

## High-level diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│ User shell (or AI agent)                                                 │
│                                                                          │
│   $ envs flarectl zone list                                              │
└────────────┬─────────────────────────────────────────────────────────────┘
             │ (1) UDS request: Resolve { canon_path, sha, argv, cwd, ... }
             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ envsd (daemon, long-running, started by launchd)                         │
│                                                                          │
│   ┌─────────────┐   ┌──────────────┐   ┌──────────────────────────────┐ │
│   │ UDS server  │ ← │  Rule cache  │ ← │ Persistence (~/.envs/state/) │ │
│   │ (tokio)     │   │  (RwLock)    │   │ - rules.toml metadata        │ │
│   └─────┬───────┘   └──────┬───────┘   └──────────────────────────────┘ │
│         │                  │                                              │
│         │             ┌────▼─────┐                                        │
│         │             │  Value   │ ← (3) `rbw get <item> --field <fld>`  │
│         │             │  cache   │                                        │
│         │             │  (30s)   │                                        │
│         │             └──────────┘                                        │
│         │                                                                 │
│         │ (2) on cache miss for rule                                      │
│         ▼                                                                 │
│   ┌─────────────────────────────────────────────────────────────────┐   │
│   │ Helper supervisor                                                │   │
│   │ - spawns envs-prompt as child at boot                            │   │
│   │ - sends HelperEvent::NewRequest via stdin pipe                   │   │
│   │ - receives HelperReply::Authorized via stdout pipe                │   │
│   │ - respawn on crash (max 3 attempts)                               │   │
│   └─────────────────────┬───────────────────────────────────────────┘   │
│                          │                                                │
│   ┌──────────────────────┼─────────────────────────────────────────┐    │
│   │ Audit log writer (JSON Lines, append-only, rotated daily)       │    │
│   │ ~/.envs/logs/audit.jsonl                                         │    │
│   └─────────────────────────────────────────────────────────────────┘    │
└──────────────────────────┼──────────────────────────────────────────────┘
                            │ stdin/stdout JSON pipe
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ envs-prompt (helper, persistent, started by envsd)                       │
│                                                                          │
│  AppKit main thread (NSApplication.run)                                  │
│   ┌──────────────────────────────────────────┐                          │
│   │ NSWindow with tab list (one per request) │                          │
│   │  - bindings checkboxes                    │                          │
│   │  - scope radio (Any / Exact argv)         │                          │
│   │  - duration picker                        │                          │
│   │  - Save as profile (project / global)     │                          │
│   │  - [Authorize via TouchID]                │                          │
│   └────────────────────┬─────────────────────┘                          │
│                         │ user click                                     │
│                         ▼                                                 │
│   ┌──────────────────────────────────────────┐                          │
│   │ LAContext.evaluatePolicy(.biometrics)    │                          │
│   └────────────────────┬─────────────────────┘                          │
│                         │ TouchID OK                                     │
│                         │                                                 │
│  Background thread reads stdin for events ←─┘                           │
│  Sends HelperReply::Authorized to stdout ──→ daemon                     │
└─────────────────────────────────────────────────────────────────────────┘
                            │ (4) Resolved { entries: [(K,V)...] }
                            ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ envs CLI                                                                 │
│                                                                          │
│   (5) execvpe(canon_path, argv, env_with_secrets)                        │
│       — current process IS REPLACED by flarectl                          │
└────────────────────────────────────────────────────────────────────────-┘
                            │
                            ▼
                       flarectl runs.
                       It reads CF_API_TOKEN from its environ as usual.
                       It has no knowledge of envs.
```

## Components

### `envs` (CLI binary, ~400 LOC)

User-facing wrapper. For each invocation:

1. Parse argv via clap.
2. For `run` command: canonicalize the binary path, compute SHA256, extract codesign Team ID, walk up CWD for `.envs/` marker, build `Resolve` request.
3. Connect UDS to daemon, send request, await response.
4. On success: build merged env (inherited + injected), `execvpe` to target binary. Current process is replaced.
5. Other commands (`init`, `doctor`, `rules`, etc.) are administrative and don't involve the resolve flow.

### `envsd` (daemon binary, ~1000 LOC)

Long-running. Started by launchd at user login. Serves UDS at `~/.envs/envsd.sock`.

Key responsibilities:
- **UDS server** (tokio) — accept connections, parse JSON, dispatch to handlers
- **Rule cache** — in-memory `Vec<Rule>` behind `RwLock`; persisted metadata (no values) to `~/.envs/state/rules.toml`
- **Value cache** — in-memory `HashMap<(env_key, source), (SecretString, Instant)>` with 30s TTL
- **rbw client** — async wrapper around `rbw get`/`rbw list` subprocess calls
- **Helper supervisor** — spawn and respawn `envs-prompt` subprocess, pipe-based IPC
- **Audit log writer** — JSON Lines, daily rotation, never logs secret values
- **Sweep task** — purges expired rules and value cache entries every 30s, zeroizes secrets before drop
- **Caller verification** — `LOCAL_PEEREUID` + `proc_pidpath` to confirm the connecting CLI's identity matches what it claims

### `envs-prompt` (helper binary, ~600 LOC eventual)

Native macOS popup helper. **v0.1 ships a stub** that auto-authorizes (for end-to-end testing). v0.2+ implements the real native UI:

- `NSApplication.run()` on main thread (AppKit requirement)
- Background thread reads stdin for `HelperEvent` JSON
- `NSWindow` with tab list (one tab per pending request)
- Each tab: bindings checkboxes, scope radio, duration picker, save-as-profile choice
- "Authorize" button calls `LAContext.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics)`
- On TouchID OK, sends `HelperReply::Authorized` to stdout (daemon reads)
- Menubar item via `NSStatusBar` showing `(N pending)` when requests are queued

## Data flows

### Resolve flow (cache miss)

```
envs CLI                envsd                envs-prompt              rbw
   │                      │                       │                    │
   │── Resolve ──────────→│                       │                    │
   │                      │── lookup rule ────────┤                    │
   │                      │   miss                 │                    │
   │                      │── NewRequest ─────────→│                    │
   │                      │                       │── show popup       │
   │                      │                       │── user TouchID OK  │
   │                      │← Authorized ──────────│                    │
   │                      │── persist rule ───┐                        │
   │                      │← OK ──────────────┘                        │
   │                      │                                              │
   │                      │── rbw get ──────────────────────────────────→│
   │                      │← value ───────────────────────────────────────│
   │                      │── cache value (30s TTL)                       │
   │                      │                                              │
   │← Resolved ───────────│                                              │
   │                                                                       │
   │── execvpe target binary with merged env                               │
```

### Resolve flow (cache hit)

```
envs CLI                envsd                                             rbw
   │                      │                                                 │
   │── Resolve ──────────→│                                                 │
   │                      │── lookup rule (active, valid)                   │
   │                      │── lookup value cache                            │
   │                      │   hit                                            │
   │← Resolved ───────────│                                                 │
   │                                                                          │
   │── execvpe target binary with merged env                                  │
```

No popup, no rbw call. ~5ms overhead.

## File layout

```
~/.envs/
├── envsd.sock            # UDS, mode 0600
├── envsd.pid
├── config.toml           # user config
├── profiles/             # global profiles
│   ├── flarectl.toml
│   └── wrangler.toml
├── state/
│   └── rules.toml        # active rules (metadata only)
├── registry/             # cloned envs-registry repo
│   └── binaries/
│       └── flarectl.toml
├── llm-cache.json        # opt-in LLM discovery cache
└── logs/
    ├── envsd.log
    └── audit.jsonl       # rotated daily

# Per-project marker
~/www/image-charts/.envs/
├── flarectl.toml
└── wrangler.toml
```

## IPC formats

### CLI ↔ daemon (UDS)

Newline-delimited JSON. One request → one response per connection. Type definitions in `crates/envs-proto/src/lib.rs`: `Request` and `Response` enums.

### Daemon ↔ helper (stdin/stdout pipe)

Newline-delimited JSON. Bidirectional async events. Type definitions: `HelperEvent` (daemon → helper) and `HelperReply` (helper → daemon).

## Security boundaries

| Boundary | Mechanism |
|---|---|
| User isolation | macOS UID — each user has their own envsd, socket, rules |
| Cross-process | UDS perm 0600, parent dir 0700 |
| Biometric authentication | `LAContext.evaluatePolicy` — secure enclave verification |
| Secret in transit | UDS stays in kernel memory, never on disk |
| Secret at rest | rbw vault is encrypted with user's master password; envs persists no values |
| Caller identity | `LOCAL_PEEREUID` (UID match) + `proc_pidpath` (path verification) |
| Binary integrity | SHA256 on every invocation + codesign Team ID for upgrades |

See [THREAT-MODEL.md](THREAT-MODEL.md) for what's in/out of scope.

## Phase plan

| Phase | Scope | Status |
|---|---|---|
| 0 | Workspace scaffold + IPC types | ✅ |
| 1 | Daemon happy path (UDS, cache, rbw, persistence, audit, stub helper) | 🚧 |
| 2 | Native UI helper (objc2-app-kit popup, LAContext TouchID, tabs, menubar) | 📋 |
| 3 | CLI wrapper complete (run with execvpe, doctor, project init, rules) | 🚧 |
| 4 | Discovery pipeline (registry, --help parsing, opt-in LLM) | 📋 |
| 5 | Hardening (peer verification, codesign auto-update, world-writable check) | 📋 |
| 6 | Lifecycle (`envs init` wizard, launchd plist generation) | 📋 |
| 7 | Audit log polish, completions, docs | 📋 |
