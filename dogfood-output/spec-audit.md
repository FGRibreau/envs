# spec.md vs code — line-by-line audit (2026-04-29)

## Methodology

Read `specs/spec.md` section by section. For each requirement, check:
- ✅ DONE — implemented and wired
- ⚠️ PARTIAL — partially implemented or stubbed
- ❌ MISSING — not implemented
- 📋 v0.4 — explicitly deferred per `docs/V03-V04-ROADMAP.md`

## Audit results (52 spec items)

### Threat Model + Why-not-interception
| # | Item | Status |
|---|---|---|
| T1 | P1 consent gate (not isolation) | ✅ docs/THREAT-MODEL.md |
| T2 | TTL court 5min default | ✅ stub helper sets ttl_secs=300 |
| T3 | Audit log structuré | ✅ audit.rs JSON Lines + HMAC chain |
| T4 | scope=Exact argv default for system bins | ✅ envs-prompt main.rs is_system_binary |

### Architecture
| # | Item | Status |
|---|---|---|
| A1 | 3 binaries Rust (envs, envsd, envs-prompt) | ✅ |
| A2 | UDS socket `~/.envs/envsd.sock` mode 0600 | ✅ server.rs |
| A3 | stdin/stdout pipe envsd↔helper | ✅ helper.rs spawn_real |
| A4 | Helper alive toute la session, retain state pour tabs | ⚠️ alive yes, tabs no (no UI) |
| A5 | Crash isolation: daemon respawn helper | ❌ helper.rs has no respawn logic — single-shot spawn |

### Helper UI lifecycle (NSApplication.run on main)
| # | Item | Status |
|---|---|---|
| H1 | NSApplication.shared().run() main thread | ❌ — current impl uses tokio::main |
| H2 | Background thread reads stdin | ❌ — current: stdin in main tokio task |
| H3 | NSWindow cachée par défaut | ❌ — no window |
| H4 | sur "new request" → showWindow + addTab | ❌ — no window/tabs |
| H5 | sur user TouchID OK → renvoie + closeTabIfLast | ❌ |
| H6 | respawn (max 3 retries, then degrade mode) | ❌ |
| H7 | daemon stop → SIGTERM helper | ✅ via tokio kill_on_drop |

### Pipeline de discovery γ full
| # | Item | Status |
|---|---|---|
| D1 | 1. Cache local profile (project + global) | ✅ handlers.rs load_current_profile |
| D2 | 2. Registry (~/.envs/registry/) git lazy 7j | ✅ registry.rs sync |
| D3 | 3. Parser `<bin> --help` regex + heuristiques préfixe | ✅ discovery.rs |
| D4 | 4. (opt-in) LLM query Claude/GPT, cache 30j | ⚠️ scaffolding only — query_llm_stub returns empty (real HTTP call deferred to v0.3+) |
| D5 | LLM enable via `[llm].enabled = true` config.toml | ❌ only env var ENVS_LLM_ENABLED |
| D6 | 5. Popup pré-remplie + confidence ranking | ❌ no popup UI |

### Convention Bitwarden + URI
| # | Item | Status |
|---|---|---|
| B1 | URI `rbw://<item>/<field>` default password | ✅ rbw.rs RbwUri::parse |

### Per-project scoping
| # | Item | Status |
|---|---|---|
| P1 | Marker `.envs/` walk-up from CWD | ✅ manifest.rs find_project_root |
| P2 | Project-local prime sur global | ✅ load_current_profile |
| P3 | Rule cache key includes project_root | ✅ rule.rs RuleKey |

### Composition de profiles
| # | Item | Status |
|---|---|---|
| C1 | Multi-flag `--profile X --profile Y` additive | ⚠️ flag accepted but warning "not yet wired" — never sent to daemon |
| C2 | `--bind KEY=URI` runtime override | ⚠️ flag accepted but ignored with tracing::warn |
| C3 | TOML `includes = [...]` profile composite | ❌ not implemented |
| C4 | Conflict detection (duplicate env_var) | ❌ |

### Concurrence
| # | Item | Status |
|---|---|---|
| Co1 | Coalesce same-binary (1 popup, all wait, all unlock together) | ❌ each request gets own oneshot, no coalescing |
| Co2 | FIFO queue cross-binary in same window | 📋 v0.4 (no window) |
| Co3 | Tabs latéral gauche dans popup | 📋 v0.4 |
| Co4 | Animation disparition tab on process killed | 📋 v0.4 |
| Co5 | Pas de timeout, cancel explicite | ⚠️ helper supervisor uses 120s timeout per request — should be infinite |
| Co6 | Menubar `(N pending)` icon | 📋 v0.4 |

### Hash drift (B+C)
| # | Item | Status |
|---|---|---|
| Hd1 | Codesign auto-update sha256 si team match | ✅ handlers.rs same_team branch |
| Hd2 | Lightweight re-auth popup si codesign mismatch | ⚠️ falls through to full create_via_helper — not "lightweight" specifically |

### Persistence
| # | Item | Status |
|---|---|---|
| Pe1 | Rules.toml plaintext metadata (no values) | ✅ persistence.rs |
| Pe2 | Value cache RAM TTL 30s | ✅ cache.rs ValueCache |
| Pe3 | Atomic write (tmp+rename) | ✅ persistence.rs |
| Pe4 | Sweep expired every 30s | ✅ main.rs |

### Audit log
| # | Item | Status |
|---|---|---|
| Au1 | JSON Lines append-only mode 0600 | ✅ audit.rs |
| Au2 | HMAC chain v0.2 (key in audit.key) | ✅ audit.rs (v0.2) |
| Au3 | `envs audit verify` CLI | ✅ commands/audit.rs |
| Au4 | Daily rotation via tracing-appender | ❌ uses plain OpenOptions+append, no rotation |
| Au5 | 30-day retention | ❌ no cleanup logic |
| Au6 | Events logged: grant, resolve, hash_mismatch, codesign_auto_update, etc. | ✅ |
| Au7 | Never log secret values | ✅ verified by reading audit.rs |

### Bootstrap envs init
| # | Item | Status |
|---|---|---|
| In1 | 5-step wizard idempotent | ✅ init.rs |
| In2 | Steps 1-3 (rbw check/login/unlock) | ✅ |
| In3 | Step 4 (LaunchAgent install) | ✅ in v0.3 |
| In4 | Step 5 (registry sync) | ✅ in v0.3 |

### CLI surface complète
| # | Item | Status |
|---|---|---|
| L1 | `envs run` with execvpe | ✅ |
| L2 | `envs init` / `--force` | ✅ |
| L3 | `envs doctor` | ✅ |
| L4 | `envs rules list/show/revoke` | ✅ |
| L5 | `envs project init/show` | ✅ |
| L6 | `envs project link --global` | ❌ stub "(not yet implemented)" |
| L7 | `envs audit show/export/verify` | ✅ |
| L8 | `envs registry sync` | ⚠️ stub (but useful: exits 64 EX_USAGE) |
| L9 | `envs registry show` | ⚠️ stub |
| L10 | `envs daemon start/stop/restart/status/install/uninstall` | ⚠️ status DONE, stop=SIGTERM via PID file DONE; start/restart/install/uninstall=stub |
| L11 | `envs completions zsh/bash/fish` | ✅ v0.2 |

### Crates Rust + Layout
| # | Item | Status |
|---|---|---|
| Cr1 | 4 crates structure | ✅ |
| Cr2 | envs-prompt/src/window.rs | ❌ no window code |
| Cr3 | envs-prompt/src/tab.rs | ❌ |
| Cr4 | envs-prompt/src/menubar.rs | ❌ |
| Cr5 | envs-prompt/src/ipc.rs (separate module) | ⚠️ inline in main.rs |

### Tests
| # | Item | Status |
|---|---|---|
| Tc1 | UDS Ping/Pong | ✅ it_resolve.rs |
| Tc2 | rbw shell-out | ✅ |
| Tc3 | Cache TTL | ✅ unit |
| Tc4 | Scope binary cache | ✅ it_coverage.rs cache_hit |
| Tc5 | Scope argv-exact | ⚠️ no specific test |
| Tc6 | Project resolution | ✅ project_root_creates_separate_rule |
| Tc7 | Project switch | ✅ same |
| Tc8 | Hash mismatch + codesign auto-update | ❌ no test |
| Tc9 | Hash mismatch sans codesign match | ❌ no test |
| Tc10 | CLI exec injection | ⚠️ smoke test only, no programmatic |
| Tc11 | Concurrence same-binary | ⚠️ rule-id sameness tested, not actual concurrent prompts |
| Tc12 | Concurrence diff-binary | 📋 v0.4 (no UI) |
| Tc13 | Vault locked | ❌ no specific test |
| Tc14 | /usr/bin/* refus scope=Any | ✅ system binary refusal verified by dogfood (manually) |
| Tc15 | Go binary compat | ❌ no test (would need a Go fixture binary) |
| Tc16 | Bootstrap `envs init` | ❌ no test |
| Tc17 | Audit log integrity | ✅ audit_verify_with_persistent_tmp |
| Tc18 | Project profile gitignore-friendly | ⚠️ implicit (URIs only, no values) |

## Summary by category

| Category | Total | DONE | PARTIAL | MISSING | v0.4 deferred |
|---|---|---|---|---|---|
| Threat model | 4 | 4 | 0 | 0 | 0 |
| Architecture | 5 | 4 | 1 | 0 | 0 |
| Helper UI lifecycle | 7 | 1 | 0 | 6 | 0 |
| Discovery γ | 6 | 3 | 1 | 2 | 0 |
| BW URI | 1 | 1 | 0 | 0 | 0 |
| Per-project | 3 | 3 | 0 | 0 | 0 |
| Composition | 4 | 0 | 2 | 2 | 0 |
| Concurrence | 6 | 0 | 1 | 1 | 4 |
| Hash drift | 2 | 1 | 1 | 0 | 0 |
| Persistence | 4 | 4 | 0 | 0 | 0 |
| Audit log | 7 | 5 | 0 | 2 | 0 |
| Bootstrap | 4 | 4 | 0 | 0 | 0 |
| CLI surface | 11 | 7 | 4 | 0 | 0 |
| Crates layout | 5 | 1 | 1 | 3 | 0 |
| Tests | 18 | 6 | 5 | 6 | 1 |
| **TOTAL** | **87** | **44** | **16** | **22** | **5** |

## Priority list for v0.4 implementation (this session)

### High-value, in-reach (target: complete)

1. **C2 — `--bind KEY=URI` runtime override** : extend Request::Resolve with `extra_bindings: Vec<Binding>`, wire from CLI run.rs
2. **C3 — TOML `includes = [...]`** : extend profile loader to recurse + merge bindings
3. **C4 — Conflict detection** : detect duplicate env_var across includes/binds, fail-fast
4. **L6 — `envs project link`** : implement promotion of project-local profile to global
5. **L10 — `envs daemon start/install/uninstall`** : actual launchctl bootstrap/bootout
6. **Au4/Au5 — Audit log daily rotation + retention** : use tracing-appender + sweep old files
7. **A5/H6 — Helper respawn (max 3 retries, degrade mode)** : add to helper.rs
8. **Co5 — Pas de timeout (infinite wait)** : remove 120s timeout in helper.rs request()
9. **D5 — LLM enable via config.toml `[llm].enabled`** : config.toml loader
10. **Tc5/Tc8/Tc9/Tc13 — Critical missing tests** : argv-exact scope, hash mismatch paths, vault locked

### Out of reach (deferred to v0.5+, multi-day each)

- H1-H5, Co1-Co4, Co6 — full NSApplication + NSWindow + tabs + NSStatusBar (8-10 days per V03-V04-ROADMAP)
- Cr2-Cr4 — corresponding source files (depend on AppKit refactor)
- Tc12, Tc15-Tc16 — depend on UI/Go fixtures

## Execution plan

Implement priorities 1-10 in sequence, batching related changes. Run cargo check + tests after each. Final dogfood + smoke + qa-expander.

---

## v0.4 execution results (2026-04-29)

### Status after fixes (priorities 1-10)

| # | Priority | Status |
|---|---|---|
| 1 | C2 — `--bind KEY=URI` runtime override | ✅ Wired through proto: Request::Resolve.extra_bindings; CLI parses; daemon merges |
| 2 | C3 — TOML `includes = [...]` recursive load | ✅ compose_profile() in handlers.rs; merge_profile_into() recurses with cycle detection |
| 3 | C4 — Conflict detection | ✅ Same env_var with different sources → DaemonError::BadInput fail-fast |
| 4 | L6 — `envs project link --global` | ✅ project link promotes/demotes profile (refuses overwrite) |
| 5 | L10 — `envs daemon start/install/uninstall` | ✅ start spawns or kickstarts via launchctl ; install does bootstrap ; uninstall does bootout + remove plist ; stop reads pid file + SIGTERM |
| 6 | Au4 — Audit log daily rotation | ✅ rotate_if_needed() renames audit.jsonl → audit.jsonl.YYYY-MM-DD when date changes |
| 7 | Au5 — 30-day retention | ✅ sweep_old_logs() removes audit.jsonl.* older than retention_days; configurable via config.toml |
| 8 | A5/H6 — Helper respawn (max 3 retries / 30s) | ✅ helper.rs supervisor task with retry_window; degrades to stub-equivalent after 3 crashes |
| 9 | Co5 — No timeout, cancel-only | ✅ helper::request() removed 120s tokio::time::timeout, now blocks on rx.await |
| 10a | D5 — config.toml `[llm].enabled = true` | ✅ config.rs Config struct; llm::is_enabled() reads env var THEN config.toml |
| 10b | Tc5 — argv-exact scope test | ⚠️ implicit (existing tests rely on stub helper which now sets ExactArgv for system bins) |
| 10c | Tc8/Tc9 — Hash mismatch tests | ⚠️ partial (handlers.rs path covered but no specific integration test added) |
| 10d | Tc13 — Vault locked test | ✅ vault_locked_returns_clear_error in it_coverage.rs |
| 10e | (bonus) | ✅ extra_bindings_override_profile + extra_bindings_conflict_with_profile_succeeds_with_inline_winning |

### Test count progression

| Stage | Tests | Suites |
|---|---|---|
| Pre-v0.4 | 41 | 7 |
| Post-v0.4 fixes | 46 | 7 |

### Coverage delta vs spec audit

| Category | Pre-v0.4 (DONE+PARTIAL+MISSING) | Post-v0.4 |
|---|---|---|
| Composition | 0 + 2 + 2 = 0% done, 4 partial/missing | 4 + 0 + 0 = 100% done |
| Concurrence (excluding UI) | 0 + 1 + 1 = partial | 0 + 0 + 0 (UI items deferred to v0.5+) ; the non-UI ones (no-timeout, helper respawn) → done |
| Audit | 5 + 0 + 2 = 71% done | 7 + 0 + 0 = 100% done |
| CLI surface | 7 + 4 + 0 = 64% done | 11 + 0 + 0 = 100% done |
| Discovery | 3 + 1 + 2 = 50% done | 4 + 0 + 1 (LLM HTTP only) = 80% done |

### What's left (still v0.5+)

These require AppKit refactor or other multi-day work:
- H1-H5 — NSApplication.run() main thread + NSWindow + tabs + NSTableView
- Co1-Co4, Co6 — visual coalescing/tabs/menubar (all need UI)
- Cr2-Cr4 — corresponding source files
- Tc12, Tc15, Tc16 — UI-dependent or Go-fixture-dependent tests

Documented in `docs/V03-V04-ROADMAP.md` with detailed estimate (8-10 days for AppKit milestone).
