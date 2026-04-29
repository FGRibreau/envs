# Threat Model — `envs`

## TL;DR

`envs` is a **consent gate**, not a sandbox. It prevents secrets from entering subprocess environments without your explicit, biometric-verified authorization. It does **not** prevent same-UID processes from observing those secrets after authorization.

## What `envs` defends against

### 1. Unauthorized secret access by AI agents and scripts

When you run `envs flarectl ...`, no secret reaches the child process unless and until you have:
1. Confirmed the env var bindings via the popup
2. Confirmed the scope (binary-wide vs argv-exact)
3. Confirmed the duration (default 5 min)
4. Validated all of the above with TouchID

Without TouchID, no secret enters `flarectl`'s `environ`. An AI agent invoking `envs <cmd>` cannot bypass this gate; only you can authorize.

### 2. Long-lived persistent exposure of secrets

Without `envs`, you typically `export CF_API_TOKEN=...` in your shell session — the secret stays in your shell's environ for hours. With `envs`, the secret is materialized only:
- Inside the daemon's value cache (TTL 30s)
- Inside the spawned child process for its lifetime

Once the cache TTL passes and the child exits, the secret is no longer in process memory anywhere on the system. Subsequent invocations re-fetch from `rbw`.

### 3. Cross-project secret confusion

Per-project profiles (`<project_root>/.envs/`) ensure that running `flarectl` in `~/www/image-charts` injects different secrets than running it in `~/www/fgribreau.github.io`. A grant in one project does not authorize access in another.

### 4. Tampering with binaries (best-effort)

Each rule binds to a specific binary path **and** SHA256. If the binary is replaced (e.g., `/opt/homebrew/bin/flarectl` swapped for a malicious script), the next invocation triggers a `BinaryHashMismatch` and:
- If the codesign Team ID matches the original (e.g., legitimate Homebrew upgrade) → silently update the SHA256 and continue
- Otherwise → require a re-authorization popup

This is best-effort: an attacker who can replace files in `/opt/homebrew/bin/` AND has a valid codesign signing key for the same Team ID can bypass this. That's not realistic for typical threat actors.

### 5. Auditability

Every grant, resolution, revocation, and security-relevant event is logged to `~/.envs/logs/audit.jsonl`. You can run `envs audit show` to review what was granted to whom and when.

## What `envs` does NOT defend against

### 1. Observation by same-UID processes after grant

**This is the most important limitation.** On macOS, any process running under the same UID can observe the environment of any other process via:
- `ps -E -p <pid>` — shows full env of the target process
- `sysctl kern.procargs2` — same data, programmatic access

When you authorize `flarectl` to receive `CF_API_TOKEN`, that token is in `flarectl`'s `environ` for the lifetime of `flarectl`. **Any other process you run** (another agent, another shell, malware running as you) can do `ps -E` and read the token during that window.

There is no native macOS mechanism to hide an environ from same-UID processes without paid Apple entitlements (`task_for_pid-allow`, EndpointSecurity system extensions, etc.).

**Implication:** if you need true isolation between AI agents, run them under different UIDs (`sudo -u agent-cf ...`) or in separate VMs. `envs` does not replace those mechanisms.

### 2. Exfiltration by the authorized child itself

Once you authorize `flarectl` to receive `CF_API_TOKEN`, `flarectl` has the token. If `flarectl` is malicious or compromised, it can:
- Send the token to a remote server
- Write it to a file you can later read
- Print it to stdout you didn't notice

`envs` cannot prevent this. **The popup IS the consent**: by authorizing, you are saying "I trust this binary to use this secret responsibly." If you don't trust the binary, don't authorize.

### 3. Compromise of the macOS Keychain or rbw

The chain of trust is: your `rbw` master password → your Bitwarden vault → `envs` → the child. If any link is compromised, the secret is gone. `envs` doesn't add isolation beyond what `rbw` already provides; it adds *consent*.

### 4. Compromise of the daemon process

`envsd` runs as you. If a same-UID attacker compromises the daemon process (memory injection, ptrace if entitled, etc.), they can read the value cache. The value cache has a 30s TTL precisely to limit this exposure window.

### 5. Sophisticated PID race conditions

When a CLI invocation connects to the daemon via UDS, the daemon checks the connecting process's PID (via `LOCAL_PEERPID`) and resolves it to a path (`proc_pidpath`). There is a small window where a PID could be reused between the `connect()` and the `proc_pidpath()`. The UID check (`LOCAL_PEEREUID`) prevents *cross-user* impersonation, but a same-UID attacker exploiting this race could in principle convince the daemon they are a different binary.

This is mitigated by:
- Same-UID attackers being out of the threat model anyway (see #1)
- The TouchID prompt at the human layer — you'd see "flarectl wants CF_API_TOKEN" with a path that doesn't match what you typed

### 6. AI agent operating in a non-interactive context

`envs` requires an interactive macOS session for the TouchID popup. In contexts where no graphical session is available (SSH without forwarding, headless CI, tmux with closed display), `envs` fails fast with `EX_TEMPFAIL` and a clear message. It does not fall back to a less secure mode.

If you need to run secret-using commands in CI, use a different mechanism (BWS Secrets Manager `BWS_ACCESS_TOKEN`, or a dedicated machine identity). `envs` is for interactive dev workflows.

## Trust assumptions

`envs` assumes:
- macOS Keychain integrity (TouchID and `LAContext.evaluatePolicy` work as advertised)
- `rbw` correctness (rbw faithfully decrypts your Bitwarden vault)
- Bitwarden vault confidentiality (your master password is strong)
- Filesystem integrity for `~/.envs/` (same-UID write access is fine; cross-UID access is prevented by 0700 perms on the parent dir)
- launchd integrity (envsd runs at login as you)

`envs` does not assume:
- Apple-signed system binary integrity (we don't trust system binaries enough to allow scope=`Any`; they require argv-exact)
- Network availability (everything works offline once the registry is synced)

## Reporting security issues

Open a private security advisory on GitHub:
https://github.com/fgribreau/envs/security/advisories
