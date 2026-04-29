# Plan : `envs` — Lulu-style firewall pour env vars (Bitwarden + TouchID + per-project)

> Crate publiée : **`envs-cli`** sur crates.io. Binary terminal : **`envs`**. Daemon : **`envsd`**. Helper UI : **`envs-prompt`**.

## Context

Sur macOS, l'utilisateur veut qu'au moment où une commande CLI a besoin d'un secret stocké dans son **vault Bitwarden personnel**, une popup native style **Lulu firewall** lui demande l'autorisation au premier appel (quelles clés, quel scope, quelle durée) validée par TouchID. Cas d'usage primaire : laisser des **agents IA** invoquer des commandes (`flarectl`, `wrangler`, `curl`) sans jamais voir les tokens en clair, le user restant gate via TouchID.

Aucun outil existant ne fait ça (validé par recherche web : `bws run` demande BWS_ACCESS_TOKEN en clair, `rbw` n'a pas de scope par-clé/par-binaire, `op run` est 1Password). Justifie un projet dédié.

## Threat Model (P1)

`envs` est un **consent gate**, pas un sandbox.

- **Garantit** : aucun secret n'entre dans un subprocess sans consentement utilisateur explicite via TouchID
- **Ne garantit PAS** : isolation post-grant. Sur macOS, `ps -E` permet aux processus same-UID de lire l'environ d'autres processus same-UID. Aucun mécanisme natif pour cacher l'env d'un process aux autres processes same-UID sans entitlements payants Apple
- **Mitigation** : audit log structuré + TTL court par défaut (5min) + scope `Exact argv` proposé en default
- **Documenté brutalement** dans `docs/THREAT-MODEL.md`

## Pourquoi pas l'interception runtime

`DYLD_INSERT_LIBRARIES` + interpose `getenv` ne marche que pour libc consumers. Go/Node/Python prennent un snapshot de `environ` au boot et ne le re-lisent jamais → l'interpose est invisible pour eux. `ptrace`/`task_for_pid`/`mach_inject` sont fermés par SIP. eBPF n'existe pas sur macOS. EndpointSecurity et DTrace sont read-only.

→ **Seul point d'injection viable et cross-langage = `execve(envp[])` au moment du fork/exec**. C'est ce que fait `op run`, c'est ce que fait `envs`.

## Modèle conceptuel (Lulu pour env vars)

```
$ cd ~/www/image-charts
$ envs flarectl zone list                         # premier appel
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ envsd : pas de rule active pour cette invocation         │
│         lookup project profile, registry, --help, LLM    │
│         pré-remplit les suggestions                       │
│                                                           │
│ envsd → envs-prompt : "show new request as new tab"      │
│                                                           │
│ Popup native macOS (objc2-app-kit) :                     │
│ ┌────────────────────────────────────────────────────┐   │
│ │ [tab1: flarectl]  [tab2: wrangler] [...]          │   │
│ ├────────────────────────────────────────────────────┤   │
│ │ Authorize secret access                            │   │
│ │                                                     │   │
│ │ Command: flarectl zone list                         │   │
│ │ CWD:     ~/www/image-charts/src/                    │   │
│ │ Project: ~/www/image-charts (.envs/ detected)       │   │
│ │                                                     │   │
│ │ Inject these env vars from Bitwarden:               │   │
│ │   ☑ CF_API_TOKEN ← rbw://CF_API_TOKEN              │   │
│ │       (registry suggestion, 95% confidence)         │   │
│ │   ☑ CF_ACCOUNT_ID ← rbw://CF_ACCOUNT_ID            │   │
│ │       (--help parsing, 70% confidence)              │   │
│ │   [+ Add custom binding ▼]                          │   │
│ │                                                     │   │
│ │ Scope:                                              │   │
│ │   ◉ Any flarectl in ~/www/image-charts              │   │
│ │   ○ Only `flarectl zone list` in this project       │   │
│ │   ○ Any flarectl, anywhere (global)                 │   │
│ │                                                     │   │
│ │ Duration: [ 5 min ▼ ]                               │   │
│ │                                                     │   │
│ │ Save as: ◉ Project profile                          │   │
│ │            (~/www/image-charts/.envs/flarectl.toml) │   │
│ │          ○ Global profile                           │   │
│ │            (~/.envs/profiles/flarectl.toml)         │   │
│ │                                                     │   │
│ │ [ Authorize via TouchID ]    [ Cancel ]             │   │
│ └────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────┘
       │ TouchID OK
       ▼
   envsd cache la rule + écrit profile sur disque
   envsd fetch via `rbw get CF_API_TOKEN`
   envs CLI reçoit valeurs, fait execvpe(flarectl, args, env_with_secrets)
```

## Architecture

### 3 binaires Rust

```
envs        — wrapper CLI (court, ~400 LOC)
envsd       — daemon long-running (~1000 LOC)
envs-prompt — helper UI persistant via objc2-app-kit (~600 LOC)
```

### Communication

| Liaison | Protocole | Format |
|---|---|---|
| `envs` ↔ `envsd` | Unix domain socket `~/.envs/envsd.sock` (mode 0600) | newline-delimited JSON, 1 req → 1 resp |
| `envsd` ↔ `envs-prompt` | stdin/stdout pipe (helper spawné au boot daemon, persistant) | newline-delimited JSON, async events bidirectionnels |

`envs-prompt` reste vivant toute la session : envsd lui pousse des "new request" events, helper ajoute un tab dans la window. Helper renvoie des "request resolved" events. Crash isolation : daemon respawn helper si exit inattendu.

### Layout disque

```
~/.envs/
├── envsd.sock                       # UDS, mode 0600
├── envsd.pid
├── config.toml                      # config user (audit retention, llm.enabled, etc.)
├── profiles/                        # global profiles
│   ├── flarectl.toml
│   └── wrangler.toml
├── state/
│   └── rules.toml                   # rules persistées (metadata only, pas de valeurs)
├── registry/                        # clone github.com/fgribreau/envs-registry
│   ├── .last_pull
│   └── binaries/
│       ├── flarectl.toml
│       └── …
├── llm-cache.json                   # discovery LLM cache (opt-in)
└── logs/
    ├── envsd.log
    └── audit.jsonl                  # rotated daily, retention 30d default

# Project-local marker
~/www/image-charts/.envs/
├── flarectl.toml                    # bindings spécifiques au projet
└── wrangler.toml
```

### Helper UI lifecycle (Option 2)

```
launchd → spawn envsd
            └→ envsd au boot :
                ├ load rules.toml (filter expirées)
                ├ git pull registry si > 7j
                ├ spawn envs-prompt en subprocess (pipe stdin/stdout)
                │   envs-prompt :
                │     - NSApplication.shared.run() en main thread
                │     - background thread lit stdin pour events
                │     - window NSWindow cachée par défaut
                │     - sur "new request" → showWindow + addTab
                │     - sur user TouchID OK → renvoie resolution + closeTabIfLast
                └ listen UDS

envsd surveille envs-prompt subprocess :
  - exit unexpected → respawn (max 3 retries, then degrade mode)
  - daemon stop → kill helper proprement (SIGTERM)
```

## Pipeline de discovery (γ full stack)

Au 1er popup pour un binaire sans profile project ni global :

```
1. Cache local profile (~/.envs/profiles/<bin>.toml ou <project>/.envs/<bin>.toml)
   ↓ miss
2. Registry communautaire (~/.envs/registry/binaries/<bin>.toml)
   ↓ miss
3. Parser stdout de `<bin> --help 2>&1` + `<bin> -h`
   - extract tokens uppercase précédés de "env", "ENV:", "[$X]", "environment variable"
   - confidence score par occurrence
   - croise avec heuristique préfixe (CF_*, AWS_*, GH_*, KUBE*, etc.)
   ↓ peu/pas de matchs
4. (opt-in via config.llm.enabled = true) Query Claude/GPT
   - prompt = binary name + --help text
   - cache 30j dans llm-cache.json
   ↓
5. Popup pré-remplie avec suggestions tagged par confidence
   - user pick/confirm/customize
   - save as profile (project ou global)
```

**Décompilation/static analysis** : explicitement out-of-scope (fragile sur Go, lourd, faux négatifs).

## Convention Bitwarden + URI scheme

**Convention 1 (default user)** : un secret = un item BW, valeur dans `password`. Vault encombré mais simple à browser, et l'item name = nom de l'env var.

```
Item: "CF_API_TOKEN"   → password = "abc..."
Item: "CF_ACCOUNT_ID"  → password = "123..."
URI: rbw://CF_API_TOKEN          (= rbw get "CF_API_TOKEN", default field password)
```

**Override free-form (Modèle 4)** : URI scheme générique `rbw://<item-name>/<field>`. `<field>` ∈ {password, username, notes, <custom-field-name>}. Le mapping est saisi via la **popup**, pas en éditant des TOML manuellement. Le user édite rarement les `.toml` à la main (c'est un artefact de persistance, pas une UI).

```
URI: rbw://Cloudflare API/CF_API_TOKEN   (custom field nommé CF_API_TOKEN)
URI: rbw://AWS Prod/username             (le username field)
```

## Per-project scoping

Marker explicite : dossier `.envs/` à la racine du projet. Walk up depuis CWD pour le trouver. **Pas d'auto-détection Git** (trop magique).

### Résolution

```
1. CWD canonicalize
2. Walk ancestors → premier `.envs/` rencontré → project_root
3. Lookup `<project_root>/.envs/<binary>.toml` (project-local)
4. Sinon : lookup `~/.envs/profiles/<binary>.toml` (global)
5. Sinon : popup avec discovery pipeline complet
```

### Rule cache key

```rust
struct RuleKey {
    canon_path: PathBuf,            // binary canonicalized
    sha256: [u8; 32],
    codesign_team: Option<String>,
    argv_match: ArgvMatch,          // Any | Exact(Vec<String>)
    project_root: Option<PathBuf>,  // None = global, Some(...) = project-scoped
    profile_id: String,
}
```

→ Une rule pour `flarectl` dans `~/www/image-charts` n'autorise PAS un appel à `flarectl` dans `~/www/fgribreau.github.io` (project_root différent).

### `.gitignore` recommendation

Le contenu de `.envs/*.toml` ne contient que des URIs `rbw://` (pointers, pas de valeurs). `envs project init` propose : "Commit `.envs/` (team partage la convention BW) ou ignore-le ?"

## Composition de profiles

### Multi-flag additif
```
envs --profile cloudflare --profile aws-prod ./deploy.sh
```
Bindings fusionnés. Conflit (même env_var) → fail-fast `conflicting binding for X`.

### Profile composite (TOML `includes`)
```toml
# .envs/deploy.toml
schema = 1
includes = ["cloudflare", "aws-prod"]

[[binding]]
env = "DEPLOY_BUCKET"
src = "rbw://Deploy/bucket"
```

## Concurrence

| Scénario | Comportement |
|---|---|
| 2e appel **même** binaire pendant popup ouverte | **Coalesce** : keyé sur `(canon_path, sha256)`. Si scope grant = `Any` → débloquent ensemble. Si scope = `Exact argv` et argv différent → 2e ouvre nouveau tab |
| 2e appel **autre** binaire pendant popup ouverte | **FIFO queue** dans la même window-popup, **tab latéral** ajouté à gauche. Animation fade-in |
| Process killed avec tab pending | Animation disappearance du tab |
| Pas de timeout | User répond ou cancel explicite. Cancel → exit 77 (`EX_NOPERM`) |

### Menubar icon

Icône menubar quand `pending_count > 0`, badge `(N pending)`. Click ouvre la popup focalisée sur le 1er tab. Permet à l'user de pas perdre le focus de sa window active.

## Hash drift (B+C dès v0.1)

Sur mismatch sha256 vs rule.sha256 :

1. Vérifier `codesign -dv --verbose=4 <path>` → extract Team Identifier
2. Si team identifier match avec `rule.codesign_team` :
   - **Auto-update** sha256 dans la rule (silencieusement)
   - Log `hash_codesign_auto_update` event dans audit log
3. Si pas match (différent team) ou pas de codesign :
   - Popup minimaliste : "Binary <path> was updated. Re-authorize <bindings>?"
   - Bindings/scope/durée préservés depuis profile saved
   - User TouchID confirm → nouvelle rule avec nouveau sha256
   - Si user cancel → rule invalidée

## Persistence

### Rules (`~/.envs/state/rules.toml`)

Plaintext metadata, **jamais de valeurs** :

```toml
schema = 1

[[rule]]
id = "01HXYZ..."
canon_path = "/opt/homebrew/bin/flarectl"
sha256 = "9f3c..."
codesign_team = "Cloudflare, Inc."
argv_match = { kind = "Any" }
project_root = "/Users/fgribreau/www/image-charts"
env_keys = ["CF_API_TOKEN", "CF_ACCOUNT_ID"]
sources = ["rbw://CF_API_TOKEN", "rbw://CF_ACCOUNT_ID"]
profile_id = "image-charts:flarectl"
created_at = "2026-04-29T14:32:11Z"
expires_at = "2026-04-29T14:37:11Z"
```

Au boot daemon : load + filter expirées.

### Value cache (RAM uniquement, TTL 30s)

```rust
HashMap<(EnvKey, RbwSource), (SecretString, fetched_at)>
```

Background sweep purge expirées + zeroize.

### Profiles persistents (jamais expirés)

`~/.envs/profiles/<bin>.toml` ou `<project>/.envs/<bin>.toml` :

```toml
schema = 1

[binary]
name = "flarectl"

[[binding]]
env = "CF_API_TOKEN"
src = "rbw://CF_API_TOKEN"

[[binding]]
env = "CF_ACCOUNT_ID"
src = "rbw://CF_ACCOUNT_ID"

[meta]
created_at = "2026-04-29T14:32:11Z"
last_used_at = "2026-04-29T14:35:42Z"
```

## Audit log

`~/.envs/logs/audit.jsonl`, JSON Lines, append-only, mode 0600. Daily rotation via tracing-appender. Retention 30j default (configurable).

### Events loggés

`grant`, `resolve`, `popup_cancel`, `hash_mismatch`, `hash_codesign_auto_update`, `rbw_locked`, `revoke`, `expired_sweep`, `unknown_caller`, `daemon_start`, `daemon_stop`.

### Schema (extrait)

```json
{"ts":"2026-04-29T14:32:11.034Z","event":"grant","rule_id":"01HXYZ...","caller_pid":12345,"caller_path":"/opt/homebrew/bin/flarectl","caller_sha256":"9f3c...","codesign_team":"Cloudflare, Inc.","argv":["flarectl","zone","list"],"caller_cwd":"/Users/fgribreau/www/image-charts/src","project_root":"/Users/fgribreau/www/image-charts","env_keys":["CF_API_TOKEN","CF_ACCOUNT_ID"],"sources":["rbw://CF_API_TOKEN","rbw://CF_ACCOUNT_ID"],"scope":"Any","profile_source":"project","expires_at":"2026-04-29T14:37:11Z"}
```

**Jamais de valeurs.** v0.1 : append-only sans HMAC. v0.2+ : HMAC chain pour tamper-detection.

### CLI

```bash
envs audit show              # tail -f les events récents (formattés humainement)
envs audit show --since 1h
envs audit show --binary flarectl
envs audit show --event grant
envs audit show --project ~/www/image-charts
envs audit export <file>     # CSV ou JSON
envs audit verify            # v0.2+ : vérifie HMAC chain
```

## Bootstrap : `envs init`

Wizard idempotent (rejouable pour repair). Au 1er appel `envs <cmd>` sans setup, message clair :

```
envs is not yet configured. Run `envs init` to set up.

This will :
  - Check that rbw is installed (brew install rbw if needed)
  - Help you log into Bitwarden
  - Install the envsd LaunchAgent
  - Sync the community registry
```

`envs init` étapes :

```
[1/5] Checking rbw...
      ✗ Not installed. Run `brew install rbw`?  [Y/n]
[2/5] Checking rbw login...
      ✗ Not logged in. Email: fg@france-nuage.fr
      Server: https://vault.bitwarden.com
      Master password: ****
[3/5] Checking rbw unlock...               ✓ Unlocked
[4/5] Installing envsd LaunchAgent...
      ~/Library/LaunchAgents/com.fgribreau.envsd.plist
      launchctl bootstrap gui/501           ✓
[5/5] Initial registry sync...
      git clone github.com/fgribreau/envs-registry  ✓ 23 known binaries

All set. Try: envs flarectl zone list
```

`envs doctor` = juste les checks, sans réparation. `envs init --force` = ré-exécute toutes les étapes.

## CLI surface complète

```bash
# Workflow principal
envs <command> [args...]
envs --profile <name> <command> [args...]      # multi: --profile X --profile Y

# Setup
envs init                                       # wizard hybrid
envs init --force                              # rejouer
envs doctor                                     # diag sans modif

# Profiles
envs project init                               # crée .envs/ dans CWD, propose .gitignore
envs project show                               # détecte project_root, liste profiles trouvés
envs project link --global <bin>                # promote project profile en global

# Rules (cache active)
envs rules list                                 # afficher rules actives
envs rules show <id>
envs rules revoke <id|all>

# Registry
envs registry sync                              # force git pull
envs registry show <bin>                        # afficher entrée registry pour un binaire

# Audit
envs audit show [filtres]
envs audit export <file>

# Daemon
envs daemon {start|stop|restart|status}
envs daemon install                             # install launchd plist
envs daemon uninstall

# Misc
envs version
envs completions <shell>                        # zsh/bash/fish completions
```

## Crates Rust

```toml
# Cargo.toml workspace root
[workspace]
resolver = "2"
members = ["crates/envs-proto", "crates/envs-cli", "crates/envs-daemon", "crates/envs-prompt"]

[workspace.dependencies]
tokio = { version = "1.41", features = ["rt-multi-thread", "macros", "net", "io-util", "sync", "process", "signal", "time", "fs"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
toml = "0.8"
clap = { version = "4.5", features = ["derive", "env"] }
nix = { version = "0.29", features = ["process", "user", "socket", "fs"] }
thiserror = "2.0"
anyhow = "1.0"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
tracing-appender = "0.2"
secrecy = "0.10"
zeroize = { version = "1.8", features = ["zeroize_derive"] }
sha2 = "0.10"
hex = "0.4"
ulid = "1.1"
dirs = "5.0"
libproc = "0.14"               # proc_pidpath pour vérif caller
fs2 = "0.4"                    # advisory locks pour rules.toml
notify = "6.1"                 # watch profiles pour reload (v2)

[target.'cfg(target_os = "macos")'.dependencies]
objc2 = "0.6"
objc2-foundation = { version = "0.3", features = ["NSString", "NSError", "NSArray", "NSData"] }
objc2-app-kit = { version = "0.3", features = ["NSWindow", "NSView", "NSTextField", "NSButton", "NSStackView", "NSTableView", "NSPopUpButton", "NSAlert", "NSApplication", "NSStatusBar"] }
block2 = "0.5"
```

`envs-prompt` ajoute :
```toml
objc2-local-authentication = { version = "0.3", features = ["LAContext"] }
```

## Layout repo

```
~/www/labs/envs/                         # publié sur github.com/fgribreau/envs
├── Cargo.toml                          # workspace
├── Cargo.lock
├── README.md                           # quickstart + features
├── LICENSE                             # MIT
├── rust-toolchain.toml
├── .gitignore
├── crates/
│   ├── envs-proto/                     # types IPC partagés
│   │   ├── Cargo.toml
│   │   └── src/lib.rs
│   ├── envs-cli/                       # binaire `envs`
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── commands/
│   │       │   ├── run.rs              # workflow principal
│   │       │   ├── init.rs             # wizard
│   │       │   ├── doctor.rs
│   │       │   ├── rules.rs
│   │       │   ├── project.rs
│   │       │   ├── audit.rs
│   │       │   ├── registry.rs
│   │       │   └── daemon.rs
│   │       ├── client.rs               # UDS client
│   │       ├── exec.rs                 # nix::execvpe
│   │       ├── manifest.rs             # parse profiles
│   │       └── error.rs
│   ├── envs-daemon/                    # binaire `envsd`
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── server.rs               # UDS listener
│   │       ├── cache.rs                # rules + value cache
│   │       ├── profile.rs              # resolve project/global
│   │       ├── rbw.rs                  # shell-out
│   │       ├── registry.rs             # lookup + git pull
│   │       ├── discovery.rs            # --help parser, LLM, scoring
│   │       ├── peer.rs                 # SO_PEEREUID + proc_pidpath
│   │       ├── binary.rs               # canonicalize + sha256 + codesign
│   │       ├── helper.rs               # supervise envs-prompt subprocess
│   │       ├── audit.rs                # JSON Lines writer
│   │       └── error.rs
│   └── envs-prompt/                    # binaire `envs-prompt` (helper UI)
│       ├── Cargo.toml
│       └── src/
│           ├── main.rs                 # NSApplication + stdin loop
│           ├── window.rs               # NSWindow + tabs (objc2-app-kit)
│           ├── tab.rs                  # contenu d'un tab popup
│           ├── menubar.rs              # NSStatusBar + (N pending)
│           ├── auth.rs                 # LAContext TouchID
│           └── ipc.rs                  # stdin/stdout JSON
├── docs/
│   ├── ARCHITECTURE.md
│   ├── THREAT-MODEL.md                 # P1 explicite, limites
│   ├── PROFILES.md                     # convention TOML, scopes
│   └── CONTRIBUTING.md
└── packaging/
    ├── com.fgribreau.envsd.plist       # launchd LaunchAgent template
    └── homebrew/
        └── envs.rb                     # tap formula (v0.1.x)
```

Registry séparé : `github.com/fgribreau/envs-registry/binaries/<bin>.toml`

## Phases d'implémentation

### Phase 0 — Skeleton + doctor (½j)
- `cargo new --vcs git` workspace + 4 crates
- `envs doctor` minimal : check rbw, paths, perms

### Phase 1 — Daemon happy path sans biométrie (1-2j)
- UDS server, parsing JSON
- Cache `Vec<Rule>` + sweep + invalidation manuelle
- `rbw.rs` shell-out + parse
- Persistence rules.toml + value cache mémoire
- Fake helper (returns hardcoded grant)
- Test e2e : `envs printenv-bin` injecte

### Phase 2 — Helper UI Rust+objc2 (2-3j)
- `envs-prompt` skeleton : NSApplication.run() + stdin loop
- NSWindow avec NSStackView + accessory views
- Tab system (NSTabViewController ou custom NSStackView vertical à gauche)
- LAContext.evaluatePolicy via objc2-local-authentication
- IPC stdin/stdout JSON, async events
- Menubar item via NSStatusBar (v0.1)

### Phase 3 — CLI wrapper complet (1j)
- `envs run` : canonicalize + sha256 + codesign extract + project_root walk-up + IPC + execvpe
- `envs rules list/show/revoke`
- `envs project init/show`
- `envs --profile X --profile Y` additive

### Phase 4 — Discovery pipeline (2j)
- Registry lookup + git clone/pull
- `--help` parser (regex + heuristiques)
- LLM opt-in (Claude API client)
- Confidence scoring + ranking

### Phase 5 — Hardening (1j)
- `peer.rs` SO_PEEREUID + proc_pidpath cross-check
- Codesign team ID extraction + auto-update sha256
- Hash mismatch → re-auth lightweight popup
- Refus `/usr/bin/*` en scope `Any`
- World-writable check
- Audit `zeroize` paths secrets

### Phase 6 — Lifecycle + bootstrap (1j)
- launchd plist template
- `envs init` wizard
- `envs daemon install/uninstall`

### Phase 7 — Audit log + polish (1j)
- `tracing-appender` daily rotation
- `envs audit show/export`
- Shell completions (`clap_complete`)
- README + docs

**MVP cutline** = Phases 0-3. Phases 4-7 nécessaires avant publish v0.1.

## Vérification end-to-end (black-box, no mocks)

Stratégie : tests black-box, mais **TouchID non-simulable programmatiquement** sur macOS. Solution : feature flag `auth-stub` qui substitue `evaluatePolicy` par une approbation immédiate. Tout le reste (rbw, IPC, exec, hash, codesign, project resolution) est vraiment testé.

| Test | Layer | Méthode |
|---|---|---|
| 1. UDS Ping/Pong | IPC | spawn daemon dans tmpdir, assert Pong |
| 2. rbw shell-out | Backend | shim `rbw` script PATH, assert valeur récupérée |
| 3. Cache TTL | Cache | 2 calls < TTL → cached=true ; sleep > TTL → re-fetch |
| 4. Scope binary | Cache | call A puis B même binaire scope=Any → 1 popup, 2 succès |
| 5. Scope argv-exact | Cache | call A puis B argv différents → 2 popups |
| 6. Project resolution | Profile | mkdir tmpdir/.envs/, run from tmpdir/sub/ → trouve project profile |
| 7. Project switch | Profile | run from project1 puis project2 → 2 popups distinctes |
| 8. Hash mismatch + codesign auto-update | Defense | rebuild bin avec même Team ID → silent update + audit event |
| 9. Hash mismatch sans codesign match | Defense | swap bin Team ID différent → re-auth lightweight popup |
| 10. CLI exec injection | Wrapper | fixture `printenv-bin` → assert env var présente |
| 11. Concurrence same-binary | Race | 5 envs en // → 1 popup, coalesce, 5 success |
| 12. Concurrence diff-binary | Race | envs A puis envs B → tabs s'ajoutent dans même popup |
| 13. Vault locked | Backend | rbw shim exit 1 + "Locked" stderr → CLI exit 75 + msg clair |
| 14. /usr/bin/* refus scope Any | Policy | refus immédiat, OK si scope=Exact |
| 15. Go binary compat | Compat | binaire Go fixture → confirme env vars visibles |
| 16. Bootstrap `envs init` | Lifecycle | tmpdir HOME, run init → all checks pass |
| 17. Audit log integrity | Audit | invariant: jamais de valeur en clair, timestamps monotones |
| 18. Project profile gitignore-friendly | Project | bindings sont des URIs (rbw://), pas des values |

```bash
cd ~/www/labs/envs/
cargo build --release --workspace
cargo test --workspace                                 # 1-9, 11-18 (auth-stub)
cargo test --ignored -- --test-threads=1               # 10 manuel TouchID réel
```

## Open questions / Risks

### Open

1. **objc2-app-kit 0.6 stability** : API surface peut shift entre minor versions. Pin `Cargo.lock`.
2. **Tabs UI : NSTabView vs custom NSStackView vertical** ? NSTabView plus standard, NSStackView vertical plus aligné avec design Lulu (tabs gauche). À trancher au moment du code.
3. **rbw `--field` parsing** : si rbw upgrade change le stdout format, daemon casse. Pin `rbw --version` minimal dans `envs doctor`.
4. **LLM cache key** : binary name suffit ou faut hash du `--help` text aussi ? Hash plus robuste mais cache invalidation plus fréquente.
5. **Argv dynamique** : scope `Exact` avec args qui varient (`--zone-id $RANDOM`) jamais match → re-popup à chaque appel. v0.1 documenter, v2 patterns regex.

### Risks

1. **objc2 + threading** : NSApplication doit être main thread. `envs-prompt` runtime structure : main thread = AppKit, background thread = lit stdin. Channel pour passer events.
2. **launchd KeepAlive thrash** : `ThrottleInterval=10` dans plist.
3. **PID race (TOCTOU)** : entre `connect()` et `proc_pidpath()`. Mitigation = check UID. Documenté dans `THREAT-MODEL.md` que same-UID attaquant est out-of-scope.
4. **Symlink Homebrew updates** : chaque MAJ change le hash. Mitigation v0.1 = codesign auto-update si team match (Cloudflare-signed). Sinon re-auth lightweight popup.
5. **rbw locked au resolve** : daemon retourne `RbwLocked`, CLI affiche "run `rbw unlock`" + exit 75.
6. **Couverture AI agent** : agent doit savoir préfixer ses commandes par `envs`. Documenter dans README + system prompt template.
7. **Crate name `envs` taken** : crate publiée sous **`envs-cli`** (binary toujours `envs`). Mention claire dans README + `cargo install envs-cli`.

## Pré-requis avant impl

- [x] Xcode 16 + Swift 6.1.2 installés (vérifié)
- [x] Rust stable + targets aarch64 (vérifié)
- [x] objc2 0.6 + objc2-app-kit 0.3 déjà en cache Cargo (vérifié)
- [x] TouchID activé (vérifié)
- [ ] `brew install rbw` (pas installé actuellement)
- [ ] `rbw config set email fg@france-nuage.fr`
- [ ] `rbw login` puis `rbw unlock`
- [ ] Créer dans Bitwarden les items selon convention 1 (1 secret = 1 item, password)

## Décisions consolidées

| # | Décision | Choix |
|---|---|---|
| 1 | Tool name | binary `envs`, crate `envs-cli` |
| 2 | Threat model | P1 — consent gate, pas isolation post-grant |
| 3 | Backend BW | `rbw` shell-out (v1) |
| 4 | UI tech | Rust + objc2-app-kit dès J1 |
| 5 | Helper architecture | Option 2 — binaire séparé persistant, IPC stdin/stdout JSON |
| 6 | Mode non-interactif | Fail-fast (envs is interactive macOS only) |
| 7 | Discovery pipeline | γ full : cache → registry → --help → LLM opt-in → popup |
| 8 | Décompilation | Out of scope |
| 9 | Convention BW | Convention 1 (1 secret = 1 item, password). Override via popup mapping |
| 10 | URI scheme | `rbw://<item-name>/<field>` (default field = password) |
| 11 | Concurrence | Coalesce same-bin + FIFO queue cross-bin + tabs gauche |
| 12 | Timeout popup | Pas de timeout, cancel explicite uniquement |
| 13 | Menubar | Icône avec `(N pending)` quand pending > 0 |
| 14 | Hash drift | B+C : codesign auto-update + lightweight re-auth fallback |
| 15 | Audit log | Append-only JSON Lines, daily rotation 30j, no HMAC v0.1 |
| 16 | Persistence | Rules metadata sur disque (no values), value cache RAM 30s |
| 17 | Bootstrap | `envs init` wizard hybrid |
| 18 | Registry | Repo séparé `envs-registry`, lazy git pull 7j + manuel sync |
| 19 | Profile composition | `--profile X --profile Y` additive + `[includes]` TOML |
| 20 | Per-project | Marker `.envs/` walk-up, project-local prime sur global, no Git auto-detect |
| 21 | License | MIT |
| 22 | Codesign v0.1 | Unsigned, brew/cargo install handle quarantine |
| 23 | Project location | `~/www/labs/envs/` → `github.com/fgribreau/envs` |
