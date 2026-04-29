# envs

> Lulu-style firewall for environment variables. Bitwarden + TouchID + per-project scoping.

`envs` lets AI agents and humans invoke CLI commands that need secrets without ever seeing the plaintext tokens. At first invocation, a native macOS popup asks for TouchID confirmation — which env vars to inject, what scope (binary or argv-exact), how long. The decision is cached; subsequent calls within scope skip the prompt.

## Status

**v0.6 — usable on macOS.** See [specs/spec.md](specs/spec.md) for the full design and [DEVELOPMENT.md](DEVELOPMENT.md) for build instructions.

## Why

Existing tools don't fit:

- `bws run` (Bitwarden Secrets Manager) requires `BWS_ACCESS_TOKEN` in plaintext env, no biometric, CI-targeted
- `rbw` has no `run` subcommand; `lock_timeout` is global
- `op run` (1Password) is the closest match but for 1Password vaults, not Bitwarden
- Wrappers like `envwarden`, `bwsh`, `bws-env` have no biometric prompt or per-call scope

`envs` fills the gap for Bitwarden personal vault users on macOS who want consent-gated secret access for CLI tools and AI agents.

## Install

```bash
brew install rbw                                # Bitwarden CLI backend
rbw config set email you@example.com
rbw login && rbw unlock

git clone https://github.com/fgribreau/envs.git
cd envs
cargo install --path crates/envs-cli \
              --path crates/envs-daemon \
              --path crates/envs-prompt
```

## Use

```bash
envs init                       # one-time setup wizard (LaunchAgent + registry)
envs daemon status              # confirm envsd is up
envs flarectl zone list         # native popup → TouchID → secret injected
envs --bind CF_TOKEN=rbw://CFProd/api_token --profile aws -- ./deploy.sh
envs audit show                 # who got which env var, when
envs audit verify               # check the HMAC chain integrity
```

See `envs --help` for the full surface (`run`, `init`, `doctor`, `rules`, `project`, `audit`, `registry`, `daemon`, `completions`).

## Sponsors

[<img src="https://github.com/FGRibreau/mcp-matomo/raw/main/assets/sponsors/natalia.svg" width="200">  
**Natalia**](https://getnatalia.com/)  
24/7 AI voice and whatsapp agent for customer services

[<img src="https://github.com/FGRibreau/mcp-matomo/raw/main/assets/sponsors/nobullshitconseil.svg" width="200">  
**NoBullshitConseil**](https://nobullshitconseil.com/)  
360° tech consulting

[<img src="https://github.com/FGRibreau/mcp-matomo/raw/main/assets/sponsors/hook0.png" width="200">  
**Hook0**](https://www.hook0.com/)  
Open-Source Webhooks-as-a-Service

[<img src="https://github.com/FGRibreau/mcp-matomo/raw/main/assets/sponsors/france-nuage.png" width="200">  
**France-Nuage**](https://france-nuage.fr/)  
Sovereign cloud hosting in France

> **Interested in sponsoring?** [Get in touch](mailto:rust@fgribreau.com)

## License

MIT — see [LICENSE](LICENSE).
