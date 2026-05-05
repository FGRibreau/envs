# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
## [0.2.0](https://github.com/FGRibreau/envs/compare/v0.1.0...v0.2.0) - 2026-05-05

### Added

- *(prompt)* Native osascript dialogs for empty-binding flow

- *(cli)* Wire audit show --since/--project + drop dead Shell stub

- *(daemon)* Wire real Anthropic API for LLM-powered discovery

- *(tests)* Docker integration — vaultwarden + rbw + envs e2e

- *(daemon)* Auto-lock + auto-unlock rbw between resolves


### Fixed

- *(daemon)* Use argv[0] basename for profile lookup, not canon name

- *(cli,daemon)* Friendlier errors + helper-degraded fail-fast

- *(ci)* Make clippy + release-plz green on first run


### Style

- Cargo fmt --all

