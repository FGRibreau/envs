# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

<!-- release-plz prepends new entries below this line -->

## [Unreleased]

### ⚠ BREAKING

- **`pinentry-touchid` is now a hard prerequisite.** `envs init` refuses to proceed without it. Install via `brew install jorgelbg/tap/pinentry-touchid` and `rbw config set pinentry pinentry-touchid`.
- `envsd` now **auto-locks `rbw` after every resolve** and **auto-unlocks it on demand**. The historical side channel (any same-UID process could `rbw get *` for the duration of `lock_timeout`, default 1 h) is now closed. An unexpected pinentry-touchid prompt while you didn't initiate a command is a tripwire signalling unauthorized access.
- New audit events: `auto_unlock`, `auto_lock`, `auto_unlock_failed`, `auto_lock_failed`. The HMAC chain is unchanged; existing logs verify cleanly.
- CLI error message for `RbwLocked` updated: now points to `envs doctor` to verify the pinentry-touchid setup.
