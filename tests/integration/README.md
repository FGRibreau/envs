# Docker integration test

Real end-to-end test against a live Vaultwarden server, with rbw and envs
co-located in a Linux container. Validates the parts that the unit + Rust
integration tests can't cover with a mocked rbw shim:

- the Bitwarden HTTP protocol (rbw ↔ vaultwarden)
- rbw's actual lock / unlock / get pipeline (real KDF, real ciphertext)
- envs auto-lock + auto-unlock cycle, value cache 30s window, audit chain
- exit codes & stderr formatting under realistic conditions

## Run locally

```bash
docker compose -f tests/integration/docker-compose.test.yml up \
  --build --abort-on-container-exit --exit-code-from envs-test
```

The `envs-test` container exits 0 on success, non-zero on any failed step in
`run-tests.sh`. Vaultwarden state is ephemeral (no volume), every run starts
clean.

## What the test asserts

| Step | What it proves |
|---|---|
| 1 | vaultwarden is up |
| 2-3 | rbw points at vaultwarden, can register + login + unlock |
| 4 | rbw can store / retrieve real items |
| 5-6 | envsd starts, exposes the UDS |
| 7 | `envs daemon status` reports `rbw unlocked: true` |
| 8 | `envs run` injects two env vars from real vault entries (cold path) |
| 9 | `rbw unlocked` returns false post-resolve — **auto_lock fired** |
| 10 | second `envs run` within 30s skips rbw entirely (warm cache) |
| 11 | audit log contains `auto_unlock`, `auto_lock`, `grant`, `resolve`, HMAC chain verifies |
| 12 | after 31s sleep, third `envs run` re-unlocks then re-locks |

## Pinentry stub

Real macOS uses `pinentry-touchid` (TouchID + Keychain). Linux containers have
no equivalent, so we ship a 30-line `pinentry-stub.sh` that implements just
enough Assuan protocol to emit `$RBW_PASSWORD` on demand. rbw can't tell the
difference. This matches how the macOS path works behind TouchID — the user
authentication is delegated entirely to the OS, envs never sees the master
password.
