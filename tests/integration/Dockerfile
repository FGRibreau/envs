# syntax=docker/dockerfile:1.7

# Multi-stage: build envs binaries on Linux, then assemble a slim test image
# with rbw + a non-interactive pinentry shim that the integration script drives.

FROM rust:1.94-slim-bookworm AS builder
WORKDIR /src

# System deps for rbw (libssl, perl) and our build (pkg-config).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates pkg-config libssl-dev perl curl \
    && rm -rf /var/lib/apt/lists/*

# Cache cargo registry & dependency builds across image rebuilds.
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY packaging ./packaging
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --workspace --bins \
    && mkdir -p /out \
    && cp target/release/envs /out/ \
    && cp target/release/envsd /out/ \
    && cp target/release/envs-prompt /out/

# Install rbw from source (no brew on Linux). 1.15.0 matches the macOS bottle.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    cargo install rbw --version 1.15.0 --locked --root /out

# ─────────────────────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS test
WORKDIR /integration

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates jq curl wget bash openssl libssl3 unzip nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# envs binaries
COPY --from=builder /out/envs       /usr/local/bin/envs
COPY --from=builder /out/envsd      /usr/local/bin/envsd
COPY --from=builder /out/envs-prompt /usr/local/bin/envs-prompt
COPY --from=builder /out/bin/rbw       /usr/local/bin/rbw
COPY --from=builder /out/bin/rbw-agent /usr/local/bin/rbw-agent

# Official Bitwarden CLI via npm (multi-arch — the static binary is amd64-only
# and crashes under Rosetta on Apple Silicon hosts). Used only for the one-shot
# account signup; the actual envs path goes through rbw.
ARG BW_VERSION=2024.7.2
RUN npm install -g "@bitwarden/cli@${BW_VERSION}" \
    && rm -rf /root/.npm

# Non-interactive pinentry shim. rbw shells out to whatever `rbw config` points
# to; we point it at this script. It returns the master password from the
# environment, which is exactly what TouchID + Keychain do on macOS.
COPY tests/integration/pinentry-stub.sh /usr/local/bin/pinentry-stub
RUN chmod +x /usr/local/bin/pinentry-stub

COPY tests/integration/run-tests.sh /integration/run-tests.sh
COPY tests/integration/register-account.js /integration/register-account.js
RUN chmod +x /integration/run-tests.sh

ENV PATH="/usr/local/bin:${PATH}"
ENV HOME="/root"
ENV ENVS_PROMPT_AUTO_GRANT="1"
ENV ENVS_HELPER_STUB="1"
