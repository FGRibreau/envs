#!/usr/bin/env bash
# End-to-end test driver — runs inside the envs-test container, talks to the
# vaultwarden service over the docker network.
#
# Asserts the auto-lock + auto-unlock cycle, value-cache short-circuit, and
# audit chain integrity against a real vault (not a mocked rbw shim).

set -euo pipefail

VAULTWARDEN_URL="${VAULTWARDEN_URL:-http://vaultwarden}"
RBW_EMAIL="${RBW_EMAIL:?RBW_EMAIL required}"
RBW_PASSWORD="${RBW_PASSWORD:?RBW_PASSWORD required}"
export RBW_PASSWORD  # consumed by pinentry-stub

red()    { printf '\033[31m%s\033[0m\n' "$*"; }
green()  { printf '\033[32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[33m%s\033[0m\n' "$*"; }
fail()   { red "FAIL: $*"; exit 1; }
ok()     { green "  ✓ $*"; }
step()   { yellow "▶ $*"; }

# ─── 1. Wait for vaultwarden ────────────────────────────────────────────────
step "wait for vaultwarden"
for i in $(seq 1 30); do
    if curl -sf "${VAULTWARDEN_URL}/alive" >/dev/null; then
        ok "vaultwarden up"
        break
    fi
    [ "$i" = 30 ] && fail "vaultwarden never became ready"
    sleep 1
done

# ─── 2. Bootstrap rbw ───────────────────────────────────────────────────────
# ─── 2a. Bootstrap account via the Bitwarden HTTP register endpoint ───────
# The official `bw` CLI no longer exposes account creation — we do the KDF
# dance + POST /identity/accounts/register ourselves via a tiny Node helper.
step "register account on vaultwarden"
node /integration/register-account.js \
    || fail "registration failed (vaultwarden may have already registered this email)"
ok "account registered"

# bw still useful for adding items (login + create item).
step "configure bw"
mkdir -p "${HOME}/.config/Bitwarden CLI"
bw config server "${VAULTWARDEN_URL}" >/dev/null
ok "bw points at $VAULTWARDEN_URL"

# Plant the two test items via bw, then forget about bw.
step "seed vault with bw"
BW_SESSION=$(bw login "${RBW_EMAIL}" "${RBW_PASSWORD}" --raw)
export BW_SESSION
bw_create() {
    local name="$1"
    local password="$2"
    local item
    item=$(bw get template item | jq -c \
        --arg name "$name" \
        --arg password "$password" \
        '.name=$name | .login={"username":null,"password":$password,"uris":[],"totp":null} | del(.notes) | del(.fields)')
    echo "$item" | bw encode | bw create item >/dev/null
}
bw_create TEST_KEY     "hello-from-vaultwarden"
bw_create ANOTHER_KEY  "second-secret"
bw sync >/dev/null
bw logout >/dev/null
unset BW_SESSION
ok "2 items seeded"

# ─── 3. Bootstrap rbw against the same vaultwarden + same account ──────────
step "configure rbw"
mkdir -p "${HOME}/.config/rbw" "${HOME}/.envs/state" "${HOME}/.envs/logs" "${HOME}/.envs/profiles"
rbw config set base_url "${VAULTWARDEN_URL}"
rbw config set email "${RBW_EMAIL}"
rbw config set pinentry pinentry-stub
ok "rbw configured against $VAULTWARDEN_URL"

step "rbw login"
rbw login
ok "logged in"

step "rbw unlock"
rbw unlock
ok "vault unlocked"

step "verify rbw can read the seeded items"
rbw get TEST_KEY    | grep -q '^hello-from-vaultwarden$'  || fail "rbw cannot read TEST_KEY"
rbw get ANOTHER_KEY | grep -q '^second-secret$'          || fail "rbw cannot read ANOTHER_KEY"
ok "rbw retrieves both items"

# ─── 5. Plant a project profile so envs-prompt-stub picks it up ────────────
step "plant envs project profile"
mkdir -p /work
cd /work
cat > "${HOME}/.envs/profiles/env.toml" <<'EOF'
schema = 1
[binary]
name = "env"
[[binding]]
env = "GREETING"
src = "rbw://TEST_KEY"
[[binding]]
env = "ANOTHER"
src = "rbw://ANOTHER_KEY"
EOF
ok "profile written"

# ─── 6. Start envsd ─────────────────────────────────────────────────────────
step "start envsd"
envsd > "${HOME}/.envs/logs/envsd.stdout.log" 2> "${HOME}/.envs/logs/envsd.stderr.log" &
DAEMON_PID=$!
trap "kill -TERM $DAEMON_PID 2>/dev/null || true" EXIT
for i in $(seq 1 30); do
    [ -S "${HOME}/.envs/envsd.sock" ] && break
    sleep 0.2
done
[ -S "${HOME}/.envs/envsd.sock" ] || fail "envsd socket never appeared"
ok "envsd up (pid $DAEMON_PID)"

# ─── 7. Pre-lock rbw so the cold path exercises auto_unlock ────────────────
step "lock rbw before cold path"
rbw lock
ok "vault locked (envs will auto-unlock on the cold call)"

# ─── 8. Cold path: envs run /usr/bin/env, expect GREETING + ANOTHER ────────
step "cold path: envs run -- /usr/bin/env"
envs run -- /usr/bin/env > /tmp/env.out 2>&1 || {
    cat /tmp/env.out
    cat "${HOME}/.envs/logs/envsd.stderr.log"
    fail "envs run failed"
}
grep -q '^GREETING=hello-from-vaultwarden$' /tmp/env.out || {
    cat /tmp/env.out
    fail "GREETING not injected"
}
grep -q '^ANOTHER=second-secret$'           /tmp/env.out || {
    cat /tmp/env.out
    fail "ANOTHER not injected"
}
ok "both env vars injected"

# ─── 9. Vault must be locked again after resolve (the whole point) ─────────
step "rbw must be locked after resolve"
if rbw unlocked; then
    fail "vault still unlocked after envs run — auto_lock did not fire"
fi
ok "vault auto-locked"

# ─── 10. Warm path: cache hit within 30s, no rbw call ──────────────────────
step "warm cache hit"
envs run -- /usr/bin/env | grep -q '^GREETING=hello-from-vaultwarden$' \
    || fail "warm path failed"
ok "warm cache returned values without unlocking"

# ─── 11. Audit chain ─────────────────────────────────────────────────────────
step "audit chain"
envs audit show > /tmp/audit.out
grep -q 'auto_unlock'  /tmp/audit.out || fail "auto_unlock event missing"
grep -q 'auto_lock'    /tmp/audit.out || fail "auto_lock event missing"
grep -q 'grant'        /tmp/audit.out || fail "grant event missing"
grep -q 'resolve'      /tmp/audit.out || fail "resolve event missing"
ok "all 4 expected events present"
envs audit verify > /tmp/audit-verify.out
grep -q '✓ chain verified' /tmp/audit-verify.out || {
    cat /tmp/audit-verify.out
    fail "audit chain verification failed"
}
ok "HMAC chain verified"

# ─── 12. Cold path again after sleep — re-unlock should fire ───────────────
step "cache expiry → re-unlock"
sleep 31
envs run -- /usr/bin/env | grep -q '^GREETING=hello-from-vaultwarden$' \
    || fail "cold path after cache expiry failed"
if rbw unlocked; then
    fail "vault still unlocked after second resolve — auto_lock did not fire again"
fi
ok "second cold path also auto-locked"

green ""
green "ALL INTEGRATION TESTS PASSED"
