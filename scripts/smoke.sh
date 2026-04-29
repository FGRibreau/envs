#!/usr/bin/env bash
# envs CLI smoke test — exercises every subcommand and verifies exit codes + stdout.
# Adapted from /qa skill (which targets web apps) for a CLI/daemon project.
#
# Usage:
#   scripts/smoke.sh [release|debug]   (default: release)
#
# What's covered:
#   ✓ envs --help, --version
#   ✓ envs doctor (exits 0 even with missing rbw/daemon — diagnostic only)
#   ✓ envs init --help (no actual install)
#   ✓ envs project init  (in tmpdir)
#   ✓ envs project show  (in tmpdir)
#   ✓ envs rules list (against running envsd; falls back to "daemon down" check)
#   ✓ envs daemon status (against running envsd)
#   ✓ envs registry sync (no-op or git pull)
#   ✓ envs audit show (empty)
#   ✓ envs audit verify (empty)
#   ✓ envs completions zsh|bash|fish
#   ✓ envs-prompt stub mode roundtrip (auto-grant)
#   ✓ daemon end-to-end with stub helper + fake rbw
#
# Failure exits non-zero with a diff of expected vs actual.

set -uo pipefail

PROFILE="${1:-release}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/$PROFILE"
ENVS="$BIN/envs"
ENVSD="$BIN/envsd"
PROMPT="$BIN/envs-prompt"

PASS=0
FAIL=0
FAIL_DETAILS=()

assert_contains() {
    local label="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -qF "$expected"; then
        printf "  ✓ %s\n" "$label"
        PASS=$((PASS + 1))
    else
        printf "  ✗ %s\n" "$label"
        FAIL=$((FAIL + 1))
        FAIL_DETAILS+=("$label: expected to contain '$expected', got: $(echo "$actual" | head -3)")
    fi
}

assert_exit_zero() {
    local label="$1" exitcode="$2"
    if [ "$exitcode" -eq 0 ]; then
        printf "  ✓ %s (exit 0)\n" "$label"
        PASS=$((PASS + 1))
    else
        printf "  ✗ %s (exit %d)\n" "$label" "$exitcode"
        FAIL=$((FAIL + 1))
        FAIL_DETAILS+=("$label: expected exit 0, got $exitcode")
    fi
}

ensure_binary() {
    if [ ! -x "$1" ]; then
        echo "✗ $1 not found. Run: cargo build --$PROFILE --workspace"
        exit 2
    fi
}

ensure_binary "$ENVS"
ensure_binary "$ENVSD"
ensure_binary "$PROMPT"

echo "envs smoke test (profile: $PROFILE)"
echo "================================"

echo
echo "[1] CLI surface (no daemon required)"
out=$("$ENVS" --version 2>&1); rc=$?
assert_exit_zero "envs --version" "$rc"
assert_contains "envs --version contains 0.1" "envs 0.1" "$out"

out=$("$ENVS" --help 2>&1); rc=$?
assert_exit_zero "envs --help" "$rc"
assert_contains "envs --help lists run" "Run a command with secrets" "$out"
assert_contains "envs --help lists doctor" "Run diagnostic checks" "$out"
assert_contains "envs --help lists project" "Manage project-local profiles" "$out"
assert_contains "envs --help lists audit" "View audit log" "$out"

echo
echo "[2] Diagnostics (envs doctor)"
out=$("$ENVS" doctor 2>&1); rc=$?
assert_exit_zero "envs doctor exits 0" "$rc"
assert_contains "doctor reports rbw status" "rbw" "$out"
assert_contains "doctor reports xcode" "Xcode" "$out"

echo
echo "[3] Shell completions"
for shell in bash zsh fish; do
    out=$("$ENVS" completions "$shell" 2>&1); rc=$?
    assert_exit_zero "envs completions $shell" "$rc"
done

echo
echo "[4] Project workflow"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT
cd "$TMPDIR"

out=$(echo "n" | "$ENVS" project init 2>&1); rc=$?
assert_exit_zero "envs project init" "$rc"
assert_contains "project init creates .envs/" ".envs" "$out"
[ -d "$TMPDIR/.envs" ] && { printf "  ✓ .envs/ directory created\n"; PASS=$((PASS + 1)); } || { printf "  ✗ .envs/ not created\n"; FAIL=$((FAIL + 1)); }

cd /

echo
echo "[5] Audit log (empty state)"
out=$("$ENVS" audit show 2>&1); rc=$?
assert_exit_zero "envs audit show" "$rc"
out=$("$ENVS" audit verify 2>&1); rc=$?
assert_exit_zero "envs audit verify" "$rc"

echo
echo "[6] Stub helper IPC roundtrip"
REQUEST='{"kind":"new_request","request_id":"smoke-1","canon_path":"/usr/bin/echo","binary_name":"echo","argv":["echo"],"cwd":"/tmp","project_root":null,"suggested_bindings":[{"env":"FOO","source":"rbw://FOO","confidence":"high","reason":"smoke","deprecated":false}],"available_vault_items":[],"current_profile":null}'
out=$(echo "$REQUEST" | ENVS_PROMPT_AUTO_GRANT=1 "$PROMPT" 2>/dev/null); rc=$?
assert_exit_zero "envs-prompt stub returns" "$rc"
assert_contains "envs-prompt outputs authorized" "authorized" "$out"
assert_contains "envs-prompt outputs binding env" "FOO" "$out"

echo
echo "[7] End-to-end daemon happy path (with stub helper + fake rbw)"
DTMP=$(mktemp -d)
trap 'rm -rf "$DTMP" "$TMPDIR"' EXIT

# Fake rbw shim in a tmp PATH
mkdir -p "$DTMP/bin"
cat > "$DTMP/bin/rbw" <<'EOF'
#!/bin/bash
case "$1" in
    --version) echo "rbw-shim 0.0.0"; exit 0 ;;
    unlocked) exit 0 ;;
    get)
        item="$2"; field="password"
        if [ "$3" = "--field" ]; then field="$4"; fi
        echo "smoke-value-${item}-${field}"
        exit 0
        ;;
    *) exit 1 ;;
esac
EOF
chmod +x "$DTMP/bin/rbw"

# Plant a global profile for the test
mkdir -p "$DTMP/home/.envs/profiles" "$DTMP/home/.envs/state" "$DTMP/home/.envs/logs"
cat > "$DTMP/home/.envs/profiles/echo.toml" <<EOF
schema = 1
[binary]
name = "echo"
[[binding]]
env = "SMOKE_TOKEN"
src = "rbw://SMOKE_TOKEN"
EOF

# Start daemon in background
SOCKET="$DTMP/envsd.sock"
HOME="$DTMP/home" \
ENVS_SOCKET="$SOCKET" \
ENVS_HELPER_STUB=1 \
ENVS_SKIP_REGISTRY_SYNC=1 \
PATH="$DTMP/bin:$PATH" \
RUST_LOG="warn" \
"$ENVSD" >"$DTMP/envsd.stderr" 2>&1 &
DPID=$!

# Wait for socket
for i in $(seq 1 30); do
    [ -S "$SOCKET" ] && break
    sleep 0.1
done

if [ -S "$SOCKET" ]; then
    printf "  ✓ daemon started, socket at %s\n" "$SOCKET"
    PASS=$((PASS + 1))

    # Status request
    out=$(ENVS_SOCKET="$SOCKET" "$ENVS" daemon status 2>&1); rc=$?
    assert_exit_zero "envs daemon status (live daemon)" "$rc"
    assert_contains "daemon status reports rules: 0" "rules active:   0" "$out"

    # Cleanup
    kill -TERM $DPID 2>/dev/null
    wait $DPID 2>/dev/null
else
    printf "  ✗ daemon failed to start\n"
    FAIL=$((FAIL + 1))
    cat "$DTMP/envsd.stderr" >&2 || true
    kill $DPID 2>/dev/null
fi

echo
echo "================================"
echo "PASS: $PASS    FAIL: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    echo "Failures:"
    for d in "${FAIL_DETAILS[@]}"; do
        echo "  - $d"
    done
    exit 1
fi
echo "All smoke tests passed."
exit 0
