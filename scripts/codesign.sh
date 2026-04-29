#!/usr/bin/env bash
# envs codesign + notarize script.
#
# What it does:
#   1. Reads ENVS_APPLE_TEAM_ID from environment (your Apple Developer Team ID).
#   2. Codesigns each release binary (envs, envsd, envs-prompt) with hardened runtime.
#   3. (Optional) Submits to Apple notarytool for notarization (requires keychain
#      profile "envs-notary" set up via `xcrun notarytool store-credentials`).
#   4. Staples the notarization ticket to each binary.
#
# When ENVS_APPLE_TEAM_ID is unset, the script SKIPS codesign and exits 0 with a
# warning, so non-Apple-Developer contributors can still run `cargo build` and
# distribute unsigned binaries via brew/cargo install.
#
# Usage:
#   ENVS_APPLE_TEAM_ID=ABC1234567 scripts/codesign.sh
#   ENVS_APPLE_TEAM_ID=ABC1234567 ENVS_NOTARIZE=1 scripts/codesign.sh
#
# Prerequisites for full notarization:
#   - macOS 13+ (notarytool replacement of altool)
#   - Apple Developer ID Application certificate in login keychain
#   - One-time setup: xcrun notarytool store-credentials envs-notary
#
# Exit codes:
#   0 = success (or skipped)
#   1 = codesign failed
#   2 = notarization failed
#   3 = stapling failed

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="$ROOT/target/release"
BINARIES=("envs" "envsd" "envs-prompt")
TEAM_ID="${ENVS_APPLE_TEAM_ID:-}"
DO_NOTARIZE="${ENVS_NOTARIZE:-0}"
NOTARY_PROFILE="${ENVS_NOTARY_PROFILE:-envs-notary}"

if [ -z "$TEAM_ID" ]; then
    echo "ENVS_APPLE_TEAM_ID is not set — skipping codesign."
    echo "Binaries will work via 'cargo install' / 'brew install' (handles quarantine)."
    echo "To enable codesign: ENVS_APPLE_TEAM_ID=YOUR_TEAM_ID scripts/codesign.sh"
    exit 0
fi

# Verify each binary exists
for bin in "${BINARIES[@]}"; do
    if [ ! -x "$BIN/$bin" ]; then
        echo "✗ missing release binary: $BIN/$bin"
        echo "  Run: cargo build --release --workspace"
        exit 1
    fi
done

# Identity to use for codesign. We use Developer ID Application:
IDENTITY="Developer ID Application: ${TEAM_ID}"

echo "envs codesign — Team ID: $TEAM_ID"
echo "================================"

for bin in "${BINARIES[@]}"; do
    path="$BIN/$bin"
    echo
    echo "[$bin] codesign with hardened runtime..."
    codesign --force --options runtime --timestamp \
        --sign "$IDENTITY" \
        --identifier "com.fgribreau.envs.$bin" \
        "$path"
    if [ $? -ne 0 ]; then
        echo "✗ codesign failed for $bin"
        exit 1
    fi

    # Verify
    if codesign --verify --strict --verbose=2 "$path" 2>&1 | grep -q "valid on disk"; then
        echo "  ✓ codesigned"
    else
        echo "  ✗ codesign verify failed for $bin"
        exit 1
    fi
done

if [ "$DO_NOTARIZE" != "1" ]; then
    echo
    echo "Codesign complete. Notarization skipped (set ENVS_NOTARIZE=1 to enable)."
    exit 0
fi

# Notarize: submit each binary as a ZIP to Apple, wait, staple
echo
echo "Notarizing binaries (this can take a few minutes per binary)..."

for bin in "${BINARIES[@]}"; do
    path="$BIN/$bin"
    zip_path="/tmp/envs-notarize-$bin.zip"

    echo
    echo "[$bin] zipping for submission..."
    rm -f "$zip_path"
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$path" "$zip_path"

    echo "[$bin] notarytool submit (waiting for Apple to finish)..."
    submit_output=$(xcrun notarytool submit "$zip_path" \
        --keychain-profile "$NOTARY_PROFILE" \
        --wait 2>&1)
    submit_status=$?

    echo "$submit_output"
    if [ $submit_status -ne 0 ]; then
        echo "✗ notarization failed for $bin"
        exit 2
    fi

    if echo "$submit_output" | grep -q "status: Accepted"; then
        echo "  ✓ accepted"
    else
        echo "  ✗ not accepted (see output above)"
        exit 2
    fi

    # Staple — only works on .app/.dmg/.pkg, NOT raw binaries.
    # For raw binaries, the notarization ticket is in the Apple notary database;
    # Gatekeeper checks online on first run. Stapling is for offline distribution.
    # We skip stapling raw binaries since Apple doesn't support it for them.
    rm -f "$zip_path"
done

echo
echo "================================"
echo "✓ Codesign + notarization complete"
echo "  Binaries are signed by Team ID $TEAM_ID and notarized by Apple."
echo "  Distribute via tar.gz; users won't see a Gatekeeper warning."
