#!/bin/bash
# Minimal rbw shim for tests. Returns a deterministic value for "get".
# Usage: rbw-shim.sh <subcommand> [args...]
case "$1" in
  --version) echo "rbw-shim 0.0.0"; exit 0 ;;
  unlocked) exit 0 ;;
  get)
    item="$2"
    field="password"
    if [ "$3" = "--field" ]; then field="$4"; fi
    echo "test-value-for-${item}-${field}"
    exit 0
    ;;
  *) echo "rbw-shim: unsupported $1" >&2; exit 1 ;;
esac
