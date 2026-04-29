#!/usr/bin/env bash
# Non-interactive pinentry shim driven by $RBW_PASSWORD.
#
# Implements just enough of the Assuan protocol to satisfy rbw:
#   OK <greeting>
#   < OPTION ... (acks)
#   < SETDESC ... (acks)
#   < SETPROMPT ... (acks)
#   < GETPIN  → emits D <password>\nOK
#   < BYE     → exits cleanly
#
# Real pinentry-touchid does the same dance but resolves the password from
# macOS Keychain after a TouchID prompt. In tests we read it from the env.
set -eu

password="${RBW_PASSWORD:?RBW_PASSWORD must be set for the pinentry stub}"

printf 'OK Pleased to meet you\n'

while IFS= read -r line; do
    case "$line" in
        GETPIN*)
            printf 'D %s\n' "$password"
            printf 'OK\n'
            ;;
        BYE*)
            printf 'OK closing connection\n'
            exit 0
            ;;
        '')
            : ;;
        *)
            # OPTION / SETDESC / SETPROMPT / SETKEYINFO / etc. — just ack.
            printf 'OK\n'
            ;;
    esac
done
