#!/bin/sh
# Starts the OpenCode phone-sync proxy on loopback, with the password read
# from the login Keychain so it never sits in a plist or in shell history.
#
# Create the Keychain item once (it prompts for the password):
#   security add-generic-password -s opencode-phone-sync -a opencode -w
#
# Override the listen address/port with OPENCODE_SYNC_HOST / OPENCODE_SYNC_PORT.
set -eu

PW=$(security find-generic-password -s opencode-phone-sync -a opencode -w 2>/dev/null || true)
if [ -z "${PW}" ]; then
  echo "opencode-phone-sync: no Keychain item 'opencode-phone-sync' (account opencode)" >&2
  exit 1
fi

export OPENCODE_PASSWORD="${PW}"
export OPENCODE_SYNC_HOST="${OPENCODE_SYNC_HOST:-127.0.0.1}"
export OPENCODE_SYNC_PORT="${OPENCODE_SYNC_PORT:-8787}"

exec /usr/bin/python3 "${HOME}/opencode-phone-sync/serve.py"
