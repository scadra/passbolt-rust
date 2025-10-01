#!/usr/bin/env bash
# Run the CLI end-to-end tests against a real Passbolt server.
# Settings: PASSBOLT_E2E_* from the environment or .env.e2e (see .env.e2e.example).
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ -f .env.e2e ]]; then
  set -a
  source .env.e2e
  set +a
fi
# Tests run from the crate directory: make the key path absolute.
if [[ -n "${PASSBOLT_E2E_USER_PRIVATE_KEY_FILE:-}" ]]; then
  PASSBOLT_E2E_USER_PRIVATE_KEY_FILE=$(realpath "$PASSBOLT_E2E_USER_PRIVATE_KEY_FILE")
  export PASSBOLT_E2E_USER_PRIVATE_KEY_FILE
fi
exec cargo test -p passbolt-cli --features e2e --test e2e "$@" -- --test-threads=1
