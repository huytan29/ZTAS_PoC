#!/usr/bin/env sh
set -eu

# Launcher bundled with the CA. Double-click may open a terminal depending on
# the desktop environment; it asks once for the local administrator password.
bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$bundle_dir/ztas-client-config.sh"
exec sudo sh "$bundle_dir/provision-client-ubuntu.sh" "$ZTAS_SERVER_IP" \
  "$bundle_dir/ztas-local-ca.crt" "${ZTAS_DNS_MODE:-}"
