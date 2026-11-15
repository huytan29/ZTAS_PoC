#!/usr/bin/env sh
set -eu

# Finder double-click entry point. macOS opens Terminal and asks once for the
# local administrator password needed to add the CA to System Keychain.
bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$bundle_dir/ztas-client-config.sh"
exec sudo sh "$bundle_dir/provision-client-macos.sh" "$ZTAS_SERVER_IP" \
  "$bundle_dir/ztas-local-ca.crt" "${ZTAS_DNS_MODE:-}"
