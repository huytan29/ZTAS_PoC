#!/usr/bin/env sh
set -eu

# Finder double-click entry point. macOS opens Terminal and asks once for the
# local administrator password needed to add the CA to System Keychain.
bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$bundle_dir/ztas-client-config.sh"
ZTAS_SERVER_IP=$(printf '%s' "${ZTAS_SERVER_IP:-}" | tr -d '\r')
ZTAS_DNS_MODE=$(printf '%s' "${ZTAS_DNS_MODE:-}" | tr -d '\r')

[ -n "$ZTAS_SERVER_IP" ] || {
  echo '[ERROR] Bo cai dat thieu IP server. Hay yeu cau admin tao lai Client_PoC.' >&2
  exit 1
}

sudo sh "$bundle_dir/provision-client-macos.sh" "$ZTAS_SERVER_IP" \
  "$bundle_dir/ztas-local-ca.crt" "$ZTAS_DNS_MODE"

open 'https://ztas.ptit:8443/connect-device'
echo '[DONE] Da mo trinh duyet den trang ket noi thiet bi.'
