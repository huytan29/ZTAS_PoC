#!/usr/bin/env sh
set -eu

# Launcher bundled with the CA. Double-click may open a terminal depending on
# the desktop environment; it asks once for the local administrator password.
bundle_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
. "$bundle_dir/ztas-client-config.sh"
# Also tolerate bundles copied from Windows before the generator switched the
# shell config to LF line endings.
ZTAS_SERVER_IP=$(printf '%s' "${ZTAS_SERVER_IP:-}" | tr -d '\r')
ZTAS_DNS_MODE=$(printf '%s' "${ZTAS_DNS_MODE:-}" | tr -d '\r')

[ -n "$ZTAS_SERVER_IP" ] || {
  echo '[ERROR] Bo cai dat thieu IP server. Hay yeu cau admin tao lai Client_PoC.' >&2
  exit 1
}

sudo sh "$bundle_dir/provision-client-ubuntu.sh" "$ZTAS_SERVER_IP" \
  "$bundle_dir/ztas-local-ca.crt" "$ZTAS_DNS_MODE"

url='https://ztas.ptit:8443/connect-device'
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$url" >/dev/null 2>&1 &
fi
echo "[DONE] Da mo trinh duyet: $url"
