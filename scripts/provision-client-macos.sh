#!/usr/bin/env sh
set -eu

# Provision one macOS client for the internal ZTAS HTTPS endpoint.
# Run as root:
#   sudo sh provision-client-macos.sh <server-ip> <path-to-ca> [--use-dns]

server_ip=${1:-}
ca_file=${2:-}
dns_mode=${3:-}
hostname='ztas.ptit'

usage() {
  echo "Usage: $0 <server-ip> <path-to-ca> [--use-dns]" >&2
  echo "Example: sudo sh $0 192.168.2.2 ~/Downloads/ztas-local-ca.crt" >&2
  echo "--use-dns: khong sua /etc/hosts, dung DNS noi bo da cau hinh." >&2
  exit 2
}

[ -n "$server_ip" ] && [ -n "$ca_file" ] || usage
[ -z "$dns_mode" ] || [ "$dns_mode" = '--use-dns' ] || usage

if [ "$(id -u)" -ne 0 ]; then
  echo '[ERROR] Hay chay script bang sudo.' >&2
  exit 1
fi

if ! printf '%s' "$server_ip" | awk -F. '
  NF != 4 { valid = 0; exit }
  {
    valid = 1
    for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) valid = 0
  }
  END { exit(valid ? 0 : 1) }
'; then
  echo "[ERROR] '$server_ip' khong phai IPv4 hop le." >&2
  exit 1
fi

if [ ! -f "$ca_file" ]; then
  echo "[ERROR] Khong tim thay CA: $ca_file" >&2
  exit 1
fi

echo '[INFO] CA fingerprint SHA-256:'
shasum -a 256 "$ca_file"
echo '[INFO] Chi tiep tuc neu fingerprint nay do admin/server ZTAS cung cap.'

security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain "$ca_file"

if [ "$dns_mode" = '--use-dns' ]; then
  echo "[INFO] Giu DNS noi bo hien co cho $hostname."
else
  echo "[INFO] Cap nhat /etc/hosts: $hostname -> $server_ip"
  hosts_tmp=$(mktemp)
  trap 'rm -f "$hosts_tmp"' EXIT HUP INT TERM
  awk -v host="$hostname" '
    {
      matched = 0
      for (i = 1; i <= NF; i++) if ($i == host) matched = 1
      if (!matched) print
    }
  ' /etc/hosts > "$hosts_tmp"
  printf '%s %s\n' "$server_ip" "$hostname" >> "$hosts_tmp"
  cat "$hosts_tmp" > /etc/hosts
fi

dscacheutil -flushcache || true
killall -HUP mDNSResponder || true

echo '[INFO] Kiem tra HTTPS...'
if ! curl --fail --silent --show-error "https://$hostname:8443/health"; then
  echo >&2
  echo '[WARN] Da cai CA, nhung chua ket noi duoc server. Kiem tra IP/DNS, Firewall 8443 va server.' >&2
  exit 1
fi

echo
echo "[DONE] macOS da san sang: https://$hostname:8443"
echo "[NEXT] Mo https://$hostname:8443/connect-device de dang ky thiet bi neu day la may moi."
