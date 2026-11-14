#!/usr/bin/env sh
set -eu

# One-command HTTPS deployment for a macOS host running ZTAS.
# Usage: sh scripts/deploy-https-macos.sh 192.168.x.x

server_ip=${1:-}
hostname="ztas.ptit"
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

if [ -z "$server_ip" ]; then
  echo "[ERROR] Can truyen IPv4 cua MacBook Server." >&2
  echo "        Vi du: sh scripts/deploy-https-macos.sh 192.168.2.10" >&2
  exit 1
fi

if ! printf '%s' "$server_ip" | awk -F. '
  NF != 4 { valid = 0; exit }
  {
    valid = 1
    for (i = 1; i <= 4; i++) {
      if ($i !~ /^[0-9]+$/ || $i > 255) valid = 0
    }
  }
  END { exit(valid ? 0 : 1) }
'; then
  echo "[ERROR] '$server_ip' khong phai IPv4 hop le." >&2
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  echo "[ERROR] Chua co Homebrew. Cai Homebrew truoc khi trien khai." >&2
  exit 1
fi

if ! command -v caddy >/dev/null 2>&1; then
  echo "[INFO] Dang cai Caddy qua Homebrew..."
  brew install caddy
fi

echo "[INFO] Cap nhat $hostname -> $server_ip trong /etc/hosts..."
hosts_tmp=$(mktemp)
trap 'rm -f "$hosts_tmp"' EXIT HUP INT TERM
sudo awk -v host="$hostname" '$2 != host { print }' /etc/hosts > "$hosts_tmp"
printf '%s %s\n' "$server_ip" "$hostname" >> "$hosts_tmp"
sudo cp "$hosts_tmp" /etc/hosts

cd "$project_root"
make stop
make run

ca_file="runtime/caddy-data/pki/authorities/local/root.crt"
attempt=1
while [ ! -f "$ca_file" ] && [ "$attempt" -le 10 ]; do
  sleep 1
  attempt=$((attempt + 1))
done

if [ ! -f "$ca_file" ]; then
  echo "[ERROR] Khong tim thay CA. Xem runtime/caddy.stderr.log" >&2
  exit 1
fi

cp "$ca_file" runtime/ztas-local-ca.crt
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain "$ca_file" >/dev/null 2>&1 || true

echo "[DONE] Dashboard: https://$hostname:8443/dashboard"
echo "[DONE] CA cho Ubuntu/Windows client: $project_root/runtime/ztas-local-ca.crt"
echo "[NEXT] Tren client, them '$server_ip $hostname' vao hosts va cai CA mot lan."
