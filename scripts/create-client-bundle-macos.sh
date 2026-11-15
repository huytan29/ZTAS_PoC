#!/usr/bin/env sh
set -eu

# Create an unpacked, no-argument client installer folder from a macOS ZTAS server.
# Usage: sh create-client-bundle-macos.sh <server-ip> [--use-dns]

server_ip=${1:-}
dns_mode=${2:-}
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
bundle_dir="$project_root/Client_PoC"
launcher_dir="$bundle_dir/Client"
ca_file="$project_root/runtime/ztas-local-ca.crt"

usage() {
  echo "Usage: $0 <server-ip> [--use-dns]" >&2
  echo "Example: sh $0 192.168.2.10" >&2
  exit 2
}

[ -n "$server_ip" ] || usage
[ -z "$dns_mode" ] || [ "$dns_mode" = '--use-dns' ] || usage

if ! printf '%s' "$server_ip" | awk -F. '
  NF != 4 { valid = 0; exit }
  { valid = 1; for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) valid = 0 }
  END { exit(valid ? 0 : 1) }
'; then
  echo "[ERROR] '$server_ip' khong phai IPv4 hop le." >&2
  exit 1
fi

if [ ! -f "$ca_file" ]; then
  echo "[ERROR] Chua co $ca_file." >&2
  echo "[NEXT] Chay make deploy-https ZTAS_SERVER_IP=$server_ip truoc." >&2
  exit 1
fi

rm -rf "$bundle_dir"
mkdir -p "$bundle_dir"
mkdir -p "$launcher_dir"
cp "$ca_file" "$bundle_dir/ztas-local-ca.crt"
cp "$project_root/scripts/provision-client-windows.cmd" "$bundle_dir/"
cp "$project_root/scripts/provision-client-ubuntu.sh" "$bundle_dir/"
cp "$project_root/scripts/provision-client-macos.sh" "$bundle_dir/"
cp "$project_root/scripts/install-client-windows.cmd" "$launcher_dir/CAI-ZTAS-Windows.cmd"
cp "$project_root/scripts/install-client-ubuntu.sh" "$launcher_dir/CAI-ZTAS-Ubuntu.sh"
cp "$project_root/scripts/install-client-macos.command" "$launcher_dir/CAI-ZTAS-macOS.command"
chmod 0755 "$launcher_dir/CAI-ZTAS-Ubuntu.sh" "$launcher_dir/CAI-ZTAS-macOS.command"

cat > "$bundle_dir/ztas-client-config.cmd" <<EOF
set "ZTAS_SERVER_IP=$server_ip"
set "ZTAS_DNS_MODE=$dns_mode"
EOF
cat > "$bundle_dir/ztas-client-config.sh" <<EOF
ZTAS_SERVER_IP='$server_ip'
ZTAS_DNS_MODE='$dns_mode'
EOF

echo "[DONE] Thu muc cai dat: $bundle_dir"
echo '[ADMIN] Chia se/chep NGUYEN thu muc nay qua SMB, VMware Shared Folder, USB quan tri hoac MDM.'
echo '[USER] Windows: double-click CAI-ZTAS-Windows.cmd va chap nhan UAC.'
echo '[USER] Ubuntu: double-click/run CAI-ZTAS-Ubuntu.sh, nhap mat khau he thong.'
echo '[USER] macOS: double-click CAI-ZTAS-macOS.command, nhap mat khau he thong.'
