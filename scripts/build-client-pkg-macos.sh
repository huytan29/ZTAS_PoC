#!/usr/bin/env sh
set -eu

# Build the macOS client installer. Run this ON A MAC after make deploy-https.
# Optional signing: MACOS_INSTALLER_SIGN_IDENTITY='Developer ID Installer: ...' make client-pkg
project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ca_file="$project_root/runtime/ztas-local-ca.crt"
output_dir="$project_root/Client_PoC/Client"
output_pkg="$output_dir/CaiDat-ZTAS-macOS.pkg"
server_ip=${ZTAS_SERVER_IP:-}

if [ -z "$server_ip" ]; then
  echo '[ERROR] Can ZTAS_SERVER_IP. Vi du: make client-pkg ZTAS_SERVER_IP=192.168.2.10' >&2
  exit 2
fi
if [ ! -f "$ca_file" ]; then
  echo "[ERROR] Khong tim thay CA: $ca_file. Hay chay make deploy-https truoc." >&2
  exit 1
fi
command -v pkgbuild >/dev/null 2>&1 || { echo '[ERROR] Can pkgbuild (Xcode Command Line Tools).' >&2; exit 1; }

stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT HUP INT TERM
payload="$stage/payload/Library/Application Support/ZTAS"
scripts="$stage/scripts"
mkdir -p "$payload" "$scripts" "$output_dir"

cp "$ca_file" "$payload/ztas-local-ca.crt"
cp "$project_root/scripts/provision-client-macos.sh" "$payload/provision-client-macos.sh"
chmod 0755 "$payload/provision-client-macos.sh"
cat > "$scripts/postinstall" <<EOF
#!/bin/sh
exec sh '/Library/Application Support/ZTAS/provision-client-macos.sh' '$server_ip' '/Library/Application Support/ZTAS/ztas-local-ca.crt'
EOF
chmod 0755 "$scripts/postinstall"

unsigned="$stage/CaiDat-ZTAS-macOS-unsigned.pkg"
pkgbuild --root "$stage/payload" --scripts "$scripts" \
  --identifier "vn.ptit.ztas.client" --version "1.0.0" \
  --install-location / "$unsigned"

if [ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" ]; then
  command -v productsign >/dev/null 2>&1 || { echo '[ERROR] Khong tim thay productsign.' >&2; exit 1; }
  productsign --sign "$MACOS_INSTALLER_SIGN_IDENTITY" "$unsigned" "$output_pkg"
  echo '[DONE] Da tao PKG da ky Developer ID.'
else
  cp "$unsigned" "$output_pkg"
  echo '[WARN] PKG chua ky. Dung cho lab; end user se van gap Gatekeeper.'
fi
echo "[DONE] $output_pkg"
