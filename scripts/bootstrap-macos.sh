#!/usr/bin/env sh
set -eu

# Bootstrap lan dau cho macOS. Dung: sh bootstrap-macos.sh [thu_muc_dich]
repository_url="https://github.com/huytan29/ZTAS_PoC.git"
repository_branch="main"
target_dir="${1:-$HOME/source/ZTAS_PoC}"

if ! command -v git >/dev/null 2>&1; then
  echo "[LOI] Chua tim thay Git. Cai Xcode Command Line Tools hoac Homebrew Git, roi chay lai." >&2
  exit 1
fi

if [ -e "$target_dir" ]; then
  echo "[DUNG] Thu muc dich da ton tai: $target_dir" >&2
  echo "       Script khong ghi de source da co. Hay chon thu muc trong hoac cap nhat repo thu cong." >&2
  exit 2
fi

parent_dir=$(dirname "$target_dir")
mkdir -p "$parent_dir"

echo "[1/2] Dang clone ZTAS PoC tu GitHub..."
git clone --origin origin --branch "$repository_branch" --single-branch "$repository_url" "$target_dir"

echo "[2/2] Da tai source thanh cong."
printf '\nThu muc du an: %s\n\n' "$target_dir"
echo "Buoc tiep theo:"
printf '  cd "%s"\n' "$target_dir"
echo "  brew install cmake cpp-httplib nlohmann-json openssl@3 sqlite"
echo "  make build"
echo "  make run"
echo
echo "Docker Desktop phai dang chay truoc khi dung make run."
