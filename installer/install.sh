#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" != "0" ]]; then
  echo "[-] you do not have permissions"
  exit 1
fi

ROOTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOTDIR"

if ! command -v go >/dev/null 2>&1; then
  echo "[+] installing Go (golang-go) ..."
  apt-get update -y
  apt-get install -y golang-go
fi

if ! command -v git >/dev/null 2>&1; then
  echo "[!] git not found; continuing (not required to build from local source)."
fi

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

BIN="$TMPDIR/splo1t"

echo "[+] building splo1t..."
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$BIN" ./cmd/splo1t

install -m 0755 "$BIN" /usr/local/bin/splo1t

echo "[+] installed: /usr/local/bin/splo1t"
echo "[+] done"

