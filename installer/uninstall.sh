#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" != "0" ]]; then
  echo "[-] you do not have permissions"
  exit 1
fi

if [[ -x /usr/local/bin/splo1t ]]; then
  rm -f /usr/local/bin/splo1t
  echo "[+] removed /usr/local/bin/splo1t"
else
  echo "[i] /usr/local/bin/splo1t not present"
fi

