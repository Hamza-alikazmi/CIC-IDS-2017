#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_DIR"

if [[ ! -x .venv/bin/python3 ]]; then
  python3 -m venv .venv
fi

.venv/bin/python3 -m pip install -r requirements.txt

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Packet capture requires elevated privileges."
  exec sudo -E .venv/bin/python3 server/server.py
fi

exec .venv/bin/python3 server/server.py
