#!/usr/bin/env bash
# Launch the GUI with root (needed for monitor mode / injection).
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -x .venv/bin/python ]]; then
  echo "Virtualenv missing. Run: ./setup.sh"
  echo "(Do not use system pip3 — Kali blocks it with externally-managed-environment.)"
  exit 1
fi

if ! .venv/bin/python -c "import customtkinter" 2>/dev/null; then
  echo "customtkinter not installed in .venv. Run: ./setup.sh"
  exit 1
fi

# Prefer sudo so airmon-ng works; fall back if already root.
if [[ "$(id -u)" -eq 0 ]]; then
  exec .venv/bin/python main.py "$@"
else
  exec sudo .venv/bin/python main.py "$@"
fi
