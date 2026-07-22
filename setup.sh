#!/usr/bin/env bash
# Create .venv and install Python deps (Kali PEP 668 safe).
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null; then
  echo "python3 not found. Install: sudo apt install -y python3 python3-venv"
  exit 1
fi

if [[ ! -d .venv ]]; then
  echo "Creating virtual environment in .venv ..."
  python3 -m venv .venv
fi

echo "Installing dependencies ..."
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt

echo
echo "Done. Run with:"
echo "  ./run.sh"
echo "or:"
echo "  sudo .venv/bin/python main.py"
