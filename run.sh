#!/usr/bin/env bash
# Convenience launcher: create venv, install deps, start monitor.
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
  echo "[setup] creating virtual environment..."
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
source .venv/bin/activate

echo "[setup] installing dependencies..."
pip install --quiet --disable-pip-version-check -r requirements.txt

echo "[run] launching Network Baseline Monitor..."
echo "[run] dashboard: http://127.0.0.1:5050/"
exec python main.py "$@"
