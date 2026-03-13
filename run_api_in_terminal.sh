#!/usr/bin/env bash
# Run the SecureGate API in this terminal (for use when launched in a separate window).
# Keeps the window open on exit so you can see logs/errors.

set -e
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

if [ -f "$ROOT/securegate.env" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$ROOT/securegate.env"
  set +a
elif [ -f "$ROOT/.env" ]; then
  set -a
  # shellcheck source=/dev/null
  source "$ROOT/.env"
  set +a
fi

export PYTHONPATH="${PYTHONPATH:-}:$ROOT/src"
export PYTHONPATH="${PYTHONPATH#:}"

HOST="${SECUREGATE_HOST:-0.0.0.0}"
PORT="${SECUREGATE_PORT:-8000}"

if [ -f "$ROOT/.venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "$ROOT/.venv/bin/activate"
fi

echo "SecureGate API — http://${HOST}:${PORT}"
echo "Dashboard: http://${HOST}:${PORT}/dashboard"
echo ""

if ! python -m uvicorn securegate.app:app --host "$HOST" --port "$PORT"; then
  echo ""
  echo "API exited with an error. Press Enter to close."
  read -r
else
  echo ""
  echo "API stopped. Press Enter to close."
  read -r
fi
