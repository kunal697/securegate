#!/usr/bin/env bash
# =============================================================================
# Run this in a NEW TERMINAL to start the MITM proxy (use .venv-proxy to avoid
# dependency conflicts with the API venv).
# =============================================================================
# Terminal 1: ./start_securegate.sh --no-proxy   (or set SECUREGATE_WITH_PROXY=false)
# Terminal 2: ./start_proxy.sh
# =============================================================================

set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Load config
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

PROXY_PORT="${SECUREGATE_PROXY_PORT:-8080}"

# Use proxy venv to avoid bcrypt/passlib conflict with API venv
if [ -f "$ROOT/.venv-proxy/bin/mitmproxy" ]; then
  echo "Using .venv-proxy for mitmproxy"
  exec "$ROOT/.venv-proxy/bin/mitmproxy" -s "$ROOT/addon.py" --listen-port "$PROXY_PORT"
fi

if [ -f "$ROOT/.venv-proxy/bin/activate" ]; then
  # shellcheck source=/dev/null
  source "$ROOT/.venv-proxy/bin/activate"
  exec mitmproxy -s "$ROOT/addon.py" --listen-port "$PROXY_PORT"
fi

echo "No .venv-proxy found. Create it to avoid dependency conflicts:"
echo "  python3 -m venv .venv-proxy"
echo "  source .venv-proxy/bin/activate"
echo "  pip install mitmproxy pyyaml requests"
echo ""
echo "Trying current env (may fail with bcrypt error)..."
exec mitmproxy -s "$ROOT/addon.py" --listen-port "$PROXY_PORT"
