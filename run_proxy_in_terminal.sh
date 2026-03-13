#!/usr/bin/env bash
# Run the MITM proxy in this terminal (for use when launched in a separate window).
# Uses .venv-proxy. Keeps the window open on exit so you can see logs/errors.

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

PROXY_PORT="${SECUREGATE_PROXY_PORT:-8080}"

echo "SecureGate MITM proxy — port ${PROXY_PORT}"
echo "Set system proxy to 127.0.0.1:${PROXY_PORT} and visit http://mitm.it to install the CA."
echo ""

if [ -x "$ROOT/.venv-proxy/bin/mitmproxy" ]; then
  RUN="$ROOT/.venv-proxy/bin/mitmproxy"
elif [ -f "$ROOT/.venv-proxy/bin/mitmproxy" ]; then
  RUN="$ROOT/.venv-proxy/bin/mitmproxy"
else
  echo "No .venv-proxy found. Create it:"
  echo "  python3 -m venv .venv-proxy && . .venv-proxy/bin/activate && pip install mitmproxy pyyaml requests"
  echo ""
  echo "Press Enter to close."
  read -r
  exit 1
fi

if ! "$RUN" -s "$ROOT/addon.py" --listen-port "$PROXY_PORT"; then
  echo ""
  echo "Proxy exited with an error. Press Enter to close."
  read -r
else
  echo ""
  echo "Proxy stopped. Press Enter to close."
  read -r
fi
