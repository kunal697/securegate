#!/usr/bin/env bash
# =============================================================================
# SecureGate – Start script
# =============================================================================
# Usage:
#   ./start_securegate.sh              # Start API only (loads securegate.env or .env)
#   ./start_securegate.sh --with-proxy # Start API in background, then MITM proxy
#
# Setup:
#   1. Copy securegate.env.example to securegate.env (or .env)
#   2. Edit securegate.env: set SECUREGATE_LLM_BACKEND, add GEMINI_API_KEY etc.
#   3. Activate venv if you use one: source .venv/bin/activate
#   4. Run: ./start_securegate.sh
# =============================================================================

set -e

# Project root = directory where this script lives
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

# Load credentials and config from securegate.env or .env
if [ -f "$ROOT/securegate.env" ]; then
  echo "Loading config from securegate.env"
  set -a
  # shellcheck source=/dev/null
  source "$ROOT/securegate.env"
  set +a
elif [ -f "$ROOT/.env" ]; then
  echo "Loading config from .env"
  set -a
  # shellcheck source=/dev/null
  source "$ROOT/.env"
  set +a
else
  echo "No securegate.env or .env found. Using defaults (see securegate.env.example)."
fi

# Ensure PYTHONPATH so securegate package is found
export PYTHONPATH="${PYTHONPATH:-}:$ROOT/src"
# Remove leading colon if present
export PYTHONPATH="${PYTHONPATH#:}"

# Server host/port (from env or default)
HOST="${SECUREGATE_HOST:-0.0.0.0}"
PORT="${SECUREGATE_PORT:-8000}"
PROXY_PORT="${SECUREGATE_PROXY_PORT:-8080}"

# Python and uvicorn (prefer venv)
VENV_ACTIVATE="$ROOT/.venv/bin/activate"
if [ -f "$VENV_ACTIVATE" ]; then
  # shellcheck source=/dev/null
  source "$VENV_ACTIVATE"
fi

UVICORN_CMD="${UVICORN_CMD:-uvicorn}"
PYTHON_CMD="${PYTHON_CMD:-python}"

# -----------------------------------------------------------------------------
# Start API only (default)
# -----------------------------------------------------------------------------
start_api() {
  echo "Starting SecureGate API on http://${HOST}:${PORT}"
  echo "  LITE_MODE=${SECUREGATE_LITE_MODE:-true}"
  echo "  DETECTORS=${SECUREGATE_DETECTORS:-pattern,prompt_injection,ner,semantic,llm_classifier}"
  echo "  LLM_BACKEND=${SECUREGATE_LLM_BACKEND:-local}"
  echo ""
  echo "Dashboard: http://${HOST}:${PORT}/dashboard"
  echo "Health:    http://${HOST}:${PORT}/health"
  echo ""
  exec "$PYTHON_CMD" -m uvicorn securegate.app:app --host "$HOST" --port "$PORT"
}

# -----------------------------------------------------------------------------
# Start API and proxy in SEPARATE Terminal windows (macOS) so you can see logs.
# -----------------------------------------------------------------------------
start_with_proxy_separate_terminals() {
  if [ "$(uname -s)" != "Darwin" ]; then
    echo "Separate terminals are supported on macOS only. Use --with-proxy-same for one terminal."
    start_with_proxy_same_terminal
    return
  fi
  ROOT_ESC=$(echo "$ROOT" | sed "s/'/'\\\\''/g")
  echo "Opening two Terminal windows: API and proxy (you'll see logs in each)."
  osascript -e "tell application \"Terminal\" to do script \"cd '$ROOT_ESC' && ./run_api_in_terminal.sh\""
  sleep 1
  osascript -e "tell application \"Terminal\" to do script \"cd '$ROOT_ESC' && ./run_proxy_in_terminal.sh\""
  echo "Done. API and proxy are running in separate windows. Close those windows to stop them."
}

# -----------------------------------------------------------------------------
# Start API in background, then MITM proxy in foreground (same terminal).
# Proxy runs from .venv-proxy to avoid bcrypt/passlib conflict with API venv.
# -----------------------------------------------------------------------------
start_with_proxy_same_terminal() {
  echo "Starting SecureGate API in background on http://${HOST}:${PORT}"
  "$PYTHON_CMD" -m uvicorn securegate.app:app --host "$HOST" --port "$PORT" &
  API_PID=$!
  echo "API PID: $API_PID"
  sleep 2
  echo "Starting MITM proxy on port ${PROXY_PORT} (forwarding to SecureGate at ${SECUREGATE_URL:-http://127.0.0.1:8000})"
  echo "Set system proxy to 127.0.0.1:${PROXY_PORT} and visit http://mitm.it to install the CA."
  echo ""
  trap 'kill $API_PID 2>/dev/null; echo "API stopped."' EXIT

  if [ -x "$ROOT/.venv-proxy/bin/mitmproxy" ]; then
    exec "$ROOT/.venv-proxy/bin/mitmproxy" -s "$ROOT/addon.py" --listen-port "$PROXY_PORT"
  fi
  if [ -f "$ROOT/.venv-proxy/bin/mitmproxy" ]; then
    exec "$ROOT/.venv-proxy/bin/mitmproxy" -s "$ROOT/addon.py" --listen-port "$PROXY_PORT"
  fi

  echo "No .venv-proxy found. Create it, then run again or use a second terminal:"
  echo "  python3 -m venv .venv-proxy && . .venv-proxy/bin/activate && pip install mitmproxy pyyaml requests"
  echo "  In a new terminal: ./start_proxy.sh"
  echo ""
  wait $API_PID
}

start_with_proxy() {
  # On macOS default to separate terminals so user can see logs; use --with-proxy-same for one terminal.
  if [ "$(uname -s)" = "Darwin" ] && [ "${SECUREGATE_PROXY_SAME_TERMINAL:-0}" != "1" ]; then
    start_with_proxy_separate_terminals
  else
    start_with_proxy_same_terminal
  fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
WITH_PROXY="${SECUREGATE_WITH_PROXY:-}"
WITH_PROXY="$([ "$WITH_PROXY" = "true" ] || [ "$WITH_PROXY" = "1" ] || [ "$WITH_PROXY" = "yes" ] && echo 1 || echo 0)"

case "${1:-}" in
  --with-proxy)
    start_with_proxy
    ;;
  --with-proxy-same)
    start_with_proxy_same_terminal
    ;;
  --no-proxy)
    start_api
    ;;
  --help|-h)
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "  (no args)          Start API; if SECUREGATE_WITH_PROXY=true in env, start with proxy."
    echo "  --with-proxy       Start API + proxy (on macOS: two separate Terminal windows for logs)."
    echo "  --with-proxy-same  Start API + proxy in one terminal."
    echo "  --no-proxy         Start API only (ignore SECUREGATE_WITH_PROXY)."
    echo "  --help             Show this help."
    echo ""
    echo "  SECUREGATE_PROXY_SAME_TERMINAL=1  Use one terminal when using --with-proxy (macOS)."
    echo "Config: securegate.env (set SECUREGATE_WITH_PROXY=true for proxy)."
    exit 0
    ;;
  *)
    if [ "$WITH_PROXY" = "1" ]; then
      start_with_proxy
    else
      start_api
    fi
    ;;
esac
