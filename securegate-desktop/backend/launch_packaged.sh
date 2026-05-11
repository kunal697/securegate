#!/usr/bin/env bash
set -e

# This script is used when SecureGate is packaged into an Electron .app
# It creates the virtual environments in ~/.securegate/ so they are persistent and writeable.

APP_DATA="$HOME/.securegate"
mkdir -p "$APP_DATA"

cd "$(dirname "$0")"
BACKEND_DIR="$(pwd)"

VENV_API="$APP_DATA/.venv"
VENV_PROXY="$APP_DATA/.venv-proxy"

# Load environment variables if they exist (Check local first, then global)
if [ -f "$BACKEND_DIR/../securegate.env" ]; then
    echo "Loading environment variables from project directory..."
    export $(grep -v '^#' "$BACKEND_DIR/../securegate.env" | xargs)
elif [ -f "$APP_DATA/.env" ]; then
    echo "Loading environment variables from $APP_DATA/.env"
    export $(grep -v '^#' "$APP_DATA/.env" | xargs)
fi

# Bootstrap API venv
if [ ! -d "$VENV_API" ]; then
    echo "Creating API virtual environment..."
    python3 -m venv "$VENV_API"
    "$VENV_API/bin/pip" install -r "$BACKEND_DIR/requirements.txt"
    "$VENV_API/bin/pip" install gliner  # Install gliner by default
    "$VENV_API/bin/python" -m spacy download en_core_web_lg || true
fi

# Bootstrap Proxy venv
if [ ! -d "$VENV_PROXY" ]; then
    echo "Creating Proxy virtual environment..."
    python3 -m venv "$VENV_PROXY"
    "$VENV_PROXY/bin/pip" install mitmproxy pyyaml requests
fi

export PYTHONPATH="$BACKEND_DIR/src"
export SECUREGATE_PROXY_SAME_TERMINAL=1
export SECUREGATE_WITH_PROXY=true
export HOST=127.0.0.1
export PORT=8000
export PROXY_PORT=8080

# Start API in background
echo "Starting SecureGate API..."
"$VENV_API/bin/python" -m uvicorn securegate.app:app --host $HOST --port $PORT &
API_PID=$!
echo "API PID: $API_PID"

sleep 2

# Start Proxy in foreground
echo "Starting MITM Proxy..."
trap 'kill $API_PID 2>/dev/null; echo "API stopped."' EXIT
exec "$VENV_PROXY/bin/mitmdump" -s "$BACKEND_DIR/addon.py" --listen-port $PROXY_PORT
