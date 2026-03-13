#!/bin/bash
# Run SecureGate MITM proxy (mitmproxy with addon)
# Requires: SecureGate API running on port 8000

cd "$(dirname "$0")"

# Prefer venv mitmproxy
if [ -f .venv/bin/mitmproxy ]; then
    MITM=".venv/bin/mitmproxy"
elif command -v mitmproxy &> /dev/null; then
    MITM="mitmproxy"
else
    echo "Install: pip install mitmproxy pyyaml requests"
    exit 1
fi

export SECUREGATE_URL="${SECUREGATE_URL:-http://127.0.0.1:8000}"
$MITM -s addon.py --listen-port 8080
