# Start SecureGate Locally

## Prerequisites

Two terminals. Both services must run at the same time.

---

## Terminal 1: SecureGate API

```bash
cd /Users/kunalrajendrabodke/Work/securegate
source .venv/bin/activate
PYTHONPATH=src python run.py
```

Wait until you see: `Uvicorn running on http://0.0.0.0:8000`

---

## Terminal 2: MITM Proxy

```bash
cd /Users/kunalrajendrabodke/Work/securegate
source .venv-proxy/bin/activate
mitmproxy -s addon.py --listen-port 8080
```

Wait until you see: `HTTP(S) proxy listening at *:8080`

---

## Use It

1. Set your system proxy to `127.0.0.1:8080` (System Settings → Network → Proxies).
2. Open ChatGPT and send a message. Traffic goes through SecureGate.
3. To stop: press Ctrl+C in each terminal.

---

## Dashboard

Open **http://localhost:8000/dashboard** to see:
- Blocked, Masked, Allowed request counts
- Analytics by action and category
- Recent events table

---

## Quick Check

| Service  | URL                    | Status   |
|----------|------------------------|----------|
| API      | http://localhost:8000/health | Should return `{"status":"ok"}` |
| Dashboard| http://localhost:8000/dashboard | Analytics & recent events |
| Proxy    | Port 8080              | Listens for browser traffic   |
