# SecureGate – Getting Started

Step-by-step guide to run SecureGate (API + MITM proxy).

---

## Important: Run from the project directory

All commands below must be run **from the SecureGate project folder** (where `src/`, `config/`, and `requirements.txt` are). If you run them from your home directory (`~`), you will get errors like `command not found: uvicorn` or `source: no such file or directory: .venv/bin/activate`.

**First, go to the project:**

```bash
cd /Users/kunalrajendrabodke/Work/securegate
```

(Or `cd path/to/your/securegate` if the project is elsewhere.)

---

## Prerequisites

- Python 3.9+
- Two virtual environments (one for API, one for proxy, due to dependency conflicts)

---

## 1. Create Virtual Environments

**Run these from the project root** (e.g. `/Users/kunalrajendrabodke/Work/securegate`):

```bash
cd /Users/kunalrajendrabodke/Work/securegate

# API venv (FastAPI + SecureGate)
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-lite.txt

# Proxy venv (mitmproxy only)
deactivate
python3 -m venv .venv-proxy
source .venv-proxy/bin/activate
pip install mitmproxy pyyaml requests
deactivate
```

---

## 2. Start SecureGate API

**Terminal 1 – API server (port 8000)**  
**Always `cd` to the project directory first.**

Using the start script (recommended; loads `securegate.env` and sets `PYTHONPATH`):

```bash
cd /Users/kunalrajendrabodke/Work/securegate
./start_securegate.sh --no-proxy
```

Or with venv and uvicorn directly:

```bash
cd /Users/kunalrajendrabodke/Work/securegate
source .venv/bin/activate
export PYTHONPATH=src
uvicorn securegate.app:app --host 0.0.0.0 --port 8000
```

Leave this running. You should see:

```
INFO:     Uvicorn running on http://0.0.0.0:8000
```

**Test the API:**

```bash
curl http://localhost:8000/health
curl -X POST http://localhost:8000/analyze -H "Content-Type: application/json" \
  -d '{"text":"My email is john@example.com"}'
```

---

## 3. Start API + proxy with one command (recommended on macOS)

**One command opens two Terminal windows** (API in one, proxy in the other) so you can see logs and errors from each:

```bash
cd /Users/kunalrajendrabodke/Work/securegate
./start_securegate.sh --with-proxy
```

Two windows will open: one running the API, one running the MITM proxy. Close either window to stop that process. To force one terminal instead, use `./start_securegate.sh --with-proxy-same`.

---

## 4. Start MITM proxy only (second terminal)

If you started the API with `--no-proxy`, run the proxy in a **new terminal** using the proxy venv (`.venv-proxy`) to avoid bcrypt/passlib conflicts:

Using the proxy script (recommended):

```bash
cd /Users/kunalrajendrabodke/Work/securegate
./start_proxy.sh
```

Or manually:

```bash
cd /Users/kunalrajendrabodke/Work/securegate
source .venv-proxy/bin/activate
mitmproxy -s addon.py --listen-port 8080
```

Leave this running.

---

## 5. Configure System Proxy (for MITM mode)

1. Open **http://mitm.it** in your browser.
2. Download and install the certificate for your OS.
3. Set system proxy:
   - **macOS**: System Settings → Network → Wi‑Fi → Details → Proxies
   - Enable **Web Proxy (HTTP)** and **Secure Web Proxy (HTTPS)**
   - Server: `127.0.0.1`, Port: `8080`

---

## 6. Test MITM Proxy

1. Visit **https://chat.openai.com** (or chatgpt.com).
2. Send: `My SSN is 123-45-6789`
3. You should see a block or masked behavior from SecureGate (not ChatGPT’s own warning).

**Filter OpenAI flows in mitmproxy:** Press `f`, type `~d openai`, Enter.

---

## Quick Reference

| Service       | Command                                         | Port |
|---------------|--------------------------------------------------|------|
| SecureGate API| `PYTHONPATH=src python run.py` (in .venv)        | 8000 |
| MITM Proxy    | `mitmproxy -s addon.py --listen-port 8080` (in .venv-proxy) | 8080 |

---

## Troubleshooting

**`command not found: uvicorn` or `source: no such file or directory: .venv/bin/activate`**

You are probably not in the SecureGate project directory. Do this:

```bash
cd /Users/kunalrajendrabodke/Work/securegate   # or your actual path to the securegate folder
pwd   # should show .../securegate
ls .venv/bin/activate   # should exist
source .venv/bin/activate
pip install uvicorn     # if uvicorn is still not found
export PYTHONPATH=src
uvicorn securegate.app:app --host 0.0.0.0 --port 8000
```

**Port already in use**

```bash
# Kill process on port 8000
kill $(lsof -t -i :8000)

# Or use a different port
PORT=8001 PYTHONPATH=src python run.py
```

**API fails after installing mitmproxy in .venv**

Use separate venvs (`.venv` for API, `.venv-proxy` for mitmproxy). Do not install mitmproxy in the API venv.

**ChatGPT requests not intercepted**

- Run mitmproxy with the addon: `mitmproxy -s addon.py --listen-port 8080`
- Ensure proxy is set to `127.0.0.1:8080`
- Check `config/protected_domains.yaml` includes `api.openai.com` and `chat.openai.com`
