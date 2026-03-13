# SecureGate

**Securing Generative AI Interactions: A Hybrid Framework for Real-Time Sensitive Data Leakage Prevention**

SecureGate is an intermediary security layer between users and AI models that detects, analyzes, and prevents sensitive data leakage during real-time interactions.

## Features

- **Hybrid Detection**: Pattern (regex), NER (Presidio/spaCy), Semantic (embeddings), LLM zero-shot, Prompt injection
- **No API keys for detectors**: All detectors (including the “LLM classifier”) run locally. If you have not installed `transformers` and `torch`, the LLM classifier is still listed but does not run the model; it will always report "No" / Safe in the dashboard (the other four detectors work as usual). The LLM classifier uses Hugging Face’s BART-MNLI model on your machine—no OpenAI/Claude or other cloud LLM credentials required.
- **Policy-driven**: Configurable category–action mapping and thresholds
- **Actions**: Allow, Mask, Block, Quarantine
- **Explainable**: Traceable reasoning and entity spans

## Quick Start

> **Quick start both services:** see **[START.md](START.md)**.  
> Full setup (venvs, proxy config): see **[GETTING_STARTED.md](GETTING_STARTED.md)**.

### Start from one config file (recommended)

Use a single env file for all options and credentials, then start the app:

1. **Copy the example and add your settings/creds:**
   ```bash
   cp securegate.env.example securegate.env
   # Edit securegate.env: set SECUREGATE_LLM_BACKEND (local | gemini | self_hosted),
   # add GEMINI_API_KEY if using Gemini, choose detectors, etc.
   ```

2. **Start the API:**
   ```bash
   source .venv/bin/activate   # if you use a venv
   ./start_securegate.sh
   ```

3. **Optional – start API + MITM proxy together:**
   ```bash
   ./start_securegate.sh --with-proxy
   ```

The script loads **securegate.env** (or **.env**) and starts the SecureGate API. All options (which detectors, which LLM, ports) are documented in **securegate.env.example**. Do not commit **securegate.env** or **.env**; they are gitignored.

### 1. Create virtual environment

```bash
cd securegate
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
```

### 2. Install dependencies

**Lite mode** (pattern + prompt injection only, no heavy ML):

```bash
pip install fastapi uvicorn pydantic pydantic-settings
```

**Full mode** (all detectors):

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 3. Run the server

```bash
# From project root, with PYTHONPATH
export PYTHONPATH=src
export SECUREGATE_LITE_MODE=true
uvicorn securegate.app:app --reload --host 0.0.0.0 --port 8000

# Or use the run script
PYTHONPATH=src python run.py
```

### 4. Test

```bash
# Health check
curl http://localhost:8000/health

# Analyze text
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"text": "My email is john@example.com and my SSN is 123-45-6789"}'

# Run unit and integration tests (from project root)
pip install pytest  # if not already installed
PYTHONPATH=src pytest tests/ -v

# Run tests for one methodology only (pattern, prompt_injection, ner, semantic, llm_classifier)
PYTHONPATH=src pytest tests/test_methodology_pattern.py -v
PYTHONPATH=src pytest tests/test_methodology_prompt_injection.py -v
PYTHONPATH=src pytest tests/test_methodology_ner.py -v
PYTHONPATH=src pytest tests/test_methodology_semantic.py -v
PYTHONPATH=src pytest tests/test_methodology_llm_classifier.py -v
```

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/analyze` | Analyze text (body: `AnalysisRequest`) |
| POST | `/analyze/text` | Analyze text (body: `{"text": "..."}`) |
| GET | `/dashboard` | Analytics dashboard (Block/Quarantine/Mask/Allow, by category, detector breakdown) |
| GET | `/api/stats` | Stats JSON (total, blocked, quarantined, masked, allowed, by_action, by_category) |
| GET | `/api/events` | Recent audit events JSON |

## Project Structure

```
securegate/
├── src/securegate/          # Core API
│   ├── app.py
│   ├── pipeline.py
│   └── detectors/
├── config/
│   └── protected_domains.yaml   # Domains to inspect (MITM)
├── proxy/                       # MITM addon (alternative)
│   ├── securegate_addon.py
│   └── prompt_extractors.py
├── addon.py                     # Standalone mitmproxy addon
├── run.py                       # Run API server
├── run_proxy.sh                 # Run MITM proxy
├── tests/                        # Unit and integration tests per detector
├── requirements.txt
└── requirements-proxy.txt       # mitmproxy, pyyaml, requests
```

## System-Wide MITM Proxy (intercept AI traffic)

SecureGate can intercept all AI API requests from your device (ChatGPT, Gemini, Claude, etc.) when configured as a system proxy.

### Setup

1. **Install proxy dependencies**

   ```bash
   pip install mitmproxy pyyaml requests
   ```

2. **Run SecureGate API** (Terminal 1)

   ```bash
   PYTHONPATH=src SECUREGATE_LITE_MODE=true python run.py
   ```

3. **Run the MITM proxy** (Terminal 2)

   ```bash
   mitmproxy -s addon.py --listen-port 8080
   # Or: bash run_proxy.sh
   ```

4. **Install mitmproxy CA certificate**

   - With mitmproxy running, open http://mitm.it in your browser
   - Download and install the certificate for your OS
   - On macOS: open the .pem, add to Keychain, mark as trusted

5. **Configure system proxy**

   - **macOS**: System Settings → Network → Proxy → Web Proxy (HTTP) and Secure Web Proxy (HTTPS) → `127.0.0.1`, port `8080`
   - Or use a per-browser proxy extension (FoxyProxy, etc.) to toggle when needed

6. **Add/remove protected domains** in `config/protected_domains.yaml`:

   ```yaml
   protected_domains:
     - api.openai.com
     - api.anthropic.com
     - generativelanguage.googleapis.com
     # Add more AI API domains as needed
   ```

### Flow

- Traffic to protected domains → SecureGate analyzes the prompt → **Block** (403) or **Mask** (replace PII) or **Allow**
- Traffic to other domains → forwarded without inspection

## Detector dependencies (when not in lite mode)

| Detector | Dependencies | If missing |
|----------|---------------|------------|
| **pattern** | None | Always works. |
| **prompt_injection** | None | Always works. |
| **ner** | `presidio-analyzer`, `spacy`, and `python -m spacy download en_core_web_lg` | Still listed; each request returns No/Safe for that row (no crash). |
| **semantic** | `sentence-transformers` | Still listed; each request returns No/Safe for that row (no crash). |
| **llm_classifier** | `transformers`, `torch` | Still listed; each request returns No/Safe for that row (no crash). |

So with a minimal install (e.g. only `requirements-lite.txt`), you can run with all five detectors enabled: pattern and prompt_injection do real work; NER, semantic, and llm_classifier will show No/0 until you install their dependencies. No API keys are required for any detector; NER, semantic, and LLM classifier use local models only.

### Run NER + Semantic without the LLM classifier

The LLM classifier (BART-MNLI) is the heaviest detector and needs more RAM/CPU. You can run **pattern, prompt_injection, NER, and semantic** only—no LLM classifier—so NER and Semantic work on a typical 8GB RAM machine:

```bash
export SECUREGATE_LITE_MODE=false
export SECUREGATE_DETECTORS=pattern,prompt_injection,ner,semantic
uvicorn securegate.app:app --host 0.0.0.0 --port 8000
```

Install only what these need (no `transformers`/`torch`):

```bash
pip install presidio-analyzer spacy sentence-transformers
python -m spacy download en_core_web_sm
```

Use **en_core_web_sm** (small) for NER if you want lower RAM; use **en_core_web_lg** (large) for slightly better accuracy. Set the model with:

```bash
export SECUREGATE_SPACY_MODEL=en_core_web_sm
```

### Resource requirements (rough guide)

| Setup | RAM | Notes |
|-------|-----|--------|
| **Lite** (pattern + prompt_injection) | &lt; 100 MB | No extra models. |
| **NER** (Presidio + spaCy) | ~200–500 MB with **en_core_web_sm**, ~1–1.5 GB with **en_core_web_lg** | 8 GB total RAM is enough. |
| **Semantic** (SentenceTransformer MiniLM) | ~200–400 MB | Lightweight; 8 GB is enough. |
| **NER + Semantic** (no LLM classifier) | ~500 MB–2 GB depending on NER model | **8 GB RAM is typically enough.** |
| **LLM classifier** (BART-MNLI) | 2 GB+ | Heaviest; skip it on low-resource PCs. |

So **yes, you can run NER and Semantic on an 8 GB machine**; they do not need more than 8 GB. Only the LLM classifier is demanding. Use `SECUREGATE_DETECTORS=pattern,prompt_injection,ner,semantic` and (optionally) `SECUREGATE_SPACY_MODEL=en_core_web_sm` for a lighter NER.

### Pluggable LLM backend (one service, Gemini or self-hosted)

One SecureGate service can use either a **cloud LLM API** (e.g. Gemini) or your **self-hosted LLM**. Set `SECUREGATE_LLM_BACKEND` and the matching credentials; both the **LLM classifier** detector and the **/chat** endpoint use this backend.

| Backend | Use case | What you set |
|---------|----------|----------------|
| **local** (default) | BART model on your machine for classifier; OpenAI for chat | Nothing, or `SECUREGATE_LLM_BACKEND=local`. For chat, set `OPENAI_API_KEY`. |
| **gemini** | Testing / cloud: classifier + chat via Google Gemini | `SECUREGATE_LLM_BACKEND=gemini`, `GEMINI_API_KEY=your_key`. Optional: `SECUREGATE_LLM_MODEL=gemini-1.5-flash`. |
| **self_hosted** | Your own LLM (Ollama, vLLM, or any OpenAI-compatible API) | `SECUREGATE_LLM_BACKEND=self_hosted`, `SECUREGATE_LLM_BASE_URL=https://your-server/v1`, `SECUREGATE_LLM_API_KEY=your_key`. Optional: `SECUREGATE_LLM_MODEL=your-model`. |

**Example – use Gemini for testing (no local BART, no OpenAI key):**

```bash
export SECUREGATE_LITE_MODE=false
export SECUREGATE_LLM_BACKEND=gemini
export GEMINI_API_KEY=your_gemini_api_key
uvicorn securegate.app:app --host 0.0.0.0 --port 8000
```

**Example – use your self-hosted LLM later:**

```bash
export SECUREGATE_LLM_BACKEND=self_hosted
export SECUREGATE_LLM_BASE_URL=https://your-llm.example.com/v1
export SECUREGATE_LLM_API_KEY=your_api_key
uvicorn securegate.app:app --host 0.0.0.0 --port 8000
```

Classifier and chat both use the selected backend; you can switch by changing env vars and restarting.

## Configuration

| Env var | Default | Description |
|---------|---------|-------------|
| `SECUREGATE_LITE_MODE` | `true` | Use only pattern + prompt_injection |
| `SECUREGATE_DETECTORS` | `pattern,prompt_injection,ner,...` | Comma-separated detector names. Omit `llm_classifier` to skip the heavy model. |
| `SECUREGATE_SPACY_MODEL` | `en_core_web_lg` | spaCy model for NER. Use `en_core_web_sm` for lower RAM (~12 MB model). |
| `SECUREGATE_LLM_BACKEND` | `local` | LLM for classifier + chat: `local` \| `gemini` \| `self_hosted` |
| `GEMINI_API_KEY` | — | Required when `SECUREGATE_LLM_BACKEND=gemini`. Get key at [aistudio.google.com](https://aistudio.google.com/app/apikey). |
| `SECUREGATE_LLM_BASE_URL` | — | Required when `self_hosted`. Base URL of your LLM (e.g. `https://your-llm/v1`). |
| `SECUREGATE_LLM_API_KEY` | — | API key for self-hosted (or use `OPENAI_API_KEY`). |
| `SECUREGATE_LLM_MODEL` | `gemini-1.5-flash` | Model name for gemini/self_hosted. |
| `SECUREGATE_URL` | `http://127.0.0.1:8000` | SecureGate API URL (for MITM proxy) |
