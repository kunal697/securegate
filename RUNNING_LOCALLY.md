# Running SecureGate Locally

This guide explains how to configure and run SecureGate in two primary modes: **Server Mode** (CLI-based) and **Desktop Mode** (GUI-based).

---

## 1. Initial Configuration

Before starting, you must configure the application settings. All core configurations are managed via the `securegate.env` file in the root directory.

### Key Configuration Options:
*   **SECUREGATE_DETECTORS**: Choose which security engines to run.
    *   *Example:* `SECUREGATE_DETECTORS=pattern,ner,custom_llm,gliner`
*   **SECUREGATE_CUSTOM_MODEL_PATH**: If using the proprietary XGBoost model, specify the `.pkl` path.
*   **GEMINI_API_KEY**: Required if using the LLM Classifier backend.
*   **SECUREGATE_LITE_MODE**: Set to `true` to disable heavy ML models for faster performance.

**To apply changes:** Simply edit `securegate.env` and restart the application.

---

## 2. Mode A: Server Mode (CLI)

Ideal for shared environments (WiFi/LAN) or development debugging.

### Step 1: Start the Backend API
The API handles the text analysis and scoring.
```bash
# Set PYTHONPATH to include the src directory
export PYTHONPATH=src
# Start the FastAPI server
.venv/bin/python -m uvicorn securegate.app:app --host 0.0.0.0 --port 8000
```

### Step 2: Start the MITM Proxy
The proxy intercepts and masks AI traffic.
```bash
# Start mitmproxy with the SecureGate addon
.venv-proxy/bin/mitmdump -s addon.py --listen-port 8080
```

### Step 3: Connect Devices
*   **Local Browser:** Set your browser's HTTP proxy to `127.0.0.1:8080`.
*   **Other Devices (WiFi):** Find your machine's local IP (e.g., `192.168.1.5`). On the other device, set the proxy to `192.168.1.5:8080`.

---

## 3. Mode B: Desktop Mode (GUI)

Ideal for individual users wanting a one-click security solution.

### Step 1: Launch the Application
The Desktop app automatically manages the API and Proxy processes for you.
```bash
cd securegate-desktop
npm start
```

### Step 2: Usage
*   The application will launch an Electron window.
*   It automatically handles the MITM Certificate installation (on macOS/Linux).
*   You can monitor blocked and masked requests in real-time via the integrated Dashboard.

---

## 4. Applying Changes & Rebuilding

If you modify the core logic (Python) or the Dashboard UI (HTML/JS), follow these steps to apply them to the packaged Desktop application.

### A. Updating the Dashboard UI
If you make changes to the files in the root `dashboard/` folder, you need to sync them with the desktop application:
```bash
cd securegate-desktop
# This copies the root dashboard into the desktop backend folder
npm run prebuild
```

cp securegate.env securegate-desktop/securegate.env

### B. Packaging the Desktop App
To create a standalone `.dmg` or `.app` file for macOS after making changes:
```bash
cd securegate-desktop
# Build the final distributable package
npm run build
```
The output will be generated in the `securegate-desktop/dist/` directory.

### C. Updating Backend Logic
*   **In Server Mode:** Changes to Python files in `src/` or `addon.py` are reflected immediately upon restarting the respective processes (Uvicorn/Mitmdump).
*   **In Desktop Mode:** You must close the Electron app and run `npm start` again to reload the backend processes.

---

## 5. Verification
Once running, you can test the protection by sending a sensitive string to a protected AI platform (e.g., ChatGPT, Gemini, or Claude):

*   **Test String:** `"My AWS secret is AKIA1234567890EXAMPLE"`
*   **Result:** You should see an immediate **BLOCK** response in your browser or the sensitive part **MASKED** before it reaches the AI provider.
