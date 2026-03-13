"""FastAPI application."""

import logging
import os
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from typing import Optional

from securegate.audit import get_events, get_stats, log_analysis
from securegate.config import Settings
from securegate.models import Action, AnalysisRequest, AnalysisResult
from securegate.pipeline import Pipeline

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Reduce noise: dashboard polling and third-party INFO logs
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)  # GET /api/stats, /api/events
logging.getLogger("presidio-analyzer").setLevel(logging.WARNING)  # recognizer load, config defaults
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)  # device, batch progress
logging.getLogger("httpx").setLevel(logging.WARNING)  # HTTP Request lines
logging.getLogger("transformers").setLevel(logging.WARNING)  # Device set to use cpu, etc.
import warnings
warnings.filterwarnings("ignore", message=".*urllib3 v2 only supports OpenSSL.*", module="urllib3")

settings = Settings()


def _build_detectors() -> list:
    """Build detector list based on config."""
    from securegate.detectors import (
        LLMClassifier,
        NERDetector,
        PatternDetector,
        PromptInjectionDetector,
        SemanticAnalyzer,
    )
    from securegate.detectors import GLiNERDetector

    if settings.lite_mode:
        return [PatternDetector(), PromptInjectionDetector()]

    enabled = set(d.strip().lower() for d in settings.detectors.split(",") if d.strip())
    detectors = []
    if "pattern" in enabled:
        detectors.append(PatternDetector())
    if "prompt_injection" in enabled:
        detectors.append(PromptInjectionDetector())
    if "gliner" in enabled and GLiNERDetector is not None:
        try:
            detectors.append(GLiNERDetector())
        except Exception as e:
            logger.warning("GLiNER detector skipped (pip install -r requirements-gliner.txt): %s", e)
    if "ner" in enabled:
        try:
            detectors.append(NERDetector())
        except Exception as e:
            logger.warning("NER detector skipped: %s", e)
    if "semantic" in enabled:
        try:
            detectors.append(SemanticAnalyzer())
        except Exception as e:
            logger.warning("Semantic analyzer skipped: %s", e)
    if "llm_classifier" in enabled:
        try:
            detectors.append(LLMClassifier())
        except Exception as e:
            logger.warning("LLM classifier skipped: %s", e)

    return detectors or [PatternDetector(), PromptInjectionDetector()]


_pipeline = None  # type: Optional[Pipeline]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup: build pipeline. Shutdown: cleanup."""
    global _pipeline
    detectors = _build_detectors()
    _pipeline = Pipeline(detectors=detectors)
    logger.info("SecureGate started with %d detectors", len(detectors))
    yield
    _pipeline = None


app = FastAPI(
    title="SecureGate",
    description="Hybrid framework for real-time sensitive data leakage prevention",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict:
    """Health check."""
    return {"status": "ok", "service": "securegate"}


@app.post("/analyze", response_model=AnalysisResult)
async def analyze(req: AnalysisRequest) -> AnalysisResult:
    """Analyze text for sensitive data and return action."""
    if not _pipeline:
        raise HTTPException(status_code=503, detail="Pipeline not initialized")

    request_id = str(uuid.uuid4())
    result = await _pipeline.analyze(req)
    result.request_id = request_id

    log_analysis(
        request_id=request_id,
        user_id=req.user_id,
        session_id=req.session_id,
        result=result,
        text_preview=req.text[:100],
    )
    return result


@app.post("/analyze/text")
async def analyze_text(body: dict) -> dict:
    """Convenience endpoint: analyze plain text. Body: {"text": "..."}."""
    text = body.get("text", "")
    req = AnalysisRequest(text=text)
    result = await analyze(req)
    return result.model_dump()


# Optional: Chat proxy (requires OPENAI_API_KEY and full detectors)
@app.post("/chat")
async def chat(body: dict) -> dict:
    """Analyze user message, then proxy to LLM if allowed. Body: {"messages": [...], "model": "gpt-4o-mini"}."""
    messages = body.get("messages", [])
    model = body.get("model", "gpt-4o-mini")
    if not messages:
        raise HTTPException(status_code=400, detail="messages required")

    last_msg = messages[-1] if messages else {}
    user_content = last_msg.get("content", "") if last_msg.get("role") == "user" else ""

    req = AnalysisRequest(text=user_content)
    result = await analyze(req)

    if result.action == Action.BLOCK or result.action == Action.QUARANTINE:
        return {
            "blocked": True,
            "action": result.action.value,
            "reason": result.reasoning,
            "response": None,
        }

    text_to_send = result.masked_text if result.masked_text else user_content
    if result.action == Action.MASK and result.masked_text:
        new_messages = messages[:-1] + [{"role": "user", "content": text_to_send}]
    else:
        new_messages = messages

    try:
        from securegate.llm_proxy import ChatMessage
        from securegate.llm_client import get_chat_proxy

        proxy = get_chat_proxy(
            settings.llm_backend,
            gemini_api_key=settings.gemini_api_key,
            llm_base_url=settings.llm_base_url,
            llm_api_key=settings.llm_api_key,
            llm_model=settings.llm_model,
            openai_api_key=os.environ.get("OPENAI_API_KEY", ""),
        )
        chat_msgs = [ChatMessage(role=m.get("role", "user"), content=m.get("content", "")) for m in new_messages]
        llm_resp = await proxy.chat(chat_msgs, model=model or settings.llm_model)
        return {
            "blocked": False,
            "action": result.action.value,
            "response": llm_resp.content,
            "model": llm_resp.model,
        }
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"LLM proxy error: {str(e)}")


# Dashboard API
@app.get("/api/stats")
async def api_stats(hours: int = 24) -> dict:
    """Get aggregated analytics for dashboard."""
    return get_stats(hours=hours)


@app.get("/api/events")
async def api_events(limit: int = 100) -> list:
    """Get recent audit events."""
    return get_events(limit=limit)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard() -> HTMLResponse:
    """Serve dashboard HTML."""
    html_path = Path(__file__).resolve().parent.parent.parent / "dashboard" / "index.html"
    if html_path.exists():
        return HTMLResponse(content=html_path.read_text())
    return HTMLResponse(content=_dashboard_html(), status_code=200)


def _dashboard_html() -> str:
    """Inline dashboard HTML fallback."""
    return """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>SecureGate Dashboard</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body class="bg-slate-900 text-slate-100 min-h-screen p-6">
  <div class="max-w-7xl mx-auto">
    <h1 class="text-2xl font-bold mb-6">SecureGate Dashboard</h1>
    <div class="grid grid-cols-1 md:grid-cols-5 gap-4 mb-8">
      <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <div class="text-slate-400 text-sm">Total (24h)</div>
        <div id="total" class="text-2xl font-semibold">-</div>
      </div>
      <div class="bg-slate-800 rounded-lg p-4 border border-red-900/50">
        <div class="text-red-400 text-sm">Blocked</div>
        <div id="blocked" class="text-2xl font-semibold text-red-400">-</div>
      </div>
      <div class="bg-slate-800 rounded-lg p-4 border border-violet-900/50">
        <div class="text-violet-400 text-sm">Quarantined</div>
        <div id="quarantined" class="text-2xl font-semibold text-violet-400">-</div>
      </div>
      <div class="bg-slate-800 rounded-lg p-4 border border-amber-900/50">
        <div class="text-amber-400 text-sm">Masked</div>
        <div id="masked" class="text-2xl font-semibold text-amber-400">-</div>
      </div>
      <div class="bg-slate-800 rounded-lg p-4 border border-emerald-900/50">
        <div class="text-emerald-400 text-sm">Allowed</div>
        <div id="allowed" class="text-2xl font-semibold text-emerald-400">-</div>
      </div>
    </div>
    <div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
      <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <h2 class="text-lg font-semibold mb-4">By Action</h2>
        <canvas id="chartActions" height="200"></canvas>
      </div>
      <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
        <h2 class="text-lg font-semibold mb-4">By Category</h2>
        <canvas id="chartCategory" height="200"></canvas>
      </div>
    </div>
    <div class="bg-slate-800 rounded-lg p-4 border border-slate-700">
      <h2 class="text-lg font-semibold mb-4">Recent Events <span class="text-slate-500 text-sm font-normal">(click for details)</span></h2>
      <div id="events" class="overflow-x-auto max-h-96 overflow-y-auto">
        <p class="text-slate-500">Loading...</p>
      </div>
      <div id="eventDetail" class="mt-4 p-4 bg-slate-900 rounded-lg border border-slate-600 hidden">
        <h3 class="font-semibold mb-2 text-cyan-400">Request details</h3>
        <div id="eventDetailContent"></div>
      </div>
    </div>
  </div>
  <script>
    const API = window.location.origin;
    let chartActions, chartCategory;
    let eventsData = [];
    function renderDetectorTable(detectors) {
      if (!detectors || !detectors.length) return '<p class="text-slate-500 text-sm">No detector breakdown</p>';
      const rows = detectors.map(d => `
        <tr class="border-b border-slate-700">
          <td class="py-2 pr-4 font-mono text-sm">${d.detector_name || '-'}</td>
          <td class="py-2 pr-4"><span class="px-2 py-0.5 rounded text-xs ${d.detected ? 'bg-amber-900/50 text-amber-400' : 'bg-slate-700 text-slate-400'}">${d.detected ? 'Yes' : 'No'}</span></td>
          <td class="py-2 pr-4 text-slate-300">${d.confidence ?? '-'}</td>
          <td class="py-2 pr-4 text-slate-400">${d.category || '-'}</td>
          <td class="py-2 text-slate-400">${d.entity_count ?? 0}</td>
        </tr>
      `).join('');
      return '<table class="w-full text-sm"><thead><tr class="text-left text-slate-500"><th>Detector</th><th>Detected</th><th>Confidence</th><th>Category</th><th>Entities</th></tr></thead><tbody>' + rows + '</tbody></table>';
    }
    function actionClass(a) {
      if (a === 'Block') return 'text-red-400';
      if (a === 'Quarantine') return 'text-violet-400';
      if (a === 'Mask') return 'text-amber-400';
      return 'text-emerald-400';
    }
    function showDetail(e) {
      const el = document.getElementById('eventDetail');
      const content = document.getElementById('eventDetailContent');
      const dr = renderDetectorTable(e.detector_results || []);
      content.innerHTML = `
        <div class="grid grid-cols-2 gap-2 text-sm mb-4">
          <div><span class="text-slate-500">Action:</span> <span class="${actionClass(e.action)} font-medium">${e.action || '-'}</span></div>
          <div><span class="text-slate-500">Category:</span> ${e.category || '-'}</div>
          <div><span class="text-slate-500">Score:</span> ${e.score ?? '-'}</div>
          <div><span class="text-slate-500">Entities:</span> ${e.entity_count ?? 0}</div>
        </div>
        <div class="text-sm mb-4"><span class="text-slate-500">Reasoning:</span> <span class="text-slate-300">${(e.reasoning || '-').replace(/</g,'&lt;')}</span></div>
        <div class="text-sm mb-4"><span class="text-slate-500">Text preview:</span> <span class="text-slate-400">${(e.text_preview || '-').replace(/</g,'&lt;')}</span></div>
        <div class="mb-2 text-slate-500 text-sm font-medium">Detector breakdown (all methodologies)</div>
        ${dr}
      `;
      el.classList.remove('hidden');
    }
    async function load() {
      const [stats, events] = await Promise.all([
        fetch(API + '/api/stats').then(r => r.json()),
        fetch(API + '/api/events?limit=50').then(r => r.json())
      ]);
      eventsData = events;
      document.getElementById('total').textContent = stats.total;
      document.getElementById('blocked').textContent = stats.blocked;
      document.getElementById('quarantined').textContent = stats.quarantined ?? 0;
      document.getElementById('masked').textContent = stats.masked;
      document.getElementById('allowed').textContent = stats.allowed;
      const byAction = stats.by_action || {};
      const byCategory = stats.by_category || {};
      const actionColors = { Block: '#ef4444', Quarantine: '#8b5cf6', Mask: '#f59e0b', Allow: '#22c55e' };
      const actionOrder = ['Block','Quarantine','Mask','Allow'];
      const labels = actionOrder.filter(l => byAction[l] !== undefined && byAction[l] > 0).length ? actionOrder.filter(l => (byAction[l] || 0) > 0) : Object.keys(byAction);
      const data = labels.map(l => byAction[l] || 0);
      const colors = labels.map(l => actionColors[l] || '#64748b');
      if (chartActions) chartActions.destroy();
      chartActions = new Chart(document.getElementById('chartActions'), {
        type: 'doughnut',
        data: {
          labels: labels,
          datasets: [{ data: data, backgroundColor: colors }]
        },
        options: { plugins: { legend: { labels: { color: '#94a3b8' } } } }
      });
      if (chartCategory) chartCategory.destroy();
      chartCategory = new Chart(document.getElementById('chartCategory'), {
        type: 'bar',
        data: {
          labels: Object.keys(byCategory),
          datasets: [{ label: 'Count', data: Object.values(byCategory), backgroundColor: '#3b82f6' }]
        },
        options: { scales: { y: { ticks: { color: '#94a3b8' } }, x: { ticks: { color: '#94a3b8' } } } }
      });
      const html = events.length ? events.map((e, i) => {
        const act = e.action || '-';
        const cls = act === 'Block' ? 'text-red-400' : act === 'Quarantine' ? 'text-violet-400' : act === 'Mask' ? 'text-amber-400' : 'text-emerald-400';
        return '<div class="flex justify-between py-2 border-b border-slate-700 text-sm cursor-pointer hover:bg-slate-700/50 rounded px-2 -mx-2" onclick="showDetail(eventsData[' + i + '])" data-i="' + i + '"><span class="' + cls + ' font-medium">' + act + '</span><span>' + (e.category || '-') + '</span><span>score ' + (e.score ?? '-') + '</span><span class="text-slate-500">' + (e.ts || '').replace('T',' ').slice(0,19) + '</span></div>';
      }).join('') : '<p class="text-slate-500">No events yet.</p>';
      document.getElementById('events').innerHTML = html;
    }
    load();
    setInterval(load, 10000);
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("securegate.app:app", host="0.0.0.0", port=8000, reload=True)
