"""
Pluggable LLM backend: one service, choose Gemini API or self-hosted via config.

- SECUREGATE_LLM_BACKEND=local  -> classifier uses local BART; chat uses OPENAI_API_KEY
- SECUREGATE_LLM_BACKEND=gemini  -> classifier + chat use Gemini (GEMINI_API_KEY)
- SECUREGATE_LLM_BACKEND=self_hosted -> classifier + chat use your URL (SECUREGATE_LLM_BASE_URL + SECUREGATE_LLM_API_KEY)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from typing import Any, Optional, Tuple

# Retry on rate limit (429) or temporary error (503)
GEMINI_RETRY_STATUSES = (429, 503)
GEMINI_RETRY_ATTEMPTS = 3
GEMINI_RETRY_BACKOFF = (1.0, 2.0, 4.0)  # seconds

# Min seconds between Gemini API calls (classifier + chat). Default 1.0 = at most 1 request/sec.
GEMINI_MIN_INTERVAL = max(0.0, float(os.environ.get("SECUREGATE_GEMINI_MIN_INTERVAL", "1.0")))

_gemini_last_call = 0.0
_gemini_lock = threading.Lock()


def acquire_gemini_rate_limit() -> None:
    """Wait so that at most 1 Gemini request runs per GEMINI_MIN_INTERVAL seconds (global)."""
    global _gemini_last_call
    if GEMINI_MIN_INTERVAL <= 0:
        return
    with _gemini_lock:
        now = time.monotonic()
        wait = GEMINI_MIN_INTERVAL - (now - _gemini_last_call)
        if wait > 0:
            time.sleep(wait)
        # Update after potential wait so the next caller waits from "now"
        _gemini_last_call = time.monotonic()

logger = logging.getLogger(__name__)

# Labels for sensitivity classification (must match llm_classifier)
CLASSIFY_LABELS = [
    "safe general text",
    "contains passwords or API keys",
    "contains medical patient information",
    "contains credit card or bank numbers",
    "contains personal identity information",
    "contains source code or credentials",
]

CLASSIFY_PROMPT = """You are a security classifier. Classify the text into exactly ONE label. Reply with ONLY that label, nothing else.

Labels:
- safe general text
- contains passwords or API keys
- contains medical patient information
- contains credit card or bank numbers
- contains personal identity information
- contains source code or credentials

Use "contains passwords or API keys" if the text has ANY of: passwords; API keys (e.g. GEMINI_API_KEY=..., OPENAI_API_KEY=..., *\_API_KEY=value, *\_SECRET=value); secret tokens; keys starting with AIza, sk-, sk-proj-, ghp_, AKIA; .env or config files with key=secret value; credentials in plain text.

Text to classify:
---
{text}
---

Single label (from the list above):"""


def _normalize_label(raw: str) -> str:
    """Normalize API response to one of CLASSIFY_LABELS."""
    raw = (raw or "").strip().lower()
    for label in CLASSIFY_LABELS:
        if label.lower() in raw or raw in label.lower():
            return label
    if "safe" in raw or not raw:
        return "safe general text"
    if (
        "password" in raw
        or "api key" in raw
        or "credential" in raw
        or "secret" in raw
        or "token" in raw
        or "env" in raw
        or "key=" in raw
    ):
        return "contains passwords or API keys"
    if "medical" in raw or "health" in raw or "patient" in raw:
        return "contains medical patient information"
    if "credit" in raw or "bank" in raw or "financial" in raw:
        return "contains credit card or bank numbers"
    if "personal" in raw or "identity" in raw or "pii" in raw:
        return "contains personal identity information"
    if "source code" in raw or "code" in raw:
        return "contains source code or credentials"
    return "safe general text"


def classify_via_gemini(text: str, api_key: str, model: str = "gemini-2.0-flash") -> Tuple[str, float]:
    """Call Gemini API for classification. Returns (label, confidence). Retries on 429/503."""
    import httpx

    acquire_gemini_rate_limit()
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    payload = {
        "contents": [{"parts": [{"text": CLASSIFY_PROMPT.format(text=text[:2000])}]}],
        "generationConfig": {"maxOutputTokens": 32, "temperature": 0},
    }
    headers = {"x-goog-api-key": api_key, "Content-Type": "application/json"}
    last_error: Optional[Exception] = None
    for attempt in range(GEMINI_RETRY_ATTEMPTS):
        try:
            with httpx.Client(timeout=15.0) as client:
                r = client.post(url, json=payload, headers=headers)
                if r.status_code in GEMINI_RETRY_STATUSES and attempt < GEMINI_RETRY_ATTEMPTS - 1:
                    delay = GEMINI_RETRY_BACKOFF[attempt] if attempt < len(GEMINI_RETRY_BACKOFF) else 4.0
                    logger.info(
                        "Gemini rate limited (HTTP %s), retry in %.1fs (attempt %d/%d)",
                        r.status_code, delay, attempt + 1, GEMINI_RETRY_ATTEMPTS,
                    )
                    time.sleep(delay)
                    continue
                r.raise_for_status()
                data = r.json()
                break
        except Exception as e:
            last_error = e
            if attempt < GEMINI_RETRY_ATTEMPTS - 1:
                delay = GEMINI_RETRY_BACKOFF[attempt] if attempt < len(GEMINI_RETRY_BACKOFF) else 4.0
                if hasattr(e, "response") and getattr(e.response, "status_code", None) in GEMINI_RETRY_STATUSES:
                    logger.info("Gemini retry in %.1fs (attempt %d/%d)", delay, attempt + 1, GEMINI_RETRY_ATTEMPTS)
                    time.sleep(delay)
                    continue
            logger.warning("Gemini classify request failed: %s", e)
            return "safe general text", 0.0
    else:
        if last_error:
            logger.warning("Gemini classify request failed after retries: %s", last_error)
        return "safe general text", 0.0

    try:
        candidates = data.get("candidates") or []
        if not candidates:
            logger.warning("Gemini classify: no candidates (possible safety block or empty response)")
            return "safe general text", 0.0
        first = candidates[0]
        finish_reason = first.get("finishReason") or first.get("finish_reason") or ""
        if finish_reason.upper() in ("SAFETY", "RECITATION", "BLOCKED"):
            # Model refused to output (often when input looks sensitive) — treat as likely sensitive
            logger.info("Gemini classify: response blocked (finishReason=%s), inferring sensitive", finish_reason)
            return "contains passwords or API keys", 0.75
        content = first.get("content") or {}
        parts = content.get("parts") or [{}]
        part = parts[0] if parts else {}
        raw = (part.get("text") or "").strip()
        if not raw:
            logger.warning("Gemini classify: empty text in response (finishReason=%s)", finish_reason)
            return "safe general text", 0.0
        label = _normalize_label(raw)
        conf = 0.85 if label != "safe general text" else 0.5
        logger.info("LLM classifier (Gemini) label=%s confidence=%.2f", label, conf)
        return label, conf
    except Exception as e:
        logger.warning("Gemini classify parse failed: %s (response keys: %s)", e, list(data.keys()) if isinstance(data, dict) else "n/a")
        return "safe general text", 0.0


def classify_via_self_hosted(text: str, base_url: str, api_key: str, model: str = "") -> Tuple[str, float]:
    """Call OpenAI-compatible endpoint for classification. Returns (label, confidence)."""
    import httpx

    base_url = base_url.rstrip("/")
    if not base_url.endswith("/v1"):
        base_url = base_url + "/v1" if "/v1" not in base_url else base_url
    url = f"{base_url}/chat/completions"
    payload = {
        "model": model or "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "You are a classifier. Reply with only the exact label from the list."},
            {"role": "user", "content": CLASSIFY_PROMPT.format(text=text[:2000])},
        ],
        "max_tokens": 64,
        "temperature": 0,
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    try:
        with httpx.Client(timeout=15.0) as client:
            r = client.post(url, json=payload, headers=headers)
            r.raise_for_status()
            data = r.json()
    except Exception as e:
        logger.warning("Self-hosted classify request failed: %s", e)
        return "safe general text", 0.0

    try:
        raw = (data.get("choices") or [{}])[0].get("message", {}).get("content", "").strip()
        label = _normalize_label(raw)
        conf = 0.85 if label != "safe general text" else 0.5
        return label, conf
    except Exception as e:
        logger.warning("Self-hosted classify parse failed: %s", e)
        return "safe general text", 0.0


def classify_remote(text: str, backend: str, *, api_key: str = "", base_url: str = "", model: str = "") -> Tuple[str, float]:
    """
    Classify text using remote LLM. Used by LLM classifier when backend is gemini or self_hosted.
    Returns (label, confidence). Label is one of CLASSIFY_LABELS.
    """
    if backend == "gemini" and api_key:
        return classify_via_gemini(text, api_key=api_key, model=model or "gemini-2.0-flash")
    if backend == "self_hosted" and base_url and api_key:
        return classify_via_self_hosted(text, base_url=base_url, api_key=api_key, model=model)
    return "safe general text", 0.0


def get_chat_proxy(
    backend: str,
    *,
    gemini_api_key: str = "",
    llm_base_url: str = "",
    llm_api_key: str = "",
    llm_model: str = "",
    openai_api_key: str = "",
) -> Any:
    """
    Return the chat proxy instance for the given backend.
    Used by /chat endpoint. Returns an object with async chat(messages, model) -> LLMResponse.
    """
    if backend == "gemini":
        from securegate.llm_proxy import GeminiProxy
        return GeminiProxy(api_key=gemini_api_key, model=llm_model or "gemini-2.0-flash")
    if backend == "self_hosted" and llm_base_url and llm_api_key:
        from securegate.llm_proxy import OpenAIDirectProxy
        return OpenAIDirectProxy(api_key=llm_api_key, base_url=llm_base_url)
    # local: use OpenAI (backward compat)
    from securegate.llm_proxy import OpenAIDirectProxy
    return OpenAIDirectProxy(api_key=openai_api_key or os.environ.get("OPENAI_API_KEY"), base_url=None)
