"""Extract user prompts from AI API request bodies."""

import json
import re


def _safe_json(body: bytes) -> dict | None:
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def extract_openai(data: dict) -> str:
    """OpenAI Chat Completions: messages[].content."""
    messages = data.get("messages") or []
    parts = []
    for m in messages:
        content = m.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for c in content:
                if isinstance(c, dict) and c.get("type") == "text":
                    parts.append(c.get("text", ""))
    return "\n".join(parts)


def extract_anthropic(data: dict) -> str:
    """Anthropic Messages API: messages[].content[].text."""
    messages = data.get("messages") or []
    parts = []
    for m in messages:
        for c in m.get("content") or []:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
    return "\n".join(parts)


def extract_google_gemini(data: dict) -> str:
    """Google Gemini: contents[].parts[].text or contents[].parts[].inline_data (skip)."""
    contents = data.get("contents") or data.get("generationConfig") or []
    if not isinstance(contents, list):
        return ""
    parts = []
    for c in contents:
        if not isinstance(c, dict):
            continue
        for p in c.get("parts") or []:
            if isinstance(p, dict) and "text" in p:
                parts.append(str(p["text"]))
    return "\n".join(parts)


def extract_cohere(data: dict) -> str:
    """Cohere: message or chat_history + message."""
    msg = data.get("message") or data.get("message") or ""
    history = data.get("chat_history") or []
    parts = []
    for h in history:
        if isinstance(h, dict) and "message" in h:
            parts.append(str(h["message"]))
    if msg:
        parts.append(str(msg))
    return "\n".join(parts)


def extract_generic_text(data: dict) -> str:
    """Fallback: look for common keys."""
    for key in ("prompt", "input", "text", "content", "query", "message"):
        v = data.get(key)
        if isinstance(v, str) and v.strip():
            return v
        if isinstance(v, list):
            return " ".join(str(x) for x in v if x)
    return ""


EXTRACTORS = [
    ("messages", extract_openai),
    ("messages", extract_anthropic),
    ("contents", extract_google_gemini),
    ("message", extract_cohere),
]


def extract_prompt(body: bytes, host: str) -> str:
    """Extract user prompt from request body based on host/API shape."""
    data = _safe_json(body)
    if not data or not isinstance(data, dict):
        return ""

    for key, fn in EXTRACTORS:
        if key in data:
            text = fn(data)
            if text.strip():
                return text.strip()

    return extract_generic_text(data)
