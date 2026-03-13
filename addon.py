"""
SecureGate mitmproxy addon - system-wide AI request inspection.
Run: mitmproxy -s addon.py --listen-port 8080
"""

import json
import os
import sys
from pathlib import Path

# Ensure project root on path
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

import requests
import yaml

CONFIG_PATH = PROJECT_ROOT / "config" / "protected_domains.yaml"


def _safe_json(body):
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _extract_openai(data):
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


def _extract_anthropic(data):
    messages = data.get("messages") or []
    parts = []
    for m in messages:
        for c in m.get("content") or []:
            if isinstance(c, dict) and c.get("type") == "text":
                parts.append(c.get("text", ""))
    return "\n".join(parts)


def _extract_google(data):
    contents = data.get("contents") or []
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


def _extract_chatgpt_web(data):
    """ChatGPT web (chatgpt.com/backend-api/f/conversation) format."""
    messages = data.get("messages") or []
    parts = []
    for m in messages:
        author = m.get("author") or {}
        role = author.get("role", m.get("role", ""))
        if role != "user":
            continue
        content = m.get("content")
        if content is None and m.get("text"):
            content = m.get("text")
        if isinstance(content, str) and content.strip():
            parts.append(content)
        elif isinstance(content, dict):
            cparts = content.get("parts") or []
            for p in cparts:
                if isinstance(p, str) and p.strip():
                    parts.append(p)
                elif isinstance(p, dict) and p.get("text"):
                    parts.append(str(p.get("text", "")))
        elif isinstance(content, list):
            for c in content:
                if isinstance(c, dict) and c.get("type") == "text":
                    parts.append(c.get("text", ""))
                elif isinstance(c, dict) and "text" in c:
                    parts.append(str(c.get("text", "")))
                elif isinstance(c, str) and c.strip():
                    parts.append(c)
    if parts:
        return "\n".join(parts)
    for key in ("input", "prompt", "message"):
        v = data.get(key)
        if isinstance(v, str) and v.strip():
            return v
    return ""


def _extract_generic(data):
    for key in ("prompt", "input", "text", "content", "query", "message"):
        v = data.get(key)
        if isinstance(v, str) and v.strip():
            return v
        if isinstance(v, list):
            return " ".join(str(x) for x in v if x)
    return ""


def extract_prompt(body, host=""):
    data = _safe_json(body)
    if not data or not isinstance(data, dict):
        return ""
    host_lower = host.lower()
    if "chatgpt.com" in host_lower:
        text = _extract_chatgpt_web(data)
        if text.strip():
            return text.strip()
    if "messages" in data:
        text = _extract_openai(data)
        if not text:
            text = _extract_anthropic(data)
        if not text and "chatgpt.com" in host_lower:
            text = _extract_chatgpt_web(data)
        if text.strip():
            return text.strip()
    if "contents" in data:
        text = _extract_google(data)
        if text.strip():
            return text.strip()
    return _extract_generic(data)


def load_protected_domains():
    domains = set()
    if not CONFIG_PATH.exists():
        return domains
    try:
        with open(CONFIG_PATH) as f:
            data = yaml.safe_load(f) or {}
        domains = set(data.get("protected_domains") or [])
    except Exception:
        pass
    return domains


def analyze(text):
    url = os.environ.get("SECUREGATE_URL", "http://127.0.0.1:8000").rstrip("/")
    try:
        # Bypass proxy for localhost - otherwise requests may go through mitmproxy and fail
        r = requests.post(
            f"{url}/analyze",
            json={"text": text},
            timeout=5,
            proxies={"http": None, "https": None},
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def is_protected(host, protected):
    host = host.split(":")[0].lower()
    for d in protected:
        d = d.lower()
        if host == d or host.endswith("." + d):
            return True
    return False


def mask_body(body, masked_text, host=""):
    """Replace user prompt in body with masked text."""
    try:
        data = json.loads(body.decode("utf-8"))
        messages = data.get("messages") or []
        for m in messages:
            role = (m.get("author") or {}).get("role") or m.get("role")
            if role != "user":
                continue
            if "content" in m:
                if isinstance(m["content"], str):
                    m["content"] = masked_text
                    return json.dumps(data).encode()
                if isinstance(m["content"], dict) and "parts" in m["content"]:
                    m["content"]["parts"] = [masked_text]
                    return json.dumps(data).encode()
            if "parts" in m:
                m["parts"] = [masked_text]
                return json.dumps(data).encode()
        if "contents" in data:
            for c in data.get("contents", []):
                for p in c.get("parts", []):
                    if "text" in p:
                        p["text"] = masked_text
                        return json.dumps(data).encode()
    except Exception:
        pass
    return body


class SecureGateAddon:
    def __init__(self):
        self.protected = load_protected_domains()

    def load(self, loader):
        from mitmproxy import ctx

        ctx.log.info(f"SecureGate addon loaded, protected domains: {sorted(self.protected)}")

    def request(self, flow):
        from mitmproxy import ctx

        host = flow.request.pretty_host
        if not is_protected(host, self.protected):
            return

        body = flow.request.content
        if not body or flow.request.method != "POST":
            return

        ct = (flow.request.headers.get("content-type") or "").lower()
        if "json" not in ct:
            return

        prompt = extract_prompt(body, host)
        if not prompt:
            ctx.log.info(f"SecureGate [{host}] no prompt extracted from path={flow.request.path}")
            return

        result = analyze(prompt)
        if result is None:
            ctx.log.warn(f"SecureGate [{host}] analyze failed - is API running on port 8000?")
            return

        action = result.get("action", "Allow")
        ctx.log.info(f"SecureGate [{host}] prompt_len={len(prompt)} action={action}")
        if action == "Block":
            from mitmproxy.http import Response

            flow.response = Response.make(
                403,
                json.dumps({
                    "error": {
                        "message": "Blocked by SecureGate: sensitive data detected.",
                        "reason": result.get("reasoning", ""),
                    }
                }).encode(),
                {"Content-Type": "application/json"},
            )
            return

        if action == "Mask" and result.get("masked_text"):
            flow.request.content = mask_body(body, result["masked_text"], host)


addons = [SecureGateAddon()]
