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


def _extract_gemini_web(body):
    """Gemini web (f.req form param) format."""
    try:
        from urllib.parse import parse_qs
        params = parse_qs(body.decode("utf-8"))
        if "f.req" not in params:
            return ""
        # f.req is a JSON array: [null, "[[prompt, ...], ...]", ...]
        req_json = json.loads(params["f.req"][0])
        if not isinstance(req_json, list) or len(req_json) < 2:
            return ""
        inner_json = json.loads(req_json[1])
        if isinstance(inner_json, list) and len(inner_json) > 0:
            # First element is usually the prompt array
            if isinstance(inner_json[0], list) and len(inner_json[0]) > 0:
                return str(inner_json[0][0])
    except Exception:
        pass
    return ""


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
    host_lower = host.lower()
    if "gemini.google.com" in host_lower:
        text = _extract_gemini_web(body)
        if text.strip():
            return text.strip()

    data = _safe_json(body)
    if not data or not isinstance(data, dict):
        return ""

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
    """Replace user prompt in body with masked text. Returns (new_body, True) if replaced, (body, False) if format unknown."""
    host_lower = host.lower()
    if "gemini.google.com" in host_lower:
        try:
            from urllib.parse import parse_qs, urlencode
            params = parse_qs(body.decode("utf-8"))
            if "f.req" in params:
                req_json = json.loads(params["f.req"][0])
                inner_json = json.loads(req_json[1])
                inner_json[0][0] = masked_text
                req_json[1] = json.dumps(inner_json)
                params["f.req"][0] = json.dumps(req_json)
                return urlencode(params, doseq=True).encode(), True
        except Exception:
            pass

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
                    return json.dumps(data).encode(), True
                if isinstance(m["content"], dict) and "parts" in m["content"]:
                    m["content"]["parts"] = [masked_text]
                    return json.dumps(data).encode(), True
                if isinstance(m["content"], list):
                    for part in m["content"]:
                        if isinstance(part, dict) and part.get("type") == "text" and "text" in part:
                            part["text"] = masked_text
                            return json.dumps(data).encode(), True
            if "parts" in m:
                m["parts"] = [masked_text]
                return json.dumps(data).encode(), True
        if "contents" in data:
            for c in data.get("contents", []):
                for p in c.get("parts", []):
                    if "text" in p:
                        p["text"] = masked_text
                        return json.dumps(data).encode(), True
        
        # Generic fallback for top-level prompt/content/input
        for key in ("prompt", "input", "text", "content", "query", "message"):
            if key in data and isinstance(data[key], str):
                data[key] = masked_text
                return json.dumps(data).encode(), True

    except Exception:
        pass
    return body, False


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
        if "json" not in ct and "x-www-form-urlencoded" not in ct:
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
            new_body, replaced = mask_body(body, result["masked_text"], host)
            if replaced:
                flow.request.content = new_body
            else:
                ctx.log.warn(f"SecureGate [{host}] Mask requested but body format not supported - blocking to avoid sending unmasked data")
                from mitmproxy.http import Response
                flow.response = Response.make(
                    403,
                    json.dumps({
                        "error": {
                            "message": "Blocked by SecureGate: sensitive data detected (masking not supported for this request format).",
                            "reason": result.get("reasoning", ""),
                        }
                    }).encode(),
                    {"Content-Type": "application/json"},
                )


addons = [SecureGateAddon()]
