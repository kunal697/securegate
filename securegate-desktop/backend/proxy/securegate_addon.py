"""
SecureGate mitmproxy addon - system-wide AI request inspection.

Intercepts requests to protected domains, extracts prompts, analyzes via SecureGate,
and applies Block/Mask/Allow before forwarding.
"""

import json
import os
from pathlib import Path

import requests

from .prompt_extractors import extract_prompt

# Config paths
ADDON_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = ADDON_DIR.parent
CONFIG_PATH = PROJECT_ROOT / "config" / "protected_domains.yaml"


def load_protected_domains() -> set:
    """Load protected domains from YAML config."""
    domains = set()
    if not CONFIG_PATH.exists():
        return domains
    try:
        import yaml

        with open(CONFIG_PATH) as f:
            data = yaml.safe_load(f) or {}
        domains = set(data.get("protected_domains") or [])
    except Exception:
        pass
    return domains


def analyze_via_securegate(text):
    """Call SecureGate /analyze API."""
    url = os.environ.get("SECUREGATE_URL", "http://127.0.0.1:8000")
    if not url.endswith("/"):
        url = url.rstrip("/")
    try:
        r = requests.post(
            f"{url}/analyze",
            json={"text": text},
            timeout=5,
        )
        r.raise_for_status()
        return r.json()
    except Exception:
        return None


def is_protected(host: str, protected: set) -> bool:
    """Check if host matches any protected domain."""
    host = host.split(":")[0].lower()
    for d in protected:
        d = d.lower()
        if host == d or host.endswith("." + d):
            return True
    return False


class SecureGateAddon:
    def __init__(self):
        self.protected = load_protected_domains()

    def load(self, loader):
        loader.add_option(
            name="securegate_url",
            typespec=str,
            default="http://127.0.0.1:8000",
            help="SecureGate API URL",
        )

    def request(self, flow):
        host = flow.request.pretty_host
        if not is_protected(host, self.protected):
            return

        body = flow.request.content
        if not body or flow.request.method != "POST":
            return

        content_type = (flow.request.headers.get("content-type") or "").lower()
        if "json" not in content_type:
            return

        prompt = extract_prompt(body, host)
        if not prompt:
            return

        result = analyze_via_securegate(prompt)
        if result is None:
            return

        action = result.get("action", "Allow")
        if action == "Block":
            from mitmproxy.http import Response

            flow.response = Response.make(
                403,
                json.dumps({
                    "error": {
                        "message": "Request blocked by SecureGate: sensitive data detected.",
                        "reason": result.get("reasoning", ""),
                    }
                }).encode(),
                {"Content-Type": "application/json"},
            )
            return

        if action == "Mask" and result.get("masked_text"):
            try:
                data = json.loads(body.decode("utf-8"))
                masked = result["masked_text"]
                if "messages" in data:
                    for m in data.get("messages", []):
                        if m.get("role") == "user" and "content" in m:
                            m["content"] = masked
                            break
                elif "contents" in data:
                    for c in data.get("contents", []):
                        for p in c.get("parts", []):
                            if "text" in p:
                                p["text"] = masked
                                break
                flow.request.content = json.dumps(data).encode()
            except Exception:
                pass


addons = [SecureGateAddon()]
