"""Audit logging for compliance and traceability."""

import json
import logging
from collections import Counter
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List

from securegate.models import Action, AnalysisResult, SensitivityCategory

AUDIT_LOG = Path("data/audit.log")
AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("securegate.audit")


def _get_log_path() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "data" / "audit.log"


def _redact(text: str, max_len: int = 50) -> str:
    """Redact sensitive content from logs."""
    if not text:
        return ""
    t = text.strip()[:max_len]
    if len(text) > max_len:
        t += "..."
    return t.replace("@", "[at]").replace(".", "[dot]")


def log_analysis(
    request_id,
    user_id,
    session_id,
    result: AnalysisResult,
    text_preview: str = "",
) -> None:
    """Write audit entry. No PII in logs."""
    detector_results = getattr(result, "detector_results", None) or []
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "request_id": request_id or "",
        "user_id": user_id[:8] + "..." if user_id and len(user_id) > 8 else (user_id or ""),
        "session_id": session_id[:8] + "..." if session_id and len(session_id) > 8 else (session_id or ""),
        "action": result.action.value,
        "category": result.category.value,
        "score": round(result.sensitivity_score, 2),
        "entity_count": len(result.entities),
        "text_preview": _redact(text_preview, 30),
        "reasoning": getattr(result, "reasoning", "") or "",
        "detector_results": detector_results,
    }
    try:
        log_path = _get_log_path()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with open(log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        logger.warning("Audit write failed: %s", e)


def _read_entries(limit: int = 500) -> List[Dict[str, Any]]:
    """Read recent audit entries (newest first)."""
    log_path = _get_log_path()
    if not log_path.exists():
        return []
    entries = []
    try:
        with open(log_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []
    entries.reverse()
    return entries[:limit]


def get_events(limit: int = 100) -> List[Dict[str, Any]]:
    """Get recent audit events for dashboard."""
    return _read_entries(limit)


def get_stats(hours: int = 24) -> Dict[str, Any]:
    """Get aggregated stats for dashboard."""
    entries = _read_entries(limit=10000)
    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
    recent = [e for e in entries if e.get("ts", "") >= cutoff]

    by_action = Counter(e.get("action", "Unknown") for e in recent)
    by_category = Counter(e.get("category", "Safe") for e in recent)

    return {
        "total": len(recent),
        "blocked": by_action.get("Block", 0),
        "masked": by_action.get("Mask", 0),
        "allowed": by_action.get("Allow", 0),
        "quarantined": by_action.get("Quarantine", 0),
        "by_action": dict(by_action),
        "by_category": dict(by_category),
    }
