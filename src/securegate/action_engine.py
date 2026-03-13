"""Action engine: apply Allow/Mask/Block/Quarantine."""

from securegate.models import Action, Entity


def _safe_placeholder_type(entity_type: str) -> str:
    """Sanitize entity type for placeholder (alphanumeric and underscore only)."""
    if not entity_type:
        return "REDACTED"
    s = "".join(c if c.isalnum() or c == "_" else "_" for c in str(entity_type))
    return s.upper() or "REDACTED"


def mask_text(text: str, entities: list) -> str:
    """Replace detected entities with placeholders."""
    if not text or not entities:
        return text or ""

    # Sort by start desc to replace from end (preserve indices)
    sorted_ents = sorted(entities, key=lambda e: -e.start)
    result = text
    for e in sorted_ents:
        start = max(0, min(e.start, len(result)))
        end = max(start, min(e.end, len(result)))
        placeholder = f"[REDACTED_{_safe_placeholder_type(getattr(e, 'type', 'REDACTED'))}]"
        result = result[:start] + placeholder + result[end:]
    return result
