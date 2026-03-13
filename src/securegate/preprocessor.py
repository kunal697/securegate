"""Text preprocessing before detection."""

import unicodedata


def preprocess(text: str) -> str:
    """Normalize and sanitize input text."""
    if not text or not isinstance(text, str):
        return ""
    # Normalize Unicode
    t = unicodedata.normalize("NFKC", text)
    # Collapse whitespace
    t = " ".join(t.split())
    return t.strip()
