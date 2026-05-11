"""Extract text from uploaded PDF or plain text for use as custom labels."""

import logging
from typing import List, Tuple

logger = logging.getLogger(__name__)

MAX_SUGGESTED_LABELS = 50
MIN_LABEL_LENGTH = 2


def extract_text_from_bytes(content: bytes, filename: str) -> Tuple[str, List[str]]:
    """Extract raw text and suggested labels (e.g. unique lines) from file content.

    Returns:
        (full_text, suggested_labels)
    """
    name = (filename or "").lower()
    if name.endswith(".pdf"):
        text = _extract_pdf(content)
    else:
        text = _extract_plain_text(content)
    labels = _text_to_suggested_labels(text)
    return text, labels


def _extract_pdf(content: bytes) -> str:
    try:
        from pypdf import PdfReader
        from io import BytesIO
        reader = PdfReader(BytesIO(content))
        parts = []
        for page in reader.pages:
            try:
                parts.append(page.extract_text() or "")
            except Exception as e:
                logger.warning("PDF page extract failed: %s", e)
        return "\n".join(parts)
    except ImportError:
        logger.warning("pypdf not installed; pip install pypdf for PDF upload")
        return ""
    except Exception as e:
        logger.warning("PDF extraction failed: %s", e)
        return ""


def _extract_plain_text(content: bytes) -> str:
    for encoding in ("utf-8", "latin-1", "cp1252"):
        try:
            return content.decode(encoding)
        except UnicodeDecodeError:
            continue
    return content.decode("utf-8", errors="replace")


def _text_to_suggested_labels(text: str) -> List[str]:
    """Derive suggested entity labels from text: unique non-empty lines, cleaned."""
    if not text or not text.strip():
        return []
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    seen = set()
    out = []
    for ln in lines:
        if len(ln) < MIN_LABEL_LENGTH:
            continue
        key = ln.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(ln[:200])
        if len(out) >= MAX_SUGGESTED_LABELS:
            break
    return out
