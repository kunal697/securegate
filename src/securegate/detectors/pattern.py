"""Pattern (regex) detector for structured sensitive data."""

import re

from securegate.detectors.base import BaseDetector
from securegate.models import DetectionResult, Entity, SensitivityCategory


class PatternDetector(BaseDetector):
    """Rule-based regex detector for credentials, PII, financial data."""

    name = "pattern"

    # (pattern, category, confidence)
    PATTERNS = []  # type: list

    def __init__(self) -> None:
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        raw = [
            # Credentials - highest priority
            (r"sk-[A-Za-z0-9]{20,}", SensitivityCategory.CREDENTIALS, 0.95),
            (r"sk-proj-[A-Za-z0-9_-]{20,}", SensitivityCategory.CREDENTIALS, 0.95),
            (r"AKIA[0-9A-Z]{16}", SensitivityCategory.CREDENTIALS, 0.95),
            (r"ghp_[A-Za-z0-9]{36}", SensitivityCategory.CREDENTIALS, 0.95),
            (r"gho_[A-Za-z0-9]{36}", SensitivityCategory.CREDENTIALS, 0.95),
            (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", SensitivityCategory.CREDENTIALS, 0.98),
            # Variable names ending in _API_KEY or _SECRET with long value (e.g. GEMINI_API_KEY=AIzaSy...)
            (r"[A-Za-z0-9_]*_API_KEY\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?", SensitivityCategory.CREDENTIALS, 0.93),
            (r"[A-Za-z0-9_]*_SECRET\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?", SensitivityCategory.CREDENTIALS, 0.93),
            # Google API key prefix (Gemini, Maps, etc.)
            (r"AIza[0-9A-Za-z_-]{35,}", SensitivityCategory.CREDENTIALS, 0.93),
            (r"\b(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?", SensitivityCategory.CREDENTIALS, 0.90),
            (r"\b(?:password|passwd|pwd)\s*[:=]\s*['\"]?.+['\"]?", SensitivityCategory.CREDENTIALS, 0.85),
            # SSN
            (r"\b\d{3}-\d{2}-\d{4}\b", SensitivityCategory.PERSONAL_INFO, 0.92),
            # Credit card (basic Luhn-compatible patterns)
            (r"\b4[0-9]{12}(?:[0-9]{3})?\b", SensitivityCategory.FINANCIAL_DATA, 0.90),
            (r"\b5[1-5][0-9]{14}\b", SensitivityCategory.FINANCIAL_DATA, 0.90),
            (r"\b3[47][0-9]{13}\b", SensitivityCategory.FINANCIAL_DATA, 0.90),
            # IBAN (simplified)
            (r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b", SensitivityCategory.FINANCIAL_DATA, 0.88),
            # Email
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", SensitivityCategory.PERSONAL_INFO, 0.85),
            # Indian phone
            (r"\b(?:\+91|91)?[6-9]\d{9}\b", SensitivityCategory.PERSONAL_INFO, 0.82),
            # US phone
            (r"\b(?:\+1)?[-.\s]?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", SensitivityCategory.PERSONAL_INFO, 0.82),
            # Medical MRN
            (r"\bMRN\s*[:#]?\s*\d{6,}\b", SensitivityCategory.HEALTH_INFO, 0.85),
            (r"\bpatient\s+id\s*[:#]?\s*\d{6,}\b", SensitivityCategory.HEALTH_INFO, 0.80),
        ]
        self.PATTERNS = [(re.compile(p, re.I), c, conf) for p, c, conf in raw]

    def detect(self, text: str) -> DetectionResult:
        if not text or not isinstance(text, str):
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        text = text.strip()
        entities = []
        max_conf = 0.0
        top_category = SensitivityCategory.SAFE

        for pattern, category, confidence in self.PATTERNS:
            for m in pattern.finditer(text):
                entities.append(
                    Entity(
                        type=category.value,
                        value=m.group(0)[:50],
                        start=m.start(),
                        end=m.end(),
                        confidence=confidence,
                        category=category,
                    )
                )
                if confidence > max_conf:
                    max_conf = confidence
                    top_category = category

        return DetectionResult(
            detected=len(entities) > 0,
            category=top_category,
            confidence=max_conf if entities else 0.0,
            entities=entities,
            detector_name=self.name,
        )
