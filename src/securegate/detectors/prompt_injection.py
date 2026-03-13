"""Prompt injection and adversarial prompt detection."""

import re

from securegate.detectors.base import BaseDetector
from securegate.models import DetectionResult, SensitivityCategory

# Suspicious patterns for prompt injection / extraction attempts
_INJECTION_PATTERNS = [
    (r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions", 0.92),
    (r"disregard\s+(?:your\s+)?(?:instructions|rules|guidelines)", 0.90),
    (r"you\s+are\s+now\s+(?:a|in)\s+[^.]+\s+mode", 0.85),
    (r"system\s*:\s*", 0.75),
    (r"\[INST\]|\[/INST\]|<<SYS>>|<<\/SYS>>", 0.88),
    (r"repeat\s+(?:the\s+)?(?:above|previous)\s+(?:word|phrase|content)", 0.85),
    (r"output\s+(?:the\s+)?(?:raw|full|entire)\s+(?:prompt|input)", 0.90),
    (r"reveal\s+(?:your|the)\s+(?:prompt|instructions|system)", 0.90),
    (r"print\s+(?:your|the)\s+prompt", 0.88),
    (r"what\s+(?:are|is)\s+your\s+(?:instructions|system\s+prompt)", 0.80),
    (r"new\s+instruction\s*:", 0.82),
    (r"override\s+(?:your|previous)", 0.85),
    (r"pretend\s+you\s+don't\s+have", 0.80),
]
_COMPILED = [(re.compile(p, re.I), c) for p, c in _INJECTION_PATTERNS]


class PromptInjectionDetector(BaseDetector):
    """Detects prompt injection and adversarial extraction attempts."""

    name = "prompt_injection"

    def detect(self, text: str) -> DetectionResult:
        if not text or not isinstance(text, str) or not text.strip():
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )

        max_conf = 0.0
        for pattern, conf in _COMPILED:
            if pattern.search(text):
                if conf > max_conf:
                    max_conf = conf

        detected = max_conf > 0
        return DetectionResult(
            detected=detected,
            category=SensitivityCategory.CREDENTIALS if detected else SensitivityCategory.SAFE,
            confidence=max_conf,
            entities=[],
            detector_name=self.name,
        )
