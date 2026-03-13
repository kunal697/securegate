"""NER detector using Presidio (spaCy).

Uses a LOCAL Presidio AnalyzerEngine with spaCy. If presidio/spaCy or the
en_core_web_lg model are not installed, detect() catches the error and returns
detected=False (Safe) so the pipeline still runs; the NER row will show No/0.
Also runs credential patterns (API keys, env vars) so NER contributes when pattern does.
"""

import re
from typing import TYPE_CHECKING, Any, Optional

from securegate.detectors.base import BaseDetector
from securegate.models import DetectionResult, Entity, SensitivityCategory

if TYPE_CHECKING:
    from presidio_analyzer import AnalyzerEngine

# Credential patterns so NER also flags API keys / env secrets
_CREDENTIAL_PATTERNS = [
    (re.compile(r"[A-Za-z0-9_]*_API_KEY\s*[:=]\s*['\"]?[A-Za-z0-9_-]{20,}['\"]?", re.I), 0.90),
    (re.compile(r"AIza[0-9A-Za-z_-]{35,}"), 0.90),
    (re.compile(r"sk-[A-Za-z0-9]{20,}"), 0.90),
]

_CATEGORY_MAP = {
    "PERSON": SensitivityCategory.PERSONAL_INFO,
    "EMAIL_ADDRESS": SensitivityCategory.PERSONAL_INFO,
    "PHONE_NUMBER": SensitivityCategory.PERSONAL_INFO,
    "CREDIT_CARD": SensitivityCategory.FINANCIAL_DATA,
    "US_SSN": SensitivityCategory.PERSONAL_INFO,
    "IBAN_CODE": SensitivityCategory.FINANCIAL_DATA,
    "MEDICAL_LICENSE": SensitivityCategory.HEALTH_INFO,
    "NRP": SensitivityCategory.PERSONAL_INFO,
}


class NERDetector(BaseDetector):
    """Presidio-based NER for PII in natural language."""

    name = "ner"
    _engine = None  # type: Any

    def __init__(self, spacy_model_name: Optional[str] = None) -> None:
        self._spacy_model_name = spacy_model_name

    def _get_engine(self) -> "AnalyzerEngine":
        if NERDetector._engine is None:
            try:
                import os
                from presidio_analyzer import AnalyzerEngine

                model_name = (
                    self._spacy_model_name
                    or os.environ.get("SECUREGATE_SPACY_MODEL", "").strip()
                    or "en_core_web_lg"
                )
                if model_name and model_name != "en_core_web_lg":
                    from presidio_analyzer.nlp_engine import NlpEngineProvider
                    configuration = {
                        "nlp_engine_name": "spacy",
                        "models": [{"lang_code": "en", "model_name": model_name}],
                    }
                    provider = NlpEngineProvider(nlp_configuration=configuration)
                    nlp_engine = provider.create_engine()
                    NERDetector._engine = AnalyzerEngine(nlp_engine=nlp_engine)
                else:
                    NERDetector._engine = AnalyzerEngine()
            except Exception as e:
                raise RuntimeError(
                    "Presidio requires spaCy. Run: python -m spacy download en_core_web_lg "
                    "(or en_core_web_sm for lower RAM)"
                ) from e
        return NERDetector._engine

    def detect(self, text: str) -> DetectionResult:
        if not text or not isinstance(text, str) or not text.strip():
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )

        results = []
        try:
            engine = self._get_engine()
            results = engine.analyze(
                text=text,
                language="en",
                entities=[
                    "PERSON",
                    "EMAIL_ADDRESS",
                    "PHONE_NUMBER",
                    "CREDIT_CARD",
                    "US_SSN",
                    "IBAN_CODE",
                ],
            )
        except Exception:
            pass  # continue to credential patterns

        entities: list[Entity] = []
        max_conf = 0.0
        top_category = SensitivityCategory.SAFE
        n = len(text)

        for r in results:
            score = getattr(r, "score", 0.0)
            if score < 0.7:
                continue
            start = getattr(r, "start", 0)
            end = getattr(r, "end", 0)
            entity_type = getattr(r, "entity_type", "PERSON")
            start = max(0, min(start, n))
            end = max(start, min(end, n))
            value = text[start:end] if start < end else ""
            cat = _CATEGORY_MAP.get(entity_type, SensitivityCategory.PERSONAL_INFO)
            entities.append(
                Entity(
                    type=entity_type,
                    value=value,
                    start=start,
                    end=end,
                    confidence=float(score),
                    category=cat,
                )
            )
            if score > max_conf:
                max_conf = float(score)
                top_category = cat

        # Credential patterns so NER also contributes score/entities for API keys, env vars
        for pattern, conf in _CREDENTIAL_PATTERNS:
            for m in pattern.finditer(text):
                entities.append(
                    Entity(
                        type="API_KEY",
                        value=m.group(0)[:50],
                        start=m.start(),
                        end=m.end(),
                        confidence=conf,
                        category=SensitivityCategory.CREDENTIALS,
                    )
                )
                if conf > max_conf:
                    max_conf = conf
                    top_category = SensitivityCategory.CREDENTIALS

        return DetectionResult(
            detected=len(entities) > 0,
            category=top_category,
            confidence=max_conf if entities else 0.0,
            entities=entities,
            detector_name=self.name,
        )
