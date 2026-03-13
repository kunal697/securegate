"""NER detector using GLiNER (zero-shot or PII model), runs locally.

Requires: pip install gliner (see requirements-gliner.txt).
Models: urchade/gliner_medium-v2.1 (zero-shot) or nvidia/gliner-pii (PII/PHI).
If gliner is not installed, detect() returns Safe so the pipeline still runs.
"""

import logging
import os
from typing import Any, List, Optional

from securegate.detectors.base import BaseDetector
from securegate.models import DetectionResult, Entity, SensitivityCategory

logger = logging.getLogger(__name__)

# Labels for generic zero-shot GLiNER (e.g. urchade/gliner_medium-v2.1)
GLINER_LABELS = [
    "API key",
    "password",
    "secret",
    "credential",
    "person name",
    "email address",
    "phone number",
    "credit card number",
    "social security number",
    "bank account",
]

# Labels for nvidia/gliner-pii (55+ PII/PHI types; use snake_case per model card)
GLINER_PII_LABELS = [
    "email",
    "phone_number",
    "user_name",
    "person_name",
    "social_security_number",
    "credit_card_number",
    "bank_account_number",
    "api_key",
    "password",
    "secret",
    "credential",
]

LABEL_TO_CATEGORY = {
    "api key": SensitivityCategory.CREDENTIALS,
    "password": SensitivityCategory.CREDENTIALS,
    "secret": SensitivityCategory.CREDENTIALS,
    "credential": SensitivityCategory.CREDENTIALS,
    "person name": SensitivityCategory.PERSONAL_INFO,
    "email address": SensitivityCategory.PERSONAL_INFO,
    "phone number": SensitivityCategory.PERSONAL_INFO,
    "credit card number": SensitivityCategory.FINANCIAL_DATA,
    "social security number": SensitivityCategory.PERSONAL_INFO,
    "bank account": SensitivityCategory.FINANCIAL_DATA,
    # nvidia/gliner-pii snake_case labels
    "email": SensitivityCategory.PERSONAL_INFO,
    "phone_number": SensitivityCategory.PERSONAL_INFO,
    "user_name": SensitivityCategory.PERSONAL_INFO,
    "person_name": SensitivityCategory.PERSONAL_INFO,
    "social_security_number": SensitivityCategory.PERSONAL_INFO,
    "credit_card_number": SensitivityCategory.FINANCIAL_DATA,
    "bank_account_number": SensitivityCategory.FINANCIAL_DATA,
    "api_key": SensitivityCategory.CREDENTIALS,
}


class GLiNERDetector(BaseDetector):
    """Zero-shot NER using GLiNER (local model)."""

    name = "gliner"
    _model: Any = None
    _initialized = False

    def __init__(
        self,
        model_name: Optional[str] = None,
        threshold: Optional[float] = None,
    ) -> None:
        self._model_name = (
            model_name
            or os.environ.get("SECUREGATE_GLINER_MODEL", "urchade/gliner_medium-v2.1").strip()
        )
        if threshold is not None:
            self._threshold = threshold
        else:
            raw = os.environ.get("SECUREGATE_GLINER_THRESHOLD", "").strip()
            self._threshold = float(raw) if raw else 0.5
        # nvidia/gliner-pii card recommends threshold=0.3 for eval; 0.5 is default

    def _get_labels(self) -> List[str]:
        """Use PII-specific labels for nvidia/gliner-pii, else zero-shot labels."""
        if "gliner-pii" in (self._model_name or "").lower():
            return GLINER_PII_LABELS
        return GLINER_LABELS

    def _get_model(self) -> Any:
        if GLiNERDetector._model is not None:
            return GLiNERDetector._model
        try:
            from gliner import GLiNER

            GLiNERDetector._model = GLiNER.from_pretrained(self._model_name)
            GLiNERDetector._initialized = True
            return GLiNERDetector._model
        except Exception as e:
            logger.warning("GLiNER load failed: %s", e)
            raise

    def detect(self, text: str) -> DetectionResult:
        if not text or not isinstance(text, str) or not text.strip():
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        try:
            model = self._get_model()
        except Exception:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        try:
            labels = self._get_labels()
            raw = model.predict_entities(text, labels, threshold=self._threshold)
        except Exception as e:
            logger.warning("GLiNER predict failed: %s", e)
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        entities = []
        max_conf = 0.0
        top_category = SensitivityCategory.SAFE
        for e in raw:
            value = (e.get("text") or "").strip()[:200]
            label = (e.get("label") or "").strip().lower()
            score = float(e.get("score", 0.0))
            start = e.get("start")
            end = e.get("end")
            if start is None or end is None:
                idx = text.find(value) if value else -1
                start = idx if idx >= 0 else 0
                end = start + len(value) if value else start
            else:
                start, end = int(start), int(end)
            cat = LABEL_TO_CATEGORY.get(label, SensitivityCategory.PERSONAL_INFO)
            entities.append(
                Entity(
                    type=label or "entity",
                    value=value,
                    start=start,
                    end=end,
                    confidence=score,
                    category=cat,
                )
            )
            if score > max_conf:
                max_conf = score
                top_category = cat
        return DetectionResult(
            detected=len(entities) > 0,
            category=top_category,
            confidence=max_conf if entities else 0.0,
            entities=entities,
            detector_name=self.name,
        )
