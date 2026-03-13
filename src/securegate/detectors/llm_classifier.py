"""Zero-shot LLM classifier for subtle sensitivity detection.

Supports two modes (via SECUREGATE_LLM_BACKEND):
- local: Uses BART-MNLI on your machine (no API key). Needs transformers/torch.
- gemini / self_hosted: Uses remote LLM (Gemini API or your OpenAI-compatible server).
"""

from typing import TYPE_CHECKING, Any

from securegate.detectors.base import BaseDetector
from securegate.models import DetectionResult, SensitivityCategory

if TYPE_CHECKING:
    from transformers import Pipeline

_LABELS = [
    "safe general text",
    "contains passwords or API keys",
    "contains medical patient information",
    "contains credit card or bank numbers",
    "contains personal identity information",
    "contains source code or credentials",
]
_LABEL_TO_CATEGORY = {
    "contains passwords or API keys": SensitivityCategory.CREDENTIALS,
    "contains medical patient information": SensitivityCategory.HEALTH_INFO,
    "contains credit card or bank numbers": SensitivityCategory.FINANCIAL_DATA,
    "contains personal identity information": SensitivityCategory.PERSONAL_INFO,
    "contains source code or credentials": SensitivityCategory.SOURCE_CODE,
}


class LLMClassifier(BaseDetector):
    """Classifier: local BART or remote (Gemini / self-hosted) per SECUREGATE_LLM_BACKEND."""

    name = "llm_classifier"
    _pipe = None  # type: Any

    def __init__(self, min_score: float = 0.75, max_length: int = 500) -> None:
        self.min_score = min_score
        self.max_length = max_length

    def _detect_remote(self, text: str) -> DetectionResult:
        """Use Gemini or self-hosted API for classification."""
        try:
            from securegate.config import Settings
            from securegate.llm_client import classify_remote
        except ImportError:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        s = Settings()
        backend = s.llm_backend
        if backend not in ("gemini", "self_hosted"):
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        api_key = s.gemini_api_key if backend == "gemini" else s.llm_api_key
        base_url = s.llm_base_url if backend == "self_hosted" else ""
        model = s.llm_model or ""
        if backend == "gemini" and not api_key:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        if backend == "self_hosted" and (not base_url or not api_key):
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        trunc = text[: self.max_length]
        label, conf = classify_remote(trunc, backend, api_key=api_key, base_url=base_url, model=model)
        if label == "safe general text" or conf < self.min_score:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        category = _LABEL_TO_CATEGORY.get(label, SensitivityCategory.PERSONAL_INFO)
        return DetectionResult(
            detected=True,
            category=category,
            confidence=conf,
            entities=[],
            detector_name=self.name,
        )

    def _get_pipeline(self) -> "Pipeline":
        if LLMClassifier._pipe is None:
            try:
                from transformers import pipeline

                LLMClassifier._pipe = pipeline(
                    "zero-shot-classification",
                    model="facebook/bart-large-mnli",
                    device=-1,
                )
            except Exception as e:
                raise RuntimeError("Failed to load BART-MNLI classifier") from e
        return LLMClassifier._pipe

    def detect(self, text: str) -> DetectionResult:
        if not text or not text.strip():
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )
        # Remote backend (gemini / self_hosted)
        try:
            from securegate.config import Settings
            backend = Settings().llm_backend
            if backend in ("gemini", "self_hosted"):
                return self._detect_remote(text)
        except Exception:
            pass
        # Local BART
        trunc = text[: self.max_length]
        try:
            pipe = self._get_pipeline()
            out = pipe(trunc, _LABELS, multi_label=False)
        except Exception:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )

        scores = out.get("scores", [])
        labels = out.get("labels", [])
        if not scores or not labels:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )

        # Handle tensor or list (transformers may return tensors)
        try:
            s0 = scores[0]
            top_score = float(s0.item() if hasattr(s0, "item") else s0)
        except (TypeError, ValueError):
            top_score = 0.0
        top_label = labels[0] if isinstance(labels[0], str) else str(labels[0])

        if top_label == "safe general text" or top_score < self.min_score:
            return DetectionResult(detected=False, detector_name=self.name)

        category = _LABEL_TO_CATEGORY.get(top_label, SensitivityCategory.PERSONAL_INFO)
        return DetectionResult(
            detected=True,
            category=category,
            confidence=top_score,
            entities=[],
            detector_name=self.name,
        )
