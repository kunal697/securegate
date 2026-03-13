"""Semantic analyzer using sentence embeddings.

Uses a LOCAL model (SentenceTransformer all-MiniLM-L6-v2). If sentence_transformers
is not installed, detect() catches the load error and returns detected=False (Safe)
so the pipeline still runs; the semantic row in the dashboard will show No/0.
"""

from typing import TYPE_CHECKING, Any, Dict, List

from securegate.detectors.base import BaseDetector
from securegate.models import DetectionResult, SensitivityCategory

if TYPE_CHECKING:
    from sentence_transformers import SentenceTransformer

# Template phrases per category (embedded once)
_TEMPLATES: Dict = {
    SensitivityCategory.CREDENTIALS: [
        "api key password secret token credential",
        "openai key aws secret access key",
        "GEMINI_API_KEY secret key in environment variable config",
        "env file contains API key and secret token",
        "configuration file with password and API key equals",
    ],
    SensitivityCategory.HEALTH_INFO: [
        "patient medical diagnosis prescription medication",
        "diabetes insulin dosage blood pressure",
        "health record medical history",
    ],
    SensitivityCategory.FINANCIAL_DATA: [
        "credit card bank account routing number",
        "salary income tax social security",
    ],
    SensitivityCategory.PERSONAL_INFO: [
        "my name is address phone number",
        "social security date of birth",
    ],
    SensitivityCategory.SOURCE_CODE: [
        "function class import def return",
        "javascript python sql database",
    ],
}


class SemanticAnalyzer(BaseDetector):
    """Embedding-based semantic sensitivity detection."""

    name = "semantic"
    _model = None  # type: Any
    _template_embeds = None  # type: Any
    _initialized = False

    def __init__(self, threshold: float = 0.78) -> None:
        self.threshold = threshold

    def _ensure_init(self) -> None:
        if SemanticAnalyzer._initialized:
            return
        try:
            from sentence_transformers import SentenceTransformer

            SemanticAnalyzer._model = SentenceTransformer("all-MiniLM-L6-v2")
        except Exception as e:
            raise RuntimeError("Failed to load SentenceTransformer") from e

        all_docs: List[str] = []
        all_cats: List = []
        for cat, phrases in _TEMPLATES.items():
            for p in phrases:
                all_docs.append(p)
                all_cats.append(cat)
        embeds = SemanticAnalyzer._model.encode(all_docs)
        SemanticAnalyzer._template_embeds = [
            (all_cats[i], embeds[i].tolist()) for i in range(len(all_docs))
        ]
        SemanticAnalyzer._initialized = True

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
            self._ensure_init()
        except Exception:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )

        model = SemanticAnalyzer._model
        templates = SemanticAnalyzer._template_embeds
        if model is None or templates is None:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )

        try:
            query_embed = model.encode([text[:512]])[0]
        except Exception:
            return DetectionResult(
                detected=False,
                category=SensitivityCategory.SAFE,
                confidence=0.0,
                entities=[],
                detector_name=self.name,
            )

        import math

        best_score = 0.0
        best_category = SensitivityCategory.SAFE

        for cat, tvec in templates:
            dot = sum(a * b for a, b in zip(query_embed, tvec))
            na = math.sqrt(sum(a * a for a in query_embed))
            nb = math.sqrt(sum(b * b for b in tvec))
            if na > 0 and nb > 0:
                similarity = dot / (na * nb)
                if similarity > best_score:
                    best_score = float(similarity)
                    if similarity >= self.threshold:
                        best_category = cat

        detected = best_score >= self.threshold
        return DetectionResult(
            detected=detected,
            category=best_category if detected else SensitivityCategory.SAFE,
            confidence=round(best_score, 2),  # always show best similarity so dashboard shows a score
            entities=[],
            detector_name=self.name,
        )
