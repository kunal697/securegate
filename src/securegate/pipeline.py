"""Main SecureGate pipeline."""

import asyncio
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, Sequence

from securegate.action_engine import mask_text
from securegate.decision_engine import aggregate_results, decide, merge_entities
from securegate.detectors.base import BaseDetector
from securegate.detectors import (
    LLMClassifier,
    NERDetector,
    PatternDetector,
    PromptInjectionDetector,
    SemanticAnalyzer,
)
from securegate.models import (
    Action,
    AnalysisRequest,
    AnalysisResult,
    DetectionResult,
    Policy,
    SensitivityCategory,
)
from securegate.preprocessor import preprocess

logger = logging.getLogger(__name__)

DEFAULT_DETECTORS = [
    PatternDetector(),
    PromptInjectionDetector(),
    NERDetector(),
    SemanticAnalyzer(),
    LLMClassifier(),
]


class Pipeline:
    """SecureGate analysis pipeline."""

    def __init__(
        self,
        detectors: Optional[Sequence[BaseDetector]] = None,
        policy: Optional[Policy] = None,
        executor: Optional[ThreadPoolExecutor] = None,
    ) -> None:
        self.detectors = list(detectors or DEFAULT_DETECTORS)
        self.policy = policy
        self._executor = executor or ThreadPoolExecutor(max_workers=4)

    def _run_detectors_sync(self, text: str) -> list:
        """Run all detectors (sync, can be called from thread pool). One result per detector."""
        results = []
        for det in self.detectors:
            name = getattr(det, "name", "?")
            try:
                r = det.detect(text)
                results.append(r)
                logger.info(
                    "detector=%s detected=%s confidence=%.2f category=%s entities=%d",
                    name,
                    r.detected,
                    r.confidence,
                    r.category.value if r.category else "Safe",
                    len(r.entities or []),
                )
            except Exception as e:
                logger.warning("Detector %s failed: %s", name, e)
                results.append(
                    DetectionResult(
                        detected=False,
                        category=SensitivityCategory.SAFE,
                        confidence=0.0,
                        entities=[],
                        detector_name=name,
                        metadata={"error": str(e)},
                    )
                )
                logger.info(
                    "detector=%s detected=false confidence=0 category=Safe entities=0 (error)",
                    name,
                )
        return results

    async def analyze(self, request: AnalysisRequest) -> AnalysisResult:
        """Analyze text and return action with reasoning."""
        text = preprocess(request.text)
        if not text:
            return AnalysisResult(
                action=Action.ALLOW,
                category=SensitivityCategory.SAFE,
                sensitivity_score=0.0,
                reasoning="Empty or invalid input",
            )

        loop = asyncio.get_event_loop()
        results = await loop.run_in_executor(
            self._executor,
            self._run_detectors_sync,
            text,
        )

        scores = aggregate_results(results, self.policy and self.policy.detector_weights or None)
        action, category, score, reasoning = decide(scores, self.policy)
        entities = merge_entities(results)

        detector_details = []
        for r in results:
            detector_details.append({
                "detector_name": r.detector_name,
                "detected": r.detected,
                "confidence": round(r.confidence, 3),
                "category": r.category.value if r.category else "Safe",
                "entity_count": len(r.entities),
            })

        logger.info(
            "analyze result action=%s category=%s score=%.2f reasoning=%s | %s",
            action.value,
            category.value if category else "Safe",
            score,
            reasoning[:80] + "..." if len(reasoning) > 80 else reasoning,
            " | ".join(
                f"{d['detector_name']}={d['detected']}({d['confidence']})"
                for d in detector_details
            ),
        )

        masked = None  # type: Optional[str]
        if action == Action.MASK and entities:
            masked = mask_text(text, entities)

        return AnalysisResult(
            action=action,
            category=category,
            sensitivity_score=score,
            entities=entities,
            reasoning=reasoning,
            masked_text=masked,
            detector_results=detector_details,
        )
