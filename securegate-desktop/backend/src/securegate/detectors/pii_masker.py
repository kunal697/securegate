"""Detector wrapper for the pii-masker (HydroXai) package."""

import logging
from typing import Any, Dict, List, Optional

from securegate.detectors.base import BaseDetector
from securegate.models import DetectionResult, Entity, SensitivityCategory

logger = logging.getLogger(__name__)

class PIIMaskerDetector(BaseDetector):
    """
    Advanced PII detector using the pii-masker package.
    Provides deep context analysis for names, phones, addresses, and specialized IDs.
    """

    name = "pii_masker"
    _masker = None  # Lazy load the heavy masker

    def __init__(self):
        self._initialized = False

    def _ensure_init(self):
        if self._initialized:
            return
        try:
            from pii_masker.masker import CustomPIIMasker
            PIIMaskerDetector._masker = CustomPIIMasker()
            self._initialized = True
        except Exception as e:
            logger.error(f"Failed to initialize PIIMasker: {e}")
            raise RuntimeError("pii-masker package not found or failed to load models.")

    def detect(self, text: str, context: Optional[dict] = None) -> DetectionResult:
        if not text or not isinstance(text, str) or not text.strip():
            return DetectionResult(detected=False, detector_name=self.name)

        try:
            self._ensure_init()
            masker = PIIMaskerDetector._masker
            if not masker:
                return DetectionResult(detected=False, detector_name=self.name)

            # Get detected entities using the masker's internal logic
            results = masker.get_detected_entities(text)
            
            entities: List[Entity] = []
            max_conf = 0.0
            top_category = SensitivityCategory.SAFE

            for r in results:
                # r is a dict with 'entity_type', 'text', 'score', 'start', 'end'
                score = r.get("score", 0.0)
                if score < 0.5:
                    continue

                entity_type = r.get("entity_type", "UNKNOWN")
                start = r.get("start", 0)
                end = r.get("end", 0)
                value = r.get("text", "")

                # Map to SecureGate categories
                category = self._map_category(entity_type)
                
                entities.append(Entity(
                    type=entity_type,
                    value=value,
                    start=start,
                    end=end,
                    confidence=float(score),
                    category=category
                ))

                if score > max_conf:
                    max_conf = float(score)
                    top_category = category

            return DetectionResult(
                detected=len(entities) > 0,
                category=top_category,
                confidence=max_conf,
                entities=entities,
                detector_name=self.name
            )

        except Exception as e:
            logger.error(f"PIIMasker detection failed: {e}")
            return DetectionResult(detected=False, detector_name=self.name)

    def _map_category(self, pii_type: str) -> SensitivityCategory:
        """Map pii-masker types to SecureGate sensitivity categories."""
        pii_type = pii_type.upper()
        
        # Financial
        if any(kw in pii_type for kw in ["CREDIT_CARD", "BANK_ACCOUNT", "ROUTING", "TIN", "LOAN"]):
            return SensitivityCategory.FINANCIAL_DATA
        
        # Health
        if any(kw in pii_type for kw in ["MEDICAL", "HEALTH"]):
            return SensitivityCategory.HEALTH_INFO
            
        # Credentials
        if any(kw in pii_type for kw in ["PASSWORD", "PIN", "USERNAME"]):
            return SensitivityCategory.CREDENTIALS
            
        # Personal Info (Default)
        return SensitivityCategory.PERSONAL_INFO
