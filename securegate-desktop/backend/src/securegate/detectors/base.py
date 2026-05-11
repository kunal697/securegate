"""Base detector interface."""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from securegate.models import DetectionResult


class BaseDetector(ABC):
    """Abstract base for all detectors."""

    name: str = "base"

    @abstractmethod
    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        """Run detection on text. context may contain custom_labels, etc. Must be thread-safe."""
        ...
