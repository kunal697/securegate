"""Base detector interface."""

from abc import ABC, abstractmethod

from securegate.models import DetectionResult


class BaseDetector(ABC):
    """Abstract base for all detectors."""

    name: str = "base"

    @abstractmethod
    def detect(self, text: str) -> DetectionResult:
        """Run detection on text. Must be thread-safe."""
        ...
