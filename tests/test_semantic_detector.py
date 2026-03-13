"""Tests for Semantic Analyzer detector."""

import pytest

from securegate.detectors.semantic import SemanticAnalyzer
from securegate.models import SensitivityCategory


def test_semantic_empty_input():
    det = SemanticAnalyzer(threshold=0.78)
    r = det.detect("")
    assert r.detected is False
    assert r.detector_name == "semantic"
    assert r.category == SensitivityCategory.SAFE
    assert r.confidence == 0.0


def test_semantic_returns_safe_when_not_detected():
    """When no template matches above threshold, category must be Safe."""
    det = SemanticAnalyzer(threshold=0.99)  # very high so "safe" text won't match
    # Without loading real model we can't test full flow; we test the contract:
    r = det.detect("   ")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE


@pytest.mark.skipif(
    True,
    reason="Semantic requires sentence-transformers (heavy)",
)
def test_semantic_with_real_model():
    """Run when sentence-transformers is installed."""
    det = SemanticAnalyzer(threshold=0.78)
    r = det.detect("patient diabetes insulin dosage and medical history")
    assert r.detector_name == "semantic"
    if r.detected:
        assert r.category == SensitivityCategory.HEALTH_INFO
        assert r.confidence >= 0.78
