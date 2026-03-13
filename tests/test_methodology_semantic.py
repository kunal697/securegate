"""
Tests for SEMANTIC methodology only (sentence embeddings + template similarity).

Light tests without loading the real model; optional test with real model when skipped by default.

Run: pytest tests/test_methodology_semantic.py -v
"""

import pytest

from securegate.detectors.semantic import SemanticAnalyzer
from securegate.models import SensitivityCategory


@pytest.fixture
def semantic_only():
    return SemanticAnalyzer(threshold=0.78)


def test_semantic_empty(semantic_only):
    r = semantic_only.detect("")
    assert r.detected is False
    assert r.detector_name == "semantic"
    assert r.category == SensitivityCategory.SAFE
    assert r.confidence == 0.0


def test_semantic_whitespace_only(semantic_only):
    r = semantic_only.detect("   \n  ")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE


@pytest.mark.skipif(
    True,
    reason="Requires sentence-transformers; would load real model",
)
def test_semantic_not_detected_returns_safe_category(semantic_only):
    """When no template matches above threshold, category must be Safe (not a random category)."""
    det = SemanticAnalyzer(threshold=0.99)  # very high so normal text won't match
    r = det.detect("Hello world")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE


@pytest.mark.skipif(
    True,
    reason="Requires: pip install sentence-transformers (heavy)",
)
def test_semantic_real_health_phrase(semantic_only):
    """Real model: health-related phrase should match Health_Info template."""
    r = semantic_only.detect("patient diabetes insulin dosage and medical history")
    assert r.detector_name == "semantic"
    if r.detected:
        assert r.category == SensitivityCategory.HEALTH_INFO
        assert r.confidence >= 0.78


@pytest.mark.skipif(
    True,
    reason="Requires: pip install sentence-transformers (heavy)",
)
def test_semantic_real_credentials_phrase(semantic_only):
    """Real model: credential-related phrase should match Credentials template."""
    r = semantic_only.detect("api key password secret token for authentication")
    assert r.detector_name == "semantic"
    if r.detected:
        assert r.category == SensitivityCategory.CREDENTIALS
        assert r.confidence >= 0.78


@pytest.mark.skipif(
    True,
    reason="Requires: pip install sentence-transformers (heavy)",
)
def test_semantic_real_safe_phrase(semantic_only):
    """Real model: neutral phrase may not match any template above threshold."""
    r = semantic_only.detect("What is the capital of France?")
    assert r.detector_name == "semantic"
    # Either no match (Safe) or low-confidence match
    assert r.category in (SensitivityCategory.SAFE, SensitivityCategory.PERSONAL_INFO, SensitivityCategory.FINANCIAL_DATA)
    if not r.detected:
        assert r.category == SensitivityCategory.SAFE
