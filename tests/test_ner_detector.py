"""Tests for NER detector (Presidio)."""

import pytest

from securegate.detectors.ner import NERDetector, _CATEGORY_MAP
from securegate.models import SensitivityCategory


def test_ner_empty_input():
    det = NERDetector()
    r = det.detect("")
    assert r.detected is False
    assert r.detector_name == "ner"
    assert r.category == SensitivityCategory.SAFE
    r2 = det.detect("   ")
    assert r2.detected is False


def test_ner_category_map():
    assert _CATEGORY_MAP["PERSON"] == SensitivityCategory.PERSONAL_INFO
    assert _CATEGORY_MAP["CREDIT_CARD"] == SensitivityCategory.FINANCIAL_DATA
    assert _CATEGORY_MAP["US_SSN"] == SensitivityCategory.PERSONAL_INFO


@pytest.mark.skipif(
    True,  # Set to False to run with Presidio installed: python -m spacy download en_core_web_lg
    reason="NER requires Presidio and spaCy model (en_core_web_lg)",
)
def test_ner_with_presidio():
    """Run only when Presidio is installed and en_core_web_lg is downloaded."""
    det = NERDetector()
    r = det.detect("John Smith lives in New York and his email is john@example.com")
    # May detect PERSON and/or EMAIL depending on model
    assert r.detector_name == "ner"
    if r.detected:
        assert r.category in (
            SensitivityCategory.PERSONAL_INFO,
            SensitivityCategory.FINANCIAL_DATA,
            SensitivityCategory.HEALTH_INFO,
        )
        assert len(r.entities) >= 1
        assert all(e.confidence >= 0.7 for e in r.entities)


def test_ner_mocked_engine():
    """Test NER with mocked Presidio engine (no real dependency)."""
    from unittest.mock import MagicMock, patch

    class MockResult:
        def __init__(self, entity_type: str, start: int, end: int, score: float):
            self.entity_type = entity_type
            self.start = start
            self.end = end
            self.score = score

    mock_engine = MagicMock()
    mock_engine.analyze.return_value = [
        MockResult("PERSON", 0, 10, 0.85),
        MockResult("EMAIL_ADDRESS", 25, 42, 0.92),
    ]

    with patch.object(NERDetector, "_get_engine", return_value=mock_engine):
        det = NERDetector()
        r = det.detect("John Smith and john@example.com")
    assert r.detected is True
    assert r.detector_name == "ner"
    assert r.category == SensitivityCategory.PERSONAL_INFO  # EMAIL maps to PERSONAL_INFO, 0.92 > 0.85
    assert len(r.entities) == 2
    assert r.entities[0].type == "PERSON"
    assert r.entities[1].type == "EMAIL_ADDRESS"
    assert r.entities[0].confidence == 0.85
    assert r.entities[1].confidence == 0.92
