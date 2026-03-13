"""
Tests for NER methodology only (Presidio/spaCy).

Uses mocked Presidio so no need for spaCy model.
Run with real NER: set SKIP_NER_REAL=False and have presidio + en_core_web_lg installed.

Run: pytest tests/test_methodology_ner.py -v
"""

import pytest

from securegate.detectors.ner import NERDetector, _CATEGORY_MAP
from securegate.models import SensitivityCategory


@pytest.fixture
def ner_only():
    return NERDetector()


def test_ner_empty(ner_only):
    r = ner_only.detect("")
    assert r.detected is False
    assert r.detector_name == "ner"
    assert r.category == SensitivityCategory.SAFE


def test_ner_category_mapping():
    assert _CATEGORY_MAP["PERSON"] == SensitivityCategory.PERSONAL_INFO
    assert _CATEGORY_MAP["EMAIL_ADDRESS"] == SensitivityCategory.PERSONAL_INFO
    assert _CATEGORY_MAP["CREDIT_CARD"] == SensitivityCategory.FINANCIAL_DATA
    assert _CATEGORY_MAP["US_SSN"] == SensitivityCategory.PERSONAL_INFO
    assert _CATEGORY_MAP["IBAN_CODE"] == SensitivityCategory.FINANCIAL_DATA


def test_ner_mocked_person_and_email():
    """NER only: mock Presidio returning PERSON and EMAIL."""
    from unittest.mock import MagicMock, patch

    class MockPresidioResult:
        def __init__(self, entity_type: str, start: int, end: int, score: float):
            self.entity_type = entity_type
            self.start = start
            self.end = end
            self.score = score

    mock_engine = MagicMock()
    mock_engine.analyze.return_value = [
        MockPresidioResult("PERSON", 0, 10, 0.88),
        MockPresidioResult("EMAIL_ADDRESS", 18, 35, 0.92),
    ]

    with patch.object(NERDetector, "_get_engine", return_value=mock_engine):
        det = NERDetector()
        r = det.detect("John Smith email john@example.com")
    assert r.detected is True
    assert r.detector_name == "ner"
    assert len(r.entities) == 2
    assert r.entities[0].type == "PERSON"
    assert r.entities[1].type == "EMAIL_ADDRESS"
    assert r.entities[0].confidence >= 0.7
    assert r.entities[1].confidence >= 0.7
    assert r.category == SensitivityCategory.PERSONAL_INFO


def test_ner_mocked_credit_card():
    """NER only: mock Presidio returning CREDIT_CARD."""
    from unittest.mock import MagicMock, patch

    class MockPresidioResult:
        def __init__(self, entity_type: str, start: int, end: int, score: float):
            self.entity_type = entity_type
            self.start = start
            self.end = end
            self.score = score

    mock_engine = MagicMock()
    mock_engine.analyze.return_value = [
        MockPresidioResult("CREDIT_CARD", 9, 28, 0.85),
    ]

    with patch.object(NERDetector, "_get_engine", return_value=mock_engine):
        det = NERDetector()
        r = det.detect("Card number 4532015112830366")
    assert r.detected is True
    assert r.category == SensitivityCategory.FINANCIAL_DATA
    assert any(e.type == "CREDIT_CARD" for e in r.entities)


def test_ner_mocked_low_confidence_filtered_out():
    """NER only: results below 0.7 are filtered out."""
    from unittest.mock import MagicMock, patch

    class MockPresidioResult:
        def __init__(self, entity_type: str, start: int, end: int, score: float):
            self.entity_type = entity_type
            self.start = start
            self.end = end
            self.score = score

    mock_engine = MagicMock()
    mock_engine.analyze.return_value = [
        MockPresidioResult("PERSON", 0, 4, 0.5),  # below 0.7
    ]

    with patch.object(NERDetector, "_get_engine", return_value=mock_engine):
        det = NERDetector()
        r = det.detect("John")
    assert r.detected is False
    assert len(r.entities) == 0


@pytest.mark.skipif(
    True,
    reason="Requires: pip install presidio-analyzer; python -m spacy download en_core_web_lg",
)
def test_ner_real_presidio_person_email(ner_only):
    """Run with real Presidio: text with person name and email."""
    r = ner_only.detect("John Smith can be reached at john.smith@company.com")
    assert r.detector_name == "ner"
    if r.detected:
        assert r.category in (SensitivityCategory.PERSONAL_INFO, SensitivityCategory.FINANCIAL_DATA, SensitivityCategory.HEALTH_INFO)
        assert len(r.entities) >= 1
