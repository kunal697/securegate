"""Tests for Pattern (Regex) detector."""

import pytest

from securegate.detectors.pattern import PatternDetector
from securegate.models import SensitivityCategory


@pytest.fixture
def detector():
    return PatternDetector()


def test_pattern_detector_empty_input(detector):
    r = detector.detect("")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE
    assert r.confidence == 0.0
    assert r.detector_name == "pattern"
    assert r.entities == []


def test_pattern_detector_none_and_whitespace(detector):
    r = detector.detect(None)  # type: ignore
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE
    r2 = detector.detect("   \n\t  ")
    assert r2.detected is False


def test_pattern_detector_openai_key(detector):
    text = "My API key is sk-1234567890abcdef1234567890abcdef"
    r = detector.detect(text)
    assert r.detected is True
    assert r.category == SensitivityCategory.CREDENTIALS
    assert r.confidence >= 0.9
    assert len(r.entities) >= 1
    assert any(e.type == "Credentials" for e in r.entities)


def test_pattern_detector_ssn(detector):
    text = "SSN: 123-45-6789"
    r = detector.detect(text)
    assert r.detected is True
    assert r.category == SensitivityCategory.PERSONAL_INFO
    assert any(e.type == "Personal_Info" for e in r.entities)
    assert any("123-45-6789" in e.value for e in r.entities)


def test_pattern_detector_email(detector):
    text = "Contact me at john.doe@example.com"
    r = detector.detect(text)
    assert r.detected is True
    assert r.category == SensitivityCategory.PERSONAL_INFO
    assert any("@" in e.value for e in r.entities)


def test_pattern_detector_credit_card(detector):
    # Visa-like pattern (test number)
    text = "Card 4532015112830366"
    r = detector.detect(text)
    assert r.detected is True
    assert r.category == SensitivityCategory.FINANCIAL_DATA
    assert any(e.type == "Financial_Data" for e in r.entities)


def test_pattern_detector_health_mrn(detector):
    text = "Patient MRN 1234567 - diabetes"
    r = detector.detect(text)
    assert r.detected is True
    assert r.category == SensitivityCategory.HEALTH_INFO
    assert any(e.type == "Health_Info" for e in r.entities)


def test_pattern_detector_safe_text(detector):
    text = "What is the capital of France?"
    r = detector.detect(text)
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE
    assert r.entities == []


def test_pattern_detector_multiple_entities(detector):
    text = "Email john@test.com and SSN 111-22-3333"
    r = detector.detect(text)
    assert r.detected is True
    assert len(r.entities) >= 2
    # Category should be the one with highest confidence among detected
    assert r.category in (SensitivityCategory.PERSONAL_INFO, SensitivityCategory.SAFE) or r.category.value == "Personal_Info"
