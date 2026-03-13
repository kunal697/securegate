"""
Tests for PATTERN methodology only (regex detector).

Run: pytest tests/test_methodology_pattern.py -v
"""

import pytest

from securegate.detectors.pattern import PatternDetector
from securegate.models import SensitivityCategory


@pytest.fixture
def pattern_only():
    """Single detector: pattern (regex) only."""
    return PatternDetector()


# ---- Pattern: credentials (API keys, passwords) ----
def test_pattern_openai_key(pattern_only):
    r = pattern_only.detect("My key is sk-1234567890abcdef1234567890abcdef")
    assert r.detected is True
    assert r.category == SensitivityCategory.CREDENTIALS
    assert r.detector_name == "pattern"
    assert any(e.type == "Credentials" for e in r.entities)


def test_pattern_aws_key(pattern_only):
    r = pattern_only.detect("AWS key: AKIAIOSFODNN7EXAMPLE")
    assert r.detected is True
    assert r.category == SensitivityCategory.CREDENTIALS


def test_pattern_github_token(pattern_only):
    # Pattern requires ghp_ + exactly 36 alphanumeric chars
    r = pattern_only.detect("token ghp_abcdefghijklmnopqrstuvwxyz1234567890ab")
    assert r.detected is True
    assert r.category == SensitivityCategory.CREDENTIALS


def test_pattern_password_equals(pattern_only):
    r = pattern_only.detect("password=superSecret123")
    assert r.detected is True
    assert r.category == SensitivityCategory.CREDENTIALS


# ---- Pattern: PII (SSN, email, phone) ----
def test_pattern_ssn(pattern_only):
    r = pattern_only.detect("SSN: 123-45-6789")
    assert r.detected is True
    assert r.category == SensitivityCategory.PERSONAL_INFO
    assert any("123-45-6789" in e.value for e in r.entities)


def test_pattern_email(pattern_only):
    r = pattern_only.detect("Contact john.doe@example.com")
    assert r.detected is True
    assert r.category == SensitivityCategory.PERSONAL_INFO
    assert any("@" in e.value for e in r.entities)


def test_pattern_indian_phone(pattern_only):
    r = pattern_only.detect("Call +91 9876543210")
    assert r.detected is True
    assert r.category == SensitivityCategory.PERSONAL_INFO


def test_pattern_us_phone(pattern_only):
    r = pattern_only.detect("Phone (555) 123-4567")
    assert r.detected is True
    assert r.category == SensitivityCategory.PERSONAL_INFO


# ---- Pattern: financial ----
def test_pattern_credit_card_visa(pattern_only):
    r = pattern_only.detect("Card 4532015112830366")
    assert r.detected is True
    assert r.category == SensitivityCategory.FINANCIAL_DATA


def test_pattern_iban(pattern_only):
    r = pattern_only.detect("IBAN DE89370400440532013000")
    assert r.detected is True
    assert r.category == SensitivityCategory.FINANCIAL_DATA


# ---- Pattern: health ----
def test_pattern_mrn(pattern_only):
    r = pattern_only.detect("Patient MRN 1234567 diabetes")
    assert r.detected is True
    assert r.category == SensitivityCategory.HEALTH_INFO


def test_pattern_patient_id(pattern_only):
    r = pattern_only.detect("patient id # 999999")
    assert r.detected is True
    assert r.category == SensitivityCategory.HEALTH_INFO


# ---- Pattern: safe (no match) ----
def test_pattern_safe_general(pattern_only):
    r = pattern_only.detect("What is the capital of France?")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE
    assert r.entities == []


def test_pattern_empty(pattern_only):
    r = pattern_only.detect("")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE
