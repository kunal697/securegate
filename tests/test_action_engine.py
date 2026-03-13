"""Tests for Action engine (mask_text)."""

import pytest

from securegate.action_engine import mask_text, _safe_placeholder_type
from securegate.models import Entity, SensitivityCategory


def test_mask_text_empty_entities():
    assert mask_text("hello world", []) == "hello world"
    assert mask_text("", []) == ""


def test_mask_text_single_entity():
    # Entity span 10:16 is "sk-xxx" (6 chars); 10:17 would include trailing space
    e = Entity(type="Credentials", value="sk-xxx", start=10, end=16, confidence=0.95, category=SensitivityCategory.CREDENTIALS)
    out = mask_text("My key is sk-xxx ok", [e])
    assert "sk-xxx" not in out
    assert "[REDACTED_CREDENTIALS]" in out
    assert out == "My key is [REDACTED_CREDENTIALS] ok"


def test_mask_text_multiple_entities():
    e1 = Entity(type="EMAIL", value="a@b.com", start=0, end=7, confidence=0.9, category=SensitivityCategory.PERSONAL_INFO)
    e2 = Entity(type="SSN", value="111-22-3333", start=15, end=26, confidence=0.92, category=SensitivityCategory.PERSONAL_INFO)
    out = mask_text("Email a@b.com and SSN 111-22-3333", [e1, e2])
    assert "a@b.com" not in out
    assert "111-22-3333" not in out
    assert "[REDACTED_EMAIL]" in out
    assert "[REDACTED_SSN]" in out


def test_mask_text_safe_placeholder_type():
    assert _safe_placeholder_type("Health_Info") == "HEALTH_INFO"
    assert _safe_placeholder_type("PERSON") == "PERSON"
    assert _safe_placeholder_type("") == "REDACTED"
    assert _safe_placeholder_type("a-b") == "A_B"
