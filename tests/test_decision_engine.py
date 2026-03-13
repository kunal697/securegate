"""Tests for Decision engine (aggregate, decide, merge_entities)."""

import pytest

from securegate.decision_engine import (
    aggregate_results,
    decide,
    merge_entities,
    DEFAULT_WEIGHTS,
)
from securegate.models import (
    Action,
    DetectionResult,
    Entity,
    SensitivityCategory,
)


def test_aggregate_results_empty():
    scores = aggregate_results([])
    assert scores == {}


def test_aggregate_results_single_detector():
    r = DetectionResult(
        detected=True,
        category=SensitivityCategory.CREDENTIALS,
        confidence=0.9,
        entities=[],
        detector_name="pattern",
    )
    scores = aggregate_results([r])
    assert SensitivityCategory.CREDENTIALS in scores
    assert scores[SensitivityCategory.CREDENTIALS] == pytest.approx(0.9 * DEFAULT_WEIGHTS["pattern"], rel=1e-2)


def test_aggregate_results_multiple_detectors_same_category():
    r1 = DetectionResult(
        detected=True,
        category=SensitivityCategory.PERSONAL_INFO,
        confidence=0.8,
        entities=[],
        detector_name="pattern",
    )
    r2 = DetectionResult(
        detected=True,
        category=SensitivityCategory.PERSONAL_INFO,
        confidence=0.9,
        entities=[],
        detector_name="ner",
    )
    scores = aggregate_results([r1, r2])
    # Higher weighted score wins
    expected = max(0.8 * 0.95, 0.9 * 0.85)
    assert scores[SensitivityCategory.PERSONAL_INFO] == pytest.approx(expected, rel=1e-2)


def test_decide_credentials_blocks():
    scores = {SensitivityCategory.CREDENTIALS: 0.85}
    action, category, score, reason = decide(scores)
    assert action == Action.BLOCK
    assert category == SensitivityCategory.CREDENTIALS
    assert score == 0.85
    assert "Credentials" in reason and "Block" in reason


def test_decide_health_quarantine():
    scores = {SensitivityCategory.HEALTH_INFO: 0.75}
    action, category, score, reason = decide(scores)
    assert action == Action.QUARANTINE
    assert category == SensitivityCategory.HEALTH_INFO


def test_decide_personal_info_masks():
    scores = {SensitivityCategory.PERSONAL_INFO: 0.8}
    action, category, score, reason = decide(scores)
    assert action == Action.MASK
    assert category == SensitivityCategory.PERSONAL_INFO


def test_decide_no_sensitive_data_allows():
    scores = {}
    action, category, score, reason = decide(scores)
    assert action == Action.ALLOW
    assert category == SensitivityCategory.SAFE
    assert score == 0.0
    assert "No sensitive" in reason


def test_decide_below_threshold_allows():
    scores = {SensitivityCategory.PERSONAL_INFO: 0.5}  # below 0.70
    action, category, score, reason = decide(scores)
    assert action == Action.ALLOW
    assert category == SensitivityCategory.SAFE


def test_merge_entities_dedup():
    e1 = Entity(type="PERSON", value="John", start=0, end=4, confidence=0.9, category=SensitivityCategory.PERSONAL_INFO)
    e2 = Entity(type="PERSON", value="John", start=0, end=4, confidence=0.85, category=SensitivityCategory.PERSONAL_INFO)
    r1 = DetectionResult(detected=True, category=SensitivityCategory.PERSONAL_INFO, confidence=0.9, entities=[e1], detector_name="ner")
    r2 = DetectionResult(detected=True, category=SensitivityCategory.PERSONAL_INFO, confidence=0.85, entities=[e2], detector_name="pattern")
    merged = merge_entities([r1, r2])
    assert len(merged) == 1
    assert merged[0].start == 0 and merged[0].end == 4


def test_merge_entities_different_spans():
    e1 = Entity(type="EMAIL", value="a@b.com", start=0, end=7, confidence=0.9, category=SensitivityCategory.PERSONAL_INFO)
    e2 = Entity(type="SSN", value="123-45-6789", start=20, end=31, confidence=0.92, category=SensitivityCategory.PERSONAL_INFO)
    r1 = DetectionResult(detected=True, category=SensitivityCategory.PERSONAL_INFO, confidence=0.92, entities=[e1, e2], detector_name="pattern")
    merged = merge_entities([r1])
    assert len(merged) == 2
    assert merged[0].start == 0 and merged[1].start == 20
