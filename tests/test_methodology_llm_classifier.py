"""
Tests for LLM CLASSIFIER methodology only (zero-shot BART-MNLI).

Uses mocked pipeline so no need for transformers/torch.
Run with real model: install transformers/torch and remove skip from real test.

Run: pytest tests/test_methodology_llm_classifier.py -v
"""

import pytest

from securegate.detectors.llm_classifier import (
    LLMClassifier,
    _LABELS,
    _LABEL_TO_CATEGORY,
)
from securegate.models import SensitivityCategory


@pytest.fixture
def llm_only():
    return LLMClassifier(min_score=0.75, max_length=500)


def test_llm_empty(llm_only):
    r = llm_only.detect("")
    assert r.detected is False
    assert r.detector_name == "llm_classifier"
    assert r.category == SensitivityCategory.SAFE
    assert r.entities == []


def test_llm_labels_and_categories():
    assert "safe general text" in _LABELS
    assert _LABEL_TO_CATEGORY["contains passwords or API keys"] == SensitivityCategory.CREDENTIALS
    assert _LABEL_TO_CATEGORY["contains medical patient information"] == SensitivityCategory.HEALTH_INFO
    assert _LABEL_TO_CATEGORY["contains credit card or bank numbers"] == SensitivityCategory.FINANCIAL_DATA
    assert _LABEL_TO_CATEGORY["contains personal identity information"] == SensitivityCategory.PERSONAL_INFO
    assert _LABEL_TO_CATEGORY["contains source code or credentials"] == SensitivityCategory.SOURCE_CODE


def test_llm_mocked_safe(llm_only):
    """LLM only: mock returns 'safe' -> not detected."""
    from unittest.mock import MagicMock, patch

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["safe general text", "contains personal identity information"],
        "scores": [0.92, 0.05],
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("What is the capital of France?")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE
    assert r.detector_name == "llm_classifier"


def test_llm_mocked_credentials(llm_only):
    """LLM only: mock returns credentials label -> detected Credentials."""
    from unittest.mock import MagicMock, patch

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["contains passwords or API keys", "safe general text"],
        "scores": [0.88, 0.1],
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("my api key is secret123")
    assert r.detected is True
    assert r.category == SensitivityCategory.CREDENTIALS
    assert r.confidence == 0.88


def test_llm_mocked_medical(llm_only):
    """LLM only: mock returns medical label -> detected Health_Info."""
    from unittest.mock import MagicMock, patch

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["contains medical patient information", "safe general text"],
        "scores": [0.82, 0.08],
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("patient has diabetes and takes insulin")
    assert r.detected is True
    assert r.category == SensitivityCategory.HEALTH_INFO
    assert r.confidence == 0.82


def test_llm_mocked_financial(llm_only):
    """LLM only: mock returns financial label -> detected Financial_Data."""
    from unittest.mock import MagicMock, patch

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["contains credit card or bank numbers", "safe general text"],
        "scores": [0.79, 0.1],
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("my bank account number is...")
    assert r.detected is True
    assert r.category == SensitivityCategory.FINANCIAL_DATA


def test_llm_mocked_below_threshold_not_detected(llm_only):
    """LLM only: score below min_score (0.75) -> not detected."""
    from unittest.mock import MagicMock, patch

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["contains personal identity information", "safe general text"],
        "scores": [0.60, 0.35],  # 0.60 < 0.75
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("my name is John")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE


def test_llm_mocked_tensor_scores(llm_only):
    """LLM only: pipeline returns tensor for scores -> converted to float."""
    from unittest.mock import MagicMock, patch

    class FakeTensor:
        def item(self):
            return 0.85

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["contains personal identity information"],
        "scores": [FakeTensor()],
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("My SSN is 123-45-6789")
    assert r.detected is True
    assert r.confidence == 0.85
    assert r.category == SensitivityCategory.PERSONAL_INFO


@pytest.mark.skipif(
    True,
    reason="Requires: pip install transformers torch (heavy)",
)
def test_llm_real_model(llm_only):
    """Run with real BART-MNLI: sensitive phrase should be classified."""
    r = llm_only.detect("My credit card number is 4532015112830366 and my SSN is 123-45-6789")
    assert r.detector_name == "llm_classifier"
    # May or may not detect depending on model; at least no crash
    assert r.category in (
        SensitivityCategory.SAFE,
        SensitivityCategory.CREDENTIALS,
        SensitivityCategory.HEALTH_INFO,
        SensitivityCategory.FINANCIAL_DATA,
        SensitivityCategory.PERSONAL_INFO,
        SensitivityCategory.SOURCE_CODE,
    )
