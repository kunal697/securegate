"""Tests for LLM (zero-shot) Classifier detector."""

import pytest

from securegate.detectors.llm_classifier import LLMClassifier, _LABELS, _LABEL_TO_CATEGORY
from securegate.models import SensitivityCategory


def test_llm_classifier_empty_input():
    det = LLMClassifier(min_score=0.75, max_length=500)
    r = det.detect("")
    assert r.detected is False
    assert r.detector_name == "llm_classifier"
    assert r.category == SensitivityCategory.SAFE
    assert r.entities == []


def test_llm_classifier_labels_mapping():
    assert "safe general text" in _LABELS
    assert _LABEL_TO_CATEGORY["contains passwords or API keys"] == SensitivityCategory.CREDENTIALS
    assert _LABEL_TO_CATEGORY["contains medical patient information"] == SensitivityCategory.HEALTH_INFO


def test_llm_classifier_mocked_pipeline_safe():
    """Test LLM classifier with mocked pipeline returning 'safe'."""
    from unittest.mock import MagicMock, patch

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["safe general text", "contains personal identity information"],
        "scores": [0.9, 0.1],
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("What is the capital of France?")
    assert r.detected is False
    assert r.category == SensitivityCategory.SAFE


def test_llm_classifier_mocked_pipeline_sensitive():
    """Test LLM classifier with mocked pipeline returning sensitive label."""
    from unittest.mock import MagicMock, patch

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["contains passwords or API keys", "safe general text"],
        "scores": [0.88, 0.1],
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("my api key is sk-xxx")
    assert r.detected is True
    assert r.category == SensitivityCategory.CREDENTIALS
    assert r.confidence == 0.88


def test_llm_classifier_mocked_pipeline_tensor_scores():
    """Test that tensor scores are converted to float."""
    from unittest.mock import MagicMock, patch

    class FakeTensor:
        def item(self):
            return 0.82

    mock_pipe = MagicMock()
    mock_pipe.return_value = {
        "labels": ["contains personal identity information"],
        "scores": [FakeTensor()],
    }

    with patch.object(LLMClassifier, "_get_pipeline", return_value=mock_pipe):
        det = LLMClassifier(min_score=0.75)
        r = det.detect("My name is John and SSN 123-45-6789")
    assert r.detected is True
    assert r.confidence == 0.82
