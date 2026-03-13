"""Tests for Preprocessor."""

import pytest

from securegate.preprocessor import preprocess


def test_preprocess_normal():
    assert preprocess("  hello   world  ") == "hello world"


def test_preprocess_empty():
    assert preprocess("") == ""
    assert preprocess("   \n\t  ") == ""


def test_preprocess_not_string():
    assert preprocess(None) == ""  # type: ignore
    assert preprocess(123) == ""   # type: ignore


def test_preprocess_unicode():
    # NFKC normalization
    assert preprocess("café")  # normalized
    assert " " in preprocess("a   b") and preprocess("a   b").strip() == "a b"
