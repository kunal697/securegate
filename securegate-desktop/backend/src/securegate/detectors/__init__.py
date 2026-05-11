"""Detection modules."""

from securegate.detectors.base import BaseDetector
from securegate.detectors.llm_classifier import LLMClassifier
from securegate.detectors.ner import NERDetector
from securegate.detectors.pattern import PatternDetector
from securegate.detectors.prompt_injection import PromptInjectionDetector
from securegate.detectors.semantic import SemanticAnalyzer
from securegate.detectors.custom_llm import CustomLLMDetector

from securegate.detectors.pii_masker import PIIMaskerDetector

try:
    from securegate.detectors.gliner_ner import GLiNERDetector
except ImportError:
    GLiNERDetector = None  # pip install -r requirements-gliner.txt to enable

__all__ = [
    "BaseDetector",
    "PatternDetector",
    "NERDetector",
    "GLiNERDetector",
    "PIIMaskerDetector",
    "SemanticAnalyzer",
    "LLMClassifier",
    "CustomLLMDetector",
    "PromptInjectionDetector",
]
