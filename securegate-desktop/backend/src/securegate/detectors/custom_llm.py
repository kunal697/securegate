import logging
import os
import re
import math
import joblib
import pandas as pd
import numpy as np
from typing import Optional, Dict, Any
from scipy.sparse import hstack, csr_matrix

from securegate.detectors.base import BaseDetector
from securegate.models import DetectionResult, SensitivityCategory, Entity

logger = logging.getLogger(__name__)

# --- COMPLETE class definition from your training notebook ---
class SensitiveDataLeakageDetector:
    def __init__(self, xgb_model, lgbm_model, binary_model, tfidf, char_tfidf):
        self.xgb_model = xgb_model
        self.lgbm_model = lgbm_model
        self.binary_model = binary_model
        self.tfidf = tfidf
        self.char_tfidf = char_tfidf
        self.PATTERNS = {
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "phone": r"(\+?\d[\d\s\-\(\)]{7,}\d)",
            "aadhaar": r"\b\d{4}\s\d{4}\s\d{4}\b",
            "pan": r"\b[A-Z]{5}\d{4}[A-Z]\b",
            "api_key": r"(sk-[a-zA-Z0-9\-_]{20,}|AKIA[A-Z0-9]{16,})"
        }
        self.RISK_NAMES = {0: "Safe", 1: "High", 2: "Critical"}

    def compute_entropy(self, s):
        if not s: return 0
        freq = {}
        for c in s: freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())

    def extract_features(self, text):
        feats = {}
        lower = text.lower()
        EXFIL_WORDS = ["upload", "github", "external", "publicly", "share"]
        SAFE_WORDS = ["internal", "secure", "encrypted"]
        for name, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            feats[f"count_{name}"] = len(matches)
            feats[f"has_{name}"] = int(len(matches) > 0)
        feats["exfil_score"] = sum(1 for w in EXFIL_WORDS if w in lower)
        feats["safe_score"] = sum(1 for w in SAFE_WORDS if w in lower)
        feats["text_length"] = len(text)
        feats["word_count"] = len(text.split())
        feats["entropy"] = self.compute_entropy(text)
        return feats

    def detect_entities(self, text):
        entities = {}
        for name, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches: entities[name] = matches
        return entities

    def redact_text(self, text):
        entities = self.detect_entities(text)
        redacted = text
        for category, matches in entities.items():
            for match in matches:
                placeholder = f"[REDACTED_{category.upper()}]"
                redacted = redacted.replace(match, placeholder)
        return redacted

    def analyze(self, text):
        feats = self.extract_features(text)
        feat_df = pd.DataFrame([feats])
        X_word = self.tfidf.transform([text])
        X_char = self.char_tfidf.transform([text])
        X_hand = csr_matrix(feat_df.values)
        X = hstack([X_word, X_char, X_hand])
        
        xgb_probs = self.xgb_model.predict_proba(X)
        lgb_probs = self.lgbm_model.predict_proba(X)
        final_probs = (0.5 * xgb_probs + 0.5 * lgb_probs)
        
        risk_idx = int(np.argmax(final_probs))
        risk_label = self.RISK_NAMES[risk_idx]
        
        entities = self.detect_entities(text)
        redacted_text = self.redact_text(text)
        
        rule_score = 0
        if entities: rule_score += 40
        if "key" in text.lower() or "secret" in text.lower(): rule_score += 20
        if feats['exfil_score'] > 0: rule_score += 20
        
        final_risk = risk_label
        if rule_score >= 80 and risk_label == "Safe":
            final_risk = "High"
            
        return {
            "risk_score": float(np.max(final_probs)),
            "risk_label": risk_label,
            "entities": entities,
            "redacted_text": redacted_text,
            "final_risk": final_risk
        }

# --- SecureGate Detector Wrapper ---

class CustomLLMDetector(BaseDetector):
    name = "custom_llm"

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or os.getenv("SECUREGATE_CUSTOM_MODEL_PATH", "llm/SecureGate_Detector_redact_text_v2.pkl")
        self.detector = None
        self._load_model()

    def _load_model(self):
        if not os.path.exists(self.model_path):
            logger.warning(f"Custom model not found at {self.model_path}")
            return
        try:
            import sys
            original_main = sys.modules.get('__main__')
            class Shim: pass
            shim = Shim()
            shim.SensitiveDataLeakageDetector = SensitiveDataLeakageDetector
            sys.modules['__main__'] = shim
            try:
                self.detector = joblib.load(self.model_path)
                logger.info(f"Loaded custom model from {self.model_path}")
            finally:
                if original_main: sys.modules['__main__'] = original_main
        except Exception as e:
            logger.error(f"Failed to load custom model: {e}")

    def detect(self, text: str, context: Optional[Dict[str, Any]] = None) -> DetectionResult:
        if not self.detector or not text:
            return DetectionResult(detected=False, detector_name=self.name)

        try:
            # CALL YOUR MODEL'S NATIVE ANALYZE METHOD
            res = self.detector.analyze(text)
            
            risk_label = res["final_risk"]
            confidence = res["risk_score"]
            
            if risk_label == "Safe":
                return DetectionResult(detected=False, detector_name=self.name)
            
            # Map risk to category
            category = SensitivityCategory.PERSONAL_INFO
            if risk_label == "Critical":
                if "api_key" in res["entities"] or "token" in text.lower():
                    category = SensitivityCategory.CREDENTIALS
                else:
                    category = SensitivityCategory.FINANCIAL_DATA
            
            # Convert entities to SecureGate format
            entities_list = []
            for cat, vals in res["entities"].items():
                for v in vals:
                    for m in re.finditer(re.escape(v), text, re.IGNORECASE):
                        entities_list.append(Entity(
                            type=cat, value=v, start=m.start(), end=m.end(),
                            confidence=confidence, category=category
                        ))

            return DetectionResult(
                detected=True, category=category, confidence=confidence,
                entities=entities_list, detector_name=self.name,
                metadata={"redacted_text": res["redacted_text"]}
            )

        except Exception as e:
            logger.error(f"CustomLLMDetector analyze failed: {e}")
            return DetectionResult(detected=False, detector_name=self.name)
