"""Decision engine: aggregates detector results and maps to actions."""

from typing import Dict, List, Optional, Tuple

from securegate.models import (
    Action,
    DetectionResult,
    Entity,
    Policy,
    SensitivityCategory,
)

# Category priority (highest first)
CATEGORY_PRIORITY = [
    SensitivityCategory.CREDENTIALS,
    SensitivityCategory.HEALTH_INFO,
    SensitivityCategory.FINANCIAL_DATA,
    SensitivityCategory.PERSONAL_INFO,
    SensitivityCategory.SOURCE_CODE,
]

DEFAULT_WEIGHTS = {
    "pattern": 0.95,
    "ner": 0.85,
    "semantic": 0.75,
    "llm_classifier": 0.70,
    "prompt_injection": 0.90,
}

DEFAULT_THRESHOLDS = {
    SensitivityCategory.CREDENTIALS: 0.70,
    SensitivityCategory.HEALTH_INFO: 0.70,
    SensitivityCategory.FINANCIAL_DATA: 0.70,
    SensitivityCategory.PERSONAL_INFO: 0.70,
    SensitivityCategory.SOURCE_CODE: 0.75,
}

DEFAULT_ACTIONS = {
    SensitivityCategory.CREDENTIALS: Action.BLOCK,
    SensitivityCategory.HEALTH_INFO: Action.QUARANTINE,
    SensitivityCategory.FINANCIAL_DATA: Action.MASK,
    SensitivityCategory.PERSONAL_INFO: Action.MASK,
    SensitivityCategory.SOURCE_CODE: Action.QUARANTINE,
    SensitivityCategory.SAFE: Action.ALLOW,
}


def aggregate_results(
    results: list,
    weights: dict = None,
) -> dict:
    """Aggregate weighted scores per category."""
    w = weights or DEFAULT_WEIGHTS
    scores = {}

    for r in results:
        if not r.detected:
            continue
        weight = w.get(r.detector_name, 0.7)
        weighted = r.confidence * weight
        if r.category not in scores or weighted > scores[r.category]:
            scores[r.category] = weighted

    return scores


def decide(
    scores: Dict,
    policy: Optional[Policy] = None,
) -> Tuple[Action, SensitivityCategory, float, str]:
    """Decide action from aggregated scores. Returns (action, category, score, reasoning)."""
    thresholds = (policy and policy.thresholds) or DEFAULT_THRESHOLDS
    actions_map = (policy and policy.category_actions) or DEFAULT_ACTIONS

    for cat in CATEGORY_PRIORITY:
        score = scores.get(cat, 0.0)
        thresh = thresholds.get(cat, 0.70)
        if score >= thresh:
            action = actions_map.get(cat, DEFAULT_ACTIONS.get(cat, Action.MASK))
            reason = f"{cat.value} detected (score={score:.2f} >= {thresh}) -> {action.value}"
            return action, cat, score, reason

    return Action.ALLOW, SensitivityCategory.SAFE, 0.0, "No sensitive data detected"


def merge_entities(results: List) -> List:
    """Merge entities from all detectors, deduplicated by span."""
    seen = set()
    out = []
    for r in results:
        for e in r.entities:
            key = (e.start, e.end, e.type)
            if key not in seen:
                seen.add(key)
                out.append(e)
    return sorted(out, key=lambda x: (x.start, -x.end))  # type: ignore
