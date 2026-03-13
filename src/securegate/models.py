"""Data models for SecureGate."""

from __future__ import annotations

from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class SensitivityCategory(str, Enum):
    """Sensitivity categories in priority order."""

    CREDENTIALS = "Credentials"
    HEALTH_INFO = "Health_Info"
    FINANCIAL_DATA = "Financial_Data"
    PERSONAL_INFO = "Personal_Info"
    SOURCE_CODE = "Source_Code"
    SAFE = "Safe"


class Action(str, Enum):
    """Action to take based on detection result."""

    ALLOW = "Allow"
    MASK = "Mask"
    BLOCK = "Block"
    QUARANTINE = "Quarantine"


class Entity(BaseModel):
    """Detected entity span."""

    type: str
    value: str
    start: int
    end: int
    confidence: float
    category: Optional[SensitivityCategory] = None


class DetectionResult(BaseModel):
    """Output of a single detector."""

    detected: bool
    category: SensitivityCategory = SensitivityCategory.SAFE
    confidence: float = 0.0
    entities: list = Field(default_factory=list)
    detector_name: str = ""
    metadata: dict = Field(default_factory=dict)


class AnalysisRequest(BaseModel):
    """Request to analyze text."""

    text: str
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    policy_id: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class DetectorDetail(BaseModel):
    """Per-detector result for analytics."""

    detector_name: str = ""
    detected: bool = False
    confidence: float = 0.0
    category: str = "Safe"
    entity_count: int = 0


class AnalysisResult(BaseModel):
    """Final result of the pipeline."""

    action: Action
    category: SensitivityCategory
    sensitivity_score: float
    entities: list = Field(default_factory=list)
    reasoning: str = ""
    masked_text: Optional[str] = None
    request_id: Optional[str] = None
    detector_results: list = Field(default_factory=list)  # List[DetectorDetail]


class Policy(BaseModel):
    """Policy configuration for detection and actions."""

    id: str
    name: str
    category_actions: dict = Field(default_factory=dict)
    thresholds: dict = Field(default_factory=dict)
    detector_weights: dict = Field(default_factory=dict)
