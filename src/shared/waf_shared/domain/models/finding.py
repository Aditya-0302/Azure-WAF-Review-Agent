"""Finding domain models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class FindingStatus(StrEnum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


class Finding(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    batch_id: uuid.UUID
    tenant_id: uuid.UUID
    rule_id: str
    resource_id: str
    resource_type: str
    status: FindingStatus
    severity: Severity
    pillar: str
    confidence_score: float
    title: str
    recommendation: str
    evidence: dict[str, Any]
    evaluation_type: str
    created_at: datetime
    waf_codes: list[str] = Field(default_factory=list)
    waf_titles: list[str] = Field(default_factory=list)
    microsoft_urls: list[str] = Field(default_factory=list)

    @field_validator("confidence_score")
    @classmethod
    def score_must_be_in_range(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence_score must be between 0.0 and 1.0")
        return v
