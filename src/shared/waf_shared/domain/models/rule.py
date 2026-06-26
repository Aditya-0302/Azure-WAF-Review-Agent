"""WAF Rule domain models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator


class Pillar(StrEnum):
    RELIABILITY = "reliability"
    SECURITY = "security"
    COST_OPTIMIZATION = "cost_optimization"
    OPERATIONAL_EXCELLENCE = "operational_excellence"
    PERFORMANCE_EFFICIENCY = "performance_efficiency"


class EvaluationType(StrEnum):
    DETERMINISTIC = "deterministic"
    LLM = "llm"
    HYBRID = "hybrid"
    ADVISOR_MAPPED = "advisor_mapped"


class WafRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    rule_id: str
    pillar: Pillar
    resource_types: list[str]
    evaluation_type: EvaluationType
    condition_dsl: dict[str, Any] | None
    prompt_template_ref: str | None
    severity: str
    title: str
    description: str
    recommendation: str
    is_active: bool
    version: int
    created_at: datetime
    updated_at: datetime

    @field_validator("rule_id")
    @classmethod
    def rule_id_must_match_pattern(cls, v: str) -> str:
        parts = v.split("-")
        if len(parts) < 3:  # noqa: PLR2004
            raise ValueError("rule_id must follow pattern PILLAR-RESOURCE-NNN (e.g. REL-VM-001)")
        return v

    @field_validator("condition_dsl", "prompt_template_ref")
    @classmethod
    def evaluation_source_must_be_consistent(cls, v: Any) -> Any:
        return v
