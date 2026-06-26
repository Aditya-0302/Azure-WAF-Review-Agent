"""Request schemas for the assessment endpoints."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CreateAssessmentSchema(BaseModel):
    model_config = ConfigDict(frozen=True)

    idempotency_key: str = Field(
        min_length=1,
        max_length=128,
        description="Client-supplied idempotency key. Same key + same params returns the existing assessment.",
    )
    subscription_ids: list[uuid.UUID] = Field(
        min_length=1,
        max_length=10,
        description="Azure subscription UUIDs to assess (1–10).",
    )
    pillar_filter: list[str] | None = Field(
        default=None,
        description="Optional WAF pillar names to restrict evaluation (e.g. ['Reliability', 'Security']).",
    )
    tag_filter: dict[str, str] | None = Field(
        default=None,
        description="Optional Azure tag key/value filter applied during resource discovery.",
    )

    @field_validator("subscription_ids")
    @classmethod
    def deduplicate_subscriptions(cls, v: list[uuid.UUID]) -> list[uuid.UUID]:
        seen: set[uuid.UUID] = set()
        result: list[uuid.UUID] = []
        for item in v:
            if item not in seen:
                seen.add(item)
                result.append(item)
        return result


class ListAssessmentsParams(BaseModel):
    model_config = ConfigDict(frozen=True)

    limit: int = Field(default=50, ge=1, le=200)
    cursor: uuid.UUID | None = None
