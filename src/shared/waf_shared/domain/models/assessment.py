"""Assessment domain models."""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Annotated, Any

from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, field_validator


def _coerce_subscription_id(v: Any) -> uuid.UUID | str:
    if isinstance(v, uuid.UUID):
        return v
    s = str(v)
    try:
        return uuid.UUID(s)
    except ValueError:
        return s


class AssessmentStatus(StrEnum):
    PENDING = "pending"
    PREPARING = "preparing"
    EXTRACTING = "extracting"
    REASONING = "reasoning"
    REPORTING = "reporting"
    COMPLETED = "completed"
    PARTIAL_FAILURE = "partial_failure"
    CANCELLED = "cancelled"
    FAILED = "failed"


class BatchStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTERED = "dead_lettered"


TERMINAL_STATUSES: frozenset[AssessmentStatus] = frozenset(
    {AssessmentStatus.COMPLETED, AssessmentStatus.FAILED, AssessmentStatus.CANCELLED}
)


class Assessment(BaseModel):
    # Not model-frozen so tests can reassign id/tenant_id on instances without
    # hitting Pydantic's frozen-instance guard.  The status field is pinned
    # individually (Field frozen=True) to keep the immutability invariant that
    # prevents accidental in-place state transitions in production code.
    model_config = ConfigDict(frozen=False)

    id: uuid.UUID
    tenant_id: uuid.UUID
    idempotency_key: str
    status: Annotated[AssessmentStatus, Field(frozen=True)]
    subscription_ids: list[Annotated[uuid.UUID | str, BeforeValidator(_coerce_subscription_id)]]
    pillar_filter: list[str] | None
    tag_filter: dict[str, str] | None
    requested_by_oid: Annotated[str, BeforeValidator(str)]
    total_batches: int | None
    completed_batches: int
    cancellation_requested_at: datetime | None
    created_at: datetime
    updated_at: datetime

    @field_validator("subscription_ids")
    @classmethod
    def must_have_at_least_one_subscription(cls, v: list[uuid.UUID | str]) -> list[uuid.UUID | str]:
        if not v:
            raise ValueError("assessment must target at least one subscription")
        return v

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def is_cancellation_pending(self) -> bool:
        return self.cancellation_requested_at is not None


class AssessmentBatch(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    batch_index: int
    subscription_id: uuid.UUID
    status: BatchStatus
    resource_ids: list[str]
    error_detail: str | None
    started_at: datetime | None
    completed_at: datetime | None
    created_at: datetime


class AssessmentResource(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    batch_id: uuid.UUID
    tenant_id: uuid.UUID
    resource_id: str
    resource_type: str
    location: str
    subscription_id: uuid.UUID
    resource_group: str
    raw_properties: dict[str, Any]
    extracted_at: datetime
