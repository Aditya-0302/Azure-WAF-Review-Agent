"""Typed event payloads for assessment pipeline messages."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssessmentCreatedEvent(BaseModel):
    """Published by API to assessment.created queue."""

    model_config = ConfigDict(frozen=True)

    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    batch_id: uuid.UUID | None = None
    subscription_ids: list[uuid.UUID]
    pillar_filter: list[str] | None
    tag_filter: dict[str, str] | None
    requested_by_oid: uuid.UUID
    created_at: datetime


class ExtractionRequestedEvent(BaseModel):
    """Published by Preparation Agent to extraction.requested queue."""

    model_config = ConfigDict(frozen=True)

    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    batch_id: uuid.UUID
    subscription_id: uuid.UUID
    batch_index: int
    resource_ids: list[str]


class ReasoningRequestedEvent(BaseModel):
    """Published by Extraction Agent to reasoning.requested queue."""

    model_config = ConfigDict(frozen=True)

    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    batch_id: uuid.UUID
    subscription_id: uuid.UUID
    batch_index: int
    total_batches: int


class ReportingRequestedEvent(BaseModel):
    """Published by Reasoning Agent (last batch) to reporting.requested queue."""

    model_config = ConfigDict(frozen=True)

    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    batch_id: uuid.UUID | None = None
    total_findings: int


class AssessmentCancelledEvent(BaseModel):
    """Published by API to assessment.cancelled queue (informational only)."""

    model_config = ConfigDict(frozen=True)

    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    batch_id: uuid.UUID | None = None
    cancelled_by_oid: uuid.UUID
    cancelled_at: datetime
