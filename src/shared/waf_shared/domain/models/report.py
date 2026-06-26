"""Report domain models."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AssessmentSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    total_resources: int
    total_findings: int
    findings_by_severity: dict[str, int]
    findings_by_pillar: dict[str, int]
    coverage_percentage: float


class AssessmentReport(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: uuid.UUID
    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    xlsx_blob_path: str
    pdf_blob_path: str
    summary: AssessmentSummary
    generated_at: datetime
