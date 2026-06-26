"""Human review domain models.

Represents the review lifecycle for the four WAF controls that cannot be
objectively assessed via Azure APIs:
  SE-10 — Adversarial testing
  OE-03 — Software planning management
  OE-04 — Continuous integration
  CO-09 — Personnel time optimisation

A HumanReviewAssessment ties a specific WAF assessment run to a reviewer's
structured questionnaire responses, evidence references, and compliance verdict.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ReviewStatus(StrEnum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    NOT_ASSESSED = "not_assessed"


class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_ASSESSED = "not_assessed"


class EvidenceType(StrEnum):
    PDF = "pdf"
    DOCX = "docx"
    PPTX = "pptx"
    PNG = "png"
    JPG = "jpg"
    LINK = "link"


class HumanReviewQuestion(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    text: str
    type: str
    options: list[str] = Field(default_factory=list)
    required: bool
    evidence_required: bool
    accepted_types: list[str] = Field(default_factory=list)


class HumanReviewControl(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    pillar: str
    title: str
    microsoft_url: str
    review_required: bool
    reason_for_human_review: str
    questions: list[HumanReviewQuestion]


class EvidenceReference(BaseModel):
    model_config = ConfigDict(frozen=True)

    evidence_type: EvidenceType
    url_or_filename: str
    description: str
    uploaded_at: datetime


class ReviewAnswer(BaseModel):
    model_config = ConfigDict(frozen=True)

    question_id: str
    answer: Any
    notes: str | None = None


class HumanReviewAssessment(BaseModel):
    model_config = ConfigDict(frozen=False)

    id: uuid.UUID
    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    control_code: str
    pillar: str
    reviewer_oid: str
    status: ReviewStatus
    compliance_status: ComplianceStatus
    score: int
    answers: list[ReviewAnswer] = Field(default_factory=list)
    evidence_refs: list[EvidenceReference] = Field(default_factory=list)
    comments: str | None = None
    reviewed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime

    @field_validator("score")
    @classmethod
    def score_must_be_in_range(cls, v: int) -> int:
        if not 0 <= v <= 100:  # noqa: PLR2004
            raise ValueError("score must be between 0 and 100")
        return v


class HumanReviewSummary(BaseModel):
    model_config = ConfigDict(frozen=True)

    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    automated_coverage_percentage: float
    automated_controls_covered: int
    automated_controls_total: int
    human_review_total: int
    human_review_completed: int
    human_review_compliant: int
    human_review_pending: int
    total_framework_coverage_percentage: float
    total_controls: int
    reviews: list[HumanReviewAssessment] = Field(default_factory=list)
