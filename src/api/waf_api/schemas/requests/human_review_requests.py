"""Request schemas for human review endpoints."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, field_validator


class ReviewAnswerSchema(BaseModel):
    question_id: str = Field(min_length=1, max_length=64)
    answer: Any
    notes: str | None = Field(default=None, max_length=2000)


class EvidenceReferenceSchema(BaseModel):
    evidence_type: str = Field(description="pdf | docx | pptx | png | jpg | link")
    url_or_filename: str = Field(min_length=1, max_length=2048)
    description: str = Field(min_length=1, max_length=500)

    @field_validator("evidence_type")
    @classmethod
    def evidence_type_must_be_valid(cls, v: str) -> str:
        allowed = {"pdf", "docx", "pptx", "png", "jpg", "link"}
        if v.lower() not in allowed:
            raise ValueError(f"evidence_type must be one of: {', '.join(sorted(allowed))}")
        return v.lower()


class SubmitHumanReviewSchema(BaseModel):
    control_code: str = Field(
        min_length=4,
        max_length=8,
        description="WAF control code, e.g. SE-10",
    )
    compliance_status: str = Field(
        description="compliant | partially_compliant | non_compliant | not_assessed",
    )
    score: int = Field(
        ge=0,
        le=100,
        description="Reviewer score 0-100",
    )
    answers: list[ReviewAnswerSchema] = Field(
        default_factory=list,
        description="Structured answers to the control questionnaire",
    )
    evidence_refs: list[EvidenceReferenceSchema] = Field(
        default_factory=list,
        description="Evidence files or links that support this review",
    )
    comments: str | None = Field(
        default=None,
        max_length=5000,
        description="Free-text reviewer comments",
    )

    @field_validator("compliance_status")
    @classmethod
    def compliance_status_must_be_valid(cls, v: str) -> str:
        allowed = {"compliant", "partially_compliant", "non_compliant", "not_assessed"}
        if v not in allowed:
            raise ValueError(f"compliance_status must be one of: {', '.join(sorted(allowed))}")
        return v

    @field_validator("control_code")
    @classmethod
    def control_code_must_be_known(cls, v: str) -> str:
        known = {"SE-10", "OE-03", "OE-04", "CO-09"}
        if v not in known:
            raise ValueError(
                f"control_code must be one of the human-review controls: "
                f"{', '.join(sorted(known))}"
            )
        return v


class UpdateHumanReviewSchema(BaseModel):
    compliance_status: str | None = Field(
        default=None,
        description="Updated compliance verdict",
    )
    score: int | None = Field(
        default=None,
        ge=0,
        le=100,
    )
    answers: list[ReviewAnswerSchema] | None = Field(
        default=None,
    )
    evidence_refs: list[EvidenceReferenceSchema] | None = Field(
        default=None,
    )
    comments: str | None = Field(
        default=None,
        max_length=5000,
    )

    @field_validator("compliance_status")
    @classmethod
    def compliance_status_must_be_valid(cls, v: str | None) -> str | None:
        if v is None:
            return v
        allowed = {"compliant", "partially_compliant", "non_compliant", "not_assessed"}
        if v not in allowed:
            raise ValueError(f"compliance_status must be one of: {', '.join(sorted(allowed))}")
        return v
