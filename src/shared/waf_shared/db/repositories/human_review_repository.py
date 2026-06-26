"""HumanReviewRepository — asyncpg implementation of IHumanReviewRepository."""

from __future__ import annotations

import json
import uuid
from datetime import datetime

import asyncpg

from waf_shared.db.jsonb import normalize_jsonb
from waf_shared.db.pool import DatabasePool
from waf_shared.db.repository import BaseRepository
from waf_shared.domain.errors.domain_errors import HumanReviewNotFoundError
from waf_shared.domain.models.human_review import (
    ComplianceStatus,
    EvidenceReference,
    EvidenceType,
    HumanReviewAssessment,
    ReviewAnswer,
    ReviewStatus,
)
from waf_shared.domain.repositories.i_human_review_repository import IHumanReviewRepository

_REVIEW_COLS = """
    id, tenant_id, assessment_id, control_code, pillar, reviewer_oid,
    status, compliance_status, score, answers, evidence_refs, comments,
    reviewed_at, created_at, updated_at
"""


def _row_to_review(row: asyncpg.Record) -> HumanReviewAssessment:  # type: ignore[type-arg]
    raw_answers = normalize_jsonb(row["answers"]) or []
    raw_evidence = normalize_jsonb(row["evidence_refs"]) or []

    answers = [
        ReviewAnswer(
            question_id=a["question_id"],
            answer=a["answer"],
            notes=a.get("notes"),
        )
        for a in raw_answers
    ]

    evidence_refs = [
        EvidenceReference(
            evidence_type=EvidenceType(e["evidence_type"]),
            url_or_filename=e["url_or_filename"],
            description=e["description"],
            uploaded_at=datetime.fromisoformat(e["uploaded_at"])
            if isinstance(e["uploaded_at"], str)
            else e["uploaded_at"],
        )
        for e in raw_evidence
    ]

    return HumanReviewAssessment(
        id=row["id"],
        tenant_id=row["tenant_id"],
        assessment_id=row["assessment_id"],
        control_code=row["control_code"],
        pillar=row["pillar"],
        reviewer_oid=row["reviewer_oid"],
        status=ReviewStatus(row["status"]),
        compliance_status=ComplianceStatus(row["compliance_status"]),
        score=int(row["score"]),
        answers=answers,
        evidence_refs=evidence_refs,
        comments=row["comments"],
        reviewed_at=row["reviewed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class HumanReviewRepository(BaseRepository, IHumanReviewRepository):
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(pool=pool, conn=conn, uow_tenant_id=uow_tenant_id)

    async def create(self, review: HumanReviewAssessment) -> HumanReviewAssessment:
        row = await self._write_one(
            f"""
            INSERT INTO human_review_assessments (
                id, tenant_id, assessment_id, control_code, pillar, reviewer_oid,
                status, compliance_status, score, answers, evidence_refs, comments,
                reviewed_at, created_at, updated_at
            ) VALUES (
                $1, $2, $3, $4, $5, $6,
                $7::review_status, $8::compliance_status, $9, $10::jsonb, $11::jsonb, $12,
                $13, $14, $15
            )
            RETURNING {_REVIEW_COLS}
            """,
            review.tenant_id,
            review.id,
            review.tenant_id,
            review.assessment_id,
            review.control_code,
            review.pillar,
            review.reviewer_oid,
            review.status.value,
            review.compliance_status.value,
            review.score,
            json.dumps([a.model_dump() for a in review.answers]),
            json.dumps([_evidence_to_dict(e) for e in review.evidence_refs]),
            review.comments,
            review.reviewed_at,
            review.created_at,
            review.updated_at,
        )
        if row is None:
            raise HumanReviewNotFoundError(review.assessment_id, review.control_code)
        return _row_to_review(row)

    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        review_id: uuid.UUID,
    ) -> HumanReviewAssessment | None:
        row = await self._read_one(
            f"SELECT {_REVIEW_COLS} FROM human_review_assessments "
            "WHERE tenant_id = $1 AND id = $2",
            tenant_id,
            tenant_id,
            review_id,
        )
        return _row_to_review(row) if row else None

    async def get_by_control(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        control_code: str,
    ) -> HumanReviewAssessment | None:
        row = await self._read_one(
            f"SELECT {_REVIEW_COLS} FROM human_review_assessments "
            "WHERE tenant_id = $1 AND assessment_id = $2 AND control_code = $3",
            tenant_id,
            tenant_id,
            assessment_id,
            control_code,
        )
        return _row_to_review(row) if row else None

    async def list_by_assessment(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[HumanReviewAssessment]:
        rows = await self._read(
            f"SELECT {_REVIEW_COLS} FROM human_review_assessments "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "ORDER BY control_code",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return [_row_to_review(r) for r in rows]

    async def update(self, review: HumanReviewAssessment) -> HumanReviewAssessment:
        row = await self._write_one(
            f"""
            UPDATE human_review_assessments
            SET
                reviewer_oid    = $3,
                status          = $4::review_status,
                compliance_status = $5::compliance_status,
                score           = $6,
                answers         = $7::jsonb,
                evidence_refs   = $8::jsonb,
                comments        = $9,
                reviewed_at     = $10,
                updated_at      = $11
            WHERE tenant_id = $1 AND id = $2
            RETURNING {_REVIEW_COLS}
            """,
            review.tenant_id,
            review.tenant_id,
            review.id,
            review.reviewer_oid,
            review.status.value,
            review.compliance_status.value,
            review.score,
            json.dumps([a.model_dump() for a in review.answers]),
            json.dumps([_evidence_to_dict(e) for e in review.evidence_refs]),
            review.comments,
            review.reviewed_at,
            review.updated_at,
        )
        if row is None:
            raise HumanReviewNotFoundError(review.assessment_id, review.control_code)
        return _row_to_review(row)

    async def count_by_compliance_status(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, int]:
        rows = await self._read(
            "SELECT compliance_status, COUNT(*) AS n "
            "FROM human_review_assessments "
            "WHERE tenant_id = $1 AND assessment_id = $2 "
            "GROUP BY compliance_status",
            tenant_id,
            tenant_id,
            assessment_id,
        )
        return {r["compliance_status"]: int(r["n"]) for r in rows}


def _evidence_to_dict(e: EvidenceReference) -> dict:
    return {
        "evidence_type": e.evidence_type.value,
        "url_or_filename": e.url_or_filename,
        "description": e.description,
        "uploaded_at": e.uploaded_at.isoformat(),
    }
