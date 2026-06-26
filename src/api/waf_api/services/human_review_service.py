"""HumanReviewService — orchestrates the human review lifecycle.

Responsibilities:
  - Load human review controls from catalog JSON (in-process, no DB)
  - Create or update HumanReviewAssessment records
  - Compute per-assessment human review summary for dashboard
  - Combine automated coverage (53/57 = 93%) with human review results
    to produce total framework coverage (up to 100%)

Does NOT know about: HTTP, SQL syntax, Azure SDK types, or Service Bus.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.human_review_repository import HumanReviewRepository
from waf_shared.domain.errors.domain_errors import (
    HumanReviewControlNotFoundError,
    HumanReviewNotFoundError,
)
from waf_shared.domain.models.human_review import (
    ComplianceStatus,
    EvidenceReference,
    EvidenceType,
    HumanReviewAssessment,
    HumanReviewControl,
    HumanReviewQuestion,
    HumanReviewSummary,
    ReviewAnswer,
    ReviewStatus,
)
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")

_CATALOG_PATH = (
    Path(__file__).resolve().parent.parent.parent.parent
    / "shared"
    / "waf_catalog"
    / "human_review_controls.json"
)
if not _CATALOG_PATH.exists():
    raise FileNotFoundError(
        f"Human Review Catalog not found: {_CATALOG_PATH}\n"
        "Expected at src/shared/waf_catalog/human_review_controls.json "
        "relative to the repository root."
    )

_AUTOMATED_COVERED = 53
_TOTAL_CONTROLS = 57
_AUTOMATED_PERCENTAGE = round(_AUTOMATED_COVERED / _TOTAL_CONTROLS * 100, 1)

_COMPLIANT_STATUSES = frozenset(
    {
        ComplianceStatus.COMPLIANT,
        ComplianceStatus.PARTIALLY_COMPLIANT,
    }
)


def _load_controls() -> dict[str, HumanReviewControl]:
    raw = json.loads(_CATALOG_PATH.read_text(encoding="utf-8"))
    result: dict[str, HumanReviewControl] = {}
    for ctrl in raw["controls"]:
        questions = [
            HumanReviewQuestion(
                id=q["id"],
                text=q["text"],
                type=q["type"],
                options=q.get("options", []),
                required=q["required"],
                evidence_required=q["evidence_required"],
                accepted_types=q.get("accepted_types", []),
            )
            for q in ctrl["questions"]
        ]
        result[ctrl["code"]] = HumanReviewControl(
            code=ctrl["code"],
            pillar=ctrl["pillar"],
            title=ctrl["title"],
            microsoft_url=ctrl["microsoft_url"],
            review_required=ctrl["review_required"],
            reason_for_human_review=ctrl["reason_for_human_review"],
            questions=questions,
        )
    return result


_CONTROLS: dict[str, HumanReviewControl] = _load_controls()


class HumanReviewService:
    def __init__(self, pool: DatabasePool) -> None:
        self._pool = pool
        self._repo = HumanReviewRepository(pool=pool)

    def list_controls(self) -> list[HumanReviewControl]:
        return list(_CONTROLS.values())

    def get_control(self, code: str) -> HumanReviewControl:
        ctrl = _CONTROLS.get(code)
        if ctrl is None:
            raise HumanReviewControlNotFoundError(code)
        return ctrl

    async def submit_review(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        reviewer_oid: str,
        control_code: str,
        compliance_status: str,
        score: int,
        answers: list[dict],
        evidence_refs: list[dict],
        comments: str | None,
    ) -> HumanReviewAssessment:
        ctrl = self.get_control(control_code)

        existing = await self._repo.get_by_control(tenant_id, assessment_id, control_code)

        now = datetime.now(UTC)
        parsed_answers = [
            ReviewAnswer(
                question_id=a["question_id"],
                answer=a["answer"],
                notes=a.get("notes"),
            )
            for a in answers
        ]
        parsed_evidence = [
            EvidenceReference(
                evidence_type=EvidenceType(e["evidence_type"]),
                url_or_filename=e["url_or_filename"],
                description=e["description"],
                uploaded_at=now,
            )
            for e in evidence_refs
        ]
        cs = ComplianceStatus(compliance_status)
        reviewed_at = now if cs != ComplianceStatus.NOT_ASSESSED else None
        status = (
            ReviewStatus.COMPLETED
            if cs != ComplianceStatus.NOT_ASSESSED
            else ReviewStatus.IN_PROGRESS
        )

        if existing is not None:
            existing.reviewer_oid = reviewer_oid
            existing.status = status
            existing.compliance_status = cs
            existing.score = score
            existing.answers = parsed_answers
            existing.evidence_refs = parsed_evidence
            existing.comments = comments
            existing.reviewed_at = reviewed_at
            existing.updated_at = now
            saved = await self._repo.update(existing)
        else:
            review = HumanReviewAssessment(
                id=uuid.uuid4(),
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                control_code=control_code,
                pillar=ctrl.pillar,
                reviewer_oid=reviewer_oid,
                status=status,
                compliance_status=cs,
                score=score,
                answers=parsed_answers,
                evidence_refs=parsed_evidence,
                comments=comments,
                reviewed_at=reviewed_at,
                created_at=now,
                updated_at=now,
            )
            saved = await self._repo.create(review)

        _logger.info(
            "human_review.submitted",
            assessment_id=str(assessment_id),
            control_code=control_code,
            compliance_status=compliance_status,
            score=score,
            tenant_id=str(tenant_id),
        )
        return saved

    async def get_review(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        control_code: str,
    ) -> HumanReviewAssessment:
        review = await self._repo.get_by_control(tenant_id, assessment_id, control_code)
        if review is None:
            raise HumanReviewNotFoundError(assessment_id, control_code)
        return review

    async def list_reviews(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[HumanReviewAssessment]:
        return await self._repo.list_by_assessment(tenant_id, assessment_id)

    async def get_summary(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> HumanReviewSummary:
        reviews = await self._repo.list_by_assessment(tenant_id, assessment_id)
        completed = [r for r in reviews if r.status == ReviewStatus.COMPLETED]
        compliant = [r for r in completed if r.compliance_status in _COMPLIANT_STATUSES]
        pending_count = len(_CONTROLS) - len(completed)

        human_covered = len(compliant)
        total_covered = _AUTOMATED_COVERED + human_covered
        total_pct = round(total_covered / _TOTAL_CONTROLS * 100, 1)

        return HumanReviewSummary(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            automated_coverage_percentage=_AUTOMATED_PERCENTAGE,
            automated_controls_covered=_AUTOMATED_COVERED,
            automated_controls_total=_TOTAL_CONTROLS,
            human_review_total=len(_CONTROLS),
            human_review_completed=len(completed),
            human_review_compliant=human_covered,
            human_review_pending=max(pending_count, 0),
            total_framework_coverage_percentage=total_pct,
            total_controls=_TOTAL_CONTROLS,
            reviews=reviews,
        )
