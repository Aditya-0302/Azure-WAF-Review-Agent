"""Human review router — endpoints for SE-10, OE-03, OE-04, CO-09 review lifecycle."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, status

from waf_api.dependencies.db import get_db_pool
from waf_api.dependencies.rbac import require_role
from waf_api.schemas.requests.human_review_requests import (
    SubmitHumanReviewSchema,
    UpdateHumanReviewSchema,
)
from waf_api.services.human_review_service import HumanReviewService
from waf_shared.db.pool import DatabasePool
from waf_shared.domain.models.human_review import (
    HumanReviewAssessment,
    HumanReviewControl,
    HumanReviewSummary,
)
from waf_shared.domain.models.tenant import UserRole
from waf_shared.telemetry.logging import StructuredLogger

router = APIRouter(prefix="/v1/human-review", tags=["human-review"])
_logger = StructuredLogger(service="waf-api", version="0.1.0")


def _get_service(pool: DatabasePool = Depends(get_db_pool)) -> HumanReviewService:
    return HumanReviewService(pool=pool)


# ── Control catalog ────────────────────────────────────────────────────────────


@router.get(
    "/controls",
    response_model=list[HumanReviewControl],
    status_code=status.HTTP_200_OK,
    summary="List all human-review WAF controls with their questionnaires",
)
async def list_controls(
    auth: Annotated[
        object,
        Depends(
            require_role(
                UserRole.TENANT_ADMIN,
                UserRole.TENANT_VIEWER,
                UserRole.PLATFORM_ADMIN,
            )
        ),
    ],
    svc: HumanReviewService = Depends(_get_service),
) -> list[HumanReviewControl]:
    return svc.list_controls()


@router.get(
    "/controls/{code}",
    response_model=HumanReviewControl,
    status_code=status.HTTP_200_OK,
    summary="Get a single human-review control with its questionnaire",
)
async def get_control(
    code: str,
    auth: Annotated[
        object,
        Depends(
            require_role(
                UserRole.TENANT_ADMIN,
                UserRole.TENANT_VIEWER,
                UserRole.PLATFORM_ADMIN,
            )
        ),
    ],
    svc: HumanReviewService = Depends(_get_service),
) -> HumanReviewControl:
    return svc.get_control(code)


# ── Review lifecycle ────────────────────────────────────────────────────────────


@router.get(
    "/assessments/{assessment_id}/reviews",
    response_model=list[HumanReviewAssessment],
    status_code=status.HTTP_200_OK,
    summary="List all human reviews for an assessment",
)
async def list_reviews(
    assessment_id: uuid.UUID,
    auth: Annotated[
        object,
        Depends(
            require_role(
                UserRole.TENANT_ADMIN,
                UserRole.TENANT_VIEWER,
                UserRole.PLATFORM_ADMIN,
            )
        ),
    ],
    svc: HumanReviewService = Depends(_get_service),
) -> list[HumanReviewAssessment]:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    return await svc.list_reviews(auth_ctx.tenant_id, assessment_id)


@router.get(
    "/assessments/{assessment_id}/reviews/{control_code}",
    response_model=HumanReviewAssessment,
    status_code=status.HTTP_200_OK,
    summary="Get the human review for a specific WAF control within an assessment",
)
async def get_review(
    assessment_id: uuid.UUID,
    control_code: str,
    auth: Annotated[
        object,
        Depends(
            require_role(
                UserRole.TENANT_ADMIN,
                UserRole.TENANT_VIEWER,
                UserRole.PLATFORM_ADMIN,
            )
        ),
    ],
    svc: HumanReviewService = Depends(_get_service),
) -> HumanReviewAssessment:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    return await svc.get_review(auth_ctx.tenant_id, assessment_id, control_code)


@router.post(
    "/assessments/{assessment_id}/reviews",
    response_model=HumanReviewAssessment,
    status_code=status.HTTP_201_CREATED,
    summary="Submit or update a human review for a WAF control",
)
async def submit_review(
    assessment_id: uuid.UUID,
    body: SubmitHumanReviewSchema,
    auth: Annotated[
        object,
        Depends(require_role(UserRole.TENANT_ADMIN, UserRole.PLATFORM_ADMIN)),
    ],
    svc: HumanReviewService = Depends(_get_service),
) -> HumanReviewAssessment:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    return await svc.submit_review(
        tenant_id=auth_ctx.tenant_id,
        assessment_id=assessment_id,
        reviewer_oid=str(auth_ctx.entra_oid),
        control_code=body.control_code,
        compliance_status=body.compliance_status,
        score=body.score,
        answers=[a.model_dump() for a in body.answers],
        evidence_refs=[e.model_dump() for e in body.evidence_refs],
        comments=body.comments,
    )


@router.put(
    "/assessments/{assessment_id}/reviews/{control_code}",
    response_model=HumanReviewAssessment,
    status_code=status.HTTP_200_OK,
    summary="Update an existing human review for a WAF control",
)
async def update_review(
    assessment_id: uuid.UUID,
    control_code: str,
    body: UpdateHumanReviewSchema,
    auth: Annotated[
        object,
        Depends(require_role(UserRole.TENANT_ADMIN, UserRole.PLATFORM_ADMIN)),
    ],
    svc: HumanReviewService = Depends(_get_service),
) -> HumanReviewAssessment:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]

    existing = await svc.get_review(auth_ctx.tenant_id, assessment_id, control_code)

    compliance_status = body.compliance_status or existing.compliance_status.value
    score = body.score if body.score is not None else existing.score
    answers = (
        [a.model_dump() for a in body.answers]
        if body.answers is not None
        else [
            {"question_id": a.question_id, "answer": a.answer, "notes": a.notes}
            for a in existing.answers
        ]
    )
    evidence_refs = (
        [e.model_dump() for e in body.evidence_refs]
        if body.evidence_refs is not None
        else [
            {
                "evidence_type": e.evidence_type.value,
                "url_or_filename": e.url_or_filename,
                "description": e.description,
                "uploaded_at": e.uploaded_at.isoformat(),
            }
            for e in existing.evidence_refs
        ]
    )
    comments = body.comments if body.comments is not None else existing.comments

    return await svc.submit_review(
        tenant_id=auth_ctx.tenant_id,
        assessment_id=assessment_id,
        reviewer_oid=str(auth_ctx.entra_oid),
        control_code=control_code,
        compliance_status=compliance_status,
        score=score,
        answers=answers,
        evidence_refs=evidence_refs,
        comments=comments,
    )


# ── Executive dashboard summary ────────────────────────────────────────────────


@router.get(
    "/assessments/{assessment_id}/summary",
    response_model=HumanReviewSummary,
    status_code=status.HTTP_200_OK,
    summary="Get human review summary and total framework coverage for an assessment",
)
async def get_summary(
    assessment_id: uuid.UUID,
    auth: Annotated[
        object,
        Depends(
            require_role(
                UserRole.TENANT_ADMIN,
                UserRole.TENANT_VIEWER,
                UserRole.PLATFORM_ADMIN,
            )
        ),
    ],
    svc: HumanReviewService = Depends(_get_service),
) -> HumanReviewSummary:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    return await svc.get_summary(auth_ctx.tenant_id, assessment_id)
