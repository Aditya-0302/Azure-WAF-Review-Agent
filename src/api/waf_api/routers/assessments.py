"""Assessments router — CRUD + lifecycle endpoints for WAF assessments."""

from __future__ import annotations

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.db.repositories.report_repository import ReportRepository
from waf_shared.domain.models.assessment import Assessment
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.report import AssessmentReport
from waf_shared.domain.models.tenant import UserRole
from waf_shared.telemetry.logging import StructuredLogger

from waf_api.dependencies.db import get_db_pool
from waf_api.dependencies.rbac import get_auth_context, require_role
from waf_api.schemas.requests.assessment_requests import CreateAssessmentSchema
from waf_api.schemas.responses.pagination_response import PaginatedResponse, PaginationMeta
from waf_api.services.assessment_service import AssessmentService, CreateAssessmentRequest

router = APIRouter(prefix="/v1/assessments", tags=["assessments"])
_logger = StructuredLogger(service="waf-api", version="0.1.0")


def _get_assessment_service(
    request: Request,
    pool: DatabasePool = Depends(get_db_pool),
) -> AssessmentService:
    return AssessmentService(pool=pool, publisher=request.app.state.publisher)


@router.post(
    "",
    response_model=Assessment,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create a new WAF assessment",
)
async def create_assessment(
    body: CreateAssessmentSchema,
    auth: Annotated[object, Depends(require_role(UserRole.TENANT_ADMIN, UserRole.PLATFORM_ADMIN))],
    svc: AssessmentService = Depends(_get_assessment_service),
) -> Assessment:
    from waf_api.middleware.auth import AuthContext  # avoid circular at module level

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    req = CreateAssessmentRequest(
        tenant_id=auth_ctx.tenant_id,
        idempotency_key=body.idempotency_key,
        subscription_ids=body.subscription_ids,
        pillar_filter=body.pillar_filter,
        tag_filter=body.tag_filter,
        requested_by_oid=auth_ctx.entra_oid,
    )
    return await svc.create_assessment(req)


@router.get(
    "/{assessment_id}",
    response_model=Assessment,
    status_code=status.HTTP_200_OK,
    summary="Get an assessment by ID",
)
async def get_assessment(
    assessment_id: uuid.UUID,
    auth: Annotated[object, Depends(require_role(UserRole.TENANT_ADMIN, UserRole.TENANT_VIEWER, UserRole.PLATFORM_ADMIN))],
    svc: AssessmentService = Depends(_get_assessment_service),
) -> Assessment:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    return await svc.get_assessment(assessment_id, auth_ctx.tenant_id)


@router.get(
    "",
    response_model=PaginatedResponse[Assessment],
    status_code=status.HTTP_200_OK,
    summary="List assessments for the caller's tenant",
)
async def list_assessments(
    auth: Annotated[object, Depends(require_role(UserRole.TENANT_ADMIN, UserRole.TENANT_VIEWER, UserRole.PLATFORM_ADMIN))],
    svc: AssessmentService = Depends(_get_assessment_service),
    limit: int = 50,
    cursor: uuid.UUID | None = None,
) -> PaginatedResponse[Assessment]:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    items = await svc.list_assessments(auth_ctx.tenant_id, limit=limit, cursor=cursor)
    next_cursor = str(items[-1].id) if len(items) == limit else None
    return PaginatedResponse(
        items=items,
        pagination=PaginationMeta(
            has_more=next_cursor is not None,
            next_cursor=next_cursor,
        ),
    )


@router.post(
    "/{assessment_id}/cancel",
    response_model=Assessment,
    status_code=status.HTTP_200_OK,
    summary="Request cancellation of an in-progress assessment",
)
async def cancel_assessment(
    assessment_id: uuid.UUID,
    auth: Annotated[object, Depends(require_role(UserRole.TENANT_ADMIN, UserRole.PLATFORM_ADMIN))],
    svc: AssessmentService = Depends(_get_assessment_service),
) -> Assessment:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    return await svc.cancel_assessment(assessment_id, auth_ctx.tenant_id)


@router.get(
    "/{assessment_id}/findings",
    response_model=PaginatedResponse[Finding],
    status_code=status.HTTP_200_OK,
    summary="List findings for an assessment",
)
async def list_findings(
    assessment_id: uuid.UUID,
    auth: Annotated[object, Depends(require_role(UserRole.TENANT_ADMIN, UserRole.TENANT_VIEWER, UserRole.PLATFORM_ADMIN))],
    pool: DatabasePool = Depends(get_db_pool),
    severity: Severity | None = None,
    pillar: str | None = None,
    finding_status: FindingStatus | None = None,
    limit: int = 100,
    cursor: uuid.UUID | None = None,
) -> PaginatedResponse[Finding]:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    repo = FindingRepository(pool=pool)
    items = await repo.list_by_assessment(
        tenant_id=auth_ctx.tenant_id,
        assessment_id=assessment_id,
        severity=severity,
        pillar=pillar,
        status=finding_status,
        limit=limit,
        cursor=cursor,
    )
    next_cursor = str(items[-1].id) if len(items) == limit else None
    return PaginatedResponse(
        items=items,
        pagination=PaginationMeta(
            has_more=next_cursor is not None,
            next_cursor=next_cursor,
        ),
    )


@router.get(
    "/{assessment_id}/report",
    response_model=AssessmentReport,
    status_code=status.HTTP_200_OK,
    summary="Get the generated report for an assessment",
)
async def get_report(
    assessment_id: uuid.UUID,
    auth: Annotated[object, Depends(require_role(UserRole.TENANT_ADMIN, UserRole.TENANT_VIEWER, UserRole.PLATFORM_ADMIN))],
    pool: DatabasePool = Depends(get_db_pool),
) -> AssessmentReport:
    from waf_api.middleware.auth import AuthContext

    auth_ctx: AuthContext = auth  # type: ignore[assignment]
    repo = ReportRepository(pool=pool)
    report = await repo.get_by_assessment(
        tenant_id=auth_ctx.tenant_id,
        assessment_id=assessment_id,
    )
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report not found. The assessment may not have completed yet.",
        )
    return report
