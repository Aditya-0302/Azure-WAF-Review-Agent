"""Unit tests for AssessmentService."""

from __future__ import annotations

import uuid
from unittest.mock import MagicMock

import pytest

from waf_shared.domain.errors.domain_errors import InvalidAssessmentScopeError
from waf_shared.domain.models.assessment import AssessmentStatus


class TestAssessmentServiceCreate:
    @pytest.mark.asyncio
    async def test_create_returns_assessment_with_pending_status(self) -> None:
        from waf_api.services.assessment_service import AssessmentService, CreateAssessmentRequest

        pool = MagicMock()
        service = AssessmentService(pool=pool)

        request = CreateAssessmentRequest(
            tenant_id=uuid.uuid4(),
            idempotency_key="key-001",
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
        )

        assessment = await service.create_assessment(request)

        assert assessment.status == AssessmentStatus.PENDING

    @pytest.mark.asyncio
    async def test_create_raises_when_no_subscriptions(self) -> None:
        from waf_api.services.assessment_service import AssessmentService, CreateAssessmentRequest

        pool = MagicMock()
        service = AssessmentService(pool=pool)

        request = CreateAssessmentRequest(
            tenant_id=uuid.uuid4(),
            idempotency_key="key-002",
            subscription_ids=[],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
        )

        with pytest.raises(InvalidAssessmentScopeError):
            await service.create_assessment(request)

    @pytest.mark.asyncio
    async def test_create_raises_when_exceeds_subscription_limit(self) -> None:
        from waf_api.services.assessment_service import (
            _MAX_SUBSCRIPTIONS,
            AssessmentService,
            CreateAssessmentRequest,
        )

        pool = MagicMock()
        service = AssessmentService(pool=pool)

        request = CreateAssessmentRequest(
            tenant_id=uuid.uuid4(),
            idempotency_key="key-003",
            subscription_ids=[uuid.uuid4() for _ in range(_MAX_SUBSCRIPTIONS + 1)],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
        )

        with pytest.raises(InvalidAssessmentScopeError, match="Maximum"):
            await service.create_assessment(request)

    @pytest.mark.asyncio
    async def test_create_sets_tenant_id_from_request(self) -> None:
        from waf_api.services.assessment_service import AssessmentService, CreateAssessmentRequest

        pool = MagicMock()
        service = AssessmentService(pool=pool)
        tenant_id = uuid.uuid4()

        request = CreateAssessmentRequest(
            tenant_id=tenant_id,
            idempotency_key="key-004",
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
        )

        assessment = await service.create_assessment(request)

        assert assessment.tenant_id == tenant_id

    @pytest.mark.asyncio
    async def test_create_preserves_pillar_filter(self) -> None:
        from waf_api.services.assessment_service import AssessmentService, CreateAssessmentRequest

        pool = MagicMock()
        service = AssessmentService(pool=pool)
        pillar_filter = ["reliability", "security"]

        request = CreateAssessmentRequest(
            tenant_id=uuid.uuid4(),
            idempotency_key="key-005",
            subscription_ids=[uuid.uuid4()],
            pillar_filter=pillar_filter,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
        )

        assessment = await service.create_assessment(request)

        assert assessment.pillar_filter == pillar_filter
