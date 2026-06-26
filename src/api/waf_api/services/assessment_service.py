"""AssessmentService — orchestrates assessment creation and lifecycle.

Responsibilities:
  - Validate scope (subscription count, non-empty)
  - Check idempotency (same key + same params → return existing)
  - Persist Assessment to DB
  - Publish AssessmentCreatedEvent to Service Bus

Does NOT know about: HTTP, SQL syntax, Azure SDK types, Service Bus wire format.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.domain.errors.application_errors import IdempotencyConflictError
from waf_shared.domain.errors.domain_errors import (
    AssessmentNotFoundError,
    InvalidAssessmentScopeError,
)
from waf_shared.domain.events.assessment_events import AssessmentCreatedEvent
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import Assessment, AssessmentStatus
from waf_shared.messaging.queue_names import ASSESSMENT_CREATED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")

_MAX_SUBSCRIPTIONS = 10
_EVENT_SOURCE = "/api"
_ASSESSMENT_CREATED_EVENT_TYPE = "com.wafagent.assessment.created"


class CreateAssessmentRequest:
    def __init__(
        self,
        tenant_id: uuid.UUID,
        idempotency_key: str,
        subscription_ids: list[uuid.UUID],
        pillar_filter: list[str] | None,
        tag_filter: dict[str, str] | None,
        requested_by_oid: uuid.UUID,
    ) -> None:
        self.tenant_id = tenant_id
        self.idempotency_key = idempotency_key
        self.subscription_ids = subscription_ids
        self.pillar_filter = pillar_filter
        self.tag_filter = tag_filter
        self.requested_by_oid = requested_by_oid


class AssessmentService:
    def __init__(self, pool: DatabasePool, publisher: ServiceBusPublisher | None = None) -> None:
        self._pool = pool
        self._repo = AssessmentRepository(pool=pool)
        self._publisher = publisher

    async def create_assessment(self, request: CreateAssessmentRequest) -> Assessment:
        if not request.subscription_ids:
            raise InvalidAssessmentScopeError("At least one subscription_id is required")

        if len(request.subscription_ids) > _MAX_SUBSCRIPTIONS:
            raise InvalidAssessmentScopeError(
                f"Maximum {_MAX_SUBSCRIPTIONS} subscriptions per assessment; "
                f"received {len(request.subscription_ids)}"
            )

        # Idempotency: return existing if key matches with same parameters.
        existing = await self._repo.get_by_idempotency_key(
            request.tenant_id, request.idempotency_key
        )
        if existing is not None:
            if (
                sorted(str(s) for s in existing.subscription_ids)
                == sorted(str(s) for s in request.subscription_ids)
                and existing.pillar_filter == request.pillar_filter
                and existing.tag_filter == request.tag_filter
            ):
                _logger.info(
                    "assessment.idempotent_return",
                    assessment_id=str(existing.id),
                    tenant_id=str(request.tenant_id),
                )
                return existing
            raise IdempotencyConflictError(
                idempotency_key=request.idempotency_key,
                existing_id=existing.id,
            )

        now = datetime.now(UTC)
        assessment = Assessment(
            id=uuid.uuid4(),
            tenant_id=request.tenant_id,
            idempotency_key=request.idempotency_key,
            status=AssessmentStatus.PENDING,
            subscription_ids=request.subscription_ids,
            pillar_filter=request.pillar_filter,
            tag_filter=request.tag_filter,
            requested_by_oid=request.requested_by_oid,
            total_batches=None,
            completed_batches=0,
            cancellation_requested_at=None,
            created_at=now,
            updated_at=now,
        )

        saved = await self._repo.create(assessment)

        if self._publisher is not None:
            await self._publisher.publish(
                ASSESSMENT_CREATED,
                CloudEventEnvelope.wrap(
                    event_type=_ASSESSMENT_CREATED_EVENT_TYPE,
                    source=_EVENT_SOURCE,
                    data=AssessmentCreatedEvent(
                        assessment_id=saved.id,
                        tenant_id=saved.tenant_id,
                        subscription_ids=saved.subscription_ids,
                        pillar_filter=saved.pillar_filter,
                        tag_filter=saved.tag_filter,
                        requested_by_oid=saved.requested_by_oid,
                        created_at=saved.created_at,
                    ),
                ),
            )

        _logger.info(
            "assessment.created",
            assessment_id=str(saved.id),
            tenant_id=str(request.tenant_id),
            subscription_count=len(request.subscription_ids),
        )
        return saved

    async def get_assessment(self, assessment_id: uuid.UUID, tenant_id: uuid.UUID) -> Assessment:
        assessment = await self._repo.get_by_id(tenant_id, assessment_id)
        if assessment is None:
            raise AssessmentNotFoundError(assessment_id=assessment_id, tenant_id=tenant_id)
        return assessment

    async def list_assessments(
        self,
        tenant_id: uuid.UUID,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
    ) -> list[Assessment]:
        return await self._repo.list_by_tenant(tenant_id, limit=limit, cursor=cursor)

    async def cancel_assessment(self, assessment_id: uuid.UUID, tenant_id: uuid.UUID) -> Assessment:
        _logger.info(
            "assessment.cancellation.requested",
            assessment_id=str(assessment_id),
            tenant_id=str(tenant_id),
        )
        return await self._repo.request_cancellation(tenant_id, assessment_id)
