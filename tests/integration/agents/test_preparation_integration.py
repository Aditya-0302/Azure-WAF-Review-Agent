"""Integration tests for the Preparation Agent handler.

Tests the full message → batch creation → event publication flow using:
- Real PreparationHandler (no logic mocked)
- Real domain models, event serialisation, and CloudEventEnvelope round-trip
- Mocked repositories (no live database required)
- Mocked Azure SDK (no live Azure subscription required)

These tests verify end-to-end orchestration: that the correct sequence of
repository and publisher calls is made in the right order for a given input.

Tests requiring Docker Compose services (real PostgreSQL + Service Bus emulator)
are tagged @pytest.mark.integration and skipped unless explicitly enabled.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from waf_preparation.handler import BATCH_SIZE, PreparationHandler

from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.discovery.resource_inventory import ResourceInventoryService
from waf_shared.discovery.subscription_discovery import SubscriptionDiscoveryService
from waf_shared.domain.events.assessment_events import AssessmentCreatedEvent
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentBatch,
    AssessmentStatus,
)
from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential
from waf_shared.messaging.queue_names import EXTRACTION_REQUESTED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.telemetry.logging import StructuredLogger

# ── Shared factories ──────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC)


def _make_assessment(
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    subscription_ids: list[uuid.UUID],
    status: AssessmentStatus = AssessmentStatus.PENDING,
    tag_filter: dict[str, str] | None = None,
    pillar_filter: list[str] | None = None,
    total_batches: int | None = None,
) -> Assessment:
    return Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        idempotency_key=f"integ-{assessment_id}",
        status=status,
        subscription_ids=subscription_ids,
        pillar_filter=pillar_filter,
        tag_filter=tag_filter,
        requested_by_oid=uuid.uuid4(),
        total_batches=total_batches,
        completed_batches=0,
        cancellation_requested_at=None,
        created_at=_now(),
        updated_at=_now(),
    )


def _make_credential_record(
    tenant_id: uuid.UUID, subscription_id: uuid.UUID
) -> SubscriptionCredential:
    return SubscriptionCredential(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        display_name="Integration Test SP",
        keyvault_secret_name="integ-test-secret",
        health=CredentialHealth.HEALTHY,
        expires_at=None,
        last_health_check_at=None,
        created_at=_now(),
        updated_at=_now(),
    )


def _make_resource(resource_id: str, tags: dict[str, str] | None = None) -> Any:
    r = MagicMock()
    r.id = resource_id
    r.tags = tags or {}
    return r


def _encode_event(
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    subscription_ids: list[uuid.UUID],
    *,
    pillar_filter: list[str] | None = None,
    tag_filter: dict[str, str] | None = None,
) -> bytes:
    event = AssessmentCreatedEvent(
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        subscription_ids=subscription_ids,
        pillar_filter=pillar_filter,
        tag_filter=tag_filter,
        requested_by_oid=uuid.uuid4(),
        created_at=_now(),
    )
    return CloudEventEnvelope.wrap(
        event_type="com.wafagent.assessment.created",
        source="/api/assessments",
        data=event,
    ).to_json_bytes()


def _build_handler(
    assessment_repo: AssessmentRepository,
    credential_repo: CredentialRepository,
    cross_tenant: CrossTenantCredentialProvider,
    sub_discovery: SubscriptionDiscoveryService,
    resource_inv: ResourceInventoryService,
    publisher: ServiceBusPublisher,
) -> PreparationHandler:
    logger = MagicMock(spec=StructuredLogger)
    logger.bind.return_value = logger
    return PreparationHandler(
        assessment_repo=assessment_repo,
        credential_repo=credential_repo,
        cross_tenant_provider=cross_tenant,
        subscription_discovery=sub_discovery,
        resource_inventory=resource_inv,
        publisher=publisher,
        logger=logger,
    )


# ── Integration test classes ──────────────────────────────────────────────────


@pytest.mark.integration
class TestPreparationAgentFullFlow:
    """End-to-end orchestration: message in → batches created → events out."""

    async def test_message_to_batches_to_events_single_subscription(self) -> None:
        """A single assessment.created message produces the correct DB writes and SB events."""
        tenant_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        assessment_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id, tenant_id, [sub_id])
        resources = [_make_resource(f"/subs/{sub_id}/rg/res-{i}") for i in range(75)]

        # ── Repositories ──
        assessment_repo = AsyncMock(spec=AssessmentRepository)
        credential_repo = AsyncMock(spec=CredentialRepository)

        created_batches: list[AssessmentBatch] = []

        assessment_repo.get_by_id.side_effect = [assessment, assessment]
        assessment_repo.list_batches.return_value = []
        assessment_repo.update_status.side_effect = lambda tid, aid, status: assessment.model_copy(
            update={"status": status}
        )
        assessment_repo.set_total_batches.return_value = None

        def _create_batch_se(batch: AssessmentBatch) -> AssessmentBatch:
            created_batches.append(batch)
            return batch

        assessment_repo.create_batch.side_effect = _create_batch_se

        credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id, sub_id
        )

        # ── Azure services ──
        cross_tenant = AsyncMock(spec=CrossTenantCredentialProvider)
        cross_tenant.get_credential_for_subscription.return_value = MagicMock()

        sub_discovery = AsyncMock(spec=SubscriptionDiscoveryService)
        sub_discovery.get_subscription.return_value = MagicMock()

        resource_inv = AsyncMock(spec=ResourceInventoryService)
        resource_inv.list_resources.return_value = resources

        # ── Publisher ──
        publisher = AsyncMock(spec=ServiceBusPublisher)

        handler = _build_handler(
            assessment_repo, credential_repo, cross_tenant, sub_discovery, resource_inv, publisher
        )

        # ── Execute ──
        raw = _encode_event(assessment_id, tenant_id, [sub_id])
        await handler.process(raw)

        # ── Assertions ──

        # Status transitions: PENDING → PREPARING → EXTRACTING
        status_calls = [c.args[2] for c in assessment_repo.update_status.call_args_list]
        assert AssessmentStatus.PREPARING in status_calls
        assert AssessmentStatus.EXTRACTING in status_calls
        assert AssessmentStatus.FAILED not in status_calls

        # 75 resources ÷ 50 = 2 batches (50 + 25)
        assert len(created_batches) == 2
        assert len(created_batches[0].resource_ids) == BATCH_SIZE
        assert len(created_batches[1].resource_ids) == 25
        assert created_batches[0].batch_index == 0
        assert created_batches[1].batch_index == 1

        # total_batches written
        assessment_repo.set_total_batches.assert_called_once_with(tenant_id, assessment_id, 2)

        # Two extraction.requested events published
        assert publisher.publish.call_count == 2
        for i, (queue_name, envelope) in enumerate(
            c.args for c in publisher.publish.call_args_list
        ):
            assert queue_name == EXTRACTION_REQUESTED
            assert envelope.data.assessment_id == assessment_id
            assert envelope.data.batch_index == i

    async def test_multi_subscription_fan_out(self) -> None:
        """Two subscriptions processed in parallel; batches interleaved by subscription order."""
        tenant_id = uuid.uuid4()
        sub1 = uuid.uuid4()
        sub2 = uuid.uuid4()
        assessment_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id, tenant_id, [sub1, sub2])

        assessment_repo = AsyncMock(spec=AssessmentRepository)
        credential_repo = AsyncMock(spec=CredentialRepository)

        created_batches: list[AssessmentBatch] = []
        assessment_repo.get_by_id.side_effect = [assessment, assessment]
        assessment_repo.list_batches.return_value = []
        assessment_repo.update_status.side_effect = lambda tid, aid, status: assessment.model_copy(
            update={"status": status}
        )
        assessment_repo.set_total_batches.return_value = None
        assessment_repo.create_batch.side_effect = lambda b: (created_batches.append(b) or b)

        credential_repo.get_by_subscription.side_effect = lambda tid, sid: _make_credential_record(
            tid, sid
        )

        cross_tenant = AsyncMock(spec=CrossTenantCredentialProvider)
        cross_tenant.get_credential_for_subscription.return_value = MagicMock()

        sub_discovery = AsyncMock(spec=SubscriptionDiscoveryService)
        sub_discovery.get_subscription.return_value = MagicMock()

        resources_by_sub = {
            sub1: [_make_resource(f"/subs/{sub1}/r-{i}") for i in range(30)],
            sub2: [_make_resource(f"/subs/{sub2}/r-{i}") for i in range(20)],
        }
        resource_inv = AsyncMock(spec=ResourceInventoryService)
        resource_inv.list_resources.side_effect = lambda cred, sub_ids: resources_by_sub[sub_ids[0]]

        publisher = AsyncMock(spec=ServiceBusPublisher)

        handler = _build_handler(
            assessment_repo, credential_repo, cross_tenant, sub_discovery, resource_inv, publisher
        )

        await handler.process(_encode_event(assessment_id, tenant_id, [sub1, sub2]))

        # 2 subscriptions × 1 batch each = 2 total
        assert len(created_batches) == 2
        assert created_batches[0].subscription_id == sub1
        assert created_batches[1].subscription_id == sub2
        assert created_batches[0].batch_index == 0
        assert created_batches[1].batch_index == 1
        assert publisher.publish.call_count == 2

    async def test_cancellation_mid_flight_stops_event_publication(self) -> None:
        """Assessment cancelled after batches are written; no extraction events are published."""
        tenant_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        assessment_id = uuid.uuid4()

        clean_assessment = _make_assessment(assessment_id, tenant_id, [sub_id])
        cancelled_assessment = clean_assessment.model_copy(
            update={"cancellation_requested_at": _now()}
        )

        assessment_repo = AsyncMock(spec=AssessmentRepository)
        credential_repo = AsyncMock(spec=CredentialRepository)

        # First get_by_id → clean; second (pre-publish re-check) → cancelled
        assessment_repo.get_by_id.side_effect = [clean_assessment, cancelled_assessment]
        assessment_repo.list_batches.return_value = []
        assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: clean_assessment.model_copy(update={"status": status})
        )
        assessment_repo.set_total_batches.return_value = None
        assessment_repo.create_batch.side_effect = lambda b: b

        credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id, sub_id
        )

        cross_tenant = AsyncMock(spec=CrossTenantCredentialProvider)
        cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        sub_discovery = AsyncMock(spec=SubscriptionDiscoveryService)
        sub_discovery.get_subscription.return_value = MagicMock()
        resource_inv = AsyncMock(spec=ResourceInventoryService)
        resource_inv.list_resources.return_value = [
            _make_resource(f"/subs/{sub_id}/r-{i}") for i in range(5)
        ]

        publisher = AsyncMock(spec=ServiceBusPublisher)

        handler = _build_handler(
            assessment_repo, credential_repo, cross_tenant, sub_discovery, resource_inv, publisher
        )

        await handler.process(_encode_event(assessment_id, tenant_id, [sub_id]))

        # Batches created (work was done), but no events published
        assessment_repo.create_batch.assert_called_once()
        publisher.publish.assert_not_called()

        status_calls = [c.args[2] for c in assessment_repo.update_status.call_args_list]
        assert AssessmentStatus.CANCELLED in status_calls
        assert AssessmentStatus.EXTRACTING not in status_calls

    async def test_cloudevent_envelope_round_trip(self) -> None:
        """Serialise AssessmentCreatedEvent → bytes → handler.process() deserialises correctly."""
        tenant_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        assessment_id = uuid.uuid4()

        assessment = _make_assessment(
            assessment_id,
            tenant_id,
            [sub_id],
            pillar_filter=["Security", "Reliability"],
            tag_filter={"owner": "platform-team"},
        )

        assessment_repo = AsyncMock(spec=AssessmentRepository)
        credential_repo = AsyncMock(spec=CredentialRepository)

        assessment_repo.get_by_id.side_effect = [assessment, assessment]
        assessment_repo.list_batches.return_value = []
        assessment_repo.update_status.side_effect = lambda tid, aid, status: assessment.model_copy(
            update={"status": status}
        )
        assessment_repo.set_total_batches.return_value = None
        assessment_repo.create_batch.side_effect = lambda b: b

        credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id, sub_id
        )

        cross_tenant = AsyncMock(spec=CrossTenantCredentialProvider)
        cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        sub_discovery = AsyncMock(spec=SubscriptionDiscoveryService)
        sub_discovery.get_subscription.return_value = MagicMock()
        resource_inv = AsyncMock(spec=ResourceInventoryService)
        resource_inv.list_resources.return_value = [
            _make_resource(f"/subs/{sub_id}/r-{i}", tags={"owner": "platform-team"})
            for i in range(3)
        ]

        publisher = AsyncMock(spec=ServiceBusPublisher)

        handler = _build_handler(
            assessment_repo, credential_repo, cross_tenant, sub_discovery, resource_inv, publisher
        )

        raw = _encode_event(
            assessment_id,
            tenant_id,
            [sub_id],
            pillar_filter=["Security", "Reliability"],
            tag_filter={"owner": "platform-team"},
        )
        await handler.process(raw)

        # Tag filter applied: all 3 resources match → 1 batch, 1 event
        assert assessment_repo.create_batch.call_count == 1
        assert publisher.publish.call_count == 1

        created: AssessmentBatch = assessment_repo.create_batch.call_args.args[0]
        assert len(created.resource_ids) == 3

    async def test_db_error_during_create_batch_propagates(self) -> None:
        """DatabaseError from create_batch propagates so the consumer can abandon the message."""
        from waf_shared.domain.errors.infrastructure_errors import DatabaseError

        tenant_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        assessment_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id, tenant_id, [sub_id])

        assessment_repo = AsyncMock(spec=AssessmentRepository)
        credential_repo = AsyncMock(spec=CredentialRepository)

        assessment_repo.get_by_id.side_effect = [assessment, assessment]
        assessment_repo.list_batches.return_value = []
        assessment_repo.update_status.side_effect = lambda tid, aid, status: assessment.model_copy(
            update={"status": status}
        )
        assessment_repo.create_batch.side_effect = DatabaseError("connection lost")

        credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id, sub_id
        )

        cross_tenant = AsyncMock(spec=CrossTenantCredentialProvider)
        cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        sub_discovery = AsyncMock(spec=SubscriptionDiscoveryService)
        sub_discovery.get_subscription.return_value = MagicMock()
        resource_inv = AsyncMock(spec=ResourceInventoryService)
        resource_inv.list_resources.return_value = [
            _make_resource(f"/subs/{sub_id}/r-{i}") for i in range(5)
        ]

        publisher = AsyncMock(spec=ServiceBusPublisher)

        handler = _build_handler(
            assessment_repo, credential_repo, cross_tenant, sub_discovery, resource_inv, publisher
        )

        with pytest.raises(DatabaseError):
            await handler.process(_encode_event(assessment_id, tenant_id, [sub_id]))

        # No extraction events published (failed before reaching publish step)
        publisher.publish.assert_not_called()
