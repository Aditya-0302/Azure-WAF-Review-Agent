"""Unit tests for PreparationHandler.

All Azure SDK calls and repository operations are mocked.  No network I/O.
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
from waf_shared.domain.errors.domain_errors import (
    SubscriptionNotFoundError,
)
from waf_shared.domain.errors.infrastructure_errors import (
    KeyVaultAccessError,
    ResourceDiscoveryError,
)
from waf_shared.domain.events.assessment_events import AssessmentCreatedEvent
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentBatch,
    AssessmentStatus,
    BatchStatus,
)
from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.telemetry.logging import StructuredLogger

# ── Factories ──────────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC)


def _make_assessment(
    *,
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    subscription_ids: list[uuid.UUID],
    status: AssessmentStatus = AssessmentStatus.PENDING,
    pillar_filter: list[str] | None = None,
    tag_filter: dict[str, str] | None = None,
    total_batches: int | None = None,
    cancellation_requested_at: datetime | None = None,
) -> Assessment:
    return Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        idempotency_key=f"test-{assessment_id}",
        status=status,
        subscription_ids=subscription_ids,
        pillar_filter=pillar_filter,
        tag_filter=tag_filter,
        requested_by_oid=uuid.uuid4(),
        total_batches=total_batches,
        completed_batches=0,
        cancellation_requested_at=cancellation_requested_at,
        created_at=_now(),
        updated_at=_now(),
    )


def _make_batch(
    *,
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    batch_index: int = 0,
    subscription_id: uuid.UUID,
    resource_ids: list[str] | None = None,
) -> AssessmentBatch:
    return AssessmentBatch(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        batch_index=batch_index,
        subscription_id=subscription_id,
        status=BatchStatus.PENDING,
        resource_ids=resource_ids
        or [f"/subscriptions/{subscription_id}/rg/res-{i}" for i in range(5)],
        error_detail=None,
        started_at=None,
        completed_at=None,
        created_at=_now(),
    )


def _make_resource(resource_id: str, tags: dict[str, str] | None = None) -> Any:
    r = MagicMock()
    r.id = resource_id
    r.tags = tags or {}
    return r


def _make_credential_record(
    *,
    tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    health: CredentialHealth = CredentialHealth.HEALTHY,
    secret_name: str = "sp-secret",
) -> SubscriptionCredential:
    return SubscriptionCredential(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        display_name="Test SP",
        keyvault_secret_name=secret_name,
        health=health,
        expires_at=None,
        last_health_check_at=None,
        created_at=_now(),
        updated_at=_now(),
    )


def _raw_event(
    *,
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    subscription_ids: list[uuid.UUID],
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


# ── Handler fixture ────────────────────────────────────────────────────────────


class _Mocks:
    def __init__(self) -> None:
        self.assessment_repo = AsyncMock(spec=AssessmentRepository)
        self.credential_repo = AsyncMock(spec=CredentialRepository)
        self.cross_tenant = AsyncMock(spec=CrossTenantCredentialProvider)
        self.sub_discovery = AsyncMock(spec=SubscriptionDiscoveryService)
        self.resource_inv = AsyncMock(spec=ResourceInventoryService)
        self.publisher = AsyncMock(spec=ServiceBusPublisher)
        self.logger = MagicMock(spec=StructuredLogger)
        self.logger.bind.return_value = self.logger

    def make_handler(self, *, max_concurrent: int = 5) -> PreparationHandler:
        return PreparationHandler(
            assessment_repo=self.assessment_repo,
            credential_repo=self.credential_repo,
            cross_tenant_provider=self.cross_tenant,
            subscription_discovery=self.sub_discovery,
            resource_inventory=self.resource_inv,
            publisher=self.publisher,
            logger=self.logger,
            max_concurrent_subscriptions=max_concurrent,
        )


@pytest.fixture
def m() -> _Mocks:
    return _Mocks()


@pytest.fixture
def tenant_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture
def sub_id() -> uuid.UUID:
    return uuid.uuid4()


@pytest.fixture
def assessment_id() -> uuid.UUID:
    return uuid.uuid4()


# ── Helpers ────────────────────────────────────────────────────────────────────


def _configure_happy_path(
    m: _Mocks,
    assessment: Assessment,
    resources_per_sub: dict[uuid.UUID, list[Any]],
) -> None:
    """Wire up mocks for a successful preparation run."""
    created_batch_index = [0]  # mutable counter for globally unique index

    m.assessment_repo.get_by_id.return_value = assessment
    m.assessment_repo.list_batches.return_value = []

    def _update_status_se(tenant_id, assessment_id, status):
        return assessment.model_copy(update={"status": status})

    m.assessment_repo.update_status.side_effect = _update_status_se
    m.assessment_repo.set_total_batches.return_value = None

    def _create_batch_se(batch: AssessmentBatch) -> AssessmentBatch:
        return batch

    m.assessment_repo.create_batch.side_effect = _create_batch_se

    for sub_id, resources in resources_per_sub.items():
        # get_by_subscription returns a HEALTHY credential record
        pass

    def _get_by_sub_se(tenant_id, subscription_id):
        return _make_credential_record(tenant_id=tenant_id, subscription_id=subscription_id)

    m.credential_repo.get_by_subscription.side_effect = _get_by_sub_se
    m.cross_tenant.get_credential_for_subscription.return_value = MagicMock()
    m.sub_discovery.get_subscription.return_value = MagicMock()

    def _list_resources_se(credential, sub_ids):
        return resources_per_sub.get(sub_ids[0], [])

    m.resource_inv.list_resources.side_effect = _list_resources_se

    # Second get_by_id call (cancellation re-check): returns clean assessment
    m.assessment_repo.get_by_id.side_effect = [
        assessment,
        assessment,  # re-check returns same (no cancellation)
    ]


# ── Tests ──────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestPreparationHandlerHappyPath:
    async def test_single_subscription_small_batch(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """30 resources → 1 batch; events published; status transitions to EXTRACTING."""
        resources = [_make_resource(f"/subs/{sub_id}/rg/res-{i}") for i in range(30)]
        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
        )
        _configure_happy_path(m, assessment, {sub_id: resources})

        handler = m.make_handler()
        await handler.process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                subscription_ids=[sub_id],
            )
        )

        # Status transitions
        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.PREPARING
        )
        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.EXTRACTING
        )
        # One batch created, one event published
        assert m.assessment_repo.create_batch.call_count == 1
        assert m.publisher.publish.call_count == 1
        m.assessment_repo.set_total_batches.assert_called_once_with(tenant_id, assessment_id, 1)

    async def test_single_subscription_large_batch_splits(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """60 resources → 2 batches of 50 and 10."""
        resources = [_make_resource(f"/subs/{sub_id}/res-{i}") for i in range(60)]
        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
        )
        _configure_happy_path(m, assessment, {sub_id: resources})

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        assert m.assessment_repo.create_batch.call_count == 2
        assert m.publisher.publish.call_count == 2
        m.assessment_repo.set_total_batches.assert_called_once_with(tenant_id, assessment_id, 2)

        # Verify batch resource counts via call_args
        calls = m.assessment_repo.create_batch.call_args_list
        first_batch: AssessmentBatch = calls[0].args[0]
        second_batch: AssessmentBatch = calls[1].args[0]
        assert len(first_batch.resource_ids) == BATCH_SIZE
        assert len(second_batch.resource_ids) == 10
        assert first_batch.batch_index == 0
        assert second_batch.batch_index == 1

    async def test_multi_subscription_global_batch_index(
        self, m: _Mocks, tenant_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """Two subscriptions → batches have globally unique, sequential indices."""
        sub1 = uuid.uuid4()
        sub2 = uuid.uuid4()
        res1 = [_make_resource(f"/subs/{sub1}/res-{i}") for i in range(30)]
        res2 = [_make_resource(f"/subs/{sub2}/res-{i}") for i in range(40)]
        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub1, sub2],
        )
        _configure_happy_path(m, assessment, {sub1: res1, sub2: res2})

        await m.make_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                subscription_ids=[sub1, sub2],
            )
        )

        assert m.assessment_repo.create_batch.call_count == 2
        assert m.publisher.publish.call_count == 2
        m.assessment_repo.set_total_batches.assert_called_once_with(tenant_id, assessment_id, 2)

        calls = m.assessment_repo.create_batch.call_args_list
        assert calls[0].args[0].batch_index == 0
        assert calls[1].args[0].batch_index == 1
        assert calls[0].args[0].subscription_id == sub1
        assert calls[1].args[0].subscription_id == sub2

    async def test_tag_filter_applied_client_side(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """Resources not matching tag_filter are excluded; only matching ones are batched."""
        matching = [
            _make_resource(f"/subs/{sub_id}/res-match-{i}", tags={"env": "prod"}) for i in range(5)
        ]
        excluded = [
            _make_resource(f"/subs/{sub_id}/res-skip-{i}", tags={"env": "dev"}) for i in range(20)
        ]
        all_resources = matching + excluded

        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            tag_filter={"env": "prod"},
        )
        _configure_happy_path(m, assessment, {sub_id: all_resources})

        await m.make_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                subscription_ids=[sub_id],
                tag_filter={"env": "prod"},
            )
        )

        created: AssessmentBatch = m.assessment_repo.create_batch.call_args.args[0]
        assert len(created.resource_ids) == 5

    async def test_pillar_filter_valid_passes_through(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """Valid pillar filters do not raise errors."""
        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            pillar_filter=["Security", "Reliability"],
        )
        _configure_happy_path(
            m, assessment, {sub_id: [_make_resource(f"/subs/{sub_id}/r-{i}") for i in range(3)]}
        )

        await m.make_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                subscription_ids=[sub_id],
                pillar_filter=["Security", "Reliability"],
            )
        )

        # Reached EXTRACTING without failure
        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.EXTRACTING
        )


@pytest.mark.unit
class TestPreparationHandlerIdempotency:
    async def test_skips_completed_assessment(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        m.assessment_repo.get_by_id.return_value = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            status=AssessmentStatus.COMPLETED,
        )
        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )
        m.assessment_repo.update_status.assert_not_called()
        m.publisher.publish.assert_not_called()

    async def test_skips_failed_assessment(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        m.assessment_repo.get_by_id.return_value = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            status=AssessmentStatus.FAILED,
        )
        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )
        m.assessment_repo.update_status.assert_not_called()

    async def test_skips_extracting_assessment(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        m.assessment_repo.get_by_id.return_value = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            status=AssessmentStatus.EXTRACTING,
        )
        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )
        m.assessment_repo.update_status.assert_not_called()

    async def test_assessment_not_found_returns_normally(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        m.assessment_repo.get_by_id.return_value = None
        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )
        m.assessment_repo.update_status.assert_not_called()
        m.publisher.publish.assert_not_called()

    async def test_redelivery_reuses_full_batch_set(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """PREPARING + total_batches matches existing count → skip discovery, re-publish."""
        existing_batch = _make_batch(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            batch_index=0,
            subscription_id=sub_id,
        )
        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            status=AssessmentStatus.PREPARING,
            total_batches=1,
        )

        m.assessment_repo.get_by_id.side_effect = [assessment, assessment]
        m.assessment_repo.list_batches.return_value = [existing_batch]
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.assessment_repo.set_total_batches.return_value = None

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        # No new discovery or batch creation
        m.credential_repo.get_by_subscription.assert_not_called()
        m.assessment_repo.create_batch.assert_not_called()
        m.assessment_repo.delete_all_batches.assert_not_called()
        # One event re-published
        assert m.publisher.publish.call_count == 1
        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.EXTRACTING
        )

    async def test_redelivery_with_partial_batches_cleans_up_and_restarts(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """Partial batch failure → delete existing batches, rediscover."""
        partial_batch = _make_batch(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_id=sub_id,
        )
        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            status=AssessmentStatus.PREPARING,
            total_batches=None,  # never written → partial failure
        )
        resources = [_make_resource(f"/subs/{sub_id}/r-{i}") for i in range(5)]

        m.assessment_repo.get_by_id.side_effect = [assessment, assessment]
        m.assessment_repo.list_batches.return_value = [partial_batch]
        m.assessment_repo.delete_all_batches.return_value = None
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.assessment_repo.set_total_batches.return_value = None
        m.assessment_repo.create_batch.side_effect = lambda b: b

        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        m.sub_discovery.get_subscription.return_value = MagicMock()
        m.resource_inv.list_resources.return_value = resources

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.delete_all_batches.assert_called_once_with(tenant_id, assessment_id)
        assert m.assessment_repo.create_batch.call_count == 1
        assert m.publisher.publish.call_count == 1


@pytest.mark.unit
class TestPreparationHandlerValidationErrors:
    async def test_invalid_pillar_marks_assessment_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            pillar_filter=["Security", "Not A Real Pillar"],
        )
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )

        await m.make_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                subscription_ids=[sub_id],
                pillar_filter=["Security", "Not A Real Pillar"],
            )
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )
        m.publisher.publish.assert_not_called()

    async def test_missing_credential_marks_assessment_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id]
        )
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.credential_repo.get_by_subscription.return_value = None  # no credential

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )

    async def test_expired_credential_marks_assessment_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id]
        )
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id,
            subscription_id=sub_id,
            health=CredentialHealth.EXPIRED,
        )

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )

    async def test_invalid_credential_marks_assessment_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id]
        )
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id,
            subscription_id=sub_id,
            health=CredentialHealth.INVALID,
        )

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )

    async def test_subscription_not_found_marks_assessment_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id]
        )
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        m.sub_discovery.get_subscription.side_effect = SubscriptionNotFoundError(sub_id)

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )
        m.assessment_repo.create_batch.assert_not_called()

    async def test_keyvault_error_marks_assessment_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id]
        )
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant.get_credential_for_subscription.side_effect = KeyVaultAccessError(
            secret_name="sp-secret", reason="permission denied"
        )

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )

    async def test_zero_resources_after_tag_filter_marks_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """All resources filtered out by tags → InvalidAssessmentScopeError → FAILED."""
        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            tag_filter={"env": "prod"},
        )
        all_non_matching = [
            _make_resource(f"/subs/{sub_id}/r-{i}", tags={"env": "dev"}) for i in range(10)
        ]
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        m.sub_discovery.get_subscription.return_value = MagicMock()
        m.resource_inv.list_resources.return_value = all_non_matching

        await m.make_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                subscription_ids=[sub_id],
                tag_filter={"env": "prod"},
            )
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )
        m.assessment_repo.create_batch.assert_not_called()

    async def test_zero_resources_no_filter_marks_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """Empty subscription (no resources at all) → FAILED."""
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id]
        )
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        m.sub_discovery.get_subscription.return_value = MagicMock()
        m.resource_inv.list_resources.return_value = []

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )

    async def test_resource_discovery_error_marks_failed(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id]
        )
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: assessment.model_copy(update={"status": status})
        )
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        m.sub_discovery.get_subscription.return_value = MagicMock()
        m.resource_inv.list_resources.side_effect = ResourceDiscoveryError(
            service="ResourceGraph", reason="throttled after retries"
        )

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.FAILED
        )


@pytest.mark.unit
class TestPreparationHandlerCancellation:
    async def test_cancellation_pending_at_start(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """Cancellation flag set before preparation starts → CANCELLED, no discovery."""
        pending_cancel_assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
            status=AssessmentStatus.PENDING,
        )
        # update_status(PREPARING) returns assessment with cancellation set
        preparing_cancelled = pending_cancel_assessment.model_copy(
            update={
                "status": AssessmentStatus.PREPARING,
                "cancellation_requested_at": _now(),
            }
        )
        m.assessment_repo.get_by_id.side_effect = [pending_cancel_assessment, preparing_cancelled]
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = [
            preparing_cancelled,
            pending_cancel_assessment.model_copy(update={"status": AssessmentStatus.CANCELLED}),
        ]

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.CANCELLED
        )
        m.credential_repo.get_by_subscription.assert_not_called()
        m.publisher.publish.assert_not_called()

    async def test_cancellation_pending_before_publish(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """Cancellation set after batch creation but before event publication → CANCELLED."""
        clean_assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            subscription_ids=[sub_id],
        )
        cancelled_assessment = clean_assessment.model_copy(
            update={"cancellation_requested_at": _now()}
        )

        # First get_by_id: clean; second (re-check before publish): cancelled
        m.assessment_repo.get_by_id.side_effect = [clean_assessment, cancelled_assessment]
        m.assessment_repo.list_batches.return_value = []
        m.assessment_repo.update_status.side_effect = (
            lambda tid, aid, status: clean_assessment.model_copy(update={"status": status})
        )
        m.assessment_repo.set_total_batches.return_value = None
        m.assessment_repo.create_batch.side_effect = lambda b: b

        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant.get_credential_for_subscription.return_value = MagicMock()
        m.sub_discovery.get_subscription.return_value = MagicMock()
        m.resource_inv.list_resources.return_value = [
            _make_resource(f"/subs/{sub_id}/r-{i}") for i in range(5)
        ]

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        m.assessment_repo.update_status.assert_any_call(
            tenant_id, assessment_id, AssessmentStatus.CANCELLED
        )
        m.publisher.publish.assert_not_called()


@pytest.mark.unit
class TestPreparationHandlerExtractionEventShape:
    async def test_extraction_event_contains_correct_fields(
        self, m: _Mocks, tenant_id: uuid.UUID, sub_id: uuid.UUID, assessment_id: uuid.UUID
    ) -> None:
        """Published CloudEventEnvelope wraps ExtractionRequestedEvent with right fields."""
        from waf_shared.domain.events.assessment_events import ExtractionRequestedEvent

        resources = [_make_resource(f"/subs/{sub_id}/r-{i}") for i in range(3)]
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id]
        )
        _configure_happy_path(m, assessment, {sub_id: resources})

        await m.make_handler().process(
            _raw_event(assessment_id=assessment_id, tenant_id=tenant_id, subscription_ids=[sub_id])
        )

        assert m.publisher.publish.call_count == 1
        queue_name, envelope = m.publisher.publish.call_args.args
        from waf_shared.messaging.queue_names import EXTRACTION_REQUESTED

        assert queue_name == EXTRACTION_REQUESTED

        extraction: ExtractionRequestedEvent = envelope.data
        assert extraction.assessment_id == assessment_id
        assert extraction.tenant_id == tenant_id
        assert extraction.subscription_id == sub_id
        assert extraction.batch_index == 0
        assert len(extraction.resource_ids) == 3
        assert all(rid.startswith("/subs/") for rid in extraction.resource_ids)
