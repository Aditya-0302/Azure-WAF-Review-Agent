"""Unit tests for ExtractionHandler.

All Azure SDK calls and repository operations are mocked.  No network I/O.
asyncio_mode = "auto" is set project-wide so @pytest.mark.asyncio is not needed.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from waf_extraction.handler import ExtractionHandler

from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.discovery.resource_graph_client import AzureResourceGraphClient
from waf_shared.domain.errors.infrastructure_errors import (
    AzureRateLimitError,
    CrossTenantAuthError,
    KeyVaultAccessError,
    ResourceDiscoveryError,
)
from waf_shared.domain.events.assessment_events import ExtractionRequestedEvent
from waf_shared.domain.events.base import CloudEventEnvelope
from waf_shared.domain.models.assessment import (
    Assessment,
    AssessmentResource,
    AssessmentStatus,
    BatchStatus,
)
from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential
from waf_shared.messaging.queue_names import REASONING_REQUESTED
from waf_shared.messaging.service_bus import ServiceBusPublisher
from waf_shared.telemetry.logging import StructuredLogger

# ── Factories ──────────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC)


def _make_assessment(
    *,
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    status: AssessmentStatus = AssessmentStatus.EXTRACTING,
    total_batches: int | None = 1,
    cancellation_requested_at: datetime | None = None,
) -> Assessment:
    return Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        idempotency_key=f"test-{assessment_id}",
        status=status,
        subscription_ids=[uuid.uuid4()],
        pillar_filter=None,
        tag_filter=None,
        requested_by_oid=uuid.uuid4(),
        total_batches=total_batches,
        completed_batches=0,
        cancellation_requested_at=cancellation_requested_at,
        created_at=_now(),
        updated_at=_now(),
    )


def _make_credential_record(
    *,
    tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    health: CredentialHealth = CredentialHealth.HEALTHY,
) -> SubscriptionCredential:
    return SubscriptionCredential(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        subscription_id=subscription_id,
        display_name="Test Credential",
        keyvault_secret_name=f"sp-creds-test-{subscription_id}",
        health=health,
        expires_at=None,
        last_health_check_at=_now(),
        created_at=_now(),
        updated_at=_now(),
    )


def _make_rg_row(
    resource_id: str, *, resource_type: str = "microsoft.compute/virtualmachines"
) -> dict[str, Any]:
    """Return a fake Resource Graph row dict for the given resource ID."""
    parts = resource_id.lower().split("/")
    rg = ""
    try:
        rg = parts[parts.index("resourcegroups") + 1]
    except (ValueError, IndexError):
        pass
    sub = ""
    try:
        sub = parts[parts.index("subscriptions") + 1]
    except (ValueError, IndexError):
        pass
    return {
        "id": resource_id,
        "name": resource_id.split("/")[-1],
        "type": resource_type,
        "location": "eastus",
        "resourceGroup": rg,
        "subscriptionId": sub,
        "tenantId": str(uuid.uuid4()),
        "properties": {"vmSize": "Standard_D2s_v3", "provisioningState": "Succeeded"},
        "tags": {"env": "test"},
        "sku": None,
        "kind": None,
        "identity": None,
        "zones": ["1"],
    }


def _make_upserted_resource(
    *,
    resource_id: str,
    assessment_id: uuid.UUID,
    batch_id: uuid.UUID,
    tenant_id: uuid.UUID,
    subscription_id: uuid.UUID,
    raw_properties: dict[str, Any] | None = None,
) -> AssessmentResource:
    return AssessmentResource(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        batch_id=batch_id,
        tenant_id=tenant_id,
        resource_id=resource_id,
        resource_type="microsoft.compute/virtualmachines",
        location="eastus",
        subscription_id=subscription_id,
        resource_group="rg-test",
        raw_properties=raw_properties or {"properties": {}},
        extracted_at=_now(),
    )


def _raw_event(
    *,
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    batch_id: uuid.UUID,
    subscription_id: uuid.UUID,
    batch_index: int = 0,
    resource_ids: list[str] | None = None,
) -> bytes:
    if resource_ids is None:
        resource_ids = [
            f"/subscriptions/{subscription_id}/resourceGroups/rg-test"
            f"/providers/Microsoft.Compute/virtualMachines/vm-{i}"
            for i in range(3)
        ]
    event = ExtractionRequestedEvent(
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        batch_id=batch_id,
        subscription_id=subscription_id,
        batch_index=batch_index,
        resource_ids=resource_ids,
    )
    envelope = CloudEventEnvelope.wrap(
        event_type="com.wafagent.extraction.requested",
        source="/agents/preparation",
        data=event,
    )
    return envelope.to_json_bytes()


# ── Mock harness ───────────────────────────────────────────────────────────────


class _Mocks:
    def __init__(self) -> None:
        self.assessment_repo = AsyncMock(spec=AssessmentRepository)
        self.credential_repo = AsyncMock(spec=CredentialRepository)
        self.cross_tenant_provider = AsyncMock(spec=CrossTenantCredentialProvider)
        self.resource_graph = AsyncMock(spec=AzureResourceGraphClient)
        self.publisher = AsyncMock(spec=ServiceBusPublisher)
        self.logger = MagicMock(spec=StructuredLogger)
        self.logger.bind.return_value = self.logger

    def build_handler(self) -> ExtractionHandler:
        return ExtractionHandler(
            assessment_repo=self.assessment_repo,
            credential_repo=self.credential_repo,
            cross_tenant_provider=self.cross_tenant_provider,
            resource_graph=self.resource_graph,
            publisher=self.publisher,
            logger=self.logger,
        )


def _configure_happy_path(
    m: _Mocks,
    *,
    assessment: Assessment,
    credential_record: SubscriptionCredential,
    rg_rows: list[dict[str, Any]],
    upserted_resources: list[AssessmentResource],
    refreshed_assessment: Assessment | None = None,
) -> None:
    """Wire all mocks for the standard happy-path scenario."""
    m.assessment_repo.get_by_id.side_effect = [
        assessment,
        refreshed_assessment or assessment,
    ]
    m.assessment_repo.update_batch_status.return_value = None
    m.credential_repo.get_by_subscription.return_value = credential_record
    m.cross_tenant_provider.get_credential_for_subscription.return_value = MagicMock()
    m.resource_graph.get_resource_properties.return_value = rg_rows
    m.assessment_repo.upsert_resource.side_effect = upserted_resources
    m.publisher.publish.return_value = None


# ── Test classes ───────────────────────────────────────────────────────────────


class TestExtractionHandlerHappyPath:
    """Full success scenarios: all resources found in Resource Graph."""

    async def test_single_resource_happy_path(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        resource_id = (
            f"/subscriptions/{sub_id}/resourceGroups/rg-prod"
            "/providers/Microsoft.Compute/virtualMachines/vm-01"
        )

        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, total_batches=1
        )
        cred = _make_credential_record(tenant_id=tenant_id, subscription_id=sub_id)
        rg_row = _make_rg_row(resource_id)
        upserted = _make_upserted_resource(
            resource_id=resource_id,
            assessment_id=assessment_id,
            batch_id=batch_id,
            tenant_id=tenant_id,
            subscription_id=sub_id,
        )
        _configure_happy_path(
            m,
            assessment=assessment,
            credential_record=cred,
            rg_rows=[rg_row],
            upserted_resources=[upserted],
        )

        handler = m.build_handler()
        raw = _raw_event(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            batch_id=batch_id,
            subscription_id=sub_id,
            resource_ids=[resource_id],
        )
        await handler.process(raw)

        m.assessment_repo.update_batch_status.assert_any_call(
            tenant_id, batch_id, BatchStatus.IN_PROGRESS
        )
        m.assessment_repo.upsert_resource.assert_called_once()
        m.publisher.publish.assert_called_once()
        queue_name = m.publisher.publish.call_args[0][0]
        assert queue_name == REASONING_REQUESTED

    async def test_multiple_resources_all_found(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        resource_ids = [
            f"/subscriptions/{sub_id}/resourceGroups/rg-prod"
            f"/providers/Microsoft.Compute/virtualMachines/vm-{i:02d}"
            for i in range(5)
        ]
        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, total_batches=2
        )
        cred = _make_credential_record(tenant_id=tenant_id, subscription_id=sub_id)
        rg_rows = [_make_rg_row(rid) for rid in resource_ids]
        upserted = [
            _make_upserted_resource(
                resource_id=rid,
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
                subscription_id=sub_id,
            )
            for rid in resource_ids
        ]
        _configure_happy_path(
            m,
            assessment=assessment,
            credential_record=cred,
            rg_rows=rg_rows,
            upserted_resources=upserted,
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
                resource_ids=resource_ids,
            )
        )

        assert m.assessment_repo.upsert_resource.call_count == 5
        m.publisher.publish.assert_called_once()

    async def test_reasoning_event_shape(self) -> None:
        """Verify the published ReasoningRequestedEvent has correct field values."""
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        resource_id = (
            f"/subscriptions/{sub_id}/resourceGroups/rg-prod"
            "/providers/Microsoft.Compute/virtualMachines/vm-01"
        )

        assessment = _make_assessment(
            assessment_id=assessment_id, tenant_id=tenant_id, total_batches=3
        )
        cred = _make_credential_record(tenant_id=tenant_id, subscription_id=sub_id)
        rg_row = _make_rg_row(resource_id)
        upserted = _make_upserted_resource(
            resource_id=resource_id,
            assessment_id=assessment_id,
            batch_id=batch_id,
            tenant_id=tenant_id,
            subscription_id=sub_id,
        )
        _configure_happy_path(
            m,
            assessment=assessment,
            credential_record=cred,
            rg_rows=[rg_row],
            upserted_resources=[upserted],
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
                batch_index=1,
                resource_ids=[resource_id],
            )
        )

        published_envelope: CloudEventEnvelope = m.publisher.publish.call_args[0][1]
        data = published_envelope.data
        assert data.assessment_id == assessment_id
        assert data.tenant_id == tenant_id
        assert data.batch_id == batch_id
        assert data.subscription_id == sub_id
        assert data.batch_index == 1
        assert data.total_batches == 3

    async def test_resource_graph_called_with_correct_args(self) -> None:
        """Verify subscription_id and resource_ids are passed to Resource Graph."""
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        resource_ids = [
            f"/subscriptions/{sub_id}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-{i}"
            for i in range(2)
        ]
        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        cred = _make_credential_record(tenant_id=tenant_id, subscription_id=sub_id)
        rg_rows = [_make_rg_row(rid) for rid in resource_ids]
        upserted = [
            _make_upserted_resource(
                resource_id=rid,
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
                subscription_id=sub_id,
            )
            for rid in resource_ids
        ]
        _configure_happy_path(
            m,
            assessment=assessment,
            credential_record=cred,
            rg_rows=rg_rows,
            upserted_resources=upserted,
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
                resource_ids=resource_ids,
            )
        )

        call_kwargs = m.resource_graph.get_resource_properties.call_args
        assert call_kwargs[0][1] == str(sub_id)
        assert call_kwargs[0][2] == resource_ids


class TestExtractionHandlerSkip:
    """Handler must skip processing for terminal or missing assessments."""

    async def test_skip_completed_assessment(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            status=AssessmentStatus.COMPLETED,
        )
        m.assessment_repo.get_by_id.return_value = assessment

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        m.assessment_repo.update_batch_status.assert_not_called()
        m.resource_graph.get_resource_properties.assert_not_called()
        m.publisher.publish.assert_not_called()

    async def test_skip_failed_assessment(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            status=AssessmentStatus.FAILED,
        )
        m.assessment_repo.get_by_id.return_value = assessment

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        m.resource_graph.get_resource_properties.assert_not_called()
        m.publisher.publish.assert_not_called()

    async def test_skip_cancelled_assessment(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            status=AssessmentStatus.CANCELLED,
        )
        m.assessment_repo.get_by_id.return_value = assessment

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        m.resource_graph.get_resource_properties.assert_not_called()
        m.publisher.publish.assert_not_called()

    async def test_skip_missing_assessment(self) -> None:
        m = _Mocks()
        m.assessment_repo.get_by_id.return_value = None
        tenant_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        await m.build_handler().process(
            _raw_event(
                assessment_id=uuid.uuid4(),
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        m.assessment_repo.update_batch_status.assert_not_called()
        m.publisher.publish.assert_not_called()


class TestExtractionHandlerPartialSuccess:
    """Resources absent from Resource Graph response are stored with error markers."""

    async def test_missing_resource_stored_with_error_marker(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        found_id = (
            f"/subscriptions/{sub_id}/resourceGroups/rg"
            "/providers/Microsoft.Compute/virtualMachines/vm-found"
        )
        missing_id = (
            f"/subscriptions/{sub_id}/resourceGroups/rg"
            "/providers/Microsoft.Compute/virtualMachines/vm-missing"
        )

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        cred = _make_credential_record(tenant_id=tenant_id, subscription_id=sub_id)
        rg_rows = [_make_rg_row(found_id)]  # missing_id NOT returned
        upserted_found = _make_upserted_resource(
            resource_id=found_id,
            assessment_id=assessment_id,
            batch_id=batch_id,
            tenant_id=tenant_id,
            subscription_id=sub_id,
        )
        upserted_missing = _make_upserted_resource(
            resource_id=missing_id,
            assessment_id=assessment_id,
            batch_id=batch_id,
            tenant_id=tenant_id,
            subscription_id=sub_id,
            raw_properties={"_extraction_failed": True, "_error": "not found"},
        )
        _configure_happy_path(
            m,
            assessment=assessment,
            credential_record=cred,
            rg_rows=rg_rows,
            upserted_resources=[upserted_found, upserted_missing],
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
                resource_ids=[found_id, missing_id],
            )
        )

        # Both resources upserted
        assert m.assessment_repo.upsert_resource.call_count == 2

        # Reasoning event still published despite one missing resource
        m.publisher.publish.assert_called_once()

        # The missing resource's raw_properties contain the failure marker
        upsert_calls = m.assessment_repo.upsert_resource.call_args_list
        missing_call_resource: AssessmentResource = next(
            c[0][0] for c in upsert_calls if c[0][0].resource_id == missing_id
        )
        assert missing_call_resource.raw_properties.get("_extraction_failed") is True

    async def test_all_missing_resources_still_completes_batch(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        resource_ids = [
            f"/subscriptions/{sub_id}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-{i}"
            for i in range(3)
        ]
        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        cred = _make_credential_record(tenant_id=tenant_id, subscription_id=sub_id)
        # Resource Graph returns EMPTY — all resources vanished
        upserted = [
            _make_upserted_resource(
                resource_id=rid,
                assessment_id=assessment_id,
                batch_id=batch_id,
                tenant_id=tenant_id,
                subscription_id=sub_id,
                raw_properties={"_extraction_failed": True},
            )
            for rid in resource_ids
        ]
        _configure_happy_path(
            m,
            assessment=assessment,
            credential_record=cred,
            rg_rows=[],
            upserted_resources=upserted,
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
                resource_ids=resource_ids,
            )
        )

        assert m.assessment_repo.upsert_resource.call_count == 3
        m.publisher.publish.assert_called_once()


class TestExtractionHandlerCredentialErrors:
    """Auth failures mark the batch FAILED and complete the SB message."""

    async def test_no_credential_registered_marks_batch_failed(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.update_batch_status.return_value = None
        m.credential_repo.get_by_subscription.return_value = None  # missing

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        update_calls = m.assessment_repo.update_batch_status.call_args_list
        failed_call = next((c for c in update_calls if c[0][2] == BatchStatus.FAILED), None)
        assert failed_call is not None, "expected update_batch_status(FAILED) to be called"
        m.publisher.publish.assert_not_called()

    async def test_expired_credential_marks_batch_failed(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.update_batch_status.return_value = None
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id, health=CredentialHealth.EXPIRED
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        # Verify FAILED was called (error_detail contains error description)
        update_calls = m.assessment_repo.update_batch_status.call_args_list
        failed_call = next((c for c in update_calls if c[0][2] == BatchStatus.FAILED), None)
        assert failed_call is not None
        m.publisher.publish.assert_not_called()

    async def test_invalid_credential_marks_batch_failed(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.update_batch_status.return_value = None
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id, health=CredentialHealth.INVALID
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        update_calls = m.assessment_repo.update_batch_status.call_args_list
        assert any(c[0][2] == BatchStatus.FAILED for c in update_calls)
        m.publisher.publish.assert_not_called()

    async def test_keyvault_access_error_marks_batch_failed(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.update_batch_status.return_value = None
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant_provider.get_credential_for_subscription.side_effect = KeyVaultAccessError(
            secret_name="sp-creds-test", reason="Forbidden"
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        update_calls = m.assessment_repo.update_batch_status.call_args_list
        assert any(c[0][2] == BatchStatus.FAILED for c in update_calls)
        m.publisher.publish.assert_not_called()

    async def test_cross_tenant_auth_error_marks_batch_failed(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.update_batch_status.return_value = None
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant_provider.get_credential_for_subscription.side_effect = CrossTenantAuthError(
            subscription_id=sub_id, reason="malformed JSON secret"
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        update_calls = m.assessment_repo.update_batch_status.call_args_list
        assert any(c[0][2] == BatchStatus.FAILED for c in update_calls)
        m.publisher.publish.assert_not_called()


class TestExtractionHandlerResourceGraphErrors:
    """Resource Graph failures mark the batch FAILED."""

    async def test_rate_limit_marks_batch_failed(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.update_batch_status.return_value = None
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant_provider.get_credential_for_subscription.return_value = MagicMock()
        m.resource_graph.get_resource_properties.side_effect = AzureRateLimitError(
            service="ResourceGraph", retry_after_seconds=30
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        update_calls = m.assessment_repo.update_batch_status.call_args_list
        assert any(c[0][2] == BatchStatus.FAILED for c in update_calls)
        m.publisher.publish.assert_not_called()

    async def test_resource_discovery_error_marks_batch_failed(self) -> None:
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.update_batch_status.return_value = None
        m.credential_repo.get_by_subscription.return_value = _make_credential_record(
            tenant_id=tenant_id, subscription_id=sub_id
        )
        m.cross_tenant_provider.get_credential_for_subscription.return_value = MagicMock()
        m.resource_graph.get_resource_properties.side_effect = ResourceDiscoveryError(
            service="ResourceGraph", reason="internal server error"
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
            )
        )

        update_calls = m.assessment_repo.update_batch_status.call_args_list
        assert any(c[0][2] == BatchStatus.FAILED for c in update_calls)
        m.publisher.publish.assert_not_called()

    async def test_db_error_propagates_for_sb_retry(self) -> None:
        """DatabaseErrors propagate so the consumer can abandon the message."""
        from waf_shared.domain.errors.infrastructure_errors import DatabaseError

        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        m.assessment_repo.get_by_id.return_value = assessment
        m.assessment_repo.update_batch_status.side_effect = DatabaseError("connection lost")

        with pytest.raises(DatabaseError):
            await m.build_handler().process(
                _raw_event(
                    assessment_id=assessment_id,
                    tenant_id=tenant_id,
                    batch_id=batch_id,
                    subscription_id=sub_id,
                )
            )


class TestExtractionHandlerCancellation:
    """Cancellation flag prevents publishing reasoning event."""

    async def test_cancellation_before_publish_skips_reasoning_event(self) -> None:
        """When assessment is cancelled between batch completion and event publication."""
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        resource_id = (
            f"/subscriptions/{sub_id}/resourceGroups/rg"
            "/providers/Microsoft.Compute/virtualMachines/vm-01"
        )

        # First get_by_id → EXTRACTING; second (post-batch) → cancellation pending
        assessment_active = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        assessment_cancelled = _make_assessment(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            cancellation_requested_at=_now(),
        )
        cred = _make_credential_record(tenant_id=tenant_id, subscription_id=sub_id)
        rg_row = _make_rg_row(resource_id)
        upserted = _make_upserted_resource(
            resource_id=resource_id,
            assessment_id=assessment_id,
            batch_id=batch_id,
            tenant_id=tenant_id,
            subscription_id=sub_id,
        )
        _configure_happy_path(
            m,
            assessment=assessment_active,
            credential_record=cred,
            rg_rows=[rg_row],
            upserted_resources=[upserted],
            refreshed_assessment=assessment_cancelled,
        )

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
                resource_ids=[resource_id],
            )
        )

        # Resources should still be upserted but reasoning event must NOT be published
        m.assessment_repo.upsert_resource.assert_called_once()
        m.publisher.publish.assert_not_called()

    async def test_batch_in_progress_marked_before_extraction(self) -> None:
        """IN_PROGRESS must be set before any Azure calls to guard against lock timeout."""
        m = _Mocks()
        tenant_id = uuid.uuid4()
        assessment_id = uuid.uuid4()
        batch_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        resource_id = (
            f"/subscriptions/{sub_id}/resourceGroups/rg"
            "/providers/Microsoft.Compute/virtualMachines/vm-01"
        )

        assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
        cred = _make_credential_record(tenant_id=tenant_id, subscription_id=sub_id)
        rg_row = _make_rg_row(resource_id)
        upserted = _make_upserted_resource(
            resource_id=resource_id,
            assessment_id=assessment_id,
            batch_id=batch_id,
            tenant_id=tenant_id,
            subscription_id=sub_id,
        )
        _configure_happy_path(
            m,
            assessment=assessment,
            credential_record=cred,
            rg_rows=[rg_row],
            upserted_resources=[upserted],
        )

        call_order: list[str] = []
        original_update = m.assessment_repo.update_batch_status

        async def tracking_update(*args: Any, **kwargs: Any) -> None:
            call_order.append(f"update_batch_status:{args[2].value}")

        async def tracking_rg(*args: Any, **kwargs: Any) -> list[dict]:
            call_order.append("rg_call")
            return [rg_row]

        m.assessment_repo.update_batch_status.side_effect = tracking_update
        m.resource_graph.get_resource_properties.side_effect = tracking_rg

        await m.build_handler().process(
            _raw_event(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                batch_id=batch_id,
                subscription_id=sub_id,
                resource_ids=[resource_id],
            )
        )

        # IN_PROGRESS must come before any Resource Graph call
        assert call_order.index("update_batch_status:in_progress") < call_order.index("rg_call")
