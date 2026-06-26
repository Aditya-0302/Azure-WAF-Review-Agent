"""Integration tests for ExtractionHandler.

Uses the real handler + real domain models + real CloudEvent serialisation.
Repository operations and Azure SDK calls are mocked so these tests run
without a live database or Azure subscription.

asyncio_mode = "auto" is set project-wide so @pytest.mark.asyncio is not needed.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.credential_repository import CredentialRepository
from waf_shared.discovery.resource_graph_client import AzureResourceGraphClient
from waf_shared.domain.errors.infrastructure_errors import DatabaseError
from waf_shared.domain.events.assessment_events import (
    ExtractionRequestedEvent,
    ReasoningRequestedEvent,
)
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
from waf_extraction.handler import ExtractionHandler


# ── Shared helpers ─────────────────────────────────────────────────────────────


def _now() -> datetime:
    return datetime.now(UTC)


def _make_assessment(
    *,
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    status: AssessmentStatus = AssessmentStatus.EXTRACTING,
    total_batches: int = 1,
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


def _make_credential(
    tenant_id: uuid.UUID, sub_id: uuid.UUID, health: CredentialHealth = CredentialHealth.HEALTHY
) -> SubscriptionCredential:
    return SubscriptionCredential(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        subscription_id=sub_id,
        display_name="test-cred",
        keyvault_secret_name=f"sp-creds-test-{sub_id}",
        health=health,
        expires_at=None,
        last_health_check_at=_now(),
        created_at=_now(),
        updated_at=_now(),
    )


def _rg_row(resource_id: str, resource_type: str = "microsoft.compute/virtualmachines") -> dict[str, Any]:
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
        "properties": {"provisioningState": "Succeeded", "hardwareProfile": {"vmSize": "Standard_D4s_v5"}},
        "tags": {"Environment": "production", "Owner": "platform-team"},
        "sku": None,
        "kind": None,
        "identity": {"type": "SystemAssigned"},
        "zones": ["2"],
    }


def _upserted(
    *,
    resource_id: str,
    assessment_id: uuid.UUID,
    batch_id: uuid.UUID,
    tenant_id: uuid.UUID,
    sub_id: uuid.UUID,
    raw_props: dict[str, Any] | None = None,
) -> AssessmentResource:
    return AssessmentResource(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        batch_id=batch_id,
        tenant_id=tenant_id,
        resource_id=resource_id,
        resource_type="microsoft.compute/virtualmachines",
        location="eastus",
        subscription_id=sub_id,
        resource_group="rg-prod",
        raw_properties=raw_props or {},
        extracted_at=_now(),
    )


def _build_event_bytes(
    *,
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    batch_id: uuid.UUID,
    sub_id: uuid.UUID,
    batch_index: int = 0,
    resource_ids: list[str],
) -> bytes:
    event = ExtractionRequestedEvent(
        assessment_id=assessment_id,
        tenant_id=tenant_id,
        batch_id=batch_id,
        subscription_id=sub_id,
        batch_index=batch_index,
        resource_ids=resource_ids,
    )
    return CloudEventEnvelope.wrap(
        event_type="com.wafagent.extraction.requested",
        source="/agents/preparation",
        data=event,
    ).to_json_bytes()


def _build_handler(
    *,
    assessment_repo: AssessmentRepository,
    credential_repo: CredentialRepository,
    cross_tenant_provider: CrossTenantCredentialProvider,
    resource_graph: AzureResourceGraphClient,
    publisher: ServiceBusPublisher,
) -> ExtractionHandler:
    logger = MagicMock(spec=StructuredLogger)
    logger.bind.return_value = logger
    return ExtractionHandler(
        assessment_repo=assessment_repo,
        credential_repo=credential_repo,
        cross_tenant_provider=cross_tenant_provider,
        resource_graph=resource_graph,
        publisher=publisher,
        logger=logger,
    )


# ── Tests ──────────────────────────────────────────────────────────────────────


@pytest.mark.integration
async def test_message_to_resources_to_reasoning_event_single_batch() -> None:
    """Full pipeline: extraction.requested → upserted resources → reasoning.requested.

    Verifies status transitions and correct event payload.
    """
    tenant_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    batch_id = uuid.uuid4()
    sub_id = uuid.uuid4()
    resource_ids = [
        f"/subscriptions/{sub_id}/resourceGroups/rg-prod/providers/Microsoft.Compute/virtualMachines/vm-{i}"
        for i in range(3)
    ]
    total_batches = 1

    assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id, total_batches=total_batches)
    cred = _make_credential(tenant_id, sub_id)
    rg_rows = [_rg_row(rid) for rid in resource_ids]
    upserted_resources = [
        _upserted(resource_id=rid, assessment_id=assessment_id, batch_id=batch_id, tenant_id=tenant_id, sub_id=sub_id)
        for rid in resource_ids
    ]

    ar = AsyncMock(spec=AssessmentRepository)
    cr = AsyncMock(spec=CredentialRepository)
    ctp = AsyncMock(spec=CrossTenantCredentialProvider)
    rg = AsyncMock(spec=AzureResourceGraphClient)
    pub = AsyncMock(spec=ServiceBusPublisher)

    ar.get_by_id.return_value = assessment
    ar.update_batch_status.return_value = None
    cr.get_by_subscription.return_value = cred
    ctp.get_credential_for_subscription.return_value = MagicMock()
    rg.get_resource_properties.return_value = rg_rows
    ar.upsert_resource.side_effect = upserted_resources
    pub.publish.return_value = None

    handler = _build_handler(
        assessment_repo=ar, credential_repo=cr,
        cross_tenant_provider=ctp, resource_graph=rg, publisher=pub,
    )
    await handler.process(
        _build_event_bytes(
            assessment_id=assessment_id, tenant_id=tenant_id,
            batch_id=batch_id, sub_id=sub_id, batch_index=0,
            resource_ids=resource_ids,
        )
    )

    # All resources were upserted
    assert ar.upsert_resource.call_count == 3

    # Status transitions: IN_PROGRESS then COMPLETED
    update_calls = ar.update_batch_status.call_args_list
    statuses = [c[0][2] for c in update_calls]
    assert BatchStatus.IN_PROGRESS in statuses
    assert BatchStatus.COMPLETED in statuses
    assert statuses.index(BatchStatus.IN_PROGRESS) < statuses.index(BatchStatus.COMPLETED)

    # One reasoning event published to the correct queue
    pub.publish.assert_called_once()
    queue, envelope = pub.publish.call_args[0]
    assert queue == REASONING_REQUESTED

    # Deserialise and verify the reasoning event payload
    raw_json = envelope.to_json_bytes()
    roundtripped = CloudEventEnvelope.from_json_bytes(raw_json, ReasoningRequestedEvent)
    data = roundtripped.data
    assert data.assessment_id == assessment_id
    assert data.tenant_id == tenant_id
    assert data.batch_id == batch_id
    assert data.subscription_id == sub_id
    assert data.batch_index == 0
    assert data.total_batches == total_batches


@pytest.mark.integration
async def test_partial_success_some_resources_missing() -> None:
    """Resources absent from Resource Graph are upserted with failure marker.

    The batch still completes and the reasoning event is still published.
    """
    tenant_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    batch_id = uuid.uuid4()
    sub_id = uuid.uuid4()
    found_id = f"/subscriptions/{sub_id}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-found"
    deleted_id = f"/subscriptions/{sub_id}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-deleted"
    resource_ids = [found_id, deleted_id]

    assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id, total_batches=1)
    cred = _make_credential(tenant_id, sub_id)
    # Resource Graph only returns one of the two
    rg_rows = [_rg_row(found_id)]

    captured_upserts: list[AssessmentResource] = []

    ar = AsyncMock(spec=AssessmentRepository)
    cr = AsyncMock(spec=CredentialRepository)
    ctp = AsyncMock(spec=CrossTenantCredentialProvider)
    rg = AsyncMock(spec=AzureResourceGraphClient)
    pub = AsyncMock(spec=ServiceBusPublisher)

    ar.get_by_id.return_value = assessment
    ar.update_batch_status.return_value = None
    cr.get_by_subscription.return_value = cred
    ctp.get_credential_for_subscription.return_value = MagicMock()
    rg.get_resource_properties.return_value = rg_rows
    pub.publish.return_value = None

    async def capture_upsert(resource: AssessmentResource) -> AssessmentResource:
        captured_upserts.append(resource)
        return resource

    ar.upsert_resource.side_effect = capture_upsert

    handler = _build_handler(
        assessment_repo=ar, credential_repo=cr,
        cross_tenant_provider=ctp, resource_graph=rg, publisher=pub,
    )
    await handler.process(
        _build_event_bytes(
            assessment_id=assessment_id, tenant_id=tenant_id,
            batch_id=batch_id, sub_id=sub_id,
            resource_ids=resource_ids,
        )
    )

    assert len(captured_upserts) == 2

    found_resource = next(r for r in captured_upserts if r.resource_id == found_id)
    deleted_resource = next(r for r in captured_upserts if r.resource_id == deleted_id)

    # Found resource has full properties
    assert found_resource.raw_properties.get("_extraction_failed") is None
    assert "properties" in found_resource.raw_properties

    # Missing resource has failure marker
    assert deleted_resource.raw_properties.get("_extraction_failed") is True

    # Batch COMPLETED and reasoning event published despite the missing resource
    update_calls = ar.update_batch_status.call_args_list
    assert any(c[0][2] == BatchStatus.COMPLETED for c in update_calls)
    pub.publish.assert_called_once()


@pytest.mark.integration
async def test_cancellation_before_publish_stops_reasoning_event() -> None:
    """Cancellation set between batch completion and publish prevents reasoning.requested."""
    tenant_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    batch_id = uuid.uuid4()
    sub_id = uuid.uuid4()
    resource_id = f"/subscriptions/{sub_id}/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm-01"

    assessment_active = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
    assessment_cancelled = _make_assessment(
        assessment_id=assessment_id, tenant_id=tenant_id,
        cancellation_requested_at=_now(),
    )
    cred = _make_credential(tenant_id, sub_id)
    rg_rows = [_rg_row(resource_id)]

    ar = AsyncMock(spec=AssessmentRepository)
    cr = AsyncMock(spec=CredentialRepository)
    ctp = AsyncMock(spec=CrossTenantCredentialProvider)
    rg = AsyncMock(spec=AzureResourceGraphClient)
    pub = AsyncMock(spec=ServiceBusPublisher)

    # First call → EXTRACTING; second call (after batch completion) → cancellation pending
    ar.get_by_id.side_effect = [assessment_active, assessment_cancelled]
    ar.update_batch_status.return_value = None
    cr.get_by_subscription.return_value = cred
    ctp.get_credential_for_subscription.return_value = MagicMock()
    rg.get_resource_properties.return_value = rg_rows

    async def capture_upsert(resource: AssessmentResource) -> AssessmentResource:
        return resource

    ar.upsert_resource.side_effect = capture_upsert
    pub.publish.return_value = None

    handler = _build_handler(
        assessment_repo=ar, credential_repo=cr,
        cross_tenant_provider=ctp, resource_graph=rg, publisher=pub,
    )
    await handler.process(
        _build_event_bytes(
            assessment_id=assessment_id, tenant_id=tenant_id,
            batch_id=batch_id, sub_id=sub_id,
            resource_ids=[resource_id],
        )
    )

    # Resource was still upserted and batch COMPLETED
    ar.upsert_resource.assert_called_once()
    update_calls = ar.update_batch_status.call_args_list
    assert any(c[0][2] == BatchStatus.COMPLETED for c in update_calls)

    # But no reasoning event
    pub.publish.assert_not_called()


@pytest.mark.integration
async def test_cloudevent_envelope_round_trip_full_properties() -> None:
    """Verify full CloudEvents serialisation / deserialisation preserves all fields.

    Also verifies that raw_properties includes all projected Resource Graph columns.
    """
    tenant_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    batch_id = uuid.uuid4()
    sub_id = uuid.uuid4()
    resource_id = (
        f"/subscriptions/{sub_id}/resourceGroups/rg-prod"
        "/providers/Microsoft.KeyVault/vaults/kv-prod-01"
    )

    row = _rg_row(resource_id, resource_type="microsoft.keyvault/vaults")
    row["properties"] = {
        "sku": {"name": "premium", "family": "A"},
        "enableSoftDelete": True,
        "enablePurgeProtection": True,
    }
    row["tags"] = {"CostCenter": "cc-001", "Application": "secrets-store"}

    assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id, total_batches=1)
    cred = _make_credential(tenant_id, sub_id)

    captured_resources: list[AssessmentResource] = []
    captured_envelopes: list[CloudEventEnvelope] = []

    ar = AsyncMock(spec=AssessmentRepository)
    cr = AsyncMock(spec=CredentialRepository)
    ctp = AsyncMock(spec=CrossTenantCredentialProvider)
    rg = AsyncMock(spec=AzureResourceGraphClient)
    pub = AsyncMock(spec=ServiceBusPublisher)

    ar.get_by_id.return_value = assessment
    ar.update_batch_status.return_value = None
    cr.get_by_subscription.return_value = cred
    ctp.get_credential_for_subscription.return_value = MagicMock()
    rg.get_resource_properties.return_value = [row]

    async def capture_upsert(resource: AssessmentResource) -> AssessmentResource:
        captured_resources.append(resource)
        return resource

    async def capture_publish(queue: str, envelope: CloudEventEnvelope) -> None:
        captured_envelopes.append(envelope)

    ar.upsert_resource.side_effect = capture_upsert
    pub.publish.side_effect = capture_publish

    handler = _build_handler(
        assessment_repo=ar, credential_repo=cr,
        cross_tenant_provider=ctp, resource_graph=rg, publisher=pub,
    )
    await handler.process(
        _build_event_bytes(
            assessment_id=assessment_id, tenant_id=tenant_id,
            batch_id=batch_id, sub_id=sub_id,
            resource_ids=[resource_id],
        )
    )

    # Verify raw_properties stored in the resource
    assert len(captured_resources) == 1
    raw = captured_resources[0].raw_properties
    assert raw["type"] == "microsoft.keyvault/vaults"
    assert raw["location"] == "eastus"
    assert raw["tags"]["CostCenter"] == "cc-001"
    assert raw["properties"]["enableSoftDelete"] is True
    assert raw["identity"] == {"type": "SystemAssigned"}

    # Verify reasoning event round-trips cleanly
    assert len(captured_envelopes) == 1
    env = captured_envelopes[0]
    raw_bytes = env.to_json_bytes()
    restored = CloudEventEnvelope.from_json_bytes(raw_bytes, ReasoningRequestedEvent)
    assert restored.data.assessment_id == assessment_id
    assert restored.data.batch_id == batch_id
    assert restored.data.total_batches == 1


@pytest.mark.integration
async def test_db_error_during_upsert_propagates_for_sb_abandon() -> None:
    """DatabaseError from upsert_resource propagates so the consumer abandons the message."""
    tenant_id = uuid.uuid4()
    assessment_id = uuid.uuid4()
    batch_id = uuid.uuid4()
    sub_id = uuid.uuid4()
    resource_id = (
        f"/subscriptions/{sub_id}/resourceGroups/rg"
        "/providers/Microsoft.Compute/virtualMachines/vm-01"
    )

    assessment = _make_assessment(assessment_id=assessment_id, tenant_id=tenant_id)
    cred = _make_credential(tenant_id, sub_id)

    ar = AsyncMock(spec=AssessmentRepository)
    cr = AsyncMock(spec=CredentialRepository)
    ctp = AsyncMock(spec=CrossTenantCredentialProvider)
    rg = AsyncMock(spec=AzureResourceGraphClient)
    pub = AsyncMock(spec=ServiceBusPublisher)

    ar.get_by_id.return_value = assessment
    ar.update_batch_status.return_value = None
    cr.get_by_subscription.return_value = cred
    ctp.get_credential_for_subscription.return_value = MagicMock()
    rg.get_resource_properties.return_value = [_rg_row(resource_id)]
    ar.upsert_resource.side_effect = DatabaseError("connection pool exhausted")

    handler = _build_handler(
        assessment_repo=ar, credential_repo=cr,
        cross_tenant_provider=ctp, resource_graph=rg, publisher=pub,
    )

    with pytest.raises(DatabaseError, match="connection pool exhausted"):
        await handler.process(
            _build_event_bytes(
                assessment_id=assessment_id, tenant_id=tenant_id,
                batch_id=batch_id, sub_id=sub_id,
                resource_ids=[resource_id],
            )
        )

    # No reasoning event published and batch not marked COMPLETED
    pub.publish.assert_not_called()
    update_calls = ar.update_batch_status.call_args_list
    assert not any(c[0][2] == BatchStatus.COMPLETED for c in update_calls)
