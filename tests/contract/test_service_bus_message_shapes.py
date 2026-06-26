"""Contract tests — Service Bus message shape verification.

These tests enforce that every message published to Azure Service Bus
conforms to the CloudEvents 1.0 envelope with the correct required fields.
They act as producer-side Pact tests without requiring a Pact broker:
the JSON shape is verified against a schema dictionary, ensuring that
consumers (agents) can always deserialise what producers publish.

Marked @pytest.mark.contract so they run in CI alongside unit tests
but can be filtered separately from integration/e2e.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

from waf_shared.domain.events.assessment_events import (
    AssessmentCreatedEvent,
    ExtractionRequestedEvent,
    ReasoningRequestedEvent,
    ReportingRequestedEvent,
)
from waf_shared.domain.events.base import CloudEventEnvelope

pytestmark = pytest.mark.contract


# ---------------------------------------------------------------------------
# Schema validation helper (zero external dependencies)
# ---------------------------------------------------------------------------


def _check_cloud_event_envelope(payload: dict[str, Any]) -> None:
    """Assert top-level CloudEvents 1.0 fields are present and typed correctly."""
    required = {
        "specversion": str,
        "id": str,
        "type": str,
        "source": str,
        "time": str,
        "datacontenttype": str,
        "data": dict,
    }
    for field, expected_type in required.items():
        assert field in payload, f"Missing required CloudEvents field: {field}"
        assert isinstance(payload[field], expected_type), (
            f"Field '{field}' expected {expected_type.__name__}, "
            f"got {type(payload[field]).__name__}"
        )
    assert payload["specversion"] == "1.0", "specversion must be '1.0'"
    assert payload["datacontenttype"] == "application/json"
    # id must be a valid UUID string
    uuid.UUID(payload["id"])


# ---------------------------------------------------------------------------
# assessment.created contract
# ---------------------------------------------------------------------------


class TestAssessmentCreatedContract:
    def _event(self) -> AssessmentCreatedEvent:
        return AssessmentCreatedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            subscription_ids=[uuid.uuid4()],
            pillar_filter=["Security"],
            tag_filter={"env": "prod"},
            requested_by_oid=uuid.uuid4(),
            created_at=datetime.now(UTC),
        )

    def test_envelope_shape(self) -> None:
        event = self._event()
        env = CloudEventEnvelope.wrap(
            event_type="com.wafagent.assessment.created",
            source="/api/v1/assessments",
            data=event,
        )
        payload = json.loads(env.to_json_bytes())
        _check_cloud_event_envelope(payload)
        assert payload["type"] == "com.wafagent.assessment.created"
        assert payload["source"] == "/api/v1/assessments"

    def test_data_required_fields(self) -> None:
        event = self._event()
        env = CloudEventEnvelope.wrap(
            event_type="com.wafagent.assessment.created",
            source="/api/v1/assessments",
            data=event,
        )
        data = json.loads(env.to_json_bytes())["data"]

        for field in (
            "assessment_id",
            "tenant_id",
            "subscription_ids",
            "pillar_filter",
            "created_at",
        ):
            assert field in data, f"Missing data field: {field}"

    def test_subscription_ids_is_list(self) -> None:
        event = self._event()
        data = json.loads(
            CloudEventEnvelope.wrap(
                event_type="com.wafagent.assessment.created",
                source="/api",
                data=event,
            ).to_json_bytes()
        )["data"]
        assert isinstance(data["subscription_ids"], list)
        assert len(data["subscription_ids"]) >= 1

    def test_no_sas_url_in_payload(self) -> None:
        event = self._event()
        raw = CloudEventEnvelope.wrap(
            event_type="com.wafagent.assessment.created",
            source="/api",
            data=event,
        ).to_json_bytes()
        text = raw.decode()
        assert "sig=" not in text
        assert "blob.core.windows.net" not in text


# ---------------------------------------------------------------------------
# extraction.requested contract
# ---------------------------------------------------------------------------


class TestExtractionRequestedContract:
    def _event(self) -> ExtractionRequestedEvent:
        return ExtractionRequestedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            subscription_id=uuid.uuid4(),
            batch_index=0,
            resource_ids=[
                "/subscriptions/abc/resourceGroups/rg/providers"
                "/Microsoft.Compute/virtualMachines/vm1"
            ],
        )

    def test_envelope_shape(self) -> None:
        event = self._event()
        env = CloudEventEnvelope.wrap(
            event_type="com.wafagent.extraction.requested",
            source="/agents/preparation",
            data=event,
        )
        _check_cloud_event_envelope(json.loads(env.to_json_bytes()))

    def test_data_required_fields(self) -> None:
        event = self._event()
        data = json.loads(
            CloudEventEnvelope.wrap(
                event_type="com.wafagent.extraction.requested",
                source="/agents/preparation",
                data=event,
            ).to_json_bytes()
        )["data"]

        for field in (
            "assessment_id",
            "tenant_id",
            "batch_id",
            "subscription_id",
            "batch_index",
            "resource_ids",
        ):
            assert field in data, f"Missing data field: {field}"

    def test_resource_ids_non_empty(self) -> None:
        event = self._event()
        data = json.loads(
            CloudEventEnvelope.wrap(
                event_type="com.wafagent.extraction.requested",
                source="/agents/preparation",
                data=event,
            ).to_json_bytes()
        )["data"]
        assert isinstance(data["resource_ids"], list)
        assert len(data["resource_ids"]) >= 1

    def test_consumer_can_deserialise(self) -> None:
        """Simulate the consumer (extraction agent) deserialising the message."""
        event = self._event()
        raw = CloudEventEnvelope.wrap(
            event_type="com.wafagent.extraction.requested",
            source="/agents/preparation",
            data=event,
        ).to_json_bytes()

        restored = CloudEventEnvelope.from_json_bytes(raw, ExtractionRequestedEvent)
        assert restored.data.batch_id == event.batch_id
        assert restored.data.batch_index == event.batch_index
        assert restored.data.resource_ids == event.resource_ids


# ---------------------------------------------------------------------------
# reasoning.requested contract
# ---------------------------------------------------------------------------


class TestReasoningRequestedContract:
    def _event(self) -> ReasoningRequestedEvent:
        return ReasoningRequestedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            subscription_id=uuid.uuid4(),
            batch_index=2,
            total_batches=10,
        )

    def test_envelope_shape(self) -> None:
        event = self._event()
        env = CloudEventEnvelope.wrap(
            event_type="com.wafagent.reasoning.requested",
            source="/agents/extraction",
            data=event,
        )
        _check_cloud_event_envelope(json.loads(env.to_json_bytes()))

    def test_total_batches_present(self) -> None:
        event = self._event()
        data = json.loads(
            CloudEventEnvelope.wrap(
                event_type="com.wafagent.reasoning.requested",
                source="/agents/extraction",
                data=event,
            ).to_json_bytes()
        )["data"]
        assert "total_batches" in data
        assert data["total_batches"] == 10

    def test_consumer_can_deserialise(self) -> None:
        event = self._event()
        raw = CloudEventEnvelope.wrap(
            event_type="com.wafagent.reasoning.requested",
            source="/agents/extraction",
            data=event,
        ).to_json_bytes()

        restored = CloudEventEnvelope.from_json_bytes(raw, ReasoningRequestedEvent)
        assert restored.data.total_batches == 10
        assert restored.data.batch_index == 2


# ---------------------------------------------------------------------------
# reporting.requested contract
# ---------------------------------------------------------------------------


class TestReportingRequestedContract:
    def _event(self) -> ReportingRequestedEvent:
        return ReportingRequestedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            total_findings=87,
        )

    def test_envelope_shape(self) -> None:
        event = self._event()
        env = CloudEventEnvelope.wrap(
            event_type="com.wafagent.reporting.requested",
            source="/agents/reasoning",
            data=event,
        )
        _check_cloud_event_envelope(json.loads(env.to_json_bytes()))

    def test_total_findings_present(self) -> None:
        event = self._event()
        data = json.loads(
            CloudEventEnvelope.wrap(
                event_type="com.wafagent.reporting.requested",
                source="/agents/reasoning",
                data=event,
            ).to_json_bytes()
        )["data"]
        assert data["total_findings"] == 87

    def test_consumer_can_deserialise(self) -> None:
        event = self._event()
        raw = CloudEventEnvelope.wrap(
            event_type="com.wafagent.reporting.requested",
            source="/agents/reasoning",
            data=event,
        ).to_json_bytes()

        restored = CloudEventEnvelope.from_json_bytes(raw, ReportingRequestedEvent)
        assert restored.data.total_findings == 87
