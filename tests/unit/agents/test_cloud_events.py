"""Unit tests for CloudEventEnvelope — serialisation, deserialisation, generic typing."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

import pytest
from pydantic import BaseModel

from waf_shared.domain.events.assessment_events import (
    AssessmentCreatedEvent,
    ExtractionRequestedEvent,
    ReasoningRequestedEvent,
    ReportingRequestedEvent,
)
from waf_shared.domain.events.base import CloudEventEnvelope

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _SampleEvent(BaseModel):
    value: str
    count: int


def _make_envelope(value: str = "hello", count: int = 42) -> CloudEventEnvelope[_SampleEvent]:
    return CloudEventEnvelope.wrap(
        event_type="com.test.sample",
        source="/tests",
        data=_SampleEvent(value=value, count=count),
    )


# ---------------------------------------------------------------------------
# Basic construction and defaults
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCloudEventEnvelopeDefaults:
    def test_specversion_is_1_0(self) -> None:
        env = _make_envelope()
        assert env.specversion == "1.0"

    def test_type_and_source_set(self) -> None:
        env = _make_envelope()
        assert env.type == "com.test.sample"
        assert env.source == "/tests"

    def test_id_is_uuid(self) -> None:
        env = _make_envelope()
        assert isinstance(env.id, uuid.UUID)

    def test_each_envelope_gets_unique_id(self) -> None:
        a = _make_envelope()
        b = _make_envelope()
        assert a.id != b.id

    def test_time_is_utc_aware(self) -> None:
        env = _make_envelope()
        assert env.time.tzinfo is not None

    def test_datacontenttype_default(self) -> None:
        env = _make_envelope()
        assert env.datacontenttype == "application/json"

    def test_data_preserved(self) -> None:
        env = _make_envelope(value="world", count=99)
        assert env.data.value == "world"
        assert env.data.count == 99

    def test_envelope_is_frozen(self) -> None:
        env = _make_envelope()
        with pytest.raises(Exception):
            env.type = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Serialisation round-trip
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestCloudEventSerialisation:
    def test_to_json_bytes_produces_bytes(self) -> None:
        env = _make_envelope()
        raw = env.to_json_bytes()
        assert isinstance(raw, bytes)

    def test_json_is_valid(self) -> None:
        env = _make_envelope()
        payload = json.loads(env.to_json_bytes())
        assert "specversion" in payload
        assert "data" in payload

    def test_json_contains_all_fields(self) -> None:
        env = _make_envelope()
        payload = json.loads(env.to_json_bytes())
        assert payload["specversion"] == "1.0"
        assert payload["type"] == "com.test.sample"
        assert payload["source"] == "/tests"
        assert "id" in payload
        assert "time" in payload

    def test_from_json_bytes_round_trip(self) -> None:
        env = _make_envelope(value="roundtrip", count=7)
        raw = env.to_json_bytes()
        restored = CloudEventEnvelope.from_json_bytes(raw, _SampleEvent)

        assert restored.type == env.type
        assert restored.source == env.source
        assert restored.specversion == env.specversion
        assert restored.data.value == "roundtrip"
        assert restored.data.count == 7

    def test_id_preserved_in_round_trip(self) -> None:
        env = _make_envelope()
        raw = env.to_json_bytes()
        restored = CloudEventEnvelope.from_json_bytes(raw, _SampleEvent)
        assert restored.id == env.id

    def test_time_preserved_in_round_trip(self) -> None:
        env = _make_envelope()
        raw = env.to_json_bytes()
        restored = CloudEventEnvelope.from_json_bytes(raw, _SampleEvent)
        # ISO format round-trip may drop microseconds — compare to second
        assert abs((restored.time - env.time).total_seconds()) < 1.0


# ---------------------------------------------------------------------------
# Domain event round-trips
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestAssessmentCreatedEventRoundTrip:
    def _make_event(self) -> AssessmentCreatedEvent:
        return AssessmentCreatedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            subscription_ids=[uuid.uuid4(), uuid.uuid4()],
            pillar_filter=["Security", "Reliability"],
            tag_filter={"env": "prod"},
            requested_by_oid=uuid.uuid4(),
            created_at=datetime.now(UTC),
        )

    def test_round_trip(self) -> None:
        event = self._make_event()
        env = CloudEventEnvelope.wrap(
            event_type="com.wafagent.assessment.created",
            source="/api/assessments",
            data=event,
        )
        raw = env.to_json_bytes()
        restored = CloudEventEnvelope.from_json_bytes(raw, AssessmentCreatedEvent)

        assert restored.data.assessment_id == event.assessment_id
        assert restored.data.tenant_id == event.tenant_id
        assert restored.data.pillar_filter == event.pillar_filter
        assert restored.data.tag_filter == event.tag_filter
        assert len(restored.data.subscription_ids) == 2

    def test_json_schema_required_fields(self) -> None:
        event = self._make_event()
        env = CloudEventEnvelope.wrap(
            event_type="com.wafagent.assessment.created",
            source="/api",
            data=event,
        )
        payload = json.loads(env.to_json_bytes())
        assert "assessment_id" in payload["data"]
        assert "tenant_id" in payload["data"]
        assert "subscription_ids" in payload["data"]


@pytest.mark.unit
class TestExtractionRequestedEventRoundTrip:
    def test_round_trip(self) -> None:
        event = ExtractionRequestedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            subscription_id=uuid.uuid4(),
            batch_index=3,
            resource_ids=[
                "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1"
            ],
        )
        raw = CloudEventEnvelope.wrap(
            event_type="com.wafagent.extraction.requested",
            source="/agents/preparation",
            data=event,
        ).to_json_bytes()

        restored = CloudEventEnvelope.from_json_bytes(raw, ExtractionRequestedEvent)
        assert restored.data.batch_index == 3
        assert len(restored.data.resource_ids) == 1


@pytest.mark.unit
class TestReasoningRequestedEventRoundTrip:
    def test_round_trip(self) -> None:
        event = ReasoningRequestedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            subscription_id=uuid.uuid4(),
            batch_index=0,
            total_batches=5,
        )
        raw = CloudEventEnvelope.wrap(
            event_type="com.wafagent.reasoning.requested",
            source="/agents/extraction",
            data=event,
        ).to_json_bytes()

        restored = CloudEventEnvelope.from_json_bytes(raw, ReasoningRequestedEvent)
        assert restored.data.total_batches == 5


@pytest.mark.unit
class TestReportingRequestedEventRoundTrip:
    def test_round_trip(self) -> None:
        event = ReportingRequestedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            total_findings=42,
        )
        raw = CloudEventEnvelope.wrap(
            event_type="com.wafagent.reporting.requested",
            source="/agents/reasoning",
            data=event,
        ).to_json_bytes()

        restored = CloudEventEnvelope.from_json_bytes(raw, ReportingRequestedEvent)
        assert restored.data.total_findings == 42
