"""Unit tests for AgentEvent and all concrete event subtypes."""

from __future__ import annotations

import uuid

import pytest

from waf_shared.agents.events import (
    AgentCompletedEvent,
    AgentEventType,
    AgentFailedEvent,
    AgentRetryingEvent,
    AgentStartedEvent,
    PipelineCompletedEvent,
    PipelineFailedEvent,
    PipelineStartedEvent,
    StageCompletedEvent,
    StageFailedEvent,
    StageStartedEvent,
    WorkflowCancelledEvent,
    WorkflowCompletedEvent,
    WorkflowFailedEvent,
    WorkflowStartedEvent,
)


def _ids() -> tuple[uuid.UUID, uuid.UUID, uuid.UUID]:
    return uuid.uuid4(), uuid.uuid4(), uuid.uuid4()


@pytest.mark.unit
class TestAgentEventDefaults:
    def test_event_id_auto_generated(self) -> None:
        wid, cid, tid = _ids()
        ev = AgentStartedEvent(
            workflow_id=wid,
            correlation_id=cid,
            tenant_id=tid,
            agent_name="prep",
            agent_version="1.0",
            stage_name="preparation",
            attempt=1,
        )
        assert ev.event_id is not None
        assert isinstance(ev.event_id, uuid.UUID)

    def test_timestamp_set_on_construction(self) -> None:
        wid, cid, tid = _ids()
        ev = WorkflowStartedEvent(
            workflow_id=wid,
            correlation_id=cid,
            tenant_id=tid,
            pipeline_name="waf",
        )
        assert ev.timestamp is not None

    def test_metadata_defaults_empty(self) -> None:
        wid, cid, tid = _ids()
        ev = StageStartedEvent(
            workflow_id=wid, correlation_id=cid, tenant_id=tid, stage_name="s"
        )
        assert ev.metadata == {}


@pytest.mark.unit
class TestAgentEventTypes:
    def test_agent_started_type(self) -> None:
        wid, cid, tid = _ids()
        ev = AgentStartedEvent(
            workflow_id=wid,
            correlation_id=cid,
            tenant_id=tid,
            agent_name="x",
            agent_version="1",
            stage_name="s",
            attempt=1,
        )
        assert ev.event_type == AgentEventType.AGENT_STARTED

    def test_agent_completed_type(self) -> None:
        wid, cid, tid = _ids()
        ev = AgentCompletedEvent(
            workflow_id=wid,
            correlation_id=cid,
            tenant_id=tid,
            agent_name="x",
            agent_version="1",
            stage_name="s",
            attempt=1,
            duration_ms=10.0,
        )
        assert ev.event_type == AgentEventType.AGENT_COMPLETED

    def test_agent_failed_type(self) -> None:
        wid, cid, tid = _ids()
        ev = AgentFailedEvent(
            workflow_id=wid,
            correlation_id=cid,
            tenant_id=tid,
            agent_name="x",
            stage_name="s",
            attempt=1,
            error_code="ERR",
            error_message="oops",
            is_retryable=True,
        )
        assert ev.event_type == AgentEventType.AGENT_FAILED

    def test_agent_retrying_type(self) -> None:
        wid, cid, tid = _ids()
        ev = AgentRetryingEvent(
            workflow_id=wid,
            correlation_id=cid,
            tenant_id=tid,
            agent_name="x",
            stage_name="s",
            attempt=2,
            wait_seconds=1.5,
            reason="transient network error",
        )
        assert ev.event_type == AgentEventType.AGENT_RETRYING

    def test_pipeline_events_have_correct_types(self) -> None:
        wid, cid, tid = _ids()
        common = dict(workflow_id=wid, correlation_id=cid, tenant_id=tid)
        assert PipelineStartedEvent(
            **common, pipeline_name="p", pipeline_version="1", stage_count=3
        ).event_type == AgentEventType.PIPELINE_STARTED
        assert PipelineCompletedEvent(
            **common, pipeline_name="p", pipeline_version="1", duration_ms=1.0, stage_count=3
        ).event_type == AgentEventType.PIPELINE_COMPLETED
        assert PipelineFailedEvent(
            **common,
            pipeline_name="p",
            failed_stage="s",
            error_code="E",
            error_message="m",
        ).event_type == AgentEventType.PIPELINE_FAILED

    def test_workflow_events_have_correct_types(self) -> None:
        wid, cid, tid = _ids()
        common = dict(workflow_id=wid, correlation_id=cid, tenant_id=tid)
        assert WorkflowStartedEvent(
            **common, pipeline_name="p"
        ).event_type == AgentEventType.WORKFLOW_STARTED
        assert WorkflowCompletedEvent(
            **common, pipeline_name="p", duration_ms=1.0
        ).event_type == AgentEventType.WORKFLOW_COMPLETED
        assert WorkflowFailedEvent(
            **common, pipeline_name="p", error_code="E", error_message="m"
        ).event_type == AgentEventType.WORKFLOW_FAILED
        assert WorkflowCancelledEvent(
            **common, pipeline_name="p"
        ).event_type == AgentEventType.WORKFLOW_CANCELLED

    def test_stage_events_have_correct_types(self) -> None:
        wid, cid, tid = _ids()
        common = dict(workflow_id=wid, correlation_id=cid, tenant_id=tid)
        assert StageStartedEvent(
            **common, stage_name="s"
        ).event_type == AgentEventType.STAGE_STARTED
        assert StageCompletedEvent(
            **common, stage_name="s", duration_ms=5.0
        ).event_type == AgentEventType.STAGE_COMPLETED
        assert StageFailedEvent(
            **common, stage_name="s", error_code="E", error_message="m"
        ).event_type == AgentEventType.STAGE_FAILED

    def test_event_is_frozen(self) -> None:
        wid, cid, tid = _ids()
        ev = WorkflowStartedEvent(
            workflow_id=wid, correlation_id=cid, tenant_id=tid, pipeline_name="p"
        )
        with pytest.raises((AttributeError, TypeError)):
            ev.pipeline_name = "other"  # type: ignore[misc]
