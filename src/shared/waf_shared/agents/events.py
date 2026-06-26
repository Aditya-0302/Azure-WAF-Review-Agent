"""Agent, pipeline, and workflow lifecycle events.

All events are frozen Pydantic models with auto-generated IDs and timestamps.
Concrete event types set their event_type default so callers need not supply it.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentEventType(StrEnum):
    AGENT_STARTED = "agent.started"
    AGENT_COMPLETED = "agent.completed"
    AGENT_FAILED = "agent.failed"
    AGENT_RETRYING = "agent.retrying"
    STAGE_STARTED = "pipeline.stage.started"
    STAGE_COMPLETED = "pipeline.stage.completed"
    STAGE_FAILED = "pipeline.stage.failed"
    PIPELINE_STARTED = "pipeline.started"
    PIPELINE_COMPLETED = "pipeline.completed"
    PIPELINE_FAILED = "pipeline.failed"
    WORKFLOW_STARTED = "workflow.started"
    WORKFLOW_COMPLETED = "workflow.completed"
    WORKFLOW_FAILED = "workflow.failed"
    WORKFLOW_CANCELLED = "workflow.cancelled"


class AgentEvent(BaseModel):
    model_config = ConfigDict(frozen=True)

    event_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    event_type: AgentEventType
    workflow_id: uuid.UUID
    correlation_id: uuid.UUID
    tenant_id: uuid.UUID
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)


# ── Agent-level events ────────────────────────────────────────────────────────


class AgentStartedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.AGENT_STARTED
    agent_name: str
    agent_version: str
    stage_name: str
    attempt: int


class AgentCompletedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.AGENT_COMPLETED
    agent_name: str
    agent_version: str
    stage_name: str
    attempt: int
    duration_ms: float


class AgentFailedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.AGENT_FAILED
    agent_name: str
    stage_name: str
    attempt: int
    error_code: str
    error_message: str
    is_retryable: bool


class AgentRetryingEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.AGENT_RETRYING
    agent_name: str
    stage_name: str
    attempt: int
    wait_seconds: float
    reason: str


# ── Stage-level events ────────────────────────────────────────────────────────


class StageStartedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.STAGE_STARTED
    stage_name: str


class StageCompletedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.STAGE_COMPLETED
    stage_name: str
    duration_ms: float


class StageFailedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.STAGE_FAILED
    stage_name: str
    error_code: str
    error_message: str


# ── Pipeline-level events ─────────────────────────────────────────────────────


class PipelineStartedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.PIPELINE_STARTED
    pipeline_name: str
    pipeline_version: str
    stage_count: int


class PipelineCompletedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.PIPELINE_COMPLETED
    pipeline_name: str
    pipeline_version: str
    duration_ms: float
    stage_count: int


class PipelineFailedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.PIPELINE_FAILED
    pipeline_name: str
    failed_stage: str
    error_code: str
    error_message: str


# ── Workflow-level events ─────────────────────────────────────────────────────


class WorkflowStartedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.WORKFLOW_STARTED
    pipeline_name: str


class WorkflowCompletedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.WORKFLOW_COMPLETED
    pipeline_name: str
    duration_ms: float


class WorkflowFailedEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.WORKFLOW_FAILED
    pipeline_name: str
    error_code: str
    error_message: str


class WorkflowCancelledEvent(AgentEvent):
    event_type: AgentEventType = AgentEventType.WORKFLOW_CANCELLED
    pipeline_name: str


def _raise_frozen_attr_error(self: object, name: str, value: object) -> None:
    raise AttributeError(f"'{type(self).__name__}' is immutable")


for _cls in [
    AgentEvent,
    AgentStartedEvent,
    AgentCompletedEvent,
    AgentFailedEvent,
    AgentRetryingEvent,
    StageStartedEvent,
    StageCompletedEvent,
    StageFailedEvent,
    PipelineStartedEvent,
    PipelineCompletedEvent,
    PipelineFailedEvent,
    WorkflowStartedEvent,
    WorkflowCompletedEvent,
    WorkflowFailedEvent,
    WorkflowCancelledEvent,
]:
    _cls.__setattr__ = _raise_frozen_attr_error  # type: ignore[assignment]
