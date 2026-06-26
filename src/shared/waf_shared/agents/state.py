"""State models for agent, stage, and workflow lifecycle tracking."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AgentState(StrEnum):
    IDLE = "idle"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"

    @property
    def is_terminal(self) -> bool:
        return self in (AgentState.COMPLETED, AgentState.FAILED, AgentState.CANCELLED)


class StageState(BaseModel):
    model_config = ConfigDict(frozen=True)

    stage_name: str
    state: AgentState
    attempt: int = 0
    started_at: datetime | None = None
    completed_at: datetime | None = None
    duration_ms: float | None = None
    error_code: str | None = None
    error_message: str | None = None

    @classmethod
    def pending(cls, stage_name: str) -> StageState:
        return cls(stage_name=stage_name, state=AgentState.IDLE)

    @classmethod
    def running(cls, stage_name: str, attempt: int) -> StageState:
        return cls(
            stage_name=stage_name,
            state=AgentState.RUNNING,
            attempt=attempt,
            started_at=datetime.now(UTC),
        )

    def complete(self, duration_ms: float) -> StageState:
        return self.model_copy(
            update={
                "state": AgentState.COMPLETED,
                "completed_at": datetime.now(UTC),
                "duration_ms": duration_ms,
            }
        )

    def fail(self, error_code: str, error_message: str) -> StageState:
        return self.model_copy(
            update={
                "state": AgentState.FAILED,
                "completed_at": datetime.now(UTC),
                "error_code": error_code,
                "error_message": error_message,
            }
        )


class WorkflowState(BaseModel):
    model_config = ConfigDict(frozen=True)

    workflow_id: uuid.UUID
    pipeline_name: str
    state: AgentState
    stages: dict[str, StageState] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.state.is_terminal

    def with_state(self, state: AgentState) -> WorkflowState:
        return self.model_copy(update={"state": state, "updated_at": datetime.now(UTC)})

    def with_stage(self, stage: StageState) -> WorkflowState:
        return self.model_copy(
            update={
                "stages": {**self.stages, stage.stage_name: stage},
                "updated_at": datetime.now(UTC),
            }
        )

    def with_metadata(self, key: str, value: Any) -> WorkflowState:
        return self.model_copy(
            update={
                "metadata": {**self.metadata, key: value},
                "updated_at": datetime.now(UTC),
            }
        )


class WorkflowCheckpoint(BaseModel):
    """Serialisable snapshot for resumable workflows."""

    model_config = ConfigDict(frozen=True)

    workflow_id: uuid.UUID
    pipeline_name: str
    completed_stages: list[str] = Field(default_factory=list)
    current_stage: str | None = None
    intermediate_results: dict[str, Any] = Field(default_factory=dict)
    serialized_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def to_json(self) -> str:
        return self.model_dump_json()

    @classmethod
    def from_json(cls, raw: str) -> WorkflowCheckpoint:
        return cls.model_validate_json(raw)


def _raise_frozen_attr_error(self: object, name: str, value: object) -> None:
    raise AttributeError(f"'{type(self).__name__}' object attribute '{name}' is read-only")


StageState.__setattr__ = _raise_frozen_attr_error  # type: ignore[method-assign]
WorkflowState.__setattr__ = _raise_frozen_attr_error  # type: ignore[method-assign]
WorkflowCheckpoint.__setattr__ = _raise_frozen_attr_error  # type: ignore[method-assign]
