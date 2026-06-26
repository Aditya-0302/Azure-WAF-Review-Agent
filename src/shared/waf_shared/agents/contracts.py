"""Core data contracts for the agent framework.

These types are shared by all layers — interfaces, pipeline, orchestrator,
and middleware — so they live here with no intra-package imports.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Generic, TypeVar

T = TypeVar("T")
TOutput = TypeVar("TOutput")


@dataclass(frozen=True)
class AgentContext:
    """Runtime context injected into every agent execution."""

    workflow_id: uuid.UUID
    stage_name: str
    tenant_id: uuid.UUID
    correlation_id: uuid.UUID = field(default_factory=uuid.uuid4)
    attempt: int = 1
    deadline: datetime | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_attempt(self, attempt: int) -> AgentContext:
        return AgentContext(
            workflow_id=self.workflow_id,
            stage_name=self.stage_name,
            tenant_id=self.tenant_id,
            correlation_id=self.correlation_id,
            attempt=attempt,
            deadline=self.deadline,
            metadata=self.metadata,
        )

    @property
    def is_expired(self) -> bool:
        if self.deadline is None:
            return False
        return datetime.now(UTC) >= self.deadline


@dataclass(frozen=True)
class AgentInput(Generic[T]):
    """Typed input wrapper carrying payload and execution context."""

    payload: T
    context: AgentContext


@dataclass(frozen=True)
class AgentOutput(Generic[T]):
    """Typed output wrapper with timing and provenance metadata."""

    payload: T
    agent_name: str
    agent_version: str
    duration_ms: float
    attempt: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class AgentSuccess(Generic[T]):
    """Successful agent result wrapping an AgentOutput."""

    output: AgentOutput[T]


@dataclass(frozen=True)
class AgentFailure:
    """Failed agent result capturing the error without raising."""

    error: Exception
    agent_name: str
    stage_name: str
    attempt: int
    is_retryable: bool


# Type alias: AgentResult[T] = AgentSuccess[T] | AgentFailure
type AgentResult[T] = AgentSuccess[T] | AgentFailure
