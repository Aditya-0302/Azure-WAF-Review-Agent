"""Abstract interfaces for the agent framework.

These ABCs define the contracts that concrete agents, pipelines, orchestrators,
middleware, and event buses must satisfy. All I/O is async.

TYPE_CHECKING imports avoid circular dependencies at runtime while preserving
full static analysis coverage.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, Generic, TypeVar

if TYPE_CHECKING:
    from waf_shared.agents.contracts import (
        AgentContext,
        AgentInput,
        AgentOutput,
    )
    from waf_shared.agents.events import AgentEvent
    from waf_shared.agents.pipeline import PipelineContext, PipelineResult
    from waf_shared.agents.state import WorkflowState

TInput = TypeVar("TInput")
TOutput = TypeVar("TOutput")

# Type alias for the "next" handler in a middleware chain
NextHandler = Callable[
    ["AgentInput[Any]", "AgentContext"],
    Awaitable["AgentOutput[Any]"],
]


class IAgent(ABC, Generic[TInput, TOutput]):
    """Single-responsibility unit of work with typed input/output."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Stable identifier used in logs, metrics, and events."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Semver string; included in AgentOutput for provenance tracking."""

    @abstractmethod
    async def execute(
        self,
        agent_input: AgentInput[TInput],
        context: AgentContext,
    ) -> AgentOutput[TOutput]:
        """Run the agent and return a typed output.

        Implementations should raise on unrecoverable failure; the pipeline
        retry wrapper handles transient errors before reaching here.
        """


class IPipeline(ABC, Generic[TInput, TOutput]):
    """Ordered sequence of stages that transforms TInput → TOutput."""

    @abstractmethod
    async def run(
        self,
        input: TInput,
        context: PipelineContext,
        *,
        cancel_event: Any | None = None,
    ) -> PipelineResult[TOutput]:
        """Execute all stages and return the composite result."""


class IWorkflowOrchestrator(ABC):
    """Lifecycle manager for pipeline executions."""

    @abstractmethod
    async def execute(
        self,
        pipeline: IPipeline[Any, Any],
        input: Any,
        context: PipelineContext,
    ) -> PipelineResult[Any]:
        """Schedule and run a pipeline, tracking workflow state."""

    @abstractmethod
    async def cancel(self, workflow_id: uuid.UUID) -> bool:
        """Request cooperative cancellation. Returns False if already terminal."""

    @abstractmethod
    def get_state(self, workflow_id: uuid.UUID) -> WorkflowState | None:
        """Return the current WorkflowState, or None if unknown."""


class IAgentMiddleware(ABC):
    """Composable decorator applied around every agent execution."""

    @abstractmethod
    async def __call__(
        self,
        agent_input: AgentInput[Any],
        context: AgentContext,
        next: NextHandler,
    ) -> AgentOutput[Any]:
        """Wrap the next handler — call next() to continue the chain."""


class IEventBus(ABC):
    """Async event publisher consumed by pipelines and the orchestrator."""

    @abstractmethod
    async def publish(self, event: AgentEvent) -> None:
        """Publish a single event. Implementations must not raise on delivery failure."""
