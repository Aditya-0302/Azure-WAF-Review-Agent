"""Public API surface for the waf_shared.agents package."""

from waf_shared.agents.base_agent import BaseAgent
from waf_shared.agents.contracts import (
    AgentContext,
    AgentFailure,
    AgentInput,
    AgentOutput,
    AgentResult,
    AgentSuccess,
)
from waf_shared.agents.events import (
    AgentCompletedEvent,
    AgentEvent,
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
from waf_shared.agents.interfaces import (
    IAgent,
    IAgentMiddleware,
    IEventBus,
    IPipeline,
    IWorkflowOrchestrator,
    NextHandler,
)
from waf_shared.agents.metrics import AgentMetrics
from waf_shared.agents.middleware import (
    LoggingMiddleware,
    MetricsMiddleware,
    TimeoutMiddleware,
)
from waf_shared.agents.orchestrator import WorkflowOrchestrator
from waf_shared.agents.pipeline import (
    LocalEventBus,
    Pipeline,
    PipelineConfig,
    PipelineContext,
    PipelineResult,
    PipelineStage,
)
from waf_shared.agents.retry import (
    RetryContext,
    RetryPolicy,
    RetryStrategy,
    with_agent_retry,
)
from waf_shared.agents.state import (
    AgentState,
    StageState,
    WorkflowCheckpoint,
    WorkflowState,
)

__all__ = [
    # Base
    "BaseAgent",
    # Contracts
    "AgentContext",
    "AgentInput",
    "AgentOutput",
    "AgentSuccess",
    "AgentFailure",
    "AgentResult",
    # State
    "AgentState",
    "StageState",
    "WorkflowState",
    "WorkflowCheckpoint",
    # Events
    "AgentEventType",
    "AgentEvent",
    "AgentStartedEvent",
    "AgentCompletedEvent",
    "AgentFailedEvent",
    "AgentRetryingEvent",
    "StageStartedEvent",
    "StageCompletedEvent",
    "StageFailedEvent",
    "PipelineStartedEvent",
    "PipelineCompletedEvent",
    "PipelineFailedEvent",
    "WorkflowStartedEvent",
    "WorkflowCompletedEvent",
    "WorkflowFailedEvent",
    "WorkflowCancelledEvent",
    # Interfaces
    "IAgent",
    "IPipeline",
    "IWorkflowOrchestrator",
    "IAgentMiddleware",
    "IEventBus",
    "NextHandler",
    # Retry
    "RetryStrategy",
    "RetryPolicy",
    "RetryContext",
    "with_agent_retry",
    # Metrics
    "AgentMetrics",
    # Middleware
    "LoggingMiddleware",
    "MetricsMiddleware",
    "TimeoutMiddleware",
    # Pipeline
    "PipelineStage",
    "PipelineConfig",
    "PipelineContext",
    "PipelineResult",
    "Pipeline",
    "LocalEventBus",
    # Orchestrator
    "WorkflowOrchestrator",
]
