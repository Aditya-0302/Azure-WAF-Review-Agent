"""Built-in middleware implementations for the agent framework.

Middleware is applied inside-out: the first element in the list is the
outermost wrapper (called first, returns last).  BaseAgent.execute() builds
the chain by iterating the list in reverse with default-argument capture to
avoid closure-over-loop bugs.
"""

from __future__ import annotations

import asyncio
from typing import Any

from waf_shared.agents.contracts import AgentContext, AgentInput, AgentOutput
from waf_shared.agents.interfaces import IAgentMiddleware, NextHandler
from waf_shared.agents.metrics import AgentMetrics
from waf_shared.domain.errors.infrastructure_errors import AgentTimeoutError
from waf_shared.telemetry.logging import StructuredLogger


class LoggingMiddleware(IAgentMiddleware):
    """Emits structured start/complete/error log lines around every execution."""

    def __init__(self, logger: StructuredLogger) -> None:
        self._logger = logger

    async def __call__(
        self,
        agent_input: AgentInput[Any],
        context: AgentContext,
        next: NextHandler,
    ) -> AgentOutput[Any]:
        self._logger.info(
            "agent.execution.start",
            stage_name=context.stage_name,
            workflow_id=str(context.workflow_id),
            tenant_id=str(context.tenant_id),
            attempt=context.attempt,
        )
        try:
            output = await next(agent_input, context)
            self._logger.info(
                "agent.execution.complete",
                stage_name=context.stage_name,
                workflow_id=str(context.workflow_id),
                duration_ms=round(output.duration_ms, 1),
                attempt=output.attempt,
            )
            return output
        except Exception as exc:
            self._logger.error(
                "agent.execution.error",
                stage_name=context.stage_name,
                workflow_id=str(context.workflow_id),
                attempt=context.attempt,
                error=str(exc),
                exc_info=True,
            )
            raise


class MetricsMiddleware(IAgentMiddleware):
    """Records OTel execution count, error count, and duration histograms."""

    def __init__(self, metrics: AgentMetrics) -> None:
        self._metrics = metrics

    async def __call__(
        self,
        agent_input: AgentInput[Any],
        context: AgentContext,
        next: NextHandler,
    ) -> AgentOutput[Any]:
        attrs = {"agent_stage": context.stage_name, "attempt": str(context.attempt)}
        self._metrics.agent_executions.add(1, attrs)
        try:
            output = await next(agent_input, context)
            self._metrics.agent_duration.record(
                output.duration_ms / 1000.0,
                {"agent_stage": context.stage_name, "status": "success"},
            )
            return output
        except Exception as exc:
            self._metrics.agent_errors.add(
                1,
                {"agent_stage": context.stage_name, "error_type": type(exc).__name__},
            )
            raise


class TimeoutMiddleware(IAgentMiddleware):
    """Raises AgentTimeoutError if the inner handler exceeds the deadline."""

    def __init__(self, timeout_seconds: float) -> None:
        self._timeout = timeout_seconds

    async def __call__(
        self,
        agent_input: AgentInput[Any],
        context: AgentContext,
        next: NextHandler,
    ) -> AgentOutput[Any]:
        try:
            return await asyncio.wait_for(next(agent_input, context), timeout=self._timeout)
        except TimeoutError as exc:
            raise AgentTimeoutError(
                agent_name=context.stage_name,
                timeout_seconds=self._timeout,
            ) from exc
