"""Pipeline: ordered stage executor with retry, events, and cancellation support.

Design notes
------------
* Stages are executed sequentially. Each stage's output payload becomes the
  next stage's input unless an input_adapter is provided.
* Per-stage retry is handled by with_agent_retry; the pipeline itself does NOT
  retry entire pipelines.
* Cancellation is cooperative: the pipeline checks cancel_event.is_set() before
  starting each stage and returns CANCELLED without error.
* Events are best-effort: a publish failure is logged as a warning and never
  propagates to the caller.
* fail_fast=True (default) stops on the first stage failure.
  fail_fast=False collects all failures and marks the pipeline FAILED at the end.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field

from waf_shared.agents.contracts import (
    AgentContext,
    AgentFailure,
    AgentInput,
    AgentOutput,
    AgentResult,
    AgentSuccess,
)
from waf_shared.agents.events import (
    PipelineCompletedEvent,
    PipelineFailedEvent,
    PipelineStartedEvent,
    StageCompletedEvent,
    StageFailedEvent,
    StageStartedEvent,
)
from waf_shared.agents.interfaces import IAgent, IEventBus, IPipeline
from waf_shared.agents.retry import RetryContext, RetryPolicy, with_agent_retry
from waf_shared.agents.state import AgentState
from waf_shared.telemetry.logging import StructuredLogger

TInput = TypeVar("TInput")
TOutput = TypeVar("TOutput")


# ── Stage definition ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PipelineStage:
    """One named unit of work within a pipeline.

    Attributes:
        name: Unique stage identifier within the pipeline.
        agent: The IAgent implementation to execute.
        retry_policy: Per-stage retry configuration. Defaults to 3 exponential attempts.
        timeout_seconds: Hard deadline for a single attempt (None = no timeout).
        input_adapter: Optional transform applied to the previous stage's output
            payload before it is passed as this stage's input. When None, the
            previous stage's output payload is used as-is.
    """

    name: str
    agent: IAgent[Any, Any]
    retry_policy: RetryPolicy = field(default_factory=RetryPolicy)
    timeout_seconds: float | None = None
    input_adapter: Callable[[Any], Any] | None = None


# ── Pipeline configuration ────────────────────────────────────────────────────


class PipelineConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    name: str
    version: str = "1.0.0"
    fail_fast: bool = True
    checkpoint_enabled: bool = False


# ── Pipeline execution context ────────────────────────────────────────────────


@dataclass(frozen=True)
class PipelineContext:
    """Immutable context created once per pipeline run and threaded through stages."""

    workflow_id: uuid.UUID
    tenant_id: uuid.UUID
    pipeline_config: PipelineConfig
    correlation_id: uuid.UUID = field(default_factory=uuid.uuid4)
    metadata: dict[str, Any] = field(default_factory=dict)


# ── Pipeline result ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PipelineResult(Generic[TOutput]):
    workflow_id: uuid.UUID
    pipeline_name: str
    output: TOutput | None
    state: AgentState
    stage_results: dict[str, AgentResult[Any]]
    duration_ms: float
    error: Exception | None = None


# ── In-memory event bus ───────────────────────────────────────────────────────


class LocalEventBus(IEventBus):
    """Thread-safe in-memory bus — primarily for testing."""

    def __init__(self) -> None:
        self._events: list[Any] = []

    async def publish(self, event: Any) -> None:
        self._events.append(event)

    @property
    def events(self) -> list[Any]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()


# ── Pipeline executor ─────────────────────────────────────────────────────────


class Pipeline(IPipeline[TInput, TOutput]):
    def __init__(
        self,
        stages: list[PipelineStage],
        config: PipelineConfig,
        *,
        event_bus: IEventBus | None = None,
        logger: StructuredLogger | None = None,
    ) -> None:
        self._stages = stages
        self._config = config
        self._event_bus = event_bus
        self._logger = logger or StructuredLogger(
            service=f"pipeline.{config.name}", version=config.version
        )

    async def run(
        self,
        input: TInput,
        context: PipelineContext,
        *,
        cancel_event: asyncio.Event | None = None,
    ) -> PipelineResult[TOutput]:
        started = time.monotonic()
        stage_results: dict[str, AgentResult[Any]] = {}
        current_value: Any = input
        final_error: Exception | None = None

        await self._emit(
            PipelineStartedEvent(
                workflow_id=context.workflow_id,
                correlation_id=context.correlation_id,
                tenant_id=context.tenant_id,
                pipeline_name=self._config.name,
                pipeline_version=self._config.version,
                stage_count=len(self._stages),
            )
        )

        pipeline_state = AgentState.RUNNING

        for stage in self._stages:
            if cancel_event is not None and cancel_event.is_set():
                pipeline_state = AgentState.CANCELLED
                break

            stage_payload = (
                stage.input_adapter(current_value)
                if stage.input_adapter is not None
                else current_value
            )

            agent_ctx = AgentContext(
                workflow_id=context.workflow_id,
                stage_name=stage.name,
                tenant_id=context.tenant_id,
                correlation_id=context.correlation_id,
                attempt=1,
                metadata=context.metadata,
            )

            await self._emit(
                StageStartedEvent(
                    workflow_id=context.workflow_id,
                    correlation_id=context.correlation_id,
                    tenant_id=context.tenant_id,
                    stage_name=stage.name,
                )
            )

            stage_start = time.monotonic()
            result = await self._execute_stage(stage, stage_payload, agent_ctx)
            stage_ms = (time.monotonic() - stage_start) * 1000

            stage_results[stage.name] = result

            if isinstance(result, AgentFailure):
                final_error = result.error
                await self._emit(
                    StageFailedEvent(
                        workflow_id=context.workflow_id,
                        correlation_id=context.correlation_id,
                        tenant_id=context.tenant_id,
                        stage_name=stage.name,
                        error_code=type(result.error).__name__,
                        error_message=str(result.error),
                    )
                )
                if self._config.fail_fast:
                    pipeline_state = AgentState.FAILED
                    break
                # fail_fast=False: record error but keep going with current_value unchanged
            else:
                current_value = result.output.payload
                await self._emit(
                    StageCompletedEvent(
                        workflow_id=context.workflow_id,
                        correlation_id=context.correlation_id,
                        tenant_id=context.tenant_id,
                        stage_name=stage.name,
                        duration_ms=stage_ms,
                    )
                )

        # If we never broke early due to failure, determine terminal state
        if pipeline_state == AgentState.RUNNING:
            has_failure = any(isinstance(r, AgentFailure) for r in stage_results.values())
            pipeline_state = AgentState.FAILED if has_failure else AgentState.COMPLETED

        duration_ms = (time.monotonic() - started) * 1000

        if pipeline_state == AgentState.COMPLETED:
            await self._emit(
                PipelineCompletedEvent(
                    workflow_id=context.workflow_id,
                    correlation_id=context.correlation_id,
                    tenant_id=context.tenant_id,
                    pipeline_name=self._config.name,
                    pipeline_version=self._config.version,
                    duration_ms=duration_ms,
                    stage_count=len(self._stages),
                )
            )
        elif pipeline_state == AgentState.FAILED and final_error is not None:
            failed_stage = next(
                (n for n, r in stage_results.items() if isinstance(r, AgentFailure)),
                "unknown",
            )
            await self._emit(
                PipelineFailedEvent(
                    workflow_id=context.workflow_id,
                    correlation_id=context.correlation_id,
                    tenant_id=context.tenant_id,
                    pipeline_name=self._config.name,
                    failed_stage=failed_stage,
                    error_code=type(final_error).__name__,
                    error_message=str(final_error),
                )
            )

        return PipelineResult(
            workflow_id=context.workflow_id,
            pipeline_name=self._config.name,
            output=current_value if pipeline_state == AgentState.COMPLETED else None,
            state=pipeline_state,
            stage_results=stage_results,
            duration_ms=duration_ms,
            error=final_error,
        )

    async def _execute_stage(
        self,
        stage: PipelineStage,
        payload: Any,
        base_ctx: AgentContext,
    ) -> AgentResult[Any]:
        attempt_counter = [0]

        async def _invoke() -> AgentOutput[Any]:
            attempt_counter[0] += 1
            ctx = base_ctx.with_attempt(attempt_counter[0])
            inp = AgentInput(payload=payload, context=ctx)

            if stage.timeout_seconds is not None:
                try:
                    return await asyncio.wait_for(
                        stage.agent.execute(inp, ctx),
                        timeout=stage.timeout_seconds,
                    )
                except asyncio.TimeoutError as exc:
                    from waf_shared.domain.errors.infrastructure_errors import AgentTimeoutError

                    raise AgentTimeoutError(
                        agent_name=stage.name,
                        timeout_seconds=stage.timeout_seconds,
                    ) from exc
            return await stage.agent.execute(inp, ctx)

        try:
            output = await with_agent_retry(
                _invoke,
                stage.retry_policy,
                logger=self._logger,
                operation=stage.name,
            )
            return AgentSuccess(output=output)
        except Exception as exc:
            return AgentFailure(
                error=exc,
                agent_name=stage.agent.name,
                stage_name=stage.name,
                attempt=attempt_counter[0],
                is_retryable=False,
            )

    async def _emit(self, event: Any) -> None:
        if self._event_bus is None:
            return
        try:
            await self._event_bus.publish(event)
        except Exception as exc:
            self._logger.warning("pipeline.event.publish_failed", error=str(exc))
