"""WorkflowOrchestrator: lifecycle manager for concurrent pipeline executions.

Responsibilities
----------------
* Enforce max_concurrent_workflows via an asyncio.Semaphore.
* Track per-workflow state (WorkflowState) in memory.
* Support cooperative cancellation: cancel() sets an asyncio.Event that the
  Pipeline checks before starting each stage.
* Emit workflow-level events via an optional IEventBus.
* Record OTel metrics for workflow starts, completions, and duration.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

from waf_shared.agents.events import (
    WorkflowCancelledEvent,
    WorkflowCompletedEvent,
    WorkflowFailedEvent,
    WorkflowStartedEvent,
)
from waf_shared.agents.interfaces import IEventBus, IPipeline, IWorkflowOrchestrator
from waf_shared.agents.metrics import AgentMetrics
from waf_shared.agents.pipeline import PipelineContext, PipelineResult
from waf_shared.agents.state import AgentState, WorkflowState
from waf_shared.domain.errors.infrastructure_errors import WorkflowError
from waf_shared.telemetry.logging import StructuredLogger


class WorkflowOrchestrator(IWorkflowOrchestrator):
    def __init__(
        self,
        *,
        event_bus: IEventBus | None = None,
        max_concurrent_workflows: int = 10,
        logger: StructuredLogger | None = None,
        metrics: AgentMetrics | None = None,
    ) -> None:
        self._event_bus = event_bus
        self._semaphore = asyncio.Semaphore(max_concurrent_workflows)
        self._logger = logger or StructuredLogger(service="workflow.orchestrator", version="1.0")
        self._metrics = metrics

        # Guarded by _lock for thread-safe state mutations
        self._states: dict[uuid.UUID, WorkflowState] = {}
        self._cancel_events: dict[uuid.UUID, asyncio.Event] = {}
        self._lock = asyncio.Lock()

    # ── Public API ────────────────────────────────────────────────────────────

    async def execute(
        self,
        pipeline: IPipeline[Any, Any],
        input: Any,
        context: PipelineContext,
    ) -> PipelineResult[Any]:
        wid = context.workflow_id
        cancel_event = asyncio.Event()
        pipeline_name = context.pipeline_config.name

        initial_state = WorkflowState(
            workflow_id=wid,
            pipeline_name=pipeline_name,
            state=AgentState.IDLE,
        )

        async with self._lock:
            self._states[wid] = initial_state
            self._cancel_events[wid] = cancel_event

        if self._metrics:
            self._metrics.workflow_executions.add(1, {"pipeline": pipeline_name})

        started = time.monotonic()

        try:
            async with self._semaphore:
                await self._set_state(wid, AgentState.RUNNING)
                await self._emit(
                    WorkflowStartedEvent(
                        workflow_id=wid,
                        correlation_id=context.correlation_id,
                        tenant_id=context.tenant_id,
                        pipeline_name=pipeline_name,
                    )
                )

                result = await pipeline.run(input, context, cancel_event=cancel_event)

                duration_ms = (time.monotonic() - started) * 1000

                if result.state == AgentState.CANCELLED:
                    await self._set_state(wid, AgentState.CANCELLED)
                    await self._emit(
                        WorkflowCancelledEvent(
                            workflow_id=wid,
                            correlation_id=context.correlation_id,
                            tenant_id=context.tenant_id,
                            pipeline_name=pipeline_name,
                        )
                    )
                elif result.state == AgentState.COMPLETED:
                    await self._set_state(wid, AgentState.COMPLETED)
                    await self._emit(
                        WorkflowCompletedEvent(
                            workflow_id=wid,
                            correlation_id=context.correlation_id,
                            tenant_id=context.tenant_id,
                            pipeline_name=pipeline_name,
                            duration_ms=duration_ms,
                        )
                    )
                else:
                    await self._set_state(wid, AgentState.FAILED)
                    error = result.error
                    await self._emit(
                        WorkflowFailedEvent(
                            workflow_id=wid,
                            correlation_id=context.correlation_id,
                            tenant_id=context.tenant_id,
                            pipeline_name=pipeline_name,
                            error_code=type(error).__name__ if error else "UNKNOWN",
                            error_message=str(error) if error else "pipeline returned FAILED",
                        )
                    )
                    if self._metrics:
                        self._metrics.workflow_completions.add(
                            1, {"pipeline": pipeline_name, "state": result.state.value}
                        )
                        self._metrics.workflow_duration.record(
                            duration_ms / 1000.0, {"pipeline": pipeline_name}
                        )
                    raise WorkflowError(
                        wid, str(error) if error else "pipeline returned FAILED"
                    ) from error

                if self._metrics:
                    self._metrics.workflow_completions.add(
                        1, {"pipeline": pipeline_name, "state": result.state.value}
                    )
                    self._metrics.workflow_duration.record(
                        duration_ms / 1000.0, {"pipeline": pipeline_name}
                    )

                return result

        except asyncio.CancelledError:
            await self._set_state(wid, AgentState.CANCELLED)
            await self._emit(
                WorkflowCancelledEvent(
                    workflow_id=wid,
                    correlation_id=context.correlation_id,
                    tenant_id=context.tenant_id,
                    pipeline_name=pipeline_name,
                )
            )
            if self._metrics:
                self._metrics.workflow_completions.add(
                    1, {"pipeline": pipeline_name, "state": "cancelled"}
                )
            raise

        except Exception as exc:
            await self._set_state(wid, AgentState.FAILED)
            duration_ms = (time.monotonic() - started) * 1000
            await self._emit(
                WorkflowFailedEvent(
                    workflow_id=wid,
                    correlation_id=context.correlation_id,
                    tenant_id=context.tenant_id,
                    pipeline_name=pipeline_name,
                    error_code=type(exc).__name__,
                    error_message=str(exc),
                )
            )
            if self._metrics:
                self._metrics.workflow_completions.add(
                    1, {"pipeline": pipeline_name, "state": "failed"}
                )
            raise WorkflowError(wid, str(exc)) from exc

    async def cancel(self, workflow_id: uuid.UUID) -> bool:
        async with self._lock:
            state = self._states.get(workflow_id)
            cancel_event = self._cancel_events.get(workflow_id)

        if state is None or cancel_event is None:
            return False
        if state.is_terminal:
            return False

        cancel_event.set()
        self._logger.info(
            "workflow.cancel.requested",
            workflow_id=str(workflow_id),
            current_state=state.state.value,
        )
        return True

    def get_state(self, workflow_id: uuid.UUID) -> WorkflowState | None:
        return self._states.get(workflow_id)

    # ── Internals ─────────────────────────────────────────────────────────────

    async def _set_state(self, workflow_id: uuid.UUID, state: AgentState) -> None:
        async with self._lock:
            current = self._states.get(workflow_id)
            if current is not None:
                self._states[workflow_id] = current.with_state(state)

    async def _emit(self, event: Any) -> None:
        if self._event_bus is None:
            return
        try:
            await self._event_bus.publish(event)
        except Exception as exc:
            self._logger.warning("orchestrator.event.publish_failed", error=str(exc))
