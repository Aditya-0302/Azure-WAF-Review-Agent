"""Unit tests for WorkflowOrchestrator."""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock

import pytest

from waf_shared.agents.base_agent import BaseAgent
from waf_shared.agents.contracts import AgentContext
from waf_shared.agents.orchestrator import WorkflowOrchestrator
from waf_shared.agents.pipeline import (
    LocalEventBus,
    Pipeline,
    PipelineConfig,
    PipelineContext,
    PipelineStage,
)
from waf_shared.agents.retry import RetryPolicy
from waf_shared.agents.state import AgentState


# ── Concrete test agents ──────────────────────────────────────────────────────


class EchoAgent(BaseAgent[str, str]):
    _name = "echo"

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload


class AlwaysFailAgent(BaseAgent[str, str]):
    _name = "fail"

    async def process(self, payload: str, context: AgentContext) -> str:
        raise RuntimeError("agent failure")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_pipeline(*, fail: bool = False) -> Pipeline:
    agent = AlwaysFailAgent() if fail else EchoAgent()
    stage = PipelineStage(name="s", agent=agent, retry_policy=RetryPolicy.no_retry())
    return Pipeline(stages=[stage], config=PipelineConfig(name="test-pipeline"))


def _ctx(workflow_id: uuid.UUID | None = None) -> PipelineContext:
    return PipelineContext(
        workflow_id=workflow_id or uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        pipeline_config=PipelineConfig(name="test-pipeline"),
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestWorkflowOrchestratorExecute:
    @pytest.mark.asyncio
    async def test_successful_pipeline_returns_completed_result(self) -> None:
        orch = WorkflowOrchestrator()
        pipeline = _make_pipeline()
        ctx = _ctx()

        result = await orch.execute(pipeline, "hello", ctx)

        assert result.state == AgentState.COMPLETED
        assert result.output == "hello"

    @pytest.mark.asyncio
    async def test_workflow_state_is_completed_after_success(self) -> None:
        orch = WorkflowOrchestrator()
        pipeline = _make_pipeline()
        ctx = _ctx()

        await orch.execute(pipeline, "x", ctx)

        state = orch.get_state(ctx.workflow_id)
        assert state is not None
        assert state.state == AgentState.COMPLETED

    @pytest.mark.asyncio
    async def test_workflow_state_is_failed_after_pipeline_failure(self) -> None:
        orch = WorkflowOrchestrator()
        pipeline = _make_pipeline(fail=True)
        ctx = _ctx()

        from waf_shared.domain.errors.infrastructure_errors import WorkflowError

        with pytest.raises(WorkflowError):
            await orch.execute(pipeline, "x", ctx)

        state = orch.get_state(ctx.workflow_id)
        assert state is not None
        assert state.state == AgentState.FAILED

    @pytest.mark.asyncio
    async def test_workflow_emits_start_and_completion_events(self) -> None:
        bus = LocalEventBus()
        orch = WorkflowOrchestrator(event_bus=bus)
        pipeline = _make_pipeline()
        ctx = _ctx()

        await orch.execute(pipeline, "x", ctx)

        event_types = [e.event_type for e in bus.events]
        from waf_shared.agents.events import AgentEventType

        assert AgentEventType.WORKFLOW_STARTED in event_types
        assert AgentEventType.WORKFLOW_COMPLETED in event_types


@pytest.mark.unit
class TestWorkflowOrchestratorCancel:
    @pytest.mark.asyncio
    async def test_cancel_returns_false_for_unknown_workflow(self) -> None:
        orch = WorkflowOrchestrator()
        result = await orch.cancel(uuid.uuid4())
        assert result is False

    @pytest.mark.asyncio
    async def test_cancel_returns_true_for_running_workflow(self) -> None:
        orch = WorkflowOrchestrator()
        wid = uuid.uuid4()
        ctx = _ctx(workflow_id=wid)

        # Pre-register the workflow in RUNNING state
        from waf_shared.agents.state import WorkflowState

        async with orch._lock:
            orch._states[wid] = WorkflowState(
                workflow_id=wid, pipeline_name="p", state=AgentState.RUNNING
            )
            orch._cancel_events[wid] = asyncio.Event()

        result = await orch.cancel(wid)
        assert result is True

    @pytest.mark.asyncio
    async def test_cancel_returns_false_for_completed_workflow(self) -> None:
        orch = WorkflowOrchestrator()
        wid = uuid.uuid4()

        from waf_shared.agents.state import WorkflowState

        async with orch._lock:
            orch._states[wid] = WorkflowState(
                workflow_id=wid, pipeline_name="p", state=AgentState.COMPLETED
            )
            orch._cancel_events[wid] = asyncio.Event()

        result = await orch.cancel(wid)
        assert result is False

    @pytest.mark.asyncio
    async def test_get_state_returns_none_for_unknown(self) -> None:
        orch = WorkflowOrchestrator()
        assert orch.get_state(uuid.uuid4()) is None

    @pytest.mark.asyncio
    async def test_get_state_returns_current_state(self) -> None:
        orch = WorkflowOrchestrator()
        pipeline = _make_pipeline()
        ctx = _ctx()

        await orch.execute(pipeline, "x", ctx)

        state = orch.get_state(ctx.workflow_id)
        assert state is not None
        assert state.workflow_id == ctx.workflow_id
        assert state.pipeline_name == "test-pipeline"


@pytest.mark.unit
class TestWorkflowOrchestratorConcurrencyBound:
    @pytest.mark.asyncio
    async def test_respects_max_concurrent_workflows(self) -> None:
        """Only max_concurrent_workflows pipelines can run at the same time."""
        concurrent_count = 0
        max_seen = 0
        lock = asyncio.Lock()

        class _SlowAgent(BaseAgent[str, str]):
            _name = "slow"

            async def process(self, payload: str, context: AgentContext) -> str:
                nonlocal concurrent_count, max_seen
                async with lock:
                    concurrent_count += 1
                    max_seen = max(max_seen, concurrent_count)
                await asyncio.sleep(0.01)
                async with lock:
                    concurrent_count -= 1
                return payload

        orch = WorkflowOrchestrator(max_concurrent_workflows=2)

        async def _run() -> None:
            pipeline = Pipeline(
                stages=[
                    PipelineStage(
                        name="slow",
                        agent=_SlowAgent(),
                        retry_policy=RetryPolicy.no_retry(),
                    )
                ],
                config=PipelineConfig(name="p"),
            )
            ctx = _ctx()
            await orch.execute(pipeline, "x", ctx)

        # Launch 5 concurrent workflows; only 2 should run simultaneously
        await asyncio.gather(*[_run() for _ in range(5)])
        assert max_seen <= 2
