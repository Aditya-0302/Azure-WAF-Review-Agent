"""Integration tests for the full agent framework stack.

These tests exercise real async coordination across BaseAgent, Pipeline,
WorkflowOrchestrator, LocalEventBus, RetryPolicy, and middleware — no I/O
mocks.  They do NOT require external services and are safe to run in CI
without the AZURE_INTEGRATION_TESTS guard.
"""

from __future__ import annotations

import asyncio
import uuid
from typing import Any

import pytest

from waf_shared.agents.base_agent import BaseAgent
from waf_shared.agents.contracts import AgentContext
from waf_shared.agents.events import AgentEventType
from waf_shared.agents.middleware import LoggingMiddleware, MetricsMiddleware
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
from waf_shared.domain.errors.infrastructure_errors import WorkflowError
from waf_shared.telemetry.logging import StructuredLogger


# ── Concrete agents used across all integration tests ─────────────────────────


class EchoAgent(BaseAgent[str, str]):
    _name = "echo"

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload


class UpperAgent(BaseAgent[str, str]):
    _name = "upper"

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload.upper()


class SuffixAgent(BaseAgent[str, str]):
    _name = "suffix"

    def __init__(self, suffix: str) -> None:
        super().__init__()
        self._suffix = suffix

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload + self._suffix


class FlakyAgent(BaseAgent[str, str]):
    """Fails for the first `fail_times` invocations, then succeeds."""

    _name = "flaky"

    def __init__(self, fail_times: int) -> None:
        super().__init__()
        self._fail_times = fail_times
        self._attempts = 0

    async def process(self, payload: str, context: AgentContext) -> str:
        self._attempts += 1
        if self._attempts <= self._fail_times:
            raise ConnectionError(f"transient #{self._attempts}")
        return f"ok-{payload}"


class AlwaysFailAgent(BaseAgent[str, str]):
    _name = "fail"

    async def process(self, payload: str, context: AgentContext) -> str:
        raise RuntimeError("permanent failure")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _ctx(wid: uuid.UUID | None = None) -> PipelineContext:
    return PipelineContext(
        workflow_id=wid or uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        pipeline_config=PipelineConfig(name="integration-pipeline"),
    )


def _no_retry() -> RetryPolicy:
    return RetryPolicy.no_retry()


def _fast_retry(n: int = 3) -> RetryPolicy:
    return RetryPolicy(
        max_attempts=n,
        initial_wait_seconds=0.001,
        backoff_factor=1.0,
        jitter_factor=0.0,
    )


# ── Integration tests ─────────────────────────────────────────────────────────


@pytest.mark.integration
class TestFullPipelineRun:
    @pytest.mark.asyncio
    async def test_three_stage_pipeline_produces_correct_output(self) -> None:
        """Three chained agents transform the input string step by step."""
        bus = LocalEventBus()
        stages = [
            PipelineStage(name="echo", agent=EchoAgent(), retry_policy=_no_retry()),
            PipelineStage(name="upper", agent=UpperAgent(), retry_policy=_no_retry()),
            PipelineStage(
                name="suffix",
                agent=SuffixAgent("!"),
                retry_policy=_no_retry(),
            ),
        ]
        pipeline = Pipeline(
            stages=stages,
            config=PipelineConfig(name="integration-pipeline"),
            event_bus=bus,
        )
        ctx = _ctx()
        result = await pipeline.run("hello world", ctx)

        assert result.state == AgentState.COMPLETED
        assert result.output == "HELLO WORLD!"
        assert result.error is None
        assert len(result.stage_results) == 3

        # Verify event trail
        event_types = [e.event_type for e in bus.events]
        assert event_types[0] == AgentEventType.PIPELINE_STARTED
        assert event_types[-1] == AgentEventType.PIPELINE_COMPLETED
        assert event_types.count(AgentEventType.STAGE_COMPLETED) == 3

    @pytest.mark.asyncio
    async def test_pipeline_with_retry_recovers_from_transient_failure(self) -> None:
        """FlakyAgent fails 2 times; retry policy allows 3 attempts — should succeed."""
        flaky = FlakyAgent(fail_times=2)
        stage = PipelineStage(
            name="flaky",
            agent=flaky,
            retry_policy=_fast_retry(3),
        )
        pipeline = Pipeline(stages=[stage], config=PipelineConfig(name="retry-pipeline"))
        result = await pipeline.run("data", _ctx())

        assert result.state == AgentState.COMPLETED
        assert result.output == "ok-data"
        assert flaky._attempts == 3


@pytest.mark.integration
class TestOrchestratorLifecycle:
    @pytest.mark.asyncio
    async def test_orchestrator_tracks_workflow_state_transitions(self) -> None:
        bus = LocalEventBus()
        orch = WorkflowOrchestrator(event_bus=bus)

        stages = [
            PipelineStage(name="a", agent=EchoAgent(), retry_policy=_no_retry()),
            PipelineStage(name="b", agent=UpperAgent(), retry_policy=_no_retry()),
        ]
        pipeline = Pipeline(
            stages=stages, config=PipelineConfig(name="lifecycle-pipeline")
        )
        ctx = _ctx()

        # State should not exist before execution
        assert orch.get_state(ctx.workflow_id) is None

        result = await orch.execute(pipeline, "start", ctx)

        assert result.state == AgentState.COMPLETED
        state = orch.get_state(ctx.workflow_id)
        assert state is not None
        assert state.state == AgentState.COMPLETED

        event_types = [e.event_type for e in bus.events]
        assert AgentEventType.WORKFLOW_STARTED in event_types
        assert AgentEventType.WORKFLOW_COMPLETED in event_types

    @pytest.mark.asyncio
    async def test_orchestrator_cancels_pipeline_mid_run(self) -> None:
        """Set the cancel event after the first stage completes."""
        cancel_event = asyncio.Event()

        class _CancelAfterFirstAgent(BaseAgent[str, str]):
            _name = "cancel_trigger"

            def __init__(self, event: asyncio.Event) -> None:
                super().__init__()
                self._event = event

            async def process(self, payload: str, context: AgentContext) -> str:
                self._event.set()
                return "first-done"

        stages = [
            PipelineStage(
                name="trigger",
                agent=_CancelAfterFirstAgent(cancel_event),
                retry_policy=_no_retry(),
            ),
            PipelineStage(
                name="should-not-run", agent=EchoAgent(), retry_policy=_no_retry()
            ),
        ]

        # Wire cancel_event directly into pipeline (bypassing orchestrator wrapper)
        pipeline = Pipeline(stages=stages, config=PipelineConfig(name="cancel-pipeline"))
        ctx = _ctx()

        result = await pipeline.run("x", ctx, cancel_event=cancel_event)

        assert result.state == AgentState.CANCELLED
        assert "trigger" in result.stage_results
        assert "should-not-run" not in result.stage_results

    @pytest.mark.asyncio
    async def test_orchestrator_raises_workflow_error_on_pipeline_failure(self) -> None:
        orch = WorkflowOrchestrator()
        stage = PipelineStage(
            name="bad", agent=AlwaysFailAgent(), retry_policy=_no_retry()
        )
        pipeline = Pipeline(stages=[stage], config=PipelineConfig(name="fail-pipeline"))
        ctx = _ctx()

        with pytest.raises(WorkflowError) as exc_info:
            await orch.execute(pipeline, "x", ctx)

        assert exc_info.value.workflow_id == ctx.workflow_id
        state = orch.get_state(ctx.workflow_id)
        assert state.state == AgentState.FAILED


@pytest.mark.integration
class TestMiddlewareIntegration:
    @pytest.mark.asyncio
    async def test_logging_middleware_applied_to_all_stages(self) -> None:
        """Logging middleware is wired into each agent individually."""
        log_events: list[str] = []

        class _ListLogger(StructuredLogger):
            def __init__(self) -> None:
                super().__init__(service="test", version="1")

            def info(self, event: str, **kwargs: Any) -> None:
                log_events.append(event)

            def error(self, event: str, exc_info: bool = False, **kwargs: Any) -> None:
                log_events.append(event)

        logger = _ListLogger()
        mw = LoggingMiddleware(logger=logger)

        stages = [
            PipelineStage(
                name="a",
                agent=EchoAgent(middleware=[mw]),
                retry_policy=_no_retry(),
            ),
            PipelineStage(
                name="b",
                agent=UpperAgent(middleware=[mw]),
                retry_policy=_no_retry(),
            ),
        ]
        pipeline = Pipeline(stages=stages, config=PipelineConfig(name="p"))
        await pipeline.run("hello", _ctx())

        start_events = [e for e in log_events if "start" in e]
        complete_events = [e for e in log_events if "complete" in e]
        assert len(start_events) == 2
        assert len(complete_events) == 2
