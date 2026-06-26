"""Unit tests for Pipeline: stage sequencing, retry, cancellation, events."""

from __future__ import annotations

import asyncio
import uuid
from typing import Any
from dataclasses import dataclass

import pytest

from waf_shared.agents.base_agent import BaseAgent
from waf_shared.agents.contracts import AgentContext, AgentFailure, AgentSuccess
from waf_shared.agents.pipeline import (
    LocalEventBus,
    Pipeline,
    PipelineConfig,
    PipelineContext,
    PipelineResult,
    PipelineStage,
)
from waf_shared.agents.retry import RetryPolicy
from waf_shared.agents.state import AgentState


# ── Concrete test agents ──────────────────────────────────────────────────────


class EchoAgent(BaseAgent[str, str]):
    _name = "echo"

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload


class UpperAgent(BaseAgent[str, str]):
    _name = "upper"

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload.upper()


class AppendAgent(BaseAgent[str, str]):
    _name = "append"

    def __init__(self, suffix: str) -> None:
        super().__init__()
        self._suffix = suffix

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload + self._suffix


@dataclass
class TransientFailAgent(BaseAgent[str, str]):
    """Fails for the first `fail_times` calls, then succeeds."""

    _name = "transient"
    _call_count: int = 0
    _fail_times: int = 2

    def __init__(self, fail_times: int = 2) -> None:
        super().__init__()
        self._fail_times = fail_times
        self._call_count = 0

    async def process(self, payload: str, context: AgentContext) -> str:
        self._call_count += 1
        if self._call_count <= self._fail_times:
            raise IOError(f"transient #{self._call_count}")
        return f"recovered-{payload}"


class AlwaysFailAgent(BaseAgent[str, str]):
    _name = "always_fail"

    async def process(self, payload: str, context: AgentContext) -> str:
        raise RuntimeError("permanent error")


# ── Helpers ───────────────────────────────────────────────────────────────────


def _context(workflow_id: uuid.UUID | None = None) -> PipelineContext:
    return PipelineContext(
        workflow_id=workflow_id or uuid.uuid4(),
        tenant_id=uuid.uuid4(),
        pipeline_config=PipelineConfig(name="test-pipeline"),
    )


def _no_retry() -> RetryPolicy:
    return RetryPolicy.no_retry()


def _fast_retry(max_attempts: int = 3) -> RetryPolicy:
    return RetryPolicy(
        max_attempts=max_attempts,
        initial_wait_seconds=0.001,
        backoff_factor=1.0,
    )


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestPipelineSuccessPath:
    @pytest.mark.asyncio
    async def test_single_stage_returns_completed(self) -> None:
        stage = PipelineStage(name="echo", agent=EchoAgent(), retry_policy=_no_retry())
        pipeline = Pipeline(stages=[stage], config=PipelineConfig(name="p"))
        result = await pipeline.run("hello", _context())
        assert result.state == AgentState.COMPLETED
        assert result.output == "hello"

    @pytest.mark.asyncio
    async def test_output_threads_through_stages(self) -> None:
        stages = [
            PipelineStage(name="s1", agent=UpperAgent(), retry_policy=_no_retry()),
            PipelineStage(name="s2", agent=AppendAgent("-done"), retry_policy=_no_retry()),
        ]
        pipeline = Pipeline(stages=stages, config=PipelineConfig(name="p"))
        result = await pipeline.run("hello", _context())
        assert result.output == "HELLO-done"

    @pytest.mark.asyncio
    async def test_input_adapter_transforms_previous_output(self) -> None:
        stages = [
            PipelineStage(name="s1", agent=EchoAgent(), retry_policy=_no_retry()),
            PipelineStage(
                name="s2",
                agent=EchoAgent(),
                retry_policy=_no_retry(),
                input_adapter=lambda s: s + "-adapted",
            ),
        ]
        pipeline = Pipeline(stages=stages, config=PipelineConfig(name="p"))
        result = await pipeline.run("start", _context())
        assert result.output == "start-adapted"

    @pytest.mark.asyncio
    async def test_empty_stages_returns_completed_with_original_input(self) -> None:
        pipeline = Pipeline(stages=[], config=PipelineConfig(name="p"))
        result = await pipeline.run("unchanged", _context())
        assert result.state == AgentState.COMPLETED
        assert result.output == "unchanged"

    @pytest.mark.asyncio
    async def test_stage_results_all_populated(self) -> None:
        stages = [
            PipelineStage(name="a", agent=EchoAgent(), retry_policy=_no_retry()),
            PipelineStage(name="b", agent=UpperAgent(), retry_policy=_no_retry()),
        ]
        pipeline = Pipeline(stages=stages, config=PipelineConfig(name="p"))
        result = await pipeline.run("x", _context())
        assert "a" in result.stage_results
        assert "b" in result.stage_results
        assert isinstance(result.stage_results["a"], AgentSuccess)
        assert isinstance(result.stage_results["b"], AgentSuccess)


@pytest.mark.unit
class TestPipelineFailurePath:
    @pytest.mark.asyncio
    async def test_fail_fast_stops_after_first_failure(self) -> None:
        stages = [
            PipelineStage(name="ok", agent=EchoAgent(), retry_policy=_no_retry()),
            PipelineStage(name="bad", agent=AlwaysFailAgent(), retry_policy=_no_retry()),
            PipelineStage(name="never-reached", agent=EchoAgent(), retry_policy=_no_retry()),
        ]
        pipeline = Pipeline(stages=stages, config=PipelineConfig(name="p", fail_fast=True))
        result = await pipeline.run("x", _context())
        assert result.state == AgentState.FAILED
        assert "never-reached" not in result.stage_results

    @pytest.mark.asyncio
    async def test_fail_fast_false_continues_after_failure(self) -> None:
        stages = [
            PipelineStage(name="fail", agent=AlwaysFailAgent(), retry_policy=_no_retry()),
            PipelineStage(name="continue", agent=EchoAgent(), retry_policy=_no_retry()),
        ]
        pipeline = Pipeline(stages=stages, config=PipelineConfig(name="p", fail_fast=False))
        result = await pipeline.run("x", _context())
        assert result.state == AgentState.FAILED
        assert "continue" in result.stage_results

    @pytest.mark.asyncio
    async def test_failed_result_has_error_set(self) -> None:
        stage = PipelineStage(
            name="bad", agent=AlwaysFailAgent(), retry_policy=_no_retry()
        )
        pipeline = Pipeline(stages=[stage], config=PipelineConfig(name="p"))
        result = await pipeline.run("x", _context())
        assert result.error is not None
        assert isinstance(result.error, RuntimeError)


@pytest.mark.unit
class TestPipelineRetry:
    @pytest.mark.asyncio
    async def test_stage_retries_on_transient_failure(self) -> None:
        agent = TransientFailAgent(fail_times=2)
        stage = PipelineStage(
            name="flaky",
            agent=agent,
            retry_policy=_fast_retry(max_attempts=3),
        )
        pipeline = Pipeline(stages=[stage], config=PipelineConfig(name="p"))
        result = await pipeline.run("data", _context())
        assert result.state == AgentState.COMPLETED
        assert result.output == "recovered-data"

    @pytest.mark.asyncio
    async def test_exhausted_retries_mark_stage_failed(self) -> None:
        agent = TransientFailAgent(fail_times=10)
        stage = PipelineStage(
            name="flaky",
            agent=agent,
            retry_policy=_fast_retry(max_attempts=2),
        )
        pipeline = Pipeline(stages=[stage], config=PipelineConfig(name="p"))
        result = await pipeline.run("data", _context())
        assert result.state == AgentState.FAILED
        assert isinstance(result.stage_results["flaky"], AgentFailure)


@pytest.mark.unit
class TestPipelineCancellation:
    @pytest.mark.asyncio
    async def test_cancel_event_stops_execution_before_stage(self) -> None:
        cancel_event = asyncio.Event()
        cancel_event.set()  # pre-cancelled

        stage = PipelineStage(name="echo", agent=EchoAgent(), retry_policy=_no_retry())
        pipeline = Pipeline(stages=[stage], config=PipelineConfig(name="p"))
        result = await pipeline.run("x", _context(), cancel_event=cancel_event)
        assert result.state == AgentState.CANCELLED
        assert result.output is None
        assert len(result.stage_results) == 0

    @pytest.mark.asyncio
    async def test_completed_stages_before_cancel_are_recorded(self) -> None:
        cancel_event = asyncio.Event()

        class _SetCancelAgent(BaseAgent[str, str]):
            _name = "set_cancel"

            def __init__(self, event: asyncio.Event) -> None:
                super().__init__()
                self._event = event

            async def process(self, payload: str, context: AgentContext) -> str:
                self._event.set()  # cancel after this stage runs
                return "done"

        stages = [
            PipelineStage(
                name="first", agent=_SetCancelAgent(cancel_event), retry_policy=_no_retry()
            ),
            PipelineStage(name="second", agent=EchoAgent(), retry_policy=_no_retry()),
        ]
        pipeline = Pipeline(stages=stages, config=PipelineConfig(name="p"))
        result = await pipeline.run("x", _context(), cancel_event=cancel_event)
        assert result.state == AgentState.CANCELLED
        assert "first" in result.stage_results
        assert "second" not in result.stage_results


@pytest.mark.unit
class TestPipelineEventBus:
    @pytest.mark.asyncio
    async def test_events_emitted_for_successful_run(self) -> None:
        bus = LocalEventBus()
        stage = PipelineStage(name="echo", agent=EchoAgent(), retry_policy=_no_retry())
        pipeline = Pipeline(
            stages=[stage], config=PipelineConfig(name="p"), event_bus=bus
        )
        await pipeline.run("x", _context())

        event_types = [e.event_type for e in bus.events]
        from waf_shared.agents.events import AgentEventType

        assert AgentEventType.PIPELINE_STARTED in event_types
        assert AgentEventType.STAGE_STARTED in event_types
        assert AgentEventType.STAGE_COMPLETED in event_types
        assert AgentEventType.PIPELINE_COMPLETED in event_types

    @pytest.mark.asyncio
    async def test_events_emitted_for_failed_run(self) -> None:
        bus = LocalEventBus()
        stage = PipelineStage(
            name="bad", agent=AlwaysFailAgent(), retry_policy=_no_retry()
        )
        pipeline = Pipeline(
            stages=[stage], config=PipelineConfig(name="p"), event_bus=bus
        )
        await pipeline.run("x", _context())

        event_types = [e.event_type for e in bus.events]
        from waf_shared.agents.events import AgentEventType

        assert AgentEventType.STAGE_FAILED in event_types
        assert AgentEventType.PIPELINE_FAILED in event_types
