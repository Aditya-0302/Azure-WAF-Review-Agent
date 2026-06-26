"""Unit tests for LoggingMiddleware, MetricsMiddleware, and TimeoutMiddleware."""

from __future__ import annotations

import asyncio
import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.agents.contracts import AgentContext, AgentInput, AgentOutput
from waf_shared.agents.middleware import (
    LoggingMiddleware,
    MetricsMiddleware,
    TimeoutMiddleware,
)
from waf_shared.domain.errors.infrastructure_errors import AgentTimeoutError
from waf_shared.telemetry.logging import StructuredLogger


def _ctx(stage: str = "test-stage") -> AgentContext:
    return AgentContext(
        workflow_id=uuid.uuid4(),
        stage_name=stage,
        tenant_id=uuid.uuid4(),
        attempt=1,
    )


def _input() -> AgentInput[str]:
    return AgentInput(payload="hello", context=_ctx())


def _output(duration_ms: float = 10.0) -> AgentOutput[str]:
    return AgentOutput(
        payload="result",
        agent_name="test",
        agent_version="1.0",
        duration_ms=duration_ms,
        attempt=1,
    )


def _mock_logger() -> MagicMock:
    logger = MagicMock(spec=StructuredLogger)
    return logger


@pytest.mark.unit
class TestLoggingMiddleware:
    @pytest.mark.asyncio
    async def test_calls_next_and_returns_output(self) -> None:
        out = _output()
        next_fn = AsyncMock(return_value=out)

        mw = LoggingMiddleware(logger=_mock_logger())
        result = await mw(_input(), _ctx(), next_fn)

        assert result is out
        next_fn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_logs_start_and_complete_on_success(self) -> None:
        logger = _mock_logger()
        next_fn = AsyncMock(return_value=_output())

        await LoggingMiddleware(logger=logger)(_input(), _ctx(), next_fn)

        assert logger.info.call_count == 2
        start_call, complete_call = logger.info.call_args_list
        assert "start" in start_call[0][0]
        assert "complete" in complete_call[0][0]

    @pytest.mark.asyncio
    async def test_re_raises_and_logs_error(self) -> None:
        logger = _mock_logger()
        next_fn = AsyncMock(side_effect=RuntimeError("boom"))

        with pytest.raises(RuntimeError, match="boom"):
            await LoggingMiddleware(logger=logger)(_input(), _ctx(), next_fn)

        logger.error.assert_called_once()
        error_event = logger.error.call_args[0][0]
        assert "error" in error_event


@pytest.mark.unit
class TestMetricsMiddleware:
    def _make_metrics(self) -> MagicMock:
        m = MagicMock()
        m.agent_executions = MagicMock()
        m.agent_executions.add = MagicMock()
        m.agent_errors = MagicMock()
        m.agent_errors.add = MagicMock()
        m.agent_duration = MagicMock()
        m.agent_duration.record = MagicMock()
        return m

    @pytest.mark.asyncio
    async def test_records_execution_counter_and_duration_on_success(self) -> None:
        metrics = self._make_metrics()
        next_fn = AsyncMock(return_value=_output(duration_ms=50.0))

        await MetricsMiddleware(metrics=metrics)(_input(), _ctx(), next_fn)

        metrics.agent_executions.add.assert_called_once()
        metrics.agent_duration.record.assert_called_once()
        # duration recorded in seconds
        call_args = metrics.agent_duration.record.call_args
        assert call_args[0][0] == pytest.approx(0.05)

    @pytest.mark.asyncio
    async def test_records_error_counter_and_re_raises(self) -> None:
        metrics = self._make_metrics()
        next_fn = AsyncMock(side_effect=ValueError("fail"))

        with pytest.raises(ValueError):
            await MetricsMiddleware(metrics=metrics)(_input(), _ctx(), next_fn)

        metrics.agent_errors.add.assert_called_once()
        attrs = metrics.agent_errors.add.call_args[0][1]
        assert attrs["error_type"] == "ValueError"


@pytest.mark.unit
class TestTimeoutMiddleware:
    @pytest.mark.asyncio
    async def test_passes_through_when_within_timeout(self) -> None:
        out = _output()
        next_fn = AsyncMock(return_value=out)

        result = await TimeoutMiddleware(timeout_seconds=10.0)(_input(), _ctx(), next_fn)
        assert result is out

    @pytest.mark.asyncio
    async def test_raises_agent_timeout_error_on_timeout(self) -> None:
        async def _slow(inp: AgentInput, ctx: AgentContext) -> AgentOutput:
            await asyncio.sleep(10.0)
            return _output()

        ctx = _ctx(stage="slow-stage")
        with pytest.raises(AgentTimeoutError) as exc_info:
            await TimeoutMiddleware(timeout_seconds=0.01)(_input(), ctx, _slow)

        assert exc_info.value.timeout_seconds == 0.01
        assert exc_info.value.agent_name == "slow-stage"


@pytest.mark.unit
class TestMiddlewareChainComposition:
    """Verify middleware invocation order when multiple are stacked."""

    @pytest.mark.asyncio
    async def test_middleware_called_in_correct_order(self) -> None:
        call_order: list[str] = []

        class _RecordingMw:
            def __init__(self, name: str) -> None:
                self._name = name

            async def __call__(self, inp: AgentInput, ctx: AgentContext, next) -> AgentOutput:
                call_order.append(f"{self._name}:before")
                out = await next(inp, ctx)
                call_order.append(f"{self._name}:after")
                return out

        middlewares = [_RecordingMw("A"), _RecordingMw("B"), _RecordingMw("C")]

        async def _core(inp: AgentInput, ctx: AgentContext) -> AgentOutput:
            call_order.append("core")
            return _output()

        # Build chain the same way BaseAgent does
        from waf_shared.agents.base_agent import _Handler

        handler: _Handler = _core
        for mw in reversed(middlewares):
            _prev = handler
            _mw = mw

            async def _wrap(
                i: AgentInput,
                c: AgentContext,
                *,
                _p: _Handler = _prev,
                _m=_mw,
            ) -> AgentOutput:
                return await _m(i, c, _p)

            handler = _wrap

        await handler(_input(), _ctx())
        assert call_order == [
            "A:before",
            "B:before",
            "C:before",
            "core",
            "C:after",
            "B:after",
            "A:after",
        ]
