"""Unit tests for BaseAgent — process() delegation, timing, middleware chain."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from waf_shared.agents.base_agent import BaseAgent
from waf_shared.agents.contracts import AgentContext, AgentInput, AgentOutput
from waf_shared.agents.interfaces import IAgentMiddleware, NextHandler


def _ctx(stage: str = "echo", attempt: int = 1) -> AgentContext:
    return AgentContext(
        workflow_id=uuid.uuid4(),
        stage_name=stage,
        tenant_id=uuid.uuid4(),
        attempt=attempt,
    )


# ── Concrete test agents ──────────────────────────────────────────────────────


class EchoAgent(BaseAgent[str, str]):
    """Returns its input payload unchanged."""

    _name = "echo"
    _version = "1.0.0"

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload


class UpperAgent(BaseAgent[str, str]):
    """Returns payload uppercased."""

    _name = "upper"
    _version = "2.0.0"

    async def process(self, payload: str, context: AgentContext) -> str:
        return payload.upper()


class AlwaysFailAgent(BaseAgent[str, str]):
    """Always raises ValueError."""

    _name = "fail"
    _version = "1.0.0"

    async def process(self, payload: str, context: AgentContext) -> str:
        raise ValueError("deliberate failure")


# ── Tests ─────────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestBaseAgentProperties:
    def test_name_returns_class_attribute(self) -> None:
        assert EchoAgent().name == "echo"

    def test_version_returns_class_attribute(self) -> None:
        assert UpperAgent().version == "2.0.0"


@pytest.mark.unit
class TestBaseAgentExecute:
    @pytest.mark.asyncio
    async def test_execute_delegates_to_process(self) -> None:
        agent = EchoAgent()
        ctx = _ctx()
        inp = AgentInput(payload="hello", context=ctx)

        out = await agent.execute(inp, ctx)

        assert out.payload == "hello"
        assert out.agent_name == "echo"
        assert out.agent_version == "1.0.0"

    @pytest.mark.asyncio
    async def test_execute_records_duration(self) -> None:
        agent = EchoAgent()
        ctx = _ctx()
        inp = AgentInput(payload="x", context=ctx)

        out = await agent.execute(inp, ctx)

        assert out.duration_ms >= 0.0

    @pytest.mark.asyncio
    async def test_execute_records_attempt_from_context(self) -> None:
        agent = EchoAgent()
        ctx = _ctx(attempt=3)
        inp = AgentInput(payload="x", context=ctx)

        out = await agent.execute(inp, ctx)

        assert out.attempt == 3

    @pytest.mark.asyncio
    async def test_execute_propagates_process_exception(self) -> None:
        agent = AlwaysFailAgent()
        ctx = _ctx()
        inp = AgentInput(payload="x", context=ctx)

        with pytest.raises(ValueError, match="deliberate failure"):
            await agent.execute(inp, ctx)

    @pytest.mark.asyncio
    async def test_execute_applies_transformation(self) -> None:
        agent = UpperAgent()
        ctx = _ctx()
        inp = AgentInput(payload="hello world", context=ctx)

        out = await agent.execute(inp, ctx)

        assert out.payload == "HELLO WORLD"


@pytest.mark.unit
class TestBaseAgentMiddleware:
    @pytest.mark.asyncio
    async def test_middleware_receives_output_from_process(self) -> None:
        received_outputs: list[AgentOutput[Any]] = []

        class _CaptureMw(IAgentMiddleware):
            async def __call__(
                self, inp: AgentInput[Any], ctx: AgentContext, next: NextHandler
            ) -> AgentOutput[Any]:
                out = await next(inp, ctx)
                received_outputs.append(out)
                return out

        agent = EchoAgent(middleware=[_CaptureMw()])
        ctx = _ctx()
        inp = AgentInput(payload="captured", context=ctx)

        await agent.execute(inp, ctx)

        assert len(received_outputs) == 1
        assert received_outputs[0].payload == "captured"

    @pytest.mark.asyncio
    async def test_middleware_can_short_circuit(self) -> None:
        class _BlockingMw(IAgentMiddleware):
            async def __call__(
                self, inp: AgentInput[Any], ctx: AgentContext, next: NextHandler
            ) -> AgentOutput[Any]:
                return AgentOutput(
                    payload="intercepted",
                    agent_name="blocker",
                    agent_version="1.0",
                    duration_ms=0.0,
                    attempt=ctx.attempt,
                )

        agent = EchoAgent(middleware=[_BlockingMw()])
        ctx = _ctx()
        inp = AgentInput(payload="original", context=ctx)

        out = await agent.execute(inp, ctx)

        assert out.payload == "intercepted"
        assert out.agent_name == "blocker"

    @pytest.mark.asyncio
    async def test_middleware_order_is_outermost_first(self) -> None:
        order: list[str] = []

        def _make_mw(label: str) -> IAgentMiddleware:
            class _Mw(IAgentMiddleware):
                async def __call__(
                    self, inp: AgentInput[Any], ctx: AgentContext, next: NextHandler
                ) -> AgentOutput[Any]:
                    order.append(f"{label}:in")
                    out = await next(inp, ctx)
                    order.append(f"{label}:out")
                    return out

            return _Mw()

        agent = EchoAgent(middleware=[_make_mw("A"), _make_mw("B")])
        ctx = _ctx()
        await agent.execute(AgentInput(payload="x", context=ctx), ctx)

        assert order == ["A:in", "B:in", "B:out", "A:out"]

    @pytest.mark.asyncio
    async def test_middleware_error_propagates(self) -> None:
        class _ErrorMw(IAgentMiddleware):
            async def __call__(
                self, inp: AgentInput[Any], ctx: AgentContext, next: NextHandler
            ) -> AgentOutput[Any]:
                raise RuntimeError("middleware exploded")

        agent = EchoAgent(middleware=[_ErrorMw()])
        ctx = _ctx()
        inp = AgentInput(payload="x", context=ctx)

        with pytest.raises(RuntimeError, match="middleware exploded"):
            await agent.execute(inp, ctx)
