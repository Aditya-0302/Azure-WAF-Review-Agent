"""BaseAgent: concrete base class for all WAF agent implementations.

Subclasses implement process() rather than execute(). BaseAgent handles:
  * Timing (measures wall-clock duration and stores it in AgentOutput)
  * Middleware chain construction (applied around the core process() call)
  * Structured logging on start/end/error (when a logger is supplied)

Middleware chain construction
------------------------------
Given middleware=[A, B, C], the call order is:
    A.__call__(... , next=B)
      B.__call__(... , next=C)
        C.__call__(... , next=_core)
          _core()  ← calls self.process()

A is the outermost wrapper (first to execute, last to return).
The chain is built using default-argument capture to avoid the
closure-over-loop bug.
"""

from __future__ import annotations

import time
from abc import abstractmethod
from collections.abc import Awaitable, Callable
from typing import Any, Generic, TypeVar

from waf_shared.agents.contracts import AgentContext, AgentInput, AgentOutput
from waf_shared.agents.interfaces import IAgent, IAgentMiddleware
from waf_shared.telemetry.logging import StructuredLogger

TInput = TypeVar("TInput")
TOutput = TypeVar("TOutput")

_Handler = Callable[[AgentInput[Any], AgentContext], Awaitable[AgentOutput[Any]]]


class BaseAgent(IAgent[TInput, TOutput], Generic[TInput, TOutput]):
    """Abstract base agent — subclass and implement process()."""

    _name: str
    _version: str = "1.0.0"

    def __init__(
        self,
        *,
        logger: StructuredLogger | None = None,
        middleware: list[IAgentMiddleware] | None = None,
    ) -> None:
        self._logger = logger or StructuredLogger(
            service=f"agent.{self._name}", version=self._version
        )
        self._middleware = middleware or []

    # ── IAgent interface ──────────────────────────────────────────────────────

    @property
    def name(self) -> str:
        return self._name

    @property
    def version(self) -> str:
        return self._version

    async def execute(
        self,
        agent_input: AgentInput[TInput],
        context: AgentContext,
    ) -> AgentOutput[TOutput]:
        started = time.monotonic()

        async def _core(inp: AgentInput[Any], ctx: AgentContext) -> AgentOutput[Any]:
            payload = await self.process(inp.payload, ctx)
            duration_ms = (time.monotonic() - started) * 1000
            return AgentOutput(
                payload=payload,
                agent_name=self._name,
                agent_version=self._version,
                duration_ms=duration_ms,
                attempt=ctx.attempt,
            )

        handler: _Handler = _core
        for mw in reversed(self._middleware):
            # Default-arg capture prevents the closure-over-loop bug
            async def _wrap(
                inp: AgentInput[Any],
                ctx: AgentContext,
                *,
                _prev: _Handler = handler,
                _mw: IAgentMiddleware = mw,
            ) -> AgentOutput[Any]:
                return await _mw(inp, ctx, _prev)

            handler = _wrap

        return await handler(agent_input, context)

    # ── Subclass contract ─────────────────────────────────────────────────────

    @abstractmethod
    async def process(self, payload: TInput, context: AgentContext) -> TOutput:
        """Core agent logic.

        Implementations should raise on unrecoverable failure. The pipeline
        retry wrapper catches retryable errors before they reach this method
        on subsequent attempts.
        """
