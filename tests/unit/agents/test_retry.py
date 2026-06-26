"""Unit tests for RetryPolicy, RetryStrategy, and with_agent_retry."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.agents.retry import (
    RetryContext,
    RetryPolicy,
    RetryStrategy,
    _compute_wait,
    with_agent_retry,
)
from waf_shared.telemetry.logging import StructuredLogger


def _logger() -> StructuredLogger:
    logger = MagicMock(spec=StructuredLogger)
    logger.info = MagicMock()
    logger.warning = MagicMock()
    logger.error = MagicMock()
    return logger


@pytest.mark.unit
class TestRetryPolicyFactories:
    def test_no_retry_sets_max_attempts_to_1(self) -> None:
        p = RetryPolicy.no_retry()
        assert p.max_attempts == 1

    def test_aggressive_has_5_attempts(self) -> None:
        p = RetryPolicy.aggressive()
        assert p.max_attempts == 5

    def test_conservative_has_longer_initial_wait(self) -> None:
        p = RetryPolicy.conservative()
        assert p.initial_wait_seconds >= 2.0


@pytest.mark.unit
class TestComputeWait:
    def test_constant_strategy_always_same(self) -> None:
        p = RetryPolicy(
            strategy=RetryStrategy.CONSTANT,
            initial_wait_seconds=2.0,
            backoff_factor=1.0,
        )
        assert _compute_wait(p, 1) == 2.0
        assert _compute_wait(p, 3) == 2.0

    def test_linear_strategy_grows_linearly(self) -> None:
        p = RetryPolicy(
            strategy=RetryStrategy.LINEAR,
            initial_wait_seconds=1.0,
            backoff_factor=1.0,
        )
        assert _compute_wait(p, 1) == 1.0
        assert _compute_wait(p, 2) == 2.0
        assert _compute_wait(p, 4) == 4.0

    def test_exponential_strategy_grows_exponentially(self) -> None:
        p = RetryPolicy(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_wait_seconds=1.0,
            backoff_factor=2.0,
        )
        assert _compute_wait(p, 1) == 1.0
        assert _compute_wait(p, 2) == 2.0
        assert _compute_wait(p, 3) == 4.0

    def test_fibonacci_strategy(self) -> None:
        p = RetryPolicy(
            strategy=RetryStrategy.FIBONACCI,
            initial_wait_seconds=1.0,
            backoff_factor=1.0,
        )
        # Fibonacci: 1, 1, 2, 3, 5 …
        assert _compute_wait(p, 1) == 1.0
        assert _compute_wait(p, 2) == 1.0
        assert _compute_wait(p, 3) == 2.0
        assert _compute_wait(p, 4) == 3.0

    def test_max_wait_is_respected(self) -> None:
        p = RetryPolicy(
            strategy=RetryStrategy.EXPONENTIAL,
            initial_wait_seconds=1.0,
            backoff_factor=10.0,
            max_wait_seconds=5.0,
        )
        assert _compute_wait(p, 5) <= 5.0


@pytest.mark.unit
class TestWithAgentRetry:
    @pytest.mark.asyncio
    async def test_success_on_first_attempt(self) -> None:
        fn = AsyncMock(return_value="ok")
        result = await with_agent_retry(
            fn,
            RetryPolicy(max_attempts=3),
            logger=_logger(),
            operation="test",
        )
        assert result == "ok"
        fn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_retries_on_retryable_exception(self) -> None:
        call_count = 0

        async def _flaky() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 3:
                raise ValueError("transient")
            return "recovered"

        policy = RetryPolicy(
            max_attempts=3,
            strategy=RetryStrategy.CONSTANT,
            initial_wait_seconds=0.001,
        )
        result = await with_agent_retry(
            _flaky,
            policy,
            logger=_logger(),
            operation="flaky",
        )
        assert result == "recovered"
        assert call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_attempts_exhausted(self) -> None:
        fn = AsyncMock(side_effect=RuntimeError("always fails"))
        policy = RetryPolicy(
            max_attempts=3,
            strategy=RetryStrategy.CONSTANT,
            initial_wait_seconds=0.001,
        )
        with pytest.raises(RuntimeError, match="always fails"):
            await with_agent_retry(fn, policy, logger=_logger(), operation="fail")

        assert fn.await_count == 3

    @pytest.mark.asyncio
    async def test_non_retryable_raises_immediately(self) -> None:
        fn = AsyncMock(side_effect=ValueError("permanent"))
        policy = RetryPolicy(
            max_attempts=5,
            strategy=RetryStrategy.CONSTANT,
            initial_wait_seconds=0.001,
        )

        with pytest.raises(ValueError, match="permanent"):
            await with_agent_retry(
                fn,
                policy,
                logger=_logger(),
                operation="perm",
                is_retryable=lambda e: not isinstance(e, ValueError),
            )

        fn.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_on_retry_callback_called_with_context(self) -> None:
        call_count = 0
        retry_contexts: list[RetryContext] = []

        async def _fn() -> str:
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise IOError("network glitch")
            return "ok"

        async def _on_retry(ctx: RetryContext) -> None:
            retry_contexts.append(ctx)

        policy = RetryPolicy(
            max_attempts=3,
            strategy=RetryStrategy.CONSTANT,
            initial_wait_seconds=0.001,
        )
        await with_agent_retry(
            _fn,
            policy,
            logger=_logger(),
            operation="net",
            on_retry=_on_retry,
        )

        assert len(retry_contexts) == 1
        assert retry_contexts[0].attempt == 1
        assert isinstance(retry_contexts[0].last_error, IOError)

    @pytest.mark.asyncio
    async def test_no_retry_policy_does_not_retry(self) -> None:
        fn = AsyncMock(side_effect=RuntimeError("boom"))
        with pytest.raises(RuntimeError):
            await with_agent_retry(
                fn,
                RetryPolicy.no_retry(),
                logger=_logger(),
                operation="one-shot",
            )
        fn.assert_awaited_once()
