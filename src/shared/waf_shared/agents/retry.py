"""Configurable async retry framework for agent operations.

Supports four back-off strategies (constant, linear, exponential, fibonacci)
with proportional jitter. Caller supplies an is_retryable predicate so only
specific exception types trigger a retry — non-matching exceptions propagate
immediately regardless of remaining attempts.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TypeVar

from pydantic import BaseModel, ConfigDict, Field

from waf_shared.telemetry.logging import StructuredLogger

T = TypeVar("T")


class RetryStrategy(StrEnum):
    CONSTANT = "constant"
    LINEAR = "linear"
    EXPONENTIAL = "exponential"
    FIBONACCI = "fibonacci"


class RetryPolicy(BaseModel):
    model_config = ConfigDict(frozen=True)

    max_attempts: int = Field(default=3, ge=1)
    strategy: RetryStrategy = RetryStrategy.EXPONENTIAL
    initial_wait_seconds: float = Field(default=1.0, gt=0)
    backoff_factor: float = Field(default=2.0, gt=0)
    max_wait_seconds: float = Field(default=60.0, gt=0)
    jitter_factor: float = Field(default=0.2, ge=0.0, le=1.0)

    @classmethod
    def no_retry(cls) -> RetryPolicy:
        return cls(max_attempts=1)

    @classmethod
    def aggressive(cls) -> RetryPolicy:
        return cls(max_attempts=5, initial_wait_seconds=0.5, max_wait_seconds=30.0)

    @classmethod
    def conservative(cls) -> RetryPolicy:
        return cls(max_attempts=3, initial_wait_seconds=2.0, max_wait_seconds=120.0)


@dataclass
class RetryContext:
    """Mutable snapshot of retry progress passed to on_retry callbacks."""

    attempt: int
    wait_seconds: float
    total_elapsed_seconds: float
    last_error: Exception | None = None
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))


def _compute_wait(policy: RetryPolicy, attempt: int) -> float:
    """Return base wait duration (before jitter) for the given 1-based attempt."""
    match policy.strategy:
        case RetryStrategy.CONSTANT:
            wait = policy.initial_wait_seconds
        case RetryStrategy.LINEAR:
            wait = policy.initial_wait_seconds * attempt
        case RetryStrategy.EXPONENTIAL:
            wait = policy.initial_wait_seconds * (policy.backoff_factor ** (attempt - 1))
        case RetryStrategy.FIBONACCI:
            a, b = 1, 1
            for _ in range(attempt - 1):
                a, b = b, a + b
            wait = policy.initial_wait_seconds * a
    return min(wait, policy.max_wait_seconds)


def _with_jitter(wait: float, factor: float) -> float:
    return wait + random.uniform(0.0, wait * factor)


async def with_agent_retry(
    fn: Callable[[], Awaitable[T]],
    policy: RetryPolicy,
    *,
    logger: StructuredLogger,
    operation: str,
    is_retryable: Callable[[Exception], bool] | None = None,
    on_retry: Callable[[RetryContext], Awaitable[None]] | None = None,
) -> T:
    """Execute fn with back-off retries governed by policy.

    Args:
        fn: Zero-argument async callable. Called once per attempt.
        policy: Retry configuration (strategy, waits, max attempts).
        logger: Structured logger for retry/exhaustion events.
        operation: Human-readable label used in log fields.
        is_retryable: Predicate that decides whether an exception warrants a
            retry. Defaults to retrying all Exception subclasses.
        on_retry: Optional async hook invoked before each sleep, useful for
            emitting AgentRetryingEvent from the pipeline.
    """
    _retryable = is_retryable if is_retryable is not None else lambda _: True
    started = datetime.now(UTC)

    for attempt in range(1, policy.max_attempts + 1):
        try:
            return await fn()

        except Exception as exc:
            if not _retryable(exc):
                raise

            elapsed = (datetime.now(UTC) - started).total_seconds()

            if attempt >= policy.max_attempts:
                logger.error(
                    "agent.retry.exhausted",
                    operation=operation,
                    attempt=attempt,
                    max_attempts=policy.max_attempts,
                    elapsed_seconds=round(elapsed, 2),
                    error=str(exc),
                    exc_info=True,
                )
                raise

            wait = _with_jitter(_compute_wait(policy, attempt), policy.jitter_factor)
            ctx = RetryContext(
                attempt=attempt,
                wait_seconds=wait,
                total_elapsed_seconds=elapsed,
                last_error=exc,
                started_at=started,
            )

            logger.warning(
                "agent.retry.transient",
                operation=operation,
                attempt=attempt,
                max_attempts=policy.max_attempts,
                wait_seconds=round(wait, 2),
                error=str(exc),
            )

            if on_retry is not None:
                await on_retry(ctx)

            await asyncio.sleep(wait)

    raise RuntimeError(  # pragma: no cover — loop always raises before this
        f"with_agent_retry: exhausted {policy.max_attempts} attempts for {operation!r}"
    )
