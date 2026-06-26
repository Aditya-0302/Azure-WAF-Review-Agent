"""Async retry helper for Azure management API calls.

Retries on transient HTTP errors (503, 504) and network errors.
Converts 429 responses to AzureRateLimitError immediately (no retry) so
callers can back off at a higher level.
"""

from __future__ import annotations

import asyncio
import random
from collections.abc import Awaitable, Callable
from typing import TypeVar

from azure.core.exceptions import HttpResponseError, ServiceRequestError

from waf_shared.domain.errors.infrastructure_errors import AzureRateLimitError
from waf_shared.telemetry.logging import StructuredLogger

T = TypeVar("T")

_TRANSIENT_STATUS_CODES = frozenset({503, 504})


async def with_azure_retry(
    fn: Callable[[], Awaitable[T]],
    *,
    max_attempts: int = 3,
    initial_wait: float = 1.0,
    backoff_factor: float = 2.0,
    max_wait: float = 30.0,
    logger: StructuredLogger,
    operation: str,
) -> T:
    """Execute fn with exponential backoff on transient Azure errors.

    Behavior by status code:
    - 429: immediately raises AzureRateLimitError (honors Retry-After header)
    - 503/504: retries up to max_attempts with exponential backoff + jitter
    - Other HttpResponseError / ServiceRequestError on last attempt: re-raises
    """
    wait = initial_wait

    for attempt in range(1, max_attempts + 1):
        try:
            return await fn()

        except HttpResponseError as exc:
            status = exc.status_code or 0

            if status == 429:
                retry_after = _parse_retry_after(exc)
                logger.warning(
                    "discovery.retry.rate_limit",
                    operation=operation,
                    attempt=attempt,
                    retry_after_seconds=retry_after,
                )
                raise AzureRateLimitError(
                    service=operation, retry_after_seconds=retry_after
                ) from exc

            if status in _TRANSIENT_STATUS_CODES and attempt < max_attempts:
                logger.warning(
                    "discovery.retry.transient",
                    operation=operation,
                    attempt=attempt,
                    status=status,
                    wait_seconds=round(wait, 2),
                )
                await asyncio.sleep(_jitter(wait))
                wait = min(wait * backoff_factor, max_wait)
                continue

            raise

        except ServiceRequestError:
            if attempt < max_attempts:
                logger.warning(
                    "discovery.retry.network_error",
                    operation=operation,
                    attempt=attempt,
                    wait_seconds=round(wait, 2),
                )
                await asyncio.sleep(_jitter(wait))
                wait = min(wait * backoff_factor, max_wait)
                continue
            raise

    raise RuntimeError(f"with_azure_retry: exhausted {max_attempts} attempts for {operation!r}")


def _parse_retry_after(exc: HttpResponseError) -> int | None:
    response = getattr(exc, "response", None)
    if response is None:
        return None
    headers = getattr(response, "headers", {})
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is not None:
        try:
            return int(raw)
        except (ValueError, TypeError):
            pass
    return None


def _jitter(wait: float) -> float:
    return wait + random.uniform(0.0, wait * 0.2)
