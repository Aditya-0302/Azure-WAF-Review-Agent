"""QuotaService — reads tenant quotas and validates against current usage.

Raises QuotaExceededException with full context (name, limit, current) so
that the exception handler can populate the HTTP 429 response detail.
"""

from __future__ import annotations

import uuid

from waf_shared.db.pool import DatabasePool
from waf_shared.domain.errors.domain_errors import QuotaExceededException
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")


class QuotaService:
    def __init__(self, pool: DatabasePool) -> None:
        self._pool = pool

    async def assert_can_create_assessment(self, tenant_id: uuid.UUID) -> None:
        """Raise QuotaExceededException if tenant has hit concurrent assessment limit."""
        limit, current = await self._get_concurrent_usage(tenant_id)
        if current >= limit:
            _logger.warning(
                "quota.exceeded",
                quota_name="max_concurrent_assessments",
                limit=limit,
                current=current,
                tenant_id=str(tenant_id),
            )
            raise QuotaExceededException(
                quota_name="max_concurrent_assessments",
                limit=limit,
                current=current,
                tenant_id=tenant_id,
            )

    async def _get_concurrent_usage(self, tenant_id: uuid.UUID) -> tuple[int, int]:
        """Returns (limit, current_in_flight_count)."""
        async with self._pool.acquire_read() as conn:
            row = await conn.fetchrow(
                """
                SELECT
                    q.max_concurrent_assessments AS lim,
                    COUNT(a.id) FILTER (
                        WHERE a.status NOT IN ('completed', 'failed', 'cancelled')
                    ) AS current_count
                FROM tenant_quotas q
                LEFT JOIN assessments a ON a.tenant_id = q.tenant_id
                WHERE q.tenant_id = $1
                GROUP BY q.max_concurrent_assessments
                """,
                tenant_id,
            )
        if row is None:
            return (3, 0)
        return (int(row["lim"]), int(row["current_count"]))
