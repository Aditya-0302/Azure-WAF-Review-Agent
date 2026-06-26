"""Unit of Work — coordinates multiple repositories within a single transaction.

Usage:
    uow = UnitOfWork(pool)
    async with uow.begin(tenant_id) as work:
        assessment = await work.assessments.create(assessment)
        await work.findings.create_batch(tenant_id, findings)
        # transaction commits on clean exit, rolls back on exception

The UnitOfWork acquires one write connection, begins a transaction, sets the
tenant RLS context, and vends repository instances bound to that connection.
All work within the `async with` block shares the same transaction — the
caller never manages commit/rollback explicitly.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass

import asyncpg

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.db.repositories.rule_repository import WafRuleRepository
from waf_shared.db.repositories.tenant_repository import TenantRepository
from waf_shared.domain.errors.infrastructure_errors import DatabaseError


@dataclass(frozen=True)
class ActiveUnitOfWork:
    """Repositories bound to the active transaction connection.

    Do not store or use these repositories outside the `async with uow.begin()` block —
    the underlying connection is released at context exit.
    """

    tenants: TenantRepository
    assessments: AssessmentRepository
    findings: FindingRepository
    rules: WafRuleRepository


class UnitOfWork:
    """Coordinates multiple repositories in a single atomic transaction.

    One instance per service is sufficient — it is stateless between operations.
    The pool is thread-safe and can be shared across all concurrent requests.
    """

    def __init__(self, pool: DatabasePool) -> None:
        self._pool = pool

    @asynccontextmanager
    async def begin(self, tenant_id: uuid.UUID) -> AsyncGenerator[ActiveUnitOfWork, None]:
        """Acquire a connection, set tenant context, and yield bound repositories.

        The transaction commits automatically on a clean exit. Any exception causes
        an automatic rollback — the caller does not call commit/rollback.

        Args:
            tenant_id: The tenant whose RLS context is set for this transaction.

        Yields:
            ActiveUnitOfWork with repositories pre-bound to the connection.

        Raises:
            DatabaseError: If the connection cannot be acquired.
        """
        async with self._pool.acquire_write() as conn:
            async with conn.transaction():
                try:
                    await conn.execute(
                        "SELECT set_config('app.current_tenant_id', $1, true)",
                        str(tenant_id),
                    )
                except asyncpg.PostgresError as exc:
                    raise DatabaseError(f"Failed to set tenant context: {exc}") from exc

                yield ActiveUnitOfWork(
                    tenants=TenantRepository(conn=conn, uow_tenant_id=tenant_id),
                    assessments=AssessmentRepository(conn=conn, uow_tenant_id=tenant_id),
                    findings=FindingRepository(conn=conn, uow_tenant_id=tenant_id),
                    rules=WafRuleRepository(conn=conn, uow_tenant_id=tenant_id),
                )
