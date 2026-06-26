"""BaseRepository — enforces tenant isolation on every query.

Rules:
- _write() and _read() assert tenant_id is not None before execution.
- Every connection sets SET LOCAL app.current_tenant_id for RLS defense-in-depth.
- Raw SQL only — no ORM, no string concatenation, parameters are always $N placeholders.
- In UoW mode (conn + uow_tenant_id set), the transaction and tenant context are already
  established by the UnitOfWork; methods use the shared connection directly.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import asyncpg

from waf_shared.db.pool import DatabasePool
from waf_shared.domain.errors.infrastructure_errors import DatabaseError, QueryTimeoutError
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")


class BaseRepository:
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        if pool is None and conn is None:
            raise ValueError("Either pool or conn must be provided")
        if conn is not None and uow_tenant_id is None:
            raise ValueError("uow_tenant_id is required when conn is provided")
        self._pool = pool
        self._conn = conn
        self._uow_tenant_id = uow_tenant_id

    @property
    def _in_uow(self) -> bool:
        return self._conn is not None

    # ── Tenant-scoped writes ──────────────────────────────────────────────────

    async def _write(
        self,
        sql: str,
        tenant_id: uuid.UUID,
        *params: Any,
    ) -> list[asyncpg.Record]:  # type: ignore[type-arg]
        assert tenant_id is not None, "tenant_id is required for write operations"  # noqa: S101

        if self._conn is not None:
            # UoW mode: transaction is already open; still set the tenant context
            # so PostgreSQL RLS policies fire correctly (defense-in-depth).
            try:
                await self._conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, true)",
                    str(tenant_id),
                )
                return await self._conn.fetch(sql, *params)
            except asyncpg.exceptions.QueryCanceledError as exc:
                raise QueryTimeoutError(sql[:80], 30.0) from exc
            except asyncpg.PostgresError as exc:
                raise DatabaseError(f"Database write failed: {exc}") from exc

        try:
            async with self._pool.acquire_write() as conn:  # type: ignore[union-attr]
                async with conn.transaction():
                    await conn.execute(
                        "SELECT set_config('app.current_tenant_id', $1, true)",
                        str(tenant_id),
                    )
                    raw = await conn.fetch(sql, *params)
                result: list[asyncpg.Record] = raw if isinstance(raw, list) else []  # type: ignore[type-arg]
                return result
        except asyncpg.exceptions.QueryCanceledError as exc:
            raise QueryTimeoutError(sql[:80], 30.0) from exc
        except asyncpg.PostgresError as exc:
            _logger.error(
                "db.query.failed",
                exc_info=True,
                tenant_id=str(tenant_id),
                sql_prefix=sql[:80],
            )
            raise DatabaseError(f"Database write failed: {exc}") from exc

    async def _write_one(
        self,
        sql: str,
        tenant_id: uuid.UUID,
        *params: Any,
    ) -> asyncpg.Record | None:  # type: ignore[type-arg]
        rows = await self._write(sql, tenant_id, *params)
        return rows[0] if rows else None

    # ── Tenant-scoped reads ───────────────────────────────────────────────────

    async def _read(
        self,
        sql: str,
        tenant_id: uuid.UUID,
        *params: Any,
    ) -> list[asyncpg.Record]:  # type: ignore[type-arg]
        assert tenant_id is not None, "tenant_id is required for read operations"  # noqa: S101

        if self._conn is not None:
            # UoW mode: set tenant context so RLS policies fire (defense-in-depth).
            try:
                await self._conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, true)",
                    str(tenant_id),
                )
                return await self._conn.fetch(sql, *params)
            except asyncpg.exceptions.QueryCanceledError as exc:
                raise QueryTimeoutError(sql[:80], 30.0) from exc
            except asyncpg.PostgresError as exc:
                raise DatabaseError(f"Database read failed: {exc}") from exc

        try:
            async with self._pool.acquire_read() as conn:  # type: ignore[union-attr]
                async with conn.transaction():
                    await conn.execute(
                        "SELECT set_config('app.current_tenant_id', $1, true)",
                        str(tenant_id),
                    )
                    raw = await conn.fetch(sql, *params)
                return raw if isinstance(raw, list) else []
        except asyncpg.exceptions.QueryCanceledError as exc:
            raise QueryTimeoutError(sql[:80], 30.0) from exc
        except asyncpg.PostgresError as exc:
            _logger.error(
                "db.query.failed",
                exc_info=True,
                tenant_id=str(tenant_id),
                sql_prefix=sql[:80],
            )
            raise DatabaseError(f"Database read failed: {exc}") from exc

    async def _read_one(
        self,
        sql: str,
        tenant_id: uuid.UUID,
        *params: Any,
    ) -> asyncpg.Record | None:  # type: ignore[type-arg]
        rows = await self._read(sql, tenant_id, *params)
        return rows[0] if rows else None

    # ── System-level operations (no tenant scoping) ───────────────────────────

    async def _execute_system(self, sql: str, *params: Any) -> None:
        """Execute a statement without tenant scoping (e.g. tenant creation)."""
        if self._conn is not None:
            try:
                await self._conn.execute(sql, *params)
                return
            except asyncpg.PostgresError as exc:
                raise DatabaseError(f"System execute failed: {exc}") from exc

        try:
            async with self._pool.acquire_write() as conn:  # type: ignore[union-attr]
                await conn.execute(sql, *params)
        except asyncpg.PostgresError as exc:
            _logger.error("db.system.query.failed", exc_info=True, sql_prefix=sql[:80])
            raise DatabaseError(f"System query failed: {exc}") from exc

    async def _write_system(self, sql: str, *params: Any) -> list[asyncpg.Record]:  # type: ignore[type-arg]
        """Execute a system write statement returning rows (INSERT … RETURNING)."""
        if self._conn is not None:
            try:
                return await self._conn.fetch(sql, *params)
            except asyncpg.PostgresError as exc:
                raise DatabaseError(f"System write failed: {exc}") from exc

        try:
            async with self._pool.acquire_write() as conn:  # type: ignore[union-attr]
                return await conn.fetch(sql, *params)
        except asyncpg.PostgresError as exc:
            _logger.error("db.system.query.failed", exc_info=True, sql_prefix=sql[:80])
            raise DatabaseError(f"System write failed: {exc}") from exc

    async def _write_system_one(self, sql: str, *params: Any) -> asyncpg.Record | None:  # type: ignore[type-arg]
        rows = await self._write_system(sql, *params)
        return rows[0] if rows else None

    async def _fetch_system(self, sql: str, *params: Any) -> list[asyncpg.Record]:  # type: ignore[type-arg]
        """Fetch rows without tenant scoping (e.g. tenant lookup by slug)."""
        if self._conn is not None:
            try:
                return await self._conn.fetch(sql, *params)
            except asyncpg.PostgresError as exc:
                raise DatabaseError(f"System fetch failed: {exc}") from exc

        try:
            async with self._pool.acquire_read() as conn:  # type: ignore[union-attr]
                return await conn.fetch(sql, *params)
        except asyncpg.PostgresError as exc:
            _logger.error("db.system.query.failed", exc_info=True, sql_prefix=sql[:80])
            raise DatabaseError(f"System fetch failed: {exc}") from exc

    async def _fetch_system_one(self, sql: str, *params: Any) -> asyncpg.Record | None:  # type: ignore[type-arg]
        rows = await self._fetch_system(sql, *params)
        return rows[0] if rows else None

    # ── Unit-of-work context manager ─────────────────────────────────────────

    @asynccontextmanager
    async def _uow(
        self, tenant_id: uuid.UUID
    ) -> AsyncGenerator[asyncpg.Connection, None]:  # type: ignore[type-arg]
        """Open a transaction as an async context manager.

        Acquires a write connection, sets the tenant RLS context, begins a
        transaction, and yields the raw connection.  Rolls back automatically if
        the body raises; commits otherwise.

        Only valid when the repository was constructed with a pool (not a UoW
        connection).  Use the yielded connection directly for statements that
        must participate in the same transaction.
        """
        if self._pool is None:
            raise DatabaseError(
                "Pool is required for _uow; cannot open a nested transaction on an existing connection",
                code="POOL_NOT_READY",
            )
        async with self._pool.acquire_write() as conn:
            async with conn.transaction():
                await conn.execute(
                    "SELECT set_config('app.current_tenant_id', $1, true)",
                    str(tenant_id),
                )
                yield conn

    # ── Batch writes (executemany — no RETURNING) ─────────────────────────────

    async def _executemany_system(self, sql: str, args: list[tuple[Any, ...]]) -> None:
        """Run executemany without tenant scoping — used for bulk inserts in UoW."""
        if self._conn is not None:
            try:
                await self._conn.executemany(sql, args)
                return
            except asyncpg.PostgresError as exc:
                raise DatabaseError(f"Batch write failed: {exc}") from exc

        try:
            async with self._pool.acquire_write() as conn:  # type: ignore[union-attr]
                await conn.executemany(sql, args)
        except asyncpg.PostgresError as exc:
            _logger.error("db.batch.failed", exc_info=True, sql_prefix=sql[:80])
            raise DatabaseError(f"Batch write failed: {exc}") from exc
