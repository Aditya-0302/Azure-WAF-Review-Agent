"""DatabasePool — asyncpg connection pool routing through PgBouncer.

Two pools may be maintained:
  - primary:  read-write connections to PgBouncer primary  (always created)
  - readonly: read-only connections to PgBouncer read-replica  (optional)

When dsn_readonly is None (DB_READONLY_HOST unset), acquire_read() falls back
to the primary pool.  This lets a single-instance local dev setup work without
any code changes — set DB_READONLY_HOST in production to enable the replica.

Never call asyncpg.connect() directly. Always acquire through this pool.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import asyncpg

from waf_shared.domain.errors.infrastructure_errors import (
    ConnectionPoolExhaustedError,
    DatabaseError,
)
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")

_DEFAULT_MIN_SIZE = 2
_DEFAULT_MAX_SIZE = 10
_ACQUIRE_TIMEOUT_SECONDS = 5.0


class DatabasePool:
    """Wrapper around asyncpg pools (primary + optional read-only replica).

    Lifecycle: call `connect()` on startup, `disconnect()` on shutdown.
    When dsn_readonly is None, acquire_read() transparently uses the primary pool.
    """

    def __init__(
        self,
        dsn_primary: str,
        dsn_readonly: str | None,
        min_size: int = _DEFAULT_MIN_SIZE,
        max_size: int = _DEFAULT_MAX_SIZE,
    ) -> None:
        self._dsn_primary = dsn_primary
        self._dsn_readonly = dsn_readonly
        self._min_size = min_size
        self._max_size = max_size
        self._primary: asyncpg.Pool | None = None  # type: ignore[type-arg]
        self._readonly: asyncpg.Pool | None = None  # type: ignore[type-arg]

    async def connect(self) -> None:
        self._primary = await asyncpg.create_pool(
            dsn=self._dsn_primary,
            min_size=self._min_size,
            max_size=self._max_size,
            command_timeout=30,
            server_settings={"application_name": "waf-agent"},
        )

        if self._dsn_readonly is None:
            _logger.warning(
                "db.pool.readonly.not_configured",
                detail="DB_READONLY_HOST is not set; acquire_read() will use the primary pool",
            )
        else:
            self._readonly = await asyncpg.create_pool(
                dsn=self._dsn_readonly,
                min_size=self._min_size,
                max_size=max(2, self._max_size // 2),
                command_timeout=30,
                server_settings={"application_name": "waf-agent-ro"},
            )

        _logger.info(
            "db.pool.connected",
            min_size=self._min_size,
            max_size=self._max_size,
            readonly_pool=self._readonly is not None,
        )

    async def disconnect(self) -> None:
        if self._primary is not None:
            await self._primary.close()
        if self._readonly is not None:
            await self._readonly.close()
        _logger.info("db.pool.disconnected")

    @asynccontextmanager
    async def acquire_write(self) -> AsyncGenerator[asyncpg.Connection, None]:  # type: ignore[type-arg]
        if self._primary is None:
            raise DatabaseError("Primary pool is not connected", code="POOL_NOT_READY")
        try:
            async with self._primary.acquire(timeout=_ACQUIRE_TIMEOUT_SECONDS) as conn:
                yield conn
        except asyncpg.TooManyConnectionsError as exc:
            raise ConnectionPoolExhaustedError("primary", _ACQUIRE_TIMEOUT_SECONDS) from exc

    @asynccontextmanager
    async def acquire_read(self) -> AsyncGenerator[asyncpg.Connection, None]:  # type: ignore[type-arg]
        # Fall back to primary when no replica is configured (local dev / single-node).
        pool = self._readonly if self._readonly is not None else self._primary
        if pool is None:
            raise DatabaseError("Primary pool is not connected", code="POOL_NOT_READY")
        pool_name = "readonly" if self._readonly is not None else "primary"
        try:
            async with pool.acquire(timeout=_ACQUIRE_TIMEOUT_SECONDS) as conn:
                yield conn
        except asyncpg.TooManyConnectionsError as exc:
            raise ConnectionPoolExhaustedError(pool_name, _ACQUIRE_TIMEOUT_SECONDS) from exc

    async def healthcheck(self) -> None:
        async with self.acquire_write() as conn:
            await conn.fetchval("SELECT 1")
