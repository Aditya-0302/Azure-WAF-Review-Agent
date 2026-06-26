"""Integration test configuration — Docker Compose service fixtures."""

from __future__ import annotations

import os

import pytest
import pytest_asyncio

pytestmark = pytest.mark.integration

_PG_DSN = os.environ.get(
    "TEST_DB_DSN",
    "postgresql://wafagent:changeme_local_only@localhost:5432/wafagent",
)
_PG_DSN_RO = os.environ.get("TEST_DB_DSN_RO", _PG_DSN)


@pytest_asyncio.fixture
async def db_pool():  # type: ignore[no-untyped-def]
    """Provide a connected DatabasePool for integration tests.

    Function-scoped so the asyncpg pool is created inside the same event loop
    that the test runs in.  A session-scoped pool would be attached to the
    session-level loop; pytest-asyncio gives each test its own loop by default,
    causing "Future attached to a different loop" / "another operation is in
    progress" errors.

    Requires: postgres service from docker-compose.dev.yml
    """
    from waf_shared.db.pool import DatabasePool

    pool = DatabasePool(
        dsn_primary=_PG_DSN,
        dsn_readonly=_PG_DSN_RO,
        min_size=2,
        max_size=5,
    )
    await pool.connect()
    yield pool
    await pool.disconnect()


@pytest_asyncio.fixture
async def clean_db(db_pool: DatabasePool) -> None:  # type: ignore[name-defined]
    """Truncate all data tables between tests (keeps schema intact)."""
    async with db_pool.acquire_write() as conn:
        await conn.execute("""
            TRUNCATE TABLE
                assessment_findings,
                assessment_resources,
                assessment_batches,
                assessments,
                subscription_credentials,
                tenant_quotas,
                tenant_users,
                waf_rules
            RESTART IDENTITY CASCADE
        """)
