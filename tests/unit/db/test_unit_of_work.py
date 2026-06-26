"""Unit tests for UnitOfWork."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest


@pytest.mark.unit
class TestUnitOfWorkBegin:
    @pytest.mark.asyncio
    async def test_begin_yields_active_uow_with_all_repos(self) -> None:
        from waf_shared.db.repositories.assessment_repository import AssessmentRepository
        from waf_shared.db.repositories.finding_repository import FindingRepository
        from waf_shared.db.repositories.rule_repository import WafRuleRepository
        from waf_shared.db.repositories.tenant_repository import TenantRepository
        from waf_shared.db.unit_of_work import UnitOfWork

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        mock_pool = MagicMock()

        @asynccontextmanager
        async def mock_acquire_write():
            yield mock_conn

        mock_pool.acquire_write = mock_acquire_write

        @asynccontextmanager
        async def mock_transaction():
            yield

        mock_conn.transaction = mock_transaction

        uow = UnitOfWork(pool=mock_pool)
        async with uow.begin(tenant_id) as work:
            assert isinstance(work.tenants, TenantRepository)
            assert isinstance(work.assessments, AssessmentRepository)
            assert isinstance(work.findings, FindingRepository)
            assert isinstance(work.rules, WafRuleRepository)

    @pytest.mark.asyncio
    async def test_begin_sets_tenant_context(self) -> None:
        from waf_shared.db.unit_of_work import UnitOfWork

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        mock_pool = MagicMock()

        @asynccontextmanager
        async def mock_acquire_write():
            yield mock_conn

        mock_pool.acquire_write = mock_acquire_write

        @asynccontextmanager
        async def mock_transaction():
            yield

        mock_conn.transaction = mock_transaction

        uow = UnitOfWork(pool=mock_pool)
        async with uow.begin(tenant_id) as _:
            pass

        mock_conn.execute.assert_called_once()
        call_sql = mock_conn.execute.call_args[0][0]
        assert "set_config" in call_sql
        assert "app.current_tenant_id" in call_sql

    @pytest.mark.asyncio
    async def test_repos_share_same_connection_in_uow(self) -> None:
        from waf_shared.db.unit_of_work import UnitOfWork

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        mock_pool = MagicMock()

        @asynccontextmanager
        async def mock_acquire_write():
            yield mock_conn

        mock_pool.acquire_write = mock_acquire_write

        @asynccontextmanager
        async def mock_transaction():
            yield

        mock_conn.transaction = mock_transaction

        uow = UnitOfWork(pool=mock_pool)
        async with uow.begin(tenant_id) as work:
            assert work.tenants._conn is mock_conn
            assert work.assessments._conn is mock_conn
            assert work.findings._conn is mock_conn
            assert work.rules._conn is mock_conn

    @pytest.mark.asyncio
    async def test_repos_have_correct_tenant_id_in_uow(self) -> None:
        from waf_shared.db.unit_of_work import UnitOfWork

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        mock_pool = MagicMock()

        @asynccontextmanager
        async def mock_acquire_write():
            yield mock_conn

        mock_pool.acquire_write = mock_acquire_write

        @asynccontextmanager
        async def mock_transaction():
            yield

        mock_conn.transaction = mock_transaction

        uow = UnitOfWork(pool=mock_pool)
        async with uow.begin(tenant_id) as work:
            assert work.tenants._uow_tenant_id == tenant_id
            assert work.assessments._uow_tenant_id == tenant_id
            assert work.findings._uow_tenant_id == tenant_id

    @pytest.mark.asyncio
    async def test_transaction_rolls_back_on_exception(self) -> None:
        from waf_shared.db.unit_of_work import UnitOfWork

        tenant_id = uuid.uuid4()
        rolled_back = False
        mock_conn = AsyncMock()
        mock_conn.execute = AsyncMock()

        mock_pool = MagicMock()

        @asynccontextmanager
        async def mock_acquire_write():
            yield mock_conn

        mock_pool.acquire_write = mock_acquire_write

        @asynccontextmanager
        async def mock_transaction():
            nonlocal rolled_back
            try:
                yield
            except Exception:
                rolled_back = True
                raise

        mock_conn.transaction = mock_transaction

        uow = UnitOfWork(pool=mock_pool)
        with pytest.raises(ValueError):
            async with uow.begin(tenant_id) as _:
                raise ValueError("something went wrong")

        assert rolled_back is True


@pytest.mark.unit
class TestBaseRepositoryInit:
    def test_requires_pool_or_conn(self) -> None:
        from waf_shared.db.repository import BaseRepository

        with pytest.raises(ValueError, match="Either pool or conn"):
            BaseRepository()

    def test_conn_requires_uow_tenant_id(self) -> None:
        from waf_shared.db.repository import BaseRepository

        mock_conn = AsyncMock()
        with pytest.raises(ValueError, match="uow_tenant_id is required"):
            BaseRepository(conn=mock_conn)

    def test_pool_only_mode_is_not_in_uow(self) -> None:
        from waf_shared.db.repository import BaseRepository

        mock_pool = MagicMock()
        repo = BaseRepository(pool=mock_pool)
        assert repo._in_uow is False

    def test_conn_mode_is_in_uow(self) -> None:
        from waf_shared.db.repository import BaseRepository

        mock_conn = AsyncMock()
        repo = BaseRepository(conn=mock_conn, uow_tenant_id=uuid.uuid4())
        assert repo._in_uow is True
