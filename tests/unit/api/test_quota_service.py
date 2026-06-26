"""Unit tests for QuotaService."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.domain.errors.domain_errors import QuotaExceededException


@pytest.fixture
def tenant_id() -> uuid.UUID:
    return uuid.UUID("11111111-1111-1111-1111-111111111111")


@pytest.fixture
def pool_mock() -> MagicMock:
    mock = MagicMock()
    mock.acquire_read = MagicMock()
    return mock


class TestQuotaServiceConcurrentLimit:
    @pytest.mark.asyncio
    async def test_raises_when_at_limit(self, tenant_id: uuid.UUID) -> None:
        from waf_api.services.quota_service import QuotaService

        pool = MagicMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"lim": 3, "current_count": 3})
        pool.acquire_read = MagicMock()
        pool.acquire_read.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire_read.return_value.__aexit__ = AsyncMock(return_value=None)

        service = QuotaService(pool=pool)

        with pytest.raises(QuotaExceededException) as exc_info:
            await service.assert_can_create_assessment(tenant_id)

        assert exc_info.value.limit == 3
        assert exc_info.value.current == 3
        assert exc_info.value.quota_name == "max_concurrent_assessments"
        assert exc_info.value.tenant_id == tenant_id

    @pytest.mark.asyncio
    async def test_passes_when_below_limit(self, tenant_id: uuid.UUID) -> None:
        from waf_api.services.quota_service import QuotaService

        pool = MagicMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"lim": 3, "current_count": 1})
        pool.acquire_read = MagicMock()
        pool.acquire_read.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire_read.return_value.__aexit__ = AsyncMock(return_value=None)

        service = QuotaService(pool=pool)

        await service.assert_can_create_assessment(tenant_id)

    @pytest.mark.asyncio
    async def test_defaults_to_three_when_no_quota_row(self, tenant_id: uuid.UUID) -> None:
        from waf_api.services.quota_service import QuotaService

        pool = MagicMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)
        pool.acquire_read = MagicMock()
        pool.acquire_read.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire_read.return_value.__aexit__ = AsyncMock(return_value=None)

        service = QuotaService(pool=pool)
        await service.assert_can_create_assessment(tenant_id)

    @pytest.mark.asyncio
    async def test_quota_exception_has_correct_code(self, tenant_id: uuid.UUID) -> None:
        from waf_api.services.quota_service import QuotaService

        pool = MagicMock()
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"lim": 1, "current_count": 1})
        pool.acquire_read = MagicMock()
        pool.acquire_read.return_value.__aenter__ = AsyncMock(return_value=conn)
        pool.acquire_read.return_value.__aexit__ = AsyncMock(return_value=None)

        service = QuotaService(pool=pool)

        with pytest.raises(QuotaExceededException) as exc_info:
            await service.assert_can_create_assessment(tenant_id)

        assert exc_info.value.code == "QUOTA_EXCEEDED"
