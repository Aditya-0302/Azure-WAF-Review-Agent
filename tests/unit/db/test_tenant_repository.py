"""Unit tests for TenantRepository."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waf_shared.domain.errors.domain_errors import TenantNotFoundError
from waf_shared.domain.models.tenant import PlanTier, Tenant, TenantQuota, TenantUser, UserRole


def _make_tenant(
    *,
    id: uuid.UUID | None = None,
    slug: str = "acme-corp",
    plan_tier: str = "standard",
) -> dict:
    now = datetime.now(UTC)
    return {
        "id": id or uuid.uuid4(),
        "slug": slug,
        "display_name": "Acme Corp",
        "azure_tenant_id": uuid.uuid4(),
        "plan_tier": plan_tier,
        "is_active": True,
        "created_at": now,
        "updated_at": now,
    }


def _make_quota(tenant_id: uuid.UUID) -> dict:
    return {
        "tenant_id": tenant_id,
        "max_concurrent_assessments": 3,
        "max_monthly_assessments": 20,
        "max_subscriptions_per_assessment": 10,
        "max_resources_per_assessment": 5000,
        "updated_at": datetime.now(UTC),
    }


@pytest.mark.unit
class TestTenantRepositoryGetById:
    @pytest.mark.asyncio
    async def test_returns_tenant_when_found(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        row = _make_tenant(id=tenant_id)
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[row])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id)

        assert result is not None
        assert result.id == tenant_id
        assert result.slug == "acme-corp"
        assert result.plan_tier == PlanTier.STANDARD

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id)

        assert result is None


@pytest.mark.unit
class TestTenantRepositoryGetBySlug:
    @pytest.mark.asyncio
    async def test_returns_tenant_by_slug(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[_make_tenant(id=tenant_id)])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_slug("acme-corp")

        assert result is not None
        assert result.slug == "acme-corp"

    @pytest.mark.asyncio
    async def test_returns_none_for_missing_slug(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_slug("does-not-exist")

        assert result is None


@pytest.mark.unit
class TestTenantRepositoryCreate:
    @pytest.mark.asyncio
    async def test_create_returns_persisted_tenant(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)
        row = _make_tenant(id=tenant_id)

        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[row])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        tenant = Tenant(
            id=tenant_id,
            slug="acme-corp",
            display_name="Acme Corp",
            azure_tenant_id=uuid.uuid4(),
            plan_tier=PlanTier.STANDARD,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        result = await repo.create(tenant)

        assert result.id == tenant_id
        mock_conn.fetch.assert_called_once()
        call_sql = mock_conn.fetch.call_args[0][0]
        assert "INSERT INTO tenants" in call_sql
        assert "RETURNING" in call_sql


@pytest.mark.unit
class TestTenantRepositoryUpdatePlanTier:
    @pytest.mark.asyncio
    async def test_update_plan_tier_returns_updated_tenant(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        row = _make_tenant(id=tenant_id, plan_tier="enterprise")
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[row])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.update_plan_tier(tenant_id, PlanTier.ENTERPRISE)

        assert result.plan_tier == PlanTier.ENTERPRISE

    @pytest.mark.asyncio
    async def test_update_plan_tier_raises_when_not_found(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)

        with pytest.raises(TenantNotFoundError) as exc_info:
            await repo.update_plan_tier(tenant_id, PlanTier.PREMIUM)

        assert exc_info.value.tenant_id == tenant_id


@pytest.mark.unit
class TestTenantRepositoryQuota:
    @pytest.mark.asyncio
    async def test_get_quota_returns_quota(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[_make_quota(tenant_id)])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_quota(tenant_id)

        assert result is not None
        assert result.max_concurrent_assessments == 3
        assert result.tenant_id == tenant_id

    @pytest.mark.asyncio
    async def test_get_quota_returns_none_when_absent(self) -> None:
        from waf_shared.db.repositories.tenant_repository import TenantRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = TenantRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_quota(tenant_id)

        assert result is None
