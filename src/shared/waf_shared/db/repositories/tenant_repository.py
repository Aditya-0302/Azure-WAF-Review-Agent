"""Tenant repository — asyncpg implementation of ITenantRepository."""

from __future__ import annotations

import uuid

import asyncpg

from waf_shared.db.pool import DatabasePool
from waf_shared.db.repository import BaseRepository
from waf_shared.domain.errors.domain_errors import TenantNotFoundError
from waf_shared.domain.models.tenant import PlanTier, Tenant, TenantQuota, TenantUser, UserRole
from waf_shared.domain.repositories.i_tenant_repository import ITenantRepository

_TENANT_COLS = (
    "id, slug, display_name, azure_tenant_id, plan_tier, is_active, created_at, updated_at"
)
_USER_COLS = "id, tenant_id, entra_oid, role, is_active, created_at"
_QUOTA_COLS = (
    "tenant_id, max_concurrent_assessments, max_monthly_assessments, "
    "max_subscriptions_per_assessment, max_resources_per_assessment, updated_at"
)


def _row_to_tenant(row: asyncpg.Record) -> Tenant:  # type: ignore[type-arg]
    return Tenant(
        id=row["id"],
        slug=row["slug"],
        display_name=row["display_name"],
        azure_tenant_id=row["azure_tenant_id"],
        plan_tier=PlanTier(row["plan_tier"]),
        is_active=row["is_active"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _row_to_user(row: asyncpg.Record) -> TenantUser:  # type: ignore[type-arg]
    return TenantUser(
        id=row["id"],
        tenant_id=row["tenant_id"],
        entra_oid=row["entra_oid"],
        role=UserRole(row["role"]),
        is_active=row["is_active"],
        created_at=row["created_at"],
    )


def _row_to_quota(row: asyncpg.Record) -> TenantQuota:  # type: ignore[type-arg]
    return TenantQuota(
        tenant_id=row["tenant_id"],
        max_concurrent_assessments=row["max_concurrent_assessments"],
        max_monthly_assessments=row["max_monthly_assessments"],
        max_subscriptions_per_assessment=row["max_subscriptions_per_assessment"],
        max_resources_per_assessment=row["max_resources_per_assessment"],
        updated_at=row["updated_at"],
    )


class TenantRepository(BaseRepository, ITenantRepository):
    def __init__(
        self,
        pool: DatabasePool | None = None,
        *,
        conn: asyncpg.Connection | None = None,  # type: ignore[type-arg]
        uow_tenant_id: uuid.UUID | None = None,
    ) -> None:
        super().__init__(pool=pool, conn=conn, uow_tenant_id=uow_tenant_id)

    async def get_by_id(self, tenant_id: uuid.UUID) -> Tenant | None:
        row = await self._fetch_system_one(
            f"SELECT {_TENANT_COLS} FROM tenants WHERE id = $1",
            tenant_id,
        )
        return _row_to_tenant(row) if row else None

    async def get_by_azure_tenant_id(self, azure_tenant_id: uuid.UUID) -> Tenant | None:
        """Look up the WAF-internal tenant by its Entra azure_tenant_id.

        Used by the auth middleware to convert the JWT 'tid' claim (Entra UUID)
        into the WAF-internal tenant UUID required for all DB queries.
        """
        row = await self._fetch_system_one(
            f"SELECT {_TENANT_COLS} FROM tenants "
            "WHERE azure_tenant_id = $1 AND is_active = TRUE",
            azure_tenant_id,
        )
        return _row_to_tenant(row) if row else None

    async def get_by_slug(self, slug: str) -> Tenant | None:
        row = await self._fetch_system_one(
            f"SELECT {_TENANT_COLS} FROM tenants WHERE slug = $1",
            slug,
        )
        return _row_to_tenant(row) if row else None

    async def create(self, tenant: Tenant) -> Tenant:
        row = await self._write_system_one(
            f"""
            INSERT INTO tenants (id, slug, display_name, azure_tenant_id, plan_tier, is_active)
            VALUES ($1, $2, $3, $4, $5::plan_tier, $6)
            RETURNING {_TENANT_COLS}
            """,
            tenant.id,
            tenant.slug,
            tenant.display_name,
            tenant.azure_tenant_id,
            tenant.plan_tier.value,
            tenant.is_active,
        )
        return _row_to_tenant(row)  # type: ignore[arg-type]

    async def update_plan_tier(self, tenant_id: uuid.UUID, plan_tier: PlanTier) -> Tenant:
        row = await self._write_system_one(
            f"""
            UPDATE tenants
            SET plan_tier = $2::plan_tier, updated_at = NOW()
            WHERE id = $1
            RETURNING {_TENANT_COLS}
            """,
            tenant_id,
            plan_tier.value,
        )
        if row is None:
            raise TenantNotFoundError(tenant_id)
        return _row_to_tenant(row)

    async def deactivate(self, tenant_id: uuid.UUID) -> None:
        await self._execute_system(
            "UPDATE tenants SET is_active = FALSE, updated_at = NOW() WHERE id = $1",
            tenant_id,
        )

    async def list_active(
        self,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
    ) -> list[Tenant]:
        if cursor is None:
            rows = await self._fetch_system(
                f"SELECT {_TENANT_COLS} FROM tenants WHERE is_active = TRUE "
                "ORDER BY id LIMIT $1",
                limit,
            )
        else:
            rows = await self._fetch_system(
                f"SELECT {_TENANT_COLS} FROM tenants WHERE is_active = TRUE AND id > $2 "
                "ORDER BY id LIMIT $1",
                limit,
                cursor,
            )
        return [_row_to_tenant(r) for r in rows]

    async def get_user_by_oid(
        self,
        tenant_id: uuid.UUID,
        entra_oid: uuid.UUID,
    ) -> TenantUser | None:
        row = await self._read_one(
            f"SELECT {_USER_COLS} FROM tenant_users "
            "WHERE tenant_id = $1 AND entra_oid = $2 AND is_active = TRUE",
            tenant_id,
            tenant_id,
            entra_oid,
        )
        return _row_to_user(row) if row else None

    async def upsert_user(self, user: TenantUser) -> TenantUser:
        row = await self._write_one(
            f"""
            INSERT INTO tenant_users (id, tenant_id, entra_oid, role, is_active)
            VALUES ($1, $2, $3, $4::user_role, $5)
            ON CONFLICT (tenant_id, entra_oid) DO UPDATE
                SET role = EXCLUDED.role,
                    is_active = EXCLUDED.is_active
            RETURNING {_USER_COLS}
            """,
            user.tenant_id,
            user.id,
            user.tenant_id,
            user.entra_oid,
            user.role.value,
            user.is_active,
        )
        return _row_to_user(row)  # type: ignore[arg-type]

    async def get_quota(self, tenant_id: uuid.UUID) -> TenantQuota | None:
        row = await self._read_one(
            f"SELECT {_QUOTA_COLS} FROM tenant_quotas WHERE tenant_id = $1",
            tenant_id,
            tenant_id,
        )
        return _row_to_quota(row) if row else None

    async def upsert_quota(self, quota: TenantQuota) -> TenantQuota:
        row = await self._write_one(
            f"""
            INSERT INTO tenant_quotas (
                tenant_id, max_concurrent_assessments, max_monthly_assessments,
                max_subscriptions_per_assessment, max_resources_per_assessment
            ) VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (tenant_id) DO UPDATE
                SET max_concurrent_assessments      = EXCLUDED.max_concurrent_assessments,
                    max_monthly_assessments         = EXCLUDED.max_monthly_assessments,
                    max_subscriptions_per_assessment = EXCLUDED.max_subscriptions_per_assessment,
                    max_resources_per_assessment    = EXCLUDED.max_resources_per_assessment,
                    updated_at                      = NOW()
            RETURNING {_QUOTA_COLS}
            """,
            quota.tenant_id,
            quota.tenant_id,
            quota.max_concurrent_assessments,
            quota.max_monthly_assessments,
            quota.max_subscriptions_per_assessment,
            quota.max_resources_per_assessment,
        )
        return _row_to_quota(row)  # type: ignore[arg-type]
