"""Repository interface for the Tenant aggregate."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod

from waf_shared.domain.models.tenant import PlanTier, Tenant, TenantQuota, TenantUser


class ITenantRepository(ABC):
    @abstractmethod
    async def get_by_id(self, tenant_id: uuid.UUID) -> Tenant | None: ...

    @abstractmethod
    async def get_by_slug(self, slug: str) -> Tenant | None: ...

    @abstractmethod
    async def create(self, tenant: Tenant) -> Tenant: ...

    @abstractmethod
    async def update_plan_tier(self, tenant_id: uuid.UUID, plan_tier: PlanTier) -> Tenant: ...

    @abstractmethod
    async def deactivate(self, tenant_id: uuid.UUID) -> None: ...

    @abstractmethod
    async def list_active(
        self,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
    ) -> list[Tenant]: ...

    @abstractmethod
    async def get_user_by_oid(
        self,
        tenant_id: uuid.UUID,
        entra_oid: uuid.UUID,
    ) -> TenantUser | None: ...

    @abstractmethod
    async def upsert_user(self, user: TenantUser) -> TenantUser: ...

    @abstractmethod
    async def get_quota(self, tenant_id: uuid.UUID) -> TenantQuota | None: ...

    @abstractmethod
    async def upsert_quota(self, quota: TenantQuota) -> TenantQuota: ...
