"""ICredentialRepository — subscription credential persistence contract."""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from datetime import datetime

from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential


class ICredentialRepository(ABC):
    @abstractmethod
    async def get_by_id(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
    ) -> SubscriptionCredential | None: ...

    @abstractmethod
    async def get_by_subscription(
        self,
        tenant_id: uuid.UUID,
        subscription_id: uuid.UUID,
    ) -> SubscriptionCredential | None: ...

    @abstractmethod
    async def create(self, credential: SubscriptionCredential) -> SubscriptionCredential: ...

    @abstractmethod
    async def update_health(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
        health: CredentialHealth,
        expires_at: datetime | None,
        last_health_check_at: datetime,
    ) -> SubscriptionCredential: ...

    @abstractmethod
    async def delete(
        self,
        tenant_id: uuid.UUID,
        credential_id: uuid.UUID,
    ) -> None: ...

    @abstractmethod
    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        limit: int = 50,
        cursor: uuid.UUID | None = None,
    ) -> list[SubscriptionCredential]: ...

    @abstractmethod
    async def list_expiring(
        self,
        before: datetime,
        limit: int = 100,
    ) -> list[SubscriptionCredential]:
        """System-scoped sweep — no tenant filter, for platform health-check jobs."""
        ...

    @abstractmethod
    async def count_by_health(
        self,
        tenant_id: uuid.UUID,
    ) -> dict[str, int]: ...
