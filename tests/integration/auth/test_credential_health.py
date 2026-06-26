"""Integration tests for credential repository and auth health flows.

DB tests run against a real PostgreSQL instance via the db_pool fixture
(same pattern as tests/integration/db/test_repositories.py).

Azure SDK tests require real Azure credentials. They are skipped unless
the AZURE_INTEGRATION_TESTS=1 environment variable is set, because they
need a live Entra ID tenant and Key Vault.
"""

from __future__ import annotations

import json
import os
import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.auth.auth_service import AuthenticationService
from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
from waf_shared.auth.token_provider import TokenProvider
from waf_shared.auth.config import PlatformAuthConfig
from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential


_AZURE_INTEGRATION = pytest.mark.skipif(
    os.environ.get("AZURE_INTEGRATION_TESTS") != "1",
    reason="Requires AZURE_INTEGRATION_TESTS=1 and live Azure credentials",
)


# ── Database integration tests (require real PostgreSQL) ──────────────────────


@pytest.mark.integration
class TestCredentialRepositoryIntegration:
    @pytest.mark.asyncio
    async def test_create_and_get_by_id(self, db_pool) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        now = datetime.now(UTC)

        cred = SubscriptionCredential(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            subscription_id=sub_id,
            display_name="Integration Test Sub",
            keyvault_secret_name=f"test-sp-{tenant_id}",
            health=CredentialHealth.UNCHECKED,
            expires_at=None,
            last_health_check_at=None,
            created_at=now,
            updated_at=now,
        )

        repo = CredentialRepository(pool=db_pool)
        created = await repo.create(cred)

        assert created.id == cred.id
        assert created.subscription_id == sub_id
        assert created.health == CredentialHealth.UNCHECKED

        fetched = await repo.get_by_id(tenant_id, cred.id)
        assert fetched is not None
        assert fetched.id == cred.id
        assert fetched.display_name == "Integration Test Sub"

    @pytest.mark.asyncio
    async def test_get_by_subscription(self, db_pool) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        now = datetime.now(UTC)

        cred = SubscriptionCredential(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            subscription_id=sub_id,
            display_name="Sub Lookup Test",
            keyvault_secret_name=f"test-sp-{sub_id}",
            health=CredentialHealth.UNCHECKED,
            expires_at=None,
            last_health_check_at=None,
            created_at=now,
            updated_at=now,
        )

        repo = CredentialRepository(pool=db_pool)
        await repo.create(cred)

        result = await repo.get_by_subscription(tenant_id, sub_id)
        assert result is not None
        assert result.subscription_id == sub_id

    @pytest.mark.asyncio
    async def test_update_health(self, db_pool) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)

        cred = SubscriptionCredential(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            subscription_id=uuid.uuid4(),
            display_name="Health Test",
            keyvault_secret_name="health-test-secret",
            health=CredentialHealth.UNCHECKED,
            expires_at=None,
            last_health_check_at=None,
            created_at=now,
            updated_at=now,
        )

        repo = CredentialRepository(pool=db_pool)
        await repo.create(cred)

        updated = await repo.update_health(
            tenant_id=tenant_id,
            credential_id=cred.id,
            health=CredentialHealth.HEALTHY,
            expires_at=None,
            last_health_check_at=now,
        )

        assert updated.health == CredentialHealth.HEALTHY
        assert updated.last_health_check_at is not None

    @pytest.mark.asyncio
    async def test_list_by_tenant_with_pagination(self, db_pool) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)
        repo = CredentialRepository(pool=db_pool)
        cred_ids = []

        for i in range(3):
            cred = SubscriptionCredential(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                subscription_id=uuid.uuid4(),
                display_name=f"Sub {i}",
                keyvault_secret_name=f"secret-{i}",
                health=CredentialHealth.UNCHECKED,
                expires_at=None,
                last_health_check_at=None,
                created_at=now,
                updated_at=now,
            )
            await repo.create(cred)
            cred_ids.append(cred.id)

        page1 = await repo.list_by_tenant(tenant_id, limit=2)
        assert len(page1) == 2

        cursor = page1[-1].id
        page2 = await repo.list_by_tenant(tenant_id, limit=2, cursor=cursor)
        assert len(page2) >= 1
        assert all(c.id > cursor for c in page2)

    @pytest.mark.asyncio
    async def test_cross_tenant_isolation(self, db_pool) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_a = uuid.uuid4()
        tenant_b = uuid.uuid4()
        now = datetime.now(UTC)

        repo = CredentialRepository(pool=db_pool)
        cred_a = SubscriptionCredential(
            id=uuid.uuid4(),
            tenant_id=tenant_a,
            subscription_id=uuid.uuid4(),
            display_name="Tenant A Sub",
            keyvault_secret_name="secret-a",
            health=CredentialHealth.UNCHECKED,
            expires_at=None,
            last_health_check_at=None,
            created_at=now,
            updated_at=now,
        )
        await repo.create(cred_a)

        result = await repo.get_by_id(tenant_b, cred_a.id)
        assert result is None, "Tenant B must not access Tenant A's credentials"

    @pytest.mark.asyncio
    async def test_delete_removes_credential(self, db_pool) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)
        cred = SubscriptionCredential(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            subscription_id=uuid.uuid4(),
            display_name="Delete Me",
            keyvault_secret_name="delete-secret",
            health=CredentialHealth.UNCHECKED,
            expires_at=None,
            last_health_check_at=None,
            created_at=now,
            updated_at=now,
        )
        repo = CredentialRepository(pool=db_pool)
        await repo.create(cred)

        await repo.delete(tenant_id, cred.id)

        result = await repo.get_by_id(tenant_id, cred.id)
        assert result is None

    @pytest.mark.asyncio
    async def test_count_by_health(self, db_pool) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)
        repo = CredentialRepository(pool=db_pool)

        for health in [CredentialHealth.HEALTHY, CredentialHealth.HEALTHY, CredentialHealth.INVALID]:
            cred = SubscriptionCredential(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                subscription_id=uuid.uuid4(),
                display_name="Count Test",
                keyvault_secret_name=f"secret-{uuid.uuid4()}",
                health=health,
                expires_at=None,
                last_health_check_at=None,
                created_at=now,
                updated_at=now,
            )
            await repo.create(cred)

        counts = await repo.count_by_health(tenant_id)
        assert counts.get("healthy", 0) >= 2
        assert counts.get("invalid", 0) >= 1


# ── Azure SDK integration tests (require live Azure credentials) ──────────────


@pytest.mark.integration
class TestAuthServiceIntegration:
    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_validate_credential_returns_healthy_for_valid_sp(self) -> None:
        """Requires AZURE_SUBSCRIPTION_ID, AZURE_KV_URI, AZURE_KV_SECRET_NAME env vars."""
        subscription_id = uuid.UUID(os.environ["AZURE_SUBSCRIPTION_ID"])
        kv_uri = os.environ["AZURE_KV_URI"]
        kv_secret = os.environ["AZURE_KV_SECRET_NAME"]

        from waf_shared.auth.credential_provider import (
            CrossTenantCredentialProvider,
            ManagedIdentityCredentialProvider,
        )

        platform = ManagedIdentityCredentialProvider()
        cross_tenant = CrossTenantCredentialProvider(
            keyvault_uri=kv_uri,
            platform_provider=platform,
        )
        token_provider = TokenProvider(
            platform_provider=platform,
            cross_tenant_provider=cross_tenant,
            config=PlatformAuthConfig(),
        )
        svc = AuthenticationService(
            token_provider=token_provider,
            cross_tenant_provider=cross_tenant,
        )

        health = await svc.validate_subscription_credential(
            subscription_id=subscription_id,
            keyvault_secret_name=kv_secret,
        )
        assert health == CredentialHealth.HEALTHY

    @_AZURE_INTEGRATION
    @pytest.mark.asyncio
    async def test_validate_credential_returns_invalid_for_bad_secret(self) -> None:
        """Expects Key Vault to exist but the named secret to be missing/malformed."""
        kv_uri = os.environ["AZURE_KV_URI"]

        from waf_shared.auth.credential_provider import (
            CrossTenantCredentialProvider,
            ManagedIdentityCredentialProvider,
        )

        platform = ManagedIdentityCredentialProvider()
        cross_tenant = CrossTenantCredentialProvider(
            keyvault_uri=kv_uri,
            platform_provider=platform,
        )
        token_provider = TokenProvider(
            platform_provider=platform,
            cross_tenant_provider=cross_tenant,
            config=PlatformAuthConfig(),
        )
        svc = AuthenticationService(
            token_provider=token_provider,
            cross_tenant_provider=cross_tenant,
        )

        health = await svc.validate_subscription_credential(
            subscription_id=uuid.uuid4(),
            keyvault_secret_name="nonexistent-secret-that-does-not-exist",
        )
        assert health == CredentialHealth.INVALID
