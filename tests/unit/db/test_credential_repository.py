"""Unit tests for CredentialRepository."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import pytest

from waf_shared.domain.errors.domain_errors import CredentialNotFoundError
from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential


def _make_cred_row(
    *,
    tenant_id: uuid.UUID | None = None,
    credential_id: uuid.UUID | None = None,
    subscription_id: uuid.UUID | None = None,
    health: str = "unchecked",
) -> dict:
    now = datetime.now(UTC)
    return {
        "id": credential_id or uuid.uuid4(),
        "tenant_id": tenant_id or uuid.uuid4(),
        "subscription_id": subscription_id or uuid.uuid4(),
        "display_name": "My Subscription",
        "keyvault_secret_name": "tenant-123-sp-creds",
        "health": health,
        "expires_at": None,
        "last_health_check_at": None,
        "created_at": now,
        "updated_at": now,
    }


@pytest.mark.unit
class TestCredentialRepositoryGetById:
    @pytest.mark.asyncio
    async def test_returns_credential_when_found(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        cred_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[_make_cred_row(tenant_id=tenant_id, credential_id=cred_id)]
        )

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, cred_id)

        assert result is not None
        assert result.id == cred_id
        assert result.tenant_id == tenant_id
        assert result.health == CredentialHealth.UNCHECKED

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_id(tenant_id, uuid.uuid4())

        assert result is None

    @pytest.mark.asyncio
    async def test_query_filters_by_tenant_id(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        await repo.get_by_id(tenant_id, uuid.uuid4())

        sql = mock_conn.fetch.call_args[0][0]
        assert "tenant_id = $1" in sql


@pytest.mark.unit
class TestCredentialRepositoryGetBySubscription:
    @pytest.mark.asyncio
    async def test_returns_credential_when_found(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        sub_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[_make_cred_row(tenant_id=tenant_id, subscription_id=sub_id)]
        )

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_subscription(tenant_id, sub_id)

        assert result is not None
        assert result.subscription_id == sub_id

    @pytest.mark.asyncio
    async def test_returns_none_when_not_found(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.get_by_subscription(tenant_id, uuid.uuid4())

        assert result is None


@pytest.mark.unit
class TestCredentialRepositoryCreate:
    @pytest.mark.asyncio
    async def test_create_issues_insert_returning(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        now = datetime.now(UTC)
        cred_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[_make_cred_row(tenant_id=tenant_id, credential_id=cred_id)]
        )

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        credential = SubscriptionCredential(
            id=cred_id,
            tenant_id=tenant_id,
            subscription_id=uuid.uuid4(),
            display_name="Test Sub",
            keyvault_secret_name="my-secret",
            health=CredentialHealth.UNCHECKED,
            expires_at=None,
            last_health_check_at=None,
            created_at=now,
            updated_at=now,
        )
        result = await repo.create(credential)

        assert result.id == cred_id
        sql = mock_conn.fetch.call_args[0][0]
        assert "INSERT INTO subscription_credentials" in sql
        assert "RETURNING" in sql


@pytest.mark.unit
class TestCredentialRepositoryUpdateHealth:
    @pytest.mark.asyncio
    async def test_update_health_returns_updated_credential(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        cred_id = uuid.uuid4()
        now = datetime.now(UTC)
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_cred_row(
                    tenant_id=tenant_id,
                    credential_id=cred_id,
                    health="healthy",
                )
            ]
        )

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.update_health(
            tenant_id=tenant_id,
            credential_id=cred_id,
            health=CredentialHealth.HEALTHY,
            expires_at=None,
            last_health_check_at=now,
        )

        assert result.health == CredentialHealth.HEALTHY
        sql = mock_conn.fetch.call_args[0][0]
        assert "UPDATE subscription_credentials" in sql
        assert "RETURNING" in sql

    @pytest.mark.asyncio
    async def test_update_health_raises_when_not_found(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        cred_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        with pytest.raises(CredentialNotFoundError) as exc_info:
            await repo.update_health(
                tenant_id=tenant_id,
                credential_id=cred_id,
                health=CredentialHealth.INVALID,
                expires_at=None,
                last_health_check_at=datetime.now(UTC),
            )
        assert exc_info.value.credential_id == cred_id
        assert exc_info.value.tenant_id == tenant_id


@pytest.mark.unit
class TestCredentialRepositoryListByTenant:
    @pytest.mark.asyncio
    async def test_list_without_cursor(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                _make_cred_row(tenant_id=tenant_id),
                _make_cred_row(tenant_id=tenant_id),
            ]
        )

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.list_by_tenant(tenant_id, limit=10)

        assert len(result) == 2
        sql = mock_conn.fetch.call_args[0][0]
        assert "ORDER BY id" in sql
        assert "LIMIT" in sql

    @pytest.mark.asyncio
    async def test_list_with_cursor_uses_cursor_filter(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        cursor_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        await repo.list_by_tenant(tenant_id, limit=10, cursor=cursor_id)

        sql = mock_conn.fetch.call_args[0][0]
        assert "id > $2" in sql


@pytest.mark.unit
class TestCredentialRepositoryCountByHealth:
    @pytest.mark.asyncio
    async def test_count_by_health_returns_dict(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(
            return_value=[
                {"health": "healthy", "n": 3},
                {"health": "expiring_soon", "n": 1},
                {"health": "invalid", "n": 2},
            ]
        )

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        result = await repo.count_by_health(tenant_id)

        assert result == {"healthy": 3, "expiring_soon": 1, "invalid": 2}


@pytest.mark.unit
class TestCredentialRepositoryDelete:
    @pytest.mark.asyncio
    async def test_delete_issues_delete_statement(self) -> None:
        from waf_shared.db.repositories.credential_repository import CredentialRepository

        tenant_id = uuid.uuid4()
        cred_id = uuid.uuid4()
        mock_conn = AsyncMock()
        mock_conn.fetch = AsyncMock(return_value=[])

        repo = CredentialRepository(conn=mock_conn, uow_tenant_id=tenant_id)
        await repo.delete(tenant_id, cred_id)

        sql = mock_conn.fetch.call_args[0][0]
        assert "DELETE FROM subscription_credentials" in sql
        assert "tenant_id = $1" in sql
