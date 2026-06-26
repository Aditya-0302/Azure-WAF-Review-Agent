"""Unit tests for AuthenticationService."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.auth.auth_service import AuthenticationService
from waf_shared.domain.errors.infrastructure_errors import (
    CredentialUnavailableError,
    CrossTenantAuthError,
)
from waf_shared.domain.models.credential import CredentialHealth


def _make_service(
    *,
    subscription_token: str | None = "tok",
    validate_side_effect: Exception | None = None,
) -> tuple[AuthenticationService, MagicMock, MagicMock]:
    mock_tokens = AsyncMock()
    if validate_side_effect:
        mock_tokens.get_subscription_token = AsyncMock(side_effect=validate_side_effect)
    else:
        mock_tokens.get_subscription_token = AsyncMock(return_value=subscription_token)
    mock_tokens.get_arm_token = AsyncMock(return_value="arm-tok")
    mock_tokens.get_graph_token = AsyncMock(return_value="graph-tok")
    mock_tokens.get_keyvault_token = AsyncMock(return_value="kv-tok")

    mock_cross = AsyncMock()
    mock_cross.get_credential_for_subscription = AsyncMock(return_value=MagicMock())
    mock_cross.invalidate_cache = AsyncMock()

    svc = AuthenticationService(
        token_provider=mock_tokens,
        cross_tenant_provider=mock_cross,
    )
    return svc, mock_tokens, mock_cross


@pytest.mark.unit
class TestAuthenticationServiceValidation:
    @pytest.mark.asyncio
    async def test_returns_healthy_on_successful_token(self) -> None:
        svc, _, _ = _make_service(subscription_token="valid-token")
        result = await svc.validate_subscription_credential(
            subscription_id=uuid.uuid4(),
            keyvault_secret_name="my-secret",
        )
        assert result == CredentialHealth.HEALTHY

    @pytest.mark.asyncio
    async def test_returns_invalid_on_empty_token(self) -> None:
        svc, _, _ = _make_service(subscription_token="")
        result = await svc.validate_subscription_credential(
            subscription_id=uuid.uuid4(),
            keyvault_secret_name="my-secret",
        )
        assert result == CredentialHealth.INVALID

    @pytest.mark.asyncio
    async def test_returns_invalid_on_cross_tenant_auth_error(self) -> None:
        sub_id = uuid.uuid4()
        svc, _, _ = _make_service(
            validate_side_effect=CrossTenantAuthError(
                subscription_id=sub_id, reason="bad SP config"
            )
        )
        result = await svc.validate_subscription_credential(
            subscription_id=sub_id,
            keyvault_secret_name="my-secret",
        )
        assert result == CredentialHealth.INVALID

    @pytest.mark.asyncio
    async def test_returns_invalid_on_credential_unavailable(self) -> None:
        svc, _, _ = _make_service(
            validate_side_effect=CredentialUnavailableError("IMDS not reachable")
        )
        result = await svc.validate_subscription_credential(
            subscription_id=uuid.uuid4(),
            keyvault_secret_name="my-secret",
        )
        assert result == CredentialHealth.INVALID


@pytest.mark.unit
class TestAuthenticationServiceCredentials:
    @pytest.mark.asyncio
    async def test_get_subscription_credential_delegates_to_cross_tenant(
        self,
    ) -> None:
        svc, _, mock_cross = _make_service()
        subscription_id = uuid.uuid4()

        await svc.get_subscription_credential(
            subscription_id=subscription_id,
            keyvault_secret_name="sec",
        )

        mock_cross.get_credential_for_subscription.assert_awaited_once_with(
            subscription_id=subscription_id,
            keyvault_secret_name="sec",
        )

    @pytest.mark.asyncio
    async def test_refresh_invalidates_cache(self) -> None:
        svc, _, mock_cross = _make_service()
        subscription_id = uuid.uuid4()

        await svc.refresh_subscription_credential(subscription_id)

        mock_cross.invalidate_cache.assert_awaited_once_with(subscription_id)


@pytest.mark.unit
class TestAuthenticationServicePlatformTokens:
    @pytest.mark.asyncio
    async def test_get_arm_token_delegates(self) -> None:
        svc, mock_tokens, _ = _make_service()
        result = await svc.get_arm_token()
        assert result == "arm-tok"
        mock_tokens.get_arm_token.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_graph_token_delegates(self) -> None:
        svc, mock_tokens, _ = _make_service()
        result = await svc.get_graph_token()
        assert result == "graph-tok"

    @pytest.mark.asyncio
    async def test_get_keyvault_token_delegates(self) -> None:
        svc, mock_tokens, _ = _make_service()
        result = await svc.get_keyvault_token()
        assert result == "kv-tok"
