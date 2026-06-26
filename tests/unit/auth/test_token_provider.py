"""Unit tests for TokenProvider."""

from __future__ import annotations

import uuid
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_shared.auth.config import PlatformAuthConfig
from waf_shared.auth.token_provider import TokenProvider


def _make_token_provider(
    platform_token: str = "plat-token",
    subscription_token: str = "sub-token",
) -> tuple[TokenProvider, MagicMock, MagicMock]:
    platform_provider = AsyncMock()
    platform_provider.get_token = AsyncMock(
        return_value=MagicMock(token=platform_token)
    )

    cross_tenant_provider = AsyncMock()
    mock_sub_cred = AsyncMock()
    mock_sub_cred.get_token = AsyncMock(
        return_value=MagicMock(token=subscription_token, expires_on=9999999999)
    )
    cross_tenant_provider.get_credential_for_subscription = AsyncMock(
        return_value=mock_sub_cred
    )
    cross_tenant_provider.invalidate_cache = AsyncMock()

    config = PlatformAuthConfig()
    provider = TokenProvider(
        platform_provider=platform_provider,
        cross_tenant_provider=cross_tenant_provider,
        config=config,
    )
    return provider, platform_provider, cross_tenant_provider


@pytest.mark.unit
class TestTokenProviderPlatformTokens:
    @pytest.mark.asyncio
    async def test_get_arm_token_returns_string(self) -> None:
        provider, mock_plat, _ = _make_token_provider(platform_token="arm-tok")
        result = await provider.get_arm_token()
        assert result == "arm-tok"
        mock_plat.get_token.assert_awaited_once_with(
            "https://management.azure.com/.default"
        )

    @pytest.mark.asyncio
    async def test_get_keyvault_token_uses_kv_scope(self) -> None:
        provider, mock_plat, _ = _make_token_provider(platform_token="kv-tok")
        result = await provider.get_keyvault_token()
        assert result == "kv-tok"
        mock_plat.get_token.assert_awaited_once_with(
            "https://vault.azure.net/.default"
        )

    @pytest.mark.asyncio
    async def test_get_graph_token_uses_graph_scope(self) -> None:
        provider, mock_plat, _ = _make_token_provider(platform_token="graph-tok")
        result = await provider.get_graph_token()
        assert result == "graph-tok"
        mock_plat.get_token.assert_awaited_once_with(
            "https://graph.microsoft.com/.default"
        )

    @pytest.mark.asyncio
    async def test_get_platform_token_uses_provided_scope(self) -> None:
        provider, mock_plat, _ = _make_token_provider(platform_token="custom-tok")
        result = await provider.get_platform_token("https://custom.azure.net/.default")
        assert result == "custom-tok"
        mock_plat.get_token.assert_awaited_once_with(
            "https://custom.azure.net/.default"
        )


@pytest.mark.unit
class TestTokenProviderSubscriptionTokens:
    @pytest.mark.asyncio
    async def test_get_subscription_token_returns_string(self) -> None:
        provider, _, mock_cross = _make_token_provider(subscription_token="sub-tok")
        subscription_id = uuid.uuid4()

        result = await provider.get_subscription_token(
            subscription_id=subscription_id,
            keyvault_secret_name="my-secret",
        )

        assert result == "sub-tok"
        mock_cross.get_credential_for_subscription.assert_awaited_once_with(
            subscription_id=subscription_id,
            keyvault_secret_name="my-secret",
        )

    @pytest.mark.asyncio
    async def test_get_subscription_token_passes_custom_scope(self) -> None:
        provider, _, mock_cross = _make_token_provider()
        mock_sub_cred = AsyncMock()
        mock_sub_cred.get_token = AsyncMock(
            return_value=MagicMock(token="scope-tok", expires_on=1)
        )
        mock_cross.get_credential_for_subscription = AsyncMock(
            return_value=mock_sub_cred
        )

        result = await provider.get_subscription_token(
            subscription_id=uuid.uuid4(),
            keyvault_secret_name="s",
            scope="https://custom/.default",
        )

        assert result == "scope-tok"
        mock_sub_cred.get_token.assert_awaited_once_with("https://custom/.default")

    @pytest.mark.asyncio
    async def test_invalidate_delegates_to_cross_tenant_provider(self) -> None:
        provider, _, mock_cross = _make_token_provider()
        subscription_id = uuid.uuid4()

        await provider.invalidate_subscription_credential(subscription_id)

        mock_cross.invalidate_cache.assert_awaited_once_with(subscription_id)
