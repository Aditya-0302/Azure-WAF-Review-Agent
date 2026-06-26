"""Unit tests for credential providers."""

from __future__ import annotations

import json
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from waf_shared.auth.config import (
    AuthMode,
    PlatformAuthConfig,
    ServicePrincipalConfig,
    WorkloadIdentityConfig,
)
from waf_shared.auth.credential_provider import (
    CrossTenantCredentialProvider,
    ManagedIdentityCredentialProvider,
    ServicePrincipalCredentialProvider,
    WorkloadIdentityCredentialProvider,
    _parse_sp_secret,
    create_platform_provider,
)
from waf_shared.domain.errors.infrastructure_errors import (
    CredentialUnavailableError,
    CrossTenantAuthError,
    KeyVaultAccessError,
)

# ── ManagedIdentityCredentialProvider ────────────────────────────────────────


@pytest.mark.unit
class TestManagedIdentityCredentialProvider:
    @pytest.mark.asyncio
    async def test_get_token_returns_access_token(self) -> None:
        fake_token = MagicMock()
        fake_token.token = "mi-bearer-token"

        with patch("waf_shared.auth.credential_provider.ManagedIdentityCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cred.get_token = AsyncMock(return_value=fake_token)
            mock_cls.return_value = mock_cred

            provider = ManagedIdentityCredentialProvider(client_id="my-mi-id")
            result = await provider.get_token("https://management.azure.com/.default")

        assert result.token == "mi-bearer-token"

    @pytest.mark.asyncio
    async def test_get_token_raises_credential_unavailable_on_failure(self) -> None:
        with patch("waf_shared.auth.credential_provider.ManagedIdentityCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cred.get_token = AsyncMock(side_effect=Exception("IMDS not available"))
            mock_cls.return_value = mock_cred

            provider = ManagedIdentityCredentialProvider()
            with pytest.raises(CredentialUnavailableError) as exc_info:
                await provider.get_token("https://management.azure.com/.default")

        assert "Managed Identity" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_credential_is_created_without_client_id_when_not_provided(
        self,
    ) -> None:
        with patch("waf_shared.auth.credential_provider.ManagedIdentityCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cred.get_token = AsyncMock(return_value=MagicMock(token="tok"))
            mock_cls.return_value = mock_cred

            provider = ManagedIdentityCredentialProvider(client_id=None)
            await provider.get_credential()

        mock_cls.assert_called_once_with()  # no client_id kwarg

    @pytest.mark.asyncio
    async def test_close_releases_credential(self) -> None:
        with patch("waf_shared.auth.credential_provider.ManagedIdentityCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cls.return_value = mock_cred

            provider = ManagedIdentityCredentialProvider()
            await provider.get_credential()
            await provider.close()

        mock_cred.close.assert_awaited_once()
        assert provider._credential is None


# ── WorkloadIdentityCredentialProvider ───────────────────────────────────────


@pytest.mark.unit
class TestWorkloadIdentityCredentialProvider:
    @pytest.mark.asyncio
    async def test_get_token_returns_access_token(self) -> None:
        fake_token = MagicMock()
        fake_token.token = "wi-bearer-token"

        with patch("waf_shared.auth.credential_provider.WorkloadIdentityCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cred.get_token = AsyncMock(return_value=fake_token)
            mock_cls.return_value = mock_cred

            provider = WorkloadIdentityCredentialProvider(
                tenant_id="tenant-123", client_id="client-abc"
            )
            result = await provider.get_token("https://management.azure.com/.default")

        assert result.token == "wi-bearer-token"

    @pytest.mark.asyncio
    async def test_get_token_raises_on_failure(self) -> None:
        with patch("waf_shared.auth.credential_provider.WorkloadIdentityCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cred.get_token = AsyncMock(side_effect=Exception("Token file not found"))
            mock_cls.return_value = mock_cred

            provider = WorkloadIdentityCredentialProvider(tenant_id="t", client_id="c")
            with pytest.raises(CredentialUnavailableError):
                await provider.get_token("https://management.azure.com/.default")


# ── ServicePrincipalCredentialProvider ───────────────────────────────────────


@pytest.mark.unit
class TestServicePrincipalCredentialProvider:
    def test_raises_if_no_secret_source(self) -> None:
        with pytest.raises(ValueError, match="One of client_secret"):
            ServicePrincipalCredentialProvider(tenant_id="t", client_id="c")

    @pytest.mark.asyncio
    async def test_get_token_using_inline_secret(self) -> None:
        fake_token = MagicMock()
        fake_token.token = "sp-bearer-token"

        with patch("waf_shared.auth.credential_provider.ClientSecretCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cred.get_token = AsyncMock(return_value=fake_token)
            mock_cls.return_value = mock_cred

            provider = ServicePrincipalCredentialProvider(
                tenant_id="tenant-id",
                client_id="client-id",
                client_secret="my-secret",
            )
            result = await provider.get_token("https://management.azure.com/.default")

        assert result.token == "sp-bearer-token"
        mock_cls.assert_called_once_with(
            tenant_id="tenant-id",
            client_id="client-id",
            client_secret="my-secret",
        )

    @pytest.mark.asyncio
    async def test_get_token_reads_secret_from_path(self, tmp_path: Path) -> None:
        secret_file = tmp_path / "client-secret"
        secret_file.write_text("file-secret\n")

        fake_token = MagicMock()
        fake_token.token = "sp-file-token"

        with patch("waf_shared.auth.credential_provider.ClientSecretCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cred.get_token = AsyncMock(return_value=fake_token)
            mock_cls.return_value = mock_cred

            provider = ServicePrincipalCredentialProvider(
                tenant_id="t",
                client_id="c",
                client_secret_path=secret_file,
            )
            result = await provider.get_token("https://management.azure.com/.default")

        assert result.token == "sp-file-token"
        mock_cls.assert_called_once_with(tenant_id="t", client_id="c", client_secret="file-secret")


# ── CrossTenantCredentialProvider ────────────────────────────────────────────


@pytest.mark.unit
class TestCrossTenantCredentialProvider:
    def _make_provider(
        self,
        kv_secret_value: str | None = None,
        kv_side_effect: Exception | None = None,
    ) -> tuple[CrossTenantCredentialProvider, AsyncMock]:
        platform_cred = AsyncMock()
        platform_cred.get_token = AsyncMock(return_value=MagicMock(token="plat"))
        platform_provider = AsyncMock()
        platform_provider.get_credential = AsyncMock(return_value=platform_cred)
        platform_provider.get_token = AsyncMock(return_value=MagicMock(token="plat"))

        mock_secret = MagicMock()
        mock_secret.value = kv_secret_value

        mock_kv_client = AsyncMock()
        if kv_side_effect:
            mock_kv_client.get_secret = AsyncMock(side_effect=kv_side_effect)
        else:
            mock_kv_client.get_secret = AsyncMock(return_value=mock_secret)

        provider = CrossTenantCredentialProvider(
            keyvault_uri="https://vault.azure.net",
            platform_provider=platform_provider,
        )
        provider._kv_client = mock_kv_client
        return provider, mock_kv_client

    @pytest.mark.asyncio
    async def test_get_credential_parses_json_and_creates_sp_cred(self) -> None:
        sp_json = json.dumps(
            {
                "tenant_id": "ext-tenant",
                "client_id": "ext-client",
                "client_secret": "ext-secret",
            }
        )
        provider, _ = self._make_provider(kv_secret_value=sp_json)
        subscription_id = uuid.uuid4()

        with patch("waf_shared.auth.credential_provider.ClientSecretCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cls.return_value = mock_cred

            result = await provider.get_credential_for_subscription(
                subscription_id=subscription_id,
                keyvault_secret_name="my-secret",
            )

        mock_cls.assert_called_once_with(
            tenant_id="ext-tenant",
            client_id="ext-client",
            client_secret="ext-secret",
        )
        assert result is mock_cred

    @pytest.mark.asyncio
    async def test_caches_credential_on_second_call(self) -> None:
        sp_json = json.dumps({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        provider, mock_kv = self._make_provider(kv_secret_value=sp_json)
        subscription_id = uuid.uuid4()

        with patch("waf_shared.auth.credential_provider.ClientSecretCredential"):
            await provider.get_credential_for_subscription(subscription_id, "secret-name")
            await provider.get_credential_for_subscription(subscription_id, "secret-name")

        assert mock_kv.get_secret.await_count == 1  # only fetched once

    @pytest.mark.asyncio
    async def test_raises_keyvault_access_error_on_kv_failure(self) -> None:
        provider, _ = self._make_provider(kv_side_effect=Exception("HTTP 403"))
        with pytest.raises(KeyVaultAccessError) as exc_info:
            await provider.get_credential_for_subscription(uuid.uuid4(), "secret-name")
        assert "HTTP 403" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_raises_cross_tenant_error_on_invalid_json(self) -> None:
        provider, _ = self._make_provider(kv_secret_value="not-json")
        with pytest.raises(CrossTenantAuthError):
            await provider.get_credential_for_subscription(uuid.uuid4(), "secret-name")

    @pytest.mark.asyncio
    async def test_raises_cross_tenant_error_on_missing_fields(self) -> None:
        provider, _ = self._make_provider(kv_secret_value=json.dumps({"tenant_id": "t"}))
        with pytest.raises(CrossTenantAuthError) as exc_info:
            await provider.get_credential_for_subscription(uuid.uuid4(), "secret-name")
        assert "missing required fields" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_invalidate_cache_removes_and_closes_credential(self) -> None:
        sp_json = json.dumps({"tenant_id": "t", "client_id": "c", "client_secret": "s"})
        provider, _ = self._make_provider(kv_secret_value=sp_json)
        subscription_id = uuid.uuid4()

        with patch("waf_shared.auth.credential_provider.ClientSecretCredential") as mock_cls:
            mock_cred = AsyncMock()
            mock_cls.return_value = mock_cred

            await provider.get_credential_for_subscription(subscription_id, "secret-name")
            assert str(subscription_id) in provider._cache

            await provider.invalidate_cache(subscription_id)

        assert str(subscription_id) not in provider._cache
        mock_cred.close.assert_awaited_once()


# ── _parse_sp_secret ──────────────────────────────────────────────────────────


@pytest.mark.unit
class TestParseSpSecret:
    def test_valid_json_returns_dict(self) -> None:
        raw = '{"tenant_id": "t1", "client_id": "c1", "client_secret": "s1"}'
        result = _parse_sp_secret(raw)
        assert result == {"tenant_id": "t1", "client_id": "c1", "client_secret": "s1"}

    def test_valid_json_with_extra_fields_passes_through(self) -> None:
        raw = '{"tenant_id": "t", "client_id": "c", "client_secret": "s", "extra": "x"}'
        result = _parse_sp_secret(raw)
        assert result["extra"] == "x"

    def test_format_a_key_equals_value_per_line(self) -> None:
        raw = "tenant_id=t1\nclient_id=c1\nclient_secret=s1"
        result = _parse_sp_secret(raw)
        assert result == {"tenant_id": "t1", "client_id": "c1", "client_secret": "s1"}

    def test_format_a_secret_value_containing_equals(self) -> None:
        raw = "tenant_id=t\nclient_id=c\nclient_secret=abc=def=="
        result = _parse_sp_secret(raw)
        assert result["client_secret"] == "abc=def=="

    def test_format_b_key_colon_value_per_line(self) -> None:
        raw = "tenant_id:t1\nclient_id:c1\nclient_secret:s1"
        result = _parse_sp_secret(raw)
        assert result == {"tenant_id": "t1", "client_id": "c1", "client_secret": "s1"}

    def test_format_c_brace_wrapped_comma_separated(self) -> None:
        raw = "{tenant_id:t1,client_id:c1,client_secret:s1}"
        result = _parse_sp_secret(raw)
        assert result == {"tenant_id": "t1", "client_id": "c1", "client_secret": "s1"}

    def test_invalid_content_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="unrecognized format"):
            _parse_sp_secret("completely-garbage-value")

    def test_empty_string_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            _parse_sp_secret("")

    def test_none_equivalent_raises_value_error(self) -> None:
        with pytest.raises(ValueError):
            _parse_sp_secret("   ")

    def test_valid_json_does_not_log_warning(self) -> None:
        with patch("waf_shared.auth.credential_provider._logger") as mock_log:
            _parse_sp_secret('{"tenant_id": "t", "client_id": "c", "client_secret": "s"}')
        mock_log.warning.assert_not_called()

    def test_legacy_format_logs_warning_with_secret_name(self) -> None:
        with patch("waf_shared.auth.credential_provider._logger") as mock_log:
            _parse_sp_secret("tenant_id=t\nclient_id=c\nclient_secret=s", secret_name="my-secret")
        mock_log.warning.assert_called_once()
        event, kwargs = mock_log.warning.call_args[0][0], mock_log.warning.call_args[1]
        assert event == "auth.cross_tenant.secret.legacy_format"
        assert kwargs.get("secret_name") == "my-secret"

    def test_format_b_logs_legacy_warning(self) -> None:
        with patch("waf_shared.auth.credential_provider._logger") as mock_log:
            _parse_sp_secret("tenant_id:t\nclient_id:c\nclient_secret:s")
        mock_log.warning.assert_called_once()

    def test_format_c_logs_legacy_warning(self) -> None:
        with patch("waf_shared.auth.credential_provider._logger") as mock_log:
            _parse_sp_secret("{tenant_id:t,client_id:c,client_secret:s}")
        mock_log.warning.assert_called_once()


# ── CrossTenantCredentialProvider — legacy format acceptance ─────────────────


@pytest.mark.unit
class TestCrossTenantLegacyFormats:
    """Verifies CrossTenantCredentialProvider accepts all non-JSON secret formats."""

    def _make_provider(self, kv_secret_value: str) -> CrossTenantCredentialProvider:
        platform_provider = AsyncMock()
        platform_provider.get_credential = AsyncMock(return_value=AsyncMock())

        mock_secret = MagicMock()
        mock_secret.value = kv_secret_value

        mock_kv_client = AsyncMock()
        mock_kv_client.get_secret = AsyncMock(return_value=mock_secret)

        provider = CrossTenantCredentialProvider(
            keyvault_uri="https://vault.azure.net",
            platform_provider=platform_provider,
        )
        provider._kv_client = mock_kv_client
        return provider

    @pytest.mark.asyncio
    async def test_accepts_format_a_key_equals_value(self) -> None:
        secret = "tenant_id=ext-tenant\nclient_id=ext-client\nclient_secret=ext-secret"
        provider = self._make_provider(secret)
        with patch("waf_shared.auth.credential_provider._SyncClientSecretCredential") as mock_cls:
            mock_cls.return_value = MagicMock()
            await provider.get_credential_for_subscription(uuid.uuid4(), "my-secret")
        mock_cls.assert_called_once_with(
            tenant_id="ext-tenant", client_id="ext-client", client_secret="ext-secret"
        )

    @pytest.mark.asyncio
    async def test_accepts_format_b_key_colon_value(self) -> None:
        secret = "tenant_id:ext-tenant\nclient_id:ext-client\nclient_secret:ext-secret"
        provider = self._make_provider(secret)
        with patch("waf_shared.auth.credential_provider._SyncClientSecretCredential") as mock_cls:
            mock_cls.return_value = MagicMock()
            await provider.get_credential_for_subscription(uuid.uuid4(), "my-secret")
        mock_cls.assert_called_once_with(
            tenant_id="ext-tenant", client_id="ext-client", client_secret="ext-secret"
        )

    @pytest.mark.asyncio
    async def test_accepts_format_c_brace_wrapped(self) -> None:
        secret = "{tenant_id:ext-tenant,client_id:ext-client,client_secret:ext-secret}"
        provider = self._make_provider(secret)
        with patch("waf_shared.auth.credential_provider._SyncClientSecretCredential") as mock_cls:
            mock_cls.return_value = MagicMock()
            await provider.get_credential_for_subscription(uuid.uuid4(), "my-secret")
        mock_cls.assert_called_once_with(
            tenant_id="ext-tenant", client_id="ext-client", client_secret="ext-secret"
        )

    @pytest.mark.asyncio
    async def test_missing_fields_raises_cross_tenant_error(self) -> None:
        secret = "tenant_id=only-tenant"
        provider = self._make_provider(secret)
        with pytest.raises(CrossTenantAuthError) as exc_info:
            await provider.get_credential_for_subscription(uuid.uuid4(), "bad-secret")
        assert "missing required fields" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_completely_unreadable_secret_raises_cross_tenant_error(self) -> None:
        provider = self._make_provider("garbage-no-separator")
        with pytest.raises(CrossTenantAuthError):
            await provider.get_credential_for_subscription(uuid.uuid4(), "bad-secret")


# ── Factory ───────────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestCreatePlatformProvider:
    def test_returns_managed_identity_provider(self) -> None:
        config = PlatformAuthConfig(mode=AuthMode.MANAGED_IDENTITY)
        provider = create_platform_provider(config)
        assert isinstance(provider, ManagedIdentityCredentialProvider)

    def test_returns_workload_identity_provider(self) -> None:
        config = PlatformAuthConfig(
            mode=AuthMode.WORKLOAD_IDENTITY,
            workload_identity=WorkloadIdentityConfig(tenant_id="t", client_id="c"),
        )
        provider = create_platform_provider(config)
        assert isinstance(provider, WorkloadIdentityCredentialProvider)

    def test_returns_sp_provider(self) -> None:
        config = PlatformAuthConfig(
            mode=AuthMode.SERVICE_PRINCIPAL,
            service_principal=ServicePrincipalConfig(
                tenant_id="t",
                client_id="c",
                client_secret="s",
            ),
        )
        provider = create_platform_provider(config)
        assert isinstance(provider, ServicePrincipalCredentialProvider)

    def test_raises_if_workload_identity_config_missing(self) -> None:
        config = PlatformAuthConfig(
            mode=AuthMode.WORKLOAD_IDENTITY,
            workload_identity=None,
        )
        with pytest.raises(ValueError, match="workload_identity config"):
            create_platform_provider(config)

    def test_raises_if_sp_config_missing(self) -> None:
        config = PlatformAuthConfig(
            mode=AuthMode.SERVICE_PRINCIPAL,
            service_principal=None,
        )
        with pytest.raises(ValueError, match="service_principal config"):
            create_platform_provider(config)
