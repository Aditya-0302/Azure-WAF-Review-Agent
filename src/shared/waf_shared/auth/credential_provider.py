"""Azure credential providers.

Four concrete implementations + a factory:

  ManagedIdentityCredentialProvider  — System- or User-Assigned MI (ACI / AKS)
  WorkloadIdentityCredentialProvider — AKS OIDC federation
  ServicePrincipalCredentialProvider — Client-secret from a mounted file
  CrossTenantCredentialProvider      — Reads customer SP JSON from Key Vault,
                                       builds per-subscription credentials
  _DefaultAzureCredentialProvider    — DefaultAzureCredential (dev / CI only)

All providers use azure.identity.aio for async token acquisition.
Credential objects are lazily created and cached inside each provider instance.
"""

from __future__ import annotations

import importlib.metadata as _meta
import json
import uuid
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

# Verify aiohttp is installed before azure.identity.aio tries to import it.
# azure-identity declares aiohttp as an optional extra ([aio]) rather than a
# required dependency, so pip omits it unless explicitly declared. Without it,
# every import of azure.identity.aio raises:
#   ImportError: aiohttp package is not installed
try:
    _AIOHTTP_VERSION: str = _meta.version("aiohttp")
except _meta.PackageNotFoundError as _exc:
    raise ImportError(
        "aiohttp is not installed but is required by azure.identity.aio for async "
        "credential support. Add 'aiohttp>=3.9.0' to the package dependencies in "
        "src/shared/pyproject.toml."
    ) from _exc

from azure.core.credentials import AccessToken
from azure.core.credentials_async import AsyncTokenCredential
from azure.identity import ClientSecretCredential as _SyncCredential
from azure.identity.aio import (
    ClientSecretCredential,
    DefaultAzureCredential,
    ManagedIdentityCredential,
    WorkloadIdentityCredential,
)
from azure.keyvault.secrets.aio import SecretClient


def _SyncClientSecretCredential(*args, **kwargs) -> ClientSecretCredential:
    """Creates an azure.identity.aio.ClientSecretCredential for cross-tenant async SDK use.

    The name is kept for test-patch compatibility: tests that assert on
    cross-tenant credential construction patch this module-level name.
    """
    return ClientSecretCredential(*args, **kwargs)


from waf_shared.auth.config import AuthMode, PlatformAuthConfig
from waf_shared.domain.errors.infrastructure_errors import (
    CredentialUnavailableError,
    CrossTenantAuthError,
    KeyVaultAccessError,
)
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-shared", version="0.1.0")
_logger.info("startup.dependency.check", aiohttp_version=_AIOHTTP_VERSION)


# ── SP secret parser ──────────────────────────────────────────────────────────


def _parse_sp_secret(secret_value: str, secret_name: str = "") -> dict[str, str]:
    """Parse a Key Vault SP credential secret in JSON or legacy text formats.

    Accepted formats (tried in order):

      JSON (canonical):
          {"tenant_id": "...", "client_id": "...", "client_secret": "..."}

      Format A — key=value per line:
          tenant_id=<value>
          client_id=<value>
          client_secret=<value>

      Format B — key:value per line:
          tenant_id:<value>
          client_id:<value>
          client_secret:<value>

      Format C — brace-wrapped, comma-separated key:value pairs:
          {tenant_id:<value>,client_id:<value>,client_secret:<value>}

    Returns a normalized dict[str, str].
    Raises ValueError when no format matches.

    Legacy formats (A/B/C) log auth.cross_tenant.secret.legacy_format.
    JSON emits no warning.
    """
    value = (secret_value or "").strip()

    # 1. Strict JSON — canonical format; no warning emitted.
    try:
        candidate = json.loads(value)
        if isinstance(candidate, dict):
            return {k: str(v) for k, v in candidate.items()}
    except (json.JSONDecodeError, ValueError):
        pass

    # 2–4. Legacy text formats.
    # Strip optional braces so Format C looks like a comma-separated A/B block.
    inner = value
    if inner.startswith("{") and inner.endswith("}"):
        inner = inner[1:-1]

    # Choose split strategy: multi-line → newline-separated (A/B); single-line → comma-separated (C).  # noqa: E501
    if "\n" in inner:
        parts = [p.strip() for p in inner.splitlines() if p.strip()]
    else:
        parts = [p.strip() for p in inner.split(",") if p.strip()]

    result: dict[str, str] = {}
    for part in parts:
        if "=" in part:
            key, _, val = part.partition("=")
            result[key.strip()] = val.strip()
        elif ":" in part:
            key, _, val = part.partition(":")
            result[key.strip()] = val.strip()

    if result:
        _logger.warning(
            "auth.cross_tenant.secret.legacy_format",
            secret_name=secret_name or "<unknown>",
        )
        # Detect unresolved null/empty placeholders (e.g. tenant_id=null written when
        # $spTenantId was unset during Key Vault secret provisioning).
        null_fields = {k for k, v in result.items() if not v or v.lower() in ("null", "none")}
        if null_fields:
            raise ValueError(
                f"Key Vault secret '{secret_name or 'unknown'}' has null/empty placeholder "
                f"values for fields: {sorted(null_fields)}. "
                "Re-provision the secret with valid SP credentials."
            )
        return result

    raise ValueError(
        f"Key Vault secret '{secret_name or 'unknown'}' uses an unrecognized format. "
        "Accepted formats: JSON object, key=value per line, key:value per line, "
        "or brace-wrapped comma-separated pairs."
    )


# ── Abstract base ─────────────────────────────────────────────────────────────


class CredentialProvider(ABC):
    """Contract for all credential providers."""

    @abstractmethod
    async def get_credential(self) -> AsyncTokenCredential:
        """Return an async credential that can acquire tokens."""
        ...

    @abstractmethod
    async def get_token(self, *scopes: str) -> AccessToken:
        """Acquire an access token for the given scopes."""
        ...

    async def close(self) -> None:
        """Release underlying HTTP connections."""


# ── Managed Identity ──────────────────────────────────────────────────────────


class ManagedIdentityCredentialProvider(CredentialProvider):
    """Authenticates via Managed Identity (System- or User-Assigned)."""

    def __init__(self, client_id: str | None = None) -> None:
        self._client_id = client_id
        self._credential: ManagedIdentityCredential | None = None

    async def get_credential(self) -> ManagedIdentityCredential:
        if self._credential is None:
            kwargs: dict[str, Any] = {}
            if self._client_id:
                kwargs["client_id"] = self._client_id
            self._credential = ManagedIdentityCredential(**kwargs)
        return self._credential

    async def get_token(self, *scopes: str) -> AccessToken:
        cred = await self.get_credential()
        try:
            return await cred.get_token(*scopes)
        except Exception as exc:
            raise CredentialUnavailableError(
                f"Managed Identity token acquisition failed: {exc}"
            ) from exc

    async def close(self) -> None:
        if self._credential is not None:
            await self._credential.close()
            self._credential = None


# ── Workload Identity ─────────────────────────────────────────────────────────


class WorkloadIdentityCredentialProvider(CredentialProvider):
    """AKS Workload Identity via OIDC federation."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        token_file_path: str | Path | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._token_file_path = str(token_file_path) if token_file_path else None
        self._credential: WorkloadIdentityCredential | None = None

    async def get_credential(self) -> WorkloadIdentityCredential:
        if self._credential is None:
            kwargs: dict[str, Any] = {
                "tenant_id": self._tenant_id,
                "client_id": self._client_id,
            }
            if self._token_file_path:
                kwargs["token_file_path"] = self._token_file_path
            self._credential = WorkloadIdentityCredential(**kwargs)
        return self._credential

    async def get_token(self, *scopes: str) -> AccessToken:
        cred = await self.get_credential()
        try:
            return await cred.get_token(*scopes)
        except Exception as exc:
            raise CredentialUnavailableError(
                f"Workload Identity token acquisition failed: {exc}"
            ) from exc

    async def close(self) -> None:
        if self._credential is not None:
            await self._credential.close()
            self._credential = None


# ── Service Principal ─────────────────────────────────────────────────────────


class ServicePrincipalCredentialProvider(CredentialProvider):
    """Client-secret or certificate SP credential.

    Secrets must arrive via a mounted file (CSI SecretStore) rather than
    environment variables. Pass client_secret only in tests / dev flows.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        *,
        client_secret: str | None = None,
        client_secret_path: Path | None = None,
        certificate_path: Path | None = None,
    ) -> None:
        if not any([client_secret, client_secret_path, certificate_path]):
            raise ValueError(
                "One of client_secret, client_secret_path, or certificate_path is required"
            )
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._client_secret_path = client_secret_path
        self._certificate_path = certificate_path
        self._credential: ClientSecretCredential | None = None

    def _read_secret(self) -> str:
        if self._client_secret:
            return self._client_secret
        if self._client_secret_path:
            return self._client_secret_path.read_text().strip()
        raise CredentialUnavailableError(
            "No client secret source configured for ServicePrincipalCredentialProvider"
        )

    async def get_credential(self) -> ClientSecretCredential:
        if self._credential is None:
            secret = self._read_secret()
            self._credential = ClientSecretCredential(
                tenant_id=self._tenant_id,
                client_id=self._client_id,
                client_secret=secret,
            )
        return self._credential

    async def get_token(self, *scopes: str) -> AccessToken:
        cred = await self.get_credential()
        try:
            return await cred.get_token(*scopes)
        except Exception as exc:
            raise CredentialUnavailableError(
                f"Service Principal token acquisition failed: {exc}"
            ) from exc

    async def close(self) -> None:
        if self._credential is not None:
            await self._credential.close()
            self._credential = None


# ── Cross-Tenant (Key Vault-backed) ──────────────────────────────────────────


class CrossTenantCredentialProvider:
    """Authenticates to customer Azure subscriptions.

    Flow:
    1. Use the platform credential to call Key Vault.
    2. Fetch the subscription's SP JSON secret  (tenant_id, client_id, client_secret).
    3. Build a ClientSecretCredential for that external tenant.
    4. Cache the credential object keyed by subscription_id.

    Call invalidate_cache() to force re-read from Key Vault (e.g. after rotation).
    """

    def __init__(
        self,
        keyvault_uri: str,
        platform_provider: CredentialProvider,
    ) -> None:
        self._keyvault_uri = keyvault_uri
        self._platform_provider = platform_provider
        self._kv_client: SecretClient | None = None
        self._cache: dict[str, ClientSecretCredential] = {}
        self._sync_cache: dict[str, _SyncCredential] = {}

    async def _ensure_kv_client(self) -> SecretClient:
        if self._kv_client is None:
            platform_cred = await self._platform_provider.get_credential()
            self._kv_client = SecretClient(
                vault_url=self._keyvault_uri,
                credential=platform_cred,
            )
        return self._kv_client

    async def get_credential_for_subscription(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
    ) -> ClientSecretCredential:
        cache_key = str(subscription_id)
        if cache_key in self._cache:
            return self._cache[cache_key]

        kv = await self._ensure_kv_client()

        try:
            secret = await kv.get_secret(keyvault_secret_name)
        except Exception as exc:
            raise KeyVaultAccessError(secret_name=keyvault_secret_name, reason=str(exc)) from exc

        try:
            sp_config = _parse_sp_secret(secret.value or "", secret_name=keyvault_secret_name)
        except ValueError as exc:
            raise CrossTenantAuthError(
                subscription_id=subscription_id,
                reason=str(exc),
            ) from exc

        required = {"tenant_id", "client_id", "client_secret"}
        missing = required - sp_config.keys()
        if missing:
            raise CrossTenantAuthError(
                subscription_id=subscription_id,
                reason=f"Key Vault secret '{keyvault_secret_name}' is missing required fields: {missing}",  # noqa: E501
            )

        try:
            cred = _SyncClientSecretCredential(
                tenant_id=sp_config["tenant_id"],
                client_id=sp_config["client_id"],
                client_secret=sp_config["client_secret"],
            )
        except Exception as exc:
            raise CrossTenantAuthError(
                subscription_id=subscription_id,
                reason=f"Failed to construct cross-tenant credential: {exc}",
            ) from exc

        self._cache[cache_key] = cred
        _logger.info(
            "auth.cross_tenant.credential.cached",
            subscription_id=str(subscription_id),
        )
        return cred

    async def get_sync_credential_for_subscription(
        self,
        subscription_id: uuid.UUID,
        keyvault_secret_name: str,
    ) -> _SyncCredential:
        """Return a SYNC credential for the subscription's service principal.

        Use when passing credentials to sync Azure management SDK clients (the
        non-aio variants). The sync pipeline policy calls credential.get_token()
        synchronously; an async credential would return a coroutine instead of
        AccessToken, causing AttributeError: 'coroutine' object has no attribute
        'token'. A sync credential returns AccessToken directly.
        """
        cache_key = str(subscription_id)
        if cache_key in self._sync_cache:
            return self._sync_cache[cache_key]

        kv = await self._ensure_kv_client()

        try:
            secret = await kv.get_secret(keyvault_secret_name)
        except Exception as exc:
            raise KeyVaultAccessError(secret_name=keyvault_secret_name, reason=str(exc)) from exc

        try:
            sp_config = _parse_sp_secret(secret.value or "", secret_name=keyvault_secret_name)
        except ValueError as exc:
            raise CrossTenantAuthError(
                subscription_id=subscription_id,
                reason=str(exc),
            ) from exc

        required = {"tenant_id", "client_id", "client_secret"}
        missing = required - sp_config.keys()
        if missing:
            raise CrossTenantAuthError(
                subscription_id=subscription_id,
                reason=f"Key Vault secret '{keyvault_secret_name}' is missing required fields: {missing}",  # noqa: E501
            )

        try:
            cred = _SyncCredential(
                tenant_id=sp_config["tenant_id"],
                client_id=sp_config["client_id"],
                client_secret=sp_config["client_secret"],
            )
        except Exception as exc:
            raise CrossTenantAuthError(
                subscription_id=subscription_id,
                reason=f"Failed to construct sync cross-tenant credential: {exc}",
            ) from exc

        self._sync_cache[cache_key] = cred
        _logger.info(
            "auth.cross_tenant.sync_credential.cached",
            subscription_id=str(subscription_id),
        )
        return cred

    async def invalidate_cache(self, subscription_id: uuid.UUID) -> None:
        cache_key = str(subscription_id)
        cred = self._cache.pop(cache_key, None)
        if cred is not None:
            await cred.close()
            _logger.info(
                "auth.cross_tenant.credential.evicted",
                subscription_id=str(subscription_id),
            )
        # Sync credentials have no async close — just discard from cache.
        self._sync_cache.pop(cache_key, None)

    async def close(self) -> None:
        for cred in list(self._cache.values()):
            await cred.close()
        self._cache.clear()
        self._sync_cache.clear()
        if self._kv_client is not None:
            await self._kv_client.close()
            self._kv_client = None
        await self._platform_provider.close()


# ── DefaultAzureCredential (dev / CI) ────────────────────────────────────────


class _DefaultAzureCredentialProvider(CredentialProvider):
    def __init__(self) -> None:
        self._credential: DefaultAzureCredential | None = None

    async def get_credential(self) -> DefaultAzureCredential:
        if self._credential is None:
            self._credential = DefaultAzureCredential()
        return self._credential

    async def get_token(self, *scopes: str) -> AccessToken:
        cred = await self.get_credential()
        try:
            return await cred.get_token(*scopes)
        except Exception as exc:
            raise CredentialUnavailableError(f"DefaultAzureCredential failed: {exc}") from exc

    async def close(self) -> None:
        if self._credential is not None:
            await self._credential.close()
            self._credential = None


# ── Factory ───────────────────────────────────────────────────────────────────


def create_platform_provider(config: PlatformAuthConfig) -> CredentialProvider:
    """Return the correct platform credential provider for the given auth mode."""
    if config.mode == AuthMode.MANAGED_IDENTITY:
        return ManagedIdentityCredentialProvider(client_id=config.managed_identity.client_id)

    if config.mode == AuthMode.WORKLOAD_IDENTITY:
        if config.workload_identity is None:
            raise ValueError("workload_identity config is required for WORKLOAD_IDENTITY mode")
        wi = config.workload_identity
        return WorkloadIdentityCredentialProvider(
            tenant_id=wi.tenant_id,
            client_id=wi.client_id,
            token_file_path=wi.token_file_path,
        )

    if config.mode == AuthMode.SERVICE_PRINCIPAL:
        if config.service_principal is None:
            raise ValueError("service_principal config is required for SERVICE_PRINCIPAL mode")
        sp = config.service_principal
        return ServicePrincipalCredentialProvider(
            tenant_id=sp.tenant_id,
            client_id=sp.client_id,
            client_secret=sp.client_secret,
            client_secret_path=sp.client_secret_path,
            certificate_path=sp.certificate_path,
        )

    if config.mode == AuthMode.DEFAULT_CHAIN:
        return _DefaultAzureCredentialProvider()

    raise ValueError(f"Unknown auth mode: {config.mode!r}")
