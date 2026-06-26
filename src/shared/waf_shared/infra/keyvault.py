"""Key Vault client wrapper — thin async facade over azure-keyvault-secrets.

All callers use Managed Identity via the platform credential; no API keys.
Secret values are returned as strings; callers that need bytes must encode.

Webhook secrets are stored in Key Vault per-tenant.
Never log or persist secret values.
"""

from __future__ import annotations

from typing import Any

from azure.keyvault.secrets.aio import SecretClient

from waf_shared.domain.errors.infrastructure_errors import KeyVaultAccessError


class KeyVaultClient:
    """Async Key Vault secret reader backed by Managed Identity."""

    def __init__(self, vault_uri: str, credential: Any) -> None:
        self._client = SecretClient(vault_url=vault_uri, credential=credential)

    async def get_secret(self, name: str) -> str:
        """Fetch a secret value. Raises KeyVaultAccessError on any failure."""
        try:
            secret = await self._client.get_secret(name)
            if secret.value is None:
                raise KeyVaultAccessError(name, "secret value is null")
            return secret.value
        except KeyVaultAccessError:
            raise
        except Exception as exc:
            raise KeyVaultAccessError(name, str(exc)) from exc

    async def close(self) -> None:
        await self._client.close()
