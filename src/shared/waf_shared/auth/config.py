"""Authentication configuration models.

Never store secrets in these models. Secrets arrive via CSI mounts or Key Vault.
"""

from __future__ import annotations

from enum import StrEnum
from pathlib import Path

from pydantic import BaseModel, Field


class AuthMode(StrEnum):
    MANAGED_IDENTITY = "managed_identity"
    WORKLOAD_IDENTITY = "workload_identity"
    SERVICE_PRINCIPAL = "service_principal"
    DEFAULT_CHAIN = "default_chain"  # DefaultAzureCredential — dev / CI only


class ManagedIdentityConfig(BaseModel):
    """User-Assigned Managed Identity config. client_id=None → System-assigned."""

    client_id: str | None = None


class WorkloadIdentityConfig(BaseModel):
    """AKS Workload Identity (OIDC federation) config."""

    client_id: str
    tenant_id: str
    token_file_path: Path = Path(
        "/var/run/secrets/azure/tokens/azure-identity-token"
    )


class ServicePrincipalConfig(BaseModel):
    """Service Principal config.

    The secret / certificate is read from a mounted file, never from an env var.
    client_secret is excluded from all serialisation so it is never logged.
    """

    client_id: str
    tenant_id: str
    client_secret_path: Path | None = None
    certificate_path: Path | None = None
    client_secret: str | None = Field(default=None, exclude=True)


class PlatformAuthConfig(BaseModel):
    """Top-level authentication configuration for the platform service."""

    mode: AuthMode = AuthMode.MANAGED_IDENTITY
    managed_identity: ManagedIdentityConfig = ManagedIdentityConfig()
    workload_identity: WorkloadIdentityConfig | None = None
    service_principal: ServicePrincipalConfig | None = None

    # Well-known OAuth2 resource scopes
    arm_scope: str = "https://management.azure.com/.default"
    keyvault_scope: str = "https://vault.azure.net/.default"
    graph_scope: str = "https://graph.microsoft.com/.default"
