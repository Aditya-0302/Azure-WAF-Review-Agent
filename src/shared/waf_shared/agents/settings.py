"""Shared base settings for all WAF Agent workers.

All platform-level variables (DB_*, SERVICEBUS_NAMESPACE, KEYVAULT_URI, etc.)
are read from the same environment variables as the API server, so a single
.env file in the project root covers every component in local development.

Subclass AgentSettings and add only agent-specific knobs.  Never duplicate
a platform variable with a new name or prefix.
"""

from __future__ import annotations

import os
import sys

from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_env_file: str | None = None if ("pytest" in sys.modules or os.getenv("WAF_NO_DOTENV")) else ".env"


class AgentSettings(BaseSettings):
    """Platform settings shared by all WAF Agent workers.

    Reads from the same unprefixed env vars as waf_api.config.Settings.
    Provides dsn_primary / dsn_readonly computed properties so DatabasePool
    can be constructed without passing raw DSN strings via environment.
    """

    model_config = SettingsConfigDict(
        env_file=_env_file,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── PostgreSQL ─────────────────────────────────────────────────────────────
    db_host: str = "localhost"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "wafagent"
    db_user: str = "wafagent"
    db_password: SecretStr = SecretStr("changeme")
    db_pool_min_size: int = Field(default=2, ge=1)
    db_pool_max_size: int = Field(default=10, ge=1)
    # Empty = no read replica; DatabasePool.acquire_read() falls back to primary.
    db_readonly_host: str = ""
    db_readonly_port: int = Field(default=5432, ge=1, le=65535)

    # ── Authentication ─────────────────────────────────────────────────────────
    # Use "default_chain" for local dev (DefaultAzureCredential).
    # Use "managed_identity" or "workload_identity" in AKS/ACI.
    auth_mode: str = "managed_identity"

    # Azure AD — forwarded to DefaultAzureCredential and used by cross-tenant
    # credential lookup. Required in all environments.
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    # Required when auth_mode=default_chain: EnvironmentCredential is the only
    # DefaultAzureCredential source available inside Docker (no CLI, no MI).
    azure_client_secret: SecretStr | None = None

    # ── Azure Service Bus ──────────────────────────────────────────────────────
    servicebus_namespace: str = ""
    # Set in local dev / CI when connecting to the emulator via connection string.
    servicebus_connection_string: SecretStr | None = None

    # ── Azure Key Vault ────────────────────────────────────────────────────────
    keyvault_uri: str = ""

    # ── Telemetry ──────────────────────────────────────────────────────────────
    applicationinsights_connection_string: SecretStr | None = None
    otel_exporter_enabled: bool = False

    @model_validator(mode="after")
    def require_azure_config(self) -> AgentSettings:
        missing: list[str] = []
        if not self.keyvault_uri:
            missing.append("KEYVAULT_URI")
        if not self.azure_tenant_id:
            missing.append("AZURE_TENANT_ID")
        if not self.azure_client_id:
            missing.append("AZURE_CLIENT_ID")
        if self.auth_mode == "default_chain" and (
            self.azure_client_secret is None or not self.azure_client_secret.get_secret_value()
        ):
            missing.append("AZURE_CLIENT_SECRET")
        if missing:
            raise ValueError(
                f"Missing required Azure configuration: {', '.join(missing)}. "
                "These must be set in the container environment. "
                "In docker-compose.dev.yml each agent service must declare "
                "KEYVAULT_URI, AZURE_TENANT_ID, AZURE_CLIENT_ID, and "
                "(when AUTH_MODE=default_chain) AZURE_CLIENT_SECRET using "
                "${VAR:-} syntax so Compose forwards them from .env."
            )
        return self

    @property
    def dsn_primary(self) -> str:
        return (
            f"postgresql://{self.db_user}:{self.db_password.get_secret_value()}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def dsn_readonly(self) -> str | None:
        """None when DB_READONLY_HOST is unset; DatabasePool falls back to primary."""
        if not self.db_readonly_host:
            return None
        return (
            f"postgresql://{self.db_user}:{self.db_password.get_secret_value()}"
            f"@{self.db_readonly_host}:{self.db_readonly_port}/{self.db_name}"
        )
