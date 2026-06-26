"""Application configuration — all values come from environment variables or mounted secrets.

Never read os.environ directly outside this module.
"""

from __future__ import annotations

import os
import sys
from enum import StrEnum
from typing import Any

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Load .env in normal runtime (uvicorn, python -m). Skip it when running under
# pytest so test assertions on default field values are not overridden by a
# developer's local .env file. WAF_NO_DOTENV=1 provides an explicit CI escape hatch.
_env_file: str | None = None if ("pytest" in sys.modules or os.getenv("WAF_NO_DOTENV")) else ".env"


class AppEnvironment(StrEnum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class LogLevel(StrEnum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_env_file,
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_env: AppEnvironment = AppEnvironment.DEVELOPMENT
    app_version: str = "0.1.0"
    log_level: LogLevel = LogLevel.INFO

    # API Server
    # Bind to all interfaces so Kubernetes pod-to-pod routing works.
    # Network-level isolation is enforced by AKS NetworkPolicy (default-deny).
    api_host: str = "0.0.0.0"  # noqa: S104  # nosec B104 — AKS pod networking requires binding all interfaces; isolation via NetworkPolicy
    api_port: int = 8000
    api_workers: int = 1

    # PostgreSQL
    db_host: str = "localhost"
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = "wafagent"
    db_user: str = "wafagent"
    db_password: SecretStr = SecretStr("changeme")
    db_pool_min_size: int = Field(default=2, ge=1)
    db_pool_max_size: int = Field(default=10, ge=1)
    # Leave empty to disable the read replica (single-instance local dev).
    # Set to the actual replica host in staging/production.
    db_readonly_host: str = ""
    db_readonly_port: int = Field(default=5432, ge=1, le=65535)

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_max_connections: int = Field(default=20, ge=1)

    # Azure Service Bus
    servicebus_namespace: str = ""
    servicebus_connection_string: SecretStr | None = None

    # Azure OpenAI
    azure_openai_endpoint: str = ""
    azure_openai_deployment_chat: str = "gpt-4o-2024-05-13"
    azure_openai_deployment_embedding: str = "text-embedding-3-large-2024-07-01"
    azure_openai_api_version: str = "2024-05-01-preview"
    azure_openai_max_tokens: int = Field(default=4096, ge=1)

    # Azure Key Vault
    keyvault_uri: str = ""

    # Azure AI Search
    search_endpoint: str = ""
    search_index_name: str = "waf-knowledge-v1"

    # Azure AD / Entra ID
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    # Required when auth_mode=default_chain: EnvironmentCredential is the only
    # DefaultAzureCredential source available inside Docker (no CLI, no MI).
    azure_client_secret: SecretStr | None = None
    jwt_audience: str = "api://waf-agent-api"
    # Auth mode: managed_identity | workload_identity | service_principal | default_chain
    auth_mode: str = "managed_identity"
    # Service principal secret path (CSI mount) — only used when auth_mode=service_principal
    sp_client_secret_path: str = ""

    # Azure Storage
    storage_account_name: str = ""
    storage_reports_container: str = "reports"
    storage_audit_container: str = "audit-exports"

    # Telemetry
    applicationinsights_connection_string: SecretStr | None = None
    otel_service_name: str = "waf-api"
    otel_exporter_enabled: bool = False

    # Feature flags
    quota_enforcement_enabled: bool = True
    webhook_signing_enabled: bool = True

    # API authentication mode.
    # "entra"       — validate Azure AD JWTs (default, production behavior).
    # "development" — skip JWT validation; inject a synthetic PLATFORM_ADMIN
    #                 AuthContext on every request.  Never use in production.
    api_auth_mode: str = "entra"

    @field_validator("api_auth_mode")
    @classmethod
    def valid_api_auth_mode(cls, v: str) -> str:
        allowed = {"entra", "development"}
        if v not in allowed:
            raise ValueError(f"API_AUTH_MODE must be one of {sorted(allowed)}, got '{v}'")
        return v

    @field_validator("db_pool_max_size")
    @classmethod
    def max_must_exceed_min(cls, v: int, info: Any) -> int:  # type: ignore[misc]
        min_size = info.data.get("db_pool_min_size", 2)
        if v < min_size:
            raise ValueError(f"db_pool_max_size ({v}) must be >= db_pool_min_size ({min_size})")
        return v

    @model_validator(mode="after")
    def guard_production_defaults(self) -> Settings:
        # DefaultAzureCredential inside Docker has no CLI or Managed Identity
        # available — EnvironmentCredential is the only working source, which
        # requires AZURE_CLIENT_SECRET.  Fail fast before any network call.
        if self.auth_mode == "default_chain" and (
            self.azure_client_secret is None or not self.azure_client_secret.get_secret_value()
        ):
            raise ValueError(
                "AZURE_CLIENT_SECRET is required when AUTH_MODE=default_chain. "
                "DefaultAzureCredential relies on EnvironmentCredential inside Docker "
                "(no Azure CLI or Managed Identity available). "
                "Set AZURE_CLIENT_SECRET in docker-compose.dev.yml via the "
                "x-azure-auth-env anchor or add it to your .env file."
            )

        # Staging and production both require real JWT validation.
        # Failing fast here prevents a misconfigured server from silently
        # bypassing authentication — the process refuses to start rather than
        # serving unauthenticated requests.
        if self.app_env in (AppEnvironment.PRODUCTION, AppEnvironment.STAGING):
            if self.api_auth_mode == "development":
                raise ValueError(
                    f"API_AUTH_MODE=development is not permitted when "
                    f"APP_ENV={self.app_env.value}. "
                    "Set API_AUTH_MODE=entra for staging and production deployments."
                )
        if self.app_env == AppEnvironment.PRODUCTION:
            if self.db_password.get_secret_value() in ("changeme", "", "password"):
                raise ValueError(
                    "db_password must be set to a secure value in production; "
                    "current value matches a known default. "
                    "Set the DB_PASSWORD environment variable or CSI mount."
                )
            if not self.azure_tenant_id:
                raise ValueError("azure_tenant_id must be set in production")
            if not self.keyvault_uri:
                raise ValueError("keyvault_uri must be set in production")
            if not self.servicebus_namespace:
                raise ValueError("servicebus_namespace must be set in production")
        return self

    @property
    def db_dsn_primary(self) -> str:
        return (
            f"postgresql://{self.db_user}:{self.db_password.get_secret_value()}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )

    @property
    def db_dsn_readonly(self) -> str | None:
        if not self.db_readonly_host:
            return None
        return (
            f"postgresql://{self.db_user}:{self.db_password.get_secret_value()}"
            f"@{self.db_readonly_host}:{self.db_readonly_port}/{self.db_name}"
        )

    @property
    def is_production(self) -> bool:
        return self.app_env == AppEnvironment.PRODUCTION
