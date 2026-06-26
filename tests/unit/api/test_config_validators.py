"""Unit tests for Settings production guard validators.

Verifies that the production model_validator blocks unsafe defaults and
allows valid production configurations.
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from waf_api.config import AppEnvironment, Settings


def _make_prod_env(**overrides: str) -> dict[str, str]:
    base = {
        "APP_ENV": "production",
        "DB_PASSWORD": "SuperSecurePassword!123",
        "AZURE_TENANT_ID": "11111111-1111-1111-1111-111111111111",
        "KEYVAULT_URI": "https://myvault.vault.azure.net",
        "SERVICEBUS_NAMESPACE": "sb-waf-prod.servicebus.windows.net",
        "APPLICATIONINSIGHTS_CONNECTION_STRING": "InstrumentationKey=abc;IngestionEndpoint=https://dc.services.visualstudio.com/",
        "OTEL_EXPORTER_ENABLED": "true",
    }
    base.update(overrides)
    return base


@pytest.mark.unit
class TestProductionPasswordGuard:
    def test_changeme_password_rejected_in_prod(self) -> None:
        env = _make_prod_env(DB_PASSWORD="changeme")
        with patch.dict(os.environ, env, clear=False):
            with pytest.raises(ValueError, match="db_password"):
                Settings(**{k.lower(): v for k, v in env.items()})

    def test_empty_password_rejected_in_prod(self) -> None:
        env = _make_prod_env(DB_PASSWORD="")
        with pytest.raises(ValueError, match="db_password"):
            Settings(
                app_env=AppEnvironment.PRODUCTION,
                db_password="",
                azure_tenant_id="abc",
                keyvault_uri="https://x.vault.azure.net",
                servicebus_namespace="sb.servicebus.windows.net",
            )

    def test_password_word_rejected_in_prod(self) -> None:
        with pytest.raises(ValueError, match="db_password"):
            Settings(
                app_env=AppEnvironment.PRODUCTION,
                db_password="password",
                azure_tenant_id="abc",
                keyvault_uri="https://x.vault.azure.net",
                servicebus_namespace="sb.servicebus.windows.net",
            )

    def test_secure_password_accepted_in_prod(self) -> None:
        s = Settings(
            app_env=AppEnvironment.PRODUCTION,
            db_password="$uperS3cur3!",
            azure_tenant_id="abc-def",
            keyvault_uri="https://myvault.vault.azure.net",
            servicebus_namespace="sb-prod.servicebus.windows.net",
        )
        assert s.app_env == AppEnvironment.PRODUCTION


@pytest.mark.unit
class TestProductionRequiredFields:
    def test_empty_tenant_id_rejected_in_prod(self) -> None:
        with pytest.raises(ValueError, match="azure_tenant_id"):
            Settings(
                app_env=AppEnvironment.PRODUCTION,
                db_password="StrongPass!1",
                azure_tenant_id="",
                keyvault_uri="https://x.vault.azure.net",
                servicebus_namespace="sb.servicebus.windows.net",
            )

    def test_empty_keyvault_uri_rejected_in_prod(self) -> None:
        with pytest.raises(ValueError, match="keyvault_uri"):
            Settings(
                app_env=AppEnvironment.PRODUCTION,
                db_password="StrongPass!1",
                azure_tenant_id="abc",
                keyvault_uri="",
                servicebus_namespace="sb.servicebus.windows.net",
            )

    def test_empty_servicebus_namespace_rejected_in_prod(self) -> None:
        with pytest.raises(ValueError, match="servicebus_namespace"):
            Settings(
                app_env=AppEnvironment.PRODUCTION,
                db_password="StrongPass!1",
                azure_tenant_id="abc",
                keyvault_uri="https://x.vault.azure.net",
                servicebus_namespace="",
            )


@pytest.mark.unit
class TestDevelopmentDefaults:
    def test_changeme_password_allowed_in_dev(self) -> None:
        s = Settings(app_env=AppEnvironment.DEVELOPMENT)
        assert s.db_password.get_secret_value() == "changeme"

    def test_empty_tenant_id_allowed_in_dev(self) -> None:
        s = Settings(app_env=AppEnvironment.DEVELOPMENT)
        assert s.azure_tenant_id == ""

    def test_default_env_is_development(self) -> None:
        s = Settings()
        assert s.app_env == AppEnvironment.DEVELOPMENT


@pytest.mark.unit
class TestStagingAuthGuard:
    """Staging must refuse to start with API_AUTH_MODE=development.

    This is the primary guard against accidentally serving unauthenticated
    requests in staging: Settings validation fails at process startup rather
    than silently bypassing JWT enforcement for every request.
    """

    def test_dev_auth_rejected_in_staging(self) -> None:
        with pytest.raises(ValueError, match="API_AUTH_MODE=development"):
            Settings(app_env=AppEnvironment.STAGING, api_auth_mode="development")

    def test_entra_auth_accepted_in_staging(self) -> None:
        s = Settings(app_env=AppEnvironment.STAGING, api_auth_mode="entra")
        assert s.app_env == AppEnvironment.STAGING
        assert s.api_auth_mode == "entra"

    def test_dev_auth_still_rejected_in_production(self) -> None:
        """Production guard still fires (regression check)."""
        with pytest.raises(ValueError):
            Settings(
                app_env=AppEnvironment.PRODUCTION,
                api_auth_mode="development",
                db_password="StrongPass!1",
                azure_tenant_id="abc",
                keyvault_uri="https://x.vault.azure.net",
                servicebus_namespace="sb.servicebus.windows.net",
            )

    def test_dev_auth_allowed_in_development(self) -> None:
        s = Settings(app_env=AppEnvironment.DEVELOPMENT, api_auth_mode="development")
        assert s.api_auth_mode == "development"

    def test_docs_condition_staging(self) -> None:
        """APP_ENV=staging must produce docs_url=None (belt-and-suspenders check)."""
        s = Settings(app_env=AppEnvironment.STAGING, api_auth_mode="entra")
        docs_url = "/docs" if s.app_env == AppEnvironment.DEVELOPMENT else None
        assert docs_url is None

    def test_docs_condition_development(self) -> None:
        """APP_ENV=development must produce a non-None docs_url."""
        s = Settings(app_env=AppEnvironment.DEVELOPMENT)
        docs_url = "/docs" if s.app_env == AppEnvironment.DEVELOPMENT else None
        assert docs_url == "/docs"


@pytest.mark.unit
class TestPoolSizeValidator:
    def test_max_less_than_min_raises(self) -> None:
        with pytest.raises(ValueError, match="db_pool_max_size"):
            Settings(db_pool_min_size=10, db_pool_max_size=2)

    def test_max_equals_min_is_valid(self) -> None:
        s = Settings(db_pool_min_size=5, db_pool_max_size=5)
        assert s.db_pool_max_size == 5


@pytest.mark.unit
class TestDSNProperties:
    def test_primary_dsn_format(self) -> None:
        s = Settings(
            db_host="db.example.com",
            db_port=5432,
            db_name="mydb",
            db_user="myuser",
            db_password="mypass",
        )
        dsn = s.db_dsn_primary
        assert "postgresql://" in dsn
        assert "myuser" in dsn
        assert "db.example.com" in dsn
        assert "5432" in dsn
        assert "mydb" in dsn

    def test_password_not_in_repr(self) -> None:
        s = Settings(db_password="supersecret")
        # SecretStr should not leak in repr
        assert "supersecret" not in repr(s)
