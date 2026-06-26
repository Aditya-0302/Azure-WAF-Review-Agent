"""IoC container — wires all dependencies using dependency-injector.

Consumers use FastAPI's Depends() with Provide[Container.*] for injection.
The container is initialised once during application startup in main.py.
"""

from __future__ import annotations

from dependency_injector import containers, providers

from waf_api.config import Settings
from waf_shared.auth.auth_service import AuthenticationService
from waf_shared.auth.config import (
    AuthMode,
    ManagedIdentityConfig,
    PlatformAuthConfig,
    ServicePrincipalConfig,
)
from waf_shared.auth.credential_provider import (
    CrossTenantCredentialProvider,
    create_platform_provider,
)
from waf_shared.auth.token_provider import TokenProvider
from waf_shared.db.pool import DatabasePool
from waf_shared.discovery.config import DiscoveryConfig
from waf_shared.discovery.metrics import DiscoveryMetrics
from waf_shared.telemetry.logging import StructuredLogger
from waf_shared.telemetry.metrics import WafMetrics


def _create_discovery_service(
    auth_service: AuthenticationService,
    config: DiscoveryConfig,
    metrics: DiscoveryMetrics,
) -> object:
    from waf_api.services.discovery_service import DiscoveryService

    return DiscoveryService(auth_service=auth_service, config=config, metrics=metrics)


def _build_platform_auth_config(settings: Settings) -> PlatformAuthConfig:
    """Construct PlatformAuthConfig from application Settings."""
    mode = AuthMode(settings.auth_mode)

    sp_config = None
    if mode == AuthMode.SERVICE_PRINCIPAL and settings.sp_client_secret_path:
        from pathlib import Path

        sp_config = ServicePrincipalConfig(
            client_id=settings.azure_client_id,
            tenant_id=settings.azure_tenant_id,
            client_secret_path=Path(settings.sp_client_secret_path),
        )

    return PlatformAuthConfig(
        mode=mode,
        managed_identity=ManagedIdentityConfig(client_id=settings.azure_client_id or None),
        service_principal=sp_config,
    )


class Container(containers.DeclarativeContainer):
    wiring_config = containers.WiringConfiguration(
        modules=[
            "waf_api.dependencies.db",
            "waf_api.dependencies.rbac",
            "waf_api.dependencies.services",
            "waf_api.routers.health",
        ]
    )

    # ── Configuration ────────────────────────────────────────────────────────
    config = providers.Singleton(Settings)

    # ── Telemetry ────────────────────────────────────────────────────────────
    logger = providers.Singleton(
        StructuredLogger,
        service="waf-api",
        version=config.provided.app_version,
    )

    metrics = providers.Singleton(WafMetrics)

    # ── Database ─────────────────────────────────────────────────────────────
    db_pool = providers.Singleton(
        DatabasePool,
        dsn_primary=config.provided.db_dsn_primary,
        dsn_readonly=config.provided.db_dsn_readonly,
        min_size=config.provided.db_pool_min_size,
        max_size=config.provided.db_pool_max_size,
    )

    # ── Authentication ────────────────────────────────────────────────────────
    platform_auth_config = providers.Singleton(
        _build_platform_auth_config,
        settings=config,
    )

    platform_credential_provider = providers.Singleton(
        create_platform_provider,
        config=platform_auth_config,
    )

    cross_tenant_provider = providers.Singleton(
        CrossTenantCredentialProvider,
        keyvault_uri=config.provided.keyvault_uri,
        platform_provider=platform_credential_provider,
    )

    token_provider = providers.Singleton(
        TokenProvider,
        platform_provider=platform_credential_provider,
        cross_tenant_provider=cross_tenant_provider,
        config=platform_auth_config,
    )

    auth_service = providers.Singleton(
        AuthenticationService,
        token_provider=token_provider,
        cross_tenant_provider=cross_tenant_provider,
    )

    # ── Discovery ─────────────────────────────────────────────────────────────
    discovery_config = providers.Singleton(DiscoveryConfig)

    discovery_metrics = providers.Singleton(DiscoveryMetrics)

    discovery_service = providers.Singleton(
        _create_discovery_service,
        auth_service=auth_service,
        config=discovery_config,
        metrics=discovery_metrics,
    )
