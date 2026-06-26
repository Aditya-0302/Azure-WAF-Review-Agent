"""Service layer dependency factories — injected into routers via Depends()."""

from __future__ import annotations

from dependency_injector.wiring import Provide, inject
from fastapi import Depends, Request

from waf_api.container import Container
from waf_api.dependencies.db import get_db_pool
from waf_shared.auth.auth_service import AuthenticationService
from waf_shared.db.pool import DatabasePool


def get_assessment_service(
    request: Request,
    pool: DatabasePool = Depends(get_db_pool),
) -> AssessmentService:  # type: ignore[name-defined]
    from waf_api.services.assessment_service import AssessmentService

    return AssessmentService(pool=pool, publisher=request.app.state.publisher)


def get_tenant_service(
    pool: DatabasePool = Depends(get_db_pool),
) -> TenantService:  # type: ignore[name-defined]
    from waf_api.services.tenant_service import TenantService

    return TenantService(pool=pool)


def get_quota_service(
    pool: DatabasePool = Depends(get_db_pool),
) -> QuotaService:  # type: ignore[name-defined]
    from waf_api.services.quota_service import QuotaService

    return QuotaService(pool=pool)


@inject
def get_auth_service(
    auth_service: AuthenticationService = Provide[Container.auth_service],
) -> AuthenticationService:
    return auth_service


def get_credential_service(
    pool: DatabasePool = Depends(get_db_pool),
    auth_service: AuthenticationService = Depends(get_auth_service),
) -> CredentialService:  # type: ignore[name-defined]
    from waf_api.services.credential_service import CredentialService

    return CredentialService(pool=pool, auth_service=auth_service)


@inject
def get_discovery_service(
    discovery_service: DiscoveryService = Provide[Container.discovery_service],  # type: ignore[name-defined]
) -> DiscoveryService:  # type: ignore[name-defined]
    return discovery_service
