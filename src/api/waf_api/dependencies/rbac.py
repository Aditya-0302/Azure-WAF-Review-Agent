"""RBAC dependency factory — require_role() enforces caller role before handler runs."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import Depends, HTTPException, Request

from waf_shared.domain.models.tenant import UserRole
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")


def get_auth_context(request: Request) -> "AuthContext":  # type: ignore[name-defined]
    """Extract the auth context populated by AuthMiddleware.

    Raises 401 if auth middleware did not populate request.state.auth,
    which should never happen in production (middleware rejects before reaching here).
    """
    from waf_api.middleware.auth import AuthContext

    auth = getattr(request.state, "auth", None)
    if auth is None:
        raise HTTPException(status_code=401, detail="Authentication required")
    return auth  # type: ignore[return-value]


def require_role(*roles: UserRole) -> Callable:
    """Dependency factory. Returns a Depends-compatible function that enforces role membership.

    Usage:
        @router.post("/tenants", dependencies=[Depends(require_role(UserRole.PLATFORM_ADMIN))])
    """
    allowed: frozenset[UserRole] = frozenset(roles)

    def _check(
        auth: "AuthContext" = Depends(get_auth_context),  # type: ignore[name-defined]
    ) -> "AuthContext":  # type: ignore[name-defined]
        if auth.role not in allowed:
            _logger.warning(
                "auth.role.denied",
                required_roles=[r.value for r in allowed],
                actual_role=auth.role.value,
                tenant_id=str(auth.tenant_id),
            )
            raise HTTPException(
                status_code=403,
                detail=f"Role '{auth.role}' is not permitted for this operation",
            )
        return auth

    return _check
