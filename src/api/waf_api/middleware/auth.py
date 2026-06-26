"""JWT authentication middleware — validate token, resolve tenant_id + role.

Every request passes through this middleware before reaching a route handler.
Unauthenticated requests are rejected with 401. The middleware populates
request.state.auth so that downstream dependencies can trust the values
without re-validating.

Public paths (health checks) are exempt from authentication.

Development mode (API_AUTH_MODE=development):
  JWT validation is skipped entirely. A synthetic AuthContext with fixed
  UUIDs and PLATFORM_ADMIN role is injected on every request so routes
  function without credentials. This mode is forbidden when APP_ENV=production
  (enforced at Settings validation time, before the process starts).
"""

from __future__ import annotations

import time
import uuid
from typing import Any

import httpx
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from waf_api.config import Settings
from waf_shared.auth.models import AuthContext  # noqa: F401 — re-exported for importers
from waf_shared.db.repositories.tenant_repository import TenantRepository
from waf_shared.domain.models.tenant import UserRole
from waf_shared.telemetry.logging import StructuredLogger

_logger = StructuredLogger(service="waf-api", version="0.1.0")

# Synthetic identity injected when API_AUTH_MODE=development.
_DEV_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")
_DEV_USER_ID = uuid.UUID("00000000-0000-0000-0000-000000000002")
_DEV_AUTH_CONTEXT = AuthContext(
    tenant_id=_DEV_TENANT_ID,
    user_id=_DEV_USER_ID,
    role=UserRole.PLATFORM_ADMIN,
    entra_oid=_DEV_USER_ID,
)

_PUBLIC_PATHS: frozenset[str] = frozenset({"/healthz", "/readyz", "/metrics"})

# Swagger/OpenAPI paths are explicitly blocked with 404 in entra mode.
# FastAPI sets docs_url/redoc_url/openapi_url=None for staging/production, so
# these routes don't exist — the middleware returns 404 to match that semantics
# and to prevent serving docs if docs_url is ever accidentally re-enabled in main.py.
_DEV_PUBLIC_PATHS: frozenset[str] = frozenset({"/docs", "/redoc", "/openapi.json"})

# JWKS cache: key → (jwks_dict, expiry_epoch_seconds).
# TTL of 3600 s keeps tokens verifiable after key rotation events while ensuring
# the process picks up new keys within 1 hour (Azure rotates ~every 6 weeks).
# Max 50 entries prevents a DoS via fabricated tid values.
_JWKS_CACHE: dict[str, tuple[dict[str, Any], float]] = {}
_JWKS_TTL_SECONDS: float = 3600.0
_JWKS_MAX_ENTRIES: int = 50


async def _http_get_jwks(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(url)
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]


class _JwksCache:
    """Per-instance JWKS cache with TTL expiry and capacity-bounded eviction.

    Replaces the module-level ``_JWKS_CACHE`` dict for callers that need
    isolated cache state (e.g. tests).  The module-level ``_fetch_jwks``
    continues to use ``_JWKS_CACHE`` for backward compatibility.
    """

    def __init__(
        self,
        ttl_seconds: float = _JWKS_TTL_SECONDS,
        max_entries: int = _JWKS_MAX_ENTRIES,
    ) -> None:
        self._cache: dict[str, tuple[dict[str, Any], float]] = {}
        self._ttl = ttl_seconds
        self._max = max_entries

    async def get(self, url: str) -> dict[str, Any]:
        now = time.monotonic()
        entry = self._cache.get(url)
        if entry is not None:
            value, expires_at = entry
            if now < expires_at:
                return value
            del self._cache[url]
        if len(self._cache) >= self._max:
            oldest = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest]
        jwks = await _http_get_jwks(url)
        self._cache[url] = (jwks, now + self._ttl)
        return jwks


async def _resolve_tenant_id(
    *,
    claims: dict[str, Any],
    path_tenant_id: str | None,
    db_pool: Any,
) -> uuid.UUID:
    """Resolve the internal tenant UUID from JWT claims.

    Platform.Admin users get either the UUID from the path parameter or the
    zero UUID (cross-tenant sentinel) when no path param is present.
    All other roles perform a DB lookup by azure_tenant_id.

    Raises:
        ValueError: when the DB lookup finds no matching tenant.
    """
    roles: list[str] = claims.get("roles", [])
    if "Platform.Admin" in roles or "WafAgent.PlatformAdmin" in roles:
        if path_tenant_id:
            return uuid.UUID(path_tenant_id)
        return uuid.UUID(int=0)

    if db_pool is None:
        raise ValueError("db_pool is required for non-admin tenant resolution")

    azure_tid = claims.get("tid")
    async with db_pool.acquire_read() as conn:
        result = await conn.fetchval(
            "SELECT id FROM tenants WHERE azure_tenant_id = $1::uuid",
            azure_tid,
        )

    if result is None:
        raise ValueError(f"Tenant not found: azure_tenant_id={azure_tid}")

    return result if isinstance(result, uuid.UUID) else uuid.UUID(str(result))


async def _validate_claims(claims: dict[str, Any]) -> None:
    if not (claims.get("oid") or claims.get("sub")):
        raise ValueError("missing claim: oid")
    if not claims.get("tid"):
        raise ValueError("missing claim: tid")


async def _fetch_jwks(tenant_id: str) -> dict[str, Any]:
    cache_key = f"jwks:{tenant_id}"
    now = time.monotonic()
    entry = _JWKS_CACHE.get(cache_key)
    if entry is not None:
        cached_value, expires_at = entry
        if now < expires_at:
            return cached_value
        del _JWKS_CACHE[cache_key]

    if len(_JWKS_CACHE) >= _JWKS_MAX_ENTRIES:
        oldest_key = min(_JWKS_CACHE, key=lambda k: _JWKS_CACHE[k][1])
        del _JWKS_CACHE[oldest_key]

    oidc_url = f"https://login.microsoftonline.com/{tenant_id}/discovery/v2.0/keys"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(oidc_url)
        response.raise_for_status()
        jwks = response.json()
        _JWKS_CACHE[cache_key] = (jwks, now + _JWKS_TTL_SECONDS)
        return jwks  # type: ignore[no-any-return]


def _make_401(message: str, trace_id: str = "") -> JSONResponse:
    return JSONResponse(
        status_code=401,
        content={
            "error": {
                "code": "UNAUTHORIZED",
                "message": message,
                "detail": None,
                "trace_id": trace_id,
                "request_id": "",
            }
        },
    )


def _make_403(message: str) -> JSONResponse:
    return JSONResponse(
        status_code=403,
        content={
            "error": {
                "code": "FORBIDDEN",
                "message": message,
                "detail": None,
                "trace_id": "",
                "request_id": "",
            }
        },
    )


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any, settings: Settings) -> None:
        super().__init__(app)
        self._settings = settings
        # Both flags are computed once at startup; zero per-request overhead.
        self._dev_mode: bool = settings.api_auth_mode == "development"
        # In dev mode, doc paths are included as public so FastAPI can serve them.
        # In entra mode, dispatch() returns 404 for these paths explicitly (see below).
        self._public_paths = _PUBLIC_PATHS | (_DEV_PUBLIC_PATHS if self._dev_mode else frozenset())
        if self._dev_mode:
            _logger.warning(
                "auth.development_mode.enabled",
                warning="Development authentication enabled. "
                "All requests receive PLATFORM_ADMIN access. "
                "Never use in production.",
            )

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if request.url.path in self._public_paths:
            return await call_next(request)

        # ── Development mode: bypass JWT validation ───────────────────────────
        if self._dev_mode:
            request.state.auth = _DEV_AUTH_CONTEXT
            return await call_next(request)

        # ── Doc paths are disabled in staging/production (docs_url=None in main.py).
        # Return 404 to match FastAPI's route-not-found semantics and to prevent
        # serving docs unauthenticated if docs_url is ever accidentally re-enabled.
        if request.url.path in _DEV_PUBLIC_PATHS:
            return JSONResponse(status_code=404, content={"detail": "Not Found"})

        # ── Entra mode: full JWT validation ──────────────────────────────────
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            _logger.warning(
                "auth.token.validation.failed",
                reason="missing_bearer_token",
                path=request.url.path,
            )
            return _make_401("Authorization header with Bearer token is required")

        token = auth_header.removeprefix("Bearer ").strip()

        # Reject structurally invalid tokens before any network call.
        # get_unverified_claims() parses the JWT without verifying the signature;
        # it raises JWTError immediately for tokens that cannot be decoded at all
        # (wrong segment count, bad base64). We also extract the tid claim here so
        # the JWKS lookup targets the correct tenant even when azure_tenant_id is
        # not pre-configured (common in staging/CI environments).
        try:
            unverified = jwt.get_unverified_claims(token)
        except JWTError:
            _logger.warning(
                "auth.token.validation.failed",
                reason="malformed_token",
                path=request.url.path,
            )
            return _make_401("Invalid or expired token")

        tid_for_jwks = unverified.get("tid") or self._settings.azure_tenant_id
        if not tid_for_jwks:
            return _make_401("Token missing tid claim; cannot locate signing keys")

        try:
            jwks = await _fetch_jwks(tid_for_jwks)
            claims: dict[str, Any] = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=self._settings.jwt_audience,
                options={"verify_exp": True, "verify_aud": True},
            )
        except JWTError as exc:
            _logger.warning(
                "auth.token.validation.failed",
                reason=str(exc),
                path=request.url.path,
            )
            return _make_401("Invalid or expired token")
        except httpx.HTTPError:
            _logger.error("auth.jwks.fetch.failed", exc_info=True)
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "code": "AUTH_SERVICE_UNAVAILABLE",
                        "message": "Unable to validate token at this time",
                    }
                },
            )

        entra_oid_raw = claims.get("oid") or claims.get("sub")
        if not entra_oid_raw:
            return _make_401("Token missing required 'oid' claim")

        tid_raw = claims.get("tid")
        if not tid_raw:
            return _make_401("Token missing required 'tid' claim")

        roles: list[str] = claims.get("roles", [])
        role = _resolve_role(roles)
        if role is None:
            return _make_403("No valid WAF Agent role assigned to this user")

        try:
            entra_oid = uuid.UUID(entra_oid_raw)
            azure_tenant_id = uuid.UUID(tid_raw)
        except ValueError:
            return _make_401("Token contains malformed UUID claims")

        tenant_id = await _resolve_tenant_id_from_request(request, azure_tenant_id, role)
        if tenant_id is None:
            return _make_401("Could not resolve tenant for this token")

        request.state.auth = AuthContext(
            tenant_id=tenant_id,
            user_id=entra_oid,
            role=role,
            entra_oid=entra_oid,
        )

        return await call_next(request)


def _resolve_role(roles: list[str]) -> UserRole | None:
    mapping = {
        "WafAgent.PlatformAdmin": UserRole.PLATFORM_ADMIN,
        "WafAgent.TenantAdmin": UserRole.TENANT_ADMIN,
        "WafAgent.TenantViewer": UserRole.TENANT_VIEWER,
    }
    for role_claim, user_role in mapping.items():
        if role_claim in roles:
            return user_role
    return None


async def _resolve_tenant_id_from_request(
    request: Request,
    azure_tenant_id: uuid.UUID,
    role: UserRole,
) -> uuid.UUID | None:
    if role == UserRole.PLATFORM_ADMIN:
        path_tenant_id = request.path_params.get("tenant_id")
        if path_tenant_id:
            try:
                return uuid.UUID(path_tenant_id)
            except ValueError:
                return None
        return uuid.UUID(int=0)

    pool = getattr(request.app.state, "db_pool", None)
    if pool is None:
        _logger.error("auth.tenant_resolution.no_pool")
        return None
    tenant_repo = TenantRepository(pool=pool)
    tenant = await tenant_repo.get_by_azure_tenant_id(azure_tenant_id)
    if tenant is None:
        _logger.warning(
            "auth.tenant_resolution.not_found",
            azure_tenant_id=str(azure_tenant_id),
        )
        return None
    return tenant.id
