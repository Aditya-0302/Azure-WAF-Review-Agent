"""Unit tests for JWT authentication middleware."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from starlette.requests import Request

from waf_api.middleware.auth import _PUBLIC_PATHS, AuthMiddleware


def _make_app_with_auth(settings: MagicMock) -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware, settings=settings)

    @app.get("/api/v1/test")
    async def _test_endpoint(request: Request) -> JSONResponse:
        return JSONResponse({"authenticated": True})

    return app


def _make_settings(
    azure_tenant_id: str = "test-tenant-id",
    jwt_audience: str = "api://waf-agent-api",
) -> MagicMock:
    settings = MagicMock()
    settings.azure_tenant_id = azure_tenant_id
    settings.jwt_audience = jwt_audience
    return settings


class TestPublicPaths:
    def test_healthz_bypasses_auth(self) -> None:
        settings = _make_settings()
        app = FastAPI()
        app.add_middleware(AuthMiddleware, settings=settings)

        @app.get("/healthz")
        async def _healthz() -> dict:
            return {"status": "ok"}

        with TestClient(app) as client:
            response = client.get("/healthz")

        assert response.status_code == 200

    def test_readyz_bypasses_auth(self) -> None:
        assert "/readyz" in _PUBLIC_PATHS

    def test_all_public_paths_defined(self) -> None:
        assert "/healthz" in _PUBLIC_PATHS
        assert "/readyz" in _PUBLIC_PATHS


class TestEntraModeStagingEnforcement:
    """API_AUTH_MODE=entra must enforce JWT validation regardless of APP_ENV.

    These tests reproduce the failure scenario: staging environment with entra
    auth mode.  Before the _public_paths fix, doc paths were exempt from auth
    in any non-production environment; before the config guard, a server could
    start with api_auth_mode=development and APP_ENV=staging silently bypassing
    all JWT validation.
    """

    @staticmethod
    def _entra_staging_settings() -> MagicMock:
        settings = MagicMock()
        settings.api_auth_mode = "entra"
        settings.is_production = False  # staging
        settings.azure_tenant_id = "test-tenant-id"
        settings.jwt_audience = "api://waf-agent-api"
        return settings

    def test_missing_auth_returns_401(self) -> None:
        app = _make_app_with_auth(self._entra_staging_settings())
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/api/v1/test")
        assert r.status_code == 401

    def test_malformed_bearer_returns_401(self) -> None:
        """Four-segment token ('not.a.real.token') must be rejected before JWKS fetch."""
        app = _make_app_with_auth(self._entra_staging_settings())
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/api/v1/test", headers={"Authorization": "Bearer not.a.real.token"})
        assert r.status_code == 401

    def test_invalid_bearer_scheme_returns_401(self) -> None:
        app = _make_app_with_auth(self._entra_staging_settings())
        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/api/v1/test", headers={"Authorization": "Basic dXNlcjpwYXNz"})
        assert r.status_code == 401

    def test_docs_path_returns_404_in_entra_mode(self) -> None:
        """In entra mode, /docs must return 404 — matching FastAPI's docs_url=None semantics.

        The middleware explicitly returns 404 for doc paths in entra mode so that:
        1. The response matches route-not-found semantics for staging/production.
        2. Docs cannot be served unauthenticated even if docs_url is accidentally
           re-enabled in main.py — middleware intercepts before FastAPI's router.
        """
        settings = self._entra_staging_settings()
        app = FastAPI()  # No /docs route — mirrors staging where docs_url=None
        app.add_middleware(AuthMiddleware, settings=settings)

        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/docs")

        assert r.status_code == 404  # middleware returns 404 before FastAPI router

    def test_redoc_and_openapi_return_404_in_entra_mode(self) -> None:
        """All three doc paths return 404 in entra mode (not 401, not 200)."""
        settings = self._entra_staging_settings()
        app = FastAPI()
        app.add_middleware(AuthMiddleware, settings=settings)

        with TestClient(app, raise_server_exceptions=False) as client:
            assert client.get("/redoc").status_code == 404
            assert client.get("/openapi.json").status_code == 404

    def test_dev_mode_bypasses_auth(self) -> None:
        """Verify the development bypass still works (negative regression)."""
        settings = MagicMock()
        settings.api_auth_mode = "development"
        settings.is_production = False

        app = FastAPI()
        app.add_middleware(AuthMiddleware, settings=settings)

        @app.get("/api/v1/test")
        async def _test(request: Request) -> JSONResponse:
            return JSONResponse({"authenticated": True})

        with TestClient(app, raise_server_exceptions=False) as client:
            r = client.get("/api/v1/test")

        assert r.status_code == 200


class TestMissingToken:
    def test_missing_authorization_header_returns_401(self) -> None:
        settings = _make_settings()
        app = _make_app_with_auth(settings)

        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/api/v1/test")

        assert response.status_code == 401

    def test_non_bearer_scheme_returns_401(self) -> None:
        settings = _make_settings()
        app = _make_app_with_auth(settings)

        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/api/v1/test", headers={"Authorization": "Basic dXNlcjpwYXNz"})

        assert response.status_code == 401

    def test_401_response_uses_error_schema(self) -> None:
        settings = _make_settings()
        app = _make_app_with_auth(settings)

        with TestClient(app, raise_server_exceptions=False) as client:
            response = client.get("/api/v1/test")

        body = response.json()
        assert "error" in body
        assert body["error"]["code"] == "UNAUTHORIZED"


class TestInvalidToken:
    def test_malformed_jwt_returns_401(self) -> None:
        settings = _make_settings()
        app = _make_app_with_auth(settings)

        with (
            patch("waf_api.middleware.auth._fetch_jwks", new=AsyncMock(return_value={"keys": []})),
            TestClient(app, raise_server_exceptions=False) as client,
        ):
            response = client.get(
                "/api/v1/test", headers={"Authorization": "Bearer not.a.valid.jwt"}
            )

        assert response.status_code == 401

    def test_expired_token_returns_401(self) -> None:
        settings = _make_settings()
        app = _make_app_with_auth(settings)

        from jose import JWTError

        with (
            patch("waf_api.middleware.auth._fetch_jwks", new=AsyncMock(return_value={"keys": []})),
            patch("waf_api.middleware.auth.jwt.decode", side_effect=JWTError("Token expired")),
            TestClient(app, raise_server_exceptions=False) as client,
        ):
            response = client.get(
                "/api/v1/test", headers={"Authorization": "Bearer expired.token.here"}
            )

        assert response.status_code == 401


# ---------------------------------------------------------------------------
# Missing claims
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestMissingClaims:
    async def _decode_claims(self, claims: dict) -> None:
        from waf_api.middleware.auth import _validate_claims

        with pytest.raises(Exception, match="401|UNAUTHORIZED|missing claim"):
            await _validate_claims(claims)

    async def test_missing_oid_claim_raises(self) -> None:
        from waf_api.middleware.auth import _validate_claims

        with pytest.raises(Exception):
            await _validate_claims({"tid": "abc", "roles": []})

    async def test_missing_tid_claim_raises(self) -> None:
        from waf_api.middleware.auth import _validate_claims

        with pytest.raises(Exception):
            await _validate_claims({"oid": "user-oid", "roles": []})

    async def test_valid_claims_pass(self) -> None:
        from waf_api.middleware.auth import _validate_claims

        # Should not raise
        await _validate_claims({"oid": "user-oid", "tid": "tenant-id", "roles": ["Tenant.User"]})


# ---------------------------------------------------------------------------
# JWKS cache TTL behaviour
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestJwksCacheTTL:
    async def test_cache_hit_within_ttl(self) -> None:
        """Second call within TTL must not hit the HTTP endpoint again."""
        from waf_api.middleware.auth import _JwksCache

        cache = _JwksCache()
        mock_response = {"keys": [{"kid": "key-1", "kty": "RSA"}]}

        fetch_call_count = {"n": 0}

        async def _mock_fetch(url: str) -> dict:
            fetch_call_count["n"] += 1
            return mock_response

        with patch("waf_api.middleware.auth._http_get_jwks", side_effect=_mock_fetch):
            result1 = await cache.get("https://jwks.example.com")
            result2 = await cache.get("https://jwks.example.com")

        assert fetch_call_count["n"] == 1, "Cache should prevent second network call"
        assert result1 == result2

    async def test_cache_miss_after_ttl_expired(self) -> None:
        """After TTL expiry, the next call must re-fetch from the network."""

        from waf_api.middleware.auth import _JwksCache

        cache = _JwksCache(ttl_seconds=0)  # zero TTL — always expired
        fetch_count = {"n": 0}

        async def _mock_fetch(url: str) -> dict:
            fetch_count["n"] += 1
            return {"keys": []}

        with patch("waf_api.middleware.auth._http_get_jwks", side_effect=_mock_fetch):
            await cache.get("https://jwks.example.com")
            await cache.get("https://jwks.example.com")

        assert fetch_count["n"] == 2, "Expired cache must trigger re-fetch"

    async def test_cache_evicts_beyond_capacity(self) -> None:
        """Cache must evict oldest entries when capacity (50) is exceeded."""
        from waf_api.middleware.auth import _JwksCache

        cache = _JwksCache(max_entries=3)
        fetch_count = {"n": 0}

        async def _mock_fetch(url: str) -> dict:
            fetch_count["n"] += 1
            return {"keys": [{"kid": url[-1]}]}

        urls = [f"https://jwks.example{i}.com" for i in range(5)]

        with patch("waf_api.middleware.auth._http_get_jwks", side_effect=_mock_fetch):
            for url in urls:
                await cache.get(url)

        # Cache is capped at 3 — oldest 2 must have been evicted
        assert len(cache._cache) <= 3


# ---------------------------------------------------------------------------
# PlatformAdmin sentinel
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPlatformAdminSentinel:
    async def test_platform_admin_gets_zero_uuid_when_no_path_param(self) -> None:
        from waf_api.middleware.auth import _resolve_tenant_id

        ZERO_UUID = "00000000-0000-0000-0000-000000000000"
        claims = {
            "oid": "admin-oid",
            "tid": "platform-tid",
            "roles": ["Platform.Admin"],
        }
        result = await _resolve_tenant_id(claims=claims, path_tenant_id=None, db_pool=None)
        assert str(result) == ZERO_UUID

    async def test_platform_admin_gets_path_param_uuid_when_present(self) -> None:
        import uuid

        from waf_api.middleware.auth import _resolve_tenant_id

        target_tenant = uuid.uuid4()
        claims = {
            "oid": "admin-oid",
            "tid": "platform-tid",
            "roles": ["Platform.Admin"],
        }
        result = await _resolve_tenant_id(
            claims=claims,
            path_tenant_id=str(target_tenant),
            db_pool=None,
        )
        assert result == target_tenant

    async def test_regular_user_resolves_tenant_from_db(self) -> None:
        import uuid

        from waf_api.middleware.auth import _resolve_tenant_id

        tenant_id = uuid.uuid4()
        oid = "user-oid"
        azure_tid = "azure-tenant-id"

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=tenant_id)
        mock_pool.acquire_read = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_conn),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        claims = {"oid": oid, "tid": azure_tid, "roles": ["Tenant.User"]}
        result = await _resolve_tenant_id(
            claims=claims,
            path_tenant_id=None,
            db_pool=mock_pool,
        )
        assert result == tenant_id

    async def test_regular_user_unknown_tenant_raises_401(self) -> None:
        from waf_api.middleware.auth import _resolve_tenant_id

        mock_pool = MagicMock()
        mock_conn = AsyncMock()
        mock_conn.fetchval = AsyncMock(return_value=None)  # Not found in DB
        mock_pool.acquire_read = MagicMock(
            return_value=AsyncMock(
                __aenter__=AsyncMock(return_value=mock_conn),
                __aexit__=AsyncMock(return_value=False),
            )
        )

        claims = {"oid": "unknown-oid", "tid": "unknown-tid", "roles": ["Tenant.User"]}

        with pytest.raises(Exception):  # Should raise HTTPException 401/403
            await _resolve_tenant_id(
                claims=claims,
                path_tenant_id=None,
                db_pool=mock_pool,
            )
