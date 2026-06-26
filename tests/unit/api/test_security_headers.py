"""Unit tests for SecurityHeadersMiddleware.

Verifies every required security header is set, Server header is stripped,
and headers appear on error responses too.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from waf_api.middleware.security_headers import SecurityHeadersMiddleware


def _make_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware)

    @app.get("/ok")
    async def _ok() -> dict:
        return {"status": "ok"}

    @app.get("/error")
    async def _err() -> JSONResponse:
        return JSONResponse({"error": "oops"}, status_code=500)

    return app


@pytest.fixture(scope="module")
def client() -> TestClient:
    return TestClient(_make_app())


@pytest.mark.unit
class TestSecurityHeadersPresent:
    def test_hsts_present(self, client: TestClient) -> None:
        r = client.get("/ok")
        hsts = r.headers.get("strict-transport-security", "")
        assert "max-age=" in hsts
        assert "includeSubDomains" in hsts

    def test_x_content_type_options(self, client: TestClient) -> None:
        r = client.get("/ok")
        assert r.headers.get("x-content-type-options") == "nosniff"

    def test_x_frame_options(self, client: TestClient) -> None:
        r = client.get("/ok")
        assert r.headers.get("x-frame-options") == "DENY"

    def test_referrer_policy(self, client: TestClient) -> None:
        r = client.get("/ok")
        assert r.headers.get("referrer-policy") == "no-referrer"

    def test_permissions_policy(self, client: TestClient) -> None:
        r = client.get("/ok")
        policy = r.headers.get("permissions-policy", "")
        assert "geolocation=()" in policy
        assert "camera=()" in policy

    def test_cache_control(self, client: TestClient) -> None:
        r = client.get("/ok")
        cc = r.headers.get("cache-control", "")
        assert "no-store" in cc

    def test_pragma_no_cache(self, client: TestClient) -> None:
        r = client.get("/ok")
        assert r.headers.get("pragma") == "no-cache"


@pytest.mark.unit
class TestServerHeaderRemoved:
    def test_server_header_absent(self, client: TestClient) -> None:
        r = client.get("/ok")
        assert "server" not in r.headers


@pytest.mark.unit
class TestHeadersOnErrorResponses:
    def test_security_headers_on_500(self, client: TestClient) -> None:
        r = client.get("/error")
        assert r.status_code == 500
        assert r.headers.get("x-content-type-options") == "nosniff"
        assert r.headers.get("x-frame-options") == "DENY"

    def test_security_headers_on_404(self, client: TestClient) -> None:
        r = client.get("/nonexistent")
        assert r.status_code == 404
        assert r.headers.get("x-content-type-options") == "nosniff"
