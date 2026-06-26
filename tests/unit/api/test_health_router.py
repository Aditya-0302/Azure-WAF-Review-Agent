"""Unit tests for /healthz and /readyz endpoints."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient

from waf_api.routers.health import router
from waf_shared.domain.errors.infrastructure_errors import DatabaseError


def _make_test_app(db_pool_mock: MagicMock) -> FastAPI:
    """Create a minimal FastAPI app with the health router and a mocked db pool."""

    app = FastAPI()
    app.state.db_pool = db_pool_mock
    app.include_router(router)
    return app


class TestLivenessEndpoint:
    def test_liveness_returns_200(self) -> None:
        app = FastAPI()
        app.include_router(router)
        with TestClient(app) as client:
            response = client.get("/healthz")

        assert response.status_code == 200

    def test_liveness_returns_ok_status(self) -> None:
        app = FastAPI()
        app.include_router(router)
        with TestClient(app) as client:
            response = client.get("/healthz")

        assert response.json() == {"status": "ok"}

    def test_liveness_requires_no_auth(self) -> None:
        app = FastAPI()
        app.include_router(router)
        with TestClient(app) as client:
            response = client.get("/healthz", headers={})

        assert response.status_code == 200


class TestReadinessEndpoint:
    def test_readiness_returns_200_when_db_healthy(self) -> None:
        mock_pool = MagicMock()
        mock_pool.healthcheck = AsyncMock(return_value=None)
        app = _make_test_app(mock_pool)

        with TestClient(app) as client:
            response = client.get("/readyz")

        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["checks"]["database"] == "ok"

    def test_readiness_returns_503_when_db_unreachable(self) -> None:
        mock_pool = MagicMock()
        mock_pool.healthcheck = AsyncMock(side_effect=DatabaseError("connection refused"))
        app = _make_test_app(mock_pool)

        with TestClient(app) as client:
            response = client.get("/readyz")

        assert response.status_code == 503
        detail = response.json()["detail"]
        assert detail["checks"]["database"] == "unreachable"
        assert detail["status"] == "degraded"

    def test_readiness_calls_db_healthcheck(self) -> None:
        mock_pool = MagicMock()
        mock_pool.healthcheck = AsyncMock(return_value=None)
        app = _make_test_app(mock_pool)

        with TestClient(app) as client:
            client.get("/readyz")

        mock_pool.healthcheck.assert_called_once()
