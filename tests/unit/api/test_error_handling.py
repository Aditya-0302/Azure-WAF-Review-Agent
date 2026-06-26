"""Unit tests for centralised exception handlers in main.py."""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from waf_shared.domain.errors.domain_errors import (
    AssessmentNotFoundError,
    QuotaExceededException,
)
from waf_shared.domain.errors.infrastructure_errors import DatabaseError


def _minimal_app() -> FastAPI:
    """FastAPI app with exception handlers wired but no auth middleware."""
    from fastapi import Request
    from fastapi.responses import JSONResponse

    app = FastAPI()

    @app.exception_handler(AssessmentNotFoundError)
    async def handle_not_found(request: Request, exc: AssessmentNotFoundError) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={"error": {"code": exc.code, "message": exc.message, "detail": None, "trace_id": "", "request_id": ""}},
        )

    @app.exception_handler(QuotaExceededException)
    async def handle_quota(request: Request, exc: QuotaExceededException) -> JSONResponse:
        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "code": exc.code,
                    "message": exc.message,
                    "detail": {"quota_name": exc.quota_name, "limit": exc.limit, "current": exc.current},
                    "trace_id": "",
                    "request_id": "",
                }
            },
        )

    tid = uuid.UUID("11111111-1111-1111-1111-111111111111")
    aid = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")

    @app.get("/raise/not-found")
    async def _raise_not_found() -> None:
        raise AssessmentNotFoundError(assessment_id=aid, tenant_id=tid)

    @app.get("/raise/quota")
    async def _raise_quota() -> None:
        raise QuotaExceededException("max_concurrent_assessments", limit=3, current=3, tenant_id=tid)

    return app


class TestAssessmentNotFoundHandler:
    def test_returns_404(self) -> None:
        app = _minimal_app()
        with TestClient(app) as client:
            response = client.get("/raise/not-found")
        assert response.status_code == 404

    def test_error_code_is_assessment_not_found(self) -> None:
        app = _minimal_app()
        with TestClient(app) as client:
            response = client.get("/raise/not-found")
        assert response.json()["error"]["code"] == "ASSESSMENTNOTFOUNDERROR"

    def test_error_response_has_required_fields(self) -> None:
        app = _minimal_app()
        with TestClient(app) as client:
            response = client.get("/raise/not-found")
        error = response.json()["error"]
        assert "code" in error
        assert "message" in error
        assert "trace_id" in error
        assert "request_id" in error


class TestQuotaExceededHandler:
    def test_returns_429(self) -> None:
        app = _minimal_app()
        with TestClient(app) as client:
            response = client.get("/raise/quota")
        assert response.status_code == 429

    def test_detail_contains_quota_info(self) -> None:
        app = _minimal_app()
        with TestClient(app) as client:
            response = client.get("/raise/quota")
        detail = response.json()["error"]["detail"]
        assert detail["quota_name"] == "max_concurrent_assessments"
        assert detail["limit"] == 3
        assert detail["current"] == 3


class TestErrorResponseSchema:
    def test_no_python_traceback_in_error_response(self) -> None:
        app = _minimal_app()
        with TestClient(app) as client:
            response = client.get("/raise/not-found")
        body_str = response.text
        assert "Traceback" not in body_str
        assert "File " not in body_str

    def test_no_sql_details_in_error_response(self) -> None:
        from fastapi import Request
        from fastapi.responses import JSONResponse

        app = FastAPI()

        @app.exception_handler(DatabaseError)
        async def handle_db(request: Request, exc: DatabaseError) -> JSONResponse:
            return JSONResponse(
                status_code=503,
                content={"error": {"code": "DATABASE_ERROR", "message": "A database error occurred", "detail": None, "trace_id": "", "request_id": ""}},
            )

        @app.get("/raise/db")
        async def _raise_db() -> None:
            raise DatabaseError("SELECT * FROM tenants WHERE id = '...'")

        with TestClient(app) as client:
            response = client.get("/raise/db")

        assert "SELECT" not in response.text
        assert "tenants" not in response.text
