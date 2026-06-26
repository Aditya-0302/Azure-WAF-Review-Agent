"""Health check endpoints.

/healthz — liveness probe: returns 200 if the process is running.
/readyz  — readiness probe: returns 200 only if all downstream dependencies are healthy.

Kubernetes uses liveness to decide whether to restart a pod and
readiness to decide whether to route traffic to it. They must remain
decoupled — a failing DB should fail readiness, not liveness.

Readiness checks:
  database — asyncpg pool ping (SELECT 1)
  redis    — redis-py async ping
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from waf_api.config import Settings
from waf_api.dependencies.db import get_db_pool
from waf_shared.db.pool import DatabasePool
from waf_shared.telemetry.logging import StructuredLogger

router = APIRouter(tags=["health"])

_logger = StructuredLogger(service="waf-api", version="0.1.0")


class LivenessResponse(BaseModel):
    status: str


class ReadinessResponse(BaseModel):
    status: str
    checks: dict[str, str]


def _get_settings() -> Settings:
    from waf_api.main import _settings  # module-level singleton

    return _settings


@router.get(
    "/healthz",
    response_model=LivenessResponse,
    status_code=status.HTTP_200_OK,
    summary="Liveness probe",
    description="Returns 200 when the process is alive. Never touches downstream services.",
)
async def liveness() -> LivenessResponse:
    return LivenessResponse(status="ok")


@router.get(
    "/readyz",
    response_model=ReadinessResponse,
    status_code=status.HTTP_200_OK,
    summary="Readiness probe",
    description="Returns 200 only when all downstream dependencies are reachable.",
)
async def readiness(
    pool: Annotated[DatabasePool, Depends(get_db_pool)],
) -> ReadinessResponse:
    checks: dict[str, str] = {}
    failed = False

    # ── Database ──────────────────────────────────────────────────────────────
    try:
        await pool.healthcheck()
        checks["database"] = "ok"
    except Exception:
        _logger.error("readyz.db.check.failed", exc_info=True)
        checks["database"] = "unreachable"
        failed = True

    # ── Redis ─────────────────────────────────────────────────────────────────
    settings = _get_settings()
    if settings.redis_url:
        try:
            import redis.asyncio as aioredis  # type: ignore[import-untyped]

            r = aioredis.from_url(settings.redis_url, socket_connect_timeout=3)
            await r.ping()
            await r.aclose()
            checks["redis"] = "ok"
        except Exception:
            _logger.warning("readyz.redis.check.failed", exc_info=True)
            checks["redis"] = "unreachable"

    if failed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=ReadinessResponse(status="degraded", checks=checks).model_dump(),
        )

    return ReadinessResponse(status="ok", checks=checks)
