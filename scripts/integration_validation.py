#!/usr/bin/env python3
"""Integration validation — verifies live runtime connectivity and the full
assessment workflow. Requires Docker Compose services to be running.

Checks (each check auto-skips if its prerequisite service is unreachable):
  1. PostgreSQL connectivity — connect, SELECT 1, healthcheck()
  2. Database schema — required tables exist, Alembic at head, RLS enabled
  3. Service Bus — TCP reachability on AMQP port, publish test message
  4. API health endpoints — GET /healthz and /readyz
  5. Assessment workflow (service layer) — create → get → list → cancel

Prerequisites:
  docker-compose -f docker-compose.dev.yml up -d postgres servicebus-emulator

Usage:
  python scripts/integration_validation.py
  SERVICEBUS_CONNECTION_STRING=<conn> python scripts/integration_validation.py
"""
from __future__ import annotations

import asyncio
import os
import socket
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

# ── Path bootstrap ─────────────────────────────────────────────────────────────
_ROOT = Path(__file__).resolve().parent.parent
for _pkg in [
    "src/shared",
    "src/api",
    "src/agents/preparation",
    "src/agents/extraction",
    "src/agents/reasoning",
    "src/agents/reporting",
]:
    _p = _ROOT / _pkg
    if _p.exists() and str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

try:
    from startup_validation import CheckResult, _run, _print_report, _SkipCheck
except ImportError:
    import dataclasses

    @dataclasses.dataclass
    class CheckResult:  # type: ignore[no-redef]
        name: str
        category: str
        severity: str
        passed: bool
        error: str | None
        duration_ms: float
        skipped: bool = False
        skip_reason: str | None = None

        @property
        def is_failure(self) -> bool:
            return not self.passed and not self.skipped

    class _SkipCheck(Exception):  # type: ignore[no-redef]
        pass

    def _run(name, category, severity, fn):  # type: ignore[misc]
        start = time.monotonic()
        try:
            fn()
            return CheckResult(name, category, severity, True, None, (time.monotonic() - start) * 1000)
        except _SkipCheck as exc:
            return CheckResult(name, category, severity, False, None, 0, True, str(exc))
        except Exception as exc:
            return CheckResult(name, category, severity, False, f"{type(exc).__name__}: {exc}", (time.monotonic() - start) * 1000)

    def _print_report(results, title):  # type: ignore[misc]
        passed  = sum(1 for r in results if r.passed)
        failed  = sum(1 for r in results if r.is_failure)
        skipped = sum(1 for r in results if r.skipped)
        print(f"\n{'='*70}\n  {title}\n{'='*70}")
        print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}  Skipped: {skipped}")
        print(f"{'='*70}")
        for r in results:
            status = "SKIP" if r.skipped else (" OK " if r.passed else "FAIL")
            print(f"  [{status}] [{r.severity:8s}] {r.name}  ({r.duration_ms:.1f}ms)")
            if r.is_failure and r.error:
                print(f"            └─ {r.error}")
        print()


# ── DB configuration helper ───────────────────────────────────────────────────

def _db_dsn() -> str:
    """Build DSN from environment, falling back to docker-compose.dev.yml defaults."""
    host     = os.environ.get("DB_HOST",     "localhost")
    port     = os.environ.get("DB_PORT",     "5432")
    name     = os.environ.get("DB_NAME",     "wafagent")
    user     = os.environ.get("DB_USER",     "wafagent")
    password = os.environ.get("DB_PASSWORD", "changeme_local_only")
    return f"postgresql://{user}:{password}@{host}:{port}/{name}"


def _api_base_url() -> str:
    host = os.environ.get("API_HOST", "localhost")
    port = os.environ.get("API_PORT", "8000")
    return f"http://{host}:{port}"


def _sb_host() -> str:
    return os.environ.get("SB_HOST", "localhost")


def _is_port_open(host: str, port: int, timeout: float = 3.0) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((host, port))
    sock.close()
    return result == 0


# ── Capturing publisher (no real Service Bus needed for workflow test) ─────────

class _CapturingPublisher:
    """Drop-in replacement for ServiceBusPublisher that captures messages."""

    def __init__(self) -> None:
        self.messages: list[tuple[str, object]] = []

    async def publish(self, queue_name: str, envelope: object) -> None:
        self.messages.append((queue_name, envelope))

    async def close(self) -> None:
        pass


# ── 1. PostgreSQL connectivity ────────────────────────────────────────────────

async def _db_connectivity_checks() -> list[CheckResult]:
    results: list[CheckResult] = []
    dsn = _db_dsn()

    try:
        import asyncpg
    except ImportError:
        results.append(CheckResult(
            name="asyncpg available",
            category="db_connectivity", severity="CRITICAL",
            passed=False, error="asyncpg not installed — run: pip install asyncpg",
            duration_ms=0,
        ))
        return results

    conn = None
    start = time.monotonic()

    # Check 1a: raw TCP connect
    host = os.environ.get("DB_HOST", "localhost")
    port = int(os.environ.get("DB_PORT", "5432"))
    if not _is_port_open(host, port, timeout=3.0):
        results.append(CheckResult(
            name=f"PostgreSQL TCP connect to {host}:{port}",
            category="db_connectivity", severity="MEDIUM",
            passed=False, error=None,
            duration_ms=(time.monotonic() - start) * 1000,
            skipped=True,
            skip_reason=f"Port {port} not reachable on {host} — start: docker-compose up -d postgres",
        ))
        return results

    # Check 1b: asyncpg.connect()
    try:
        conn = await asyncio.wait_for(asyncpg.connect(dsn=dsn), timeout=10.0)
        results.append(CheckResult(
            name="asyncpg.connect() succeeds",
            category="db_connectivity", severity="CRITICAL",
            passed=True, error=None,
            duration_ms=(time.monotonic() - start) * 1000,
        ))
    except Exception as exc:
        results.append(CheckResult(
            name="asyncpg.connect() succeeds",
            category="db_connectivity", severity="CRITICAL",
            passed=False, error=f"{type(exc).__name__}: {exc}",
            duration_ms=(time.monotonic() - start) * 1000,
        ))
        return results

    # Check 1c: SELECT 1
    start = time.monotonic()
    try:
        val = await conn.fetchval("SELECT 1")
        assert val == 1
        results.append(CheckResult(
            name="SELECT 1 returns 1",
            category="db_connectivity", severity="CRITICAL",
            passed=True, error=None,
            duration_ms=(time.monotonic() - start) * 1000,
        ))
    except Exception as exc:
        results.append(CheckResult(
            name="SELECT 1 returns 1",
            category="db_connectivity", severity="CRITICAL",
            passed=False, error=f"{type(exc).__name__}: {exc}",
            duration_ms=(time.monotonic() - start) * 1000,
        ))

    # Check 1d: DatabasePool.healthcheck()
    start = time.monotonic()
    try:
        from waf_shared.db.pool import DatabasePool
        pool = DatabasePool(dsn_primary=dsn, dsn_readonly=None, min_size=1, max_size=3)
        await asyncio.wait_for(pool.connect(), timeout=10.0)
        await pool.healthcheck()
        await pool.disconnect()
        results.append(CheckResult(
            name="DatabasePool.connect() + healthcheck() + disconnect()",
            category="db_connectivity", severity="CRITICAL",
            passed=True, error=None,
            duration_ms=(time.monotonic() - start) * 1000,
        ))
    except Exception as exc:
        results.append(CheckResult(
            name="DatabasePool.connect() + healthcheck() + disconnect()",
            category="db_connectivity", severity="CRITICAL",
            passed=False, error=f"{type(exc).__name__}: {exc}",
            duration_ms=(time.monotonic() - start) * 1000,
        ))
    finally:
        if conn and not conn.is_closed():
            await conn.close()

    return results


# ── 2. Database schema ────────────────────────────────────────────────────────

_REQUIRED_TABLES = {
    "tenants", "tenant_users", "tenant_quotas", "subscription_credentials",
    "assessments", "assessment_batches", "assessment_resources",
    "waf_rules", "assessment_findings",
}

_LATEST_MIGRATION = "0004"


async def _db_schema_checks() -> list[CheckResult]:
    results: list[CheckResult] = []

    try:
        import asyncpg
    except ImportError:
        return results

    host = os.environ.get("DB_HOST", "localhost")
    port = int(os.environ.get("DB_PORT", "5432"))
    if not _is_port_open(host, port, timeout=2.0):
        return results

    dsn = _db_dsn()

    try:
        conn = await asyncio.wait_for(asyncpg.connect(dsn=dsn), timeout=10.0)
    except Exception:
        return results

    try:
        # Check 2a: required tables
        start = time.monotonic()
        try:
            rows = await conn.fetch(
                "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
            )
            existing = {row["tablename"] for row in rows}
            missing = _REQUIRED_TABLES - existing
            if missing:
                results.append(CheckResult(
                    name=f"Required tables exist ({len(_REQUIRED_TABLES)} tables)",
                    category="db_schema", severity="CRITICAL",
                    passed=False,
                    error=f"Missing tables: {sorted(missing)} — run: alembic upgrade head",
                    duration_ms=(time.monotonic() - start) * 1000,
                ))
            else:
                results.append(CheckResult(
                    name=f"Required tables exist ({len(_REQUIRED_TABLES)} tables)",
                    category="db_schema", severity="CRITICAL",
                    passed=True, error=None,
                    duration_ms=(time.monotonic() - start) * 1000,
                ))
        except Exception as exc:
            results.append(CheckResult(
                name=f"Required tables exist ({len(_REQUIRED_TABLES)} tables)",
                category="db_schema", severity="CRITICAL",
                passed=False, error=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        # Check 2b: Alembic migration at head
        start = time.monotonic()
        try:
            row = await conn.fetchrow("SELECT version_num FROM alembic_version LIMIT 1")
            if row is None:
                raise AssertionError(
                    "alembic_version table is empty — run: alembic upgrade head"
                )
            version = row["version_num"]
            if version != _LATEST_MIGRATION:
                raise AssertionError(
                    f"Migration at '{version}', expected '{_LATEST_MIGRATION}' — "
                    f"run: alembic upgrade head"
                )
            results.append(CheckResult(
                name=f"Alembic migration at head (version={_LATEST_MIGRATION})",
                category="db_schema", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name=f"Alembic migration at head (version={_LATEST_MIGRATION})",
                category="db_schema", severity="HIGH",
                passed=False, error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        # Check 2c: RLS enabled on tenants-scoped tables
        start = time.monotonic()
        try:
            rows = await conn.fetch(
                "SELECT tablename FROM pg_tables "
                "WHERE schemaname = 'public' "
                "AND tablename IN ("
                "  SELECT relname FROM pg_class "
                "  WHERE relrowsecurity = true AND relnamespace = 'public'::regnamespace"
                ")"
            )
            rls_tables = {row["tablename"] for row in rows}
            required_rls = {
                "tenant_users", "tenant_quotas", "subscription_credentials",
                "assessments", "assessment_findings",
            }
            missing_rls = required_rls - rls_tables
            if missing_rls:
                raise AssertionError(
                    f"RLS not enabled on: {sorted(missing_rls)}"
                )
            results.append(CheckResult(
                name="Row-Level Security enabled on all tenant-scoped tables",
                category="db_schema", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name="Row-Level Security enabled on all tenant-scoped tables",
                category="db_schema", severity="HIGH",
                passed=False, error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        # Check 2d: DB enum types include advisor_mapped
        start = time.monotonic()
        try:
            row = await conn.fetchrow(
                "SELECT array_agg(enumlabel ORDER BY enumsortorder) AS labels "
                "FROM pg_enum "
                "WHERE enumtypid = 'evaluation_type'::regtype"
            )
            if row is None or row["labels"] is None:
                raise AssertionError("evaluation_type enum not found in DB")
            labels = list(row["labels"])
            assert "advisor_mapped" in labels, (
                f"'advisor_mapped' missing from DB evaluation_type enum. "
                f"Found: {labels}. Run migration 0003 again."
            )
            results.append(CheckResult(
                name="DB evaluation_type enum includes 'advisor_mapped'",
                category="db_schema", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name="DB evaluation_type enum includes 'advisor_mapped'",
                category="db_schema", severity="HIGH",
                passed=False, error=str(exc),
                duration_ms=(time.monotonic() - start) * 1000,
            ))

    finally:
        if not conn.is_closed():
            await conn.close()

    return results


# ── 3. Service Bus connectivity ───────────────────────────────────────────────

async def _service_bus_checks() -> list[CheckResult]:
    results: list[CheckResult] = []
    sb_host = _sb_host()

    # Check 3a: AMQP port (5672)
    start = time.monotonic()
    amqp_open = _is_port_open(sb_host, 5672, timeout=3.0)
    if not amqp_open:
        results.append(CheckResult(
            name=f"Service Bus emulator AMQP port 5672 reachable on {sb_host}",
            category="service_bus", severity="MEDIUM",
            passed=False, error=None,
            duration_ms=(time.monotonic() - start) * 1000,
            skipped=True,
            skip_reason=(
                f"Port 5672 not reachable on {sb_host} — "
                "start: docker-compose up -d servicebus-emulator"
            ),
        ))
        return results

    results.append(CheckResult(
        name=f"Service Bus emulator AMQP port 5672 reachable on {sb_host}",
        category="service_bus", severity="MEDIUM",
        passed=True, error=None,
        duration_ms=(time.monotonic() - start) * 1000,
    ))

    # Check 3b: publish a test CloudEvent to assessment.created
    conn_str = os.environ.get("SERVICEBUS_CONNECTION_STRING", "")
    if not conn_str:
        results.append(CheckResult(
            name="ServiceBusPublisher can publish to assessment.created",
            category="service_bus", severity="MEDIUM",
            passed=False, error=None,
            duration_ms=0,
            skipped=True,
            skip_reason=(
                "SERVICEBUS_CONNECTION_STRING not set — "
                "export SERVICEBUS_CONNECTION_STRING from docker-compose"
            ),
        ))
        return results

    start = time.monotonic()
    try:
        from waf_shared.messaging.service_bus import ServiceBusPublisher
        from waf_shared.messaging.queue_names import ASSESSMENT_CREATED
        from waf_shared.domain.events.base import CloudEventEnvelope
        from waf_shared.domain.events.assessment_events import AssessmentCreatedEvent

        publisher = ServiceBusPublisher(connection_string=conn_str)
        now = datetime.now(UTC)
        event_data = AssessmentCreatedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            subscription_ids=[uuid.UUID("00000000-0000-0000-0000-000000000001")],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
            created_at=now,
        )
        envelope = CloudEventEnvelope.wrap(
            event_type="com.wafagent.assessment.created",
            source="/validation",
            data=event_data,
        )
        await asyncio.wait_for(
            publisher.publish(ASSESSMENT_CREATED, envelope),
            timeout=10.0,
        )
        await publisher.close()
        results.append(CheckResult(
            name="ServiceBusPublisher can publish to assessment.created",
            category="service_bus", severity="MEDIUM",
            passed=True, error=None,
            duration_ms=(time.monotonic() - start) * 1000,
        ))
    except Exception as exc:
        results.append(CheckResult(
            name="ServiceBusPublisher can publish to assessment.created",
            category="service_bus", severity="MEDIUM",
            passed=False,
            error=f"{type(exc).__name__}: {exc}",
            duration_ms=(time.monotonic() - start) * 1000,
        ))

    return results


# ── 4. API health endpoints ───────────────────────────────────────────────────

async def _health_endpoint_checks() -> list[CheckResult]:
    results: list[CheckResult] = []

    try:
        import httpx
    except ImportError:
        results.append(CheckResult(
            name="httpx available for health checks",
            category="api_health", severity="MEDIUM",
            passed=False,
            error="httpx not installed — run: pip install httpx",
            duration_ms=0,
        ))
        return results

    base_url = _api_base_url()
    api_host = os.environ.get("API_HOST", "localhost")
    api_port = int(os.environ.get("API_PORT", "8000"))

    if not _is_port_open(api_host, api_port, timeout=3.0):
        for endpoint in ["/healthz", "/readyz"]:
            results.append(CheckResult(
                name=f"GET {base_url}{endpoint} → 200",
                category="api_health", severity="MEDIUM",
                passed=False, error=None,
                duration_ms=0,
                skipped=True,
                skip_reason=(
                    f"API not reachable on {api_host}:{api_port} — "
                    "start: docker-compose up -d api"
                ),
            ))
        return results

    async with httpx.AsyncClient(timeout=httpx.Timeout(10.0)) as client:
        # Check 4a: /healthz
        start = time.monotonic()
        try:
            resp = await client.get(f"{base_url}/healthz")
            assert resp.status_code == 200, f"Expected 200, got {resp.status_code}"
            data = resp.json()
            assert data.get("status") == "ok", f"Expected status=ok, got: {data}"
            results.append(CheckResult(
                name=f"GET {base_url}/healthz → 200 {{status: ok}}",
                category="api_health", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name=f"GET {base_url}/healthz → 200 {{status: ok}}",
                category="api_health", severity="HIGH",
                passed=False, error=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        # Check 4b: /readyz (200 = all deps up; 503 = degraded but API is alive)
        start = time.monotonic()
        try:
            resp = await client.get(f"{base_url}/readyz")
            assert resp.status_code in (200, 503), (
                f"Expected 200 or 503, got {resp.status_code}"
            )
            data_raw = resp.json()
            # If 503, it means API is up but DB may not be connected through lifespan
            data = data_raw if isinstance(data_raw, dict) else data_raw.get("detail", {})
            assert data.get("status") in ("ok", "degraded"), (
                f"Expected status in ok/degraded, got: {data}"
            )
            results.append(CheckResult(
                name=f"GET {base_url}/readyz → 200/503 with status field",
                category="api_health", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name=f"GET {base_url}/readyz → 200/503 with status field",
                category="api_health", severity="HIGH",
                passed=False, error=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))

    return results


# ── 5. Assessment workflow (service layer) ────────────────────────────────────

async def _assessment_workflow_checks() -> list[CheckResult]:
    results: list[CheckResult] = []

    try:
        import asyncpg
    except ImportError:
        return results

    host = os.environ.get("DB_HOST", "localhost")
    port = int(os.environ.get("DB_PORT", "5432"))
    if not _is_port_open(host, port, timeout=2.0):
        for name in [
            "create_assessment persists to DB with PENDING status",
            "get_assessment retrieves created assessment",
            "list_assessments returns at least one item",
            "cancel_assessment sets cancellation_requested_at",
        ]:
            results.append(CheckResult(
                name=name, category="workflow", severity="HIGH",
                passed=False, error=None, duration_ms=0,
                skipped=True, skip_reason="PostgreSQL not reachable",
            ))
        return results

    dsn = _db_dsn()
    test_tenant_id = uuid.uuid4()
    test_azure_tenant_id = uuid.uuid4()
    assessment_id: uuid.UUID | None = None

    try:
        from waf_shared.db.pool import DatabasePool
        from waf_api.services.assessment_service import AssessmentService, CreateAssessmentRequest
        from waf_shared.domain.models.assessment import AssessmentStatus
    except ImportError as exc:
        for name in [
            "create_assessment persists to DB with PENDING status",
            "get_assessment retrieves created assessment",
            "list_assessments returns at least one item",
            "cancel_assessment sets cancellation_requested_at",
        ]:
            results.append(CheckResult(
                name=name, category="workflow", severity="HIGH",
                passed=False, error=f"Import failed: {exc}", duration_ms=0,
            ))
        return results

    pool = DatabasePool(dsn_primary=dsn, dsn_readonly=None, min_size=1, max_size=3)
    capturing_publisher = _CapturingPublisher()

    try:
        await asyncio.wait_for(pool.connect(), timeout=10.0)

        # Insert test tenant (tenants table has no RLS)
        async with pool.acquire_write() as conn:
            await conn.execute(
                """
                INSERT INTO tenants (id, slug, display_name, azure_tenant_id, plan_tier, is_active)
                VALUES ($1, $2, $3, $4, 'standard', true)
                ON CONFLICT (id) DO NOTHING
                """,
                test_tenant_id,
                f"val-{str(test_tenant_id)[:8]}",
                "Validation Test Tenant",
                test_azure_tenant_id,
            )

        svc = AssessmentService(pool=pool, publisher=capturing_publisher)
        req = CreateAssessmentRequest(
            tenant_id=test_tenant_id,
            idempotency_key=f"val-wf-{uuid.uuid4().hex[:12]}",
            subscription_ids=[uuid.UUID("00000000-0000-0000-0000-000000000001")],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
        )

        # Check 5a: create_assessment
        start = time.monotonic()
        try:
            assessment = await asyncio.wait_for(svc.create_assessment(req), timeout=10.0)
            assessment_id = assessment.id
            assert assessment.status == AssessmentStatus.PENDING, (
                f"Expected PENDING, got {assessment.status}"
            )
            assert assessment.tenant_id == test_tenant_id
            assert len(capturing_publisher.messages) == 1, (
                f"Expected 1 message published, got {len(capturing_publisher.messages)}"
            )
            queue_name, envelope = capturing_publisher.messages[0]
            assert queue_name == "assessment.created", (
                f"Expected 'assessment.created', got '{queue_name}'"
            )
            results.append(CheckResult(
                name="create_assessment persists to DB with PENDING status",
                category="workflow", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name="create_assessment persists to DB with PENDING status",
                category="workflow", severity="HIGH",
                passed=False, error=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))
            # Can't continue without an assessment ID
            return results

        # Check 5b: get_assessment
        start = time.monotonic()
        try:
            fetched = await asyncio.wait_for(
                svc.get_assessment(assessment_id, test_tenant_id),  # type: ignore[arg-type]
                timeout=10.0,
            )
            assert fetched.id == assessment_id
            assert fetched.status == AssessmentStatus.PENDING
            assert fetched.tenant_id == test_tenant_id
            results.append(CheckResult(
                name="get_assessment retrieves created assessment",
                category="workflow", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name="get_assessment retrieves created assessment",
                category="workflow", severity="HIGH",
                passed=False, error=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        # Check 5c: list_assessments
        start = time.monotonic()
        try:
            assessments = await asyncio.wait_for(
                svc.list_assessments(test_tenant_id, limit=10),
                timeout=10.0,
            )
            assert len(assessments) >= 1, (
                f"Expected at least 1 assessment, got {len(assessments)}"
            )
            ids = [a.id for a in assessments]
            assert assessment_id in ids, (
                f"Created assessment {assessment_id} not in list: {ids}"
            )
            results.append(CheckResult(
                name="list_assessments returns at least one item",
                category="workflow", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name="list_assessments returns at least one item",
                category="workflow", severity="HIGH",
                passed=False, error=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))

        # Check 5d: cancel_assessment
        start = time.monotonic()
        try:
            cancelled = await asyncio.wait_for(
                svc.cancel_assessment(assessment_id, test_tenant_id),  # type: ignore[arg-type]
                timeout=10.0,
            )
            assert cancelled.cancellation_requested_at is not None, (
                "cancellation_requested_at should be set after cancel"
            )
            assert cancelled.is_cancellation_pending, (
                "is_cancellation_pending should be True"
            )
            results.append(CheckResult(
                name="cancel_assessment sets cancellation_requested_at",
                category="workflow", severity="HIGH",
                passed=True, error=None,
                duration_ms=(time.monotonic() - start) * 1000,
            ))
        except Exception as exc:
            results.append(CheckResult(
                name="cancel_assessment sets cancellation_requested_at",
                category="workflow", severity="HIGH",
                passed=False, error=f"{type(exc).__name__}: {exc}",
                duration_ms=(time.monotonic() - start) * 1000,
            ))

    except Exception as exc:
        results.append(CheckResult(
            name="Assessment workflow setup (pool.connect + tenant insert)",
            category="workflow", severity="CRITICAL",
            passed=False, error=f"{type(exc).__name__}: {exc}",
            duration_ms=0,
        ))
    finally:
        # Best-effort cleanup: delete test tenant (cascades through FK to assessments if configured)
        try:
            async with pool.acquire_write() as conn:
                async with conn.transaction():
                    await conn.execute(
                        "SELECT set_config('app.current_tenant_id', $1, true)",
                        str(test_tenant_id),
                    )
                    if assessment_id is not None:
                        # Delete assessment (RLS context set above)
                        await conn.execute(
                            "DELETE FROM assessments WHERE tenant_id = $1 AND id = $2",
                            test_tenant_id, assessment_id,
                        )
            # Delete tenant (no RLS on tenants table)
            async with pool.acquire_write() as conn:
                await conn.execute(
                    "DELETE FROM tenants WHERE id = $1", test_tenant_id
                )
        except Exception:
            pass  # cleanup is best-effort in a test DB

        await pool.disconnect()

    return results


# ── Public API ────────────────────────────────────────────────────────────────

async def _run_all_async() -> list[CheckResult]:
    all_results: list[CheckResult] = []
    all_results.extend(await _db_connectivity_checks())
    all_results.extend(await _db_schema_checks())
    all_results.extend(await _service_bus_checks())
    all_results.extend(await _health_endpoint_checks())
    all_results.extend(await _assessment_workflow_checks())
    return all_results


def run() -> list[CheckResult]:
    return asyncio.run(_run_all_async())


def main() -> int:
    results = run()
    _print_report(results, "Integration Validation")
    critical_failures = [r for r in results if r.is_failure and r.severity in ("CRITICAL", "HIGH")]
    return 1 if critical_failures else 0


if __name__ == "__main__":
    sys.exit(main())
