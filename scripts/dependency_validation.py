#!/usr/bin/env python3
"""Dependency validation — verifies DI container structure, repository instantiation,
service instantiation, and FastAPI app creation. Requires no live infrastructure.

Checks:
  1. DI Container has all expected providers
  2. Container wiring_config covers all required modules
  3. All repository classes instantiate with a mock pool
  4. All repository classes expose their required methods
  5. All service classes instantiate with mock dependencies
  6. ServiceBusPublisher validates constructor arguments
  7. FastAPI app creates successfully with all routes registered
  8. All API exception handlers are registered

Usage:
  python scripts/dependency_validation.py
"""
from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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

# Import shared result type (also triggers path bootstrap from startup_validation if already imported)
try:
    from startup_validation import CheckResult, _run, _print_report
except ImportError:
    # standalone execution — redefine locally
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

    class _SkipCheck(Exception):
        pass

    def _run(name: str, category: str, severity: str, fn) -> CheckResult:
        start = time.monotonic()
        try:
            fn()
            return CheckResult(name, category, severity, True, None, (time.monotonic() - start) * 1000)
        except _SkipCheck as exc:
            return CheckResult(name, category, severity, False, None, 0, True, str(exc))
        except Exception as exc:
            return CheckResult(name, category, severity, False, f"{type(exc).__name__}: {exc}", (time.monotonic() - start) * 1000)

    def _print_report(results: list, title: str) -> None:
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


# ── 1. DI Container structure ─────────────────────────────────────────────────

def _container_checks() -> list[CheckResult]:
    results = []

    def check_container_init():
        from waf_api.container import Container
        container = Container()
        assert container is not None

    def check_container_providers():
        from waf_api.container import Container
        expected_providers = [
            "config", "logger", "metrics",
            "db_pool",
            "platform_auth_config", "platform_credential_provider",
            "cross_tenant_provider", "token_provider", "auth_service",
            "discovery_config", "discovery_metrics", "discovery_service",
        ]
        for attr in expected_providers:
            assert hasattr(Container, attr), (
                f"Container is missing provider: {attr}"
            )

    def check_wiring_config():
        from waf_api.container import Container
        assert hasattr(Container, "wiring_config"), "Container must have wiring_config"
        modules = Container.wiring_config.modules
        required_modules = [
            "waf_api.dependencies.db",
            "waf_api.dependencies.rbac",
            "waf_api.dependencies.services",
            "waf_api.routers.health",
        ]
        for mod in required_modules:
            assert mod in modules, (
                f"wiring_config.modules must include '{mod}'; found: {list(modules)}"
            )

    def check_container_override():
        from waf_api.container import Container
        from dependency_injector import providers
        from waf_api.config import Settings
        container = Container()
        settings = Settings()
        # Override is used in main.py lifespan; verify it doesn't raise
        container.config.override(providers.Object(settings))
        resolved_settings = container.config()
        assert resolved_settings is settings

    for name, fn in [
        ("Container() instantiates without error", check_container_init),
        ("Container has all expected provider attributes", check_container_providers),
        ("Container.wiring_config covers all required modules", check_wiring_config),
        ("Container.config.override(providers.Object(settings)) works", check_container_override),
    ]:
        results.append(_run(name, "di_container", "CRITICAL", fn))

    return results


# ── 2. Repository instantiation ───────────────────────────────────────────────

def _repository_checks() -> list[CheckResult]:
    results = []

    _mock_pool = MagicMock()

    def _check_repo(import_path: str, class_name: str, required_methods: list[str]):
        mod = __import__(import_path, fromlist=[class_name])
        cls = getattr(mod, class_name)
        repo = cls(pool=_mock_pool)
        assert repo is not None
        for method in required_methods:
            assert hasattr(repo, method), (
                f"{class_name} is missing method: {method}"
            )
            assert callable(getattr(repo, method)), (
                f"{class_name}.{method} must be callable"
            )

    repo_specs: list[tuple[str, str, str, list[str]]] = [
        (
            "AssessmentRepository",
            "waf_shared.db.repositories.assessment_repository",
            "AssessmentRepository",
            ["get_by_id", "get_by_idempotency_key", "create", "update_status",
             "list_by_tenant", "count_active", "request_cancellation",
             "create_batch", "update_batch_status", "complete_batch_and_check_fanin"],
        ),
        (
            "FindingRepository",
            "waf_shared.db.repositories.finding_repository",
            "FindingRepository",
            ["create_batch", "get_by_id", "list_by_assessment",
             "update_status", "count_by_severity"],
        ),
        (
            "TenantRepository",
            "waf_shared.db.repositories.tenant_repository",
            "TenantRepository",
            ["get_by_id", "get_by_azure_tenant_id", "create",
             "get_user_by_oid", "upsert_user"],
        ),
        (
            "CredentialRepository",
            "waf_shared.db.repositories.credential_repository",
            "CredentialRepository",
            ["get_by_id", "get_by_subscription", "list_by_tenant",
             "create", "update_health", "delete"],
        ),
        (
            "WafRuleRepository",
            "waf_shared.db.repositories.rule_repository",
            "WafRuleRepository",
            ["get_by_rule_id", "list_active", "upsert", "deactivate", "count_active"],
        ),
        (
            "ReportRepository",
            "waf_shared.db.repositories.report_repository",
            "ReportRepository",
            ["create", "get_by_assessment", "get_by_id"],
        ),
    ]

    for display_name, import_path, class_name, methods in repo_specs:
        results.append(_run(
            name=f"{display_name} instantiation + method presence check",
            category="repositories",
            severity="HIGH",
            fn=lambda ip=import_path, cn=class_name, m=methods: _check_repo(ip, cn, m),
        ))

    return results


# ── 3. Service instantiation ──────────────────────────────────────────────────

def _service_checks() -> list[CheckResult]:
    results = []

    _mock_pool = MagicMock()
    _mock_publisher = MagicMock()
    _mock_auth_service = MagicMock()

    def check_assessment_service():
        from waf_api.services.assessment_service import AssessmentService, CreateAssessmentRequest
        svc = AssessmentService(pool=_mock_pool, publisher=_mock_publisher)
        assert hasattr(svc, "create_assessment")
        assert hasattr(svc, "get_assessment")
        assert hasattr(svc, "list_assessments")
        assert hasattr(svc, "cancel_assessment")
        # Verify CreateAssessmentRequest dataclass
        req = CreateAssessmentRequest(
            tenant_id=uuid.uuid4(),
            idempotency_key="test-key",
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
        )
        assert req.idempotency_key == "test-key"

    def check_tenant_service():
        from waf_api.services.tenant_service import TenantService
        svc = TenantService(pool=_mock_pool)
        assert hasattr(svc, "get_by_id")
        assert hasattr(svc, "get_by_azure_tenant_id")
        assert hasattr(svc, "get_user_by_oid")

    def check_quota_service():
        from waf_api.services.quota_service import QuotaService
        svc = QuotaService(pool=_mock_pool)
        assert hasattr(svc, "assert_can_create_assessment")

    def check_credential_service():
        from waf_api.services.credential_service import CredentialService
        svc = CredentialService(pool=_mock_pool, auth_service=_mock_auth_service)
        assert hasattr(svc, "register")
        assert hasattr(svc, "check_health")
        assert hasattr(svc, "get")
        assert hasattr(svc, "delete")

    for name, fn in [
        ("AssessmentService(pool, publisher) + CreateAssessmentRequest", check_assessment_service),
        ("TenantService(pool) + method presence", check_tenant_service),
        ("QuotaService(pool) + assert_can_create_assessment", check_quota_service),
        ("CredentialService(pool, auth_service) + method presence", check_credential_service),
    ]:
        results.append(_run(name, "services", "HIGH", fn))

    return results


# ── 4. ServiceBusPublisher constructor validation ─────────────────────────────

def _publisher_checks() -> list[CheckResult]:
    results = []

    def check_publisher_with_connection_string():
        from waf_shared.messaging.service_bus import ServiceBusPublisher
        p = ServiceBusPublisher(
            connection_string="Endpoint=sb://localhost;SharedAccessKeyName=RootManageSharedAccessKey;SharedAccessKey=test=="
        )
        assert p is not None

    def check_publisher_with_namespace_and_credential():
        from waf_shared.messaging.service_bus import ServiceBusPublisher
        mock_cred = MagicMock()
        p = ServiceBusPublisher(
            fully_qualified_namespace="wafagent.servicebus.windows.net",
            credential=mock_cred,
        )
        assert p is not None

    def check_publisher_rejects_empty_constructor():
        from waf_shared.messaging.service_bus import ServiceBusPublisher
        try:
            ServiceBusPublisher()
            assert False, "ServiceBusPublisher() with no args should raise ValueError"
        except ValueError as e:
            assert "connection_string" in str(e).lower() or "namespace" in str(e).lower()

    def check_publisher_rejects_namespace_without_credential():
        from waf_shared.messaging.service_bus import ServiceBusPublisher
        try:
            ServiceBusPublisher(fully_qualified_namespace="test.servicebus.windows.net")
            assert False, "Publisher with namespace but no credential should raise ValueError"
        except ValueError:
            pass

    for name, fn in [
        ("ServiceBusPublisher accepts connection_string", check_publisher_with_connection_string),
        ("ServiceBusPublisher accepts namespace + credential", check_publisher_with_namespace_and_credential),
        ("ServiceBusPublisher rejects empty constructor", check_publisher_rejects_empty_constructor),
        ("ServiceBusPublisher rejects namespace without credential", check_publisher_rejects_namespace_without_credential),
    ]:
        results.append(_run(name, "service_bus", "HIGH", fn))

    return results


# ── 5. DatabasePool constructor validation ────────────────────────────────────

def _pool_checks() -> list[CheckResult]:
    results = []

    def check_pool_constructor():
        from waf_shared.db.pool import DatabasePool
        pool = DatabasePool(
            dsn_primary="postgresql://wafagent:test@localhost:5432/wafagent",
            dsn_readonly=None,
            min_size=2,
            max_size=10,
        )
        assert pool is not None
        assert hasattr(pool, "connect")
        assert hasattr(pool, "disconnect")
        assert hasattr(pool, "acquire_write")
        assert hasattr(pool, "acquire_read")
        assert hasattr(pool, "healthcheck")

    def check_pool_readonly_optional():
        from waf_shared.db.pool import DatabasePool
        pool_no_replica = DatabasePool(
            dsn_primary="postgresql://wafagent:test@localhost:5432/wafagent",
            dsn_readonly=None,
        )
        pool_with_replica = DatabasePool(
            dsn_primary="postgresql://wafagent:test@localhost:5432/wafagent",
            dsn_readonly="postgresql://wafagent:test@localhost-ro:5432/wafagent",
        )
        assert pool_no_replica is not None
        assert pool_with_replica is not None

    for name, fn in [
        ("DatabasePool constructor + all lifecycle methods present", check_pool_constructor),
        ("DatabasePool dsn_readonly is optional (None = use primary)", check_pool_readonly_optional),
    ]:
        results.append(_run(name, "db_pool", "CRITICAL", fn))

    return results


# ── 6. FastAPI app creation ───────────────────────────────────────────────────

def _fastapi_checks() -> list[CheckResult]:
    results = []

    def check_create_app():
        from waf_api.main import create_app
        app = create_app()
        assert app is not None
        assert app.title == "WAF Review Agent API"

    def check_routes_registered():
        from waf_api.main import create_app
        app = create_app()
        route_paths = {r.path for r in app.routes if hasattr(r, "path")}
        # Health probes
        assert "/healthz" in route_paths, f"/healthz not in routes: {route_paths}"
        assert "/readyz" in route_paths, f"/readyz not in routes: {route_paths}"
        # Assessment endpoints
        assert "/api/v1/assessments" in route_paths, (
            f"/api/v1/assessments not in routes: {route_paths}"
        )
        assert "/api/v1/assessments/{assessment_id}" in route_paths
        assert "/api/v1/assessments/{assessment_id}/cancel" in route_paths

    def check_exception_handlers():
        from waf_api.main import create_app
        from waf_shared.domain.errors.domain_errors import AssessmentNotFoundError, QuotaExceededException
        from waf_shared.domain.errors.application_errors import IdempotencyConflictError
        app = create_app()
        # exception_handlers is a dict keyed by exception class
        handled = set(app.exception_handlers.keys())
        required = {AssessmentNotFoundError, QuotaExceededException, IdempotencyConflictError}
        missing = required - handled
        assert not missing, f"Missing exception handlers: {[e.__name__ for e in missing]}"

    def check_middleware_configured():
        from waf_api.main import create_app
        from waf_api.middleware.auth import AuthMiddleware
        app = create_app()
        # app.user_middleware is a list of Middleware objects; check AuthMiddleware is in there
        middleware_classes = [m.cls for m in app.user_middleware if hasattr(m, "cls")]
        assert AuthMiddleware in middleware_classes, (
            f"AuthMiddleware not in user_middleware. Found: {[c.__name__ for c in middleware_classes]}"
        )

    for name, fn in [
        ("create_app() returns FastAPI app with correct title", check_create_app),
        ("All 5 assessment routes + 2 health routes registered", check_routes_registered),
        ("Exception handlers registered for domain errors", check_exception_handlers),
        ("AuthMiddleware registered in middleware stack", check_middleware_configured),
    ]:
        results.append(_run(name, "fastapi", "CRITICAL", fn))

    return results


# ── 7. Credential provider factory ───────────────────────────────────────────

def _credential_provider_checks() -> list[CheckResult]:
    results = []

    def check_default_chain_factory():
        from waf_shared.auth.config import AuthMode, PlatformAuthConfig
        from waf_shared.auth.credential_provider import create_platform_provider, _DefaultAzureCredentialProvider
        config = PlatformAuthConfig(mode=AuthMode.DEFAULT_CHAIN)
        provider = create_platform_provider(config)
        assert isinstance(provider, _DefaultAzureCredentialProvider)
        assert hasattr(provider, "get_credential")
        assert hasattr(provider, "get_token")
        assert hasattr(provider, "close")

    def check_cross_tenant_provider_structure():
        from waf_shared.auth.credential_provider import CrossTenantCredentialProvider
        mock_platform = MagicMock()
        provider = CrossTenantCredentialProvider(
            keyvault_uri="https://kv-test.vault.azure.net/",
            platform_provider=mock_platform,
        )
        assert hasattr(provider, "get_credential_for_subscription")
        assert hasattr(provider, "invalidate_cache")
        assert hasattr(provider, "close")

    for name, fn in [
        ("create_platform_provider(DEFAULT_CHAIN) returns _DefaultAzureCredentialProvider", check_default_chain_factory),
        ("CrossTenantCredentialProvider constructor + method presence", check_cross_tenant_provider_structure),
    ]:
        results.append(_run(name, "credentials", "HIGH", fn))

    return results


# ── Public API ────────────────────────────────────────────────────────────────

def run() -> list[CheckResult]:
    all_results: list[CheckResult] = []
    all_results.extend(_container_checks())
    all_results.extend(_repository_checks())
    all_results.extend(_service_checks())
    all_results.extend(_publisher_checks())
    all_results.extend(_pool_checks())
    all_results.extend(_fastapi_checks())
    all_results.extend(_credential_provider_checks())
    return all_results


def main() -> int:
    results = run()
    _print_report(results, "Dependency Validation")
    critical_failures = [r for r in results if r.is_failure and r.severity in ("CRITICAL", "HIGH")]
    return 1 if critical_failures else 0


if __name__ == "__main__":
    sys.exit(main())
