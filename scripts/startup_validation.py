#!/usr/bin/env python3
"""Startup validation — verifies all imports resolve and static invariants hold.

Checks (no I/O required, safe before any infrastructure is available):
  1. All Python modules import without error
  2. Domain models instantiate with valid data
  3. All StrEnum values are complete (catches missing ADVISOR_MAPPED, etc.)
  4. Settings parse with environment defaults
  5. Error hierarchy constructors work correctly
  6. CloudEventEnvelope wrap + JSON roundtrip
  7. All queue name constants are non-empty strings

Usage:
  python scripts/startup_validation.py
  python -m scripts.startup_validation   # from project root
"""
from __future__ import annotations

import dataclasses
import importlib
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path

# ── Path bootstrap — adds all src packages to sys.path ───────────────────────
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


# ── Shared result type (imported by other validation scripts) ─────────────────

@dataclasses.dataclass
class CheckResult:
    name: str
    category: str
    severity: str    # CRITICAL | HIGH | MEDIUM | LOW
    passed: bool
    error: str | None
    duration_ms: float
    skipped: bool = False
    skip_reason: str | None = None

    @property
    def is_failure(self) -> bool:
        return not self.passed and not self.skipped


class _SkipCheck(Exception):
    """Raised inside a check function to mark the check as skipped."""


def _run(name: str, category: str, severity: str, fn) -> CheckResult:
    start = time.monotonic()
    try:
        fn()
        return CheckResult(
            name=name, category=category, severity=severity,
            passed=True, error=None,
            duration_ms=(time.monotonic() - start) * 1000,
        )
    except _SkipCheck as exc:
        return CheckResult(
            name=name, category=category, severity=severity,
            passed=False, error=None, duration_ms=0,
            skipped=True, skip_reason=str(exc),
        )
    except Exception as exc:
        return CheckResult(
            name=name, category=category, severity=severity,
            passed=False,
            error=f"{type(exc).__name__}: {exc}",
            duration_ms=(time.monotonic() - start) * 1000,
        )


# ── 1. Module import checks ───────────────────────────────────────────────────

_MODULES: list[tuple[str, str]] = [
    # shared — critical path
    ("waf_shared.db.pool",                                     "CRITICAL"),
    ("waf_shared.db.repository",                               "CRITICAL"),
    ("waf_shared.db.unit_of_work",                             "HIGH"),
    ("waf_shared.db.repositories.assessment_repository",       "CRITICAL"),
    ("waf_shared.db.repositories.credential_repository",       "HIGH"),
    ("waf_shared.db.repositories.finding_repository",          "HIGH"),
    ("waf_shared.db.repositories.rule_repository",             "HIGH"),
    ("waf_shared.db.repositories.tenant_repository",           "HIGH"),
    ("waf_shared.db.repositories.report_repository",           "MEDIUM"),
    ("waf_shared.domain.models.assessment",                    "CRITICAL"),
    ("waf_shared.domain.models.tenant",                        "CRITICAL"),
    ("waf_shared.domain.models.finding",                       "HIGH"),
    ("waf_shared.domain.models.rule",                          "HIGH"),
    ("waf_shared.domain.models.credential",                    "HIGH"),
    ("waf_shared.domain.models.report",                        "MEDIUM"),
    ("waf_shared.domain.errors.domain_errors",                 "CRITICAL"),
    ("waf_shared.domain.errors.application_errors",            "CRITICAL"),
    ("waf_shared.domain.errors.infrastructure_errors",         "HIGH"),
    ("waf_shared.domain.events.assessment_events",             "CRITICAL"),
    ("waf_shared.domain.events.base",                          "CRITICAL"),
    ("waf_shared.messaging.service_bus",                       "CRITICAL"),
    ("waf_shared.messaging.queue_names",                       "CRITICAL"),
    ("waf_shared.auth.models",                                 "CRITICAL"),
    ("waf_shared.auth.config",                                 "CRITICAL"),
    ("waf_shared.auth.credential_provider",                    "CRITICAL"),
    ("waf_shared.auth.auth_service",                           "HIGH"),
    ("waf_shared.auth.authz_service",                          "HIGH"),
    ("waf_shared.agents.settings",                             "CRITICAL"),
    ("waf_shared.telemetry.logging",                           "CRITICAL"),
    ("waf_shared.telemetry.metrics",                           "HIGH"),
    # API
    ("waf_api.config",                                         "CRITICAL"),
    ("waf_api.container",                                      "CRITICAL"),
    ("waf_api.main",                                           "CRITICAL"),
    ("waf_api.middleware.auth",                                "CRITICAL"),
    ("waf_api.middleware.security_headers",                    "HIGH"),
    ("waf_api.middleware.telemetry",                           "HIGH"),
    ("waf_api.routers.health",                                 "CRITICAL"),
    ("waf_api.routers.assessments",                            "CRITICAL"),
    ("waf_api.schemas.requests.assessment_requests",           "HIGH"),
    ("waf_api.schemas.responses.pagination_response",          "HIGH"),
    ("waf_api.schemas.responses.error_response",               "HIGH"),
    ("waf_api.services.assessment_service",                    "CRITICAL"),
    ("waf_api.services.tenant_service",                        "HIGH"),
    ("waf_api.services.credential_service",                    "HIGH"),
    ("waf_api.services.quota_service",                         "HIGH"),
    ("waf_api.dependencies.db",                                "CRITICAL"),
    ("waf_api.dependencies.rbac",                              "CRITICAL"),
    ("waf_api.dependencies.services",                          "HIGH"),
    # agents
    ("waf_preparation.config",                                 "HIGH"),
    ("waf_preparation.handler",                                "HIGH"),
    ("waf_extraction.config",                                  "HIGH"),
    ("waf_extraction.handler",                                 "HIGH"),
    ("waf_reasoning.config",                                   "HIGH"),
    ("waf_reasoning.handler",                                  "HIGH"),
    ("waf_reporting.config",                                   "HIGH"),
    ("waf_reporting.handler",                                  "HIGH"),
]


def _import_checks() -> list[CheckResult]:
    results = []
    for mod, severity in _MODULES:
        results.append(_run(
            name=f"import:{mod}",
            category="imports",
            severity=severity,
            fn=lambda m=mod: importlib.import_module(m),
        ))
    return results


# ── 2. Domain model instantiation ─────────────────────────────────────────────

def _domain_model_checks() -> list[CheckResult]:
    results = []

    def check_assessment():
        from waf_shared.domain.models.assessment import Assessment, AssessmentStatus, TERMINAL_STATUSES
        now = datetime.now(UTC)
        a = Assessment(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            idempotency_key="val-test-key-001",
            status=AssessmentStatus.PENDING,
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
            total_batches=None,
            completed_batches=0,
            cancellation_requested_at=None,
            created_at=now,
            updated_at=now,
        )
        assert not a.is_terminal, "PENDING should not be terminal"
        assert not a.is_cancellation_pending, "No cancellation requested"
        assert AssessmentStatus.COMPLETED in TERMINAL_STATUSES
        assert AssessmentStatus.FAILED in TERMINAL_STATUSES
        assert AssessmentStatus.CANCELLED in TERMINAL_STATUSES

    def check_tenant():
        from waf_shared.domain.models.tenant import Tenant, TenantUser, UserRole, PlanTier
        now = datetime.now(UTC)
        tid = uuid.uuid4()
        t = Tenant(
            id=tid,
            slug="validation-tenant",
            display_name="Validation Tenant",
            azure_tenant_id=uuid.uuid4(),
            plan_tier=PlanTier.STANDARD,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        assert t.is_active
        assert t.slug == "validation-tenant"
        u = TenantUser(
            id=uuid.uuid4(),
            tenant_id=tid,
            entra_oid=uuid.uuid4(),
            role=UserRole.TENANT_ADMIN,
            is_active=True,
            created_at=now,
        )
        assert u.role == UserRole.TENANT_ADMIN

    def check_finding():
        from waf_shared.domain.models.finding import Finding, Severity, FindingStatus
        now = datetime.now(UTC)
        f = Finding(
            id=uuid.uuid4(),
            assessment_id=uuid.uuid4(),
            batch_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            rule_id="SEC-STORAGE-001",
            resource_id="/subscriptions/x/resourceGroups/y/providers/Microsoft.Storage/storageAccounts/z",
            resource_type="Microsoft.Storage/storageAccounts",
            status=FindingStatus.OPEN,
            severity=Severity.HIGH,
            pillar="security",
            confidence_score=0.95,
            title="Storage account lacks HTTPS enforcement",
            recommendation="Enable HTTPS-only traffic on the storage account",
            evidence={"property": "supportsHttpsTrafficOnly", "actual": False},
            evaluation_type="deterministic",
            created_at=now,
        )
        assert f.severity == Severity.HIGH
        assert 0.0 <= f.confidence_score <= 1.0

    def check_waf_rule():
        from waf_shared.domain.models.rule import WafRule, EvaluationType, Pillar
        now = datetime.now(UTC)
        r = WafRule(
            id=uuid.uuid4(),
            rule_id="SEC-STORAGE-001",
            pillar=Pillar.SECURITY,
            resource_types=["Microsoft.Storage/storageAccounts"],
            evaluation_type=EvaluationType.DETERMINISTIC,
            condition_dsl={"field": "properties.supportsHttpsTrafficOnly", "operator": "eq", "value": True},
            prompt_template_ref=None,
            severity="high",
            title="Storage HTTPS enforcement",
            description="Azure Storage accounts must enforce HTTPS-only traffic.",
            recommendation="Enable Secure transfer required on the storage account.",
            is_active=True,
            version=1,
            created_at=now,
            updated_at=now,
        )
        assert r.evaluation_type == EvaluationType.DETERMINISTIC
        assert r.pillar == Pillar.SECURITY
        # Test ADVISOR_MAPPED variant
        r2 = WafRule(
            id=uuid.uuid4(),
            rule_id="SEC-STORAGE-002",
            pillar=Pillar.SECURITY,
            resource_types=["Microsoft.Storage/storageAccounts"],
            evaluation_type=EvaluationType.ADVISOR_MAPPED,
            condition_dsl=None,
            prompt_template_ref="advisor-security-storage",
            severity="medium",
            title="Advisor storage recommendation",
            description="Maps Azure Advisor recommendation to WAF finding.",
            recommendation="Follow Advisor recommendations for storage security.",
            is_active=True,
            version=1,
            created_at=now,
            updated_at=now,
        )
        assert r2.evaluation_type == EvaluationType.ADVISOR_MAPPED

    def check_credential():
        from waf_shared.domain.models.credential import SubscriptionCredential, CredentialHealth
        now = datetime.now(UTC)
        c = SubscriptionCredential(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            subscription_id=uuid.uuid4(),
            display_name="Test Subscription",
            keyvault_secret_name="wafagent-sub-aabbccdd",
            health=CredentialHealth.UNCHECKED,
            expires_at=None,
            last_health_check_at=None,
            created_at=now,
            updated_at=now,
        )
        assert c.health == CredentialHealth.UNCHECKED

    def check_auth_context():
        from waf_shared.auth.models import AuthContext
        from waf_shared.domain.models.tenant import UserRole
        ctx = AuthContext(
            tenant_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            role=UserRole.TENANT_ADMIN,
            entra_oid=uuid.uuid4(),
        )
        assert ctx.role == UserRole.TENANT_ADMIN
        assert isinstance(ctx.tenant_id, uuid.UUID)
        # Verify it's frozen (should raise if we try to mutate)
        try:
            ctx.role = UserRole.PLATFORM_ADMIN  # type: ignore[misc]
            assert False, "AuthContext should be frozen"
        except (dataclasses.FrozenInstanceError, AttributeError):
            pass

    for name, fn in [
        ("Assessment model instantiation + is_terminal + TERMINAL_STATUSES", check_assessment),
        ("Tenant + TenantUser model instantiation", check_tenant),
        ("Finding model instantiation + confidence_score validator", check_finding),
        ("WafRule model + DETERMINISTIC and ADVISOR_MAPPED evaluation types", check_waf_rule),
        ("SubscriptionCredential model instantiation", check_credential),
        ("AuthContext dataclass frozen + field access", check_auth_context),
    ]:
        results.append(_run(name, "domain_models", "HIGH", fn))

    return results


# ── 3. Enum completeness ──────────────────────────────────────────────────────

def _enum_checks() -> list[CheckResult]:
    results = []

    def check_assessment_status():
        from waf_shared.domain.models.assessment import AssessmentStatus
        required = {
            "PENDING", "PREPARING", "EXTRACTING", "REASONING", "REPORTING",
            "COMPLETED", "PARTIAL_FAILURE", "CANCELLED", "FAILED",
        }
        actual = {m.name for m in AssessmentStatus}
        missing = required - actual
        assert not missing, f"AssessmentStatus missing members: {missing}"

    def check_evaluation_type():
        from waf_shared.domain.models.rule import EvaluationType
        # ADVISOR_MAPPED was added as a production fix (C-6 / migration 0003)
        required = {"DETERMINISTIC", "LLM", "HYBRID", "ADVISOR_MAPPED"}
        actual = {m.name for m in EvaluationType}
        missing = required - actual
        assert not missing, (
            f"EvaluationType missing members: {missing}. "
            f"ADVISOR_MAPPED is required for advisor-mapped WAF rules."
        )
        # Also verify string values match DB enum values
        assert EvaluationType.ADVISOR_MAPPED.value == "advisor_mapped", (
            f"Expected 'advisor_mapped', got '{EvaluationType.ADVISOR_MAPPED.value}'"
        )

    def check_user_role():
        from waf_shared.domain.models.tenant import UserRole
        required = {"TENANT_ADMIN", "TENANT_VIEWER", "PLATFORM_ADMIN"}
        actual = {m.name for m in UserRole}
        missing = required - actual
        assert not missing, f"UserRole missing members: {missing}"
        # Verify values (used in router require_role calls)
        assert UserRole.TENANT_ADMIN.value == "tenant_admin"
        assert UserRole.PLATFORM_ADMIN.value == "platform_admin"
        assert UserRole.TENANT_VIEWER.value == "tenant_viewer"

    def check_severity():
        from waf_shared.domain.models.finding import Severity
        required = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}
        actual = {m.name for m in Severity}
        missing = required - actual
        assert not missing, f"Severity missing members: {missing}"

    def check_auth_mode():
        from waf_shared.auth.config import AuthMode
        required = {"MANAGED_IDENTITY", "WORKLOAD_IDENTITY", "SERVICE_PRINCIPAL", "DEFAULT_CHAIN"}
        actual = {m.name for m in AuthMode}
        missing = required - actual
        assert not missing, f"AuthMode missing members: {missing}"

    def check_pillar():
        from waf_shared.domain.models.rule import Pillar
        required = {
            "RELIABILITY", "SECURITY", "COST_OPTIMIZATION",
            "OPERATIONAL_EXCELLENCE", "PERFORMANCE_EFFICIENCY",
        }
        actual = {m.name for m in Pillar}
        missing = required - actual
        assert not missing, f"Pillar missing members: {missing}"

    for name, fn in [
        ("AssessmentStatus — all 9 members present", check_assessment_status),
        ("EvaluationType — ADVISOR_MAPPED present and value='advisor_mapped'", check_evaluation_type),
        ("UserRole — 3 members with correct string values", check_user_role),
        ("Severity — all 5 members present", check_severity),
        ("AuthMode — all 4 members present (including DEFAULT_CHAIN)", check_auth_mode),
        ("Pillar — all 5 WAF pillars present", check_pillar),
    ]:
        results.append(_run(name, "enums", "HIGH", fn))

    return results


# ── 4. Settings parse ─────────────────────────────────────────────────────────

def _settings_checks() -> list[CheckResult]:
    results = []

    def check_api_settings():
        from waf_api.config import Settings, AppEnvironment
        s = Settings()
        assert s.app_env == AppEnvironment.DEVELOPMENT
        assert s.db_host, "db_host must have a default"
        assert s.db_pool_min_size >= 1
        assert s.db_pool_max_size >= s.db_pool_min_size
        # Computed properties
        dsn = s.db_dsn_primary
        assert dsn.startswith("postgresql://"), f"Expected postgresql:// DSN, got: {dsn[:20]}"
        assert s.db_name in dsn
        # Check auth_mode field exists (needed for local dev)
        assert hasattr(s, "auth_mode"), "Settings must have auth_mode field"
        assert hasattr(s, "servicebus_connection_string"), (
            "Settings must have servicebus_connection_string for emulator"
        )

    def check_agent_settings():
        from waf_shared.agents.settings import AgentSettings
        s = AgentSettings()
        assert hasattr(s, "auth_mode"), "AgentSettings must have auth_mode (local dev)"
        assert hasattr(s, "servicebus_connection_string"), (
            "AgentSettings must have servicebus_connection_string (emulator)"
        )
        dsn = s.dsn_primary
        assert dsn.startswith("postgresql://")
        assert s.db_name in dsn

    def check_preparation_config():
        from waf_preparation.config import PreparationConfig
        c = PreparationConfig()
        assert c.batch_size >= 1, f"batch_size={c.batch_size} must be >= 1"
        assert c.max_concurrent_subscriptions >= 1

    def check_reasoning_config():
        from waf_reasoning.config import ReasoningConfig
        c = ReasoningConfig()
        assert 0.0 <= c.llm_temperature <= 2.0
        assert c.azure_openai_max_tokens >= 1
        assert c.azure_openai_api_version  # must be non-empty default

    def check_reporting_config():
        from waf_reporting.config import ReportingConfig
        c = ReportingConfig()
        assert hasattr(c, "storage_account_name")
        assert hasattr(c, "storage_reports_container")
        # Computed URL property
        c2 = ReportingConfig(storage_account_name="stwaftest")
        assert c2.storage_account_url == "https://stwaftest.blob.core.windows.net"

    for name, fn in [
        ("API Settings parse + db_dsn_primary + auth_mode + servicebus_connection_string", check_api_settings),
        ("AgentSettings parse + auth_mode + servicebus_connection_string + dsn_primary", check_agent_settings),
        ("PreparationConfig parse + batch_size + max_concurrent_subscriptions", check_preparation_config),
        ("ReasoningConfig parse + llm_temperature + api_version default", check_reasoning_config),
        ("ReportingConfig parse + storage_account_url computed property", check_reporting_config),
    ]:
        results.append(_run(name, "settings", "CRITICAL", fn))

    return results


# ── 5. Error hierarchy ────────────────────────────────────────────────────────

def _error_checks() -> list[CheckResult]:
    results = []

    def check_domain_errors():
        from waf_shared.domain.errors.domain_errors import (
            WafAgentError, DomainError, AssessmentNotFoundError, QuotaExceededException,
            InvalidAssessmentScopeError, TenantNotFoundError, PermissionDeniedError,
            CredentialNotFoundError, FindingNotFoundError, DSLValidationError,
        )
        tid = uuid.uuid4()
        aid = uuid.uuid4()
        e1 = AssessmentNotFoundError(assessment_id=aid, tenant_id=tid)
        assert e1.code == "ASSESSMENT_NOT_FOUND"
        assert isinstance(e1, DomainError)
        assert isinstance(e1, WafAgentError)

        e2 = QuotaExceededException(
            quota_name="concurrent_assessments", limit=3, current=3, tenant_id=tid
        )
        assert e2.quota_name == "concurrent_assessments"
        assert e2.limit == 3
        assert e2.code == "QUOTA_EXCEEDED"

        e3 = InvalidAssessmentScopeError("at least one subscription required")
        assert e3.code == "INVALID_SCOPE"

        e4 = DSLValidationError(rule_id="SEC-STORAGE-001", detail="unknown operator")
        assert e4.code == "DSL_VALIDATION_ERROR"

    def check_application_errors():
        from waf_shared.domain.errors.application_errors import (
            ApplicationError, IdempotencyConflictError, CancellationRequestedError,
        )
        from waf_shared.domain.errors.domain_errors import WafAgentError
        aid = uuid.uuid4()

        e1 = IdempotencyConflictError(idempotency_key="test-key-abc", existing_id=aid)
        assert e1.code == "IDEMPOTENCY_CONFLICT"
        assert e1.idempotency_key == "test-key-abc"
        assert e1.existing_id == aid
        assert isinstance(e1, ApplicationError)
        assert isinstance(e1, WafAgentError)

        e2 = CancellationRequestedError(assessment_id=aid)
        assert e2.code == "CANCELLATION_REQUESTED"
        assert e2.assessment_id == aid

    def check_infrastructure_errors():
        from waf_shared.domain.errors.infrastructure_errors import (
            InfrastructureError, DatabaseError, ConnectionPoolExhaustedError,
            CredentialUnavailableError, AzureRateLimitError, ServiceBusDeliveryError,
            KeyVaultAccessError, CrossTenantAuthError,
        )
        e1 = DatabaseError("connection refused")
        assert isinstance(e1, InfrastructureError)

        e2 = ConnectionPoolExhaustedError("primary", 5.0)
        assert e2.pool_name == "primary"
        assert e2.code == "CONNECTION_POOL_EXHAUSTED"

        e3 = CredentialUnavailableError("IMDS endpoint not reachable")
        assert e3.code == "CREDENTIAL_UNAVAILABLE"

        e4 = AzureRateLimitError("Resource Graph", retry_after_seconds=30)
        assert e4.service == "Resource Graph"
        assert e4.retry_after_seconds == 30

        e5 = ServiceBusDeliveryError("assessment.created", "connection reset")
        assert e5.queue_name == "assessment.created"
        assert e5.code == "SERVICEBUS_DELIVERY_ERROR"

    for name, fn in [
        ("Domain error hierarchy + constructors for all domain errors", check_domain_errors),
        ("IdempotencyConflictError(idempotency_key, existing_id) constructor", check_application_errors),
        ("Infrastructure error hierarchy + field access", check_infrastructure_errors),
    ]:
        results.append(_run(name, "errors", "HIGH", fn))

    return results


# ── 6. Messaging — CloudEventEnvelope + queue names ──────────────────────────

def _messaging_checks() -> list[CheckResult]:
    results = []

    def check_cloud_event_envelope():
        import json
        from waf_shared.domain.events.base import CloudEventEnvelope
        from waf_shared.domain.events.assessment_events import AssessmentCreatedEvent

        now = datetime.now(UTC)
        event_data = AssessmentCreatedEvent(
            assessment_id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
            created_at=now,
        )
        env = CloudEventEnvelope.wrap(
            event_type="com.wafagent.assessment.created",
            source="/validation",
            data=event_data,
        )
        assert env.type == "com.wafagent.assessment.created"
        assert env.source == "/validation"
        assert env.specversion == "1.0"
        assert env.datacontenttype == "application/json"
        assert isinstance(env.id, uuid.UUID)

        # Serialization roundtrip
        raw = env.to_json_bytes()
        assert isinstance(raw, bytes)
        parsed = json.loads(raw)
        assert parsed["type"] == "com.wafagent.assessment.created"
        assert parsed["specversion"] == "1.0"
        assert "data" in parsed

    def check_queue_names():
        from waf_shared.messaging import queue_names as qn
        for attr in [
            "ASSESSMENT_CREATED",
            "EXTRACTION_REQUESTED",
            "REASONING_REQUESTED",
            "REPORTING_REQUESTED",
            "ASSESSMENT_CANCELLED",
            "WEBHOOK_DELIVERY",
        ]:
            val = getattr(qn, attr, None)
            assert val is not None, f"queue_names.{attr} is not defined"
            assert isinstance(val, str) and val, f"queue_names.{attr} must be a non-empty string"

    results.append(_run(
        "CloudEventEnvelope.wrap() + to_json_bytes() roundtrip",
        "messaging", "CRITICAL", check_cloud_event_envelope,
    ))
    results.append(_run(
        "All queue name constants defined and non-empty",
        "messaging", "HIGH", check_queue_names,
    ))
    return results


# ── Public API ────────────────────────────────────────────────────────────────

def run() -> list[CheckResult]:
    all_results: list[CheckResult] = []
    all_results.extend(_import_checks())
    all_results.extend(_domain_model_checks())
    all_results.extend(_enum_checks())
    all_results.extend(_settings_checks())
    all_results.extend(_error_checks())
    all_results.extend(_messaging_checks())
    return all_results


def main() -> int:
    results = run()
    _print_report(results, "Startup Validation")
    critical_failures = [r for r in results if r.is_failure and r.severity in ("CRITICAL", "HIGH")]
    return 1 if critical_failures else 0


def _print_report(results: list[CheckResult], title: str) -> None:
    passed  = sum(1 for r in results if r.passed)
    failed  = sum(1 for r in results if r.is_failure)
    skipped = sum(1 for r in results if r.skipped)

    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")
    print(f"  Total: {len(results)}  Passed: {passed}  Failed: {failed}  Skipped: {skipped}")
    print(f"{'='*70}")

    for r in results:
        if r.skipped:
            status = "SKIP"
        elif r.passed:
            status = " OK "
        else:
            status = "FAIL"
        sev = f"[{r.severity:8s}]"
        print(f"  [{status}] {sev} {r.name}  ({r.duration_ms:.1f}ms)")
        if r.is_failure and r.error:
            for line in r.error.splitlines():
                print(f"            └─ {line}")
        elif r.skipped and r.skip_reason:
            print(f"            └─ {r.skip_reason}")
    print()


if __name__ == "__main__":
    sys.exit(main())
