"""Domain object factories for tests.

These are plain Python factory functions — not ORM factories.
They produce domain models with sensible defaults that can be overridden.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from waf_shared.domain.models.assessment import Assessment, AssessmentBatch, AssessmentStatus, BatchStatus
from waf_shared.domain.models.credential import CredentialHealth, SubscriptionCredential
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule
from waf_shared.domain.models.tenant import PlanTier, Tenant, TenantQuota, TenantUser, UserRole


def make_tenant(
    *,
    tenant_id: uuid.UUID | None = None,
    slug: str = "test-tenant",
    plan_tier: PlanTier = PlanTier.STANDARD,
    is_active: bool = True,
) -> Tenant:
    return Tenant(
        id=tenant_id or uuid.uuid4(),
        slug=slug,
        display_name=f"Test Tenant ({slug})",
        azure_tenant_id=uuid.uuid4(),
        plan_tier=plan_tier,
        is_active=is_active,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def make_tenant_quota(
    *,
    tenant_id: uuid.UUID | None = None,
    max_concurrent_assessments: int = 3,
    max_monthly_assessments: int = 20,
) -> TenantQuota:
    return TenantQuota(
        tenant_id=tenant_id or uuid.uuid4(),
        max_concurrent_assessments=max_concurrent_assessments,
        max_monthly_assessments=max_monthly_assessments,
        max_subscriptions_per_assessment=10,
        max_resources_per_assessment=5000,
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def make_assessment(
    *,
    assessment_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    status: AssessmentStatus = AssessmentStatus.PENDING,
    subscription_count: int = 1,
) -> Assessment:
    return Assessment(
        id=assessment_id or uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        idempotency_key=f"key-{uuid.uuid4().hex[:8]}",
        status=status,
        subscription_ids=[uuid.uuid4() for _ in range(subscription_count)],
        pillar_filter=None,
        tag_filter=None,
        requested_by_oid=uuid.uuid4(),
        total_batches=None,
        completed_batches=0,
        cancellation_requested_at=None,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def make_finding(
    *,
    finding_id: uuid.UUID | None = None,
    assessment_id: uuid.UUID | None = None,
    tenant_id: uuid.UUID | None = None,
    severity: Severity = Severity.HIGH,
    confidence_score: float = 0.9,
) -> Finding:
    return Finding(
        id=finding_id or uuid.uuid4(),
        assessment_id=assessment_id or uuid.uuid4(),
        batch_id=uuid.uuid4(),
        tenant_id=tenant_id or uuid.uuid4(),
        rule_id="REL-VM-001",
        resource_id="/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1",
        resource_type="microsoft.compute/virtualmachines",
        status=FindingStatus.OPEN,
        severity=severity,
        pillar=Pillar.RELIABILITY.value,
        confidence_score=confidence_score,
        title="Virtual machine availability zone not configured",
        recommendation="Deploy across availability zones for HA.",
        evidence={"current_zones": [], "recommended_zones": [1, 2, 3]},
        evaluation_type=EvaluationType.DETERMINISTIC.value,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


def make_waf_rule(
    *,
    rule_id: str = "REL-VM-001",
    pillar: Pillar = Pillar.RELIABILITY,
    evaluation_type: EvaluationType = EvaluationType.DETERMINISTIC,
) -> WafRule:
    return WafRule(
        id=uuid.uuid4(),
        rule_id=rule_id,
        pillar=pillar,
        resource_types=["microsoft.compute/virtualmachines"],
        evaluation_type=evaluation_type,
        condition_dsl={"op": "eq", "path": "properties.zones", "value": []},
        prompt_template_ref=None,
        severity=Severity.HIGH.value,
        title="VM availability zones not configured",
        description="Virtual machines without zone configuration have no redundancy.",
        recommendation="Configure availability zones 1, 2, 3.",
        is_active=True,
        version=1,
    )
