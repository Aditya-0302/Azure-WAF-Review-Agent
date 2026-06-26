"""Integration tests for all repository implementations.

Requires: postgres:16 service running (see docker-compose.dev.yml).
Run with: pytest -m integration

All tests use the `db_pool` and `clean_db` fixtures from tests/integration/conftest.py.
The `clean_db` fixture truncates data tables before each test to ensure isolation.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest

pytestmark = pytest.mark.integration


# ── Helpers ───────────────────────────────────────────────────────────────────


def _slug(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


async def _insert_tenant(pool, *, tenant_id: uuid.UUID | None = None) -> uuid.UUID:
    t_id = tenant_id or uuid.uuid4()
    async with pool.acquire_write() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, slug, display_name, azure_tenant_id) "
            "VALUES ($1, $2, $3, $4)",
            t_id,
            _slug("test"),
            "Test Tenant",
            uuid.uuid4(),
        )
    return t_id


# ── Tenant Repository ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tenant_create_and_get_by_id(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.tenant_repository import TenantRepository
    from waf_shared.domain.models.tenant import PlanTier, Tenant

    repo = TenantRepository(pool=db_pool)
    tenant_id = uuid.uuid4()
    now = datetime.now(UTC)
    tenant = Tenant(
        id=tenant_id,
        slug=_slug("t"),
        display_name="Integration Tenant",
        azure_tenant_id=uuid.uuid4(),
        plan_tier=PlanTier.STANDARD,
        is_active=True,
        created_at=now,
        updated_at=now,
    )

    created = await repo.create(tenant)
    fetched = await repo.get_by_id(tenant_id)

    assert created.id == tenant_id
    assert fetched is not None
    assert fetched.id == tenant_id
    assert fetched.plan_tier == PlanTier.STANDARD


@pytest.mark.asyncio
async def test_tenant_get_by_slug(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.tenant_repository import TenantRepository
    from waf_shared.domain.models.tenant import PlanTier, Tenant

    repo = TenantRepository(pool=db_pool)
    slug = _slug("byslug")
    now = datetime.now(UTC)
    tenant = Tenant(
        id=uuid.uuid4(),
        slug=slug,
        display_name="Slug Test",
        azure_tenant_id=uuid.uuid4(),
        plan_tier=PlanTier.STANDARD,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    await repo.create(tenant)

    result = await repo.get_by_slug(slug)
    assert result is not None
    assert result.slug == slug


@pytest.mark.asyncio
async def test_tenant_update_plan_tier(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.tenant_repository import TenantRepository
    from waf_shared.domain.models.tenant import PlanTier, Tenant

    repo = TenantRepository(pool=db_pool)
    now = datetime.now(UTC)
    tenant_id = uuid.uuid4()
    tenant = Tenant(
        id=tenant_id,
        slug=_slug("pt"),
        display_name="Plan Tier Test",
        azure_tenant_id=uuid.uuid4(),
        plan_tier=PlanTier.STANDARD,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    await repo.create(tenant)

    updated = await repo.update_plan_tier(tenant_id, PlanTier.ENTERPRISE)
    assert updated.plan_tier == PlanTier.ENTERPRISE

    fetched = await repo.get_by_id(tenant_id)
    assert fetched is not None
    assert fetched.plan_tier == PlanTier.ENTERPRISE


@pytest.mark.asyncio
async def test_tenant_quota_upsert(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.tenant_repository import TenantRepository
    from waf_shared.domain.models.tenant import PlanTier, Tenant, TenantQuota

    repo = TenantRepository(pool=db_pool)
    now = datetime.now(UTC)
    tenant_id = uuid.uuid4()
    tenant = Tenant(
        id=tenant_id,
        slug=_slug("quota"),
        display_name="Quota Test",
        azure_tenant_id=uuid.uuid4(),
        plan_tier=PlanTier.PREMIUM,
        is_active=True,
        created_at=now,
        updated_at=now,
    )
    await repo.create(tenant)

    quota = TenantQuota(
        tenant_id=tenant_id,
        max_concurrent_assessments=5,
        max_monthly_assessments=50,
        max_subscriptions_per_assessment=20,
        max_resources_per_assessment=10000,
        updated_at=now,
    )
    result = await repo.upsert_quota(quota)
    assert result.max_concurrent_assessments == 5

    fetched = await repo.get_quota(tenant_id)
    assert fetched is not None
    assert fetched.max_concurrent_assessments == 5


# ── Assessment Repository ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_assessment_create_and_get(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.assessment_repository import AssessmentRepository
    from waf_shared.domain.models.assessment import Assessment, AssessmentStatus

    tenant_id = await _insert_tenant(db_pool)
    repo = AssessmentRepository(pool=db_pool)
    now = datetime.now(UTC)
    assessment_id = uuid.uuid4()

    assessment = Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        idempotency_key="idem-integ-001",
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

    created = await repo.create(assessment)
    fetched = await repo.get_by_id(tenant_id, assessment_id)

    assert created.id == assessment_id
    assert fetched is not None
    assert fetched.status == AssessmentStatus.PENDING
    assert fetched.tenant_id == tenant_id


@pytest.mark.asyncio
async def test_assessment_idempotency_key_lookup(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.assessment_repository import AssessmentRepository
    from waf_shared.domain.models.assessment import Assessment, AssessmentStatus

    tenant_id = await _insert_tenant(db_pool)
    repo = AssessmentRepository(pool=db_pool)
    now = datetime.now(UTC)
    key = f"idem-{uuid.uuid4().hex[:8]}"

    assessment = Assessment(
        id=uuid.uuid4(),
        tenant_id=tenant_id,
        idempotency_key=key,
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
    await repo.create(assessment)

    result = await repo.get_by_idempotency_key(tenant_id, key)
    assert result is not None
    assert result.idempotency_key == key


@pytest.mark.asyncio
async def test_assessment_update_status(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.assessment_repository import AssessmentRepository
    from waf_shared.domain.models.assessment import Assessment, AssessmentStatus

    tenant_id = await _insert_tenant(db_pool)
    repo = AssessmentRepository(pool=db_pool)
    now = datetime.now(UTC)
    assessment_id = uuid.uuid4()

    await repo.create(
        Assessment(
            id=assessment_id,
            tenant_id=tenant_id,
            idempotency_key="idem-status-001",
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
    )

    updated = await repo.update_status(tenant_id, assessment_id, AssessmentStatus.PREPARING)
    assert updated.status == AssessmentStatus.PREPARING


@pytest.mark.asyncio
async def test_assessment_count_active(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.assessment_repository import AssessmentRepository
    from waf_shared.domain.models.assessment import Assessment, AssessmentStatus

    tenant_id = await _insert_tenant(db_pool)
    repo = AssessmentRepository(pool=db_pool)
    now = datetime.now(UTC)

    for i in range(3):
        await repo.create(
            Assessment(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                idempotency_key=f"idem-active-{i}",
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
        )

    count = await repo.count_active(tenant_id)
    assert count == 3


@pytest.mark.asyncio
async def test_assessment_cross_tenant_isolation(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    """Assessment repository must never return another tenant's rows."""
    from waf_shared.db.repositories.assessment_repository import AssessmentRepository
    from waf_shared.domain.models.assessment import Assessment, AssessmentStatus

    tenant_a = await _insert_tenant(db_pool)
    tenant_b = await _insert_tenant(db_pool)

    repo = AssessmentRepository(pool=db_pool)
    now = datetime.now(UTC)

    await repo.create(
        Assessment(
            id=uuid.uuid4(),
            tenant_id=tenant_a,
            idempotency_key="idem-a-001",
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
    )

    # Querying as tenant_B must return nothing
    results = await repo.list_by_tenant(tenant_b)
    tenant_a_ids = {r.tenant_id for r in results}
    assert (
        tenant_a not in tenant_a_ids
    ), "CRITICAL: Cross-tenant data leak — tenant_B query returned tenant_A assessments"


# ── Unit of Work ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_uow_commit_on_clean_exit(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.assessment_repository import AssessmentRepository
    from waf_shared.db.unit_of_work import UnitOfWork
    from waf_shared.domain.models.assessment import Assessment, AssessmentStatus
    from waf_shared.domain.models.tenant import PlanTier, Tenant

    tenant_id = uuid.uuid4()
    now = datetime.now(UTC)

    # Create tenant outside UoW (system-level operation)
    from waf_shared.db.repositories.tenant_repository import TenantRepository

    tenant_repo = TenantRepository(pool=db_pool)
    await tenant_repo.create(
        Tenant(
            id=tenant_id,
            slug=_slug("uow"),
            display_name="UoW Test Tenant",
            azure_tenant_id=uuid.uuid4(),
            plan_tier=PlanTier.STANDARD,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
    )

    assessment_id = uuid.uuid4()
    uow = UnitOfWork(pool=db_pool)

    async with uow.begin(tenant_id) as work:
        await work.assessments.create(
            Assessment(
                id=assessment_id,
                tenant_id=tenant_id,
                idempotency_key="uow-idem-001",
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
        )

    # Verify it was committed
    repo = AssessmentRepository(pool=db_pool)
    fetched = await repo.get_by_id(tenant_id, assessment_id)
    assert fetched is not None
    assert fetched.id == assessment_id


@pytest.mark.asyncio
async def test_uow_rollback_on_exception(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.assessment_repository import AssessmentRepository
    from waf_shared.db.unit_of_work import UnitOfWork
    from waf_shared.domain.models.assessment import Assessment, AssessmentStatus
    from waf_shared.domain.models.tenant import PlanTier, Tenant

    tenant_id = uuid.uuid4()
    now = datetime.now(UTC)

    from waf_shared.db.repositories.tenant_repository import TenantRepository

    await TenantRepository(pool=db_pool).create(
        Tenant(
            id=tenant_id,
            slug=_slug("uow-rb"),
            display_name="Rollback Test",
            azure_tenant_id=uuid.uuid4(),
            plan_tier=PlanTier.STANDARD,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
    )

    assessment_id = uuid.uuid4()
    uow = UnitOfWork(pool=db_pool)

    with pytest.raises(RuntimeError):
        async with uow.begin(tenant_id) as work:
            await work.assessments.create(
                Assessment(
                    id=assessment_id,
                    tenant_id=tenant_id,
                    idempotency_key="uow-rb-001",
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
            )
            raise RuntimeError("intentional failure to trigger rollback")

    # Verify the row was NOT committed
    repo = AssessmentRepository(pool=db_pool)
    fetched = await repo.get_by_id(tenant_id, assessment_id)
    assert fetched is None, "Row should not exist after rollback"


# ── WAF Rule Repository ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_rule_upsert_and_get(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.rule_repository import WafRuleRepository
    from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule

    repo = WafRuleRepository(pool=db_pool)
    now = datetime.now(UTC)

    rule = WafRule(
        id=uuid.uuid4(),
        rule_id="REL-VM-999",
        pillar=Pillar.RELIABILITY,
        resource_types=["Microsoft.Compute/virtualMachines"],
        evaluation_type=EvaluationType.DETERMINISTIC,
        condition_dsl={"op": "eq", "path": "$.sku.name", "value": "Standard_DS1_v2"},
        prompt_template_ref=None,
        severity="high",
        title="Test Rule",
        description="Integration test rule",
        recommendation="Fix the VM",
        is_active=True,
        version=1,
        created_at=now,
        updated_at=now,
    )

    upserted = await repo.upsert(rule)
    fetched = await repo.get_by_rule_id("REL-VM-999")

    assert upserted.rule_id == "REL-VM-999"
    assert fetched is not None
    assert fetched.pillar == Pillar.RELIABILITY
    assert fetched.condition_dsl == {"op": "eq", "path": "$.sku.name", "value": "Standard_DS1_v2"}


@pytest.mark.asyncio
async def test_rule_list_active_by_pillar(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.rule_repository import WafRuleRepository
    from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule

    repo = WafRuleRepository(pool=db_pool)
    now = datetime.now(UTC)

    for i, pillar in enumerate([Pillar.RELIABILITY, Pillar.RELIABILITY, Pillar.SECURITY]):
        await repo.upsert(
            WafRule(
                id=uuid.uuid4(),
                rule_id=f"TEST-VM-{800 + i}",
                pillar=pillar,
                resource_types=["Microsoft.Compute/virtualMachines"],
                evaluation_type=EvaluationType.DETERMINISTIC,
                condition_dsl={"op": "is_not_null", "path": "$.id"},
                prompt_template_ref=None,
                severity="medium",
                title=f"Rule {i}",
                description=f"Desc {i}",
                recommendation=f"Fix {i}",
                is_active=True,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )

    rel_rules = await repo.list_active(pillar=Pillar.RELIABILITY)
    sec_rules = await repo.list_active(pillar=Pillar.SECURITY)

    assert len(rel_rules) >= 2
    assert len(sec_rules) >= 1
    assert all(r.pillar == Pillar.RELIABILITY for r in rel_rules)
    assert all(r.pillar == Pillar.SECURITY for r in sec_rules)


@pytest.mark.asyncio
async def test_rule_deactivate(db_pool, clean_db) -> None:  # type: ignore[no-untyped-def]
    from waf_shared.db.repositories.rule_repository import WafRuleRepository
    from waf_shared.domain.models.rule import EvaluationType, Pillar, WafRule

    repo = WafRuleRepository(pool=db_pool)
    now = datetime.now(UTC)

    await repo.upsert(
        WafRule(
            id=uuid.uuid4(),
            rule_id="SEC-DEACT-001",
            pillar=Pillar.SECURITY,
            resource_types=["Microsoft.KeyVault/vaults"],
            evaluation_type=EvaluationType.LLM,
            condition_dsl=None,
            prompt_template_ref="security/keyvault_check",
            severity="critical",
            title="Deactivation test",
            description="Will be deactivated",
            recommendation="N/A",
            is_active=True,
            version=1,
            created_at=now,
            updated_at=now,
        )
    )

    await repo.deactivate("SEC-DEACT-001")

    fetched = await repo.get_by_rule_id("SEC-DEACT-001")
    assert fetched is not None
    assert fetched.is_active is False
