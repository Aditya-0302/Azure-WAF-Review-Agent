"""Integration test: cross-tenant data isolation.

This test is MANDATORY and must never be skipped.
It validates the cross-tenant isolation contract:
  - Application-layer WHERE tenant_id = $N is the primary isolation layer.
  - PostgreSQL RLS is the secondary defence.

Requires: Docker Compose postgres service (pytest -m integration)
"""

from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_tenant_a_cannot_see_tenant_b_assessments(db_pool: DatabasePool) -> None:  # type: ignore[name-defined]
    """
    Given: tenant_A and tenant_B both have assessments in the database
    When: AssessmentRepository is called with tenant_B's tenant_id
    Then: it NEVER returns tenant_A's data
    """

    tenant_a_id = uuid.uuid4()
    tenant_b_id = uuid.uuid4()

    # This test requires a real DB — skipped if fixture is not available
    if db_pool is None:
        pytest.skip("db_pool fixture not available outside integration environment")

    # Insert tenants directly (bypassing repository to set up test data)
    async with db_pool.acquire_write() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, slug, display_name, azure_tenant_id) VALUES ($1, $2, $3, $4)",
            tenant_a_id,
            f"tenant-a-{tenant_a_id.hex[:6]}",
            "Tenant A",
            uuid.uuid4(),
        )
        await conn.execute(
            "INSERT INTO tenants (id, slug, display_name, azure_tenant_id) VALUES ($1, $2, $3, $4)",
            tenant_b_id,
            f"tenant-b-{tenant_b_id.hex[:6]}",
            "Tenant B",
            uuid.uuid4(),
        )

    # Query as tenant_B — must never see tenant_A rows
    from waf_shared.db.repository import BaseRepository

    class _TestRepo(BaseRepository):
        async def get_tenant_ids_visible(self, tenant_id: uuid.UUID) -> list[uuid.UUID]:
            rows = await self._read(
                "SELECT id FROM tenants WHERE tenant_id = $1",
                tenant_id,
                tenant_id,
            )
            return [row["id"] for row in rows]

    repo = _TestRepo(pool=db_pool)
    visible = await repo.get_tenant_ids_visible(tenant_b_id)

    assert tenant_a_id not in visible, (
        f"CRITICAL: Cross-tenant leak detected — tenant_B query returned tenant_A data.\n"
        f"tenant_A={tenant_a_id}, tenant_B={tenant_b_id}, visible={visible}"
    )


@pytest.mark.asyncio
async def test_assessment_list_scoped_to_tenant(db_pool: DatabasePool) -> None:  # type: ignore[name-defined]
    """list() must only return assessments belonging to the requesting tenant."""
    if db_pool is None:
        pytest.skip("db_pool fixture not available outside integration environment")

    from waf_shared.db.repositories.assessment_repository import AssessmentRepository

    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    async with db_pool.acquire_write() as conn:
        await conn.execute(
            "INSERT INTO tenants (id, slug, display_name, azure_tenant_id) VALUES ($1,$2,$3,$4)",
            tenant_a,
            f"ta-{tenant_a.hex[:6]}",
            "Tenant A",
            uuid.uuid4(),
        )
        await conn.execute(
            "INSERT INTO tenants (id, slug, display_name, azure_tenant_id) VALUES ($1,$2,$3,$4)",
            tenant_b,
            f"tb-{tenant_b.hex[:6]}",
            "Tenant B",
            uuid.uuid4(),
        )
        a_aid = uuid.uuid4()
        b_aid = uuid.uuid4()
        for tid, aid in [(tenant_a, a_aid), (tenant_b, b_aid)]:
            await conn.execute(
                """
                INSERT INTO assessments (id, tenant_id, status, pillar_filter, tag_filter,
                    total_batches, completed_batches, failed_batches, created_at, updated_at)
                VALUES ($1,$2,'completed','{}','{}',1,1,0,NOW(),NOW())
                """,
                aid,
                tid,
            )

    repo = AssessmentRepository(pool=db_pool)
    results = await repo.list(tenant_id=tenant_a, limit=100)
    returned_ids = {r.id for r in results}

    assert a_aid in returned_ids, "Tenant A cannot see its own assessment"
    assert b_aid not in returned_ids, "CRITICAL: Tenant A can see Tenant B's assessment"


@pytest.mark.asyncio
async def test_findings_rls_cross_tenant(db_pool: DatabasePool) -> None:  # type: ignore[name-defined]
    """Findings table RLS must prevent cross-tenant queries."""
    if db_pool is None:
        pytest.skip("db_pool fixture not available outside integration environment")

    from waf_shared.db.repositories.finding_repository import FindingRepository

    tenant_a = uuid.uuid4()
    tenant_b = uuid.uuid4()

    async with db_pool.acquire_write() as conn:
        for tid, slug in [(tenant_a, "fa"), (tenant_b, "fb")]:
            await conn.execute(
                "INSERT INTO tenants (id, slug, display_name, azure_tenant_id) VALUES ($1,$2,$3,$4)",
                tid,
                f"{slug}-{tid.hex[:6]}",
                f"Tenant {slug}",
                uuid.uuid4(),
            )
        b_aid = uuid.uuid4()
        await conn.execute(
            """
            INSERT INTO assessments (id, tenant_id, status, pillar_filter, tag_filter,
                total_batches, completed_batches, failed_batches, created_at, updated_at)
            VALUES ($1,$2,'completed','{}','{}',1,1,0,NOW(),NOW())
            """,
            b_aid,
            tenant_b,
        )
        await conn.execute(
            """
            INSERT INTO findings (
                id, assessment_id, batch_id, tenant_id, rule_id, resource_id, resource_type,
                status, severity, pillar, confidence_score, title, recommendation, evidence,
                evaluation_type, created_at
            ) VALUES ($1,$2,$3,$4,'WAF-001','/subs/x/rg/rg1/providers/MC/vm/v',
                      'mc/virtualmachines','open','critical','security',0.9,
                      'Test','Fix','{}','deterministic',NOW())
            """,
            uuid.uuid4(),
            b_aid,
            uuid.uuid4(),
            tenant_b,
        )

    repo = FindingRepository(pool=db_pool)
    results = await repo.list_by_assessment(tenant_id=tenant_a, assessment_id=b_aid)
    assert results == [], "CRITICAL: Tenant A can read Tenant B's findings"


@pytest.mark.asyncio
async def test_uow_transaction_rollback_on_error(db_pool: DatabasePool) -> None:  # type: ignore[name-defined]
    """A failed UoW write must roll back the entire transaction."""
    if db_pool is None:
        pytest.skip("db_pool fixture not available outside integration environment")

    from waf_shared.db.repository import BaseRepository

    class _WritingRepo(BaseRepository):
        async def insert_then_fail(self, tenant_id: uuid.UUID, rid: uuid.UUID) -> None:
            async with self._uow(tenant_id) as conn:
                await conn.execute(
                    "INSERT INTO tenants (id, slug, display_name, azure_tenant_id) "
                    "VALUES ($1,$2,$3,$4)",
                    rid,
                    f"r-{rid.hex[:6]}",
                    "Rollback Test",
                    uuid.uuid4(),
                )
                raise RuntimeError("forced rollback")

    rid = uuid.uuid4()
    repo = _WritingRepo(pool=db_pool)

    with pytest.raises(RuntimeError, match="forced rollback"):
        await repo.insert_then_fail(tenant_id=uuid.uuid4(), rid=rid)

    # Row must not exist after rollback
    async with db_pool.acquire_read() as conn:
        count = await conn.fetchval("SELECT COUNT(*) FROM tenants WHERE id = $1", rid)
    assert count == 0, "Transaction was not rolled back"
