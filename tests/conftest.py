"""Global pytest configuration — markers, shared fixtures, test database setup."""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
import pytest_asyncio

from waf_shared.domain.models.assessment import Assessment, AssessmentStatus
from waf_shared.domain.models.tenant import PlanTier, Tenant, TenantQuota, UserRole


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "unit: fast tests with no I/O")
    config.addinivalue_line("markers", "integration: requires Docker Compose services")
    config.addinivalue_line("markers", "contract: Pact consumer/provider tests")
    config.addinivalue_line("markers", "e2e: staging environment required")
    config.addinivalue_line("markers", "smoke: minimal e2e subset run in CI post-deploy")
    config.addinivalue_line("markers", "slow: long-running tests (live Azure)")


@pytest.fixture(scope="session")
def event_loop_policy() -> asyncio.DefaultEventLoopPolicy:
    return asyncio.DefaultEventLoopPolicy()


@pytest.fixture
def tenant_id() -> uuid.UUID:
    return uuid.UUID("11111111-1111-1111-1111-111111111111")


@pytest.fixture
def other_tenant_id() -> uuid.UUID:
    return uuid.UUID("22222222-2222-2222-2222-222222222222")


@pytest.fixture
def assessment_id() -> uuid.UUID:
    return uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")


@pytest.fixture
def user_oid() -> uuid.UUID:
    return uuid.UUID("cccccccc-cccc-cccc-cccc-cccccccccccc")


@pytest.fixture
def sample_tenant(tenant_id: uuid.UUID) -> Tenant:
    return Tenant(
        id=tenant_id,
        slug="acme-corp",
        display_name="ACME Corporation",
        azure_tenant_id=uuid.uuid4(),
        plan_tier=PlanTier.STANDARD,
        is_active=True,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


@pytest.fixture
def sample_quota(tenant_id: uuid.UUID) -> TenantQuota:
    return TenantQuota(
        tenant_id=tenant_id,
        max_concurrent_assessments=3,
        max_monthly_assessments=20,
        max_subscriptions_per_assessment=10,
        max_resources_per_assessment=5000,
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )


@pytest.fixture
def sample_assessment(assessment_id: uuid.UUID, tenant_id: uuid.UUID, user_oid: uuid.UUID) -> Assessment:
    return Assessment(
        id=assessment_id,
        tenant_id=tenant_id,
        idempotency_key="test-idempotency-key-001",
        status=AssessmentStatus.PENDING,
        subscription_ids=[uuid.uuid4()],
        pillar_filter=None,
        tag_filter=None,
        requested_by_oid=user_oid,
        total_batches=None,
        completed_batches=0,
        cancellation_requested_at=None,
        created_at=datetime(2026, 1, 1, tzinfo=UTC),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
    )
