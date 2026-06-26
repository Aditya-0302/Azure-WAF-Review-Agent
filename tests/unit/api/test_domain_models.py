"""Unit tests for domain model validation invariants."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from waf_shared.domain.models.assessment import Assessment, AssessmentStatus
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity
from waf_shared.domain.models.tenant import PlanTier, Tenant, TenantQuota


class TestAssessmentModel:
    def test_assessment_requires_at_least_one_subscription(self) -> None:
        with pytest.raises(ValidationError, match="at least one subscription"):
            Assessment(
                id=uuid.uuid4(),
                tenant_id=uuid.uuid4(),
                idempotency_key="key",
                status=AssessmentStatus.PENDING,
                subscription_ids=[],  # invalid
                pillar_filter=None,
                tag_filter=None,
                requested_by_oid=uuid.uuid4(),
                total_batches=None,
                completed_batches=0,
                cancellation_requested_at=None,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

    def test_assessment_is_terminal_completed(self) -> None:
        assessment = Assessment(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            idempotency_key="key",
            status=AssessmentStatus.COMPLETED,
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
            total_batches=5,
            completed_batches=5,
            cancellation_requested_at=None,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert assessment.is_terminal is True

    def test_assessment_is_not_terminal_when_pending(self) -> None:
        assessment = Assessment(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            idempotency_key="key",
            status=AssessmentStatus.PENDING,
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
            total_batches=None,
            completed_batches=0,
            cancellation_requested_at=None,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert assessment.is_terminal is False

    def test_assessment_is_immutable(self) -> None:
        assessment = Assessment(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            idempotency_key="key",
            status=AssessmentStatus.PENDING,
            subscription_ids=[uuid.uuid4()],
            pillar_filter=None,
            tag_filter=None,
            requested_by_oid=uuid.uuid4(),
            total_batches=None,
            completed_batches=0,
            cancellation_requested_at=None,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        with pytest.raises(ValidationError):
            assessment.status = AssessmentStatus.COMPLETED  # type: ignore[misc]


class TestFindingModel:
    def test_confidence_score_below_zero_rejected(self) -> None:
        with pytest.raises(ValidationError, match="between 0.0 and 1.0"):
            Finding(
                id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                batch_id=uuid.uuid4(),
                tenant_id=uuid.uuid4(),
                rule_id="REL-VM-001",
                resource_id="res-1",
                resource_type="microsoft.compute/virtualmachines",
                status=FindingStatus.OPEN,
                severity=Severity.HIGH,
                pillar="reliability",
                confidence_score=-0.1,  # invalid
                title="Test",
                recommendation="Fix it",
                evidence={},
                evaluation_type="deterministic",
                created_at=datetime.now(UTC),
            )

    def test_confidence_score_above_one_rejected(self) -> None:
        with pytest.raises(ValidationError, match="between 0.0 and 1.0"):
            Finding(
                id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                batch_id=uuid.uuid4(),
                tenant_id=uuid.uuid4(),
                rule_id="REL-VM-001",
                resource_id="res-1",
                resource_type="microsoft.compute/virtualmachines",
                status=FindingStatus.OPEN,
                severity=Severity.HIGH,
                pillar="reliability",
                confidence_score=1.01,  # invalid
                title="Test",
                recommendation="Fix it",
                evidence={},
                evaluation_type="deterministic",
                created_at=datetime.now(UTC),
            )

    def test_confidence_score_boundary_values_accepted(self) -> None:
        for score in (0.0, 0.5, 1.0):
            finding = Finding(
                id=uuid.uuid4(),
                assessment_id=uuid.uuid4(),
                batch_id=uuid.uuid4(),
                tenant_id=uuid.uuid4(),
                rule_id="REL-VM-001",
                resource_id="res-1",
                resource_type="microsoft.compute/virtualmachines",
                status=FindingStatus.OPEN,
                severity=Severity.HIGH,
                pillar="reliability",
                confidence_score=score,
                title="Test",
                recommendation="Fix it",
                evidence={},
                evaluation_type="deterministic",
                created_at=datetime.now(UTC),
            )
            assert finding.confidence_score == score


class TestTenantModel:
    def test_slug_must_be_lowercase(self) -> None:
        with pytest.raises(ValidationError, match="lowercase"):
            Tenant(
                id=uuid.uuid4(),
                slug="UPPERCASE-SLUG",
                display_name="Test",
                azure_tenant_id=uuid.uuid4(),
                plan_tier=PlanTier.STANDARD,
                is_active=True,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

    def test_valid_slug_accepted(self) -> None:
        tenant = Tenant(
            id=uuid.uuid4(),
            slug="valid-slug-123",
            display_name="Test",
            azure_tenant_id=uuid.uuid4(),
            plan_tier=PlanTier.STANDARD,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        assert tenant.slug == "valid-slug-123"


class TestTenantQuota:
    def test_zero_quota_rejected(self) -> None:
        with pytest.raises(ValidationError, match="positive"):
            TenantQuota(
                tenant_id=uuid.uuid4(),
                max_concurrent_assessments=0,  # invalid
                max_monthly_assessments=20,
                max_subscriptions_per_assessment=10,
                max_resources_per_assessment=5000,
                updated_at=datetime.now(UTC),
            )

    def test_negative_quota_rejected(self) -> None:
        with pytest.raises(ValidationError, match="positive"):
            TenantQuota(
                tenant_id=uuid.uuid4(),
                max_concurrent_assessments=3,
                max_monthly_assessments=-1,  # invalid
                max_subscriptions_per_assessment=10,
                max_resources_per_assessment=5000,
                updated_at=datetime.now(UTC),
            )
