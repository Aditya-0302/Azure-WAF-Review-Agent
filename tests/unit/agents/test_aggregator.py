"""Unit tests for FindingAggregator.

Verifies compliance score calculation, pillar summarisation,
coverage percentage, and empty/edge-case handling.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from waf_reporting.aggregator import (
    AggregatedReport,
    FindingAggregator,
    PillarSummary,
    _pillar_compliance_score,
)
from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.domain.models.finding import Finding, FindingStatus, Severity


# ---------------------------------------------------------------------------
# _pillar_compliance_score — pure function
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestPillarComplianceScore:
    def test_all_critical_is_zero(self) -> None:
        assert _pillar_compliance_score({"critical": 10}) == 0.0

    def test_all_informational_is_one(self) -> None:
        assert _pillar_compliance_score({"informational": 5}) == 1.0

    def test_empty_is_one(self) -> None:
        assert _pillar_compliance_score({}) == 1.0

    def test_all_high_weight(self) -> None:
        # 1 - (0.75 * 1) / (1 * 1.0) ... wait, the formula is:
        # weighted = sum(weight * count) for each sev
        # score = 1.0 - weighted / total
        # weighted = 0.75 * 10 = 7.5; total = 10; score = 1 - 7.5/10 = 0.25
        score = _pillar_compliance_score({"high": 10})
        assert score == pytest.approx(0.25, abs=1e-4)

    def test_mixed_severities(self) -> None:
        # critical=1 (1.0), medium=1 (0.5), low=1 (0.25), informational=1 (0.0)
        # total=4; weighted=1.75; score=1.0 - 1.75/4 = 1 - 0.4375 = 0.5625
        score = _pillar_compliance_score({
            "critical": 1,
            "medium": 1,
            "low": 1,
            "informational": 1,
        })
        assert score == pytest.approx(0.5625, abs=1e-4)

    def test_unknown_severity_uses_default_weight(self) -> None:
        # Unknown severity uses 0.5 default weight
        score = _pillar_compliance_score({"unknown_sev": 2})
        # weighted = 0.5 * 2 = 1; total=2; score = 1.0 - 0.5 = 0.5
        assert score == pytest.approx(0.5, abs=1e-4)

    def test_score_clipped_between_0_and_1(self) -> None:
        score = _pillar_compliance_score({"critical": 1000})
        assert 0.0 <= score <= 1.0

    def test_result_rounded_to_4_decimal_places(self) -> None:
        score = _pillar_compliance_score({"critical": 1, "high": 2, "medium": 3})
        # Verify it is rounded (not a repeating float)
        assert score == round(score, 4)


# ---------------------------------------------------------------------------
# FindingAggregator.aggregate
# ---------------------------------------------------------------------------


def _make_finding(
    *,
    assessment_id: uuid.UUID,
    tenant_id: uuid.UUID,
    severity: str = "medium",
    pillar: str = "security",
) -> Finding:
    return Finding(
        id=uuid.uuid4(),
        assessment_id=assessment_id,
        batch_id=uuid.uuid4(),
        tenant_id=tenant_id,
        rule_id="WAF-SEC-001",
        resource_id="/subscriptions/sub/rg/providers/Microsoft.Network/agw/agw1",
        resource_type="microsoft.network/applicationgateways",
        status=FindingStatus.OPEN,
        severity=Severity(severity),
        pillar=pillar,
        confidence_score=0.9,
        title="Test Finding",
        recommendation="Fix it",
        evidence={"result": "FAIL"},
        evaluation_type="deterministic",
        created_at=datetime.now(UTC),
    )


def _make_aggregator(
    *,
    by_severity: dict[str, int] | None = None,
    pillar_severity: dict[str, dict[str, int]] | None = None,
    total_resources: int = 10,
    resources_with_findings: int = 5,
    top_critical: list[Finding] | None = None,
) -> tuple[FindingAggregator, MagicMock, MagicMock]:
    finding_repo = MagicMock(spec=FindingRepository)
    assessment_repo = MagicMock(spec=AssessmentRepository)

    finding_repo.count_by_severity = AsyncMock(return_value=by_severity or {"medium": 3})
    finding_repo.aggregate_pillar_severity = AsyncMock(
        return_value=pillar_severity or {"security": {"medium": 3}}
    )
    finding_repo.count_distinct_resources = AsyncMock(return_value=resources_with_findings)
    finding_repo.list_by_assessment = AsyncMock(return_value=top_critical or [])
    # Phase-5 methods — not configured per test; provide safe empty defaults.
    finding_repo.aggregate_resource_type_severity = AsyncMock(return_value={})
    finding_repo.list_top_risks = AsyncMock(return_value=[])
    finding_repo.aggregate_waf_control_coverage = AsyncMock(return_value={})
    # Phase-5 scoring: three-way pillar × resource_type × severity breakdown
    finding_repo.aggregate_pillar_resource_type_severity = AsyncMock(return_value={})
    assessment_repo.count_resources = AsyncMock(return_value=total_resources)
    assessment_repo.aggregate_resource_inventory = AsyncMock(return_value=[])

    agg = FindingAggregator(finding_repo=finding_repo, assessment_repo=assessment_repo)
    return agg, finding_repo, assessment_repo


@pytest.mark.unit
class TestFindingAggregatorAggregate:
    async def test_returns_aggregated_report(self) -> None:
        tid = uuid.uuid4()
        aid = uuid.uuid4()
        agg, _, _ = _make_aggregator()

        result = await agg.aggregate(tid, aid)

        assert isinstance(result, AggregatedReport)
        assert result.tenant_id == tid
        assert result.assessment_id == aid

    async def test_total_findings_from_severity_counts(self) -> None:
        tid, aid = uuid.uuid4(), uuid.uuid4()
        agg, _, _ = _make_aggregator(
            by_severity={"critical": 2, "high": 5, "medium": 3}
        )

        result = await agg.aggregate(tid, aid)
        assert result.total_findings == 10

    async def test_coverage_percentage_calculation(self) -> None:
        tid, aid = uuid.uuid4(), uuid.uuid4()
        agg, _, _ = _make_aggregator(total_resources=10, resources_with_findings=4)

        result = await agg.aggregate(tid, aid)
        assert result.coverage_percentage == pytest.approx(0.4, abs=1e-4)

    async def test_zero_resources_gives_zero_coverage(self) -> None:
        tid, aid = uuid.uuid4(), uuid.uuid4()
        agg, _, _ = _make_aggregator(total_resources=0, resources_with_findings=0)

        result = await agg.aggregate(tid, aid)
        assert result.coverage_percentage == 0.0

    async def test_pillar_summaries_built(self) -> None:
        tid, aid = uuid.uuid4(), uuid.uuid4()
        agg, _, _ = _make_aggregator(
            pillar_severity={
                "reliability": {"critical": 1, "high": 2},
                "security": {"medium": 5},
            }
        )

        result = await agg.aggregate(tid, aid)
        assert "reliability" in result.findings_by_pillar
        assert "security" in result.findings_by_pillar

        rel = result.findings_by_pillar["reliability"]
        assert rel.total_findings == 3
        assert rel.compliance_score < 0.5  # mostly critical/high

        sec = result.findings_by_pillar["security"]
        assert sec.total_findings == 5

    async def test_top_critical_findings_passed_through(self) -> None:
        tid, aid = uuid.uuid4(), uuid.uuid4()
        findings = [_make_finding(assessment_id=aid, tenant_id=tid, severity="critical")]
        agg, _, _ = _make_aggregator(top_critical=findings)

        result = await agg.aggregate(tid, aid)
        assert result.top_critical_findings == findings

    async def test_generated_at_is_utc_aware(self) -> None:
        tid, aid = uuid.uuid4(), uuid.uuid4()
        agg, _, _ = _make_aggregator()

        result = await agg.aggregate(tid, aid)
        assert result.generated_at.tzinfo is not None

    async def test_pillar_compliance_score_all_critical(self) -> None:
        tid, aid = uuid.uuid4(), uuid.uuid4()
        agg, _, _ = _make_aggregator(
            pillar_severity={"reliability": {"critical": 10}}
        )

        result = await agg.aggregate(tid, aid)
        assert result.findings_by_pillar["reliability"].compliance_score == 0.0

    async def test_empty_findings(self) -> None:
        tid, aid = uuid.uuid4(), uuid.uuid4()
        agg, _, _ = _make_aggregator(
            by_severity={},
            pillar_severity={},
            total_resources=5,
            resources_with_findings=0,
            top_critical=[],
        )

        result = await agg.aggregate(tid, aid)
        assert result.total_findings == 0
        assert result.findings_by_pillar == {}
        assert result.coverage_percentage == 0.0
