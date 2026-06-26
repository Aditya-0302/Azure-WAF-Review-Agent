"""Finding aggregator — transforms raw finding rows into a structured summary.

Builds an AggregatedReport used by both the Excel and PDF generators.

Compliance score formula (per pillar) — Phase 5 weighted pass-rate model:
  weight(finding) = severity_weight × resource_criticality_multiplier
  pillar_score    = weighted_passed / weighted_applicable × 100

  Legacy per-pillar compliance (PillarSummary.compliance_score):
    Each finding contributes a severity weight:
      critical → 1.0, high → 0.75, medium → 0.5, low → 0.25, informational → 0.0
    compliance_score = 1.0 - (sum of weights) / (total_findings × max_weight)
    Kept for backward compatibility with trend data and internal comparisons.

Phase 5 enterprise fields:
  - ResourceTypeStats:     per-resource-type compliance from actual assessment_resources
  - PillarControlStats:    WAF control pass/fail derived from findings waf_codes
  - TrendDataPoint:        historical compliance snapshots from previous reports
  - TopRisk:               top-5 highest-severity findings for executive highlight
  - overall_compliance_score / overall_risk_score: from scoring.py (new weighted model)
  - pillar_scores:         per-pillar scores from the weighted pass-rate model
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime

from waf_shared.db.repositories.assessment_repository import AssessmentRepository
from waf_shared.db.repositories.finding_repository import FindingRepository
from waf_shared.db.repositories.report_repository import ReportRepository
from waf_shared.domain.models.assessment import Assessment
from waf_shared.domain.models.finding import Finding, Severity

# ── Legacy severity weight for PillarSummary.compliance_score ────────────────
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.75,
    "medium": 0.5,
    "low": 0.25,
    "informational": 0.0,
}

# ── Business impact category mapping ─────────────────────────────────────────
_PILLAR_TO_IMPACT: dict[str, str] = {
    "security": "Security Exposure",
    "reliability": "Availability Risk",
    "cost_optimization": "Financial Waste",
    "operational_excellence": "Operational Risk",
    "performance_efficiency": "Performance Degradation",
}

_TOP_CRITICAL_LIMIT = 5
_TREND_HISTORY_LIMIT = 6  # previous assessments to include in trend
_HUMAN_REVIEW_CODES = frozenset({"SE-10", "OE-03", "OE-04", "CO-09"})


# ── Domain dataclasses ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class PillarSummary:
    pillar: str
    findings_by_severity: dict[str, int]
    total_findings: int
    compliance_score: float


@dataclass(frozen=True)
class ResourceTypeStats:
    """Per-resource-type compliance metrics derived from actual assessment data."""

    resource_type: str
    total: int
    with_findings: int
    compliant: int  # total - with_findings
    compliance_pct: float  # (compliant / total) × 100
    critical_findings: int
    high_findings: int


@dataclass(frozen=True)
class PillarControlStats:
    """WAF control coverage per pillar, derived from findings.waf_codes."""

    pillar: str
    controls_assessed: int  # distinct WAF codes appearing in findings
    controls_passed: int  # codes with no critical/high finding
    controls_failed: int  # codes with ≥1 critical/high finding
    compliance_pct: float  # passed / assessed × 100


@dataclass(frozen=True)
class TrendDataPoint:
    """Compliance snapshot from a historical assessment report."""

    assessment_id: uuid.UUID
    assessment_date: datetime
    total_findings: int
    compliance_score: float
    findings_by_pillar: dict[str, int]


@dataclass(frozen=True)
class TopRisk:
    """Top-N highest-severity findings for executive risk section."""

    title: str
    resource_id: str
    resource_type: str
    severity: str
    pillar: str
    waf_codes: list[str]
    rule_id: str
    business_impact: str


@dataclass(frozen=True)
class AggregatedReport:
    # ── Existing core fields ───────────────────────────────────────────────────
    assessment_id: uuid.UUID
    tenant_id: uuid.UUID
    total_resources: int
    resources_with_findings: int
    total_findings: int
    findings_by_pillar: dict[str, PillarSummary]
    findings_by_severity: dict[str, int]
    top_critical_findings: list[Finding]
    coverage_percentage: float
    generated_at: datetime

    # ── Phase 5 fields (all have defaults for backward compatibility) ──────────
    subscription_count: int = 0
    assessment_date: datetime = field(default_factory=lambda: datetime.now(UTC))
    resource_type_inventory: dict[str, ResourceTypeStats] = field(default_factory=dict)
    top_5_risks: list[TopRisk] = field(default_factory=list)
    overall_compliance_score: float = 100.0
    overall_risk_score: float = 0.0
    weighted_severity_score: float = 0.0
    business_impact_score: float = 0.0
    pillar_control_stats: dict[str, PillarControlStats] = field(default_factory=dict)
    trend_data: list[TrendDataPoint] = field(default_factory=list)
    scoring_methodology: str = ""
    # Per-pillar scores from the weighted pass-rate model (0–100).
    # Empty dict falls back to PillarSummary.compliance_score × 100 in consumers.
    pillar_scores: dict[str, float] = field(default_factory=dict)


# ── Compliance scoring helpers (legacy, kept for PillarSummary + trend data) ──


def _pillar_compliance_score(sev_counts: dict[str, int]) -> float:
    total = sum(sev_counts.values())
    if total == 0:
        return 1.0
    weighted = sum(_SEVERITY_WEIGHTS.get(sev, 0.5) * count for sev, count in sev_counts.items())
    return round(1.0 - weighted / total, 4)


# ── Main aggregator ────────────────────────────────────────────────────────────


class FindingAggregator:
    """Builds AggregatedReport from the database for one assessment."""

    def __init__(
        self,
        finding_repo: FindingRepository,
        assessment_repo: AssessmentRepository,
        report_repo: ReportRepository | None = None,
        rule_repo: object | None = None,  # WafRuleRepository | None — avoid circular import
    ) -> None:
        self._finding_repo = finding_repo
        self._assessment_repo = assessment_repo
        self._report_repo = report_repo
        self._rule_repo = rule_repo

    async def aggregate(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
        assessment: Assessment | None = None,
    ) -> AggregatedReport:
        total_resources = await self._assessment_repo.count_resources(tenant_id, assessment_id)
        resources_with_findings = await self._finding_repo.count_distinct_resources(
            tenant_id, assessment_id
        )

        if resources_with_findings == 0:
            return AggregatedReport(
                assessment_id=assessment_id,
                tenant_id=tenant_id,
                total_resources=total_resources,
                resources_with_findings=0,
                total_findings=0,
                findings_by_pillar={},
                findings_by_severity={},
                top_critical_findings=[],
                coverage_percentage=0.0,
                generated_at=datetime.now(UTC),
                subscription_count=len(assessment.subscription_ids) if assessment else 0,
                assessment_date=assessment.created_at if assessment else datetime.now(UTC),
            )

        # ── Core aggregations ─────────────────────────────────────────────────
        by_severity = await self._finding_repo.count_by_severity(tenant_id, assessment_id)
        pillar_severity = await self._finding_repo.aggregate_pillar_severity(
            tenant_id, assessment_id
        )

        top_critical = await self._finding_repo.list_by_assessment(
            tenant_id=tenant_id,
            assessment_id=assessment_id,
            severity=Severity.CRITICAL,
            limit=_TOP_CRITICAL_LIMIT,
        )

        pillars: dict[str, PillarSummary] = {}
        for pillar, sev_counts in pillar_severity.items():
            pillar_total = sum(sev_counts.values())
            pillars[pillar] = PillarSummary(
                pillar=pillar,
                findings_by_severity=dict(sev_counts),
                total_findings=pillar_total,
                compliance_score=_pillar_compliance_score(sev_counts),
            )

        total_findings = sum(by_severity.values())
        coverage = (
            round(resources_with_findings / total_resources, 4) if total_resources > 0 else 0.0
        )

        # ── Phase 5: resource type inventory ─────────────────────────────────
        resource_type_inventory = await self._build_resource_inventory(tenant_id, assessment_id)

        # ── Phase 5: top-5 risks ──────────────────────────────────────────────
        top_5_risks = await self._build_top_risks(tenant_id, assessment_id)

        # ── Phase 5: pillar control stats ─────────────────────────────────────
        pillar_control_stats = await self._build_pillar_control_stats(tenant_id, assessment_id)

        # ── Phase 5: enhanced scoring (weighted pass-rate model) ──────────────
        from waf_reporting.scoring import CatalogRule, compute_scores

        catalog_rules: list[CatalogRule] | None = None
        resource_type_counts: dict[str, int] | None = None
        pillar_rt_severity: dict[str, dict[str, dict[str, int]]] | None = None

        if self._rule_repo is not None:
            try:
                db_rules = await self._rule_repo.list_active()  # type: ignore[union-attr]
                catalog_rules = [
                    CatalogRule(
                        rule_id=r.rule_id,
                        pillar=r.pillar.value if hasattr(r.pillar, "value") else r.pillar,
                        severity=r.severity,
                        resource_types=[rt.lower() for rt in r.resource_types],
                    )
                    for r in db_rules
                ]
                # Resource type → count from the inventory
                resource_type_counts = {
                    rt: stats.total for rt, stats in resource_type_inventory.items()
                }
                # Three-way breakdown needed for exact failure weight
                pillar_rt_severity = (
                    await self._finding_repo.aggregate_pillar_resource_type_severity(
                        tenant_id, assessment_id
                    )
                )
            except Exception:
                # Fall back to legacy formula if catalog load fails.
                # Log so operators can distinguish a transient DB error from
                # a permanently misconfigured catalog — silent fallback masks
                # scoring degradation that may persist undetected.
                import logging as _logging

                _logging.getLogger(__name__).warning(
                    "aggregator.scoring_catalog_load_failed: falling back to legacy "
                    "compliance formula; weighted pass-rate scores unavailable",
                    exc_info=True,
                )
                catalog_rules = None
                resource_type_counts = None
                pillar_rt_severity = None

        scores = compute_scores(
            pillars,
            dict(by_severity),
            catalog_rules=catalog_rules,
            resource_type_counts=resource_type_counts,
            pillar_rt_severity=pillar_rt_severity,
        )

        # ── Phase 5: trend data ───────────────────────────────────────────────
        trend_data = await self._build_trend_data(tenant_id, assessment_id)

        return AggregatedReport(
            assessment_id=assessment_id,
            tenant_id=tenant_id,
            total_resources=total_resources,
            resources_with_findings=resources_with_findings,
            total_findings=total_findings,
            findings_by_pillar=pillars,
            findings_by_severity=dict(by_severity),
            top_critical_findings=top_critical,
            coverage_percentage=coverage,
            generated_at=datetime.now(UTC),
            subscription_count=len(assessment.subscription_ids) if assessment else 0,
            assessment_date=assessment.created_at if assessment else datetime.now(UTC),
            resource_type_inventory=resource_type_inventory,
            top_5_risks=top_5_risks,
            overall_compliance_score=scores.overall_compliance_score,
            overall_risk_score=scores.overall_risk_score,
            weighted_severity_score=scores.weighted_severity_score,
            business_impact_score=scores.business_impact_score,
            pillar_control_stats=pillar_control_stats,
            trend_data=trend_data,
            scoring_methodology=scores.methodology,
            pillar_scores=scores.pillar_scores,
        )

    # ── Private builders ───────────────────────────────────────────────────────

    async def _build_resource_inventory(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, ResourceTypeStats]:
        """Cross-reference assessment_resources with assessment_findings."""
        rows = await self._assessment_repo.aggregate_resource_inventory(tenant_id, assessment_id)
        rt_severity = await self._finding_repo.aggregate_resource_type_severity(
            tenant_id, assessment_id
        )
        result: dict[str, ResourceTypeStats] = {}
        for resource_type, total, with_findings in rows:
            sev_counts = rt_severity.get(resource_type, {})
            critical = sev_counts.get("critical", 0)
            high = sev_counts.get("high", 0)
            compliant = total - with_findings
            pct = round(compliant / total * 100, 1) if total > 0 else 100.0
            result[resource_type] = ResourceTypeStats(
                resource_type=resource_type,
                total=total,
                with_findings=with_findings,
                compliant=compliant,
                compliance_pct=pct,
                critical_findings=critical,
                high_findings=high,
            )
        return result

    async def _build_top_risks(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[TopRisk]:
        findings = await self._finding_repo.list_top_risks(tenant_id, assessment_id, limit=5)
        risks: list[TopRisk] = []
        for f in findings:
            primary_impact = _PILLAR_TO_IMPACT.get(f.pillar, "Operational Risk")
            if f.severity.value == "critical" and f.pillar in ("security", "reliability"):
                primary_impact += " / Data Loss Risk"
            risks.append(
                TopRisk(
                    title=f.title,
                    resource_id=f.resource_id,
                    resource_type=f.resource_type,
                    severity=f.severity.value,
                    pillar=f.pillar,
                    waf_codes=list(f.waf_codes),
                    rule_id=f.rule_id,
                    business_impact=primary_impact,
                )
            )
        return risks

    async def _build_pillar_control_stats(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> dict[str, PillarControlStats]:
        coverage = await self._finding_repo.aggregate_waf_control_coverage(tenant_id, assessment_id)
        result: dict[str, PillarControlStats] = {}
        for pillar, code_map in coverage.items():
            assessed = len(code_map)
            failed = sum(1 for v in code_map.values() if v == 1)
            passed = assessed - failed
            pct = round(passed / assessed * 100, 1) if assessed > 0 else 100.0
            result[pillar] = PillarControlStats(
                pillar=pillar,
                controls_assessed=assessed,
                controls_passed=passed,
                controls_failed=failed,
                compliance_pct=pct,
            )
        return result

    async def _build_trend_data(
        self,
        tenant_id: uuid.UUID,
        assessment_id: uuid.UUID,
    ) -> list[TrendDataPoint]:
        if self._report_repo is None:
            return []
        try:
            recent = await self._report_repo.list_recent_by_tenant(
                tenant_id, assessment_id, limit=_TREND_HISTORY_LIMIT
            )
        except Exception:
            return []

        points: list[TrendDataPoint] = []
        for r in reversed(recent):  # chronological order (oldest first)
            s = r.summary
            total = sum(s.findings_by_severity.values())
            if total > 0:
                weighted = sum(
                    _SEVERITY_WEIGHTS.get(sev, 0.5) * cnt
                    for sev, cnt in s.findings_by_severity.items()
                )
                comp = round((1.0 - weighted / total) * 100, 1)
            else:
                comp = 100.0
            points.append(
                TrendDataPoint(
                    assessment_id=r.assessment_id,
                    assessment_date=r.generated_at,
                    total_findings=s.total_findings,
                    compliance_score=comp,
                    findings_by_pillar=dict(s.findings_by_pillar),
                )
            )
        return points
