"""Unit tests for the enterprise WAF scoring engine.

Tests cover:
  - Resource criticality weighting
  - Severity weighting
  - NOT_APPLICABLE exclusion (no finding = counted as passed)
  - Pillar weight configuration for overall score
  - Boundary conditions (zero findings, all failures, empty catalog)
  - Backward-compatible fallback in compute_scores()
"""

from __future__ import annotations

import pytest

from waf_reporting.scoring_config import DEFAULT_SCORING_WEIGHTS, ScoringWeights
from waf_reporting.scoring_engine import CatalogRule, ScoringEngine
from waf_reporting.scoring import ScoringResult, compute_scores
from waf_reporting.aggregator import PillarSummary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine(weights: ScoringWeights | None = None) -> ScoringEngine:
    return ScoringEngine(weights or DEFAULT_SCORING_WEIGHTS)


def _rule(
    rule_id: str = "TEST-001",
    pillar: str = "security",
    severity: str = "medium",
    resource_types: list[str] | None = None,
) -> CatalogRule:
    return CatalogRule(
        rule_id=rule_id,
        pillar=pillar,
        severity=severity,
        resource_types=resource_types or ["microsoft.compute/virtualmachines"],
    )


def _pillar_summary(
    pillar: str,
    sev_counts: dict[str, int],
) -> PillarSummary:
    from waf_reporting.aggregator import _pillar_compliance_score
    total = sum(sev_counts.values())
    return PillarSummary(
        pillar=pillar,
        findings_by_severity=sev_counts,
        total_findings=total,
        compliance_score=_pillar_compliance_score(sev_counts),
    )


# ---------------------------------------------------------------------------
# ScoringEngine.compute_pillar_scores
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestComputePillarScores:
    def test_no_findings_scores_100(self) -> None:
        engine = _engine()
        rules = [_rule(pillar="security", severity="critical",
                       resource_types=["microsoft.compute/virtualmachines"])]
        rt_counts = {"microsoft.compute/virtualmachines": 3}
        pillar_rt_sev: dict = {}  # no findings

        scores = engine.compute_pillar_scores(rules, rt_counts, pillar_rt_sev)
        assert scores["security"] == 100.0

    def test_all_resources_fail_critical_scores_0(self) -> None:
        engine = _engine()
        # One critical rule for 2 VMs; both VMs fail the rule
        rules = [_rule(pillar="security", severity="critical",
                       resource_types=["microsoft.compute/virtualmachines"])]
        rt_counts = {"microsoft.compute/virtualmachines": 2}
        # 2 critical findings for VMs in security pillar
        pillar_rt_sev = {
            "security": {
                "microsoft.compute/virtualmachines": {"critical": 2}
            }
        }
        scores = engine.compute_pillar_scores(rules, rt_counts, pillar_rt_sev)
        assert scores["security"] == pytest.approx(0.0, abs=0.1)

    def test_half_resources_fail_scores_50(self) -> None:
        engine = _engine()
        # One medium rule for 4 VMs; 2 VMs fail → weighted_failed = 2×5×1.2
        rules = [_rule(pillar="security", severity="medium",
                       resource_types=["microsoft.compute/virtualmachines"])]
        rt_counts = {"microsoft.compute/virtualmachines": 4}
        pillar_rt_sev = {
            "security": {
                "microsoft.compute/virtualmachines": {"medium": 2}
            }
        }
        scores = engine.compute_pillar_scores(rules, rt_counts, pillar_rt_sev)
        assert scores["security"] == pytest.approx(50.0, abs=0.2)

    def test_resource_criticality_applied(self) -> None:
        engine = _engine()
        # Two rule types: one for KV (criticality 1.5), one for Disk (criticality 0.6)
        # Both have 1 resource, severity=critical, and both fail.
        rules = [
            _rule("R1", "security", "critical", ["microsoft.keyvault/vaults"]),
            _rule("R2", "security", "critical", ["microsoft.compute/disks"]),
        ]
        rt_counts = {
            "microsoft.keyvault/vaults": 1,
            "microsoft.compute/disks": 1,
        }
        # Both resources fail their respective rules
        pillar_rt_sev = {
            "security": {
                "microsoft.keyvault/vaults": {"critical": 1},
                "microsoft.compute/disks": {"critical": 1},
            }
        }
        scores = engine.compute_pillar_scores(rules, rt_counts, pillar_rt_sev)
        # All failed → score should be 0
        assert scores["security"] == pytest.approx(0.0, abs=0.1)

    def test_resource_criticality_partial_failure(self) -> None:
        engine = _engine()
        # KV (1.5×) passes; Disk (0.6×) fails
        rules = [
            _rule("R1", "security", "critical", ["microsoft.keyvault/vaults"]),
            _rule("R2", "security", "critical", ["microsoft.compute/disks"]),
        ]
        rt_counts = {"microsoft.keyvault/vaults": 1, "microsoft.compute/disks": 1}
        pillar_rt_sev = {
            "security": {
                "microsoft.compute/disks": {"critical": 1},
                # Key Vault passes (no finding)
            }
        }
        scores = engine.compute_pillar_scores(rules, rt_counts, pillar_rt_sev)
        # applicable = 10×1.5 + 10×0.6 = 21.0; failed = 10×0.6 = 6.0
        # passed = 21 - 6 = 15; score = 15/21 × 100 ≈ 71.4
        assert scores["security"] == pytest.approx(71.4, abs=0.5)

    def test_not_applicable_resources_excluded(self) -> None:
        """Resource types with zero assessed count must not affect applicable weight."""
        engine = _engine()
        rules = [
            _rule("R1", "security", "critical", ["microsoft.keyvault/vaults"]),
            _rule("R2", "security", "critical", ["microsoft.containerservice/managedclusters"]),
        ]
        # Only KV was assessed; AKS was not in scope
        rt_counts = {"microsoft.keyvault/vaults": 1}
        pillar_rt_sev: dict = {}  # no findings
        scores = engine.compute_pillar_scores(rules, rt_counts, pillar_rt_sev)
        # Only KV rule is applicable; no findings → 100
        assert scores["security"] == 100.0

    def test_empty_catalog_returns_no_scores(self) -> None:
        engine = _engine()
        scores = engine.compute_pillar_scores([], {}, {})
        assert scores == {}

    def test_multiple_pillars_scored_independently(self) -> None:
        engine = _engine()
        rules = [
            _rule("S1", "security", "critical", ["microsoft.keyvault/vaults"]),
            _rule("C1", "cost_optimization", "low", ["microsoft.compute/disks"]),
        ]
        rt_counts = {"microsoft.keyvault/vaults": 1, "microsoft.compute/disks": 2}
        pillar_rt_sev = {
            "security": {"microsoft.keyvault/vaults": {"critical": 1}},
            # cost_optimization has no findings
        }
        scores = engine.compute_pillar_scores(rules, rt_counts, pillar_rt_sev)
        assert scores["security"] == pytest.approx(0.0, abs=0.1)
        assert scores["cost_optimization"] == 100.0

    def test_severity_weights_differentiate_failure_magnitude(self) -> None:
        """Failing a critical rule produces a lower score than failing a low rule
        when both rules apply to the same resources (same applicable baseline)."""
        engine = _engine()
        # Two rules for the same resource type — one critical, one low.
        # The applicable weight is the same in both scenarios (both rules apply).
        # Only the *failed* rule changes.
        rules = [
            _rule("R-CRIT", "security", "critical",
                  resource_types=["microsoft.compute/virtualmachines"]),
            _rule("R-LOW", "security", "low",
                  resource_types=["microsoft.compute/virtualmachines"]),
        ]
        rt_counts = {"microsoft.compute/virtualmachines": 1}

        # Scenario A: resource fails the critical rule only
        scores_a = engine.compute_pillar_scores(
            rules, rt_counts,
            {"security": {"microsoft.compute/virtualmachines": {"critical": 1}}}
        )
        # Scenario B: resource fails the low-severity rule only
        scores_b = engine.compute_pillar_scores(
            rules, rt_counts,
            {"security": {"microsoft.compute/virtualmachines": {"low": 1}}}
        )
        # Critical failure deducts weight=10; low failure deducts weight=2
        # → critical failure → lower compliance score
        assert scores_a["security"] < scores_b["security"]


# ---------------------------------------------------------------------------
# ScoringEngine.compute_overall_score
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestComputeOverallScore:
    def test_all_100_pillars_gives_100(self) -> None:
        engine = _engine()
        scores = {p: 100.0 for p in DEFAULT_SCORING_WEIGHTS.pillar_weights}
        assert engine.compute_overall_score(scores) == pytest.approx(100.0, abs=0.1)

    def test_all_0_pillars_gives_0(self) -> None:
        engine = _engine()
        scores = {p: 0.0 for p in DEFAULT_SCORING_WEIGHTS.pillar_weights}
        assert engine.compute_overall_score(scores) == pytest.approx(0.0, abs=0.1)

    def test_missing_pillar_treated_as_100(self) -> None:
        """Pillars not assessed default to 100 (no findings = fully compliant)."""
        engine = _engine()
        # Only security is assessed and has a low score; all others default to 100
        scores = {"security": 0.0}
        result = engine.compute_overall_score(scores)
        # Security contributes 30% at score 0; remaining 70% at score 100
        # overall = 0.0×0.30 + 100×0.70 = 70.0
        assert result == pytest.approx(70.0, abs=0.2)

    def test_pillar_weights_are_proportional(self) -> None:
        """Security (30%) must have more impact than cost_optimization (15%)."""
        engine = _engine()
        # Security at 0, all others at 100
        scores_a = engine.compute_overall_score({"security": 0.0})
        # Cost at 0, all others at 100
        scores_b = engine.compute_overall_score({"cost_optimization": 0.0})
        # Security zero should hurt more
        assert scores_a < scores_b

    def test_custom_pillar_weights(self) -> None:
        custom_weights = ScoringWeights(
            severity_weights=DEFAULT_SCORING_WEIGHTS.severity_weights,
            pillar_weights={"security": 1.0},  # Only one pillar
            resource_criticality=DEFAULT_SCORING_WEIGHTS.resource_criticality,
        )
        engine = ScoringEngine(custom_weights)
        assert engine.compute_overall_score({"security": 60.0}) == pytest.approx(60.0, abs=0.1)

    def test_fixed_weights_not_finding_count_weighted(self) -> None:
        """Overall score must NOT depend on how many findings each pillar has."""
        engine = _engine()
        # Same per-pillar scores regardless of finding count
        scores = {
            "security": 50.0,
            "reliability": 50.0,
            "performance_efficiency": 50.0,
            "operational_excellence": 50.0,
            "cost_optimization": 50.0,
        }
        result = engine.compute_overall_score(scores)
        assert result == pytest.approx(50.0, abs=0.1)


# ---------------------------------------------------------------------------
# ScoringEngine.compute_risk_score
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestComputeRiskScore:
    def test_perfect_compliance_gives_low_risk(self) -> None:
        engine = _engine()
        risk = engine.compute_risk_score({}, 100.0)
        assert risk == pytest.approx(0.0, abs=0.1)

    def test_zero_compliance_gives_high_risk(self) -> None:
        engine = _engine()
        risk = engine.compute_risk_score({"critical": 10}, 0.0)
        assert risk == pytest.approx(100.0, abs=0.2)

    def test_critical_amplification(self) -> None:
        engine = _engine()
        # 50% compliance base; all findings critical → +10 amplification
        risk_all_crit = engine.compute_risk_score({"critical": 5}, 50.0)
        risk_all_low  = engine.compute_risk_score({"low": 5}, 50.0)
        assert risk_all_crit > risk_all_low

    def test_risk_capped_at_100(self) -> None:
        engine = _engine()
        risk = engine.compute_risk_score({"critical": 100}, 0.0)
        assert risk <= 100.0


# ---------------------------------------------------------------------------
# ScoringEngine.compute_weighted_severity_score
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestComputeWeightedSeverityScore:
    def test_no_findings_returns_0(self) -> None:
        engine = _engine()
        assert engine.compute_weighted_severity_score({}) == 0.0

    def test_all_critical_returns_100(self) -> None:
        engine = _engine()
        score = engine.compute_weighted_severity_score({"critical": 10})
        assert score == pytest.approx(100.0, abs=0.1)

    def test_all_informational_returns_non_zero(self) -> None:
        engine = _engine()
        score = engine.compute_weighted_severity_score({"informational": 10})
        # informational weight = 1; max weight = 10 → 1/10 × 100 = 10
        assert score == pytest.approx(10.0, abs=0.1)

    def test_severity_ordering(self) -> None:
        engine = _engine()
        critical_score = engine.compute_weighted_severity_score({"critical": 5})
        high_score     = engine.compute_weighted_severity_score({"high": 5})
        medium_score   = engine.compute_weighted_severity_score({"medium": 5})
        low_score      = engine.compute_weighted_severity_score({"low": 5})
        assert critical_score > high_score > medium_score > low_score


# ---------------------------------------------------------------------------
# ScoringEngine.compute_business_impact_score
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestComputeBusinessImpactScore:
    def test_no_findings_returns_0(self) -> None:
        engine = _engine()
        assert engine.compute_business_impact_score({}, {}) == 0.0

    def test_perfect_pillar_scores_returns_0(self) -> None:
        engine = _engine()
        scores = {"security": 100.0, "reliability": 100.0}
        counts = {"security": 5, "reliability": 3}
        assert engine.compute_business_impact_score(scores, counts) == 0.0

    def test_pillar_importance_amplifies_impact(self) -> None:
        """Security failures (30% weight) produce higher business impact than
        cost_optimization failures (15% weight) given the same finding count
        and same pillar score, because the formula uses pillar importance as
        the multiplier against a fixed max-weight denominator."""
        engine = _engine()
        # Both pillars at 0% compliance; same finding count.
        # Security weight = 0.30; cost_optimization weight = 0.15;
        # max_pillar_weight = 0.30 (security).
        # business_impact(security) = 1.0×0.30×5 / (0.30×5) × 100 = 100.0
        # business_impact(cost)     = 1.0×0.15×5 / (0.30×5) × 100 = 50.0
        impact_sec  = engine.compute_business_impact_score({"security": 0.0}, {"security": 5})
        impact_cost = engine.compute_business_impact_score({"cost_optimization": 0.0}, {"cost_optimization": 5})
        assert impact_sec == pytest.approx(100.0, abs=0.1)
        assert impact_cost == pytest.approx(50.0, abs=0.1)
        assert impact_sec > impact_cost

    def test_bounded_between_0_and_100(self) -> None:
        engine = _engine()
        scores = {p: 0.0 for p in DEFAULT_SCORING_WEIGHTS.pillar_weights}
        counts = {p: 100 for p in DEFAULT_SCORING_WEIGHTS.pillar_weights}
        score = engine.compute_business_impact_score(scores, counts)
        assert 0.0 <= score <= 100.0


# ---------------------------------------------------------------------------
# NOT_APPLICABLE exclusion via scoring.compute_scores() fallback
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestComputeScoresFallback:
    """Verify compute_scores() backward-compat fallback (no catalog data)."""

    def test_no_findings_overall_100(self) -> None:
        result = compute_scores({}, {})
        assert isinstance(result, ScoringResult)
        assert result.overall_compliance_score == pytest.approx(100.0, abs=0.1)

    def test_pillar_scores_derived_from_summary(self) -> None:
        summary = _pillar_summary("security", {"critical": 5})
        result = compute_scores({"security": summary}, {"critical": 5})
        # old formula: score = _pillar_compliance_score × 100 = 0.0 × 100 = 0.0
        assert result.pillar_scores["security"] == pytest.approx(0.0, abs=0.1)

    def test_overall_uses_fixed_pillar_weights(self) -> None:
        """Even in fallback mode, overall score uses fixed pillar weights, not finding counts."""
        sec_summary  = _pillar_summary("security",  {"critical": 100})
        cost_summary = _pillar_summary("cost_optimization", {"low": 1})
        by_pillar = {"security": sec_summary, "cost_optimization": cost_summary}
        by_severity = {"critical": 100, "low": 1}

        result = compute_scores(by_pillar, by_severity)
        # Security (30%) at ~0; cost (15%) at ~0.875 (1 low out of 1 total).
        # overall ≈ 0×0.30 + 0.875×100×0.15 + (other pillars at 100) × their weights
        # Security dominates the drag more than cost at same finding count
        assert result.overall_compliance_score < 70.0

    def test_not_applicable_not_stored_means_full_applicable_passes(self) -> None:
        """When a pillar has zero findings, it contributes 100 to the overall score."""
        # Reliability has no findings → should contribute 100 at 20% weight
        sec_summary = _pillar_summary("security", {"medium": 5})
        result = compute_scores({"security": sec_summary}, {"medium": 5})
        # Reliability (20%) unassessed → treated as 100
        # Overall must be higher than just security score
        sec_score = result.pillar_scores.get("security", 0.0)
        assert result.overall_compliance_score > sec_score

    def test_scoring_result_has_methodology_string(self) -> None:
        result = compute_scores({}, {})
        assert len(result.methodology) > 50
        assert "weighted" in result.methodology.lower()

    def test_risk_score_between_0_and_100(self) -> None:
        summary = _pillar_summary("security", {"critical": 20, "high": 5, "low": 2})
        result = compute_scores({"security": summary}, {"critical": 20, "high": 5, "low": 2})
        assert 0.0 <= result.overall_risk_score <= 100.0

    def test_weighted_severity_score_bounded(self) -> None:
        summary = _pillar_summary("security", {"critical": 5, "low": 5})
        result = compute_scores({"security": summary}, {"critical": 5, "low": 5})
        assert 0.0 <= result.weighted_severity_score <= 100.0


# ---------------------------------------------------------------------------
# Full model with catalog data
# ---------------------------------------------------------------------------

@pytest.mark.unit
class TestComputeScoresFullModel:
    """Verify compute_scores() with catalog + resource type data (full model)."""

    def _catalog(self) -> list[CatalogRule]:
        return [
            CatalogRule("SEC-001", "security", "critical",
                        ["microsoft.keyvault/vaults"]),
            CatalogRule("REL-001", "reliability", "medium",
                        ["microsoft.compute/virtualmachines"]),
        ]

    def test_no_findings_full_model_scores_100(self) -> None:
        from waf_reporting.scoring import compute_scores
        result = compute_scores(
            {},
            {},
            catalog_rules=self._catalog(),
            resource_type_counts={
                "microsoft.keyvault/vaults": 2,
                "microsoft.compute/virtualmachines": 3,
            },
            pillar_rt_severity={},
        )
        assert result.pillar_scores.get("security", 100.0) == pytest.approx(100.0)
        assert result.pillar_scores.get("reliability", 100.0) == pytest.approx(100.0)

    def test_all_kv_fail_security_0(self) -> None:
        from waf_reporting.scoring import compute_scores
        summary = _pillar_summary("security", {"critical": 2})
        result = compute_scores(
            {"security": summary},
            {"critical": 2},
            catalog_rules=self._catalog(),
            resource_type_counts={"microsoft.keyvault/vaults": 2,
                                   "microsoft.compute/virtualmachines": 3},
            pillar_rt_severity={
                "security": {"microsoft.keyvault/vaults": {"critical": 2}}
            },
        )
        assert result.pillar_scores["security"] == pytest.approx(0.0, abs=0.1)

    def test_resource_criticality_affects_score(self) -> None:
        """Failing a high-criticality resource must yield a lower score than
        failing an equivalent low-criticality resource."""
        from waf_reporting.scoring import compute_scores
        rules = [
            CatalogRule("SEC-KV", "security", "critical", ["microsoft.keyvault/vaults"]),
            CatalogRule("SEC-DISK", "security", "critical", ["microsoft.compute/disks"]),
        ]
        rt_counts = {"microsoft.keyvault/vaults": 1, "microsoft.compute/disks": 1}

        # Only KV fails
        result_kv = compute_scores(
            _summary_dict({"security": {"critical": 1}}),
            {"critical": 1},
            catalog_rules=rules,
            resource_type_counts=rt_counts,
            pillar_rt_severity={"security": {"microsoft.keyvault/vaults": {"critical": 1}}},
        )
        # Only Disk fails
        result_disk = compute_scores(
            _summary_dict({"security": {"critical": 1}}),
            {"critical": 1},
            catalog_rules=rules,
            resource_type_counts=rt_counts,
            pillar_rt_severity={"security": {"microsoft.compute/disks": {"critical": 1}}},
        )
        # KV (1.5×) failure → lower score than Disk (0.6×) failure
        assert result_kv.pillar_scores["security"] < result_disk.pillar_scores["security"]

    def test_overall_uses_fixed_pillar_weights_full_model(self) -> None:
        """Security at 0%, all other pillars at 100% → overall ≈ 70%."""
        from waf_reporting.scoring import compute_scores
        rules = [CatalogRule("SEC-001", "security", "critical",
                              ["microsoft.keyvault/vaults"])]
        rt_counts = {"microsoft.keyvault/vaults": 1}
        summary = _pillar_summary("security", {"critical": 1})
        result = compute_scores(
            {"security": summary},
            {"critical": 1},
            catalog_rules=rules,
            resource_type_counts=rt_counts,
            pillar_rt_severity={"security": {"microsoft.keyvault/vaults": {"critical": 1}}},
        )
        # Security (30%) at 0; remaining 70% (other pillars) at 100 → overall ≈ 70
        assert result.overall_compliance_score == pytest.approx(70.0, abs=1.0)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _summary_dict(pillar_sev: dict[str, dict[str, int]]) -> dict[str, PillarSummary]:
    return {
        pillar: _pillar_summary(pillar, sev_counts)
        for pillar, sev_counts in pillar_sev.items()
    }
