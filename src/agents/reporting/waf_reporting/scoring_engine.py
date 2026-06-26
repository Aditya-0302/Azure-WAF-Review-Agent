"""Enterprise WAF scoring engine — pure scoring logic, no I/O.

Scoring Model
─────────────
The engine implements a *weighted-pass-rate* model per WAF pillar:

    pillar_score = weighted_passed / weighted_applicable × 100

Every rule-resource pair contributes a weight:

    weight = severity_weight(rule.severity) × resource_criticality(resource_type)

A *finding* (failed control check) reduces ``weighted_passed`` by that same weight.
Rules where ``NOT_APPLICABLE`` short-circuits (the DSL returns False for a resource
that doesn't meet the rule's applicability guard) are never stored as findings, so
they are counted as passed — a conservative but correct approximation.

Overall Score
─────────────
The overall compliance score is a fixed-pillar-weight average:

    overall = Σ(pillar_score[P] × pillar_weight[P])

This gives Security a constant 30 % contribution regardless of finding volume,
matching the Microsoft Well-Architected Framework approach to pillar importance.

NOT_APPLICABLE Handling
───────────────────────
Findings are only stored for rule evaluations that produce a failure (FAIL).
Rules that evaluate as NOT_APPLICABLE produce no finding and are counted as
passed in the weighted denominator.  This is consistent with WAF guidance that
NOT_APPLICABLE controls do not reduce the score.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from waf_reporting.scoring_config import DEFAULT_SCORING_WEIGHTS, ScoringWeights


@dataclass(frozen=True)
class CatalogRule:
    """Minimal rule descriptor consumed by ``ScoringEngine``."""

    rule_id: str
    pillar: str            # e.g. "security"
    severity: str          # e.g. "critical"
    resource_types: list[str]  # lowercase Azure resource-type strings


class ScoringEngine:
    """Enterprise WAF scoring engine with configurable weights.

    This class is a pure value-in / value-out calculator.  It performs no I/O
    and holds no mutable state beyond the constructor argument.

    Parameters
    ----------
    weights:
        Configurable scoring weights.  Defaults to ``DEFAULT_SCORING_WEIGHTS``.
    """

    def __init__(self, weights: ScoringWeights = DEFAULT_SCORING_WEIGHTS) -> None:
        self._w = weights

    # ── Pillar scores ──────────────────────────────────────────────────────────

    def compute_pillar_scores(
        self,
        catalog_rules: Sequence[CatalogRule],
        resource_type_counts: dict[str, int],
        pillar_rt_severity: dict[str, dict[str, dict[str, int]]],
    ) -> dict[str, float]:
        """Compute 0–100 compliance score for each assessed pillar.

        Parameters
        ----------
        catalog_rules:
            All active WAF rules from the database.  Used to derive the total
            *applicable* weight for each pillar (rules × resource counts ×
            criticality).

        resource_type_counts:
            ``{resource_type_lower: N}`` — number of resources of each type
            that were assessed.  Only types with N > 0 contribute.

        pillar_rt_severity:
            ``{pillar: {resource_type: {severity: count}}}`` — findings grouped
            by pillar, resource type, and severity.  Represents failed checks.

        Returns
        -------
        dict[str, float]
            ``{pillar: score}`` where score is 0–100, higher = more compliant.
            Pillars with no applicable rules receive 100.0.
        """
        # ── Step 1: applicable weight per pillar (from catalog + resource counts)
        applicable: dict[str, float] = {}
        for rule in catalog_rules:
            p = rule.pillar
            sev_w = self._w.severity_weights.get(rule.severity, 1.0)
            for rt in rule.resource_types:
                rt_l = rt.lower()
                n = resource_type_counts.get(rt_l, 0)
                if n <= 0:
                    continue
                crit = self._w.resource_criticality.get(
                    rt_l, self._w.default_resource_criticality
                )
                applicable[p] = applicable.get(p, 0.0) + n * crit * sev_w

        # ── Step 2: failed weight per pillar (from findings breakdown)
        failed: dict[str, float] = {}
        for pillar, rt_data in pillar_rt_severity.items():
            pillar_failed = 0.0
            for rt, sev_data in rt_data.items():
                rt_l = rt.lower()
                crit = self._w.resource_criticality.get(
                    rt_l, self._w.default_resource_criticality
                )
                for sev, count in sev_data.items():
                    sev_w = self._w.severity_weights.get(sev, 1.0)
                    pillar_failed += count * crit * sev_w
            failed[pillar] = pillar_failed

        # ── Step 3: score = passed / applicable for each pillar
        all_pillars = set(applicable.keys()) | set(failed.keys())
        scores: dict[str, float] = {}
        for pillar in all_pillars:
            app = applicable.get(pillar, 0.0)
            fail = min(failed.get(pillar, 0.0), app)  # cap: can't fail more than applicable
            if app <= 0.0:
                scores[pillar] = 100.0  # no applicable rules → perfect
            else:
                passed = app - fail
                scores[pillar] = round(passed / app * 100.0, 1)
        return scores

    # ── Overall score ──────────────────────────────────────────────────────────

    def compute_overall_score(self, pillar_scores: dict[str, float]) -> float:
        """Fixed-pillar-weight average of pillar compliance scores.

        Pillars absent from ``pillar_scores`` (not assessed) contribute their
        configured weight at a score of 100.0 — no findings means full compliance.

        Returns
        -------
        float
            Overall compliance score 0–100, rounded to one decimal place.
        """
        total_score = 0.0
        total_weight = 0.0
        for pillar, weight in self._w.pillar_weights.items():
            score = pillar_scores.get(pillar, 100.0)
            total_score += score * weight
            total_weight += weight
        if total_weight == 0.0:
            return 100.0
        return round(total_score / total_weight, 1)

    # ── Risk score ─────────────────────────────────────────────────────────────

    def compute_risk_score(
        self,
        findings_by_severity: dict[str, int],
        overall_compliance: float,
    ) -> float:
        """Overall risk score (0 = no risk, 100 = maximum risk).

        Base risk is the complement of compliance (100 − compliance).
        An amplification of up to 10 points is added based on the fraction of
        critical and high findings, reflecting that severity mix worsens risk
        beyond the raw count.
        """
        base = 100.0 - overall_compliance
        total = sum(findings_by_severity.values())
        if total > 0:
            critical_high = (
                findings_by_severity.get("critical", 0)
                + findings_by_severity.get("high", 0)
            )
            base = min(100.0, base + (critical_high / total) * 10.0)
        return round(base, 1)

    # ── Weighted severity score ────────────────────────────────────────────────

    def compute_weighted_severity_score(
        self,
        findings_by_severity: dict[str, int],
    ) -> float:
        """Normalized severity mix score (0–100).

        Captures the severity distribution of findings: an assessment with only
        critical findings scores near 100; one with only informational findings
        scores near 10.  Returns 0 when there are no findings.
        """
        total = sum(findings_by_severity.values())
        if total == 0:
            return 0.0
        max_weight = max(self._w.severity_weights.values(), default=1.0)
        weighted = sum(
            self._w.severity_weights.get(sev, 1.0) * count
            for sev, count in findings_by_severity.items()
        )
        return round(weighted / (total * max_weight) * 100.0, 1)

    # ── Business impact score ──────────────────────────────────────────────────

    def compute_business_impact_score(
        self,
        pillar_scores: dict[str, float],
        pillar_finding_counts: dict[str, int],
    ) -> float:
        """Business impact score (0–100).

        Reflects both *how bad* each pillar is (pillar risk) and *how important*
        that pillar is to the business (pillar weight).  Security failures
        register higher business impact than equivalent Cost Optimization failures.

        Formula:
            weighted_risk   = Σ(pillar_risk × pillar_importance × finding_count)
            total_possible  = max_pillar_importance × total_findings
            business_impact = weighted_risk / total_possible × 100

        Returns 0 when there are no findings.
        """
        total_findings = sum(pillar_finding_counts.values())
        if total_findings == 0:
            return 0.0

        max_pillar_weight = max(self._w.pillar_weights.values(), default=1.0)
        weighted_risk = 0.0

        for pillar, finding_count in pillar_finding_counts.items():
            pillar_importance = self._w.pillar_weights.get(pillar, 0.15)
            pillar_risk = (100.0 - pillar_scores.get(pillar, 100.0)) / 100.0
            weighted_risk += pillar_risk * pillar_importance * finding_count

        total_possible = max_pillar_weight * total_findings
        if total_possible == 0.0:
            return 0.0

        return round(min(100.0, weighted_risk / total_possible * 100.0), 1)
