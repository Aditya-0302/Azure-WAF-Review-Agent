"""WAF assessment scoring — public API and thin adapter over ScoringEngine.

Scoring Methodology (Phase 5 — weighted pass-rate model)
─────────────────────────────────────────────────────────
All scores are deterministic: same inputs always produce identical outputs.

Pillar Score (0–100)
    For each WAF pillar, every rule-resource pair contributes a weight:

        weight = severity_weight(rule.severity)
                 × resource_criticality(resource_type)

    Severity weights:
        Critical=10, High=7, Medium=5, Low=2, Informational=1

    Resource criticality multipliers (examples):
        Key Vault / SQL Server = 1.5 × (tier-1 business impact)
        Storage Account        = 1.3 ×
        Virtual Machine / AKS  = 1.2 ×
        Load Balancer / NSG     = 0.9 ×
        Managed Disk / Snapshot = 0.6 ×

    pillar_score = weighted_passed / weighted_applicable × 100

    NOT_APPLICABLE rule evaluations are never stored as findings; they are
    counted as passed — consistent with WAF scoring guidance that
    NOT_APPLICABLE controls do not reduce the score.

Overall Compliance Score (0–100)
    Fixed-pillar-weight average (not finding-count weighted):

        overall = Σ(pillar_score[P] × pillar_weight[P])

    Default pillar weights:
        Security 30 %, Reliability 20 %, Performance Efficiency 20 %,
        Operational Excellence 15 %, Cost Optimization 15 %

Overall Risk Score (0–100)
    base  = 100 − overall_compliance_score
    bonus = (critical + high findings) / total_findings × 10
    risk  = min(100, base + bonus)

Weighted Severity Score (0–100)
    Captures the severity mix: critical-heavy assessments score near 100.
    score = Σ(severity_weight × count) / (total × max_severity_weight) × 100

Business Impact Score (0–100)
    Pillar-risk weighted by pillar importance and finding volume.
"""

from __future__ import annotations

from dataclasses import dataclass

from waf_reporting.aggregator import PillarSummary
from waf_reporting.scoring_config import DEFAULT_SCORING_WEIGHTS, ScoringWeights
from waf_reporting.scoring_engine import CatalogRule, ScoringEngine

__all__ = ["ScoringResult", "compute_scores", "CatalogRule"]


@dataclass(frozen=True)
class ScoringResult:
    """All enterprise scores for one assessment."""

    overall_compliance_score: float  # 0–100; 100 = fully compliant
    overall_risk_score: float  # 0–100; 100 = maximum risk
    weighted_severity_score: float  # 0–100; captures severity mix
    business_impact_score: float  # 0–100; weighted by pillar importance
    pillar_scores: dict[str, float]  # pillar name → 0–100 compliance
    methodology: str  # human-readable formula description


# ---------------------------------------------------------------------------
# Public API — signature unchanged for backward compatibility
# ---------------------------------------------------------------------------


def compute_scores(
    findings_by_pillar: dict[str, PillarSummary],
    findings_by_severity: dict[str, int],
    *,
    catalog_rules: list[CatalogRule] | None = None,
    resource_type_counts: dict[str, int] | None = None,
    pillar_rt_severity: dict[str, dict[str, dict[str, int]]] | None = None,
    weights: ScoringWeights | None = None,
) -> ScoringResult:
    """Compute all enterprise scoring metrics from aggregated findings.

    Parameters
    ----------
    findings_by_pillar:
        Per-pillar summary (severity counts, compliance_score).  Always required.

    findings_by_severity:
        Overall severity distribution across all pillars.  Always required.

    catalog_rules:
        All active WAF rules from the database.  When provided together with
        ``resource_type_counts`` and ``pillar_rt_severity``, the full weighted
        pass-rate formula is used.  When absent the engine falls back to using
        ``PillarSummary.compliance_score`` (legacy formula).

    resource_type_counts:
        ``{resource_type_lower: count}`` of assessed resources.

    pillar_rt_severity:
        ``{pillar: {resource_type: {severity: count}}}`` — per-finding breakdown
        required for exact resource-criticality-weighted failure calculation.

    weights:
        Override the default scoring weights.  Pass ``None`` to use
        ``DEFAULT_SCORING_WEIGHTS``.
    """
    engine = ScoringEngine(weights or DEFAULT_SCORING_WEIGHTS)

    # ── Pillar scores ──────────────────────────────────────────────────────────
    use_full_model = (
        catalog_rules is not None
        and resource_type_counts is not None
        and pillar_rt_severity is not None
    )

    if use_full_model:
        assert catalog_rules is not None  # narrowing for type checker
        assert resource_type_counts is not None
        assert pillar_rt_severity is not None
        pillar_scores = engine.compute_pillar_scores(
            catalog_rules=catalog_rules,
            resource_type_counts=resource_type_counts,
            pillar_rt_severity=pillar_rt_severity,
        )
    else:
        # Fallback: derive from legacy PillarSummary.compliance_score (0.0–1.0)
        pillar_scores = {
            pillar: round(ps.compliance_score * 100.0, 1)
            for pillar, ps in findings_by_pillar.items()
        }

    # ── Aggregate scores ───────────────────────────────────────────────────────
    overall_compliance = engine.compute_overall_score(pillar_scores)
    risk_score = engine.compute_risk_score(findings_by_severity, overall_compliance)
    weighted_sev = engine.compute_weighted_severity_score(findings_by_severity)

    pillar_finding_counts = {pillar: ps.total_findings for pillar, ps in findings_by_pillar.items()}
    biz_impact = engine.compute_business_impact_score(pillar_scores, pillar_finding_counts)

    # ── Methodology string (stored in report for Appendix) ────────────────────
    w = weights or DEFAULT_SCORING_WEIGHTS
    pillar_weight_str = ", ".join(
        f"{p.replace('_', ' ').title()} {int(v * 100)}%" for p, v in w.pillar_weights.items()
    )
    methodology = (
        "Weighted pass-rate model: pillar_score = weighted_passed / weighted_applicable × 100. "
        f"Severity weights — Critical: {w.severity_weights.get('critical', 10)}, "
        f"High: {w.severity_weights.get('high', 7)}, "
        f"Medium: {w.severity_weights.get('medium', 5)}, "
        f"Low: {w.severity_weights.get('low', 2)}, "
        f"Informational: {w.severity_weights.get('informational', 1)}. "
        "Resource criticality multipliers applied (Key Vault/SQL = 1.5×, "
        "VM/AKS/Web = 1.2×, Disk/NIC = 0.6–0.7×). "
        "NOT_APPLICABLE rules excluded from all calculations. "
        f"Overall score = fixed-pillar-weight average: {pillar_weight_str}. "
        "Risk = 100 − compliance + severity-amplification (up to +10 for critical/high mix). "
        "Business Impact = pillar-risk weighted by pillar importance and finding volume."
    )

    return ScoringResult(
        overall_compliance_score=overall_compliance,
        overall_risk_score=risk_score,
        weighted_severity_score=weighted_sev,
        business_impact_score=biz_impact,
        pillar_scores=pillar_scores,
        methodology=methodology,
    )
