"""Executive insights — strategic observations derived from WAF assessment findings.

Insight types:
  Risk Concentration   — where findings cluster by resource type or pillar
  Pillar Weakness      — which WAF pillar is the lowest performing
  Remediation Leverage — top findings that eliminate the most risk
  Governance           — configuration vs enforcement maturity gap (conditional)
  Trend Readiness      — baseline established for future maturity tracking

Safety rules:
  - Conservative language only: "may indicate", "suggests", "appears to",
    "could contribute", "potentially"
  - Never: "guarantees", "will cause", "certain breach", "proves", "confirms"
  - Never invents resources, findings, compliance certifications, financial losses,
    or security incidents not present in the assessment data
  - All public functions are fully defensive — never raise
  - Fallback mode: deterministic insights from finding counts when generation fails
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any, Sequence

from waf_shared.domain.models.finding import Finding


# ── Data types ─────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ExecutiveInsight:
    """A single strategic observation derived from actual assessment findings."""

    insight_type: str              # Risk Concentration | Pillar Weakness | Remediation Leverage | Governance | Trend Readiness
    insight: str                   # Observation text — hedged, conservative language only
    confidence: str                # High | Medium | Low
    supporting_findings: tuple[str, ...]   # Titles of findings backing this insight
    strategic_priority: str        # Immediate | Near-Term | Long-Term


@dataclass(frozen=True)
class StrategicRecommendations:
    """Three-horizon strategic recommendations derived from actual findings."""

    immediate_focus: str    # 0–30 days — critical/high severity actions
    near_term_focus: str    # 30–90 days — medium severity / monitoring improvements
    long_term_focus: str    # 90+ days  — governance, automation, continuous improvement


@dataclass(frozen=True)
class ExecutiveInsights:
    """Complete executive insights package for a WAF assessment."""

    observations: tuple[ExecutiveInsight, ...]   # up to 5 strategic observations
    strategic_recommendations: StrategicRecommendations
    assessment_narrative: str                     # 100–200 word executive narrative
    overall_confidence: str                       # High | Medium | Low


# ── Internal constants ─────────────────────────────────────────────────────────

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

_PILLAR_DISPLAY: dict[str, str] = {
    "security":               "Security",
    "reliability":            "Reliability",
    "operational_excellence": "Operational Excellence",
    "performance_efficiency": "Performance Efficiency",
    "cost_optimization":      "Cost Optimization",
}

_PILLAR_DOMAIN: dict[str, str] = {
    "security":               "data protection and access controls",
    "reliability":            "service reliability and availability controls",
    "operational_excellence": "operational governance and monitoring controls",
    "performance_efficiency": "application performance and capacity controls",
    "cost_optimization":      "cloud cost management controls",
}

_PILLAR_PRIORITY_LABEL: dict[str, str] = {
    "security":               "security controls",
    "reliability":            "resilience and availability controls",
    "operational_excellence": "operational monitoring and governance",
    "performance_efficiency": "application performance configuration",
    "cost_optimization":      "cloud cost management",
}

_PILLAR_SCORE_ORDER = [
    "security", "reliability", "operational_excellence",
    "performance_efficiency", "cost_optimization",
]


# ── Private helpers ────────────────────────────────────────────────────────────

def _tr(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"


def _calculate_pillar_scores(
    findings: list[Finding],
) -> list[tuple[str, int, str]]:
    """Compute (display_name, score, status) per pillar from findings.

    Score starts at 100; deductions: Critical=15, High=10, Medium=5, Low=2.
    Pillars not present in findings are omitted.  Never raises.
    """
    by_pillar: dict[str, dict[str, int]] = {}
    for f in findings:
        by_pillar.setdefault(f.pillar, {})
        by_pillar[f.pillar][f.severity.value] = by_pillar[f.pillar].get(f.severity.value, 0) + 1

    result: list[tuple[str, int, str]] = []
    for pk in _PILLAR_SCORE_ORDER:
        if pk not in by_pillar:
            continue
        c = by_pillar[pk]
        score = max(0, 100 - (
            c.get("critical", 0) * 15 + c.get("high", 0) * 10 +
            c.get("medium", 0) * 5 + c.get("low", 0) * 2
        ))
        if score >= 90:
            status = "Excellent"
        elif score >= 75:
            status = "Good"
        elif score >= 60:
            status = "Needs Improvement"
        else:
            status = "High Risk"
        result.append((_PILLAR_DISPLAY.get(pk, pk), score, status))
    return result


def _aggregate_confidence(observations: list[ExecutiveInsight]) -> str:
    """Weighted average of individual confidence scores → overall level."""
    if not observations:
        return "Low"
    weight = {"High": 2, "Medium": 1, "Low": 0}
    total = sum(weight.get(o.confidence, 0) for o in observations)
    avg = total / len(observations)
    if avg >= 1.5:
        return "High"
    if avg >= 0.75:
        return "Medium"
    return "Low"


def _build_fallback_insights() -> ExecutiveInsights:
    """Return minimal deterministic insights when data is insufficient."""
    return ExecutiveInsights(
        observations=(
            ExecutiveInsight(
                insight_type="Trend Readiness",
                insight=(
                    "Current assessment results establish a baseline for future maturity "
                    "tracking and continuous improvement initiatives."
                ),
                confidence="Low",
                supporting_findings=(),
                strategic_priority="Long-Term",
            ),
        ),
        strategic_recommendations=StrategicRecommendations(
            immediate_focus=(
                "Review all open findings and prioritize critical and high-severity items."
            ),
            near_term_focus=(
                "Improve monitoring and operational visibility across Azure resources."
            ),
            long_term_focus=(
                "Establish governance automation to reduce future configuration drift."
            ),
        ),
        assessment_narrative=(
            "The assessment did not identify sufficient findings to generate detailed executive "
            "insights. Review the findings data to ensure all Azure resources are covered by "
            "the assessment scope."
        ),
        overall_confidence="Low",
    )


# ── Insight builders ───────────────────────────────────────────────────────────

def _add_risk_concentration_insight(
    observations: list[ExecutiveInsight],
    findings: list[Finding],
    total: int,
) -> None:
    """Risk Concentration — where findings cluster by resource type (or pillar fallback)."""
    rt_counts: Counter[str] = Counter(f.resource_type for f in findings if f.resource_type)
    if rt_counts:
        top_rt, top_count = rt_counts.most_common(1)[0]
        short_rt = top_rt.rsplit("/", 1)[-1] if "/" in top_rt else top_rt
        pct = round(top_count / total * 100)
        supporting = tuple(
            f.title for f in findings if f.resource_type == top_rt
        )[:5]
        conf = calculate_insight_confidence(top_count, total)
        observations.append(ExecutiveInsight(
            insight_type="Risk Concentration",
            insight=(
                f"Approximately {pct}% of assessment findings originate from "
                f"{short_rt} configurations, suggesting this resource type may represent "
                f"the primary risk concentration area and could benefit from focused remediation."
            ),
            confidence=conf,
            supporting_findings=supporting,
            strategic_priority="Immediate" if conf == "High" else "Near-Term",
        ))
        return

    # Fallback: pillar concentration
    pillar_counts: Counter[str] = Counter(f.pillar for f in findings)
    if pillar_counts:
        top_pillar, top_count = pillar_counts.most_common(1)[0]
        pct = round(top_count / total * 100)
        display = _PILLAR_DISPLAY.get(top_pillar, top_pillar)
        domain = _PILLAR_DOMAIN.get(top_pillar, "infrastructure controls")
        supporting = tuple(f.title for f in findings if f.pillar == top_pillar)[:5]
        conf = calculate_insight_confidence(top_count, total)
        observations.append(ExecutiveInsight(
            insight_type="Risk Concentration",
            insight=(
                f"Approximately {pct}% of assessment findings originate from "
                f"{display} {domain}, suggesting this area may represent the primary "
                f"risk concentration requiring focused attention."
            ),
            confidence=conf,
            supporting_findings=supporting,
            strategic_priority="Immediate" if conf == "High" else "Near-Term",
        ))


def _add_pillar_weakness_insight(
    observations: list[ExecutiveInsight],
    pillar_scores: list[tuple[str, int, str]],
) -> None:
    """Pillar Weakness — lowest-performing WAF pillar from actual scores."""
    if not pillar_scores:
        return
    weakest = min(pillar_scores, key=lambda x: x[1])
    display_name, score, status = weakest[0], weakest[1], weakest[2]
    if score >= 90:
        return  # all pillars excellent — no weakness to report
    conf = "High" if score < 60 else "Medium" if score < 75 else "Low"
    priority = "Immediate" if score < 60 else "Near-Term"
    observations.append(ExecutiveInsight(
        insight_type="Pillar Weakness",
        insight=(
            f"{display_name} appears to be the lowest-performing Well-Architected pillar "
            f"(estimated score: {score}/100, status: {status}), suggesting it may warrant "
            f"prioritization before broader optimization initiatives."
        ),
        confidence=conf,
        supporting_findings=(),
        strategic_priority=priority,
    ))


def _add_remediation_leverage_insight(
    observations: list[ExecutiveInsight],
    findings: list[Finding],
    total: int,
) -> None:
    """Remediation Leverage — top findings that could eliminate the most risk."""
    critical_high = [
        f for f in sorted(
            findings,
            key=lambda x: _SEVERITY_ORDER.index(x.severity.value)
            if x.severity.value in _SEVERITY_ORDER else 99,
        )
        if f.severity.value in ("critical", "high")
    ]
    if not critical_high:
        return
    top_n = critical_high[:3]
    n = len(top_n)
    supporting = tuple(f.title for f in top_n)
    conf = calculate_insight_confidence(len(critical_high), total)
    observations.append(ExecutiveInsight(
        insight_type="Remediation Leverage",
        insight=(
            f"Addressing the top {n} high-priority finding{'s' if n != 1 else ''} could "
            f"potentially reduce the majority of currently identified critical and high-severity "
            f"risk exposure, as these represent the highest-impact items in the assessment."
        ),
        confidence=conf,
        supporting_findings=supporting,
        strategic_priority="Immediate",
    ))


def _add_governance_insight(
    observations: list[ExecutiveInsight],
    pillar_scores: list[tuple[str, int, str]],
) -> None:
    """Governance — generated only when Operational Excellence exceeds Security by >= 15 pts.

    This gap suggests governance processes may be present but security enforcement lags.
    """
    if not pillar_scores:
        return
    scores_dict = {ps[0]: ps[1] for ps in pillar_scores}
    ops_score = scores_dict.get("Operational Excellence")
    sec_score = scores_dict.get("Security")
    if ops_score is None or sec_score is None:
        return
    if ops_score - sec_score < 15:
        return
    observations.append(ExecutiveInsight(
        insight_type="Governance",
        insight=(
            "The assessment data suggests the environment may demonstrate stronger "
            "operational configuration consistency than security-control maturity. "
            "This could indicate that governance processes are present but security "
            "enforcement may require improvement to match operational standards."
        ),
        confidence="Medium",
        supporting_findings=(),
        strategic_priority="Near-Term",
    ))


def _add_trend_readiness_insight(
    observations: list[ExecutiveInsight],
    total: int,
) -> None:
    """Trend Readiness — always included as a baseline statement."""
    observations.append(ExecutiveInsight(
        insight_type="Trend Readiness",
        insight=(
            f"The current assessment — covering {total} "
            f"finding{'s' if total != 1 else ''} — establishes a baseline for future "
            f"maturity tracking and continuous improvement initiatives across all "
            f"Well-Architected pillars."
        ),
        confidence="High",
        supporting_findings=(),
        strategic_priority="Long-Term",
    ))


def _build_strategic_recommendations(findings: list[Finding]) -> StrategicRecommendations:
    """Derive three-horizon recommendations exclusively from actual findings."""
    critical = [f for f in findings if f.severity.value == "critical"]
    high = [f for f in findings if f.severity.value == "high"]
    medium = [f for f in findings if f.severity.value == "medium"]
    pillars_present = {f.pillar for f in findings}

    # Immediate (0–30 days) — critical / high security
    if critical:
        sample = ", ".join(f"'{_tr(f.title, 50)}'" for f in critical[:2])
        immediate = (
            f"Prioritize remediation of critical-severity findings including {sample} "
            f"to address the highest-severity risk exposure immediately."
        )
    elif high:
        top_sec_high = ([f for f in high if f.pillar == "security"] or high)[:1]
        area = _PILLAR_PRIORITY_LABEL.get(top_sec_high[0].pillar, "security controls")
        immediate = (
            f"Prioritize {area} remediation to address the highest-severity findings "
            f"before other improvement initiatives."
        )
    else:
        immediate = (
            "Review all open findings and address any remaining medium-severity items "
            "that may collectively increase risk exposure."
        )

    # Near-term (30–90 days) — monitoring / medium severity
    if "operational_excellence" in pillars_present or "reliability" in pillars_present:
        near_term = (
            "Improve monitoring, diagnostics, and operational visibility controls to "
            "strengthen incident detection and response capabilities."
        )
    elif medium:
        near_term = (
            "Address medium-severity findings to reduce accumulated risk before they "
            "could contribute to more complex operational or security events."
        )
    else:
        near_term = (
            "Review operational controls and monitoring configurations to improve "
            "visibility and detection capabilities across the environment."
        )

    # Long-term (90+ days) — governance / policy
    if "cost_optimization" in pillars_present or "operational_excellence" in pillars_present:
        long_term = (
            "Expand governance automation and policy-based enforcement to reduce future "
            "configuration drift and improve compliance consistency across cloud resources."
        )
    else:
        long_term = (
            "Develop a continuous improvement programme to track assessment maturity and "
            "enforce architectural standards consistently across all cloud workloads."
        )

    return StrategicRecommendations(
        immediate_focus=immediate,
        near_term_focus=near_term,
        long_term_focus=long_term,
    )


def _build_assessment_narrative(
    findings: list[Finding],
    pillar_scores: list[tuple[str, int, str]],
) -> str:
    """Build a 100–200 word executive narrative from actual assessment data only."""
    total = len(findings)
    sev_counts: Counter[str] = Counter(f.severity.value for f in findings)
    critical = sev_counts.get("critical", 0)
    high_count = sev_counts.get("high", 0)

    pillar_counts: Counter[str] = Counter(f.pillar for f in findings)
    dominant_pillar = pillar_counts.most_common(1)[0][0] if pillar_counts else "security"
    domain = _PILLAR_DOMAIN.get(dominant_pillar, "infrastructure controls")
    focus_area = _PILLAR_PRIORITY_LABEL.get(dominant_pillar, "infrastructure controls")

    well_scored = [ps for ps in pillar_scores if len(ps) >= 2 and ps[1] >= 75]
    if well_scored:
        strength_clause = (
            f" While the environment appears to demonstrate a reasonable foundation in "
            f"certain areas, improvements in {focus_area} would significantly reduce "
            f"overall risk exposure."
        )
    else:
        strength_clause = (
            f" Improvements in {focus_area} appear to represent the strongest opportunity "
            f"for near-term risk reduction."
        )

    if critical > 0 or high_count > 0:
        ch_total = critical + high_count
        priority_clause = (
            f" Addressing the {critical} critical and {high_count} high-severity "
            f"finding{'s' if ch_total != 1 else ''} should be treated as immediate "
            f"priorities to reduce potential exposure."
        )
    else:
        priority_clause = (
            " Continuing to monitor and remediate the identified findings will support "
            "ongoing maturity improvement."
        )

    return (
        f"The assessment identified {total} finding{'s' if total != 1 else ''} across the "
        f"Azure environment. The largest concentration of risk was observed within {domain}."
        f"{strength_clause}"
        f" The strongest near-term opportunity lies in addressing {focus_area}, which "
        f"collectively represents the majority of high-priority recommendations."
        f"{priority_clause}"
    )


# ── Public API ─────────────────────────────────────────────────────────────────

def calculate_insight_confidence(supporting_count: int, total_count: int) -> str:
    """Return confidence level based on supporting evidence ratio.

    High:   supporting_count / total_count >= 0.5 AND supporting_count >= 3
    Medium: ratio >= 0.25 OR supporting_count >= 2
    Low:    otherwise, including zero or negative inputs

    Never raises.
    """
    try:
        if total_count <= 0 or supporting_count <= 0:
            return "Low"
        ratio = supporting_count / total_count
        if ratio >= 0.5 and supporting_count >= 3:
            return "High"
        if ratio >= 0.25 or supporting_count >= 2:
            return "Medium"
        return "Low"
    except Exception:
        return "Low"


def generate_executive_insights(
    findings: Sequence[Finding],
    pillar_scores: list[tuple[str, int, str]] | None = None,
    business_impact_score: float | None = None,
    roadmap: list[dict[str, Any]] | None = None,
) -> ExecutiveInsights:
    """Generate strategic executive insights from actual assessment findings.

    Derives all observations exclusively from the provided findings and scores.
    No data is fabricated.  Conservative, hedged language throughout.

    Falls back to deterministic insights when data is insufficient or any error occurs.
    Never raises.
    """
    try:
        findings_list = list(findings)
        if not findings_list:
            return _build_fallback_insights()

        total = len(findings_list)

        if pillar_scores is None:
            pillar_scores = _calculate_pillar_scores(findings_list)

        observations: list[ExecutiveInsight] = []

        try:
            _add_risk_concentration_insight(observations, findings_list, total)
        except Exception:
            pass

        try:
            _add_pillar_weakness_insight(observations, pillar_scores)
        except Exception:
            pass

        try:
            _add_remediation_leverage_insight(observations, findings_list, total)
        except Exception:
            pass

        try:
            _add_governance_insight(observations, pillar_scores)
        except Exception:
            pass

        try:
            _add_trend_readiness_insight(observations, total)
        except Exception:
            pass

        if not observations:
            return _build_fallback_insights()

        recommendations = _build_strategic_recommendations(findings_list)
        narrative = _build_assessment_narrative(findings_list, pillar_scores)
        overall_conf = _aggregate_confidence(observations)

        return ExecutiveInsights(
            observations=tuple(observations),
            strategic_recommendations=recommendations,
            assessment_narrative=narrative,
            overall_confidence=overall_conf,
        )

    except Exception:
        return _build_fallback_insights()
