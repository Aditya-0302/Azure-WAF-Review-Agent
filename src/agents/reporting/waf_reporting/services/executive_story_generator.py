"""Executive narrative generator — five paragraphs derived from WAF assessment data.

Input:   AggregatedReport + list[Finding]
Output:  ExecutiveNarrative (five string paragraphs, 80–140 words each)

Safety rules:
  - No hallucination: every statement traces directly to actual assessment data
  - Omit statements when data is insufficient rather than inventing
  - Qualitative language only: "may", "could", "potentially", "appears to"
  - Never: "guarantees", "will cause", "certain breach", "confirms", "proves"
  - Never invents financial values, compliance certifications, or legal exposure
  - Fully defensive: never raises; fallback narrative returned on any error
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass

from waf_reporting.aggregator import AggregatedReport

from waf_shared.domain.models.finding import Finding

# ── Lookup tables ──────────────────────────────────────────────────────────────

_PILLAR_DISPLAY: dict[str, str] = {
    "security": "Security",
    "reliability": "Reliability",
    "operational_excellence": "Operational Excellence",
    "performance_efficiency": "Performance Efficiency",
    "cost_optimization": "Cost Optimization",
}

_PILLAR_DOMAIN: dict[str, str] = {
    "security": "data protection and access controls",
    "reliability": "service reliability and availability controls",
    "operational_excellence": "operational governance and monitoring controls",
    "performance_efficiency": "application performance and capacity controls",
    "cost_optimization": "cloud cost management controls",
}

_PILLAR_BUSINESS_RISK: dict[str, str] = {
    "security": (
        "potential exposure to unauthorised access, data compromise, and "
        "related compliance implications"
    ),
    "reliability": (
        "potential impact to service availability, business continuity, "
        "and recovery time objectives"
    ),
    "operational_excellence": (
        "potential reduction in operational visibility, incident detection speed, "
        "and change management confidence"
    ),
    "performance_efficiency": (
        "potential degradation of user-facing application performance "
        "and capacity management effectiveness"
    ),
    "cost_optimization": (
        "potential unnecessary cloud expenditure and budget allocation " "inefficiencies"
    ),
}

_SEVERITY_DEDUCTIONS: dict[str, int] = {
    "critical": 15,
    "high": 10,
    "medium": 5,
    "low": 2,
    "informational": 0,
}

_PILLAR_SCORE_ORDER = [
    "security",
    "reliability",
    "operational_excellence",
    "performance_efficiency",
    "cost_optimization",
]


# ── Data type ──────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ExecutiveNarrative:
    """Five professional narrative paragraphs derived from WAF assessment data."""

    executive_overview: str  # A. overall health, pillars, compliance, risk
    primary_risk_drivers: str  # B. why risk exists, resources, misconfigs
    business_consequences: str  # C. cautious business impact (may/could/potentially)
    remediation_outlook: str  # D. projected compliance improvement
    executive_recommendation: str  # E. prioritised action plan across three horizons


# ── Private helpers ────────────────────────────────────────────────────────────


def _local_pillar_scores(
    findings: list[Finding],
    aggregated: AggregatedReport,
) -> list[tuple[str, int, str]]:
    """Compute (display_name, score, status) from aggregated data (fallback: raw findings).

    Score starts at 100; deductions: Critical=15, High=10, Medium=5, Low=2.
    Pillars with no findings are omitted.  Never raises.
    """
    try:
        by_pillar: dict[str, dict[str, int]] = {}

        # Prefer validated aggregated data
        for pk, ps in aggregated.findings_by_pillar.items():
            by_pillar[pk] = dict(ps.findings_by_severity)

        # Fallback if aggregated has no pillar data
        if not by_pillar:
            for f in findings:
                by_pillar.setdefault(f.pillar, {})
                sev = f.severity.value
                by_pillar[f.pillar][sev] = by_pillar[f.pillar].get(sev, 0) + 1

        result: list[tuple[str, int, str]] = []
        seen: set[str] = set()

        for pk in _PILLAR_SCORE_ORDER:
            if pk not in by_pillar:
                continue
            c = by_pillar[pk]
            score = max(
                0, 100 - sum(_SEVERITY_DEDUCTIONS.get(sev, 0) * cnt for sev, cnt in c.items())
            )
            if score >= 90:
                status = "Excellent"
            elif score >= 75:
                status = "Good"
            elif score >= 60:
                status = "Needs Improvement"
            else:
                status = "High Risk"
            result.append((_PILLAR_DISPLAY.get(pk, pk), score, status))
            seen.add(pk)

        for pk in by_pillar:
            if pk in seen:
                continue
            c = by_pillar[pk]
            score = max(
                0, 100 - sum(_SEVERITY_DEDUCTIONS.get(sev, 0) * cnt for sev, cnt in c.items())
            )
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
    except Exception:
        return []


def _project_compliance(agg: AggregatedReport) -> tuple[float, float]:
    """Return (after_high_fixed, after_high_and_medium_fixed) compliance %.

    Replicates the PDF compliance projection formula without importing from
    pdf_generator (avoids circular dependency).
    Returns (current, current) on error or when no projection is possible.
    """
    try:
        sev = agg.findings_by_severity
        crit = sev.get("critical", 0)
        high = sev.get("high", 0)
        med = sev.get("medium", 0)
        low = sev.get("low", 0)
        total = agg.total_findings
        current = agg.overall_compliance_score

        if total == 0:
            return current, current

        rem_h = total - high
        if rem_h <= 0:
            after_high = 100.0
        else:
            w_h = crit * 1.0 + med * 0.5 + low * 0.25
            after_high = max(0.0, min(100.0, round((1.0 - w_h / rem_h) * 100, 1)))

        rem_hm = total - high - med
        if rem_hm <= 0:
            after_hm = 100.0
        else:
            w_hm = crit * 1.0 + low * 0.25
            after_hm = max(0.0, min(100.0, round((1.0 - w_hm / rem_hm) * 100, 1)))

        return after_high, after_hm
    except Exception:
        return agg.overall_compliance_score, agg.overall_compliance_score


def _maturity_label(compliance: float) -> str:
    if compliance >= 90:
        return "enterprise-ready"
    if compliance >= 80:
        return "strong"
    if compliance >= 70:
        return "moderate"
    if compliance >= 60:
        return "developing"
    return "early-stage"


# ── Paragraph builders ─────────────────────────────────────────────────────────


def _build_executive_overview(
    agg: AggregatedReport,
    findings: list[Finding],
    pillar_scores: list[tuple[str, int, str]],
) -> str:
    """Paragraph A — overall health, strongest/weakest pillar, compliance, risk."""
    total = agg.total_findings
    compliance = agg.overall_compliance_score
    risk = agg.overall_risk_score
    maturity = _maturity_label(compliance)

    scope = f"{agg.total_resources} assessed resource{'s' if agg.total_resources != 1 else ''}"
    if agg.subscription_count > 0:
        scope += (
            f" across {agg.subscription_count} "
            f"Azure subscription{'s' if agg.subscription_count != 1 else ''}"
        )

    crit = agg.findings_by_severity.get("critical", 0)
    high = agg.findings_by_severity.get("high", 0)

    if crit > 0 and high > 0:
        urgency = (
            f", including {crit} critical and {high} high-severity "
            f"item{'s' if (crit + high) > 1 else ''} requiring immediate attention"
        )
    elif crit > 0:
        urgency = (
            f", including {crit} critical-severity "
            f"item{'s' if crit > 1 else ''} requiring immediate attention"
        )
    elif high > 0:
        urgency = (
            f", including {high} high-severity "
            f"item{'s' if high > 1 else ''} requiring prompt remediation"
        )
    else:
        urgency = ""

    risk_desc = "elevated" if risk >= 70 else "moderate" if risk >= 40 else "manageable"

    pillar_clause = ""
    if pillar_scores and len(pillar_scores) >= 2:
        strongest = max(pillar_scores, key=lambda x: x[1])
        weakest = min(pillar_scores, key=lambda x: x[1])
        if strongest[0] != weakest[0]:
            pillar_clause = (
                f" The {strongest[0]} pillar demonstrates the strongest compliance "
                f"posture at {strongest[1]}/100, while {weakest[0]} represents the "
                f"primary improvement opportunity, scoring {weakest[1]}/100."
            )
        else:
            # All evaluated pillars share the same score
            pillar_clause = (
                f" All evaluated pillars score equally at {strongest[1]}/100 "
                f"({strongest[2]}), indicating consistent performance across the "
                f"assessed Well-Architected dimensions."
            )
    elif pillar_scores:
        only = pillar_scores[0]
        pillar_clause = (
            f" The {only[0]} pillar is the primary area with identified findings, "
            f"scoring {only[1]}/100 ({only[2]})."
        )

    if total == 0:
        return (
            f"This Azure Well-Architected Framework assessment reviewed {scope} "
            f"and identified no actionable findings across the evaluated controls. "
            f"The environment demonstrates an enterprise-ready compliance posture, "
            f"with an overall compliance score of {compliance:.1f}% and an overall "
            f"risk score of {risk:.1f}%, indicating that assessed resources are "
            f"operating within expected Well-Architected parameters. This result "
            f"provides confidence in the current configuration baseline and supports "
            f"the ongoing investment in proactive cloud governance. A regular "
            f"assessment cadence is recommended to sustain this posture as the "
            f"cloud environment evolves."
        )

    coverage_clause = ""
    if agg.resources_with_findings > 0 and not urgency:
        coverage_clause = (
            f" Of these, {agg.resources_with_findings} "
            f"resource{'s' if agg.resources_with_findings != 1 else ''} had at "
            f"least one identified finding, representing "
            f"{agg.coverage_percentage * 100:.0f}% of the assessed environment."
        )

    return (
        f"This Azure Well-Architected Framework assessment reviewed {scope} and "
        f"identified {total} finding{'s' if total != 1 else ''}{urgency}."
        f"{coverage_clause} "
        f"The environment demonstrates a {maturity} compliance posture, with an "
        f"overall compliance score of {compliance:.1f}% and an overall risk score "
        f"of {risk:.1f}% ({risk_desc} risk level)."
        f"{pillar_clause} "
        f"This assessment provides a structured baseline for prioritising remediation "
        f"efforts toward the enterprise Well-Architected target of 90% compliance."
    ).strip()


def _build_primary_risk_drivers(
    agg: AggregatedReport,
    findings: list[Finding],
) -> str:
    """Paragraph B — WHY risk exists, resource types, misconfigs, concentration."""
    total = agg.total_findings

    if total == 0:
        return (
            "No findings were identified in this assessment, indicating that the "
            "environment is operating within expected Well-Architected Framework "
            "parameters across all evaluated controls. The absence of findings "
            "suggests the configuration baseline is currently sound. Periodic "
            "reassessment is still recommended as workloads evolve, new resources "
            "are provisioned, and the threat landscape changes. Proactive monitoring, "
            "continuous configuration management, and a structured assessment cadence "
            "will help sustain this result and detect any emerging drift before it "
            "develops into a material risk to the organisation."
        )

    # Dominant pillar by finding count
    pillar_counts = {pk: ps.total_findings for pk, ps in agg.findings_by_pillar.items()}
    if not pillar_counts and findings:
        pillar_counts = dict(Counter(f.pillar for f in findings))

    if not pillar_counts:
        return (
            "The primary risk drivers are detailed in the Detailed Findings section. "
            "Review the finding distribution by pillar in the Compliance Overview "
            "to understand where risk is most concentrated in the environment."
        )

    dominant_pillar = max(pillar_counts, key=lambda p: pillar_counts[p])
    dominant_count = pillar_counts[dominant_pillar]
    dominant_pct = round(dominant_count / total * 100)
    domain = _PILLAR_DOMAIN.get(dominant_pillar, "infrastructure controls")
    display = _PILLAR_DISPLAY.get(dominant_pillar, dominant_pillar.replace("_", " ").title())

    # Recurring resource type from raw findings or aggregated inventory
    rt_clause = ""
    if findings:
        rt_counts: Counter[str] = Counter(f.resource_type for f in findings if f.resource_type)
        if rt_counts:
            top_rt, rt_count = rt_counts.most_common(1)[0]
            short_rt = top_rt.rsplit("/", 1)[-1] if "/" in top_rt else top_rt
            rt_pct = round(rt_count / total * 100)
            rt_clause = (
                f" {short_rt} resources account for approximately {rt_pct}% of all "
                f"identified findings, suggesting this resource type may benefit from "
                f"targeted configuration review and policy enforcement."
            )
    elif agg.resource_type_inventory:
        most_affected = max(
            agg.resource_type_inventory.values(),
            key=lambda s: s.with_findings,
        )
        if most_affected.with_findings > 0:
            short = most_affected.resource_type.rsplit("/", 1)[-1]
            rt_clause = (
                f" {short} resources were among the most affected resource types, "
                f"with {most_affected.with_findings} "
                f"resource{'s' if most_affected.with_findings != 1 else ''} flagged."
            )

    # Recurring rule pattern (most frequent misconfiguration)
    misc_clause = ""
    if findings:
        rule_counts: Counter[str] = Counter(f.rule_id for f in findings)
        top_rule, rule_count = rule_counts.most_common(1)[0]
        if rule_count >= 3:
            misc_clause = (
                f" A single configuration pattern (rule {top_rule}) appears across "
                f"{rule_count} finding{'s' if rule_count != 1 else ''}, indicating "
                f"a recurring misconfiguration that may benefit from automated "
                f"policy-based remediation."
            )
        elif rule_count >= 2:
            misc_clause = (
                " Several findings share common configuration patterns, suggesting "
                "systematic gaps that could be addressed through policy enforcement."
            )

    return (
        f"The primary concentration of risk is within {display} controls, "
        f"which account for approximately {dominant_pct}% of all findings "
        f"related to {domain}."
        f"{rt_clause}"
        f"{misc_clause} "
        f"This concentration suggests that a focused remediation effort targeting "
        f"this area is likely to yield the greatest overall compliance improvement "
        f"relative to the effort invested."
    ).strip()


def _build_business_consequences(
    agg: AggregatedReport,
    findings: list[Finding],
) -> str:
    """Paragraph C — cautious business impact using may/could/potentially."""
    total = agg.total_findings

    if total == 0:
        return (
            "No actionable findings were identified that could introduce measurable "
            "business consequences based on the evaluated controls. The assessed "
            "resources appear to meet Well-Architected Framework expectations across "
            "all evaluated pillars, suggesting the organisation's current cloud "
            "configuration practices are broadly aligned with enterprise standards. "
            "Maintaining these practices, combined with proactive monitoring, "
            "regular reassessment, and continued adoption of Azure governance tools, "
            "may support sustained compliance and help prevent future risk "
            "accumulation as the environment grows, evolves, and onboards new "
            "Azure workloads over time."
        )

    # Top two pillars by finding count to keep consequences focused
    pillar_counts = {pk: ps.total_findings for pk, ps in agg.findings_by_pillar.items()}
    if not pillar_counts and findings:
        pillar_counts = dict(Counter(f.pillar for f in findings))

    top_pillars = sorted(pillar_counts, key=lambda p: pillar_counts[p], reverse=True)[:2]

    consequences: list[str] = []
    for pillar in _PILLAR_SCORE_ORDER:
        if pillar not in top_pillars:
            continue
        risk_phrase = _PILLAR_BUSINESS_RISK.get(pillar)
        if risk_phrase:
            consequences.append(risk_phrase)

    if not consequences:
        consequences.append(
            "potential operational disruption and compliance exposure "
            "across the assessed environment"
        )

    if len(consequences) == 1:
        cons_str = consequences[0]
    else:
        cons_str = f"{consequences[0]}, as well as {consequences[1]}"

    crit = agg.findings_by_severity.get("critical", 0)
    high = agg.findings_by_severity.get("high", 0)

    if crit > 0:
        urgency_clause = (
            f" The presence of {crit} critical-severity "
            f"finding{'s' if crit > 1 else ''} may pose the most immediate business "
            f"exposure and could warrant prompt executive attention."
        )
    elif high > 0:
        urgency_clause = (
            f" The {high} high-severity "
            f"finding{'s' if high > 1 else ''} identified could contribute to "
            f"meaningful exposure if not addressed within the recommended timeframe."
        )
    else:
        urgency_clause = (
            " Addressing the identified findings within a structured remediation "
            "programme may reduce exposure before risk accumulates further."
        )

    return (
        f"The findings in this assessment could potentially contribute to "
        f"{cons_str}."
        f"{urgency_clause} "
        f"These are qualitative observations derived solely from assessment data. "
        f"Actual business impact may vary based on the organisation's specific "
        f"workload characteristics, existing mitigating controls, risk tolerance, "
        f"and the compensating safeguards already in place across the environment."
    ).strip()


def _build_remediation_outlook(
    agg: AggregatedReport,
    findings: list[Finding],
) -> str:
    """Paragraph D — projected compliance improvement after High and Medium remediation."""
    total = agg.total_findings
    current = agg.overall_compliance_score

    if total == 0:
        return (
            f"With no actionable findings identified, the environment is well "
            f"positioned to maintain its current compliance score of {current:.1f}%. "
            f"Continued reassessment on a regular cadence may support early "
            f"identification of configuration drift and help preserve the "
            f"Well-Architected compliance baseline established in this initial review. "
            f"As new Azure services are adopted and existing workloads evolve, "
            f"maintaining this assessment discipline will be important for "
            f"sustaining ongoing enterprise compliance and demonstrating a "
            f"consistent, auditable governance posture to internal stakeholders "
            f"and external auditors over time."
        )

    crit = agg.findings_by_severity.get("critical", 0)
    high = agg.findings_by_severity.get("high", 0)
    med = agg.findings_by_severity.get("medium", 0)

    after_high, after_hm = _project_compliance(agg)
    high_gain = round(after_high - current, 1)
    hm_gain = round(after_hm - current, 1)

    if high > 0 and high_gain > 0:
        high_clause = (
            f"Remediating the {high} high-severity "
            f"finding{'s' if high > 1 else ''} is projected to improve the overall "
            f"compliance score from {current:.1f}% to approximately {after_high:.1f}% "
            f"(+{high_gain:.1f} percentage point{'s' if high_gain != 1.0 else ''})."
        )
    elif crit > 0:
        high_clause = (
            f"Addressing the {crit} critical-severity "
            f"finding{'s' if crit > 1 else ''} represents the highest-priority "
            f"remediation opportunity. Resolving these items is expected to produce "
            f"the most significant improvement in the current compliance score of "
            f"{current:.1f}% and meaningfully reduce overall risk exposure."
        )
    else:
        high_clause = (
            f"The current compliance score of {current:.1f}% reflects the "
            f"identified medium and lower-severity findings. Systematically "
            f"addressing these items through a structured remediation programme "
            f"is expected to improve compliance over successive assessment cycles."
        )

    hm_clause = ""
    if med > 0 and hm_gain > high_gain:
        hm_clause = (
            f" Further addressing the {med} medium-severity "
            f"finding{'s' if med > 1 else ''} could lift compliance to "
            f"approximately {after_hm:.1f}% "
            f"(+{hm_gain:.1f} percentage point{'s' if hm_gain != 1.0 else ''} total), "
            f"approaching the 90% enterprise target."
        )

    pillars_present = {f.pillar for f in findings} if findings else set(agg.findings_by_pillar)
    benefit_clause = ""
    if "security" in pillars_present:
        benefit_clause = (
            " Improving security control compliance may also reduce exposure to "
            "audit findings and strengthen the organisation's overall risk posture."
        )
    elif "reliability" in pillars_present:
        benefit_clause = (
            " Improving reliability controls may strengthen service continuity "
            "commitments and reduce mean time to recovery during incidents."
        )

    return (
        f"{high_clause}{hm_clause}{benefit_clause} "
        f"These projections are estimates derived from the current assessment's "
        f"severity distribution and may vary based on the actual complexity of "
        f"individual remediations, available remediation resources, and any "
        f"interdependencies between findings."
    ).strip()


def _build_executive_recommendation(
    agg: AggregatedReport,
    findings: list[Finding],
) -> str:
    """Paragraph E — prioritised action plan across three horizons."""
    total = agg.total_findings
    crit = agg.findings_by_severity.get("critical", 0)
    high = agg.findings_by_severity.get("high", 0)
    med = agg.findings_by_severity.get("medium", 0)

    if total == 0:
        return (
            "The environment currently meets all evaluated Well-Architected Framework "
            "controls. It is recommended to maintain current configuration standards, "
            "establish a monthly assessment cadence to detect future configuration "
            "drift early, and continue expanding WAF control coverage as new Azure "
            "services are adopted. Applying governance automation such as Azure "
            "Policy assignments and automated compliance dashboards will help "
            "sustain this compliance baseline, strengthen auditability, and support "
            "enterprise risk management objectives. Documenting the current "
            "configuration baseline also provides a valuable reference point for "
            "future assessments and compliance audits."
        )

    if crit > 0:
        immediate = (
            f"immediately assign dedicated remediation capacity to all "
            f"{crit} critical-severity "
            f"finding{'s' if crit > 1 else ''} to address the most significant "
            f"risk exposure"
        )
    elif high > 0:
        immediate = (
            f"prioritise the {high} high-severity "
            f"finding{'s' if high > 1 else ''} for resolution within 30 days, "
            f"as these represent the highest-severity items in the assessment"
        )
    else:
        immediate = (
            "review and triage all identified findings to establish a structured "
            "remediation backlog with clear ownership and target dates"
        )

    most_affected = (
        max(agg.findings_by_pillar, key=lambda p: agg.findings_by_pillar[p].total_findings)
        if agg.findings_by_pillar
        else None
    )
    if most_affected:
        display = _PILLAR_DISPLAY.get(most_affected, most_affected.replace("_", " ").title())
        ps = agg.findings_by_pillar[most_affected]
        medium_term = (
            f"focus the next remediation sprint on the {display} pillar, "
            f"which carries {ps.total_findings} "
            f"finding{'s' if ps.total_findings != 1 else ''} and represents "
            f"the highest concentration of identified risk"
        )
    elif med > 0:
        medium_term = (
            f"address the {med} medium-severity "
            f"finding{'s' if med > 1 else ''} within the next 60–90 days "
            f"to prevent accumulated risk"
        )
    else:
        medium_term = (
            "continue monitoring all Well-Architected pillars and address any "
            "newly identified findings in the next assessment cycle"
        )

    oe_ps = agg.findings_by_pillar.get("operational_excellence")
    if oe_ps and oe_ps.total_findings > 0:
        governance = (
            "implement Azure Policy assignments and automated compliance reporting "
            "to address the identified operational excellence gaps and reduce "
            "future configuration drift"
        )
    else:
        governance = (
            "establish a regular assessment cadence and governance framework "
            "to proactively detect and address configuration drift over time"
        )

    return (
        f"The following prioritised actions are recommended based on this assessment. "
        f"In the immediate term, {immediate}. "
        f"Over the medium term, {medium_term}. "
        f"For long-term governance, {governance}. "
        f"Establishing a regular Well-Architected assessment cadence will provide an "
        f"auditable compliance history and support continuous improvement toward "
        f"enterprise security and operational objectives."
    ).strip()


def _build_fallback_narrative() -> ExecutiveNarrative:
    """Return minimal deterministic narrative when generation fails."""
    return ExecutiveNarrative(
        executive_overview=(
            "This Azure Well-Architected Framework assessment has completed. "
            "Review the Detailed Findings and Compliance Overview sections of this "
            "report for a complete view of the environment's compliance posture and "
            "identified risk areas."
        ),
        primary_risk_drivers=(
            "The primary risk drivers are detailed in the findings sections of this "
            "report. Review the finding distribution by pillar in the Compliance "
            "Overview to understand where risk is most concentrated in the assessed "
            "environment."
        ),
        business_consequences=(
            "Business consequences may vary based on the specific findings identified "
            "in this assessment. Review the Business Impact Analysis section for a "
            "structured view of potential business consequences derived from the "
            "assessment findings."
        ),
        remediation_outlook=(
            "Remediation outlook information is available in the Compliance Projection "
            "and Executive Remediation Roadmap sections of this report. These sections "
            "provide projected compliance scores after addressing high and medium "
            "severity findings."
        ),
        executive_recommendation=(
            "It is recommended to review all identified findings, prioritise by "
            "severity, and establish a structured remediation programme. Refer to "
            "the Executive Recommendations section of this report for detailed "
            "guidance on immediate, medium-term, and long-term actions."
        ),
    )


# ── Public API ─────────────────────────────────────────────────────────────────


def generate_executive_narrative(
    aggregated: AggregatedReport,
    findings: Sequence[Finding],
) -> ExecutiveNarrative:
    """Generate five professional executive narrative paragraphs.

    All content is derived exclusively from actual assessment data.
    Conservative, hedged language is used throughout.
    Never raises — returns a fallback narrative on any error.
    """
    try:
        findings_list = list(findings)
        pillar_scores = _local_pillar_scores(findings_list, aggregated)

        overview = _build_executive_overview(aggregated, findings_list, pillar_scores)
        drivers = _build_primary_risk_drivers(aggregated, findings_list)
        consequences = _build_business_consequences(aggregated, findings_list)
        outlook = _build_remediation_outlook(aggregated, findings_list)
        recommendation = _build_executive_recommendation(aggregated, findings_list)

        return ExecutiveNarrative(
            executive_overview=overview,
            primary_risk_drivers=drivers,
            business_consequences=consequences,
            remediation_outlook=outlook,
            executive_recommendation=recommendation,
        )
    except Exception:
        return _build_fallback_narrative()
