"""Business impact analysis — translates technical WAF findings into business consequences.

Classifies each finding into five executive risk categories:
  Security Risk    — unauthorized access, weak encryption, missing controls
  Compliance Risk  — regulatory / policy exposure from missing controls
  Operational Risk — monitoring gaps, backup failures, recovery issues
  Financial Risk   — cost overruns, idle resources, budget exposure
  Reputation Risk  — public exposure scenarios, data breach risk

Safety rules:
  - Qualitative language only: "Potential", "May increase", "Could contribute",
    "May affect" — never "Will cause", "Guaranteed loss", "Certain breach"
  - Never invents financial values, compliance certifications, or legal exposure
  - All public functions are fully defensive — never raise
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from waf_shared.domain.models.finding import Finding

# ── Data types ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class BusinessImpact:
    """Business impact classification for a single finding."""

    risk_category: (
        str  # Security Risk | Compliance Risk | Operational Risk | Financial Risk | Reputation Risk
    )
    finding_impact: str  # qualitative business impact sentence (hedged language)
    priority: str  # P1 (critical) → P5 (informational)
    impact_score: int  # 100 / 75 / 50 / 25 / 0


# ── Lookup tables ──────────────────────────────────────────────────────────────

_SEV_SCORE: dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "informational": 0,
}

_SEV_PRIORITY: dict[str, str] = {
    "critical": "P1",
    "high": "P2",
    "medium": "P3",
    "low": "P4",
    "informational": "P5",
}

_SEV_IMPACT_LEVEL: dict[str, str] = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Low",
}

# Primary risk category per WAF pillar — used as the "Risk Category" column value
_PILLAR_PRIMARY_CATEGORY: dict[str, str] = {
    "security": "Security Risk",
    "reliability": "Operational Risk",
    "operational_excellence": "Operational Risk",
    "performance_efficiency": "Operational Risk",
    "cost_optimization": "Financial Risk",
}

# All risk categories each pillar contributes to — used for aggregate PDF table
_PILLAR_CONTRIBUTES_TO: dict[str, set[str]] = {
    "security": {
        "Security Risk",
        "Compliance Risk",
        "Reputation Risk",
    },
    "reliability": {
        "Operational Risk",
        "Compliance Risk",
    },
    "operational_excellence": {
        "Operational Risk",
        "Compliance Risk",
    },
    "performance_efficiency": {
        "Operational Risk",
        "Financial Risk",
    },
    "cost_optimization": {
        "Financial Risk",
    },
}

# Reputation risk is only elevated for critical or high security/reliability findings
_REPUTATION_RISK_SEVERITIES: frozenset[str] = frozenset({"critical", "high"})

# Finding-level impact sentence templates — all hedged / qualitative
_FINDING_IMPACT_TEMPLATES: dict[str, dict[str, str]] = {
    "security": {
        "critical": (
            "Potential unauthorized access to sensitive data — may increase exposure "
            "to security incidents, compliance violations, and reputational harm."
        ),
        "high": (
            "Could contribute to unauthorized data access or system compromise; "
            "may affect compliance posture and customer trust."
        ),
        "medium": (
            "May increase security risk if combined with other vulnerabilities; "
            "potential compliance gap that could affect internal security policies."
        ),
        "low": (
            "Minor security hygiene gap; potential to weaken overall security posture "
            "over time if left unaddressed."
        ),
        "informational": (
            "Best-practice observation; may affect compliance documentation "
            "and security posture reporting."
        ),
    },
    "reliability": {
        "critical": (
            "Potential service disruption affecting business availability; "
            "may delay incident detection and increase recovery time significantly."
        ),
        "high": (
            "Could contribute to extended downtime; may affect business continuity "
            "and service commitments to customers."
        ),
        "medium": (
            "May reduce service resilience; potential for increased recovery time "
            "during infrastructure incidents."
        ),
        "low": (
            "Minor reliability gap; limited direct operational impact under "
            "normal operating conditions."
        ),
        "informational": (
            "Best-practice reliability observation; minimal direct impact "
            "on service availability."
        ),
    },
    "operational_excellence": {
        "critical": (
            "Reduced operational visibility may significantly delay incident detection "
            "and disrupt recovery workflows, increasing mean time to recovery."
        ),
        "high": (
            "Could increase mean time to recovery; may affect engineering efficiency "
            "and change management confidence."
        ),
        "medium": (
            "May reduce operational confidence; potential for slower incident response "
            "and reduced deployment safety."
        ),
        "low": (
            "Minor operational gap; limited direct impact on service delivery "
            "under normal conditions."
        ),
        "informational": (
            "Best-practice operational observation; minimal direct impact "
            "on engineering processes."
        ),
    },
    "performance_efficiency": {
        "critical": (
            "Potential performance degradation affecting user experience; "
            "may increase operational costs and risk capacity failures under load."
        ),
        "high": (
            "Could contribute to latency increases or capacity shortfalls; "
            "may affect user experience during peak traffic periods."
        ),
        "medium": (
            "May affect application responsiveness; potential for degraded "
            "user experience under sustained load."
        ),
        "low": (
            "Minor performance consideration; limited direct user-facing impact "
            "under typical load conditions."
        ),
        "informational": (
            "Performance optimisation opportunity; minimal direct impact "
            "on current user experience."
        ),
    },
    "cost_optimization": {
        "critical": (
            "Potential unnecessary cloud spending; may increase monthly costs "
            "beyond approved budgets and reduce funds for strategic initiatives."
        ),
        "high": (
            "Could contribute to budget overruns; may reduce funds available "
            "for product development and strategic cloud investments."
        ),
        "medium": (
            "Potential for unnecessary spend; review may reveal optimisation "
            "opportunities to improve cost efficiency."
        ),
        "low": (
            "Minor cost optimisation opportunity; limited direct financial impact " "in isolation."
        ),
        "informational": (
            "Cost awareness observation; minimal direct financial impact " "at current scale."
        ),
    },
}

_DEFAULT_FINDING_IMPACT = (
    "May affect business operations, compliance posture, or cloud costs. "
    "Review the finding details for specific organisational impact."
)

# Canonical order used for the aggregate PDF table
_ALL_RISK_CATEGORIES = [
    "Security Risk",
    "Compliance Risk",
    "Operational Risk",
    "Financial Risk",
    "Reputation Risk",
]

_LEVEL_ORDER = ["High", "Medium", "Low"]


# ── Public API ─────────────────────────────────────────────────────────────────


def build_business_impact_analysis(finding: Finding) -> BusinessImpact:
    """Classify a finding's business impact using qualitative, hedged language.

    Never raises — returns a safe default on any error.
    """
    try:
        sev = finding.severity.value
        pillar = finding.pillar

        risk_category = _PILLAR_PRIMARY_CATEGORY.get(pillar, "Operational Risk")
        pillar_templates = _FINDING_IMPACT_TEMPLATES.get(pillar, {})
        finding_impact = pillar_templates.get(sev, _DEFAULT_FINDING_IMPACT)
        priority = _SEV_PRIORITY.get(sev, "P3")
        impact_score = _SEV_SCORE.get(sev, 25)

        return BusinessImpact(
            risk_category=risk_category,
            finding_impact=finding_impact,
            priority=priority,
            impact_score=impact_score,
        )
    except Exception:
        return BusinessImpact(
            risk_category="Operational Risk",
            finding_impact=_DEFAULT_FINDING_IMPACT,
            priority="P3",
            impact_score=50,
        )


def calculate_business_impact_score(findings: Sequence[Finding]) -> float:
    """Average business impact score across all findings.

    Scores per finding: Critical=100, High=75, Medium=50, Low=25, Informational=0.
    Returns 0.0 for an empty findings list.  Never raises.
    """
    try:
        if not findings:
            return 0.0
        scores = [_SEV_SCORE.get(f.severity.value, 25) for f in findings]
        return round(sum(scores) / len(scores), 1)
    except Exception:
        return 0.0


def aggregate_risk_category_levels(findings: Sequence[Finding]) -> dict[str, str]:
    """Return the overall impact level for each of the five risk categories.

    Derived exclusively from actual findings — no fabrication.
    Categories with no contributing findings default to "Low".
    Returns dict with keys: Security Risk, Compliance Risk, Operational Risk,
    Financial Risk, Reputation Risk.  Never raises.
    """
    category_levels: dict[str, str] = {cat: "Low" for cat in _ALL_RISK_CATEGORIES}

    try:
        for f in findings:
            sev = f.severity.value
            pillar = f.pillar
            sev_level = _SEV_IMPACT_LEVEL.get(sev, "Low")
            contributed = _PILLAR_CONTRIBUTES_TO.get(pillar, set())

            for cat in contributed:
                # Reputation Risk only elevated for critical/high severity findings
                if cat == "Reputation Risk" and sev not in _REPUTATION_RISK_SEVERITIES:
                    continue
                current = category_levels.get(cat, "Low")
                if _LEVEL_ORDER.index(sev_level) < _LEVEL_ORDER.index(current):
                    category_levels[cat] = sev_level
    except Exception:
        pass

    return category_levels


def build_executive_business_impact_summary(findings: Sequence[Finding]) -> str:
    """Generate an executive narrative from actual findings.

    Uses qualitative, hedged language only — never invents financial values,
    compliance certifications, or legal exposure.  Never raises.
    """
    try:
        if not findings:
            return "Not Available — no findings recorded."

        total = len(findings)

        # Dominant pillar by finding count
        pillar_counts: dict[str, int] = {}
        for f in findings:
            pillar_counts[f.pillar] = pillar_counts.get(f.pillar, 0) + 1
        dominant_pillar = max(pillar_counts, key=lambda p: pillar_counts[p])

        _PILLAR_DOMAIN: dict[str, str] = {
            "security": "data protection and access controls",
            "reliability": "business continuity and availability controls",
            "operational_excellence": "operational governance and monitoring controls",
            "performance_efficiency": "application performance controls",
            "cost_optimization": "cloud cost management controls",
        }
        domain = _PILLAR_DOMAIN.get(dominant_pillar, "infrastructure controls")

        # Exposure risk types derived from pillars present
        pillars_present = {f.pillar for f in findings}
        risks: list[str] = []
        if "security" in pillars_present:
            risks.extend(["security incidents", "compliance violations"])
        if "reliability" in pillars_present:
            risks.append("operational disruption")
        if "cost_optimization" in pillars_present:
            risks.append("unnecessary cloud spending")
        if not risks:
            risks.append("operational risks")
        risks_str = ", ".join(risks)

        # Highest priority control area
        _PILLAR_PRIORITY_LABEL: dict[str, str] = {
            "security": "security controls",
            "reliability": "resilience and availability controls",
            "operational_excellence": "operational monitoring and governance",
            "performance_efficiency": "application performance configuration",
            "cost_optimization": "cloud cost management",
        }
        priority_label = _PILLAR_PRIORITY_LABEL.get(dominant_pillar, "infrastructure controls")

        return (
            f"The assessment identified {total} finding{'s' if total != 1 else ''}. "
            f"The largest concentration of risk exists within {domain}. "
            f"Failure to address these findings could increase exposure to {risks_str}. "
            f"The highest business priority is improving {priority_label}."
        )
    except Exception:
        return "Business impact summary could not be generated from the available findings."
