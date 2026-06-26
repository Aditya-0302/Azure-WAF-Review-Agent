"""Enterprise implementation roadmap — 9-section remediation plan from existing findings.

Consumes ONLY existing Finding and AggregatedReport objects.
Never calls Azure, never uses LLM, never invents data.
All sections are fully deterministic.

Sections
--------
1. Executive Roadmap       — Immediate / Near-Term / Medium-Term / Long-Term phases
2. Remediation Table       — full per-finding detail with owner, effort, risk reduction
3. Quick Wins              — low-effort / high-impact items sorted by impact then effort
4. Strategic Improvements  — recurring findings grouped into named initiatives
5. Implementation Timeline — activity placement across Week 1 / Week 2 / Month 1 / Quarter
6. Expected Improvements   — qualitative projections (never guaranteed outcomes)
7. Dependencies            — rule-based implementation dependency pairs
8. Verification Checklist  — per-finding actionable checklist items
9. Management Summary      — executive one-page implementation summary

Public API
----------
build_remediation_plan(agg, findings) -> RemediationPlan

Never raises — returns a plan with empty/default sections on any error.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from waf_reporting.aggregator import AggregatedReport
from waf_shared.domain.models.finding import Finding


# ---------------------------------------------------------------------------
# Lookup tables
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]

_PRIORITY_LABEL: dict[str, str] = {
    "critical":      "Immediate",
    "high":          "Near-Term",
    "medium":        "Medium-Term",
    "low":           "Long-Term",
    "informational": "Long-Term",
}

_TIMEFRAME: dict[str, str] = {
    "Immediate":   "0–7 Days",
    "Near-Term":   "7–30 Days",
    "Medium-Term": "30–90 Days",
    "Long-Term":   "90+ Days",
}

_EFFORT_MAP: dict[str, str] = {
    "critical":      "2–5 days",
    "high":          "1–3 days",
    "medium":        "2–8 hours",
    "low":           "Less than 2 hours",
    "informational": "Less than 1 hour",
}

_RISK_REDUCTION_MAP: dict[str, str] = {
    "critical":      "Very High",
    "high":          "High",
    "medium":        "Moderate",
    "low":           "Low",
    "informational": "Minimal",
}

# Owner assignment: first pattern that appears in lowercase resource_type wins
_OWNER_PATTERNS: list[tuple[str, str]] = [
    ("storageaccount",     "Storage Team"),
    ("storage",            "Storage Team"),
    ("virtualmachine",     "Infrastructure Team"),
    ("managedcluster",     "Infrastructure Team"),
    ("disk",               "Infrastructure Team"),
    ("applicationgateway", "Network Team"),
    ("networksecurity",    "Network Team"),
    ("networkinterface",   "Network Team"),
    ("loadbalancer",       "Network Team"),
    ("virtualnetwork",     "Network Team"),
    ("publicip",           "Network Team"),
    ("keyvault",           "Security Team"),
    ("containerregistry",  "Security Team"),
    ("vault",              "Security Team"),
    ("sql",                "Database Team"),
    ("mysql",              "Database Team"),
    ("postgresql",         "Database Team"),
    ("database",           "Database Team"),
    ("cosmosdb",           "Database Team"),
    ("site",               "Application Team"),
    ("functionapp",        "Application Team"),
    ("appservice",         "Application Team"),
    ("serverfarm",         "Application Team"),
    ("namespace",          "Application Team"),
    ("monitor",            "Operations Team"),
    ("insight",            "Operations Team"),
    ("workspace",          "Operations Team"),
    ("automationaccount",  "Operations Team"),
    ("recoveryservices",   "Operations Team"),
]
_OWNER_DEFAULT = "Platform Team"

# Quick-win keyword detection (title + recommendation, case-insensitive)
_QUICK_WIN_KEYWORDS: frozenset[str] = frozenset({
    "secure transfer", "https only", "https-only",
    "tls 1.2", "minimum tls", "tls version",
    "diagnostic", "diagnostic setting", "diagnostic log",
    "resource tag", "enforce tag", "tagging",
    "resource lock", "delete lock", "readonly lock",
    "budget", "budget alert",
    "encryption at rest", "blob encryption",
    "https", "http to https",
    "backup retention", "soft delete",
    "firewall rule", "ip restriction",
    "audit log", "activity log",
})

_QUICK_WIN_HIGH_IMPACT_PILLARS: frozenset[str] = frozenset({"security", "reliability"})

# Strategic initiative definitions (a finding may match multiple initiatives)
_INITIATIVE_MATCHERS: list[dict] = [
    {
        "name": "Storage Security Hardening",
        "description": (
            "Consolidate all storage account security findings into a single hardening sprint. "
            "Covers secure transfer enforcement, minimum TLS version, access key rotation, "
            "shared access signature governance, and private endpoint configuration."
        ),
        "timeline": "Month 1",
        "matcher": lambda f: "storage" in (f.resource_type or "").lower(),
    },
    {
        "name": "Identity Hardening",
        "description": (
            "Address identity and access management gaps including managed identity adoption, "
            "role assignment hygiene, authentication configuration, and key/secret rotation."
        ),
        "timeline": "Weeks 1–2",
        "matcher": lambda f: any(
            c in (f.waf_codes or []) for c in ("SE-05", "SE-08", "SE-10", "SE-01")
        ),
    },
    {
        "name": "Monitoring & Observability",
        "description": (
            "Enable diagnostic logging, metric alerts, and monitoring baselines across all "
            "assessed resources to close operational visibility and incident response gaps."
        ),
        "timeline": "Month 1",
        "matcher": lambda f: (
            f.pillar == "operational_excellence"
            and any(kw in (f.rule_id or "").upper() for kw in ("DIAG", "MON", "ALERT", "LOG"))
        ),
    },
    {
        "name": "Application Governance",
        "description": (
            "Address application service configuration gaps covering HTTPS enforcement, "
            "minimum TLS version, system-assigned identity, and deployment slot hygiene."
        ),
        "timeline": "Month 1",
        "matcher": lambda f: any(
            kw in (f.resource_type or "").lower()
            for kw in ("site", "functionapp", "appservice", "serverfarm")
        ),
    },
    {
        "name": "Network Security Hardening",
        "description": (
            "Harden network perimeter controls including NSG inbound rules, private endpoint "
            "deployment, firewall policy enforcement, and public IP exposure reduction."
        ),
        "timeline": "Month 1–2",
        "matcher": lambda f: any(
            kw in (f.resource_type or "").lower()
            for kw in ("networksecurity", "virtualnetwork", "applicationgateway",
                       "firewall", "publicip", "networkinterface")
        ),
    },
    {
        "name": "Cost Governance",
        "description": (
            "Address cost optimisation findings through tagging policies, budget alert "
            "configuration, reserved capacity evaluation, and rightsizing recommendations."
        ),
        "timeline": "Quarter",
        "matcher": lambda f: f.pillar == "cost_optimization",
    },
    {
        "name": "Operational Excellence",
        "description": (
            "Improve deployment automation, change management processes, and operational "
            "governance to reduce recurring incident probability and operational debt."
        ),
        "timeline": "Quarter",
        "matcher": lambda f: f.pillar == "operational_excellence",
    },
]

# Dependency detection: (prereq_titles_fn, dep_titles_fn, prereq_label, dep_label, rationale)
_DEPENDENCY_CHECKS: list[tuple] = [
    (
        lambda ts: any("diagnostic" in t.lower() for t in ts),
        lambda ts: any(kw in t.lower() for t in ts for kw in ("alert", "monitor")),
        "Enable Diagnostic Settings on affected resources",
        "Configure metric alerts and monitoring rules",
        "Alert evaluation requires diagnostic data flowing to a Log Analytics workspace.",
    ),
    (
        lambda ts: any("secure transfer" in t.lower() for t in ts),
        lambda ts: any("tls" in t.lower() or "minimum tls" in t.lower() for t in ts),
        "Enable Secure Transfer on storage accounts",
        "Enforce minimum TLS version policy",
        "TLS version enforcement is only effective after Secure Transfer is enabled.",
    ),
    (
        lambda ts: any("private endpoint" in t.lower() for t in ts),
        lambda ts: any("public network" in t.lower() or "firewall" in t.lower() for t in ts),
        "Deploy Private Endpoints for affected services",
        "Restrict or disable public network access",
        "Private endpoint connectivity must be confirmed before public access is disabled.",
    ),
    (
        lambda ts: any("key vault" in t.lower() for t in ts),
        lambda ts: any("certificate" in t.lower() or "secret" in t.lower() for t in ts),
        "Harden Key Vault configuration (soft-delete, purge protection)",
        "Rotate certificates and secrets to Key Vault-managed versions",
        "Key Vault hardening should precede migration of certificates and secrets.",
    ),
    (
        lambda ts: any("managed identity" in t.lower() for t in ts),
        lambda ts: any("access key" in t.lower() or "connection string" in t.lower() for t in ts),
        "Enable Managed Identity on affected services",
        "Replace access keys and connection strings with managed identity",
        "Managed identity must be active and tested before removing key-based access.",
    ),
    (
        lambda ts: any("backup" in t.lower() for t in ts),
        lambda ts: any("retention" in t.lower() or "recovery" in t.lower() for t in ts),
        "Enable backup on affected resources",
        "Configure retention policies and recovery point objectives",
        "Retention policies apply only to an active backup configuration.",
    ),
]

# Checklist verb selection by rule_id prefix
_CHECKLIST_PREFIXES: list[tuple[str, str]] = [
    ("SEC-STG-", "Enable secure configuration on"),
    ("SEC-KV-",  "Harden Key Vault settings for"),
    ("SEC-NET-", "Apply network security controls to"),
    ("SEC-DEF-", "Enable Defender plan for"),
    ("SEC-",     "Apply security recommendation to"),
    ("REL-AGW-", "Reconfigure Application Gateway health probe on"),
    ("REL-",     "Implement reliability improvement on"),
    ("OPS-DIAG-","Enable diagnostic settings on"),
    ("OPS-MON-", "Configure monitoring alerts for"),
    ("OPS-",     "Apply operational improvement to"),
    ("PER-",     "Apply performance tuning to"),
    ("CST-BUDGET-", "Create budget alert for"),
    ("CST-",     "Apply cost governance to"),
]
_CHECKLIST_DEFAULT_VERB = "Apply recommendation to"


# ---------------------------------------------------------------------------
# Output dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class RemediationItem:
    """One finding entry in the remediation roadmap or full table."""
    rank: int
    title: str
    severity: str
    pillar: str                    # display form e.g. "Security"
    waf_controls: str              # "SE-03, RE-02"
    recommendation: str
    affected_resource: str         # first short resource name
    affected_resource_count: int
    owner: str
    estimated_effort: str
    estimated_risk_reduction: str
    priority_label: str            # "Immediate" | "Near-Term" | "Medium-Term" | "Long-Term"
    verification_step: str
    rule_id: str


@dataclass(frozen=True)
class RemediationPhase:
    """One priority phase grouping related severity findings."""
    label: str                     # "Immediate" | "Near-Term" | "Medium-Term" | "Long-Term"
    timeframe: str                 # "0–7 Days" etc.
    severity_bucket: str           # "Critical" | "High" | "Medium" | "Low / Informational"
    items: tuple                   # tuple[RemediationItem, ...]


@dataclass(frozen=True)
class QuickWin:
    """A low-effort / high-impact finding identified automatically."""
    rank: int
    title: str
    severity: str
    pillar: str
    recommendation: str
    impact_label: str
    effort_label: str
    affected_resource_count: int
    waf_controls: str


@dataclass(frozen=True)
class StrategicInitiative:
    """A named strategic improvement initiative grouping related findings."""
    name: str
    description: str
    finding_count: int
    severity_summary: str
    pillars_involved: str
    recommended_timeline: str


@dataclass(frozen=True)
class TimelinePeriod:
    """One time period in the implementation timeline."""
    period: str               # "Week 1" | "Week 2" | "Month 1" | "Quarter"
    focus: str
    activities: tuple         # tuple[str, ...]
    finding_count: int


@dataclass(frozen=True)
class ExpectedImprovement:
    """Qualitative improvement projections using non-guaranteeing language."""
    potential_security_increase: str
    potential_compliance_increase: str
    potential_risk_reduction: str
    caveat: str


@dataclass(frozen=True)
class Dependency:
    """One implementation dependency relationship."""
    prerequisite: str
    dependent: str
    rationale: str


@dataclass(frozen=True)
class ChecklistItem:
    """One item in the verification checklist."""
    category: str    # "Immediate" | "Near-Term" | "Medium-Term" | "Long-Term" | "Close-Out"
    text: str        # "☐ Enable Secure Transfer on mystorageaccount"


@dataclass(frozen=True)
class ManagementSummary:
    """Executive one-page implementation summary."""
    total_findings: int
    immediate_count: int
    near_term_count: int
    medium_term_count: int
    long_term_count: int
    estimated_total_effort: str
    estimated_duration: str
    top_priorities: tuple      # tuple[str, ...]  — up to 3
    expected_outcome: str
    top_risks: tuple           # tuple[str, ...]  — up to 3


@dataclass(frozen=True)
class RemediationPlan:
    """Master container for all 9 enterprise remediation plan sections."""
    phases: tuple                              # tuple[RemediationPhase, ...]
    remediation_table: tuple                   # tuple[RemediationItem, ...]
    quick_wins: tuple                          # tuple[QuickWin, ...]
    strategic_initiatives: tuple               # tuple[StrategicInitiative, ...]
    timeline: tuple                            # tuple[TimelinePeriod, ...]
    expected_improvements: ExpectedImprovement
    dependencies: tuple                        # tuple[Dependency, ...]
    checklist: tuple                           # tuple[ChecklistItem, ...]
    management_summary: ManagementSummary


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _sev_sort_key(sev: str) -> int:
    try:
        return _SEVERITY_ORDER.index(sev.lower())
    except ValueError:
        return 99


def _short_name(resource_id: str) -> str:
    return resource_id.rsplit("/", 1)[-1] if "/" in resource_id else resource_id


def _get_owner(resource_type: str) -> str:
    """Deterministic owner assignment from resource type string."""
    rt = (resource_type or "").lower().replace("/", "").replace("microsoft.", "")
    last = (resource_type or "").rsplit("/", 1)[-1].lower()
    for pattern, team in _OWNER_PATTERNS:
        if pattern in rt or pattern in last:
            return team
    return _OWNER_DEFAULT


def _get_verification_step(rule_id: str) -> str:
    """Deterministic verification guidance derived from rule ID prefix."""
    _PREFIXES: list[tuple[str, str]] = [
        ("SEC-STG-", "Re-run storage assessment; confirm secure transfer and TLS setting match expected values."),
        ("SEC-KV-",  "Re-run Key Vault assessment; verify soft-delete, purge protection, and access policy."),
        ("SEC-NET-", "Re-run network assessment; confirm NSG rules and private endpoint configuration."),
        ("SEC-DEF-", "Re-run Defender assessment; verify Defender plan is enabled and alerts are routed."),
        ("SEC-",     "Re-run security assessment; confirm the observed value matches the expected value in evidence."),
        ("REL-AGW-", "Re-run Application Gateway assessment; verify health probe and WAF policy settings."),
        ("REL-",     "Re-run reliability assessment; verify redundancy, health probes, and replication settings."),
        ("OPS-DIAG-","Re-run diagnostics assessment; confirm diagnostic settings are active and logs are flowing."),
        ("OPS-MON-", "Re-run monitoring assessment; verify alerts are active and routed to action groups."),
        ("OPS-",     "Re-run operational assessment; confirm monitoring, alerting, and governance settings."),
        ("PER-",     "Re-run performance assessment; verify autoscale, cache, and load-balancing configuration."),
        ("CST-BUDGET-", "Re-run cost assessment; confirm budget alert is active and thresholds are correct."),
        ("CST-",     "Re-run cost assessment; verify tagging, reserved capacity, and resource sizing."),
    ]
    rid = (rule_id or "").upper()
    for prefix, text in _PREFIXES:
        if rid.startswith(prefix):
            return text
    return (
        "Re-run the WAF assessment after applying the fix. "
        "Confirm the finding no longer appears and evidence matches the expected value."
    )


def _checklist_verb(rule_id: str) -> str:
    for prefix, verb in _CHECKLIST_PREFIXES:
        if (rule_id or "").upper().startswith(prefix):
            return verb
    return _CHECKLIST_DEFAULT_VERB


def _is_quick_win(f: Finding) -> bool:
    """Return True if finding qualifies as quick win (low effort + high impact)."""
    sev = f.severity.value
    if sev == "critical":
        return False  # critical = high effort, not a quick win
    title_rec = f"{(f.title or '').lower()} {(f.recommendation or '').lower()}"
    # Condition 1: medium/low severity + high-impact pillar
    if sev in ("medium", "low") and f.pillar in _QUICK_WIN_HIGH_IMPACT_PILLARS:
        return True
    # Condition 2: keyword match in title/recommendation
    if any(kw in title_rec for kw in _QUICK_WIN_KEYWORDS):
        return True
    return False


def _deduplicate_by_rule(findings: list[Finding]) -> list[dict]:
    """Group findings by (rule_id, severity), aggregate resource names."""
    groups: dict[tuple[str, str], dict] = {}
    for f in findings:
        key = (f.rule_id, f.severity.value)
        if key not in groups:
            groups[key] = {
                "title":          f.title,
                "severity":       f.severity.value,
                "pillar":         f.pillar,
                "rule_id":        f.rule_id,
                "recommendation": f.recommendation,
                "resource_type":  f.resource_type,
                "waf_codes":      list(f.waf_codes or []),
                "resources":      [],
            }
        short = _short_name(f.resource_id)
        if short not in groups[key]["resources"]:
            groups[key]["resources"].append(short)
    return sorted(
        groups.values(),
        key=lambda g: (_sev_sort_key(g["severity"]), -len(g["resources"])),
    )


def _make_item(rank: int, item: dict) -> RemediationItem:
    return RemediationItem(
        rank=rank,
        title=item["title"],
        severity=item["severity"],
        pillar=item["pillar"].replace("_", " ").title(),
        waf_controls=", ".join(item["waf_codes"]) if item["waf_codes"] else "—",
        recommendation=item["recommendation"],
        affected_resource=item["resources"][0] if item["resources"] else "—",
        affected_resource_count=len(item["resources"]),
        owner=_get_owner(item["resource_type"]),
        estimated_effort=_EFFORT_MAP.get(item["severity"], "—"),
        estimated_risk_reduction=_RISK_REDUCTION_MAP.get(item["severity"], "—"),
        priority_label=_PRIORITY_LABEL.get(item["severity"], "Long-Term"),
        verification_step=_get_verification_step(item["rule_id"]),
        rule_id=item["rule_id"],
    )


# ---------------------------------------------------------------------------
# Section builders
# ---------------------------------------------------------------------------

def _build_phases(deduped: list[dict]) -> tuple:
    """Section 1: Group items into Immediate / Near-Term / Medium-Term / Long-Term."""
    buckets: dict[str, list[dict]] = {
        "Immediate":   [],
        "Near-Term":   [],
        "Medium-Term": [],
        "Long-Term":   [],
    }
    _sev_bucket = {
        "critical":      "Immediate",
        "high":          "Near-Term",
        "medium":        "Medium-Term",
        "low":           "Long-Term",
        "informational": "Long-Term",
    }
    _bucket_sev_label = {
        "Immediate":   "Critical",
        "Near-Term":   "High",
        "Medium-Term": "Medium",
        "Long-Term":   "Low / Informational",
    }
    for rank, item in enumerate(deduped, 1):
        buckets[_sev_bucket.get(item["severity"], "Long-Term")].append(
            {**item, "_rank": rank}
        )

    return tuple(
        RemediationPhase(
            label=label,
            timeframe=_TIMEFRAME[label],
            severity_bucket=_bucket_sev_label[label],
            items=tuple(_make_item(item["_rank"], item) for item in items),
        )
        for label in ("Immediate", "Near-Term", "Medium-Term", "Long-Term")
        for items in [buckets[label]]
        if items
    )


def _build_remediation_table(deduped: list[dict]) -> tuple:
    """Section 2: Full remediation table with all columns."""
    return tuple(_make_item(rank, item) for rank, item in enumerate(deduped, 1))


def _build_quick_wins(findings: list[Finding]) -> tuple:
    """Section 3: Quick wins — low effort, high impact, sorted best-first."""
    seen: set[str] = set()
    qw: list[Finding] = []
    for f in findings:
        if f.rule_id not in seen and _is_quick_win(f):
            qw.append(f)
            seen.add(f.rule_id)

    def _sort_key(f: Finding) -> tuple:
        return (
            {"security": 0, "reliability": 1}.get(f.pillar, 2),
            _sev_sort_key(f.severity.value),
        )
    qw.sort(key=_sort_key)

    rule_counts: dict[str, int] = {}
    for f in findings:
        rule_counts[f.rule_id] = rule_counts.get(f.rule_id, 0) + 1

    _impact = {"security": "Very High", "reliability": "High"}
    _effort = {"low": "Very Low", "medium": "Low", "informational": "Very Low"}

    return tuple(
        QuickWin(
            rank=rank,
            title=f.title,
            severity=f.severity.value,
            pillar=f.pillar.replace("_", " ").title(),
            recommendation=f.recommendation,
            impact_label=_impact.get(f.pillar, "Moderate"),
            effort_label=_effort.get(f.severity.value, "Low"),
            affected_resource_count=rule_counts.get(f.rule_id, 1),
            waf_controls=", ".join(f.waf_codes or []) or "—",
        )
        for rank, f in enumerate(qw[:15], 1)
    )


def _build_strategic_initiatives(findings: list[Finding]) -> tuple:
    """Section 4: Group findings into named strategic initiatives (existing findings only)."""
    rule_resources: dict[str, set[str]] = {}
    for f in findings:
        rule_resources.setdefault(f.rule_id, set()).add(f.resource_id)

    initiatives: list[StrategicInitiative] = []
    for cfg in _INITIATIVE_MATCHERS:
        try:
            matched = [f for f in findings if cfg["matcher"](f)]
        except Exception:
            continue
        if not matched:
            continue

        seen: set[str] = set()
        deduped: list[Finding] = []
        for f in matched:
            if f.rule_id not in seen:
                deduped.append(f)
                seen.add(f.rule_id)

        sev_counts: dict[str, int] = {}
        pillars: set[str] = set()
        for f in deduped:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1
            pillars.add(f.pillar.replace("_", " ").title())

        sev_parts = [
            f"{sev_counts[s]} {s.capitalize()}"
            for s in _SEVERITY_ORDER
            if s in sev_counts
        ]

        initiatives.append(StrategicInitiative(
            name=cfg["name"],
            description=cfg["description"],
            finding_count=len(deduped),
            severity_summary=", ".join(sev_parts) if sev_parts else "None",
            pillars_involved=", ".join(sorted(pillars)),
            recommended_timeline=cfg["timeline"],
        ))

    return tuple(initiatives)


def _build_timeline(findings: list[Finding]) -> tuple:
    """Section 5: Place unique rule findings into Week 1 / Week 2 / Month 1 / Quarter."""
    buckets: dict[str, list[str]] = {
        "Week 1": [], "Week 2": [], "Month 1": [], "Quarter": [],
    }
    _sev_to_period = {
        "critical": "Week 1", "high": "Week 2",
        "medium": "Month 1", "low": "Quarter", "informational": "Quarter",
    }
    _foci = {
        "Week 1":  "Critical finding remediation — immediate executive action required",
        "Week 2":  "High severity remediation — dedicated security engineering sprint",
        "Month 1": "Medium severity remediation — planned sprint cycle",
        "Quarter": "Low severity and informational findings — maintenance backlog",
    }
    seen: set[str] = set()
    for f in findings:
        if f.rule_id in seen:
            continue
        seen.add(f.rule_id)
        period = _sev_to_period.get(f.severity.value, "Quarter")
        title = f.title[:50] + "…" if len(f.title) > 50 else f.title
        buckets[period].append(title)

    return tuple(
        TimelinePeriod(
            period=period,
            focus=_foci[period],
            activities=tuple(activities[:10]),
            finding_count=len(activities),
        )
        for period, activities in buckets.items()
        if activities
    )


def _build_expected_improvements(
    agg: AggregatedReport,
    findings: list[Finding],
) -> ExpectedImprovement:
    """Section 6: Qualitative improvement projections — never guaranteed outcomes."""
    crit  = agg.findings_by_severity.get("critical", 0)
    high  = agg.findings_by_severity.get("high",     0)
    med   = agg.findings_by_severity.get("medium",   0)
    score = agg.overall_compliance_score

    # Security increase estimate
    sec_ch = [
        f for f in findings
        if f.pillar == "security" and f.severity.value in ("critical", "high")
    ]
    if len(sec_ch) >= 5:
        sec_inc = "Estimated 20–35 percentage point potential improvement in security posture"
    elif len(sec_ch) >= 2:
        sec_inc = "Estimated 10–20 percentage point potential improvement in security posture"
    elif len(sec_ch) >= 1:
        sec_inc = "Estimated 5–15 percentage point potential improvement in security posture"
    else:
        sec_inc = "Security posture may already be at or near target levels"

    # Compliance increase estimate
    if agg.total_findings == 0:
        comp_inc = "No open findings — compliance target is maintained"
    elif score < 50:
        comp_inc = (
            f"Potential compliance improvement from {score:.0f}% to an estimated 65–80% "
            "upon remediation of all Critical and High severity findings"
        )
    elif score < 70:
        comp_inc = (
            f"Potential compliance improvement from {score:.0f}% to an estimated 75–90% "
            "upon remediation of all Critical and High severity findings"
        )
    elif score < 90:
        comp_inc = (
            f"Potential compliance improvement from {score:.0f}% to an estimated 90–100% "
            "upon remediation of all open findings"
        )
    else:
        comp_inc = f"Projected compliance score of ≥ 90% may be maintained (current: {score:.0f}%)"

    # Risk reduction estimate
    if crit > 0:
        risk_red = (
            f"Projected reduction of approximately 40–60% in overall risk score "
            f"upon remediation of {crit} Critical and {high} High finding(s)"
        )
    elif high > 0:
        risk_red = (
            f"Projected reduction of approximately 20–35% in overall risk score "
            f"upon remediation of {high} High finding(s)"
        )
    elif med > 0:
        risk_red = (
            f"Projected reduction of approximately 10–20% in overall risk score "
            f"upon remediation of {med} Medium finding(s)"
        )
    else:
        risk_red = "Risk score is projected to remain low with the current posture"

    return ExpectedImprovement(
        potential_security_increase=sec_inc,
        potential_compliance_increase=comp_inc,
        potential_risk_reduction=risk_red,
        caveat=(
            "These are estimated projections based on finding severity weights. "
            "Actual improvements may vary based on remediation scope and implementation quality. "
            "Outcomes are not guaranteed. Language used: Estimated, Potential, Projected."
        ),
    )


def _build_dependencies(findings: list[Finding]) -> tuple:
    """Section 7: Rule-based dependency pairs — only where both sides exist in findings."""
    titles = [f.title for f in findings]
    deps: list[Dependency] = []
    for check in _DEPENDENCY_CHECKS:
        prereq_fn, dep_fn, prereq_label, dep_label, rationale = check
        try:
            if prereq_fn(titles) and dep_fn(titles):
                deps.append(Dependency(
                    prerequisite=prereq_label,
                    dependent=dep_label,
                    rationale=rationale,
                ))
        except Exception:
            pass
    return tuple(deps)


def _build_checklist(deduped: list[dict]) -> tuple:
    """Section 8: Per-finding checklist plus standard close-out items."""
    _sev_cat = {
        "critical":      "Immediate",
        "high":          "Near-Term",
        "medium":        "Medium-Term",
        "low":           "Long-Term",
        "informational": "Long-Term",
    }
    items: list[ChecklistItem] = []
    for item in deduped:
        cat  = _sev_cat.get(item["severity"], "Long-Term")
        verb = _checklist_verb(item["rule_id"])
        res  = item["resources"][0] if item["resources"] else "affected resources"
        items.append(ChecklistItem(category=cat, text=f"☐ {verb} {res}"))

    for text in (
        "☐ Re-run WAF Assessment to verify all remediations",
        "☐ Confirm overall compliance score has improved",
        "☐ Review any remaining open findings",
        "☐ Validate no regressions introduced by applied changes",
        "☐ Archive this report and distribute to relevant stakeholders",
    ):
        items.append(ChecklistItem(category="Close-Out", text=text))

    return tuple(items)


def _build_management_summary(
    agg: AggregatedReport,
    phases: tuple,
) -> ManagementSummary:
    """Section 9: Executive one-page management summary."""
    immediate_ct  = sum(len(p.items) for p in phases if p.label == "Immediate")
    near_term_ct  = sum(len(p.items) for p in phases if p.label == "Near-Term")
    medium_ct     = sum(len(p.items) for p in phases if p.label == "Medium-Term")
    long_term_ct  = sum(len(p.items) for p in phases if p.label == "Long-Term")

    crit = agg.findings_by_severity.get("critical", 0)
    high = agg.findings_by_severity.get("high",     0)
    med  = agg.findings_by_severity.get("medium",   0)
    low  = agg.findings_by_severity.get("low",      0)

    # Rough effort: critical ≈ 3.5 days avg, high ≈ 2 days, medium ≈ 5 h, low ≈ 1 h
    total_hours = crit * 28 + high * 16 + med * 5 + low * 1
    if total_hours >= 200:
        effort_str = f"Estimated {total_hours / 40:.0f}+ weeks of engineering effort"
    elif total_hours >= 40:
        effort_str = f"Estimated {total_hours / 8:.0f}+ engineering days"
    elif total_hours > 0:
        effort_str = f"Estimated {total_hours:.0f}+ engineering hours"
    else:
        effort_str = "Estimated less than 1 engineering day"

    if crit > 0:
        duration = "Estimated 30–90 days to remediate all Critical and High findings"
    elif high > 0:
        duration = "Estimated 14–30 days to remediate all High severity findings"
    elif med > 0:
        duration = "Estimated 30–60 days to remediate all Medium findings"
    else:
        duration = "Estimated less than 30 days for remaining findings"

    # Top 3 priorities (first items across phases by severity order)
    top_prios: list[str] = []
    for phase in phases:
        for item in phase.items:
            top_prios.append(f"{item.severity.capitalize()}: {item.title}")
            if len(top_prios) >= 3:
                break
        if len(top_prios) >= 3:
            break

    # Expected outcome
    score = agg.overall_compliance_score
    if crit > 0 or high > 0:
        outcome = (
            f"Remediating all Critical and High severity findings ({crit + high} total) "
            f"may meaningfully improve the overall compliance posture from "
            f"{score:.0f}%, potentially reducing the organisation's exposure to "
            "active exploitation, regulatory penalty, and unplanned service disruption."
        )
    elif med > 0:
        outcome = (
            f"Addressing Medium severity findings ({med} total) may strengthen "
            f"compliance and reduce residual risk from the current {score:.0f}% baseline."
        )
    else:
        outcome = (
            "The environment maintains a strong compliance posture. "
            "Ongoing assessment and governance activities are recommended "
            "to sustain the current posture."
        )

    # Top risks if not remediated
    risks: list[str] = []
    if crit > 0:
        risks.append(
            f"{crit} Critical finding(s) present active exploitation risk "
            "if not immediately remediated."
        )
    if high > 0:
        risks.append(
            f"{high} High finding(s) may be leveraged in multi-stage attacks "
            "if deferred beyond 30 days."
        )
    sec_ps = agg.findings_by_pillar.get("security")
    if sec_ps and sec_ps.total_findings > 0 and not risks:
        risks.append(
            f"{sec_ps.total_findings} security finding(s) may accumulate into "
            "a material risk posture over time."
        )

    return ManagementSummary(
        total_findings=agg.total_findings,
        immediate_count=immediate_ct,
        near_term_count=near_term_ct,
        medium_term_count=medium_ct,
        long_term_count=long_term_ct,
        estimated_total_effort=effort_str,
        estimated_duration=duration,
        top_priorities=tuple(top_prios[:3]),
        expected_outcome=outcome,
        top_risks=tuple(risks[:3]),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_remediation_plan(
    agg: AggregatedReport,
    findings: Sequence[Finding],
) -> RemediationPlan:
    """Build a complete 9-section enterprise remediation plan.

    Consumes only existing AggregatedReport and Finding objects.
    Never raises — returns a plan with empty/default sections on any error.
    """
    try:
        all_f   = list(findings)
        deduped = _deduplicate_by_rule(all_f)
        phases  = _build_phases(deduped)
        return RemediationPlan(
            phases                = phases,
            remediation_table     = _build_remediation_table(deduped),
            quick_wins            = _build_quick_wins(all_f),
            strategic_initiatives = _build_strategic_initiatives(all_f),
            timeline              = _build_timeline(all_f),
            expected_improvements = _build_expected_improvements(agg, all_f),
            dependencies          = _build_dependencies(all_f),
            checklist             = _build_checklist(deduped),
            management_summary    = _build_management_summary(agg, phases),
        )
    except Exception:
        _empty_impr = ExpectedImprovement(
            potential_security_increase   = "Not available",
            potential_compliance_increase = "Not available",
            potential_risk_reduction      = "Not available",
            caveat                        = "Assessment data unavailable.",
        )
        _empty_sum = ManagementSummary(
            total_findings=0, immediate_count=0, near_term_count=0,
            medium_term_count=0, long_term_count=0,
            estimated_total_effort="Not available",
            estimated_duration="Not available",
            top_priorities=(), expected_outcome="Not available", top_risks=(),
        )
        return RemediationPlan(
            phases=(), remediation_table=(), quick_wins=(),
            strategic_initiatives=(), timeline=(),
            expected_improvements=_empty_impr,
            dependencies=(), checklist=(),
            management_summary=_empty_sum,
        )
