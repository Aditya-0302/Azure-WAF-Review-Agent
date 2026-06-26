"""Evidence presentation layer for enterprise report enrichment.

Consumes only existing Finding objects. Never calls Azure, never performs
new assessments, and never modifies findings. Formats information already
available in the Finding domain model into presentation-ready structures.

Public API
----------
format_finding_card(finding) -> FormattedFindingCard

Never raises — all methods are fully defensive.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from waf_shared.domain.models.finding import Finding

# ---------------------------------------------------------------------------
# Output dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FormattedFindingCard:
    """Presentation-ready evidence card derived from one Finding."""

    # ── Resource identity ───────────────────────────────────────────────────
    resource_name: str  # last segment of resource_id
    resource_type: str  # e.g. Microsoft.Storage/storageAccounts
    subscription_id: str  # parsed from resource_id; "" if absent
    resource_group: str  # parsed from resource_id; "" if absent

    # ── Evaluation metadata ─────────────────────────────────────────────────
    evaluation_method: str  # "Deterministic Rule" | "LLM Review"
    confidence_pct: int  # 0–100

    # ── Evidence table rows [(label, value)] ────────────────────────────────
    evidence_rows: tuple[tuple[str, str], ...]

    # ── Microsoft documentation URLs ────────────────────────────────────────
    microsoft_urls: tuple[str, ...]

    # ── WAF controls [(code, title)] ────────────────────────────────────────
    waf_controls: tuple[tuple[str, str], ...]

    # ── Deterministic narrative fields ──────────────────────────────────────
    business_impact_text: str
    remediation_priority_label: str
    verification_step: str


# ---------------------------------------------------------------------------
# Azure resource-ID parser
# ---------------------------------------------------------------------------


def _parse_resource_id(resource_id: str) -> dict[str, str]:
    """Extract name, subscription, and resource-group from an ARM resource ID.

    Handles full IDs (/subscriptions/.../resourceGroups/.../providers/...)
    and short names gracefully.  Returns empty strings for absent segments.
    """
    result = {"name": "", "subscription": "", "resource_group": ""}
    if not resource_id:
        return result
    try:
        # Resource name = last non-empty path segment
        parts_raw = resource_id.strip("/").split("/")
        result["name"] = parts_raw[-1] if parts_raw else resource_id

        parts_lower = [p.lower() for p in parts_raw]

        if "subscriptions" in parts_lower:
            idx = parts_lower.index("subscriptions")
            if idx + 1 < len(parts_raw):
                result["subscription"] = parts_raw[idx + 1]

        if "resourcegroups" in parts_lower:
            idx = parts_lower.index("resourcegroups")
            if idx + 1 < len(parts_raw):
                result["resource_group"] = parts_raw[idx + 1]
    except Exception:
        result["name"] = resource_id.rsplit("/", 1)[-1] if "/" in resource_id else resource_id
    return result


# ---------------------------------------------------------------------------
# Evaluation method label
# ---------------------------------------------------------------------------


def _evaluation_method(evaluation_type: str) -> str:
    t = (evaluation_type or "").lower()
    if t in ("llm", "ai", "llm_review", "llm-review"):
        return "LLM Review"
    return "Deterministic Rule"


# ---------------------------------------------------------------------------
# Evidence table builder
# ---------------------------------------------------------------------------

# Human-readable label map for common evidence field names
_EVIDENCE_LABEL_MAP: dict[str, str] = {
    "observed_value": "Observed Value",
    "expected_value": "Expected Value",
    "property": "Property",
    "property_path": "Property Path",
    "source": "Source",
    "api_version": "API Version",
    "policy_effect": "Policy Effect",
    "rule": "Rule",
    "result": "Result",
    "status": "Status",
    "value": "Value",
    "current": "Current Setting",
    "required": "Required Setting",
    "description": "Description",
    "control": "Control",
    "resource": "Resource",
}

# Fields redacted for security
_REDACT_KEYS = frozenset(
    {
        "password",
        "secret",
        "token",
        "key",
        "certificate",
        "sas",
        "connectionstring",
        "credential",
        "apikey",
    }
)


def _is_sensitive(key: str) -> bool:
    kl = key.lower()
    return any(r in kl for r in _REDACT_KEYS)


def _format_value(v: Any) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return str(v).lower()
    if isinstance(v, int | float):
        return str(v)
    if isinstance(v, list | dict):
        s = str(v)
        return s if len(s) <= 120 else s[:119] + "…"
    s = str(v)
    return s if len(s) <= 200 else s[:199] + "…"


def _build_evidence_rows(evidence: dict[str, Any]) -> tuple[tuple[str, str], ...]:
    """Flatten evidence dict to labelled [(label, value)] pairs.

    Prioritises known fields in the canonical display order, then appends
    remaining fields alphabetically.  Redacts sensitive keys.  Returns ()
    on empty input.
    """
    if not evidence:
        return ()
    try:
        # Priority display order
        priority_keys = [
            "observed_value",
            "expected_value",
            "property",
            "property_path",
            "source",
            "api_version",
            "status",
            "result",
            "value",
            "current",
            "required",
            "policy_effect",
            "rule",
        ]
        rows: list[tuple[str, str]] = []
        seen: set[str] = set()

        for pk in priority_keys:
            for k, v in evidence.items():
                if k.lower() == pk and k not in seen and not _is_sensitive(k):
                    label = _EVIDENCE_LABEL_MAP.get(k.lower(), k.replace("_", " ").title())
                    rows.append((label, _format_value(v)))
                    seen.add(k)

        for k, v in sorted(evidence.items()):
            if k not in seen and not _is_sensitive(k):
                label = _EVIDENCE_LABEL_MAP.get(k.lower(), k.replace("_", " ").title())
                rows.append((label, _format_value(v)))
                seen.add(k)

        return tuple(rows[:12])  # cap at 12 rows for readability
    except Exception:
        return ()


# ---------------------------------------------------------------------------
# Deterministic business impact lookup
# ---------------------------------------------------------------------------

# (severity, pillar) → impact text
_BUSINESS_IMPACT: dict[tuple[str, str], str] = {
    ("critical", "security"): (
        "May expose the entire workload to unauthorized access or data exfiltration. "
        "Exploitation of this configuration gap could potentially result in complete "
        "loss of data confidentiality and integrity across affected resources."
    ),
    ("critical", "reliability"): (
        "May result in extended service outages affecting all dependent workloads "
        "and downstream consumers. Could contribute to breach of SLA commitments "
        "and potential loss of customer trust."
    ),
    ("critical", "operational_excellence"): (
        "May severely impair the ability to detect, respond to, or recover from "
        "operational incidents. Could contribute to prolonged downtime and "
        "increased mean time to recovery."
    ),
    ("critical", "performance_efficiency"): (
        "May cause severe performance degradation affecting end-user experience "
        "across all consumers of the affected services. Could potentially result "
        "in complete service unavailability during peak demand."
    ),
    ("critical", "cost_optimization"): (
        "May result in significant unplanned expenditure due to uncontrolled "
        "resource consumption. Could potentially contribute to budget overruns "
        "that affect the viability of the workload."
    ),
    ("high", "security"): (
        "May expose sensitive data to unauthorized parties or allow privilege "
        "escalation within the environment. Attackers could potentially leverage "
        "this weakness to move laterally across workload boundaries."
    ),
    ("high", "reliability"): (
        "May increase the likelihood of service disruption under failure or "
        "high-load conditions. Could contribute to degraded availability and "
        "impact SLA compliance for dependent workloads."
    ),
    ("high", "operational_excellence"): (
        "May reduce operational visibility and impair incident response "
        "effectiveness. Could contribute to longer mean time to detect and "
        "resolve operational issues."
    ),
    ("high", "performance_efficiency"): (
        "May cause measurable performance degradation affecting end-user "
        "experience. Could potentially result in increased latency or "
        "reduced throughput under load."
    ),
    ("high", "cost_optimization"): (
        "May lead to ongoing unnecessary expenditure on over-provisioned or "
        "idle resources. Could contribute to budget overruns if not addressed "
        "within the current billing period."
    ),
    ("medium", "security"): (
        "May reduce compliance with security standards and increase exposure to "
        "opportunistic threats. Could contribute to a broader attack surface "
        "if combined with other configuration weaknesses."
    ),
    ("medium", "reliability"): (
        "May reduce resilience to partial failures or unexpected load spikes. "
        "Could contribute to degraded availability during maintenance windows "
        "or regional incidents."
    ),
    ("medium", "operational_excellence"): (
        "May limit operational insight and slow incident diagnosis. Could "
        "contribute to increased operational overhead for the engineering team."
    ),
    ("medium", "performance_efficiency"): (
        "May reduce throughput efficiency and increase resource utilization "
        "under moderate load. Could contribute to a suboptimal end-user "
        "experience during peak usage periods."
    ),
    ("medium", "cost_optimization"): (
        "May result in moderate unnecessary spend due to sub-optimal resource "
        "allocation. Could contribute to cost inefficiencies accumulating over "
        "the medium term."
    ),
    ("low", "security"): (
        "May create minor security gaps that, in aggregate, could weaken the "
        "overall security posture. Represents a low-priority hardening opportunity."
    ),
    ("low", "reliability"): (
        "May introduce marginal reliability risk under unusual conditions. "
        "Represents an incremental improvement opportunity for resilience."
    ),
    ("low", "operational_excellence"): (
        "May introduce minor operational friction. Represents an incremental "
        "improvement that may reduce long-term operational overhead."
    ),
    ("low", "performance_efficiency"): (
        "May have a marginal impact on performance under edge-case conditions. "
        "Represents an incremental tuning opportunity."
    ),
    ("low", "cost_optimization"): (
        "May result in a minor ongoing cost inefficiency. Represents a low-"
        "priority optimization that may deliver incremental savings."
    ),
}

_BUSINESS_IMPACT_DEFAULT: dict[str, str] = {
    "critical": (
        "May represent an immediate threat to environment security, availability, "
        "or compliance posture. Prompt remediation is strongly advisable."
    ),
    "high": (
        "May significantly increase risk exposure across one or more Well-Architected "
        "dimensions. Remediation within the current sprint is recommended."
    ),
    "medium": (
        "May moderately increase risk exposure or reduce operational efficiency. "
        "Remediation within the current release cycle is advisable."
    ),
    "low": (
        "Represents a minor deviation from best practice. Remediation may be "
        "scheduled as part of routine maintenance activities."
    ),
    "informational": (
        "Represents an observation that may warrant review as part of ongoing "
        "configuration hygiene and governance processes."
    ),
}


def _get_business_impact(severity: str, pillar: str) -> str:
    return _BUSINESS_IMPACT.get((severity.lower(), pillar.lower())) or _BUSINESS_IMPACT_DEFAULT.get(
        severity.lower(), _BUSINESS_IMPACT_DEFAULT["informational"]
    )


# ---------------------------------------------------------------------------
# Deterministic remediation priority
# ---------------------------------------------------------------------------

_REMEDIATION_PRIORITY: dict[str, str] = {
    "critical": "Immediate (within 24 hours)",
    "high": "Within 7 days",
    "medium": "Within 30 days",
    "low": "Next maintenance cycle",
    "informational": "Monitor / Review quarterly",
}


def _get_remediation_priority(severity: str) -> str:
    return _REMEDIATION_PRIORITY.get(severity.lower(), "Review as appropriate")


# ---------------------------------------------------------------------------
# Deterministic verification step
# ---------------------------------------------------------------------------

# Prefix-based verification guidance (checked in order; first match wins)
_VERIFICATION_PREFIXES: list[tuple[str, str]] = [
    (
        "SEC-CR-",
        "Re-run the container registry assessment. Confirm content trust "
        "policy is enabled and all image pulls require signature verification.",
    ),
    (
        "SEC-KV-",
        "Re-run the Key Vault assessment. Confirm soft-delete, purge "
        "protection, and private endpoint settings reflect the expected values.",
    ),
    (
        "SEC-NET-",
        "Re-run the network security assessment. Confirm NSG rules, "
        "firewall policies, and private endpoint configurations are in effect.",
    ),
    (
        "SEC-DEF-",
        "Re-run the Defender for Cloud assessment. Confirm all recommended "
        "Defender plans are enabled and security alerts are routed correctly.",
    ),
    (
        "SEC-",
        "Re-run the security assessment after applying the recommended "
        "configuration change. Confirm the observed value matches the expected "
        "value in the assessment evidence.",
    ),
    (
        "REL-AGW-",
        "Re-run the Application Gateway assessment. Confirm health probe "
        "settings, WAF policies, and autoscale configuration are correct.",
    ),
    (
        "REL-SB-",
        "Re-run the Service Bus assessment. Confirm geo-redundancy, "
        "premium tier settings, and message lock durations are correct.",
    ),
    (
        "REL-ASR-",
        "Re-run the Site Recovery assessment. Confirm replication health "
        "status and recovery point objectives meet the required targets.",
    ),
    (
        "REL-",
        "Re-run the reliability assessment after applying the recommended "
        "change. Confirm redundancy, replication, and health probe settings "
        "reflect the expected configuration.",
    ),
    (
        "OPS-DIAG-",
        "Re-run the diagnostics assessment. Confirm diagnostic settings "
        "are enabled and logs are flowing to the expected destination workspace.",
    ),
    (
        "OPS-SLOT-",
        "Re-run the deployment slot assessment. Confirm the production slot "
        "has traffic routing and staging slot configurations correctly set.",
    ),
    (
        "OPS-MON-",
        "Re-run the monitoring assessment. Confirm alerts are active and "
        "routed to the correct action groups.",
    ),
    (
        "OPS-",
        "Re-run the operational assessment after applying the recommended "
        "change. Confirm monitoring, alerting, and diagnostic settings are "
        "correctly configured.",
    ),
    (
        "PER-",
        "Re-run the performance assessment after applying the recommended "
        "change. Confirm autoscale policies, cache settings, and load "
        "balancing configurations are in effect.",
    ),
    (
        "CST-BUDGET-",
        "Re-run the cost assessment. Confirm budget alerts are active and "
        "spending thresholds are correctly set for the subscription.",
    ),
    (
        "CST-",
        "Re-run the cost assessment after applying the recommended change. "
        "Confirm resource sizing, reserved capacity, and tagging policies "
        "are correctly configured.",
    ),
]

_VERIFICATION_DEFAULT = (
    "Re-run the WAF assessment after applying the recommended configuration change. "
    "Confirm the finding no longer appears in the assessment results and that the "
    "observed evidence value matches the expected value."
)


def _get_verification_step(rule_id: str, evidence: dict[str, Any]) -> str:
    rule_upper = (rule_id or "").upper()

    # Try evidence-driven verification if property + expected_value are present
    prop = evidence.get("property") or evidence.get("property_path") or ""
    expected = evidence.get("expected_value")
    if prop and expected is not None:
        prop_str = str(prop)
        exp_str = str(expected).lower() if isinstance(expected, bool) else str(expected)
        base = f"Re-run the assessment after applying the fix. Confirm {prop_str}={exp_str}."
        return base

    # Prefix lookup
    for prefix, text in _VERIFICATION_PREFIXES:
        if rule_upper.startswith(prefix):
            return text

    return _VERIFICATION_DEFAULT


# ---------------------------------------------------------------------------
# WAF controls builder
# ---------------------------------------------------------------------------


def _build_waf_controls(
    codes: list[str],
    titles: list[str],
) -> tuple[tuple[str, str], ...]:
    """Pair WAF codes with their titles.

    Uses waf_titles when available; falls back to empty title string if the
    lists have different lengths.  Returns () if codes is empty.
    """
    if not codes:
        return ()
    result: list[tuple[str, str]] = []
    for i, code in enumerate(codes):
        title = titles[i] if titles and i < len(titles) else ""
        result.append((code, title))
    return tuple(result)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def format_finding_card(finding: Finding) -> FormattedFindingCard:
    """Build a FormattedFindingCard from an existing Finding.

    Never raises — all errors produce graceful empty/default values so that
    report generation is never interrupted by the evidence formatter.
    """
    try:
        resource_parts = _parse_resource_id(finding.resource_id or "")

        ev = finding.evidence or {}
        evidence_rows = _build_evidence_rows(ev)
        verification = _get_verification_step(finding.rule_id, ev)

        return FormattedFindingCard(
            resource_name=resource_parts["name"] or finding.resource_id,
            resource_type=finding.resource_type or "",
            subscription_id=resource_parts["subscription"],
            resource_group=resource_parts["resource_group"],
            evaluation_method=_evaluation_method(finding.evaluation_type or ""),
            confidence_pct=max(0, min(100, round(finding.confidence_score * 100))),
            evidence_rows=evidence_rows,
            microsoft_urls=tuple(u for u in (finding.microsoft_urls or []) if u),
            waf_controls=_build_waf_controls(
                finding.waf_codes or [],
                finding.waf_titles or [],
            ),
            business_impact_text=_get_business_impact(finding.severity.value, finding.pillar),
            remediation_priority_label=_get_remediation_priority(finding.severity.value),
            verification_step=verification,
        )
    except Exception:
        # Ultimate fallback — empty card that never breaks report generation
        return FormattedFindingCard(
            resource_name="",
            resource_type="",
            subscription_id="",
            resource_group="",
            evaluation_method="Deterministic Rule",
            confidence_pct=0,
            evidence_rows=(),
            microsoft_urls=(),
            waf_controls=(),
            business_impact_text=_BUSINESS_IMPACT_DEFAULT.get("informational", ""),
            remediation_priority_label="Review as appropriate",
            verification_step=_VERIFICATION_DEFAULT,
        )
